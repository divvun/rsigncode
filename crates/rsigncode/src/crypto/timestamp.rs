use bcder::encode::Values;
use bcder::{Captured, Mode, Oid};
use bytes::Bytes;
use der::asn1::OctetString;
use der::Encode;
use x509_certificate::rfc5652::{Attribute, AttributeValue};

use crate::asn1::timestamp::{TimeStampRequest, TimeStampRequestBlob};
use crate::error::{Error, Result};
use crate::oid;

type Rfc5652SignedData = cryptographic_message_syntax::asn1::rfc5652::SignedData;
type Rfc5652UnsignedAttributes = cryptographic_message_syntax::asn1::rfc5652::UnsignedAttributes;

/// Convert a `const_oid::ObjectIdentifier` to a `bcder::Oid`.
fn oid_to_bcder(oid: &const_oid::ObjectIdentifier) -> Oid {
    Oid(Bytes::copy_from_slice(oid.as_bytes()))
}

/// Send an RFC 3161 timestamp request to a TSA server.
///
/// `signature_bytes` is the raw signature (encrypted digest) from the SignerInfo.
/// Returns the low-level `rfc5652::SignedData` of the timestamp token.
fn request_rfc3161(
    signature_bytes: &[u8],
    url: &str,
) -> Result<Rfc5652SignedData> {
    let response = cryptographic_message_syntax::time_stamp_message_http(
        url,
        signature_bytes,
        x509_certificate::DigestAlgorithm::Sha256,
    )
    .map_err(|e| Error::Timestamp(format!("RFC 3161 request to {url} failed: {e}")))?;

    if !response.is_success() {
        return Err(Error::Timestamp(format!(
            "RFC 3161 server {url} returned unsuccessful status: {:?}",
            response.status.status
        )));
    }

    response
        .signed_data()
        .map_err(|e| Error::Timestamp(format!("failed to decode timestamp token: {e}")))?
        .ok_or_else(|| Error::Timestamp("no signed data in timestamp response".into()))
}

/// Send an RFC 3161 timestamp request, trying each URL in order until one succeeds.
fn request_rfc3161_with_fallback(
    signature_bytes: &[u8],
    urls: &[String],
) -> Result<Rfc5652SignedData> {
    let mut last_err = None;
    for url in urls {
        match request_rfc3161(signature_bytes, url) {
            Ok(token) => return Ok(token),
            Err(e) => {
                eprintln!("Warning: timestamp request to {url} failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Timestamp("no timestamp URLs provided".into())))
}

/// Send an Authenticode timestamp request to a TSA server.
///
/// `signature_bytes` is the raw signature (encrypted digest) from the SignerInfo.
/// Returns the low-level `rfc5652::SignedData` from the TSA's PKCS#7 response.
fn request_authenticode(
    signature_bytes: &[u8],
    url: &str,
) -> Result<Rfc5652SignedData> {
    use base64::Engine;

    // Build the Authenticode TimeStampRequest structure
    let ts_request = TimeStampRequest {
        req_type: oid::SPC_TIME_STAMP_REQUEST,
        blob: TimeStampRequestBlob {
            content_type: oid::PKCS7_DATA,
            signature: OctetString::new(signature_bytes)
                .map_err(|e| Error::Timestamp(format!("OctetString error: {e}")))?,
        },
    };

    // DER encode, then base64 encode
    let der_bytes = ts_request
        .to_der()
        .map_err(|e| Error::Timestamp(format!("failed to DER-encode timestamp request: {e}")))?;
    let b64_body = base64::engine::general_purpose::STANDARD.encode(&der_bytes);

    // POST to the TSA
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(url)
        .header("Content-Type", "application/octet-stream")
        .body(b64_body)
        .send()
        .map_err(|e| {
            Error::Http(format!(
                "Authenticode timestamp request to {url} failed: {e}"
            ))
        })?;

    if !response.status().is_success() {
        return Err(Error::Http(format!(
            "Authenticode timestamp server {url} returned HTTP {}",
            response.status()
        )));
    }

    let response_bytes = response
        .bytes()
        .map_err(|e| Error::Http(format!("failed to read response body: {e}")))?;

    // Response may be base64-encoded PKCS#7 or raw DER
    let pkcs7_der = if response_bytes.starts_with(b"MII") {
        // Looks like base64
        base64::engine::general_purpose::STANDARD
            .decode(&response_bytes)
            .map_err(|e| {
                Error::Timestamp(format!("failed to base64-decode timestamp response: {e}"))
            })?
    } else {
        response_bytes.to_vec()
    };

    Rfc5652SignedData::decode_ber(&pkcs7_der)
        .map_err(|e| Error::Timestamp(format!("failed to parse Authenticode timestamp PKCS#7: {e}")))
}

/// Send an Authenticode timestamp request, trying each URL in order until one succeeds.
fn request_authenticode_with_fallback(
    signature_bytes: &[u8],
    urls: &[String],
) -> Result<Rfc5652SignedData> {
    let mut last_err = None;
    for url in urls {
        match request_authenticode(signature_bytes, url) {
            Ok(token) => return Ok(token),
            Err(e) => {
                eprintln!("Warning: Authenticode timestamp request to {url} failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Timestamp("no timestamp URLs provided".into())))
}

/// Attach an RFC 3161 timestamp token as an unauthenticated attribute under the
/// Microsoft SPC_RFC3161 OID (1.3.6.1.4.1.311.3.3.1).
fn attach_rfc3161_timestamp(
    signed_data: &mut Rfc5652SignedData,
    token: &Rfc5652SignedData,
) -> Result<()> {
    let spc_rfc3161_oid = oid_to_bcder(&oid::SPC_RFC3161);

    // Use Ber mode because the token was parsed from a BER-encoded TSP response.
    // bcder panics if you try to DER-encode a Captured that was decoded from BER.
    let captured = Captured::from_values(Mode::Ber, token.encode_ref());

    let attr = Attribute {
        typ: spc_rfc3161_oid,
        values: vec![AttributeValue::new(captured)],
    };

    push_unsigned_attribute(signed_data, attr)
}

/// Attach an Authenticode counter-signature as an unauthenticated attribute.
///
/// The Authenticode timestamp attaches the TSA's SignerInfo as a PKCS#9 counter-signature.
fn attach_authenticode_timestamp(
    signed_data: &mut Rfc5652SignedData,
    tsa_response: &Rfc5652SignedData,
) -> Result<()> {
    let counter_sig_oid = oid_to_bcder(&oid::PKCS9_COUNTER_SIGNATURE);

    let tsa_signer = tsa_response
        .signer_infos
        .first()
        .ok_or_else(|| Error::Timestamp("no signer in Authenticode timestamp response".into()))?;

    let captured = Captured::from_values(Mode::Ber, tsa_signer.encode_ref());

    let attr = Attribute {
        typ: counter_sig_oid,
        values: vec![AttributeValue::new(captured)],
    };

    push_unsigned_attribute(signed_data, attr)
}

/// Push an attribute onto the first signer's unsigned attributes.
fn push_unsigned_attribute(
    signed_data: &mut Rfc5652SignedData,
    attr: Attribute,
) -> Result<()> {
    let signer_info = signed_data
        .signer_infos
        .first_mut()
        .ok_or_else(|| Error::Timestamp("no signer info in signed data".into()))?;

    match &mut signer_info.unsigned_attributes {
        Some(attrs) => attrs.push(attr),
        None => {
            let mut attrs = Rfc5652UnsignedAttributes::default();
            attrs.push(attr);
            signer_info.unsigned_attributes = Some(attrs);
        }
    }

    Ok(())
}

/// Re-encode a low-level `rfc5652::SignedData` as a full PKCS#7 ContentInfo blob.
///
/// `rfc5652::SignedData::encode_ref()` already produces the ContentInfo wrapper
/// (SEQUENCE { OID, [0] EXPLICIT SignedData }).
fn encode_signed_data_as_content_info(signed_data: &Rfc5652SignedData) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    signed_data
        .encode_ref()
        .write_encoded(Mode::Ber, &mut buf)
        .map_err(|e| Error::Timestamp(format!("failed to encode ContentInfo: {e}")))?;

    Ok(buf)
}

/// Add timestamps to an existing PKCS#7 signature.
///
/// Parses the PKCS#7 at the low level, requests timestamps from the given URLs,
/// attaches them as unauthenticated attributes, and returns the modified PKCS#7 DER.
pub fn add_timestamps(
    pkcs7_der: &[u8],
    rfc3161_urls: &[String],
    authenticode_urls: &[String],
) -> Result<Vec<u8>> {
    if rfc3161_urls.is_empty() && authenticode_urls.is_empty() {
        return Ok(pkcs7_der.to_vec());
    }

    // Parse at the low level so we can mutate
    let mut signed_data = Rfc5652SignedData::decode_ber(pkcs7_der)
        .map_err(|e| Error::Timestamp(format!("failed to parse PKCS#7 for timestamping: {e}")))?;

    // Get the signature bytes from the first signer
    let signature_bytes = {
        let signer = signed_data
            .signer_infos
            .first()
            .ok_or_else(|| Error::Timestamp("no signer info in PKCS#7".into()))?;
        signer.signature.clone().into_bytes()
    };

    // Add RFC 3161 timestamps
    if !rfc3161_urls.is_empty() {
        let token = request_rfc3161_with_fallback(&signature_bytes, rfc3161_urls)?;
        attach_rfc3161_timestamp(&mut signed_data, &token)?;
    }

    // Add Authenticode timestamps
    if !authenticode_urls.is_empty() {
        let tsa_response =
            request_authenticode_with_fallback(&signature_bytes, authenticode_urls)?;
        attach_authenticode_timestamp(&mut signed_data, &tsa_response)?;
    }

    // Re-encode as ContentInfo
    encode_signed_data_as_content_info(&signed_data)
}
