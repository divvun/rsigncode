use bcder::encode::Values;
use bcder::{Captured, Mode, Oid};
use bytes::Bytes;
use cryptographic_message_syntax::asn1::rfc3161::OID_CONTENT_TYPE_TST_INFO;
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
fn request_rfc3161(signature_bytes: &[u8], url: &str) -> Result<Rfc5652SignedData> {
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

/// Attempts per TSA URL. Public TSAs (Certum among them) drop the odd connection,
/// and one reset must not fail a whole signing request.
const TIMESTAMP_ATTEMPTS: u32 = 3;

/// Send an RFC 3161 timestamp request, trying each URL in order until one succeeds.
fn request_rfc3161_with_fallback(
    signature_bytes: &[u8],
    urls: &[String],
) -> Result<Rfc5652SignedData> {
    let mut last_err = None;
    for url in urls {
        for attempt in 1..=TIMESTAMP_ATTEMPTS {
            match request_rfc3161(signature_bytes, url) {
                Ok(token) => return Ok(token),
                Err(e) => {
                    eprintln!(
                        "Warning: timestamp request to {url} failed (attempt {attempt}/{TIMESTAMP_ATTEMPTS}): {e}"
                    );
                    last_err = Some(e);
                    if attempt < TIMESTAMP_ATTEMPTS {
                        std::thread::sleep(std::time::Duration::from_millis(
                            500 * u64::from(attempt),
                        ));
                    }
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Timestamp("no timestamp URLs provided".into())))
}

/// Send an Authenticode timestamp request to a TSA server.
///
/// `signature_bytes` is the raw signature (encrypted digest) from the SignerInfo.
/// Returns the low-level `rfc5652::SignedData` from the TSA's PKCS#7 response.
fn request_authenticode(signature_bytes: &[u8], url: &str) -> Result<Rfc5652SignedData> {
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

    Rfc5652SignedData::decode_ber(&pkcs7_der).map_err(|e| {
        Error::Timestamp(format!(
            "failed to parse Authenticode timestamp PKCS#7: {e}"
        ))
    })
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
/// The Authenticode timestamp attaches the TSA's SignerInfo as a PKCS#9 counter-signature,
/// and the TSA's certificates go into the outer certificate set so the counter-signature
/// can be verified.
///
/// Some TSAs (Certum among them) answer a legacy Authenticode request with an RFC 3161
/// token. Its SignerInfo signs a TSTInfo, not our signature, so as a counter-signature
/// it can never verify and Windows rejects the whole signature. Such a response is
/// attached whole under SPC_RFC3161 instead, exactly as if it had been requested that way.
fn attach_authenticode_timestamp(
    signed_data: &mut Rfc5652SignedData,
    tsa_response: &Rfc5652SignedData,
) -> Result<()> {
    if tsa_response.content_info.content_type == OID_CONTENT_TYPE_TST_INFO {
        return attach_rfc3161_timestamp(signed_data, tsa_response);
    }

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

    if let Some(tsa_certs) = &tsa_response.certificates {
        let certs = signed_data
            .certificates
            .get_or_insert_with(Default::default);
        for cert in tsa_certs.iter() {
            if !certs.contains(cert) {
                certs.push(cert.clone());
            }
        }
    }

    push_unsigned_attribute(signed_data, attr)
}

/// Push an attribute onto the first signer's unsigned attributes.
fn push_unsigned_attribute(signed_data: &mut Rfc5652SignedData, attr: Attribute) -> Result<()> {
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

    // A PE contains native Authenticode content without RFC 5652's OCTET STRING
    // wrapper. Restore it temporarily for the generic CMS parser.
    let cms_der = super::signing::wrap_authenticode_content(pkcs7_der)
        .map_err(|e| Error::Timestamp(format!("failed to normalize PKCS#7: {e}")))?;

    // Parse at the low level so we can mutate.
    let mut signed_data = Rfc5652SignedData::decode_ber(&cms_der)
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
        let tsa_response = request_authenticode_with_fallback(&signature_bytes, authenticode_urls)?;
        attach_authenticode_timestamp(&mut signed_data, &tsa_response)?;
    }

    // Re-encode as ContentInfo, then restore native Authenticode content for
    // embedding in the PE certificate table.
    let encoded = encode_signed_data_as_content_info(&signed_data)?;
    super::signing::normalize_authenticode_signature(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA;
    use cryptographic_message_syntax::{SignedDataBuilder, SignerBuilder};
    use x509_certificate::{KeyAlgorithm, X509CertificateBuilder};

    /// A CMS SignedData over `content_type`, signed by a throwaway certificate that
    /// the builder embeds in its certificate set.
    fn signed_data(content_type: Oid) -> Rfc5652SignedData {
        let mut builder = X509CertificateBuilder::default();
        builder
            .subject()
            .append_common_name_utf8_string("rsigncode test")
            .unwrap();
        let (cert, key) = builder
            .create_with_random_keypair(KeyAlgorithm::Ed25519)
            .unwrap();

        let der = SignedDataBuilder::default()
            .content_inline(b"content".to_vec())
            .content_type(content_type.clone())
            .signer(SignerBuilder::new(&key, cert).content_type(content_type))
            .build_der()
            .unwrap();
        Rfc5652SignedData::decode_ber(&der).unwrap()
    }

    fn unsigned_attr_types(sd: &Rfc5652SignedData) -> Vec<Oid> {
        sd.signer_infos[0]
            .unsigned_attributes
            .as_ref()
            .map(|attrs| attrs.iter().map(|a| a.typ.clone()).collect())
            .unwrap_or_default()
    }

    fn cert_count(sd: &Rfc5652SignedData) -> usize {
        sd.certificates.as_ref().map_or(0, |c| c.len())
    }

    #[test]
    fn rfc3161_token_on_legacy_path_is_attached_as_spc_rfc3161() {
        let mut ours = signed_data(Oid(OID_ID_DATA.as_ref().into()));
        let token = signed_data(Oid(OID_CONTENT_TYPE_TST_INFO.as_ref().into()));
        let certs_before = cert_count(&ours);

        attach_authenticode_timestamp(&mut ours, &token).unwrap();

        assert_eq!(
            unsigned_attr_types(&ours),
            vec![oid_to_bcder(&oid::SPC_RFC3161)],
            "an RFC 3161 token must not be split into a PKCS#9 counter-signature"
        );
        // The token carries its own certificates; nothing is hoisted to the outer set.
        assert_eq!(cert_count(&ours), certs_before);
    }

    #[test]
    fn legacy_counter_signature_brings_tsa_certificates() {
        let mut ours = signed_data(Oid(OID_ID_DATA.as_ref().into()));
        let tsa = signed_data(Oid(OID_ID_DATA.as_ref().into()));
        let certs_before = cert_count(&ours);

        attach_authenticode_timestamp(&mut ours, &tsa).unwrap();
        assert_eq!(
            unsigned_attr_types(&ours),
            vec![oid_to_bcder(&oid::PKCS9_COUNTER_SIGNATURE)]
        );
        assert_eq!(
            cert_count(&ours),
            certs_before + cert_count(&tsa),
            "TSA certificates must be added to verify the counter-signature"
        );

        // Re-attaching does not duplicate the certificates.
        attach_authenticode_timestamp(&mut ours, &tsa).unwrap();
        assert_eq!(cert_count(&ours), certs_before + cert_count(&tsa));
    }
}
