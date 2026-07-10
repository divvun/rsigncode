use bcder::{Captured, Mode, Oid};
use bytes::Bytes;
use cryptographic_message_syntax::{SignedDataBuilder, SignerBuilder};
use der::asn1::{BitString, OctetString};
use der::{Decode, Encode};
use x509_certificate::{rfc5652::AttributeValue, CapturedX509Certificate, InMemorySigningKeyPair};

use crate::asn1::spc::{
    DigestInfo, SpcAttributeTypeAndOptionalValue, SpcIndirectDataContent, SpcLink, SpcPeImageData,
    SpcSpOpusInfo, SpcString,
};
use crate::error::{Error, Result};
use crate::oid;

/// Which hash algorithm to use for signing.
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            _ => Err(Error::Other(format!("unsupported hash algorithm: {name}"))),
        }
    }

    fn digest_algorithm_oid(&self) -> const_oid::ObjectIdentifier {
        match self {
            Self::Sha1 => const_oid::db::rfc5912::ID_SHA_1,
            Self::Sha256 => const_oid::db::rfc5912::ID_SHA_256,
            Self::Sha384 => const_oid::db::rfc5912::ID_SHA_384,
            Self::Sha512 => const_oid::db::rfc5912::ID_SHA_512,
        }
    }
}

/// Options for creating an Authenticode signature.
pub struct SigningOptions<'a> {
    pub hash_algo: HashAlgorithm,
    pub program_name: Option<&'a str>,
    pub program_url: Option<&'a str>,
    pub rfc3161_urls: Vec<String>,
    pub authenticode_urls: Vec<String>,
}

/// Calculate the Authenticode digest of a PE file using the given algorithm.
pub fn pe_digest(
    f: &mut std::fs::File,
    pe: &crate::format::pe::PeInfo,
    algo: HashAlgorithm,
) -> Result<Vec<u8>> {
    use sha2::Digest;
    match algo {
        HashAlgorithm::Sha256 => {
            let mut h = sha2::Sha256::new();
            crate::format::pe::authenticode_digest(f, pe, &mut h)?;
            Ok(h.finalize().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let mut h = sha2::Sha384::new();
            crate::format::pe::authenticode_digest(f, pe, &mut h)?;
            Ok(h.finalize().to_vec())
        }
        HashAlgorithm::Sha512 => {
            let mut h = sha2::Sha512::new();
            crate::format::pe::authenticode_digest(f, pe, &mut h)?;
            Ok(h.finalize().to_vec())
        }
        HashAlgorithm::Sha1 => {
            let mut h = sha1::Sha1::new();
            crate::format::pe::authenticode_digest(f, pe, &mut h)?;
            Ok(h.finalize().to_vec())
        }
    }
}

/// Build a DER-encoded PKCS#7 Authenticode signature over a PE file digest.
///
/// The `digest` should be the Authenticode digest of the PE file (from `format::pe::authenticode_digest`).
pub fn create_authenticode_signature(
    signing_key: &InMemorySigningKeyPair,
    signer_cert: CapturedX509Certificate,
    extra_certs: Vec<CapturedX509Certificate>,
    digest: &[u8],
    opts: &SigningOptions,
) -> Result<Vec<u8>> {
    // cryptographic-message-syntax 0.26 hardcodes SHA-256 as the signer digest algorithm.
    // Using a different hash for the file digest would produce a mismatch that verifiers reject.
    if !matches!(opts.hash_algo, HashAlgorithm::Sha256) {
        return Err(Error::Signing(
            "only SHA-256 is supported for signing (CMS crate limitation)".into(),
        ));
    }

    // 1. Build SpcIndirectDataContent
    let spc_content = build_spc_indirect_data(digest, opts)?;

    // 2. Build the signer with SPC_INDIRECT_DATA as content type.
    //
    // Authenticode computes the messageDigest signed attribute over the *content
    // octets* of the SpcIndirectDataContent SEQUENCE — i.e. with the outer
    // SEQUENCE tag+length stripped — not over the full DER. The generic CMS
    // crate would hash the full DER, so we hand it the stripped value ourselves.
    // (Verified against signtool output.)
    let spc_indirect_data_oid = oid_to_bcder(&oid::SPC_INDIRECT_DATA);
    let spc_content_value = der_sequence_content(&spc_content)?.to_vec();
    let mut signer = SignerBuilder::new(signing_key, signer_cert.clone())
        .content_type(spc_indirect_data_oid)
        .message_id_content(spc_content_value);

    // Authenticode requires these Microsoft-specific signed attributes. Their
    // values are ASN.1 structures directly inside the attribute SET, not OCTET
    // STRING wrappers.
    let opus_info = build_opus_info(opts)?;
    signer = signer.signed_attribute(
        oid_to_bcder(&oid::SPC_SP_OPUS_INFO),
        vec![attribute_value_from_der(&opus_info)?],
    );

    let statement_type = emit_tlv(
        0x30,
        &oid::SPC_INDIVIDUAL_SP_KEY_PURPOSE
            .to_der()
            .map_err(|e| Error::Signing(format!("DER encode statement type: {e}")))?,
    );
    signer = signer.signed_attribute(
        oid_to_bcder(&oid::SPC_STATEMENT_TYPE),
        vec![attribute_value_from_der(&statement_type)?],
    );

    // 3. Build the SignedData
    let encap_content_type_oid = oid_to_bcder(&oid::SPC_INDIRECT_DATA);

    let builder = SignedDataBuilder::default()
        .content_type(encap_content_type_oid)
        .content_inline(spc_content)
        .signer(signer)
        .certificate(signer_cert)
        .certificates(extra_certs.into_iter());

    let pkcs7_der = builder
        .build_der()
        .map_err(|e| Error::Signing(format!("failed to build SignedData: {e}")))?;

    // Timestamping re-parses the PKCS#7 with the CMS crate and returns native
    // Authenticode content. Without timestamping, normalize it here.
    let pkcs7_der = if !opts.rfc3161_urls.is_empty() || !opts.authenticode_urls.is_empty() {
        super::timestamp::add_timestamps(&pkcs7_der, &opts.rfc3161_urls, &opts.authenticode_urls)?
    } else {
        pkcs7_der
    };

    normalize_authenticode_signature(&pkcs7_der)
}

/// Build a PKCS#7 SignedData envelope containing SpcIndirectDataContent but no signers.
///
/// This is the output of `extract-data` — it gets sent to a remote signer who adds the
/// actual cryptographic signature and returns a complete PKCS#7.
pub fn build_extract_data_pkcs7(digest: &[u8], opts: &SigningOptions) -> Result<Vec<u8>> {
    let spc_content = build_spc_indirect_data(digest, opts)?;
    let encap_oid = oid_to_bcder(&oid::SPC_INDIRECT_DATA);

    // Build a SignedData with no signers — just the encapsulated content
    let builder = SignedDataBuilder::default()
        .content_type(encap_oid)
        .content_inline(spc_content);

    builder
        .build_der()
        .map_err(|e| Error::Signing(format!("failed to build extract-data PKCS#7: {e}")))
}

/// Build the DER-encoded SpcIndirectDataContent for a PE file.
pub fn build_spc_indirect_data(digest: &[u8], opts: &SigningOptions) -> Result<Vec<u8>> {
    // Build SpcPeImageData.
    //
    // The `file` field is mandatory in practice: the Windows PE SIP rejects a
    // signature whose SpcPeImageData omits it (WinVerifyTrust 0x8009200D,
    // "cryptographic message is not formatted correctly"). Match signtool's
    // empty Unicode file link when there is no page hash.
    let obsolete_link = SpcLink::File(SpcString::Unicode(
        der::asn1::BmpString::from_utf8("")
            .map_err(|e| Error::Signing(format!("BmpString error: {e}")))?,
    ));
    let pe_image_data = SpcPeImageData {
        flags: BitString::from_bytes(&[])
            .map_err(|e| Error::Signing(format!("BitString error: {e}")))?,
        file: Some(obsolete_link),
    };
    let pe_image_data_der = pe_image_data
        .to_der()
        .map_err(|e| Error::Signing(format!("DER encode SpcPeImageData: {e}")))?;

    let spc = SpcIndirectDataContent {
        data: SpcAttributeTypeAndOptionalValue {
            obj_type: oid::SPC_PE_IMAGE_DATA,
            value: Some(
                der::Any::from_der(&pe_image_data_der)
                    .map_err(|e| Error::Signing(format!("Any from DER: {e}")))?,
            ),
        },
        message_digest: DigestInfo {
            digest_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: opts.hash_algo.digest_algorithm_oid(),
                // Explicit NULL parameters, as emitted by osslsigncode; Windows
                // expects the digest AlgorithmIdentifier to carry them.
                parameters: Some(
                    der::Any::from_der(&[0x05, 0x00])
                        .map_err(|e| Error::Signing(format!("NULL params: {e}")))?,
                ),
            },
            digest: OctetString::new(digest)
                .map_err(|e| Error::Signing(format!("OctetString error: {e}")))?,
        },
    };

    spc.to_der()
        .map_err(|e| Error::Signing(format!("DER encode SpcIndirectDataContent: {e}")))
}

/// Build DER-encoded SpcSpOpusInfo.
fn build_opus_info(opts: &SigningOptions) -> Result<Vec<u8>> {
    let program_name = match opts.program_name {
        Some(name) => Some(SpcString::Ascii(
            der::asn1::Ia5String::new(name)
                .map_err(|e| Error::Signing(format!("program name not ASCII: {e}")))?,
        )),
        None => None,
    };

    let more_info = match opts.program_url {
        Some(url) => Some(SpcLink::Url(
            der::asn1::Ia5String::new(url)
                .map_err(|e| Error::Signing(format!("program URL not ASCII: {e}")))?,
        )),
        None => None,
    };

    let opus = SpcSpOpusInfo {
        program_name,
        more_info,
    };

    opus.to_der()
        .map_err(|e| Error::Signing(format!("DER encode SpcSpOpusInfo: {e}")))
}

/// Convert a `const_oid::ObjectIdentifier` to a `bcder::Oid`.
fn oid_to_bcder(oid: &const_oid::ObjectIdentifier) -> Oid {
    Oid(Bytes::copy_from_slice(oid.as_bytes()))
}

struct RawDerValue<'a>(&'a [u8]);

impl bcder::encode::Values for RawDerValue<'_> {
    fn encoded_len(&self, _mode: Mode) -> usize {
        self.0.len()
    }

    fn write_encoded<W: std::io::Write>(&self, _mode: Mode, target: &mut W) -> std::io::Result<()> {
        target.write_all(self.0)
    }
}

/// Turn one complete DER value into a CMS attribute value without wrapping it
/// in an OCTET STRING.
fn attribute_value_from_der(value: &[u8]) -> Result<AttributeValue> {
    Ok(AttributeValue::new(Captured::from_values(
        Mode::Der,
        RawDerValue(value),
    )))
}

// ── Authenticode content-wrapping fixup ──────────────────────────────────
//
// `cryptographic-message-syntax` follows RFC 5652 and wraps the encapsulated
// content in an OCTET STRING:  eContent [0] EXPLICIT OCTET STRING.
// Authenticode does NOT do this — the SpcIndirectDataContent SEQUENCE sits
// directly inside the [0] EXPLICIT tag. If we leave the OCTET STRING wrapper
// in place the Windows PE SIP cannot decode the content and WinVerifyTrust
// fails with 0x8009200D ("cryptographic message is not formatted correctly").
//
// The digest that the signer commits to (the messageDigest signed attribute)
// is computed over the content octets of the SpcIndirectDataContent SEQUENCE.
// Removing only the OCTET STRING wrapper leaves those octets unchanged.

// The fixup is done by byte-splicing rather than by re-encoding the whole
// structure: the SignerInfo — including the authenticated attributes that the
// RSA signature commits to — must survive byte-for-byte, or the signature no
// longer verifies. We only rewrite the length fields of the five nested
// containers on the path down to the content, and drop the OCTET STRING header.

/// Encode a DER definite length.
fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let sig = &be[start..];
        out.push(0x80 | sig.len() as u8);
        out.extend_from_slice(sig);
    }
}

/// Emit a single definite-length TLV.
fn emit_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    encode_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Read one definite-length TLV header at `pos`. Returns
/// `(tag, content_start, content_end)`. All tags in a PKCS#7 SignedData spine
/// are single-byte.
fn read_header(b: &[u8], pos: usize) -> Result<(u8, usize, usize)> {
    let bad = |m: &str| Error::Signing(format!("malformed DER: {m}"));
    if pos + 1 >= b.len() {
        return Err(bad("truncated TLV header"));
    }
    let tag = b[pos];
    let l0 = b[pos + 1];
    let (content_start, len) = if l0 & 0x80 == 0 {
        (pos + 2, l0 as usize)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || pos + 2 + n > b.len() {
            return Err(bad("unsupported length encoding"));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | b[pos + 2 + i] as usize;
        }
        (pos + 2 + n, len)
    };
    let end = content_start + len;
    if end > b.len() {
        return Err(bad("length exceeds buffer"));
    }
    Ok((tag, content_start, end))
}

/// Return the content octets of a top-level DER SEQUENCE (i.e. the value with
/// the outer `SEQUENCE` tag and length removed).
pub(crate) fn der_sequence_content(der: &[u8]) -> Result<&[u8]> {
    let (tag, cs, ce) = read_header(der, 0)?;
    if tag != 0x30 {
        return Err(Error::Signing("expected SEQUENCE".into()));
    }
    Ok(&der[cs..ce])
}

/// Children of a constructed value spanning `[start, end)`, each as
/// `(tag, full_start, content_start, content_end)`.
fn children(b: &[u8], start: usize, end: usize) -> Result<Vec<(u8, usize, usize, usize)>> {
    let mut v = Vec::new();
    let mut p = start;
    while p < end {
        let (tag, cs, ce) = read_header(b, p)?;
        v.push((tag, p, cs, ce));
        p = ce;
    }
    Ok(v)
}

/// Strip the RFC 5652 OCTET STRING wrapper around the Authenticode
/// SpcIndirectDataContent, producing Authenticode-conformant PKCS#7 that the
/// Windows PE SIP accepts. See the module note above.
fn unwrap_authenticode_content(der: &[u8]) -> Result<Vec<u8>> {
    rewrite_authenticode_content(der, false)
}

/// Convert generic RFC 5652 encapsulated content to the representation the
/// Windows Authenticode SIP requires. Already-normalized signatures are
/// returned unchanged.
pub fn normalize_authenticode_signature(der: &[u8]) -> Result<Vec<u8>> {
    unwrap_authenticode_content(der)
}

/// Restore the RFC 5652 OCTET STRING wrapper so a generic CMS parser can read
/// Authenticode content. This is an internal parsing normalization only; PE
/// signatures retain the native Authenticode representation.
pub(crate) fn wrap_authenticode_content(der: &[u8]) -> Result<Vec<u8>> {
    rewrite_authenticode_content(der, true)
}

fn rewrite_authenticode_content(der: &[u8], wrap: bool) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::Signing(format!("cannot fix up PKCS#7 content: {m}"));

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    let (t0, cs0, ce0) = read_header(der, 0)?;
    if t0 != 0x30 {
        return Err(bad("ContentInfo is not a SEQUENCE"));
    }
    let l0_children = children(der, cs0, ce0)?;
    // content [0]
    let l1 = *l0_children
        .iter()
        .find(|c| c.0 == 0xA0)
        .ok_or_else(|| bad("missing [0] content"))?;
    let l1_children = children(der, l1.2, l1.3)?;
    // SignedData SEQUENCE
    let l2 = *l1_children
        .iter()
        .find(|c| c.0 == 0x30)
        .ok_or_else(|| bad("missing SignedData SEQUENCE"))?;
    let l2_children = children(der, l2.2, l2.3)?;
    // encapContentInfo: first inner SEQUENCE of SignedData.
    let l3 = *l2_children
        .iter()
        .find(|c| c.0 == 0x30)
        .ok_or_else(|| bad("missing encapContentInfo"))?;
    let l3_children = children(der, l3.2, l3.3)?;
    // eContent [0]
    let l4 = *l3_children
        .iter()
        .find(|c| c.0 == 0xA0)
        .ok_or_else(|| bad("missing eContent [0]"))?;
    let l4_children = children(der, l4.2, l4.3)?;
    // eContent's sole child is either the RFC 5652 OCTET STRING or the native
    // Authenticode content value.
    let l5 = l4_children.first().ok_or_else(|| bad("empty eContent"))?;
    let new_l4_content = match (wrap, l5.0) {
        (false, 0x04) => der[l5.2..l5.3].to_vec(),
        (true, 0x04) | (false, _) => return Ok(der.to_vec()),
        (true, _) => emit_tlv(0x04, &der[l5.1..l5.3]),
    };

    // Rebuild bottom-up, keeping every non-spine byte verbatim.
    let new_l4 = emit_tlv(0xA0, &new_l4_content);

    // encapContentInfo = [ eContentType OID ][ new eContent ]
    let mut l3_content = Vec::new();
    l3_content.extend_from_slice(&der[l3.2..l4.1]); // siblings before eContent
    l3_content.extend_from_slice(&new_l4);
    l3_content.extend_from_slice(&der[l4.3..l3.3]); // siblings after (none expected)
    let new_l3 = emit_tlv(0x30, &l3_content);

    // SignedData = [ version ][ digestAlgos ][ new encap ][ certs ][ signerInfos ]
    let mut l2_content = Vec::new();
    l2_content.extend_from_slice(&der[l2.2..l3.1]);
    l2_content.extend_from_slice(&new_l3);
    l2_content.extend_from_slice(&der[l3.3..l2.3]);
    let new_l2 = emit_tlv(0x30, &l2_content);

    // content [0] wraps SignedData.
    let mut l1_content = Vec::new();
    l1_content.extend_from_slice(&der[l1.2..l2.1]);
    l1_content.extend_from_slice(&new_l2);
    l1_content.extend_from_slice(&der[l2.3..l1.3]);
    let new_l1 = emit_tlv(0xA0, &l1_content);

    // ContentInfo = [ contentType OID ][ content [0] ]
    let mut l0_content = Vec::new();
    l0_content.extend_from_slice(&der[cs0..l1.1]);
    l0_content.extend_from_slice(&new_l1);
    l0_content.extend_from_slice(&der[l1.3..ce0]);
    Ok(emit_tlv(0x30, &l0_content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticode_content_wrapper_round_trip() {
        let opts = SigningOptions {
            hash_algo: HashAlgorithm::Sha256,
            program_name: None,
            program_url: None,
            rfc3161_urls: Vec::new(),
            authenticode_urls: Vec::new(),
        };
        let cms = build_extract_data_pkcs7(&[0u8; 32], &opts).unwrap();
        let authenticode = normalize_authenticode_signature(&cms).unwrap();

        assert_ne!(authenticode, cms);
        assert_eq!(wrap_authenticode_content(&authenticode).unwrap(), cms);
    }
}
