use bcder::Oid;
use bytes::Bytes;
use cryptographic_message_syntax::{SignedDataBuilder, SignerBuilder};
use der::asn1::{BitString, OctetString};
use der::{Decode, Encode};
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

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
pub fn pe_digest(f: &mut std::fs::File, pe: &crate::format::pe::PeInfo, algo: HashAlgorithm) -> Result<Vec<u8>> {
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

    // 2. Build the signer with SPC_INDIRECT_DATA as content type
    let spc_indirect_data_oid = oid_to_bcder(&oid::SPC_INDIRECT_DATA);
    let mut signer = SignerBuilder::new(signing_key, signer_cert.clone())
        .content_type(spc_indirect_data_oid)
        .message_id_content(spc_content.clone());

    // Add SPC_SP_OPUS_INFO as a signed attribute if program name or URL are provided
    if opts.program_name.is_some() || opts.program_url.is_some() {
        let opus_info = build_opus_info(opts)?;
        let opus_oid = oid_to_bcder(&oid::SPC_SP_OPUS_INFO);
        signer = signer.signed_attribute_octet_string(opus_oid, &opus_info);
    }

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

    // Add timestamps if URLs are provided
    if !opts.rfc3161_urls.is_empty() || !opts.authenticode_urls.is_empty() {
        return super::timestamp::add_timestamps(
            &pkcs7_der,
            &opts.rfc3161_urls,
            &opts.authenticode_urls,
        );
    }

    Ok(pkcs7_der)
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
    // Build SpcPeImageData
    let pe_image_data = SpcPeImageData {
        flags: BitString::from_bytes(&[0])
            .map_err(|e| Error::Signing(format!("BitString error: {e}")))?,
        file: None, // no page hash for now
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
                parameters: None,
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
