use std::fmt;
use std::fs::File;

use bcder::Oid;
use bytes::Bytes;
use cryptographic_message_syntax::SignedData;
use der::Decode;
use sha2::Digest;
use x509_certificate::CapturedX509Certificate;

use crate::asn1::spc::{SpcIndirectDataContent, SpcSpOpusInfo, SpcString};
use crate::crypto::chain;
use crate::error::{Error, Result};
use crate::format::pe;
use crate::oid;

type Rfc5652SignedData = cryptographic_message_syntax::asn1::rfc5652::SignedData;

// ── Public types ──────────────────────────────────────────────────────

/// Options controlling verification behavior.
#[derive(Default)]
pub struct VerifyOptions {
    pub ca_certs: Vec<CapturedX509Certificate>,
    pub tsa_ca_certs: Vec<CapturedX509Certificate>,
    pub require_leaf_hash: Option<String>,
    pub ignore_timestamp: bool,
    pub ignore_cdp: bool,
    pub ignore_crl: bool,
    pub verbose: bool,
    pub time: Option<i64>,
}

/// Result of verifying all signatures in a file.
pub struct VerifyResult {
    pub signatures: Vec<SignatureResult>,
}

impl VerifyResult {
    pub fn all_ok(&self) -> bool {
        !self.signatures.is_empty()
            && self.signatures.iter().all(|s| {
                s.digest_ok
                    && s.signature_ok
                    && s.chain_ok.unwrap_or(true)
                    && s.timestamp_ok.unwrap_or(true)
                    && s.leaf_hash_ok.unwrap_or(true)
            })
    }
}

/// Result of verifying a single signature.
pub struct SignatureResult {
    pub index: usize,
    pub digest_algorithm: String,
    pub message_digest: Vec<u8>,
    pub signing_time: Option<chrono::DateTime<chrono::Utc>>,
    pub program_name: Option<String>,
    pub program_url: Option<String>,
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub signer_serial: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub timestamp_info: Option<TimestampInfo>,
    pub digest_ok: bool,
    pub signature_ok: bool,
    pub chain_ok: Option<bool>,
    pub timestamp_ok: Option<bool>,
    pub leaf_hash_ok: Option<bool>,
}

pub struct TimestampInfo {
    pub timestamp_type: TimestampType,
    pub time: Option<chrono::DateTime<chrono::Utc>>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub hash_algorithm: Option<String>,
}

#[derive(Debug)]
pub enum TimestampType {
    Rfc3161,
    Authenticode,
}

impl fmt::Display for TimestampType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rfc3161 => write!(f, "RFC 3161"),
            Self::Authenticode => write!(f, "Authenticode"),
        }
    }
}

// ── Backward-compatible API ───────────────────────────────────────────

/// Verify the Authenticode signature on a PE file (basic check only).
///
/// Returns Ok(()) if valid, Err otherwise.
pub fn verify_pe(input: &mut File) -> Result<()> {
    let result = verify_pe_rich(input, &VerifyOptions::default())?;
    if result.all_ok() {
        Ok(())
    } else {
        Err(Error::Verification("signature verification failed".into()))
    }
}

// ── Rich verification ─────────────────────────────────────────────────

/// Verify the Authenticode signature on a PE file with full diagnostics.
pub fn verify_pe_rich(input: &mut File, opts: &VerifyOptions) -> Result<VerifyResult> {
    let pe_info = pe::parse_pe(input)?;

    let pkcs7_der = pe::extract_signature(input, &pe_info)?.ok_or(Error::NoSignature)?;

    // Collect all signatures: primary + nested
    let sig_blobs = collect_signature_blobs(&pkcs7_der)?;

    let mut signatures = Vec::new();

    for (index, blob) in sig_blobs.iter().enumerate() {
        let signed_data = SignedData::parse_ber(blob)
            .map_err(|e| Error::Verification(format!("failed to parse SignedData: {e}")))?;

        // ── Extract info ──
        let mut sig_result = extract_signature_info(&signed_data, blob, index);

        // ── Verify digest ──
        sig_result.digest_ok = verify_digest(input, &pe_info, &signed_data).unwrap_or(false);

        // ── Verify cryptographic signature ──
        sig_result.signature_ok = verify_crypto_signature(&signed_data);

        // ── Verify certificate chain ──
        if !opts.ca_certs.is_empty() {
            sig_result.chain_ok = Some(verify_chain(&signed_data, &opts.ca_certs));
        }

        // ── Verify timestamp ──
        if !opts.ignore_timestamp {
            sig_result.timestamp_ok = verify_timestamp(blob);
        }

        // ── Verify leaf hash ──
        if let Some(ref spec) = opts.require_leaf_hash {
            sig_result.leaf_hash_ok = Some(verify_leaf_hash_for_signer(&signed_data, spec));
        }

        signatures.push(sig_result);
    }

    Ok(VerifyResult { signatures })
}

/// Print verification results in the osslsigncode C tool format.
pub fn print_verify_result(result: &VerifyResult) {
    for sig in &result.signatures {
        let primary = if sig.index == 0 {
            "  (Primary Signature)"
        } else {
            ""
        };
        println!("\nSignature Index: {}{}\n", sig.index, primary);

        println!("Message digest algorithm: {}", sig.digest_algorithm);

        // Authenticated attributes
        println!("\nAuthenticated attributes:");
        println!("\tMessage digest: {}", hex::encode(&sig.message_digest));
        if let Some(ref t) = sig.signing_time {
            println!("\tSigning time: {}", t.format("%b %e %H:%M:%S %Y UTC"));
        }
        if let Some(ref name) = sig.program_name {
            println!("\tText description: {name}");
        }
        if let Some(ref url) = sig.program_url {
            println!("\tURL description: {url}");
        }

        // Timestamp info
        if let Some(ref ts) = sig.timestamp_info {
            println!("\nCountersignatures:");
            if let Some(ref t) = ts.time {
                println!("\tTimestamp time: {}", t.format("%b %e %H:%M:%S %Y UTC"));
            }
            if let Some(ref algo) = ts.hash_algorithm {
                println!("\tHash Algorithm: {algo}");
            }
            if let Some(ref issuer) = ts.issuer {
                println!("\tIssuer: {issuer}");
            }
            if let Some(ref serial) = ts.serial {
                println!("\tSerial: {serial}");
            }
        }

        // Signer certificate
        println!("\nSigner's certificate:");
        println!("\t------------------");
        if let Some(ref subj) = sig.signer_subject {
            println!("\tSigner #{}:", sig.index);
            println!("\t\tSubject: {subj}");
        }
        if let Some(ref issuer) = sig.signer_issuer {
            println!("\t\tIssuer : {issuer}");
        }
        if let Some(ref serial) = sig.signer_serial {
            println!("\t\tSerial : {serial}");
        }
        if sig.not_before.is_some() || sig.not_after.is_some() {
            println!("\t\tCertificate expiration date:");
            if let Some(ref nb) = sig.not_before {
                println!("\t\t\tnotBefore : {nb}");
            }
            if let Some(ref na) = sig.not_after {
                println!("\t\t\tnotAfter : {na}");
            }
        }

        // Leaf hash
        if let Some(ok) = sig.leaf_hash_ok {
            println!(
                "\nLeaf hash match: {}",
                if ok { "ok" } else { "failed" }
            );
        }

        // Timestamp verification
        match sig.timestamp_ok {
            Some(true) => println!("\nTimestamp Server Signature verification: ok"),
            Some(false) => println!("\nTimestamp Server Signature verification: failed"),
            None => {
                if sig.timestamp_info.is_some() {
                    println!("\nTimestamp Server Signature verification is disabled");
                } else {
                    println!("\nTimestamp is not available");
                }
            }
        }

        // Chain verification
        match sig.chain_ok {
            Some(true) => println!("Signature CRL verification: ok"),
            Some(false) => println!("Signature CRL verification: failed"),
            None => {}
        }

        // Final verdict
        println!(
            "Signature verification: {}\n",
            if sig.digest_ok && sig.signature_ok {
                "ok"
            } else {
                "failed"
            }
        );
    }

    println!(
        "Number of verified signatures: {}",
        result.signatures.len()
    );
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Collect the primary signature + any nested signatures.
fn collect_signature_blobs(pkcs7_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut blobs = vec![pkcs7_der.to_vec()];

    // Parse at low level to find nested signatures in unsigned attributes
    let low_level = Rfc5652SignedData::decode_ber(pkcs7_der)
        .map_err(|e| Error::Verification(format!("failed to parse SignedData: {e}")))?;

    let nested_oid = Oid(Bytes::copy_from_slice(oid::SPC_NESTED_SIGNATURE.as_bytes()));

    for signer_info in low_level.signer_infos.iter() {
        if let Some(ref attrs) = signer_info.unsigned_attributes {
            for attr in attrs.iter() {
                if attr.typ == nested_oid {
                    for value in &attr.values {
                        let raw = value.as_slice();
                        blobs.push(raw.to_vec());
                    }
                }
            }
        }
    }

    Ok(blobs)
}

/// Extract metadata about a signature.
fn extract_signature_info(
    signed_data: &SignedData,
    raw_der: &[u8],
    index: usize,
) -> SignatureResult {
    let mut result = SignatureResult {
        index,
        digest_algorithm: String::new(),
        message_digest: Vec::new(),
        signing_time: None,
        program_name: None,
        program_url: None,
        signer_subject: None,
        signer_issuer: None,
        signer_serial: None,
        not_before: None,
        not_after: None,
        timestamp_info: None,
        digest_ok: false,
        signature_ok: false,
        chain_ok: None,
        timestamp_ok: None,
        leaf_hash_ok: None,
    };

    // Extract digest algorithm and digest from SpcIndirectDataContent
    if let Some(content) = signed_data.signed_content() {
        if let Ok(spc) = SpcIndirectDataContent::from_der(content) {
            result.digest_algorithm = oid_to_algo_name(&spc.message_digest.digest_algorithm.oid);
            result.message_digest = spc.message_digest.digest.as_bytes().to_vec();
        }
    }

    // Extract signer info
    for signer in signed_data.signers() {
        // Signed attributes
        if let Some(attrs) = signer.signed_attributes() {
            result.signing_time = attrs.signing_time().cloned();

            // Scan raw signed attributes for SPC_SP_OPUS_INFO
            let opus_oid = Oid(Bytes::copy_from_slice(oid::SPC_SP_OPUS_INFO.as_bytes()));
            for attr in attrs.attributes().iter() {
                if attr.typ == opus_oid {
                    if let Some(value) = attr.values.first() {
                        let raw = value.as_slice();
                        if let Ok(opus) = SpcSpOpusInfo::from_der(&raw) {
                            result.program_name = opus.program_name.map(|s| match s {
                                SpcString::Ascii(a) => a.to_string(),
                                SpcString::Unicode(u) => u.to_string(),
                            });
                            result.program_url = opus.more_info.map(|l| match l {
                                crate::asn1::spc::SpcLink::Url(u) => u.to_string(),
                                _ => String::new(),
                            });
                        }
                    }
                }
            }
        }

        // Find signer certificate
        if let Some(cert) = chain::find_signer_cert(signed_data, signer) {
            result.signer_subject = cert.subject_common_name();
            result.signer_issuer = cert.issuer_common_name();
            let serial_bytes: &[u8] = cert.serial_number_asn1().as_ref();
            result.signer_serial = Some(hex::encode(serial_bytes));
            let nb = cert.validity_not_before();
            result.not_before = Some(nb.to_string());
            let na = cert.validity_not_after();
            result.not_after = Some(na.to_string());
        }

        break; // only process first signer
    }

    // Extract timestamp info from low-level unsigned attributes
    result.timestamp_info = extract_timestamp_info(raw_der, signed_data);

    result
}

/// Extract timestamp info by scanning unsigned attributes at the low level.
fn extract_timestamp_info(raw_der: &[u8], high_level: &SignedData) -> Option<TimestampInfo> {
    // First check the standard OID via the high-level API
    for signer in high_level.signers() {
        if let Ok(Some(tst_signed_data)) = signer.time_stamp_token_signed_data() {
            return extract_timestamp_from_signed_data(&tst_signed_data, TimestampType::Rfc3161);
        }
    }

    // Check raw unsigned attributes for Microsoft OIDs
    let low_level = Rfc5652SignedData::decode_ber(raw_der).ok()?;

    let spc_rfc3161_oid = Oid(Bytes::copy_from_slice(oid::SPC_RFC3161.as_bytes()));
    let counter_sig_oid =
        Oid(Bytes::copy_from_slice(oid::PKCS9_COUNTER_SIGNATURE.as_bytes()));

    for signer_info in low_level.signer_infos.iter() {
        if let Some(ref attrs) = signer_info.unsigned_attributes {
            for attr in attrs.iter() {
                if attr.typ == spc_rfc3161_oid {
                    if let Some(value) = attr.values.first() {
                        let raw = value.as_slice();
                        if let Ok(sd) = Rfc5652SignedData::decode_ber(raw) {
                            if let Ok(hl) = SignedData::try_from(&sd) {
                                return extract_timestamp_from_signed_data(
                                    &hl,
                                    TimestampType::Rfc3161,
                                );
                            }
                        }
                    }
                } else if attr.typ == counter_sig_oid {
                    return Some(TimestampInfo {
                        timestamp_type: TimestampType::Authenticode,
                        time: None,
                        issuer: None,
                        serial: None,
                        hash_algorithm: None,
                    });
                }
            }
        }
    }

    None
}

/// Extract timestamp details from a timestamp's SignedData.
fn extract_timestamp_from_signed_data(
    signed_data: &SignedData,
    ts_type: TimestampType,
) -> Option<TimestampInfo> {
    let mut info = TimestampInfo {
        timestamp_type: ts_type,
        time: None,
        issuer: None,
        serial: None,
        hash_algorithm: None,
    };

    for signer in signed_data.signers() {
        if let Some(attrs) = signer.signed_attributes() {
            info.time = attrs.signing_time().cloned();
        }

        info.hash_algorithm = Some(format!("{:?}", signer.digest_algorithm()));

        if let Some(cert) = chain::find_signer_cert(signed_data, signer) {
            info.issuer = cert.issuer_common_name();
            let serial_bytes: &[u8] = cert.serial_number_asn1().as_ref();
            info.serial = Some(hex::encode(serial_bytes));
        }

        break;
    }

    Some(info)
}

/// Verify the Authenticode digest matches the file.
fn verify_digest(
    input: &mut File,
    pe_info: &pe::PeInfo,
    signed_data: &SignedData,
) -> Result<bool> {
    let encap_content = signed_data
        .signed_content()
        .ok_or_else(|| Error::Verification("no encapsulated content in signature".into()))?;

    let spc = SpcIndirectDataContent::from_der(encap_content).map_err(|e| {
        Error::Verification(format!("failed to decode SpcIndirectDataContent: {e}"))
    })?;

    let expected_digest = spc.message_digest.digest.as_bytes();
    let algo_oid = spc.message_digest.digest_algorithm.oid;
    let actual_digest = compute_pe_digest(input, pe_info, &algo_oid)?;

    Ok(actual_digest == expected_digest)
}

/// Verify the cryptographic signature.
fn verify_crypto_signature(signed_data: &SignedData) -> bool {
    let mut ok = false;
    for signer in signed_data.signers() {
        if signer
            .verify_signature_with_signed_data(signed_data)
            .is_err()
        {
            return false;
        }
        ok = true;
    }
    ok
}

/// Verify the certificate chain to a trusted CA.
fn verify_chain(signed_data: &SignedData, ca_certs: &[CapturedX509Certificate]) -> bool {
    for signer in signed_data.signers() {
        if let Some(cert) = chain::find_signer_cert(signed_data, signer) {
            let cert_bag: Vec<CapturedX509Certificate> =
                signed_data.certificates().cloned().collect();
            return chain::verify_chain_to_ca(cert, &cert_bag, ca_certs);
        }
    }
    false
}

/// Verify any timestamp present in the signature.
fn verify_timestamp(pkcs7_der: &[u8]) -> Option<bool> {
    let signed_data = SignedData::parse_ber(pkcs7_der).ok()?;

    // Check standard OID timestamp token via high-level API
    for signer in signed_data.signers() {
        if let Ok(Some(())) = signer.verify_time_stamp_token() {
            return Some(true);
        }
    }

    // Check Microsoft OID at the low level
    let low_level = Rfc5652SignedData::decode_ber(pkcs7_der).ok()?;
    let spc_rfc3161_oid = Oid(Bytes::copy_from_slice(oid::SPC_RFC3161.as_bytes()));

    for signer_info in low_level.signer_infos.iter() {
        if let Some(ref attrs) = signer_info.unsigned_attributes {
            for attr in attrs.iter() {
                if attr.typ == spc_rfc3161_oid {
                    if let Some(value) = attr.values.first() {
                        let raw = value.as_slice();
                        if let Ok(sd) = Rfc5652SignedData::decode_ber(raw) {
                            if let Ok(high_level) = SignedData::try_from(&sd) {
                                let mut ok = true;
                                for ts_signer in high_level.signers() {
                                    if ts_signer
                                        .verify_signature_with_signed_data(&high_level)
                                        .is_err()
                                    {
                                        ok = false;
                                    }
                                }
                                return Some(ok);
                            }
                        }
                    }
                    return Some(false);
                }
            }
        }
    }

    None // no timestamp found
}

/// Verify the leaf certificate hash.
fn verify_leaf_hash_for_signer(signed_data: &SignedData, spec: &str) -> bool {
    let Some((algo, expected_hex)) = spec.split_once(':') else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(expected_hex) else {
        return false;
    };

    for signer in signed_data.signers() {
        if let Some(cert) = chain::find_signer_cert(signed_data, signer) {
            let cert_der = cert.constructed_data();

            let actual = match algo.to_lowercase().as_str() {
                "sha1" => {
                    use sha1::Digest as _;
                    sha1::Sha1::digest(&cert_der).to_vec()
                }
                "sha256" => sha2::Sha256::digest(&cert_der).to_vec(),
                "sha384" => sha2::Sha384::digest(&cert_der).to_vec(),
                "sha512" => sha2::Sha512::digest(&cert_der).to_vec(),
                _ => return false,
            };

            return actual == expected_bytes;
        }
    }
    false
}

fn compute_pe_digest(
    f: &mut File,
    pe_info: &pe::PeInfo,
    algo_oid: &const_oid::ObjectIdentifier,
) -> Result<Vec<u8>> {
    use const_oid::db::rfc5912;

    if *algo_oid == rfc5912::ID_SHA_256 {
        let mut hasher = sha2::Sha256::new();
        pe::authenticode_digest(f, pe_info, &mut hasher)?;
        Ok(hasher.finalize().to_vec())
    } else if *algo_oid == rfc5912::ID_SHA_384 {
        let mut hasher = sha2::Sha384::new();
        pe::authenticode_digest(f, pe_info, &mut hasher)?;
        Ok(hasher.finalize().to_vec())
    } else if *algo_oid == rfc5912::ID_SHA_512 {
        let mut hasher = sha2::Sha512::new();
        pe::authenticode_digest(f, pe_info, &mut hasher)?;
        Ok(hasher.finalize().to_vec())
    } else if *algo_oid == rfc5912::ID_SHA_1 {
        let mut hasher = sha1::Sha1::new();
        pe::authenticode_digest(f, pe_info, &mut hasher)?;
        Ok(hasher.finalize().to_vec())
    } else {
        Err(Error::Verification(format!(
            "unsupported digest algorithm OID: {algo_oid}"
        )))
    }
}

fn oid_to_algo_name(oid: &const_oid::ObjectIdentifier) -> String {
    use const_oid::db::rfc5912;
    if *oid == rfc5912::ID_SHA_256 {
        "SHA256".into()
    } else if *oid == rfc5912::ID_SHA_384 {
        "SHA384".into()
    } else if *oid == rfc5912::ID_SHA_512 {
        "SHA512".into()
    } else if *oid == rfc5912::ID_SHA_1 {
        "SHA1".into()
    } else {
        format!("{oid}")
    }
}
