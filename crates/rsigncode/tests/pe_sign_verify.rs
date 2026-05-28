use std::fs::File;

use rsigncode::crypto::signing::{self, HashAlgorithm, SigningOptions};
use rsigncode::crypto::verify;
use rsigncode::format::pe;

use x509_certificate::CapturedX509Certificate;
use x509_certificate::InMemorySigningKeyPair;

fn test_exe_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/files/unsigned.exe")
}

// Hardcoded test key pair from x509-certificate crate's test utilities.
const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC2rF88ecfP3lsn\n\
    i21jnGm7IqMG4RyG5nuXlyqmjZdvOW5tjonRyjxFJucp8GyppKwssEVuG4ohmDYi\n\
    pNdHcMjVx1rMplE6FZTvRC7RuFgmFY0PLddDFtFqUi2Z1RCkW/+Q8ebRRlhr4Pj/\n\
    qGsKDzHIgcmADOXzIqzlO+lA9xodxCfT6ay0cjG1WL1+Agf7ngy7OvVr/CDf4pbv\n\
    ooHZ9e+SZmTs1/gXVQDvEZcCk7hH12HBb7I/NHDucOEE7kJklXVGuwb5+Mhw/gKo\n\
    LEcZ644K6Jac8AH9NVM6MdNMxyZt6pR0q08oqeozP+YoIhDrtlRLkRMzw3VS2/v1\n\
    0xh+7SDzAgMBAAECggEBAI8IKs3cgPKnJXKyPmW3jCYl+caiLscF4xIQIConRcKm\n\
    EmwgJpOoqUZwLqJtCXhPYyzenI6Za6/gUcsQjSv4CJkzLkp9k65KRcKO/aXilMrF\n\
    Jx0ShLGYRULds6z24r/+9P4WGugUD5nwnqb3xVAsE4vu68qizs5wgTZAkeP3V3Cj\n\
    2usyWKuLjbXoeR/wuRluq2Q07QXHTjrVziw2JwISn5w6ynHw4ogGDxmIMoAcThiq\n\
    rTNufGA3pmBxq0Sk8umXVRjUBeoKKo/qGpfoxSDzrTxn3wt5gVRpit+oKnxTy2B7\n\
    vwC4+ASo9HEeQX0L6HJBTIxUSsgzeWnf25T+fquhyAkCgYEA2sWEsktyRQMHygjZ\n\
    S6Lb/V4ZsbJwfix6hm7//wbMFDzgtDKSRMp+C265kRf/hdYnyGQDTtan6w9GFsvO\n\
    V12CugxdC07gt2mmikWf9um716X9u5nrEgJvNotwmW1mk28rP55nr/SsKniNkx6y\n\
    JgLjGzVa2Yf9jP0A3+ASYKqFisUCgYEA1cJIuOhnBZGBBdqxG/YPljYmoaAXSrUu\n\
    raZA8a9KeZ/QODWsZwCCGA+OQZIfoLn9WueZf3oRxpIqNSqXW2XE7Xv78Ih01xLN\n\
    d7nzMSTz3GiNv1UNYmm4ZsKf/XDapYCM23oqiNcVw7XBEr1hit1IRB5slm4gESWf\n\
    dNdjMybumFcCgYEA0SeFdfArj08WY1GSbX2GVPViG0E9y2M6wMveczNMaQzKx3yR\n\
    2rK9TrDNOKp44LudzTfQ8c7HOzOfDqxK2bvM/5JSYj1HGhMn5YorJSTRMZrAulqt\n\
    IsqxCLTHMegl6U6fSnNnLhH9h505vS3bo/uepKSd9trMzb4U1/ShnUlp4wECgYEA\n\
    lwwQo0jl85Nb3q0oVZ/MZ9Kf/bnIe6wH7gD7B01cjREW64FR7/717tafKUp+Ou7y\n\
    Tpg1aVTy1qRWWvdbuOPzAfWIk/F4zrmkoyOs6183Sto+v6L0MESQX1zL/SUP+78Y\n\
    ycZL5CJIaOE4K2vTT3MKK8hr5uiulC9HvCKvIGg0VUUCgYBNrn4+tINn6iN0c45/\n\
    0qmmNuM/lLmI5UMgGsbpR0E7zHueiNjZSkPkra8uvV7km8YWoxaCyNpQMi2r/aRp\n\
    VzRAm2HqWPLEtc+BzoVT9ySc8RuOibUH6hJ7b8/secpFQwJUBhxjnxuyKXnIdxsK\n\
    wCqqgSEHwBtdDKP/nox4H+CcMw==\n\
    -----END PRIVATE KEY-----";

const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
    MIIDkzCCAnugAwIBAgIUDNhjvv6ol8EZG5YhNniO4pAiUQEwDQYJKoZIhvcNAQEL\n\
    BQAwWTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM\n\
    B3Rlc3RpbmcxDTALBgNVBAsMBHVuaXQxFDASBgNVBAMMC1VuaXQgVGVzdGVyMB4X\n\
    DTIxMDMxNjE2MDkyOFoXDTI2MDkwNjE2MDkyOFowWTELMAkGA1UEBhMCVVMxEzAR\n\
    BgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB3Rlc3RpbmcxDTALBgNVBAsMBHVu\n\
    aXQxFDASBgNVBAMMC1VuaXQgVGVzdGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n\
    MIIBCgKCAQEAtqxfPHnHz95bJ4ttY5xpuyKjBuEchuZ7l5cqpo2XbzlubY6J0co8\n\
    RSbnKfBsqaSsLLBFbhuKIZg2IqTXR3DI1cdazKZROhWU70Qu0bhYJhWNDy3XQxbR\n\
    alItmdUQpFv/kPHm0UZYa+D4/6hrCg8xyIHJgAzl8yKs5TvpQPcaHcQn0+mstHIx\n\
    tVi9fgIH+54Muzr1a/wg3+KW76KB2fXvkmZk7Nf4F1UA7xGXApO4R9dhwW+yPzRw\n\
    7nDhBO5CZJV1RrsG+fjIcP4CqCxHGeuOCuiWnPAB/TVTOjHTTMcmbeqUdKtPKKnq\n\
    Mz/mKCIQ67ZUS5ETM8N1Utv79dMYfu0g8wIDAQABo1MwUTAdBgNVHQ4EFgQUkiWC\n\
    PwIRoykbi6mtOjWNR0X1eFEwHwYDVR0jBBgwFoAUkiWCPwIRoykbi6mtOjWNR0X1\n\
    eFEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAN4plkAcXZIx\n\
    4KqM5AueYqYtR1y8HAaVz+5BKAWyiQJxhktAJJr7o8Yafde7SrUMfEVGDvPa2xuG\n\
    xhx5d2L3G/FDUhHbsmM3Yp3XTGkS5VwH2nHi6x4HBEpLJZfTbbTDQgS1AdtrQg0V\n\
    VY4ph7n/F0sjJL9pmpTdRx1Z2OrwYpJfWOEIA3NDflYvby9Ubb29uVRsFWrgBijl\n\
    3NIzXHvoJ2Fd+Crkc43+wWZ55hcbwSgkC1/T1mFNzd4klwncH4Rqw2KDkEFdWKmM\n\
    CiRnpyZ52+8FW64s952/SGtMs4P3fFNnWpL3njNDnfxa+r+aWDtz12PJc5FyzlkC\n\
    P4ysBX3CuA==\n\
    -----END CERTIFICATE-----";

fn test_key() -> InMemorySigningKeyPair {
    let key_pem = pem::parse(TEST_KEY_PEM.as_bytes()).unwrap();
    InMemorySigningKeyPair::from_pkcs8_der(key_pem.contents()).unwrap()
}

fn test_cert() -> CapturedX509Certificate {
    CapturedX509Certificate::from_pem(TEST_CERT_PEM.as_bytes()).unwrap()
}

#[test]
fn sign_and_verify_pe_roundtrip() {
    let exe_path = test_exe_path();
    if !exe_path.exists() {
        eprintln!("skipping: {:?} not found", exe_path);
        return;
    }

    let key = test_key();
    let cert = test_cert();

    // Parse PE and compute digest
    let mut input = File::open(&exe_path).unwrap();
    let pe_info = pe::parse_pe(&mut input).unwrap();
    let digest = signing::pe_digest(&mut input, &pe_info, HashAlgorithm::Sha256).unwrap();

    // Create signature
    let opts = SigningOptions {
        hash_algo: HashAlgorithm::Sha256,
        program_name: Some("Test Program"),
        program_url: Some("https://example.com"),
        rfc3161_urls: Vec::new(),
        authenticode_urls: Vec::new(),
    };
    let pkcs7_der = signing::create_authenticode_signature(
        &key,
        cert.clone(),
        vec![],
        &digest,
        &opts,
    )
    .unwrap();

    assert!(!pkcs7_der.is_empty(), "PKCS#7 should not be empty");

    // Write signed PE to temp file in target dir (avoid Windows Defender locks)
    let signed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test_signed.bin");
    pe::write_signed_pe(&mut input, &signed_path, &pe_info, &pkcs7_der)
        .unwrap_or_else(|e| panic!("write_signed_pe failed: {e}"));

    // Verify the signed file has a signature
    let mut signed = File::open(&signed_path).unwrap();
    let signed_pe = pe::parse_pe(&mut signed).unwrap();
    assert!(signed_pe.sigpos > 0, "signed file should have a signature");
    assert!(signed_pe.siglen > 0);

    // Extract the signature blob
    let extracted = pe::extract_signature(&mut signed, &signed_pe).unwrap();
    assert!(extracted.is_some(), "should be able to extract signature");

    // Verify digest of signed file matches original unsigned digest
    let verify_digest =
        signing::pe_digest(&mut signed, &signed_pe, HashAlgorithm::Sha256).unwrap();
    assert_eq!(
        digest, verify_digest,
        "digest should match between unsigned and signed file"
    );

    // Full verification (digest + cryptographic signature)
    let mut signed = File::open(&signed_path).unwrap();
    verify::verify_pe(&mut signed).unwrap();

    // Cleanup
    std::fs::remove_file(&signed_path).ok();
}

#[test]
fn unsigned_pe_has_no_signature() {
    let exe_path = test_exe_path();
    if !exe_path.exists() {
        eprintln!("skipping: {:?} not found", exe_path);
        return;
    }

    let mut f = File::open(&exe_path).unwrap();
    let pe_info = pe::parse_pe(&mut f).unwrap();
    assert_eq!(pe_info.sigpos, 0);
    assert_eq!(pe_info.siglen, 0);

    let sig = pe::extract_signature(&mut f, &pe_info).unwrap();
    assert!(sig.is_none());
}

/// Test the sign.necessary.nu workflow: extract-data → sign → attach-signature → verify
#[test]
fn extract_data_attach_signature_roundtrip() {
    let exe_path = test_exe_path();
    if !exe_path.exists() {
        eprintln!("skipping: {:?} not found", exe_path);
        return;
    }

    let key = test_key();
    let cert = test_cert();

    // Step 1: extract-data — build the PKCS#7 envelope with SpcIndirectDataContent
    let mut input = File::open(&exe_path).unwrap();
    let pe_info = pe::parse_pe(&mut input).unwrap();
    let digest = signing::pe_digest(&mut input, &pe_info, HashAlgorithm::Sha256).unwrap();

    let opts = SigningOptions {
        hash_algo: HashAlgorithm::Sha256,
        program_name: None,
        program_url: None,
        rfc3161_urls: Vec::new(),
        authenticode_urls: Vec::new(),
    };
    let extract_data_pkcs7 = signing::build_extract_data_pkcs7(&digest, &opts).unwrap();

    // Verify the extract-data output is parseable as PKCS#7
    let parsed = cryptographic_message_syntax::SignedData::parse_ber(&extract_data_pkcs7)
        .expect("extract-data output should be valid PKCS#7");
    assert!(
        parsed.signed_content().is_some(),
        "extract-data PKCS#7 should have encapsulated content"
    );

    // Step 2: "remote sign" — in reality we sign locally with the full signing function
    let signed_pkcs7 = signing::create_authenticode_signature(
        &key,
        cert.clone(),
        vec![],
        &digest,
        &opts,
    )
    .unwrap();

    // Step 3: attach-signature — embed the signed PKCS#7 into the PE
    let attached_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test_attached.bin");
    pe::write_signed_pe(&mut input, &attached_path, &pe_info, &signed_pkcs7)
        .expect("attach-signature should succeed");

    // Step 4: verify
    let mut attached = File::open(&attached_path).unwrap();
    verify::verify_pe(&mut attached).expect("attached signature should verify");

    // Verify the PE structure is sane
    let mut attached = File::open(&attached_path).unwrap();
    let attached_pe = pe::parse_pe(&mut attached).unwrap();
    assert!(attached_pe.sigpos > 0);
    assert!(attached_pe.siglen > 0);

    std::fs::remove_file(&attached_path).ok();
}

/// Test the real sign.necessary.nu remote signing flow.
///
/// Requires `SIGN_NECESSARY_TOKEN` env var. Skipped if not set.
/// Flow: extract-data → POST to sign.necessary.nu → attach-signature → verify
#[test]
fn sign_necessary_nu_remote() {
    let token = match std::env::var("SIGN_NECESSARY_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("skipping: SIGN_NECESSARY_TOKEN not set");
            return;
        }
    };

    let exe_path = test_exe_path();
    if !exe_path.exists() {
        eprintln!("skipping: {:?} not found", exe_path);
        return;
    }

    // Step 1: extract-data
    let mut input = File::open(&exe_path).unwrap();
    let pe_info = pe::parse_pe(&mut input).unwrap();
    let digest = signing::pe_digest(&mut input, &pe_info, HashAlgorithm::Sha256).unwrap();

    let opts = SigningOptions {
        hash_algo: HashAlgorithm::Sha256,
        program_name: None,
        program_url: None,
        rfc3161_urls: Vec::new(),
        authenticode_urls: Vec::new(),
    };
    let extract_data = signing::build_extract_data_pkcs7(&digest, &opts).unwrap();

    // Step 2: POST to sign.necessary.nu
    let client = reqwest::blocking::Client::new();
    let response = client
        .post("https://sign.necessary.nu/windows/sign")
        .bearer_auth(&token)
        .header("content-type", "application/octet-stream")
        .body(extract_data)
        .send()
        .expect("failed to contact sign.necessary.nu");

    assert!(
        response.status().is_success(),
        "sign.necessary.nu returned {}",
        response.status()
    );

    let signed_pkcs7 = response.bytes().expect("failed to read response body");

    // Verify the response is valid PKCS#7
    cryptographic_message_syntax::SignedData::parse_ber(&signed_pkcs7)
        .expect("response should be valid PKCS#7 SignedData");

    // Step 3: attach-signature
    let signed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test_necessary_signed.bin");
    pe::write_signed_pe(&mut input, &signed_path, &pe_info, &signed_pkcs7)
        .expect("attach-signature should succeed");

    // Step 4: verify
    let mut signed = File::open(&signed_path).unwrap();
    verify::verify_pe(&mut signed).expect("signature from sign.necessary.nu should verify");

    std::fs::remove_file(&signed_path).ok();
}

// ── Rich verify tests ─────────────────────────────────────────────────

use rsigncode::crypto::verify::VerifyOptions;

#[test]
fn verify_rich_roundtrip() {
    let exe_path = test_exe_path();
    if !exe_path.exists() {
        eprintln!("skipping: {:?} not found", exe_path);
        return;
    }

    let key = test_key();
    let cert = test_cert();

    let mut input = File::open(&exe_path).unwrap();
    let pe_info = pe::parse_pe(&mut input).unwrap();
    let digest = signing::pe_digest(&mut input, &pe_info, HashAlgorithm::Sha256).unwrap();

    let opts = SigningOptions {
        hash_algo: HashAlgorithm::Sha256,
        program_name: Some("RichVerifyTest"),
        program_url: Some("https://test.example.com"),
        rfc3161_urls: Vec::new(),
        authenticode_urls: Vec::new(),
    };
    let pkcs7_der = signing::create_authenticode_signature(
        &key,
        cert.clone(),
        vec![],
        &digest,
        &opts,
    )
    .unwrap();

    let signed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test_rich_verify.bin");
    pe::write_signed_pe(&mut input, &signed_path, &pe_info, &pkcs7_der).unwrap();

    let mut signed = File::open(&signed_path).unwrap();
    let result = verify::verify_pe_rich(&mut signed, &VerifyOptions::default()).unwrap();

    assert!(result.all_ok(), "verification should succeed");
    assert_eq!(result.signatures.len(), 1);

    let sig = &result.signatures[0];
    assert_eq!(sig.index, 0);
    assert_eq!(sig.digest_algorithm, "SHA256");
    assert!(sig.digest_ok);
    assert!(sig.signature_ok);
    assert!(!sig.message_digest.is_empty());

    // Print the result for manual inspection
    verify::print_verify_result(&result);

    std::fs::remove_file(&signed_path).ok();
}

#[test]
fn verify_with_self_signed_ca() {
    let exe_path = test_exe_path();
    if !exe_path.exists() {
        eprintln!("skipping: {:?} not found", exe_path);
        return;
    }

    let key = test_key();
    let cert = test_cert();

    let mut input = File::open(&exe_path).unwrap();
    let pe_info = pe::parse_pe(&mut input).unwrap();
    let digest = signing::pe_digest(&mut input, &pe_info, HashAlgorithm::Sha256).unwrap();

    let opts = SigningOptions {
        hash_algo: HashAlgorithm::Sha256,
        program_name: None,
        program_url: None,
        rfc3161_urls: Vec::new(),
        authenticode_urls: Vec::new(),
    };
    let pkcs7_der = signing::create_authenticode_signature(
        &key,
        cert.clone(),
        vec![],
        &digest,
        &opts,
    )
    .unwrap();

    let signed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test_ca_verify.bin");
    pe::write_signed_pe(&mut input, &signed_path, &pe_info, &pkcs7_der).unwrap();

    // Verify with the self-signed cert as CA — should pass chain verification
    let mut signed = File::open(&signed_path).unwrap();
    let verify_opts = VerifyOptions {
        ca_certs: vec![cert.clone()],
        ..Default::default()
    };
    let result = verify::verify_pe_rich(&mut signed, &verify_opts).unwrap();

    assert!(result.all_ok());
    assert_eq!(result.signatures[0].chain_ok, Some(true));

    std::fs::remove_file(&signed_path).ok();
}
