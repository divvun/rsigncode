use std::path::Path;

use x509_certificate::CapturedX509Certificate;

use crate::error::{Error, Result};

/// Load PEM-encoded certificates from a file (supports bundles with multiple certs).
pub fn load_pem_certs(path: &Path) -> Result<Vec<CapturedX509Certificate>> {
    let data = std::fs::read(path)
        .map_err(|e| Error::Certificate(format!("failed to read {}: {e}", path.display())))?;

    let certs = CapturedX509Certificate::from_pem_multiple(&data)
        .map_err(|e| {
            Error::Certificate(format!(
                "failed to parse PEM certs from {}: {e}",
                path.display()
            ))
        })?;

    if certs.is_empty() {
        return Err(Error::Certificate(format!(
            "no certificates found in {}",
            path.display()
        )));
    }

    Ok(certs)
}

/// Find the signer's certificate in the PKCS#7 certificate bag by matching issuer and serial.
pub fn find_signer_cert<'a>(
    signed_data: &'a cryptographic_message_syntax::SignedData,
    signer: &cryptographic_message_syntax::SignerInfo,
) -> Option<&'a CapturedX509Certificate> {
    let (issuer, serial) = signer.certificate_issuer_and_serial()?;

    signed_data.certificates().find(|cert| {
        *cert.serial_number_asn1() == *serial && *cert.issuer_name() == *issuer
    })
}

/// Verify a certificate chain from the signer cert to a trusted CA.
///
/// Walks from `signer_cert`, finds issuer in `cert_bag` or `ca_certs`,
/// verifies each signature, checks that the terminal cert is self-signed or in `ca_certs`.
pub fn verify_chain_to_ca(
    signer_cert: &CapturedX509Certificate,
    cert_bag: &[CapturedX509Certificate],
    ca_certs: &[CapturedX509Certificate],
) -> bool {
    let all_certs: Vec<&CapturedX509Certificate> =
        cert_bag.iter().chain(ca_certs.iter()).collect();

    let mut current = signer_cert;
    let mut visited = std::collections::HashSet::new();

    for _ in 0..20 {
        // depth limit
        let current_data = current.constructed_data().to_vec();

        if !visited.insert(current_data) {
            break; // cycle detected
        }

        // Check if current cert is in the trusted CA set
        if is_cert_in_set(current, ca_certs) {
            return true;
        }

        // Check if self-signed (root)
        if current.verify_signed_by_certificate(current).is_ok() {
            // Self-signed — trusted only if it's in the CA set
            return is_cert_in_set(current, ca_certs);
        }

        // Find issuer
        match find_issuer(current, &all_certs) {
            Some(issuer) => {
                if current.verify_signed_by_certificate(issuer).is_err() {
                    return false;
                }
                current = issuer;
            }
            None => return false,
        }
    }

    false
}

fn is_cert_in_set(cert: &CapturedX509Certificate, set: &[CapturedX509Certificate]) -> bool {
    let cert_data = cert.constructed_data();
    set.iter()
        .any(|c| c.constructed_data() == cert_data)
}

fn find_issuer<'a>(
    cert: &CapturedX509Certificate,
    candidates: &[&'a CapturedX509Certificate],
) -> Option<&'a CapturedX509Certificate> {
    for candidate in candidates {
        if cert.verify_signed_by_certificate(candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}
