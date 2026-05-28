use std::path::Path;

use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

use crate::error::{Error, Result};

/// Loaded key material for signing.
pub struct KeyMaterial {
    pub signing_key: InMemorySigningKeyPair,
    pub signer_cert: CapturedX509Certificate,
    pub extra_certs: Vec<CapturedX509Certificate>,
}

impl KeyMaterial {
    /// Load signing key and certificate from PEM files.
    pub fn from_pem(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_data = std::fs::read(cert_path)?;
        let key_data = std::fs::read(key_path)?;

        let certs = CapturedX509Certificate::from_pem_multiple(&cert_data)
            .map_err(|e| Error::Certificate(format!("failed to parse cert PEM: {e}")))?;

        let signer_cert = certs
            .first()
            .ok_or_else(|| Error::Certificate("no certificates in PEM file".into()))?
            .clone();

        let extra_certs = certs.into_iter().skip(1).collect();

        let signing_key = InMemorySigningKeyPair::from_pkcs8_pem(&key_data)
            .map_err(|e| Error::Certificate(format!("failed to parse key PEM: {e}")))?;

        Ok(KeyMaterial {
            signing_key,
            signer_cert,
            extra_certs,
        })
    }

    /// Load signing key and certificate from DER files.
    pub fn from_der(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_data = std::fs::read(cert_path)?;
        let key_data = std::fs::read(key_path)?;

        let signer_cert = CapturedX509Certificate::from_der(cert_data)
            .map_err(|e| Error::Certificate(format!("failed to parse cert DER: {e}")))?;

        let signing_key = InMemorySigningKeyPair::from_pkcs8_der(&key_data)
            .map_err(|e| Error::Certificate(format!("failed to parse key DER: {e}")))?;

        Ok(KeyMaterial {
            signing_key,
            signer_cert,
            extra_certs: vec![],
        })
    }

    /// Load an additional certificate file (PEM) to include in the chain.
    pub fn add_extra_certs_pem(&mut self, path: &Path) -> Result<()> {
        let data = std::fs::read(path)?;
        let certs = CapturedX509Certificate::from_pem_multiple(&data)
            .map_err(|e| Error::Certificate(format!("failed to parse extra certs: {e}")))?;
        self.extra_certs.extend(certs);
        Ok(())
    }

    /// All certificates to include in the PKCS#7 (signer + extras).
    pub fn all_certs(&self) -> Vec<CapturedX509Certificate> {
        let mut certs = vec![self.signer_cert.clone()];
        certs.extend(self.extra_certs.iter().cloned());
        certs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_test_pem_certs() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/certs");
        let cert = base.join("cert.pem");
        let key = base.join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test certs not generated yet");
            return;
        }
        let km = KeyMaterial::from_pem(&cert, &key).unwrap();
        assert!(!km.all_certs().is_empty());
    }
}
