//! Signing through a PKCS#11 token (smartcard / HSM).
//!
//! The private key never leaves the device: we hand the token the bytes to be
//! signed — for Authenticode that is the DER-encoded `signedAttrs` SET — and it
//! returns the RSA signature.
//!
//! The module is loaded at runtime via `libloading`, so nothing about the token
//! needs to exist at compile time.

use std::path::Path;
use std::sync::Mutex;

use bytes::Bytes;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use x509_certificate::{
    CapturedX509Certificate, KeyAlgorithm, KeyInfoSigner, Sign, Signature, SignatureAlgorithm,
    X509CertificateError,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// DER `DigestInfo` prefix for SHA-256, per RFC 8017 §9.2 notes.
///
/// Only needed when the token cannot do `CKM_SHA256_RSA_PKCS` itself and we must
/// fall back to raw `CKM_RSA_PKCS`, which signs a pre-built DigestInfo.
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// How the token will be asked to produce the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningMode {
    /// The token hashes and signs in one operation.
    Sha256RsaPkcs,
    /// The token signs a DigestInfo we build ourselves.
    RawRsaPkcs,
}

/// An RSA signer backed by a PKCS#11 token.
///
/// `Session` is deliberately `!Sync` upstream — a PKCS#11 session must not be used
/// from several threads at once — so it is held behind a `Mutex`. That makes the
/// signer `Sync` and serialises access to the card, which is required anyway since
/// the token processes one operation at a time.
pub struct Pkcs11Signer {
    session: Mutex<Session>,
    private_key: ObjectHandle,
    mode: SigningMode,
    public_key: Bytes,
}

impl Pkcs11Signer {
    /// Open a session on `module_path`, log in, and locate the signing key.
    ///
    /// `key_id` is matched against `CKA_ID` when it parses as hex, and against
    /// `CKA_LABEL` otherwise. An empty `key_id` selects the token's only private
    /// key, failing if it has more than one.
    pub fn open(
        module_path: &Path,
        pin: &str,
        key_id: &str,
        signer_cert: &CapturedX509Certificate,
    ) -> Result<Self> {
        let ctx = Pkcs11::new(module_path).map_err(|e| {
            Error::Signing(format!(
                "failed to load PKCS#11 module {}: {e}",
                module_path.display()
            ))
        })?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Error::Signing(format!("PKCS#11 C_Initialize failed: {e}")))?;

        let slot = *ctx
            .get_slots_with_token()
            .map_err(|e| Error::Signing(format!("PKCS#11 C_GetSlotList failed: {e}")))?
            .first()
            .ok_or_else(|| Error::Signing("no PKCS#11 slot with a token present".into()))?;

        let mode = if supports_sha256_rsa(&ctx, slot) {
            SigningMode::Sha256RsaPkcs
        } else {
            SigningMode::RawRsaPkcs
        };

        let session = ctx
            .open_ro_session(slot)
            .map_err(|e| Error::Signing(format!("PKCS#11 C_OpenSession failed: {e}")))?;

        // C_Login, so the PIN never appears on a command line or in the process table.
        session
            .login(
                UserType::User,
                Some(&AuthPin::new(pin.to_owned().into_boxed_str())),
            )
            .map_err(|e| Error::Signing(format!("PKCS#11 C_Login failed: {e}")))?;

        let private_key = find_private_key(&session, key_id)?;

        Ok(Self {
            session: Mutex::new(session),
            private_key,
            mode,
            public_key: signer_cert.public_key_data(),
        })
    }

    /// Sign `message` on the token.
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        let (mechanism, payload) = match self.mode {
            SigningMode::Sha256RsaPkcs => (Mechanism::Sha256RsaPkcs, message.to_vec()),
            SigningMode::RawRsaPkcs => {
                use sha2::Digest;
                let digest = sha2::Sha256::digest(message);
                let mut payload = SHA256_DIGEST_INFO_PREFIX.to_vec();
                payload.extend_from_slice(&digest);
                (Mechanism::RsaPkcs, payload)
            }
        };

        let session = self
            .session
            .lock()
            .map_err(|_| Error::Signing("PKCS#11 session mutex poisoned".into()))?;

        session
            .sign(&mechanism, self.private_key, &payload)
            .map_err(|e| Error::Signing(format!("PKCS#11 C_Sign failed: {e}")))
    }
}

/// Does the token advertise the combined hash-and-sign mechanism?
fn supports_sha256_rsa(ctx: &Pkcs11, slot: cryptoki::slot::Slot) -> bool {
    ctx.get_mechanism_list(slot)
        .map(|list| list.contains(&MechanismType::SHA256_RSA_PKCS))
        .unwrap_or(false)
}

fn find_private_key(session: &Session, key_id: &str) -> Result<ObjectHandle> {
    let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];

    if !key_id.is_empty() {
        match hex::decode(key_id) {
            Ok(id) => template.push(Attribute::Id(id)),
            Err(_) => template.push(Attribute::Label(key_id.as_bytes().to_vec())),
        }
    }

    let handles = session
        .find_objects(&template)
        .map_err(|e| Error::Signing(format!("PKCS#11 C_FindObjects failed: {e}")))?;

    match handles.len() {
        0 if key_id.is_empty() => Err(Error::Signing("token has no private key".into())),
        0 => Err(Error::Signing(format!(
            "no private key on the token matches id/label {key_id:?}"
        ))),
        1 => Ok(handles[0]),
        n if key_id.is_empty() => Err(Error::Signing(format!(
            "token has {n} private keys; set a key id to choose one"
        ))),
        n => Err(Error::Signing(format!(
            "{n} private keys match id/label {key_id:?}; expected exactly one"
        ))),
    }
}

impl x509_certificate::Signer<Signature> for Pkcs11Signer {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Signature, signature::Error> {
        self.sign_message(message)
            .map(Signature::from)
            .map_err(signature::Error::from_source)
    }
}

impl Sign for Pkcs11Signer {
    #[allow(deprecated)]
    fn sign(
        &self,
        message: &[u8],
    ) -> std::result::Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let signature = self
            .sign_message(message)
            .map_err(|e| X509CertificateError::Other(e.to_string()))?;
        Ok((signature, SignatureAlgorithm::RsaSha256))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        Some(KeyAlgorithm::Rsa)
    }

    fn public_key_data(&self) -> Bytes {
        self.public_key.clone()
    }

    fn signature_algorithm(&self) -> std::result::Result<SignatureAlgorithm, X509CertificateError> {
        Ok(SignatureAlgorithm::RsaSha256)
    }

    /// Always `None` — that is the point of a hardware token.
    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        None
    }

    /// Always `None` — the primes are not extractable from the token.
    fn rsa_primes(
        &self,
    ) -> std::result::Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError>
    {
        Ok(None)
    }
}

impl KeyInfoSigner for Pkcs11Signer {}

/// What a token reports about itself, for operator diagnostics.
#[derive(Debug)]
pub struct ProbeReport {
    pub slot_description: String,
    pub token_label: String,
    pub supports_sha256_rsa_pkcs: bool,
    pub private_key_count: usize,
}

/// Inspect a token without signing anything.
///
/// Intended for a `test-hsm`-style command: it answers whether the module loads,
/// whether the PIN is accepted, whether the combined SHA-256 mechanism is
/// available, and how many private keys are visible.
pub fn probe(module_path: &Path, pin: &str) -> Result<ProbeReport> {
    let ctx = Pkcs11::new(module_path).map_err(|e| {
        Error::Signing(format!(
            "failed to load PKCS#11 module {}: {e}",
            module_path.display()
        ))
    })?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| Error::Signing(format!("PKCS#11 C_Initialize failed: {e}")))?;

    let slot = *ctx
        .get_slots_with_token()
        .map_err(|e| Error::Signing(format!("PKCS#11 C_GetSlotList failed: {e}")))?
        .first()
        .ok_or_else(|| Error::Signing("no PKCS#11 slot with a token present".into()))?;

    let slot_info = ctx
        .get_slot_info(slot)
        .map_err(|e| Error::Signing(format!("PKCS#11 C_GetSlotInfo failed: {e}")))?;
    let token_info = ctx
        .get_token_info(slot)
        .map_err(|e| Error::Signing(format!("PKCS#11 C_GetTokenInfo failed: {e}")))?;

    let supports_sha256_rsa_pkcs = supports_sha256_rsa(&ctx, slot);

    let session = ctx
        .open_ro_session(slot)
        .map_err(|e| Error::Signing(format!("PKCS#11 C_OpenSession failed: {e}")))?;
    session
        .login(
            UserType::User,
            Some(&AuthPin::new(pin.to_owned().into_boxed_str())),
        )
        .map_err(|e| Error::Signing(format!("PKCS#11 C_Login failed: {e}")))?;

    let private_key_count = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .map_err(|e| Error::Signing(format!("PKCS#11 C_FindObjects failed: {e}")))?
        .len();

    Ok(ProbeReport {
        slot_description: slot_info.slot_description().to_string(),
        token_label: token_info.label().to_string(),
        supports_sha256_rsa_pkcs,
        private_key_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Session` is `!Sync` upstream, so the `Mutex` is load-bearing: without it a
    /// multi-threaded server cannot hold the signer in shared state. Assert the
    /// property here rather than discovering it as a confusing error downstream.
    #[test]
    fn signer_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pkcs11Signer>();
    }

    /// The fallback path must produce exactly the RFC 8017 DigestInfo, or the
    /// token will sign the wrong bytes and Windows will reject the signature.
    #[test]
    fn sha256_digest_info_prefix_is_well_formed() {
        use der::{Decode, Encode};

        let digest = [0xabu8; 32];
        let mut encoded = SHA256_DIGEST_INFO_PREFIX.to_vec();
        encoded.extend_from_slice(&digest);

        let parsed = crate::asn1::spc::DigestInfo::from_der(&encoded)
            .expect("prefix + digest should decode as a DigestInfo");
        assert_eq!(
            parsed.digest_algorithm.oid,
            const_oid::db::rfc5912::ID_SHA_256
        );
        assert_eq!(parsed.digest.as_bytes(), digest);
        assert_eq!(parsed.to_der().unwrap(), encoded);
    }
}
