#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid PE file: {0}")]
    InvalidPe(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("ASN.1 encoding error: {0}")]
    Der(#[from] der::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timestamp error: {0}")]
    Timestamp(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("No signature found")]
    NoSignature,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
