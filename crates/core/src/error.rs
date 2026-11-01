use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Authentication tag mismatch: wrong key, wrong context, or tampered data.
    #[error("decryption failed")]
    Decrypt,
    #[error("unsupported ciphertext version {0}")]
    UnsupportedVersion(u8),
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("KDF parameters below the allowed minimum")]
    WeakKdf,
    #[error("key derivation failed")]
    Kdf,
    #[error("random number generator unavailable")]
    Rng,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid TOTP secret")]
    InvalidTotp,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
