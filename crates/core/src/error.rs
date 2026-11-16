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
    /// KDF parameters below the core's floor: a server could make the key cheap to guess.
    #[error("KDF parameters below the allowed minimum")]
    WeakKdf,
    /// KDF parameters above the core's ceiling (or a Send's tighter one): a server could
    /// make the app allocate or compute without bound.
    #[error("KDF parameters above the allowed maximum")]
    KdfTooStrong,
    #[error("key derivation failed")]
    Kdf,
    #[error("random number generator unavailable")]
    Rng,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid TOTP secret")]
    InvalidTotp,
    #[error("{0}")]
    Import(String),
    #[error("this file is password protected")]
    PasswordRequired,
    /// Sign-in from another device: the words the user picked aren't the request key's own.
    #[error("the chosen words are not this sign-in request's")]
    PhraseMismatch,
    /// Sign-in from another device: the code doesn't belong to this approval.
    #[error("wrong confirmation code")]
    WrongCode,
    /// Sign-in from another device: three wrong codes; the approval is refused for good.
    #[error("too many wrong confirmation codes")]
    TooManyWrongCodes,
    /// Sign-in from another device: the approving app's code hasn't been confirmed yet.
    #[error("the sign-in is not confirmed with the approving app's code yet")]
    NotConfirmed,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    /// The stable code of an error apps tell apart, the same in both bindings (WASM: the
    /// thrown `Error`'s message; UniFFI: the message of the `CoreError` variant of the same
    /// name in CamelCase); `None` for the rest, which carry their description instead.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::Decrypt => "decrypt_failed",
            Self::PasswordRequired => "password_required",
            Self::WeakKdf => "weak_kdf",
            Self::KdfTooStrong => "kdf_too_strong",
            Self::PhraseMismatch => "phrase_mismatch",
            Self::WrongCode => "wrong_code",
            Self::TooManyWrongCodes => "too_many_wrong_codes",
            Self::NotConfirmed => "not_confirmed",
            _ => return None,
        })
    }
}
