//! Master password + optional Secret Key → Account Unlock Key (AUK).

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{SymmetricKey, hkdf_key, random_bytes};
use crate::{Error, Result};

/// Floors enforced by every client, regardless of what the server sends, so a
/// malicious server cannot downgrade the KDF.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
pub const MIN_ITERATIONS: u32 = 3;
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
pub const MAX_ITERATIONS: u32 = 20;
pub const MAX_PARALLELISM: u32 = 8;

const SECRET_KEY_PREFIX: &str = "PA1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// 16 random bytes, base64url.
    pub salt: String,
}

impl KdfParams {
    pub fn new_default() -> Result<Self> {
        Ok(Self {
            memory_kib: 128 * 1024,
            iterations: 3,
            parallelism: 1,
            salt: crate::item::b64(&random_bytes::<16>()?),
        })
    }

    pub fn validate(&self) -> Result<()> {
        let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_PARALLELISM).contains(&self.parallelism);
        if ok { Ok(()) } else { Err(Error::WeakKdf) }
    }
}

/// A 128-bit Secret Key, formatted `PA1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XX`.
pub struct SecretKey([u8; 16]);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    pub fn format(&self) -> String {
        let enc = data_encoding::BASE32_NOPAD.encode(&self.0);
        let groups: Vec<&str> = enc
            .as_bytes()
            .chunks(6)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect();
        format!("{SECRET_KEY_PREFIX}-{}", groups.join("-"))
    }

    pub fn parse(s: &str) -> Result<Self> {
        let cleaned: String = s
            .trim()
            .to_ascii_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let body = cleaned
            .strip_prefix(SECRET_KEY_PREFIX)
            .ok_or(Error::InvalidSecretKey)?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| Error::InvalidSecretKey)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::InvalidSecretKey)?))
    }
}

/// Derive the Account Unlock Key. `account_id` binds the Secret Key mix to this
/// account so the same key material is never reused across accounts.
pub fn derive_auk(
    password: &str,
    params: &KdfParams,
    secret_key: Option<&SecretKey>,
    account_id: &str,
) -> Result<SymmetricKey> {
    params.validate()?;
    derive_auk_unchecked(password, params, secret_key, account_id)
}

pub(crate) fn derive_auk_unchecked(
    password: &str,
    params: &KdfParams,
    secret_key: Option<&SecretKey>,
    account_id: &str,
) -> Result<SymmetricKey> {
    let salt = crate::item::unb64(&params.salt)?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(32),
        )
        .map_err(|_| Error::Kdf)?,
    );
    let normalized: String = password.trim_end_matches(['\r', '\n']).to_owned();
    let mut stretched = [0u8; 32];
    argon
        .hash_password_into(normalized.as_bytes(), &salt, &mut stretched)
        .map_err(|_| Error::Kdf)?;

    if let Some(sk) = secret_key {
        let mix = hkdf_key(&sk.0, account_id.as_bytes(), b"passauth/secret-key/v1");
        for (a, b) in stretched.iter_mut().zip(mix.as_bytes()) {
            *a ^= b;
        }
    }
    let auk = hkdf_key(&stretched, account_id.as_bytes(), b"passauth/auk/v1");
    stretched.zeroize();
    Ok(auk)
}

#[cfg(test)]
pub(crate) fn test_params() -> KdfParams {
    KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
        salt: crate::item::b64(&[1; 16]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_roundtrip() {
        let sk = SecretKey::generate().unwrap();
        let s = sk.format();
        assert!(s.starts_with("PA1-"));
        assert_eq!(SecretKey::parse(&s.to_lowercase()).unwrap().0, sk.0);
        assert!(SecretKey::parse("PA1-ABC").is_err());
    }

    #[test]
    fn weak_params_rejected() {
        assert!(matches!(
            derive_auk("pw", &test_params(), None, "u"),
            Err(Error::WeakKdf)
        ));
    }

    #[test]
    fn secret_key_changes_auk() {
        let p = test_params();
        let sk = SecretKey::generate().unwrap();
        let a = derive_auk_unchecked("pw", &p, None, "u").unwrap();
        let b = derive_auk_unchecked("pw", &p, Some(&sk), "u").unwrap();
        let c = derive_auk_unchecked("pw", &p, None, "other").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_eq!(
            a.as_bytes(),
            derive_auk_unchecked("pw", &p, None, "u")
                .unwrap()
                .as_bytes()
        );
    }
}
