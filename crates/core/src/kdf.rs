//! Master password + optional Secret Key → Account Unlock Key (AUK).

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{SymmetricKey, hkdf_key, random_bytes};
use crate::{Error, Result};

/// Floors enforced by every client, regardless of what the server sends, so a
/// malicious server cannot downgrade the KDF.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
pub const MIN_ITERATIONS: u32 = 3;
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
pub const MAX_ITERATIONS: u32 = 20;
pub const MAX_PARALLELISM: u32 = 8;
/// What clients use for new keys unless a server's policy asks for more.
pub const DEFAULT_MEMORY_KIB: u32 = 128 * 1024;
pub const DEFAULT_ITERATIONS: u32 = 3;

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
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: 1,
            salt: crate::item::b64(&random_bytes::<16>()?),
        })
    }

    /// [`new_default`](Self::new_default) raised to at least `min_memory_mib` MiB
    /// and `min_iterations` passes, e.g. a server's `min_kdf_memory_mib` /
    /// `min_kdf_iterations` policy: memory = max(128 MiB, minimum), passes =
    /// max(3, minimum). A minimum that is given must lie within the core's range
    /// (64–1024 MiB, 3–20 passes): below it is [`Error::WeakKdf`], above it
    /// [`Error::KdfTooStrong`], so a server can't make a client allocate more than the
    /// ceiling.
    pub fn with_minimums(min_memory_mib: Option<u32>, min_iterations: Option<u32>) -> Result<Self> {
        let mut params = Self::new_default()?;
        if let Some(mib) = min_memory_mib {
            let kib = mib.checked_mul(1024).ok_or(Error::KdfTooStrong)?;
            check_range(kib, MIN_MEMORY_KIB, MAX_MEMORY_KIB)?;
            params.memory_kib = params.memory_kib.max(kib);
        }
        if let Some(passes) = min_iterations {
            check_range(passes, MIN_ITERATIONS, MAX_ITERATIONS)?;
            params.iterations = params.iterations.max(passes);
        }
        Ok(params)
    }

    /// Within the core's range: [`Error::WeakKdf`] when any value is below the floor
    /// (64 MiB, 3 passes, one lane), else [`Error::KdfTooStrong`] when any is above the
    /// ceiling (1 GiB, 20 passes, 8 lanes).
    pub fn validate(&self) -> Result<()> {
        // Only other crates' test builds enable this feature (never release builds).
        if cfg!(feature = "insecure-test-kdf") {
            return Ok(());
        }
        self.check_limits(MAX_MEMORY_KIB, MAX_ITERATIONS, MAX_PARALLELISM)
    }

    /// The floor, then these ceilings.
    fn check_limits(&self, max_kib: u32, max_passes: u32, max_lanes: u32) -> Result<()> {
        if self.memory_kib < MIN_MEMORY_KIB
            || self.iterations < MIN_ITERATIONS
            || self.parallelism < 1
        {
            return Err(Error::WeakKdf);
        }
        if self.memory_kib > max_kib || self.iterations > max_passes || self.parallelism > max_lanes
        {
            return Err(Error::KdfTooStrong);
        }
        Ok(())
    }
}

fn check_range(value: u32, min: u32, max: u32) -> Result<()> {
    if value < min {
        Err(Error::WeakKdf)
    } else if value > max {
        Err(Error::KdfTooStrong)
    } else {
        Ok(())
    }
}

/// Raw 32-byte Argon2id output for `params` (the caller validates them).
pub(crate) fn argon2id(password: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
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
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, &salt, out.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

/// A 128-bit Secret Key, formatted `PA1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XX`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 16]);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    /// The 16 raw bytes (carried in a sealed login key, `device_login`).
    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
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
        let cleaned = Zeroizing::new(cleaned);
        let body = cleaned
            .strip_prefix(SECRET_KEY_PREFIX)
            .ok_or(Error::InvalidSecretKey)?;
        // The key alphabet is A-Z and 2-7; 0, 1 and 8 are look-alikes typed from paper.
        let body: Zeroizing<String> = Zeroizing::new(
            body.chars()
                .map(|c| match c {
                    '0' => 'O',
                    '1' => 'I',
                    '8' => 'B',
                    c => c,
                })
                .collect(),
        );
        let bytes = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(body.as_bytes())
                .map_err(|_| Error::InvalidSecretKey)?,
        );
        let raw: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSecretKey)?;
        Ok(Self(raw))
    }
}

/// Derive the master keys (AUK + OPAQUE login key). `account_id` binds the Secret Key mix to this
/// account so the same key material is never reused across accounts.
pub fn derive_master(
    password: &str,
    params: &KdfParams,
    secret_key: Option<&SecretKey>,
    account_id: &str,
) -> Result<MasterKeys> {
    params.validate()?;
    derive_master_unchecked(password, params, secret_key, account_id)
}

pub(crate) fn derive_master_unchecked(
    password: &str,
    params: &KdfParams,
    secret_key: Option<&SecretKey>,
    account_id: &str,
) -> Result<MasterKeys> {
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
    let mut stretched = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut stretched)
        .map_err(|_| Error::Kdf)?;

    if let Some(sk) = secret_key {
        let mix = hkdf_key(&sk.0, account_id.as_bytes(), b"passauth/secret-key/v1");
        for (a, b) in stretched.iter_mut().zip(mix.as_bytes()) {
            *a ^= b;
        }
    }
    let salt = account_id.as_bytes();
    let keys = MasterKeys {
        auk: hkdf_key(&stretched, salt, b"passauth/auk/v1"),
        login: hkdf_key(&stretched, salt, b"passauth/opaque-password/v1"),
    };
    stretched.zeroize();
    Ok(keys)
}

/// Two independent keys from one Argon2id run: `auk` decrypts the Account Key
/// and never leaves the client; `login` is the OPAQUE password input.
pub struct MasterKeys {
    pub auk: SymmetricKey,
    pub login: SymmetricKey,
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
        // Look-alikes typed from a printed kit: 0/O, 1/I and 8/B.
        let typo = format!(
            "PA1{}",
            s[3..].replace('O', "0").replace('I', "1").replace('B', "8")
        );
        assert_eq!(SecretKey::parse(&typo).unwrap().0, sk.0);
    }

    #[test]
    #[cfg(not(feature = "insecure-test-kdf"))]
    fn weak_params_rejected() {
        assert!(matches!(
            derive_master("pw", &test_params(), None, "u"),
            Err(Error::WeakKdf)
        ));
        let p = |memory_kib, iterations, parallelism| KdfParams {
            memory_kib,
            iterations,
            parallelism,
            salt: crate::item::b64(&[1; 16]),
        };
        assert!(p(MIN_MEMORY_KIB, MIN_ITERATIONS, 1).validate().is_ok());
        assert!(
            p(MAX_MEMORY_KIB, MAX_ITERATIONS, MAX_PARALLELISM)
                .validate()
                .is_ok()
        );
        for (m, t, l) in [
            (MIN_MEMORY_KIB - 1, 3, 1),
            (MIN_MEMORY_KIB, 2, 1),
            (MIN_MEMORY_KIB, 3, 0),
        ] {
            assert!(matches!(p(m, t, l).validate(), Err(Error::WeakKdf)));
        }
        for (m, t, l) in [
            (MAX_MEMORY_KIB + 1, 3, 1),
            (MIN_MEMORY_KIB, MAX_ITERATIONS + 1, 1),
            (MIN_MEMORY_KIB, 3, MAX_PARALLELISM + 1),
        ] {
            assert!(matches!(p(m, t, l).validate(), Err(Error::KdfTooStrong)));
        }
        // Too weak in one way and too strong in another: the weakness is what counts.
        assert!(matches!(
            p(MAX_MEMORY_KIB + 1, 2, 1).validate(),
            Err(Error::WeakKdf)
        ));
    }

    #[test]
    fn minimums_raise_the_defaults_within_the_range() {
        let p = KdfParams::with_minimums(None, None).unwrap();
        assert_eq!(
            (p.memory_kib, p.iterations, p.parallelism),
            (128 * 1024, 3, 1)
        );
        assert_eq!(crate::item::unb64(&p.salt).unwrap().len(), 16);
        // Below the defaults: the defaults stay (a policy only ever raises them).
        let p = KdfParams::with_minimums(Some(64), Some(3)).unwrap();
        assert_eq!((p.memory_kib, p.iterations), (128 * 1024, 3));
        let p = KdfParams::with_minimums(Some(256), Some(5)).unwrap();
        assert_eq!((p.memory_kib, p.iterations), (256 * 1024, 5));
        let p = KdfParams::with_minimums(Some(1024), Some(20)).unwrap();
        assert_eq!(
            (p.memory_kib, p.iterations),
            (MAX_MEMORY_KIB, MAX_ITERATIONS)
        );
        assert!(p.validate().is_ok());
        // Outside the core's range, whatever the build's test features.
        assert!(matches!(
            KdfParams::with_minimums(Some(63), None),
            Err(Error::WeakKdf)
        ));
        assert!(matches!(
            KdfParams::with_minimums(None, Some(2)),
            Err(Error::WeakKdf)
        ));
        for (m, t) in [(Some(1025), None), (None, Some(21)), (Some(u32::MAX), None)] {
            assert!(matches!(
                KdfParams::with_minimums(m, t),
                Err(Error::KdfTooStrong)
            ));
        }
        // A new random salt each time.
        assert_ne!(
            KdfParams::with_minimums(None, None).unwrap().salt,
            KdfParams::with_minimums(None, None).unwrap().salt
        );
    }

    #[test]
    fn secret_key_changes_auk() {
        let p = test_params();
        let sk = SecretKey::generate().unwrap();
        let a = derive_master_unchecked("pw", &p, None, "u").unwrap();
        let b = derive_master_unchecked("pw", &p, Some(&sk), "u").unwrap();
        let c = derive_master_unchecked("pw", &p, None, "other").unwrap();
        assert_ne!(a.auk.as_bytes(), b.auk.as_bytes());
        assert_ne!(a.auk.as_bytes(), c.auk.as_bytes());
        assert_eq!(
            a.auk.as_bytes(),
            derive_master_unchecked("pw", &p, None, "u")
                .unwrap()
                .auk
                .as_bytes()
        );
    }
}
