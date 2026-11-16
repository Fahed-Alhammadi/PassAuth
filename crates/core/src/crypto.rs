//! Symmetric AEAD (XChaCha20-Poly1305) and X25519 sealed boxes.
//!
//! Ciphertext layout: `version (1) || nonce (24) || ciphertext+tag`.
//! Every call takes associated data that binds the ciphertext to where it is
//! stored, so blobs cannot be swapped between items, fields or users.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + NONCE_LEN;
const SEALED_BOX_INFO: &[u8] = b"passauth/sealed-box/v1";

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}

/// A 256-bit symmetric key, wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Malformed("key length"))?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random_bytes()?;
        let cipher = XChaCha20Poly1305::new(&self.0.into());
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Decrypt)?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let (&version, rest) = data
            .split_first()
            .ok_or(Error::Malformed("empty ciphertext"))?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if rest.len() < NONCE_LEN + 16 {
            return Err(Error::Malformed("ciphertext too short"));
        }
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("checked length");
        let cipher = XChaCha20Poly1305::new(&self.0.into());
        cipher
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
            .map_err(|_| Error::Decrypt)
    }

    /// Encrypt another key under this one.
    pub fn wrap(&self, key: &SymmetricKey, aad: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(key.as_bytes(), aad)
    }

    pub fn unwrap_key(&self, wrapped: &[u8], aad: &[u8]) -> Result<SymmetricKey> {
        let mut raw = self.decrypt(wrapped, aad)?;
        let key = SymmetricKey::from_slice(&raw);
        raw.zeroize();
        key
    }
}

/// HKDF-SHA256 expand to a 256-bit key.
pub fn hkdf_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> SymmetricKey {
    let mut okm = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    SymmetricKey(okm)
}

/// X25519 keypair used to receive shared vault keys.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_secret_bytes(random_bytes()?))
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Open a sealed box addressed to this keypair.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 32 {
            return Err(Error::Malformed("sealed box too short"));
        }
        let (epk, ct) = sealed.split_at(32);
        let epk: [u8; 32] = epk.try_into().expect("checked length");
        let shared = self.secret.diffie_hellman(&PublicKey::from(epk));
        let key = sealed_box_key(&shared, &epk, &self.public_bytes());
        key.decrypt(ct, aad)
    }
}

/// Encrypt to a recipient's X25519 public key (ephemeral-static ECDH + HKDF + AEAD).
///
/// Refuses a low-order "public key" (all-zero shared secret): the box would be
/// sealed under a key anyone can compute, so a server handing out such a key
/// would read everything sealed to it.
pub fn seal_to(recipient: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let eph = StaticSecret::from(random_bytes::<32>()?);
    let epk = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(Error::Malformed("invalid public key"));
    }
    let key = sealed_box_key(&shared, &epk, recipient);
    let ct = key.encrypt(plaintext, aad)?;
    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn sealed_box_key(shared: &SharedSecret, epk: &[u8; 32], recipient: &[u8; 32]) -> SymmetricKey {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(recipient);
    hkdf_key(shared.as_bytes(), &salt, SEALED_BOX_INFO)
}

/// Short, human-comparable fingerprint of a public key (for out-of-band verification).
pub fn fingerprint(public: &[u8; 32]) -> String {
    use sha2::Digest;
    fingerprint_digest(&Sha256::digest(public).into())
}

/// The fingerprint format of a SHA-256 digest: its first 15 bytes in base32, in groups
/// of four (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`).
pub fn fingerprint_digest(digest: &[u8; 32]) -> String {
    let enc = data_encoding::BASE32_NOPAD.encode(&digest[..15]);
    enc.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("base32 is ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_aad_binding() {
        let key = SymmetricKey::generate().unwrap();
        let ct = key.encrypt(b"hunter2", b"item:1").unwrap();
        assert_eq!(key.decrypt(&ct, b"item:1").unwrap(), b"hunter2");
        assert!(matches!(key.decrypt(&ct, b"item:2"), Err(Error::Decrypt)));
    }

    #[test]
    fn tamper_detected() {
        let key = SymmetricKey::generate().unwrap();
        let mut ct = key.encrypt(b"secret", b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(key.decrypt(&ct, b"").is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = SymmetricKey::generate().unwrap();
        assert_ne!(
            key.encrypt(b"x", b"").unwrap(),
            key.encrypt(b"x", b"").unwrap()
        );
    }

    #[test]
    fn sealed_box_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let sealed = seal_to(&kp.public_bytes(), b"vault key", b"share:v1").unwrap();
        assert_eq!(kp.open(&sealed, b"share:v1").unwrap(), b"vault key");
        assert!(other.open(&sealed, b"share:v1").is_err());
        assert!(kp.open(&sealed, b"share:v2").is_err());
    }

    #[test]
    fn sealing_to_a_low_order_point_is_refused() {
        // u = 0 and points of order 8: every secret gives an all-zero shared secret.
        let order8 = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
        for bad in [
            [0u8; 32],
            order8("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            order8("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ] {
            assert!(matches!(
                seal_to(&bad, b"vault key", b"share:v1"),
                Err(Error::Malformed(_))
            ));
        }
    }

    #[test]
    fn fingerprint_is_stable() {
        let kp = KeyPair::from_secret_bytes([7; 32]);
        assert_eq!(
            fingerprint(&kp.public_bytes()),
            fingerprint(&kp.public_bytes())
        );
        assert_eq!(fingerprint(&kp.public_bytes()).len(), 29);
    }
}
