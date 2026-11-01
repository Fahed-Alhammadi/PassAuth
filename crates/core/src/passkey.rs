//! WebAuthn authenticator crypto for PassAuth passkeys (ES256, "none" attestation).
//!
//! Byte-compatible with the browser extension (`extension/src/background/passkeys.ts`):
//! same AAGUID, flags (UP|UV|BE|BS, plus AT on creation), signature counter 0
//! (synced passkeys), PKCS#8 private keys (base64url in the vault item). Mobile
//! apps use this through the FFI bindings; the client (browser / OS) supplies
//! the clientDataJSON hash.

use p256::SecretKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use sha2_v10::{Digest, Sha256};

use crate::crypto::random_bytes;
use crate::error::{Error, Result};

/// PassAuth authenticator AAGUID: bbc747a1-4ff9-29df-6533-dfaa44f86a18.
pub const AAGUID: [u8; 16] = [
    0xbb, 0xc7, 0x47, 0xa1, 0x4f, 0xf9, 0x29, 0xdf, 0x65, 0x33, 0xdf, 0xaa, 0x44, 0xf8, 0x6a, 0x18,
];
/// COSE algorithm identifier for ES256.
pub const ES256: i64 = -7;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const ASSERTION_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
const CREATE_FLAGS: u8 = ASSERTION_FLAGS | FLAG_AT;

/// A newly created passkey and the registration data for the relying party.
pub struct NewPasskey {
    /// 16 random bytes.
    pub credential_id: Vec<u8>,
    /// PKCS#8 DER; store base64url-encoded in the item's `private_key`.
    pub private_key_pkcs8: Vec<u8>,
    /// SubjectPublicKeyInfo DER (`response.publicKey` in WebAuthn JSON).
    pub public_key_spki: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// CBOR `{fmt: "none", attStmt: {}, authData}`.
    pub attestation_object: Vec<u8>,
}

/// An assertion over `authenticatorData || clientDataHash`.
pub struct PasskeyAssertion {
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature.
    pub signature: Vec<u8>,
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

fn new_secret_key() -> Result<SecretKey> {
    // A uniformly random 32-byte string is a valid scalar with overwhelming probability.
    for _ in 0..8 {
        let bytes: [u8; 32] = random_bytes()?;
        if let Ok(k) = SecretKey::from_slice(&bytes) {
            return Ok(k);
        }
    }
    Err(Error::Rng)
}

/// Create a discoverable ES256 passkey for `rp_id`.
pub fn create(rp_id: &str) -> Result<NewPasskey> {
    let secret = new_secret_key()?;
    let public = secret.public_key();
    let point = public.to_sec1_point(false);
    let (x, y) = (
        point.x().ok_or(Error::Malformed("public key"))?,
        point.y().ok_or(Error::Malformed("public key"))?,
    );
    let credential_id: [u8; 16] = random_bytes()?;

    let mut auth = Vec::with_capacity(160);
    auth.extend_from_slice(&rp_id_hash(rp_id));
    auth.push(CREATE_FLAGS);
    auth.extend_from_slice(&0u32.to_be_bytes());
    auth.extend_from_slice(&AAGUID);
    auth.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&credential_id);
    auth.extend_from_slice(&cose_ec2_key(x, y));

    // {"fmt": "none", "attStmt": {}, "authData": <bytes>} with canonical key order (as the extension).
    let mut att = vec![0xa3];
    cbor_text(&mut att, "fmt");
    cbor_text(&mut att, "none");
    cbor_text(&mut att, "attStmt");
    att.push(0xa0);
    cbor_text(&mut att, "authData");
    cbor_bytes(&mut att, &auth);

    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|_| Error::Malformed("private key"))?;
    let spki = public
        .to_public_key_der()
        .map_err(|_| Error::Malformed("public key"))?;
    Ok(NewPasskey {
        credential_id: credential_id.to_vec(),
        private_key_pkcs8: pkcs8.as_bytes().to_vec(),
        public_key_spki: spki.as_bytes().to_vec(),
        authenticator_data: auth,
        attestation_object: att,
    })
}

/// Sign an assertion for `rp_id` with a stored passkey.
pub fn assert(
    private_key_pkcs8: &[u8],
    rp_id: &str,
    client_data_hash: &[u8],
) -> Result<PasskeyAssertion> {
    if client_data_hash.len() != 32 {
        return Err(Error::Malformed("client data hash"));
    }
    let secret = SecretKey::from_pkcs8_der(private_key_pkcs8)
        .map_err(|_| Error::Malformed("private key"))?;
    let mut auth = Vec::with_capacity(37);
    auth.extend_from_slice(&rp_id_hash(rp_id));
    auth.push(ASSERTION_FLAGS);
    auth.extend_from_slice(&0u32.to_be_bytes());

    let mut msg = auth.clone();
    msg.extend_from_slice(client_data_hash);
    let signature: Signature = SigningKey::from(&secret).sign(&msg);
    Ok(PasskeyAssertion {
        authenticator_data: auth,
        signature: signature.to_der().as_bytes().to_vec(),
    })
}

/// clientDataJSON with WebAuthn's key order (for callers that don't provide a hash, e.g. Android apps).
pub fn client_data_json(kind: &str, challenge_b64url: &str, origin: &str) -> String {
    format!(
        r#"{{"type":{},"challenge":{},"origin":{},"crossOrigin":false}}"#,
        serde_json::Value::from(kind),
        serde_json::Value::from(challenge_b64url),
        serde_json::Value::from(origin)
    )
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
fn cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    cbor_bytes(&mut out, x);
    out.push(0x22);
    cbor_bytes(&mut out, y);
    out
}

fn cbor_head(out: &mut Vec<u8>, major: u8, len: usize) {
    let m = major << 5;
    match len {
        0..=23 => out.push(m | len as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, len as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;

    #[test]
    fn create_then_assert_verifies() {
        let pk = create("example.com").unwrap();
        assert_eq!(pk.credential_id.len(), 16);
        let auth = &pk.authenticator_data;
        assert_eq!(&auth[..32], &rp_id_hash("example.com"));
        assert_eq!(auth[32], CREATE_FLAGS);
        assert_eq!(&auth[37..53], &AAGUID);
        assert_eq!(&auth[53..55], &[0, 16]);
        assert_eq!(&auth[55..71], pk.credential_id.as_slice());
        // COSE key header: map(5), kty EC2, alg ES256, crv P-256.
        assert_eq!(&auth[71..78], &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
        assert!(
            pk.attestation_object
                .starts_with(&[0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e'])
        );

        let hash = sha256(
            client_data_json("webauthn.get", "Y2hhbGxlbmdl", "https://example.com").as_bytes(),
        );
        let a = assert(&pk.private_key_pkcs8, "example.com", &hash).unwrap();
        assert_eq!(a.authenticator_data.len(), 37);
        assert_eq!(a.authenticator_data[32], ASSERTION_FLAGS);
        let vk = VerifyingKey::from_public_key_der(&pk.public_key_spki).unwrap();
        let sig = Signature::from_der(&a.signature).unwrap();
        let mut msg = a.authenticator_data.clone();
        msg.extend_from_slice(&hash);
        vk.verify(&msg, &sig).unwrap();
    }

    /// A key exported by the browser extension (WebCrypto PKCS#8) signs here too.
    #[test]
    fn signs_with_extension_created_key() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let pkcs8 = b64.decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfDgI2NOg7A2czbry7RcAgs0iPTDU3iF8YwtIFYYvf-yhRANCAATojJwTKaVvt68rmdnzIQ4qp169nJpxNB0lkOK-iG47p021ApJwJWz3jyY1FZzI54HlUxlfjLFEQAwEdNBHmEuC").unwrap();
        let spki = b64.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6IycEymlb7evK5nZ8yEOKqdevZyacTQdJZDivohuO6dNtQKScCVs948mNRWcyOeB5VMZX4yxREAMBHTQR5hLgg").unwrap();
        let hash = [7u8; 32];
        let a = assert(&pkcs8, "example.com", &hash).unwrap();
        let mut msg = a.authenticator_data.clone();
        msg.extend_from_slice(&hash);
        VerifyingKey::from_public_key_der(&spki)
            .unwrap()
            .verify(&msg, &Signature::from_der(&a.signature).unwrap())
            .unwrap();
    }

    #[test]
    fn client_data_json_matches_extension_format() {
        assert_eq!(
            client_data_json("webauthn.create", "abc", "https://a.example"),
            r#"{"type":"webauthn.create","challenge":"abc","origin":"https://a.example","crossOrigin":false}"#
        );
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(assert(b"not a key", "example.com", &[0; 32]).is_err());
        let pk = create("example.com").unwrap();
        assert!(assert(&pk.private_key_pkcs8, "example.com", &[0; 31]).is_err());
    }
}
