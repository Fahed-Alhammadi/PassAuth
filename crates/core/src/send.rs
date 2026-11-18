//! Send: text shared through a link, `/send/<id>#<key>`.
//!
//! - The send key is 32 random bytes, base64url in the link's fragment, which
//!   browsers never send to a server. The owner keeps it wrapped by their Account
//!   Key ([`UnlockedAccount::wrap_send_key`](crate::keys::UnlockedAccount::wrap_send_key)).
//! - `name` and `data` are each `base64url(0x01 ‖ nonce (24) ‖ ciphertext ‖ tag (16))`:
//!   XChaCha20-Poly1305 under the send key with associated data
//!   `passauth/send/v1/<field>`, so the two can't be swapped. The server picks the
//!   Send's id after the app encrypted, so the id is not bound; every Send has a key
//!   of its own instead.
//! - An optional password is checked by the server, not mixed into the encryption:
//!   the app stores `access_salt` ([`new_password_salt`]) with a verifier
//!   ([`password_verifier`] = HKDF-SHA256 over Argon2id of the password), and a
//!   visitor's app derives the verifier again from the salt the server hands out.
//!   The server keeps only the verifier's SHA-256. Visitors have no account: none
//!   of this needs one. So the password only keeps honest servers from handing out
//!   the text: whoever has the link and the server's data (its operator, an attacker
//!   on the server, a stolen database plus the link) reads the text without it.
//! - **Send v2** (migration 16, server feature `send_v2`): a Send with a password
//!   encrypts `name` and `data` with a *content key* made from the send key **and** the
//!   password, so the link alone no longer opens it (security review L2). From the same
//!   Argon2id output as the verifier: `pw_key` = HKDF-SHA256(Argon2id(password), salt,
//!   `passauth/send-password-key/v2`) (never leaves the device), then `content_key` =
//!   HKDF-SHA256(ikm = send key, salt = `pw_key`, info `passauth/send-content/v2`).
//!   Each field is `base64url(0x02 ‖ 0x01 ‖ nonce ‖ ciphertext ‖ tag)` with associated
//!   data `passauth/send/v2/<field>`; the first byte tells the versions apart (no trial
//!   decryption). Sends without a password stay v1 exactly as before. The owner keeps
//!   the content key wrapped by their Account Key (`owner_content_key`,
//!   [`UnlockedAccount::wrap_send_content_key`](crate::keys::UnlockedAccount::wrap_send_content_key)),
//!   so their apps show and edit the Send without the password. What remains: whoever
//!   has the link *and* the server's data can guess the password offline, each guess
//!   costing one Argon2id run with the Send's parameters.
//! - Whoever wrote `access_salt` (any account through the API, or the server) picks
//!   the visitor's Argon2id cost, so visitors accept only the core's floor up to
//!   [`VISITOR_MAX_MEMORY_KIB`], [`VISITOR_MAX_ITERATIONS`] and
//!   [`VISITOR_MAX_PARALLELISM`] (twice the memory and passes the app writes).

use zeroize::Zeroizing;

use crate::crypto::{SymmetricKey, hkdf_key};
use crate::item::{b64, unb64};
use crate::kdf::{KdfParams, argon2id};
use crate::{Error, Result};

/// First part of an `access_salt` (names the format and its version).
const SALT_TAG: &str = "sendpw-v1";
/// HKDF info of the verifier: domain-separates it from every account key derivation.
const VERIFIER_INFO: &[u8] = b"passauth/send-password/v1";
/// HKDF info of a v2 Send's password key (same Argon2id output as the verifier).
const PASSWORD_KEY_INFO: &[u8] = b"passauth/send-password-key/v2";
/// HKDF info of a v2 Send's content key (ikm = send key, salt = password key).
const CONTENT_KEY_INFO: &[u8] = b"passauth/send-content/v2";
/// The marker byte before a v2 Send field (`0x02 ‖ version ‖ nonce ‖ ciphertext`); a
/// v1 field starts with the cipher's version byte (`0x01`).
const V2_MARKER: u8 = 0x02;
const SALT_LEN: usize = 16;
/// Most memory (KiB) an `access_salt` may ask a visitor's app for: 256 MiB.
pub const VISITOR_MAX_MEMORY_KIB: u32 = 256 * 1024;
/// Most Argon2id passes an `access_salt` may ask for.
pub const VISITOR_MAX_ITERATIONS: u32 = 6;
/// Most Argon2id lanes an `access_salt` may ask for.
pub const VISITOR_MAX_PARALLELISM: u32 = 4;

/// Which part of a Send a ciphertext belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendField {
    Name,
    Data,
}

impl SendField {
    /// `"name"` or `"data"`.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "name" => Ok(Self::Name),
            "data" => Ok(Self::Data),
            _ => Err(Error::Malformed("send field must be \"name\" or \"data\"")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Data => "data",
        }
    }

    fn aad(self) -> Vec<u8> {
        format!("passauth/send/v1/{}", self.as_str()).into_bytes()
    }

    fn aad_v2(self) -> Vec<u8> {
        format!("passauth/send/v2/{}", self.as_str()).into_bytes()
    }
}

/// The format of a Send's `name` or `data`: 1 (the link key opens it) or 2 (the content
/// key of a Send with a password, [`SendContentKey`]). Told by the first byte; anything
/// else is [`Error::UnsupportedVersion`].
pub fn field_version(ciphertext: &str) -> Result<u8> {
    match unb64(ciphertext)?.first() {
        Some(&1) => Ok(1),
        Some(&V2_MARKER) => Ok(2),
        Some(&b) => Err(Error::UnsupportedVersion(b)),
        None => Err(Error::Malformed("empty send field")),
    }
}

/// What a Send's password gives, from one Argon2id run ([`password_secrets`]): the
/// verifier the server checks and the password key that, with the send key, makes a v2
/// Send's content key ([`SendKey::content_key`]). The password key never leaves the
/// device; it is wiped on drop.
pub struct SendPassword {
    /// `access_verifier` (base64url of 32 bytes), as [`password_verifier`] gives it.
    pub verifier: String,
    key: SymmetricKey,
}

/// A v2 Send's content key: HKDF-SHA256(ikm = send key, salt = password key, info
/// `passauth/send-content/v2`). Wiped from memory on drop.
#[derive(Clone)]
pub struct SendContentKey(SymmetricKey);

impl SendContentKey {
    /// base64url (43 characters): for the bindings, never for a link or a server.
    pub fn to_b64(&self) -> String {
        b64(self.0.as_bytes())
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(unb64(s)?);
        SymmetricKey::from_slice(&raw)
            .map(Self)
            .map_err(|_| Error::Malformed("send content key length"))
    }

    /// Encrypt a v2 Send's `name` or `data`: `base64url(0x02 ‖ cipher output)`, associated
    /// data `passauth/send/v2/<field>`.
    pub fn encrypt(&self, field: SendField, plaintext: &[u8]) -> Result<String> {
        let mut out = vec![V2_MARKER];
        out.extend(self.0.encrypt(plaintext, &field.aad_v2())?);
        Ok(b64(&out))
    }

    /// Decrypt a v2 field. A v1 field (or anything without the `0x02` marker) is
    /// [`Error::UnsupportedVersion`]; a wrong key, the other field or tampered data
    /// [`Error::Decrypt`].
    pub fn decrypt(&self, field: SendField, ciphertext: &str) -> Result<Vec<u8>> {
        let raw = unb64(ciphertext)?;
        match raw.split_first() {
            Some((&V2_MARKER, rest)) => self.0.decrypt(rest, &field.aad_v2()),
            Some((&b, _)) => Err(Error::UnsupportedVersion(b)),
            None => Err(Error::Malformed("empty send field")),
        }
    }

    pub(crate) fn key(&self) -> &SymmetricKey {
        &self.0
    }

    pub(crate) fn from_key(key: SymmetricKey) -> Self {
        Self(key)
    }
}

/// Open a Send's `name` or `data` of either format: v1 with the link's send key, v2
/// with `content` (from [`SendKey::content_key`] after the visitor typed the password,
/// or the owner's `owner_content_key`). A v2 field without `content` is
/// [`Error::PasswordRequired`].
pub fn open_field(
    link: &SendKey,
    content: Option<&SendContentKey>,
    field: SendField,
    ciphertext: &str,
) -> Result<Vec<u8>> {
    match field_version(ciphertext)? {
        1 => link.decrypt(field, ciphertext),
        _ => content
            .ok_or(Error::PasswordRequired)?
            .decrypt(field, ciphertext),
    }
}

/// A Send's random 256-bit key, wiped from memory on drop.
#[derive(Clone)]
pub struct SendKey(SymmetricKey);

impl SendKey {
    pub fn generate() -> Result<Self> {
        SymmetricKey::generate().map(Self)
    }

    /// The key from a link's fragment: base64url (no padding) of exactly 32 bytes.
    pub fn from_b64(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(unb64(s)?);
        SymmetricKey::from_slice(&raw)
            .map(Self)
            .map_err(|_| Error::Malformed("send key length"))
    }

    /// base64url (43 characters) for the link's fragment.
    pub fn to_b64(&self) -> String {
        b64(self.0.as_bytes())
    }

    /// Encrypt a Send's `name` or `data` (base64url, versioned, see the module docs).
    pub fn encrypt(&self, field: SendField, plaintext: &[u8]) -> Result<String> {
        Ok(b64(&self.0.encrypt(plaintext, &field.aad())?))
    }

    /// [`Error::Decrypt`] for a wrong key, the other field's ciphertext or tampered data;
    /// [`Error::UnsupportedVersion`] (2) for a v2 field (use [`open_field`]).
    pub fn decrypt(&self, field: SendField, ciphertext: &str) -> Result<Vec<u8>> {
        self.0.decrypt(&unb64(ciphertext)?, &field.aad())
    }

    /// A v2 Send's content key: this send key and the password key of `password`
    /// ([`password_secrets`] over the Send's `access_salt`).
    pub fn content_key(&self, password: &SendPassword) -> SendContentKey {
        SendContentKey(hkdf_key(
            self.0.as_bytes(),
            password.key.as_bytes(),
            CONTENT_KEY_INFO,
        ))
    }

    pub(crate) fn key(&self) -> &SymmetricKey {
        &self.0
    }

    pub(crate) fn from_key(key: SymmetricKey) -> Self {
        Self(key)
    }
}

/// A new `access_salt` for a Send's password: the Argon2id parameters (the
/// account defaults, 128 MiB and 3 passes) and a random 16-byte salt, as
/// `sendpw-v1$m=<KiB>,t=<passes>,p=<lanes>$<salt, base64url>`. The server stores
/// it as given and hands it to visitors.
pub fn new_password_salt() -> Result<String> {
    Ok(encode_salt(&KdfParams::new_default()?))
}

/// The verifier the server checks (base64url of 32 bytes) for `password` and an
/// `access_salt` from [`new_password_salt`]. The salt comes from the server, so its
/// parameters must lie between the core's floor (64 MiB, 3 passes, one lane) and the
/// visitor ceiling (256 MiB, 6 passes, 4 lanes): below is [`Error::WeakKdf`] (a server
/// can't make the verifier cheap to guess), above [`Error::KdfTooStrong`] (nobody can
/// make a visitor's tab freeze or allocate gigabytes). Salts this app writes are always
/// within.
pub fn password_verifier(password: &str, salt: &str) -> Result<String> {
    verifier(password, &visitor_params(salt)?)
}

/// The salt's Argon2id parameters, when a visitor's app may run them.
fn visitor_params(salt: &str) -> Result<KdfParams> {
    let params = parse_salt(salt)?;
    params.validate()?;
    // Applies whatever the build's test features (`validate` skips its checks with
    // `insecure-test-kdf`).
    if params.memory_kib > VISITOR_MAX_MEMORY_KIB
        || params.iterations > VISITOR_MAX_ITERATIONS
        || params.parallelism > VISITOR_MAX_PARALLELISM
    {
        return Err(Error::KdfTooStrong);
    }
    Ok(params)
}

/// The verifier and the password key of `password` for an `access_salt` (one Argon2id
/// run, with the same parameter bounds as [`password_verifier`]): the owner when setting
/// a password on a v2 Send, a visitor before opening one (send `verifier`, then
/// [`SendKey::content_key`]).
pub fn password_secrets(password: &str, salt: &str) -> Result<SendPassword> {
    secrets(password, &visitor_params(salt)?)
}

pub(crate) fn secrets(password: &str, params: &KdfParams) -> Result<SendPassword> {
    if password.is_empty() {
        return Err(Error::Malformed("empty password"));
    }
    let stretched = argon2id(password.as_bytes(), params)?;
    let salt = unb64(&params.salt)?;
    let verifier = hkdf_key(stretched.as_ref(), &salt, VERIFIER_INFO);
    Ok(SendPassword {
        verifier: b64(verifier.as_bytes()),
        key: hkdf_key(stretched.as_ref(), &salt, PASSWORD_KEY_INFO),
    })
}

fn verifier(password: &str, params: &KdfParams) -> Result<String> {
    Ok(secrets(password, params)?.verifier)
}

fn encode_salt(p: &KdfParams) -> String {
    format!(
        "{SALT_TAG}$m={},t={},p={}${}",
        p.memory_kib, p.iterations, p.parallelism, p.salt
    )
}

/// Strict inverse of [`encode_salt`] (does not check the parameters' range).
fn parse_salt(s: &str) -> Result<KdfParams> {
    const BAD: Error = Error::Malformed("send password salt");
    let mut parts = s.split('$');
    let (Some(SALT_TAG), Some(params), Some(salt), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(BAD);
    };
    let mut values = params.split(',');
    let (Some(m), Some(t), Some(p), None) =
        (values.next(), values.next(), values.next(), values.next())
    else {
        return Err(BAD);
    };
    let number = |part: &str, key: &str| -> Result<u32> {
        let digits = part.strip_prefix(key).ok_or(BAD)?;
        let n: u32 = digits.parse().map_err(|_| BAD)?;
        // One spelling per value: no leading zeros or signs.
        if n.to_string() == digits {
            Ok(n)
        } else {
            Err(BAD)
        }
    };
    if unb64(salt).map_err(|_| BAD)?.len() != SALT_LEN {
        return Err(BAD);
    }
    Ok(KdfParams {
        memory_kib: number(m, "m=")?,
        iterations: number(t, "t=")?,
        parallelism: number(p, "p=")?,
        salt: salt.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, aead::KeyInit, aead::Payload};

    fn key() -> SendKey {
        SendKey::from_b64(&b64(&(0u8..32).collect::<Vec<_>>())).unwrap()
    }

    #[test]
    fn roundtrip_and_fields_are_bound() {
        let k = SendKey::generate().unwrap();
        let name = k.encrypt(SendField::Name, b"Wi-Fi").unwrap();
        let data = k
            .encrypt(SendField::Data, "pässwörd 🔑".as_bytes())
            .unwrap();
        assert_eq!(k.decrypt(SendField::Name, &name).unwrap(), b"Wi-Fi");
        assert_eq!(
            k.decrypt(SendField::Data, &data).unwrap(),
            "pässwörd 🔑".as_bytes()
        );
        // The name can't be served as the text, nor the other way round.
        assert!(matches!(
            k.decrypt(SendField::Data, &name),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            k.decrypt(SendField::Name, &data),
            Err(Error::Decrypt)
        ));
        // Another Send's key.
        let other = SendKey::generate().unwrap();
        assert!(matches!(
            other.decrypt(SendField::Name, &name),
            Err(Error::Decrypt)
        ));
        // A new nonce every time.
        assert_ne!(name, k.encrypt(SendField::Name, b"Wi-Fi").unwrap());
        // Empty text is fine.
        let empty = k.encrypt(SendField::Data, b"").unwrap();
        assert_eq!(k.decrypt(SendField::Data, &empty).unwrap(), b"");
    }

    #[test]
    fn tampering_and_truncation_are_detected() {
        let k = SendKey::generate().unwrap();
        let ct = unb64(&k.encrypt(SendField::Data, b"the text").unwrap()).unwrap();
        assert_eq!(ct.len(), 1 + 24 + 8 + 16);
        assert_eq!(ct[0], 1);
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x80;
            let err = k.decrypt(SendField::Data, &b64(&bad)).unwrap_err();
            if i == 0 {
                assert!(matches!(err, Error::UnsupportedVersion(0x81)));
            } else {
                assert!(matches!(err, Error::Decrypt), "byte {i}");
            }
        }
        for len in 0..ct.len() {
            assert!(k.decrypt(SendField::Data, &b64(&ct[..len])).is_err());
        }
        let mut longer = ct.clone();
        longer.push(0);
        assert!(k.decrypt(SendField::Data, &b64(&longer)).is_err());
        assert!(k.decrypt(SendField::Data, "not base64!").is_err());
    }

    #[test]
    fn fields_and_keys_are_parsed_strictly() {
        assert_eq!(SendField::parse("name").unwrap(), SendField::Name);
        assert_eq!(SendField::parse("data").unwrap(), SendField::Data);
        for bad in ["", "Name", "text", "data ", "name/x"] {
            assert!(SendField::parse(bad).is_err(), "{bad}");
        }
        let k = SendKey::generate().unwrap();
        let s = k.to_b64();
        assert_eq!(s.len(), 43);
        assert_eq!(SendKey::from_b64(&s).unwrap().to_b64(), s);
        assert!(SendKey::from_b64(&b64(&[1; 31])).is_err());
        assert!(SendKey::from_b64(&b64(&[1; 33])).is_err());
        assert!(SendKey::from_b64(&format!("{s}=")).is_err());
        assert!(SendKey::from_b64("").is_err());
        // Only the URL-safe alphabet (0xfb… encodes to "-" and "_").
        let url = b64(&[0xfb; 32]);
        assert!(url.contains('-') && url.contains('_'));
        assert!(SendKey::from_b64(&url).is_ok());
        assert!(SendKey::from_b64(&url.replace('-', "+").replace('_', "/")).is_err());
        // Non-canonical base64 (the last character's unused bits set).
        let mut last = s.clone();
        let c = last.pop().unwrap();
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let pos = alphabet.find(c).unwrap();
        last.push(alphabet.as_bytes()[pos ^ 1] as char);
        assert!(SendKey::from_b64(&last).is_err());
    }

    /// Known answer, computed independently (Node.js: HChaCha20 + OpenSSL
    /// ChaCha20-Poly1305) from the format in the module docs: key 00..1f,
    /// nonce 40..57, field `data`, text "Hello from PassAuth Send".
    const KAT_DATA: &str =
        "AUBBQkNERUZHSElKS0xNTk9QUVJTVFVWV5xcaRy_wB9k4Jmn7s7vFtPnzsXkQDw9_v0s-rEmcY7HwqQ0Ef-xqmg";

    #[test]
    fn known_answer() {
        let k = key();
        assert_eq!(
            k.decrypt(SendField::Data, KAT_DATA).unwrap(),
            b"Hello from PassAuth Send"
        );
        assert!(k.decrypt(SendField::Name, KAT_DATA).is_err());
        // The same bytes from the cipher directly, with the documented layout.
        let raw = unb64(KAT_DATA).unwrap();
        let nonce: [u8; 24] = raw[1..25].try_into().unwrap();
        let cipher = XChaCha20Poly1305::new(&(*k.key().as_bytes()).into());
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: b"Hello from PassAuth Send",
                    aad: b"passauth/send/v1/data",
                },
            )
            .unwrap();
        assert_eq!(&raw[25..], ct.as_slice());
    }

    fn small(salt: &[u8]) -> KdfParams {
        KdfParams {
            memory_kib: 256,
            iterations: 3,
            parallelism: 1,
            salt: b64(salt),
        }
    }

    /// Known answer, computed independently (Node.js `crypto.argon2Sync` and
    /// `hkdfSync`): Argon2id(m=256 KiB, t=3, p=1, salt 01..10, 32 bytes) of
    /// "correct horse battery staple", then HKDF-SHA256(salt = the same 16 bytes,
    /// info "passauth/send-password/v1").
    const KAT_VERIFIER: &str = "f3e_4PkM0RyzWpdb6um2W_0Hgm6x5OtajjNdIK3eWMI";

    #[test]
    fn verifier_known_answer_and_domain_separation() {
        let salt: Vec<u8> = (1u8..=16).collect();
        let p = small(&salt);
        let v = verifier("correct horse battery staple", &p).unwrap();
        assert_eq!(v, KAT_VERIFIER);
        // Not the raw Argon2id output, and not what the account KDF derives.
        let raw = argon2id(b"correct horse battery staple", &p).unwrap();
        assert_ne!(unb64(&v).unwrap(), raw.to_vec());
        let master =
            crate::kdf::derive_master_unchecked("correct horse battery staple", &p, None, "")
                .unwrap();
        assert_ne!(unb64(&v).unwrap(), master.auk.as_bytes().to_vec());
        assert_ne!(unb64(&v).unwrap(), master.login.as_bytes().to_vec());
        // Depends on the password and on the salt.
        assert_ne!(verifier("correct horse battery stapler", &p).unwrap(), v);
        assert_ne!(
            verifier("correct horse battery staple", &small(&[9; 16])).unwrap(),
            v
        );
        assert!(verifier("", &p).is_err());
    }

    /// Known answer, computed independently (Node.js `crypto.argon2Sync` and
    /// `hkdfSync`): the same Argon2id output as [`KAT_VERIFIER`], then the password key
    /// (HKDF, info `passauth/send-password-key/v2`) and the content key for the send key
    /// 00..1f (HKDF, ikm = send key, salt = password key, info `passauth/send-content/v2`).
    const KAT_CONTENT_KEY: &str = "p6XF6XOOVCNuy3hX0Tt538c2SQzyL9mqY2y7GDJ0WN0";

    #[test]
    fn v2_content_key_known_answer() {
        let salt: Vec<u8> = (1u8..=16).collect();
        let pw = secrets("correct horse battery staple", &small(&salt)).unwrap();
        assert_eq!(pw.verifier, KAT_VERIFIER, "one Argon2id run gives both");
        let ck = key().content_key(&pw);
        assert_eq!(ck.to_b64(), KAT_CONTENT_KEY);
        // Neither the link key, the verifier nor the password key.
        assert_ne!(ck.to_b64(), key().to_b64());
        assert_ne!(ck.to_b64(), pw.verifier);
        assert_ne!(ck.key().as_bytes(), pw.key.as_bytes());
        assert_eq!(
            SendContentKey::from_b64(KAT_CONTENT_KEY).unwrap().to_b64(),
            KAT_CONTENT_KEY
        );
        assert!(SendContentKey::from_b64(&b64(&[1; 31])).is_err());
    }

    #[test]
    fn v2_needs_the_link_and_the_password() {
        let p = small(&[3; 16]);
        let link = SendKey::generate().unwrap();
        let owner = link.content_key(&secrets("hunter2", &p).unwrap());
        let name = owner.encrypt(SendField::Name, b"Door code").unwrap();
        let data = owner.encrypt(SendField::Data, "4711 ✓".as_bytes()).unwrap();
        assert_eq!(field_version(&name).unwrap(), 2);
        assert_eq!(unb64(&data).unwrap()[..2], [2, 1]);
        // A visitor with the link and the right password.
        let visitor = link.content_key(&secrets("hunter2", &p).unwrap());
        assert_eq!(
            open_field(&link, Some(&visitor), SendField::Data, &data).unwrap(),
            "4711 ✓".as_bytes()
        );
        assert_eq!(
            open_field(&link, Some(&visitor), SendField::Name, &name).unwrap(),
            b"Door code"
        );
        // The wrong password, the link alone, another link, swapped fields: refused.
        let wrong = link.content_key(&secrets("hunter3", &p).unwrap());
        assert!(matches!(
            open_field(&link, Some(&wrong), SendField::Data, &data),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            open_field(&link, None, SendField::Data, &data),
            Err(Error::PasswordRequired)
        ));
        assert!(matches!(
            link.decrypt(SendField::Data, &data),
            Err(Error::UnsupportedVersion(2))
        ));
        let other = SendKey::generate()
            .unwrap()
            .content_key(&secrets("hunter2", &p).unwrap());
        assert!(other.decrypt(SendField::Data, &data).is_err());
        assert!(visitor.decrypt(SendField::Name, &data).is_err());
        // The same password with another salt is another key.
        let resalted = link.content_key(&secrets("hunter2", &small(&[4; 16])).unwrap());
        assert!(resalted.decrypt(SendField::Data, &data).is_err());
        // The v2 key under v1's associated data (marker stripped) doesn't open either.
        let unmarked = b64(&unb64(&data).unwrap()[1..]);
        assert!(link.decrypt(SendField::Data, &unmarked).is_err());
        assert!(visitor.decrypt(SendField::Data, &unmarked).is_err());
        // Tampering anywhere is detected.
        let raw = unb64(&data).unwrap();
        for i in 1..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0x40;
            assert!(visitor.decrypt(SendField::Data, &b64(&bad)).is_err(), "{i}");
        }
    }

    #[test]
    fn v1_sends_open_as_before() {
        let link = SendKey::generate().unwrap();
        let data = link.encrypt(SendField::Data, b"plain link").unwrap();
        assert_eq!(field_version(&data).unwrap(), 1);
        assert_eq!(
            open_field(&link, None, SendField::Data, &data).unwrap(),
            b"plain link"
        );
        // A content key given for a v1 field is not used: the link key opens it.
        let ck = link.content_key(&secrets("pw", &small(&[1; 16])).unwrap());
        assert_eq!(
            open_field(&link, Some(&ck), SendField::Data, &data).unwrap(),
            b"plain link"
        );
        assert!(matches!(
            ck.decrypt(SendField::Data, &data),
            Err(Error::UnsupportedVersion(1))
        ));
        assert_eq!(
            key().decrypt(SendField::Data, KAT_DATA).unwrap(),
            b"Hello from PassAuth Send"
        );
        assert!(field_version("").is_err());
        assert!(matches!(
            field_version(&b64(&[3, 1])),
            Err(Error::UnsupportedVersion(3))
        ));
        assert!(password_secrets("", &new_password_salt().unwrap()).is_err());
    }

    #[test]
    fn salt_format_is_strict() {
        let s = new_password_salt().unwrap();
        assert!(s.starts_with("sendpw-v1$m=131072,t=3,p=1$"), "{s}");
        assert!(s.len() <= 512 && s.bytes().all(|b| b.is_ascii_graphic()));
        let p = parse_salt(&s).unwrap();
        assert_eq!((p.memory_kib, p.iterations, p.parallelism), (131072, 3, 1));
        assert_eq!(encode_salt(&p), s);
        assert_ne!(new_password_salt().unwrap(), s);
        let salt = s.rsplit('$').next().unwrap();
        for bad in [
            String::new(),
            format!("sendpw-v2$m=131072,t=3,p=1${salt}"),
            format!("sendpw-v1$m=131072,t=3${salt}"),
            format!("sendpw-v1$m=131072,t=3,p=1,x=1${salt}"),
            format!("sendpw-v1$t=3,m=131072,p=1${salt}"),
            format!("sendpw-v1$m=0131072,t=3,p=1${salt}"),
            format!("sendpw-v1$m=+131072,t=3,p=1${salt}"),
            format!("sendpw-v1$m=131072,t=3,p=1${salt}$"),
            "sendpw-v1$m=131072,t=3,p=1$".to_owned(),
            format!("sendpw-v1$m=131072,t=3,p=1${}", b64(&[1; 15])),
            format!("sendpw-v1$m=131072,t=3,p=1${}", b64(&[1; 17])),
            format!("sendpw-v1$m=131072,t=3,p=1${salt}="),
            format!("sendpw-v1$m=99999999999,t=3,p=1${salt}"),
        ] {
            assert!(parse_salt(&bad).is_err(), "{bad}");
            assert!(password_verifier("pw", &bad).is_err(), "{bad}");
        }
    }

    #[test]
    #[cfg(not(feature = "insecure-test-kdf"))]
    fn salt_parameters_must_be_above_the_floor() {
        let salt = b64(&[7; 16]);
        for (m, t, p) in [
            (65535, 3, 1),
            (65536, 2, 1),
            (65536, 3, 0),
            // Too weak in one way counts even when too strong in another.
            (1024 * 1024 + 1, 2, 1),
        ] {
            let s = format!("sendpw-v1$m={m},t={t},p={p}${salt}");
            assert!(
                matches!(password_verifier("pw", &s), Err(Error::WeakKdf)),
                "{s}"
            );
        }
    }

    #[test]
    fn visitors_refuse_costs_above_their_ceiling() {
        // Review L3: whoever wrote the salt picks the visitor's cost. Refused before any
        // work (these would take seconds and gigabytes), whatever the build's features.
        let salt = b64(&[7; 16]);
        for (m, t, p) in [
            (VISITOR_MAX_MEMORY_KIB + 1, 3, 1),
            (65536, VISITOR_MAX_ITERATIONS + 1, 1),
            (65536, 3, VISITOR_MAX_PARALLELISM + 1),
            (1024 * 1024, 3, 1),
            (1024 * 1024, 20, 8),
            (1024 * 1024 + 1, 21, 9),
        ] {
            let s = format!("sendpw-v1$m={m},t={t},p={p}${salt}");
            assert!(
                matches!(password_verifier("pw", &s), Err(Error::KdfTooStrong)),
                "{s}"
            );
        }
        // What this app writes is well within.
        let ours = parse_salt(&new_password_salt().unwrap()).unwrap();
        assert!(ours.memory_kib * 2 <= VISITOR_MAX_MEMORY_KIB);
        assert!(ours.iterations * 2 <= VISITOR_MAX_ITERATIONS);
        assert!(ours.parallelism <= VISITOR_MAX_PARALLELISM);
    }

    #[test]
    fn visitors_accept_up_to_their_ceiling() {
        // Computed only: deriving with 256 MiB is too slow for a unit test.
        let s = format!(
            "sendpw-v1$m={VISITOR_MAX_MEMORY_KIB},t={VISITOR_MAX_ITERATIONS},p={VISITOR_MAX_PARALLELISM}${}",
            b64(&[7; 16])
        );
        let p = visitor_params(&s).unwrap();
        assert_eq!((p.memory_kib, p.iterations, p.parallelism), (262_144, 6, 4));
        assert!(visitor_params(&new_password_salt().unwrap()).is_ok());
    }

    #[test]
    #[cfg(not(feature = "insecure-test-kdf"))]
    fn verifier_at_the_floor() {
        // The public path with real parameters (the core's floor, to keep the test fast).
        let s = format!("sendpw-v1$m=65536,t=3,p=1${}", b64(&[7; 16]));
        let v = password_verifier("hunter2", &s).unwrap();
        assert_eq!(unb64(&v).unwrap().len(), 32);
        assert_eq!(password_verifier("hunter2", &s).unwrap(), v);
        assert_ne!(password_verifier("hunter3", &s).unwrap(), v);
    }
}
