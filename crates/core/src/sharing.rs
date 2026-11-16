//! Sender-authenticated vault sharing (security review F2/F3, round 2).
//!
//! Vault keys reach other members in anonymous sealed boxes, so on their own they
//! prove nothing about who sealed them: a malicious server could seal a key of its
//! own "from" a colleague, serve an older key after a key replacement, or have a key
//! replacement sealed to members it chose. This module adds, on top of the boxes:
//!
//! - **Signing identities**: an Ed25519 key pair per account. The private key (its
//!   32-byte seed) is wrapped by the Account Key (`passauth/signing-key/v1/<account
//!   id>`). The identity statement (user id, X25519 key, Ed25519 key) is signed twice:
//!   by the Ed25519 key and, as an XEdDSA cross-signature, by the X25519 key, so
//!   nobody can attach their own Ed25519 key to someone else's X25519 key. An identity
//!   is `(user id, X25519 public key, Ed25519 public key)`; its hash and fingerprint
//!   cover all three. Accounts from before have only the X25519 key: their *legacy*
//!   identity hashes an empty signing key and carries no signing authority anywhere.
//! - **Share statements**: whoever seals a vault key to a member signs what they gave
//!   to whom: vault, recipient and their identity, role, key epoch, the sealed box
//!   (its SHA-256) and the signer.
//! - **Member rosters**: per vault, a signed, versioned list of the members (user id,
//!   identity hash, role) with the key epoch and a commitment to the vault key at that
//!   epoch. Version 1 is signed by an owner or admin it lists, after the signer
//!   reviewed every member ([`roster_review`]); every later version by an owner or
//!   admin of the version before, within a hierarchy (only the owner changes the owner
//!   entry or admins; a member's identity changes only by them or the owner).
//! - **Key pins** (trust on first use): each account's own list of the identities it
//!   has seen for other users, its own identity, the vaults it accepted (with each
//!   vault's key epoch, key id and retired key ids), the vaults it left, and the
//!   shared vaults it already had when it first checked signatures, sealed with its
//!   Account Key so they follow the account to every device.
//!
//! Everything signed is encoded canonically: a sequence of fields, each a 4-byte
//! big-endian length and its bytes, the first field the domain tag (e.g.
//! `passauth/share/v1`); numbers are 8-byte big-endian fields; lists start with their
//! count (a number). Never JSON. docs/ARCHITECTURE.md ("Signed sharing") has the byte
//! layouts and the client protocol; testdata/vectors.json (`signedSharing`) pins them.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::crypto::{SymmetricKey, fingerprint_digest, hkdf_key, random_bytes};
use crate::item::{b64, unb64};
use crate::keys::{UnlockedAccount, share_vault_key};
use crate::{Error, Result};

const IDENTITY_TAG: &[u8] = b"passauth/identity/v1";
const IDENTITY_HASH_TAG: &[u8] = b"passauth/identity-hash/v1";
const SHARE_TAG: &[u8] = b"passauth/share/v1";
const ROSTER_TAG: &[u8] = b"passauth/member-roster/v1";
const COMMITMENT_TAG: &[u8] = b"passauth/vault-key-commitment/v1";
const KEY_ID_TAG: &[u8] = b"passauth/vault-key-id/v1";
const MEMBER_LIST_TAG: &[u8] = b"passauth/member-list/v2";
const ROSTER_HASH_TAG: &[u8] = b"passauth/member-roster-hash/v1";
const SIGNING_KEY_AAD: &str = "passauth/signing-key/v1/";
const KEY_PINS_AAD: &str = "passauth/key-pins/v1/";

/// Longest user or vault id (bytes). Ids are UUIDs in practice.
pub const MAX_ID: usize = 128;
/// Most members one roster lists.
pub const MAX_ROSTER_MEMBERS: usize = 2000;
/// Largest roster JSON accepted (bytes).
pub const MAX_ROSTER_JSON: usize = 512 * 1024;
/// Most roster versions [`verify_roster_chain`] checks in one call (`too_large` beyond).
pub const MAX_ROSTER_CHAIN: usize = 1000;
/// Largest key pins JSON sealed (bytes): sealed and in base64url it stays below the
/// server's 256 KiB.
pub const MAX_KEY_PINS_JSON: usize = 190 * 1024;
/// Longest email address kept in a pin (bytes).
pub const MAX_PIN_EMAIL: usize = 320;
/// Retired key ids kept per vault (the oldest go first).
pub const MAX_RETIRED_KEY_IDS: usize = 1024;
/// Retired key ids kept in a tombstone's pin (the newest; review round 4 L5). A re-join
/// also needs a share signature and a roster chain that bind the key to its epoch.
pub const MAX_TOMBSTONE_RETIRED_KEY_IDS: usize = 64;
/// Retired key ids the key pins keep for all accepted vaults together (review round 4
/// L5: an admin replacing the keys of many vaults could otherwise grow the pins past
/// [`MAX_KEY_PINS_JSON`]). Beyond it the longest lists lose their oldest ids first,
/// never below [`MAX_TOMBSTONE_RETIRED_KEY_IDS`] per vault.
pub const MAX_TOTAL_RETIRED_KEY_IDS: usize = 4096;
/// Bytes of a retired key id kept in the pins: the first 12 of the 32-byte [`key_id`]
/// (96 bits; a server can't make a key with a chosen id, and only members' apps replace
/// keys, so a collision would need ~2^96 work). Full 32-byte ids from before are read too.
pub const RETIRED_KEY_ID_BYTES: usize = 12;
/// The member roster format this core writes and reads.
pub const ROSTER_FORMAT: u32 = 1;
/// Roles a share or roster may name.
pub const ROLES: [&str; 4] = ["read", "write", "admin", "owner"];

// ------------------------------------------------------------- encoding

/// Canonical bytes: length-prefixed fields (see the module docs).
struct Canon(Vec<u8>);

impl Canon {
    fn new(tag: &[u8]) -> Self {
        Self(Vec::with_capacity(256)).field(tag)
    }

    fn field(mut self, bytes: &[u8]) -> Self {
        // Every field is bounded (ids, hashes, tags, roles), far below 4 GiB.
        let len = u32::try_from(bytes.len()).expect("canonical fields are bounded");
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    fn text(self, s: &str) -> Self {
        self.field(s.as_bytes())
    }

    fn number(self, n: u64) -> Self {
        self.field(&n.to_be_bytes())
    }

    fn bytes(self) -> Vec<u8> {
        self.0
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A user or vault id: non-empty, at most [`MAX_ID`] bytes, no control characters.
fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID || id.chars().any(char::is_control) {
        return Err(Error::Malformed(
            "ids must be 1–128 bytes without control characters",
        ));
    }
    Ok(())
}

fn check_role(role: &str) -> Result<()> {
    if ROLES.contains(&role) {
        Ok(())
    } else {
        Err(Error::Malformed("role must be read, write, admin or owner"))
    }
}

fn is_manager_role(role: &str) -> bool {
    role == "owner" || role == "admin"
}

fn key32(s: &str, what: &'static str) -> Result<[u8; 32]> {
    unb64(s)?.try_into().map_err(|_| Error::Malformed(what))
}

fn sig64(s: &str) -> Result<[u8; 64]> {
    unb64(s)?
        .try_into()
        .map_err(|_| Error::Malformed("signature length"))
}

fn signature(s: &str) -> Result<Signature> {
    Ok(Signature::from_bytes(&sig64(s)?))
}

/// An Ed25519 public key; refuses malformed points and weak (small-order) keys.
fn verifying_key(s: &str) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&key32(s, "signing key length")?)
        .map_err(|_| Error::Malformed("signing key"))?;
    if key.is_weak() {
        return Err(Error::Malformed("signing key"));
    }
    Ok(key)
}

/// `verify_strict`: no malleable signatures, no small-order keys or points.
fn verify(key: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<()> {
    key.verify_strict(message, sig)
        .map_err(|_| Error::BadSignature)
}

/// Equal strings without an early exit on the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ---------------------------------------------------------------- XEdDSA

/// `hash_1` of the XEdDSA specification: SHA-512 of `2^256 − 2` (little-endian: 0xFE
/// then 31 × 0xFF) before the input.
fn xeddsa_hash1_prefix() -> [u8; 32] {
    let mut prefix = [0xFF; 32];
    prefix[0] = 0xFE;
    prefix
}

/// XEdDSA signature (Signal's "The XEdDSA and VXEdDSA Signature Schemes", rev. 1,
/// `xeddsa_sign`) of `message` by the X25519 private key `secret` (used clamped, as
/// X25519 uses it), with `z` = 64 fresh random bytes. The Edwards key pair is the
/// X25519 one with its sign bit forced to 0 (`calculate_key_pair`), so the signature
/// verifies as a plain Ed25519 signature under [`xeddsa_public_key`] of the X25519
/// public key. Apps don't call this: [`UnlockedAccount::new_signing_identity`] does
/// (fixed `z` only in test vectors).
pub fn xeddsa_sign(secret: &[u8; 32], message: &[u8], z: &[u8; 64]) -> [u8; 64] {
    let clamped = Zeroizing::new(clamp_integer(*secret));
    let k = Zeroizing::new(Scalar::from_bytes_mod_order(*clamped));
    let e = EdwardsPoint::mul_base(&k).compress();
    let negative = Choice::from(e.as_bytes()[31] >> 7);
    let minus_k = Zeroizing::new(-*k);
    let a = Zeroizing::new(Scalar::conditional_select(&k, &minus_k, negative));
    let big_a = EdwardsPoint::mul_base(&a).compress();
    let mut h1 = Sha512::new();
    h1.update(xeddsa_hash1_prefix());
    h1.update(a.as_bytes());
    h1.update(message);
    h1.update(z);
    // `Sha512` wipes its state and buffer (which held `a`) on drop (sha2 `zeroize`).
    let wide: Zeroizing<[u8; 64]> = Zeroizing::new(h1.finalize().into());
    let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    let big_r = EdwardsPoint::mul_base(&r).compress();
    let mut h = Sha512::new();
    h.update(big_r.as_bytes());
    h.update(big_a.as_bytes());
    h.update(message);
    let h = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    // `h·a` would reveal `a` with the signature's `s`: wiped too (review round 4 I4).
    let ha = Zeroizing::new(h * *a);
    let s = *ha + *r;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(big_r.as_bytes());
    out[32..].copy_from_slice(s.as_bytes());
    out
}

/// The Ed25519 public key XEdDSA signatures of the X25519 key `u` verify under: the
/// Edwards point with `y = (u − 1) / (u + 1)` and sign bit 0 (`convert_mont`). `None`
/// for a non-canonical `u` (≥ p, or the top bit set), a `u` not on the curve, and
/// small-order points.
pub fn xeddsa_public_key(u: &[u8; 32]) -> Option<[u8; 32]> {
    let point = MontgomeryPoint(*u).to_edwards(0)?;
    if point.to_montgomery().to_bytes() != *u || point.is_small_order() {
        return None;
    }
    Some(point.compress().to_bytes())
}

/// `xeddsa_verify`: whether `signature` is an XEdDSA signature of `message` by the
/// X25519 key `u`. Checked as Ed25519 with `verify_strict` under
/// [`xeddsa_public_key`] (canonical `s`, no small-order `R`).
pub fn xeddsa_verify(u: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(a) = xeddsa_public_key(u) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&a) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

// ------------------------------------------------------------ identities

/// The bytes an identity's keys sign (the Ed25519 key, and the X25519 key as an
/// XEdDSA cross-signature): its account and both keys.
pub fn identity_statement(user_id: &str, public_key: &[u8; 32], signing_key: &[u8; 32]) -> Vec<u8> {
    Canon::new(IDENTITY_TAG)
        .text(user_id)
        .field(public_key)
        .field(signing_key)
        .bytes()
}

/// SHA-256 of `passauth/identity-hash/v1`, the user id, the X25519 key and the
/// Ed25519 key (an empty field for a legacy identity, which has none).
pub fn identity_hash(
    user_id: &str,
    public_key: &[u8; 32],
    signing_key: Option<&[u8; 32]>,
) -> [u8; 32] {
    sha256(
        &Canon::new(IDENTITY_HASH_TAG)
            .text(user_id)
            .field(public_key)
            .field(signing_key.map_or(&[][..], |k| &k[..]))
            .bytes(),
    )
}

/// A user's public identity as the server lists it (also the shape of member rows,
/// `/users/lookup` and `invited_by`, whose `id` is read as `user_id`; other fields are
/// ignored). `signing_key`, `identity_signature` and `x25519_signature` are all null
/// for an account that has no signing identity yet (legacy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    #[serde(alias = "id")]
    pub user_id: String,
    /// X25519, base64url.
    pub public_key: String,
    /// Ed25519, base64url.
    #[serde(default)]
    pub signing_key: Option<String>,
    /// Ed25519 signature of [`identity_statement`], base64url.
    #[serde(default)]
    pub identity_signature: Option<String>,
    /// XEdDSA signature of [`identity_statement`] by the X25519 key, base64url.
    #[serde(default)]
    pub x25519_signature: Option<String>,
}

/// A [`PublicIdentity`] whose keys parsed and whose identity signatures verified.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    user_id: String,
    public_key: [u8; 32],
    signing: Option<VerifyingKey>,
    hash: [u8; 32],
    legacy_hash: [u8; 32],
}

impl PublicIdentity {
    /// Parse the keys and check both identity signatures (a legacy identity has
    /// neither key nor signatures; anything in between is malformed).
    pub fn verify(&self) -> Result<VerifiedIdentity> {
        check_id(&self.user_id)?;
        let public_key = key32(&self.public_key, "public key length")?;
        let legacy_hash = identity_hash(&self.user_id, &public_key, None);
        let (signing, hash) = match (
            &self.signing_key,
            &self.identity_signature,
            &self.x25519_signature,
        ) {
            (None, None, None) => (None, legacy_hash),
            (Some(k), Some(s), Some(x)) => {
                let key = verifying_key(k)?;
                let statement = identity_statement(&self.user_id, &public_key, key.as_bytes());
                verify(&key, &statement, &signature(s)?)?;
                if !xeddsa_verify(&public_key, &statement, &sig64(x)?) {
                    return Err(Error::BadSignature);
                }
                let hash = identity_hash(&self.user_id, &public_key, Some(key.as_bytes()));
                (Some(key), hash)
            }
            _ => {
                return Err(Error::Malformed(
                    "signing_key, identity_signature and x25519_signature go together",
                ));
            }
        };
        Ok(VerifiedIdentity {
            user_id: self.user_id.clone(),
            public_key,
            signing,
            hash,
            legacy_hash,
        })
    }
}

impl VerifiedIdentity {
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Whether the account has a signing identity (else legacy: X25519 only).
    pub fn is_signing(&self) -> bool {
        self.signing.is_some()
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The hash base64url, as rosters and pins hold it.
    pub fn hash_b64(&self) -> String {
        b64(&self.hash)
    }

    /// The same user id and X25519 key without the signing key.
    pub fn legacy_hash(&self) -> [u8; 32] {
        self.legacy_hash
    }

    /// The X25519 key vault keys are sealed to.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// For out-of-band comparison: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` over the identity
    /// hash (user id and both keys), unlike the older X25519-only `fingerprint`.
    pub fn fingerprint(&self) -> String {
        fingerprint_digest(&self.hash)
    }

    /// Whether `hash` (from a share statement or roster) names this identity as a
    /// *member*: its hash, or its legacy hash (the same user and X25519 key, written
    /// before the account had a signing key; the key a vault key is sealed to is the
    /// same, and the XEdDSA cross-signature binds the signing key to it). Never
    /// enough for authority: see [`is_exactly`](Self::is_exactly).
    pub fn matches(&self, hash: &[u8]) -> bool {
        let full: &[u8] = &self.hash;
        let legacy: &[u8] = &self.legacy_hash;
        bool::from(hash.ct_eq(full)) || bool::from(hash.ct_eq(legacy))
    }

    fn matches_b64(&self, hash: &str) -> bool {
        unb64(hash).is_ok_and(|h| self.matches(&h))
    }

    /// Whether `hash` is this identity's full hash and it has a signing key: what
    /// signing authority (roster owner/admin, share signer) requires. A legacy
    /// listing grants none.
    pub fn is_exactly(&self, hash: &[u8]) -> bool {
        let full: &[u8] = &self.hash;
        self.is_signing() && bool::from(hash.ct_eq(full))
    }

    fn is_exactly_b64(&self, hash: &str) -> bool {
        unb64(hash).is_ok_and(|h| self.is_exactly(&h))
    }

    fn signing_key(&self) -> Result<&VerifyingKey> {
        self.signing
            .as_ref()
            .ok_or(Error::Malformed("the signer has no signing identity"))
    }
}

/// What an account uploads once (`PUT /account/identity`), and what `/sync` returns
/// as `user.identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Ed25519 public key, base64url.
    pub signing_key: String,
    /// Ed25519 signature of [`identity_statement`], base64url.
    pub identity_signature: String,
    /// XEdDSA signature of [`identity_statement`] by the account's X25519 key,
    /// base64url.
    pub x25519_signature: String,
    /// The 32-byte Ed25519 seed encrypted with the Account Key, associated data
    /// `passauth/signing-key/v1/<account id>`, base64url.
    pub wrapped_signing_key: String,
}

/// An account's own signing identity, held while the vault is unlocked. The private
/// key is wiped on drop.
pub struct SigningIdentity {
    user_id: String,
    public_key: [u8; 32],
    key: SigningKey,
    /// The cross-signature made with the identity (XEdDSA uses a random nonce, so it is
    /// kept, not made again).
    x25519_signature: String,
}

/// [`UnlockedAccount::new_signing_identity`]'s answer.
pub struct NewSigningIdentity {
    pub identity: SigningIdentity,
    /// Upload once with `PUT /account/identity`.
    pub record: IdentityRecord,
}

fn signing_key_aad(account_id: &str) -> Vec<u8> {
    format!("{SIGNING_KEY_AAD}{account_id}").into_bytes()
}

impl UnlockedAccount {
    /// A new signing identity for this account: an Ed25519 key, its seed wrapped by
    /// the Account Key, its signature over the account's X25519 key and the X25519
    /// key's XEdDSA signature over the Ed25519 key (the same statement).
    pub fn new_signing_identity(&self) -> Result<NewSigningIdentity> {
        check_id(&self.account_id)?;
        let seed = Zeroizing::new(random_bytes::<32>()?);
        let wrapped = self
            .account_key
            .encrypt(&seed[..], &signing_key_aad(&self.account_id))?;
        let public_key = self.keypair.public_bytes();
        let ed = SigningKey::from_bytes(&seed);
        let statement = identity_statement(
            &self.account_id,
            &public_key,
            &ed.verifying_key().to_bytes(),
        );
        let secret = Zeroizing::new(self.keypair.secret_bytes());
        let z = Zeroizing::new(random_bytes::<64>()?);
        let x25519_signature = b64(&xeddsa_sign(&secret, &statement, &z));
        let identity = SigningIdentity {
            user_id: self.account_id.clone(),
            public_key,
            key: ed,
            x25519_signature,
        };
        let public = identity.public();
        public.verify()?;
        Ok(NewSigningIdentity {
            record: IdentityRecord {
                signing_key: public.signing_key.expect("a signing identity's own"),
                identity_signature: public.identity_signature.expect("a signing identity's own"),
                x25519_signature: public.x25519_signature.expect("a signing identity's own"),
                wrapped_signing_key: b64(&wrapped),
            },
            identity,
        })
    }

    /// Open this account's signing identity from its record (`/sync` `user.identity`).
    /// [`Error::IdentityMismatch`] when the record's public key or signatures aren't the
    /// wrapped key's and this account's X25519 key's own (the server lists another
    /// identity for this account).
    pub fn open_signing_identity(&self, record: &IdentityRecord) -> Result<SigningIdentity> {
        check_id(&self.account_id)?;
        let seed = Zeroizing::new(self.account_key.decrypt(
            &unb64(&record.wrapped_signing_key)?,
            &signing_key_aad(&self.account_id),
        )?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| Error::Malformed("signing key length"))?,
        );
        let identity = SigningIdentity {
            user_id: self.account_id.clone(),
            public_key: self.keypair.public_bytes(),
            key: SigningKey::from_bytes(&seed),
            x25519_signature: record.x25519_signature.clone(),
        };
        let listed = PublicIdentity {
            user_id: self.account_id.clone(),
            public_key: b64(&self.keypair.public_bytes()),
            signing_key: Some(record.signing_key.clone()),
            identity_signature: Some(record.identity_signature.clone()),
            x25519_signature: Some(record.x25519_signature.clone()),
        };
        let verified = listed.verify().map_err(|_| Error::IdentityMismatch)?;
        if !verified.is_exactly(&identity.identity_hash()) {
            return Err(Error::IdentityMismatch);
        }
        Ok(identity)
    }

    /// This account's legacy identity (no signing key): what other members used for
    /// it before it had a signing identity.
    pub fn legacy_identity(&self) -> PublicIdentity {
        PublicIdentity {
            user_id: self.account_id.clone(),
            public_key: b64(&self.keypair.public_bytes()),
            signing_key: None,
            identity_signature: None,
            x25519_signature: None,
        }
    }

    /// Seal this account's key pins with the Account Key (base64url), as version `seq`
    /// (the `seq` sent with `PUT /account/key-pins`). Refuses pins over
    /// [`MAX_KEY_PINS_JSON`] ([`Error::TooLarge`]): never trimmed.
    pub fn seal_key_pins(&self, pins: &KeyPins, seq: u64) -> Result<String> {
        check_id(&self.account_id)?;
        pins.check()?;
        let mut pins = pins.clone();
        pins.version = seq;
        pins.pins.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        let json = Zeroizing::new(serde_json::to_vec(&pins)?);
        if json.len() > MAX_KEY_PINS_JSON {
            return Err(Error::TooLarge);
        }
        Ok(b64(&self
            .account_key
            .encrypt(&json, &key_pins_aad(&self.account_id))?))
    }

    /// Open key pins sealed by [`seal_key_pins`](Self::seal_key_pins): this account's,
    /// unchanged, with version `seq` (the server's `seq` for them; another version is
    /// [`Error::Rollback`]: an older list under a newer number).
    pub fn open_key_pins(&self, sealed: &str, seq: u64) -> Result<KeyPins> {
        check_id(&self.account_id)?;
        let json = Zeroizing::new(
            self.account_key
                .decrypt(&unb64(sealed)?, &key_pins_aad(&self.account_id))?,
        );
        let pins: KeyPins = serde_json::from_slice(&json)?;
        pins.check()?;
        if pins.version != seq {
            return Err(Error::Rollback);
        }
        Ok(pins)
    }
}

fn key_pins_aad(account_id: &str) -> Vec<u8> {
    format!("{KEY_PINS_AAD}{account_id}").into_bytes()
}

impl SigningIdentity {
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    fn signing_public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The public identity other users verify (the same every time: Ed25519
    /// signatures are deterministic and the cross-signature is kept).
    pub fn public(&self) -> PublicIdentity {
        let signing = self.signing_public();
        let statement = identity_statement(&self.user_id, &self.public_key, &signing);
        PublicIdentity {
            user_id: self.user_id.clone(),
            public_key: b64(&self.public_key),
            signing_key: Some(b64(&signing)),
            identity_signature: Some(b64(&self.key.sign(&statement).to_bytes())),
            x25519_signature: Some(self.x25519_signature.clone()),
        }
    }

    pub fn identity_hash(&self) -> [u8; 32] {
        identity_hash(
            &self.user_id,
            &self.public_key,
            Some(&self.signing_public()),
        )
    }

    /// See [`VerifiedIdentity::fingerprint`].
    pub fn fingerprint(&self) -> String {
        fingerprint_digest(&self.identity_hash())
    }

    fn sign(&self, message: &[u8]) -> String {
        b64(&self.key.sign(message).to_bytes())
    }

    /// Sign that `sealed_key` gives `recipient` the key of `vault_id` at `key_epoch`
    /// with `role` (base64url signature). The recipient's identity must verify.
    pub fn sign_share(
        &self,
        vault_id: &str,
        recipient: &PublicIdentity,
        role: &str,
        key_epoch: u64,
        sealed_key: &str,
    ) -> Result<String> {
        let recipient = recipient.verify()?;
        let bytes = share_statement(&ShareStatement {
            vault_id,
            recipient_id: recipient.user_id(),
            recipient_identity: &recipient.hash(),
            role,
            key_epoch,
            sealed_key,
            signer_id: &self.user_id,
        })?;
        Ok(self.sign(&bytes))
    }

    /// Seal `vault_key` to `recipient` (their identity must verify) and sign the share.
    pub fn seal_and_sign_share(
        &self,
        vault_key: &SymmetricKey,
        vault_id: &str,
        recipient: &PublicIdentity,
        role: &str,
        key_epoch: u64,
    ) -> Result<SignedShare> {
        recipient.verify()?;
        check_id(vault_id)?;
        check_role(role)?;
        let sealed_key = share_vault_key(vault_id, vault_key, &recipient.public_key)?;
        let signature = self.sign_share(vault_id, recipient, role, key_epoch, &sealed_key)?;
        Ok(SignedShare {
            sealed_key,
            signature,
        })
    }

    /// Sign the next member roster of `vault_id`: version `previous.version + 1` (1
    /// without a `previous`, which must then have been reviewed member by member, see
    /// [`roster_review`]) at key epoch `key_epoch`, whose key is `vault_key` (its
    /// commitment goes in), listing `members` (the member rows after the change).
    /// `previous` is the roster this device trusts for the vault (verified). The list
    /// must be exactly the one reviewed: `reviewed` is [`RosterReview::digest`] (else
    /// [`Error::ReviewMismatch`]: the server's answer changed since, or the review was
    /// `blocked`, whose digest is empty). `previous` must check on its own. A non-owner keeps
    /// a member's legacy listing where `previous` has one (only the owner or the member
    /// replaces it); owners and admins need a signing identity; the change must follow
    /// the hierarchy ([`verify_roster_chain`], else [`Error::RosterUnauthorized`]).
    pub fn sign_roster(
        &self,
        vault_key: &SymmetricKey,
        vault_id: &str,
        previous: Option<&SignedRoster>,
        key_epoch: u64,
        members: &[RosterMemberInput],
        reviewed: &str,
    ) -> Result<SignedRoster> {
        check_id(vault_id)?;
        let me = self.public().verify()?;
        if let Some(p) = previous {
            p.check()?;
            if p.vault_id != vault_id {
                return Err(Error::Malformed("member rosters of another vault"));
            }
        }
        let entries = roster_entries(previous, &me, members)?;
        if !same(&member_list_digest(vault_id, previous, &entries)?, reviewed) {
            return Err(Error::ReviewMismatch);
        }
        let version = previous.map_or(1, |p| p.version.saturating_add(1));
        let roster = self.sign_entries(vault_key, vault_id, version, key_epoch, entries)?;
        match previous {
            Some(p) => check_step(p, &roster)?,
            None => roster.check()?,
        }
        Ok(roster)
    }

    /// A roster with version `version` listing `members` with their full hashes, signed
    /// without the review, chain or hierarchy checks: only for tests (servers' tests
    /// make rosters the protocol forbids, to see them refused).
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    pub fn sign_roster_unchecked(
        &self,
        vault_key: &SymmetricKey,
        vault_id: &str,
        version: u64,
        key_epoch: u64,
        members: &[RosterMemberInput],
    ) -> Result<SignedRoster> {
        let mut entries = BTreeMap::new();
        for m in members {
            check_role(&m.role)?;
            let v = m.identity.verify()?;
            let entry = RosterMember {
                user_id: v.user_id().to_owned(),
                identity: v.hash_b64(),
                role: m.role.clone(),
            };
            if entries.insert(entry.user_id.clone(), entry).is_some() {
                return Err(Error::Malformed("a member is listed twice"));
            }
        }
        let roster = self.sign_entries(
            vault_key,
            vault_id,
            version,
            key_epoch,
            entries.into_values().collect(),
        )?;
        roster.check()?;
        Ok(roster)
    }

    fn sign_entries(
        &self,
        vault_key: &SymmetricKey,
        vault_id: &str,
        version: u64,
        key_epoch: u64,
        members: Vec<RosterMember>,
    ) -> Result<SignedRoster> {
        let mut roster = SignedRoster {
            format: ROSTER_FORMAT,
            vault_id: vault_id.to_owned(),
            version,
            key_epoch,
            key_commitment: key_commitment(vault_key, vault_id, key_epoch)?,
            members,
            signer: self.public(),
            signature: String::new(),
        };
        roster.signature = self.sign(&roster.signed_bytes(&self.identity_hash())?);
        Ok(roster)
    }
}

// ----------------------------------------------------------------- shares

/// What a share signature covers (see [`share_statement`]).
pub struct ShareStatement<'a> {
    pub vault_id: &'a str,
    pub recipient_id: &'a str,
    /// The recipient's identity hash as the signer saw it.
    pub recipient_identity: &'a [u8; 32],
    pub role: &'a str,
    pub key_epoch: u64,
    /// The sealed box exactly as the server stores it (base64url text); its SHA-256
    /// is signed.
    pub sealed_key: &'a str,
    pub signer_id: &'a str,
}

/// The canonical bytes of a share statement: tag `passauth/share/v1`, vault id,
/// recipient id, recipient identity hash (32), role, key epoch (u64), SHA-256 of the
/// sealed key's text (32), signer id.
pub fn share_statement(s: &ShareStatement) -> Result<Vec<u8>> {
    check_id(s.vault_id)?;
    check_id(s.recipient_id)?;
    check_id(s.signer_id)?;
    check_role(s.role)?;
    Ok(Canon::new(SHARE_TAG)
        .text(s.vault_id)
        .text(s.recipient_id)
        .field(s.recipient_identity)
        .text(s.role)
        .number(s.key_epoch)
        .field(&sha256(s.sealed_key.as_bytes()))
        .text(s.signer_id)
        .bytes())
}

/// A vault key sealed to a member and the signature over the share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedShare {
    pub sealed_key: String,
    pub signature: String,
}

/// Check a share signature: `signer` signed that `sealed_key` gives `recipient` the
/// key of `vault_id` at `key_epoch` with `role`. The recipient's identity hash in the
/// statement may be their full or legacy one; the signer needs a signing identity (a
/// legacy identity signs nothing). Returns the signer's verified identity (for the key
/// pin and the roster checks). [`Error::BadSignature`] when it doesn't verify.
pub fn verify_share(
    vault_id: &str,
    recipient: &PublicIdentity,
    role: &str,
    key_epoch: u64,
    sealed_key: &str,
    signer: &PublicIdentity,
    signature_b64: &str,
) -> Result<VerifiedIdentity> {
    let recipient = recipient.verify()?;
    let signer = signer.verify()?;
    let key = *signer.signing_key()?;
    let sig = signature(signature_b64)?;
    let mut hashes = vec![recipient.hash()];
    if recipient.is_signing() {
        hashes.push(recipient.legacy_hash());
    }
    for hash in &hashes {
        let bytes = share_statement(&ShareStatement {
            vault_id,
            recipient_id: recipient.user_id(),
            recipient_identity: hash,
            role,
            key_epoch,
            sealed_key,
            signer_id: signer.user_id(),
        })?;
        if verify(&key, &bytes, &sig).is_ok() {
            return Ok(signer);
        }
    }
    Err(Error::BadSignature)
}

// --------------------------------------------------------- member rosters

/// One member in a roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterMember {
    pub user_id: String,
    /// Identity hash, base64url.
    pub identity: String,
    pub role: String,
}

/// A member for [`roster_review`], [`SigningIdentity::sign_roster`] and
/// [`compare_members`]: the shape of the server's member rows (identity fields,
/// `role` and `email`; others are ignored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMemberInput {
    #[serde(flatten)]
    pub identity: PublicIdentity,
    pub role: String,
    /// The email the server lists (shown as "listed by your server as …" when it
    /// differs from the pinned one); never signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// A signed member roster, the JSON the server stores and returns as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRoster {
    /// [`ROSTER_FORMAT`].
    pub format: u32,
    pub vault_id: String,
    /// 1, 2, …: one more with every change.
    pub version: u64,
    /// The vault's key epoch when it was signed.
    pub key_epoch: u64,
    /// [`key_commitment`] of the vault key at `key_epoch`.
    pub key_commitment: String,
    /// Sorted by `user_id` (byte order), each once.
    pub members: Vec<RosterMember>,
    /// The signer's full public identity.
    pub signer: PublicIdentity,
    pub signature: String,
}

impl SignedRoster {
    /// Parse and [`check`](Self::check) a roster from the server.
    pub fn parse(json: &str) -> Result<Self> {
        if json.len() > MAX_ROSTER_JSON {
            return Err(Error::TooLarge);
        }
        let roster: Self = serde_json::from_str(json)?;
        roster.check()?;
        Ok(roster)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// The canonical bytes signed: tag `passauth/member-roster/v1`, vault id, version
    /// (u64), key epoch (u64), key commitment (32), member count (u64), then per member
    /// user id, identity hash (32) and role; then the signer's user id and identity
    /// hash (32).
    pub fn signed_bytes(&self, signer_hash: &[u8; 32]) -> Result<Vec<u8>> {
        check_id(&self.vault_id)?;
        check_id(&self.signer.user_id)?;
        let commitment: [u8; 32] = key32(&self.key_commitment, "key commitment length")?;
        let mut c = Canon::new(ROSTER_TAG)
            .text(&self.vault_id)
            .number(self.version)
            .number(self.key_epoch)
            .field(&commitment)
            .number(self.members.len() as u64);
        for m in &self.members {
            check_id(&m.user_id)?;
            check_role(&m.role)?;
            c = c
                .text(&m.user_id)
                .field(&key32(&m.identity, "identity hash length")?)
                .text(&m.role);
        }
        Ok(c.text(&self.signer.user_id).field(signer_hash).bytes())
    }

    /// The roster on its own: format, ids, members sorted and unique with valid roles
    /// and exactly one owner, the signer's identity and signature, and the signer
    /// listed in it as owner or admin with exactly that (full, signing) identity.
    pub fn check(&self) -> Result<()> {
        if self.format != ROSTER_FORMAT {
            return Err(Error::Malformed("unknown member roster format"));
        }
        check_id(&self.vault_id)?;
        if self.version == 0 {
            return Err(Error::Malformed("member roster versions start at 1"));
        }
        if self.members.is_empty() || self.members.len() > MAX_ROSTER_MEMBERS {
            return Err(Error::Malformed("member roster size"));
        }
        if self
            .members
            .windows(2)
            .any(|w| w[0].user_id.as_bytes() >= w[1].user_id.as_bytes())
        {
            return Err(Error::Malformed(
                "members must be sorted by user id, each once",
            ));
        }
        if self.members.iter().filter(|m| m.role == "owner").count() != 1 {
            return Err(Error::Malformed("a member roster lists exactly one owner"));
        }
        let signer = self.signer.verify()?;
        let key = *signer.signing_key()?;
        if !self.manages(&signer) {
            return Err(Error::RosterUnauthorized);
        }
        verify(
            &key,
            &self.signed_bytes(&signer.hash())?,
            &signature(&self.signature)?,
        )
    }

    fn entry(&self, user_id: &str) -> Option<&RosterMember> {
        self.members.iter().find(|m| m.user_id == user_id)
    }

    /// Whether `who` is listed as owner or admin with exactly their full identity.
    fn manages(&self, who: &VerifiedIdentity) -> bool {
        self.entry(who.user_id())
            .is_some_and(|m| is_manager_role(&m.role) && who.is_exactly_b64(&m.identity))
    }

    /// Whether `who` is this roster's owner, listed with exactly their full identity.
    fn is_owner(&self, who: &VerifiedIdentity) -> bool {
        self.entry(who.user_id())
            .is_some_and(|m| m.role == "owner" && who.is_exactly_b64(&m.identity))
    }

    fn owner(&self) -> Option<&RosterMember> {
        self.members.iter().find(|m| m.role == "owner")
    }

    /// The role this roster gives `identity` as a *member* (listed with their full or
    /// legacy hash): for "the roster lists me with the role my row has".
    pub fn member_role(&self, identity: &PublicIdentity) -> Result<Option<String>> {
        let who = identity.verify()?;
        Ok(self
            .entry(who.user_id())
            .filter(|m| who.matches_b64(&m.identity))
            .map(|m| m.role.clone()))
    }

    /// The role this roster gives `signer` as a *signer*: only when listed with exactly
    /// their full identity (a signing one). For "the share's signer is an owner or
    /// admin": a legacy listing carries no authority.
    pub fn signer_role(&self, signer: &PublicIdentity) -> Result<Option<String>> {
        let who = signer.verify()?;
        Ok(self
            .entry(who.user_id())
            .filter(|m| who.is_exactly_b64(&m.identity))
            .map(|m| m.role.clone()))
    }

    /// The roster's hash (base64url): SHA-256 of `["passauth/member-roster-hash/v1",
    /// signed bytes, signature (64)]`. Key pins remember it with the highest roster
    /// version seen per vault ([`EpochPin::roster_version_max`]), so another roster with
    /// that version is a fork on every device. The roster must [`check`](Self::check).
    pub fn hash(&self) -> Result<String> {
        let signer = self.signer.verify()?;
        Ok(b64(&sha256(
            &Canon::new(ROSTER_HASH_TAG)
                .field(&self.signed_bytes(&signer.hash())?)
                .field(&sig64(&self.signature)?)
                .bytes(),
        )))
    }

    /// Whether `vault_key` is this roster's key (its commitment at `key_epoch`) and the
    /// roster is `vault_id`'s.
    pub fn commits_to(&self, vault_id: &str, vault_key: &SymmetricKey) -> Result<bool> {
        Ok(self.vault_id == vault_id
            && same(
                &key_commitment(vault_key, &self.vault_id, self.key_epoch)?,
                &self.key_commitment,
            ))
    }
}

/// The entries a roster signed by `signer` lists for `members`, following `previous`:
/// full hashes, except that a signer who is neither the owner nor the member keeps a
/// member's legacy listing from `previous` (it names the same X25519 key). Owners and
/// admins need a signing identity.
fn roster_entries(
    previous: Option<&SignedRoster>,
    signer: &VerifiedIdentity,
    members: &[RosterMemberInput],
) -> Result<Vec<RosterMember>> {
    if members.is_empty() || members.len() > MAX_ROSTER_MEMBERS {
        return Err(Error::Malformed("member roster size"));
    }
    let by_owner = previous.is_some_and(|p| p.is_owner(signer));
    let mut entries = BTreeMap::new();
    for m in members {
        check_role(&m.role)?;
        let v = m.identity.verify()?;
        if is_manager_role(&m.role) && !v.is_signing() {
            return Err(Error::Malformed(
                "owners and admins need a signing identity",
            ));
        }
        let mut identity = v.hash_b64();
        if let Some(prev) = previous.and_then(|p| p.entry(v.user_id())) {
            let keep_legacy = !by_owner
                && v.user_id() != signer.user_id()
                && !is_manager_role(&m.role)
                && !same(&prev.identity, &identity)
                && v.matches_b64(&prev.identity);
            if keep_legacy {
                identity = prev.identity.clone();
            }
        }
        let entry = RosterMember {
            user_id: v.user_id().to_owned(),
            identity,
            role: m.role.clone(),
        };
        if entries.insert(entry.user_id.clone(), entry).is_some() {
            return Err(Error::Malformed("a member is listed twice"));
        }
    }
    Ok(entries.into_values().collect())
}

/// SHA-256 (base64url) of `["passauth/member-list/v2", vault id, version (u64), first
/// (u64: 1 without a previous roster, else 0), the previous roster's hash (32;
/// [`SignedRoster::hash`]) or an empty field, member count (u64), then per member: user
/// id, identity hash (32), role]` in the roster's order: what a review showed, so the
/// list signed can be compared with it. The version, `first` and the previous roster are
/// bound (review round 4 I3): a review made after one roster can't approve a signing
/// after another (or a version 1).
pub fn member_list_digest(
    vault_id: &str,
    previous: Option<&SignedRoster>,
    members: &[RosterMember],
) -> Result<String> {
    check_id(vault_id)?;
    let version = previous.map_or(1, |p| p.version.saturating_add(1));
    let previous_hash = previous.map(SignedRoster::hash).transpose()?;
    let mut c = Canon::new(MEMBER_LIST_TAG)
        .text(vault_id)
        .number(version)
        .number(u64::from(previous.is_none()))
        .field(&match &previous_hash {
            Some(h) => key32(h, "roster hash length")?.to_vec(),
            None => Vec::new(),
        })
        .number(members.len() as u64);
    for m in members {
        check_id(&m.user_id)?;
        check_role(&m.role)?;
        c = c
            .text(&m.user_id)
            .field(&key32(&m.identity, "identity hash length")?)
            .text(&m.role);
    }
    Ok(b64(&sha256(&c.bytes())))
}

/// The hierarchy of a change from `prev` to the member list `next` signed by `signer`
/// (an owner or admin of `prev`): the owner's user id never changes; only the owner
/// changes the owner entry, adds an admin or raises someone to admin; an admin's entry
/// otherwise changes (identity, lower role) only by the owner or that admin; any
/// manager may remove an admin (who left: removing only takes access away); a member's
/// identity hash changes only by the owner or that member.
fn check_change(
    prev: &SignedRoster,
    signer: &VerifiedIdentity,
    next: &[RosterMember],
) -> Result<()> {
    let by_owner = prev.is_owner(signer);
    let prev_owner = prev
        .owner()
        .ok_or(Error::Malformed("a member roster lists exactly one owner"))?;
    let next_owner = next
        .iter()
        .find(|m| m.role == "owner")
        .ok_or(Error::Malformed("a member roster lists exactly one owner"))?;
    if next_owner.user_id != prev_owner.user_id {
        return Err(Error::RosterUnauthorized);
    }
    if next_owner != prev_owner && !by_owner {
        return Err(Error::RosterUnauthorized);
    }
    let users: BTreeSet<&str> = prev
        .members
        .iter()
        .chain(next.iter())
        .map(|m| m.user_id.as_str())
        .collect();
    for user in users {
        let p = prev.entry(user);
        let n = next.iter().find(|m| m.user_id == user);
        let by_self = user == signer.user_id();
        let allowed = match (p, n) {
            (Some(p), Some(n)) if p == n => true,
            (_, None) => true,
            (None, Some(n)) => n.role != "admin" || by_owner,
            (Some(p), Some(n)) => {
                if p.role == "owner" || n.role == "owner" {
                    // The owner entry: checked above.
                    true
                } else if n.role == "admin" && p.role != "admin" {
                    by_owner
                } else if p.role == "admin" || !same(&p.identity, &n.identity) {
                    by_owner || by_self
                } else {
                    // A role change between read and write.
                    true
                }
            }
        };
        if !allowed {
            return Err(Error::RosterUnauthorized);
        }
    }
    Ok(())
}

/// One step of a chain: `next` checks on its own, is the same vault, the next version,
/// keeps or raises the key epoch (at the same epoch the commitment stays), is signed
/// by an owner or admin of `prev` (exactly their full identity), and follows the
/// hierarchy ([`check_change`]).
fn check_step(prev: &SignedRoster, next: &SignedRoster) -> Result<()> {
    next.check()?;
    if next.vault_id != prev.vault_id {
        return Err(Error::Malformed("member rosters of another vault"));
    }
    if next.version <= prev.version || next.key_epoch < prev.key_epoch {
        return Err(Error::Rollback);
    }
    if next.version != prev.version + 1 {
        return Err(Error::Malformed("a member roster version is missing"));
    }
    let signer = next.signer.verify()?;
    if !prev.manages(&signer) {
        return Err(Error::RosterUnauthorized);
    }
    check_change(prev, &signer, &next.members)?;
    if next.key_epoch == prev.key_epoch && !same(&next.key_commitment, &prev.key_commitment) {
        return Err(Error::Malformed(
            "a member roster changed the key commitment without a new key epoch",
        ));
    }
    Ok(())
}

/// Check a roster chain of vault `vault_id` ending at `latest` (the row's
/// `member_roster`): `newer` are the versions after `trusted` (a roster this device
/// verified before; `None`: none, so `newer` must start at version 1), oldest first,
/// at most [`MAX_ROSTER_CHAIN`] ([`Error::TooLarge`]). Each must
/// [`check`](SignedRoster::check) on its own and follow the one before (see
/// [`check_step`]: next version, key epoch, signer an owner or admin of the version
/// before with exactly their full identity, the hierarchy). The chain must end exactly
/// at `latest` (shorter: malformed; longer: [`Error::Rollback`]; another roster with
/// the same version: [`Error::RosterForked`]). Returns it, now trusted.
pub fn verify_roster_chain(
    vault_id: &str,
    trusted: Option<&SignedRoster>,
    newer: &[SignedRoster],
    latest: &SignedRoster,
) -> Result<SignedRoster> {
    check_id(vault_id)?;
    if newer.len() > MAX_ROSTER_CHAIN {
        return Err(Error::TooLarge);
    }
    if latest.vault_id != vault_id {
        return Err(Error::Malformed("member rosters of another vault"));
    }
    if let Some(t) = trusted {
        t.check()?;
        if t.vault_id != vault_id {
            return Err(Error::Malformed("member rosters of another vault"));
        }
    }
    let mut prev = trusted;
    for next in newer {
        if next.vault_id != vault_id {
            return Err(Error::Malformed("member rosters of another vault"));
        }
        match prev {
            None => {
                next.check()?;
                if next.version != 1 {
                    return Err(Error::Malformed(
                        "the member roster chain starts at version 1",
                    ));
                }
            }
            Some(p) => check_step(p, next)?,
        }
        prev = Some(next);
    }
    let end = prev.ok_or(Error::Malformed("no member roster"))?;
    match end.version.cmp(&latest.version) {
        Ordering::Less => Err(Error::Malformed(
            "the member roster chain stops before the vault's roster",
        )),
        Ordering::Greater => Err(Error::Rollback),
        Ordering::Equal if end != latest => Err(Error::RosterForked),
        Ordering::Equal => Ok(end.clone()),
    }
}

/// What a device does with the roster the server lists for a vault, given the one it
/// trusted last for that vault ([`roster_head`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RosterHead {
    /// Neither: the vault has no roster (not signed yet).
    Unsigned,
    /// The same roster: nothing to do.
    Same,
    /// A newer one: fetch the versions after `after` (`GET /vaults/{id}/rosters?after=`)
    /// and [`verify_roster_chain`] them.
    Fetch { after: u64 },
}

/// Compare the server's latest roster for vault `vault_id` with the one this device
/// trusted last. Either of another vault is malformed; an older version, or none where
/// this device saw one, is [`Error::Rollback`]; a different roster with the same
/// version is [`Error::RosterForked`].
pub fn roster_head(
    vault_id: &str,
    remembered: Option<&SignedRoster>,
    latest: Option<&SignedRoster>,
) -> Result<RosterHead> {
    check_id(vault_id)?;
    if remembered
        .into_iter()
        .chain(latest)
        .any(|r| r.vault_id != vault_id)
    {
        return Err(Error::Malformed("member rosters of another vault"));
    }
    Ok(match (remembered, latest) {
        (None, None) => RosterHead::Unsigned,
        (Some(_), None) => return Err(Error::Rollback),
        (None, Some(_)) => RosterHead::Fetch { after: 0 },
        (Some(r), Some(l)) => {
            if l.version < r.version {
                return Err(Error::Rollback);
            }
            if l.version == r.version {
                if l == r {
                    RosterHead::Same
                } else {
                    return Err(Error::RosterForked);
                }
            } else {
                RosterHead::Fetch { after: r.version }
            }
        }
    })
}

/// How the server's member list differs from a trusted roster (user ids).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MemberDiff {
    /// Listed by the server, not in the roster.
    pub unknown: Vec<String>,
    /// In both, with another identity (or one that doesn't verify).
    pub identity_changed: Vec<String>,
    /// In both, with another role.
    pub role_changed: Vec<String>,
    /// In the roster, not listed by the server (left, declined, removed or deleted
    /// since; or hidden by the server).
    pub missing: Vec<String>,
}

impl MemberDiff {
    /// No member the roster doesn't vouch for: `unknown`, `identity_changed` and
    /// `role_changed` are empty (`missing` members only lose access).
    pub fn is_clean(&self) -> bool {
        self.unknown.is_empty() && self.identity_changed.is_empty() && self.role_changed.is_empty()
    }
}

/// Compare the server's members (rows of `GET /vaults/{id}/members`) with a trusted
/// roster before sealing a new key to them.
pub fn compare_members(roster: &SignedRoster, members: &[RosterMemberInput]) -> MemberDiff {
    let mut diff = MemberDiff::default();
    for m in members {
        let id = &m.identity.user_id;
        match roster.entry(id) {
            None => diff.unknown.push(id.clone()),
            Some(entry) => {
                let same_identity = m
                    .identity
                    .verify()
                    .is_ok_and(|v| v.matches_b64(&entry.identity));
                if !same_identity {
                    diff.identity_changed.push(id.clone());
                } else if entry.role != m.role {
                    diff.role_changed.push(id.clone());
                }
            }
        }
    }
    for entry in &roster.members {
        if !members.iter().any(|m| m.identity.user_id == entry.user_id) {
            diff.missing.push(entry.user_id.clone());
        }
    }
    diff
}

/// How a member of a [`RosterReview`] differs from the trusted roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberChange {
    /// Listed the same (a legacy listing of the same X25519 key counts as the same).
    Same,
    /// Not in the trusted roster (every member when there is none: version 1).
    Added,
    /// Another identity than the trusted roster's.
    IdentityChanged,
    /// The same identity with another role.
    RoleChanged,
}

/// One member as a review shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewMember {
    pub user_id: String,
    pub role: String,
    /// The identity hash that will be signed (base64url).
    pub identity: String,
    /// The identity fingerprint of the identity the server lists (compare it).
    pub fingerprint: String,
    /// The signer's own row.
    pub is_self: bool,
    /// The key pin state ([`KeyPins::check_identity`]; for the own row `match` when
    /// the server lists this account's identity, else `changed`).
    pub pin: PinStatus,
    /// Pinned and compared out of band.
    pub verified: bool,
    /// The email pinned with this identity: the one to show first.
    pub pinned_email: Option<String>,
    /// The email the server lists now (show "listed by your server as …" when it
    /// differs from `pinned_email`; never next to "Verified").
    pub listed_email: Option<String>,
    pub change: MemberChange,
}

/// A member of the trusted roster the server no longer lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewMissing {
    pub user_id: String,
    pub role: String,
    pub identity: String,
    pub pinned_email: Option<String>,
}

/// [`roster_review`]'s answer: what the next roster would list, for the user to check
/// before anything is sealed or signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RosterReview {
    pub vault_id: String,
    /// The version [`SigningIdentity::sign_roster`] will sign (trusted + 1, or 1); it
    /// must equal the server's `member_roster_seq` + 1.
    pub version: u64,
    /// Version 1 (no trusted roster): show every member and get an explicit
    /// confirmation; automatic or background flows must stop here.
    pub first: bool,
    /// A member's key changed against the pins (`changed`, `email_conflict`), the server
    /// lists another identity for the signer, or a member's identity differs from the
    /// trusted roster's: stop (nothing may be sealed or signed).
    pub blocked: bool,
    /// Every member that will be listed, sorted by user id.
    pub members: Vec<ReviewMember>,
    /// Members of the trusted roster the server doesn't list (confirm them by user id).
    pub missing: Vec<ReviewMissing>,
    /// [`member_list_digest`] of the list that will be signed: pass it to
    /// [`SigningIdentity::sign_roster`] (which refuses another list). Empty when
    /// `blocked`, so nothing can be signed from a blocked review.
    pub digest: String,
}

/// Prepare the review of the next roster of `vault_id` that `signer` (this account's
/// own public identity, a signing one) would sign for `members` (the member rows of
/// the change), after `previous` (the roster this device trusts, or `None`: version 1,
/// which always needs the review shown), with this account's key `pins`.
/// [`Error::RosterUnauthorized`] when the signer may not make this change.
pub fn roster_review(
    vault_id: &str,
    previous: Option<&SignedRoster>,
    signer: &PublicIdentity,
    members: &[RosterMemberInput],
    pins: &KeyPins,
) -> Result<RosterReview> {
    check_id(vault_id)?;
    let me = signer.verify()?;
    me.signing_key()?;
    if let Some(p) = previous {
        p.check()?;
        if p.vault_id != vault_id {
            return Err(Error::Malformed("member rosters of another vault"));
        }
        if !p.manages(&me) {
            return Err(Error::RosterUnauthorized);
        }
    }
    let entries = roster_entries(previous, &me, members)?;
    if entries.iter().filter(|e| e.role == "owner").count() != 1 {
        return Err(Error::Malformed("a member roster lists exactly one owner"));
    }
    if !entries.iter().any(|e| {
        e.user_id == me.user_id() && is_manager_role(&e.role) && me.is_exactly_b64(&e.identity)
    }) {
        return Err(Error::RosterUnauthorized);
    }
    if let Some(p) = previous {
        check_change(p, &me, &entries)?;
    }
    let mut blocked = false;
    let mut out = Vec::with_capacity(entries.len());
    for entry in &entries {
        let row = members
            .iter()
            .find(|m| m.identity.user_id == entry.user_id)
            .expect("every entry comes from a member row");
        let v = row.identity.verify()?;
        let is_self = entry.user_id == me.user_id();
        let pinned = pins.get(&entry.user_id);
        let pin = if is_self {
            if v.is_exactly(&me.hash()) {
                PinStatus::Match
            } else {
                PinStatus::Changed
            }
        } else {
            pins.check_identity(&row.identity, row.email.as_deref())?
        };
        let change = match previous.and_then(|p| p.entry(&entry.user_id)) {
            None => MemberChange::Added,
            Some(p) if !v.matches_b64(&p.identity) => MemberChange::IdentityChanged,
            Some(p) if p.role != entry.role => MemberChange::RoleChanged,
            Some(_) => MemberChange::Same,
        };
        if matches!(pin, PinStatus::Changed | PinStatus::EmailConflict)
            || change == MemberChange::IdentityChanged
        {
            blocked = true;
        }
        out.push(ReviewMember {
            user_id: entry.user_id.clone(),
            role: entry.role.clone(),
            identity: entry.identity.clone(),
            fingerprint: v.fingerprint(),
            is_self,
            verified: pin == PinStatus::Match && pinned.is_some_and(|p| p.verified),
            pin,
            pinned_email: if is_self {
                None
            } else {
                pinned.map(|p| p.email.clone())
            },
            listed_email: row.email.clone(),
            change,
        });
    }
    let missing = previous
        .map(|p| {
            p.members
                .iter()
                .filter(|m| !entries.iter().any(|e| e.user_id == m.user_id))
                .map(|m| ReviewMissing {
                    user_id: m.user_id.clone(),
                    role: m.role.clone(),
                    identity: m.identity.clone(),
                    pinned_email: pins.get(&m.user_id).map(|p| p.email.clone()),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(RosterReview {
        vault_id: vault_id.to_owned(),
        version: previous.map_or(1, |p| p.version.saturating_add(1)),
        first: previous.is_none(),
        blocked,
        members: out,
        missing,
        digest: if blocked {
            String::new()
        } else {
            member_list_digest(vault_id, previous, &entries)?
        },
    })
}

// ------------------------------------------------------------ key epochs

/// HKDF-SHA256 of the vault key (no salt) with `info` = the tag: each use of the
/// vault key outside encryption gets its own subkey.
fn vault_subkey(vault_key: &SymmetricKey, tag: &[u8]) -> SymmetricKey {
    hkdf_key(vault_key.as_bytes(), &[], tag)
}

fn hmac_b64(key: &SymmetricKey, message: &[u8]) -> String {
    let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(message);
    b64(&mac.finalize().into_bytes())
}

/// HMAC-SHA256, keyed with the vault key's subkey for `passauth/vault-key-commitment/v1`
/// (HKDF-SHA256, no salt, info = that tag), of `["passauth/vault-key-commitment/v1",
/// vault id, key epoch (u64)]`, base64url: tells which key a vault had at an epoch
/// without revealing it.
pub fn key_commitment(vault_key: &SymmetricKey, vault_id: &str, key_epoch: u64) -> Result<String> {
    check_id(vault_id)?;
    Ok(hmac_b64(
        &vault_subkey(vault_key, COMMITMENT_TAG),
        &Canon::new(COMMITMENT_TAG)
            .text(vault_id)
            .number(key_epoch)
            .bytes(),
    ))
}

/// The key's id, independent of the epoch: HMAC-SHA256, keyed with the vault key's
/// subkey for `passauth/vault-key-id/v1`, of `["passauth/vault-key-id/v1", vault id]`,
/// base64url. Pinned per vault; a replaced key's id is retired, so it is refused under
/// any epoch number later.
pub fn key_id(vault_key: &SymmetricKey, vault_id: &str) -> Result<String> {
    check_id(vault_id)?;
    Ok(hmac_b64(
        &vault_subkey(vault_key, KEY_ID_TAG),
        &Canon::new(KEY_ID_TAG).text(vault_id).bytes(),
    ))
}

/// Per vault: the key epoch and key id this account accepted (the highest epoch), the
/// ids of the keys it replaced, since which roster version it saw the vault signed and
/// the highest roster version (with its hash) it trusted. As a vault's *current* key
/// (what [`EpochPin::of`] gives) only `key_epoch` and `key_id` count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochPin {
    pub key_epoch: u64,
    /// [`key_id`] of the key.
    pub key_id: String,
    /// Ids of keys this vault had before (newest last, at most
    /// [`MAX_RETIRED_KEY_IDS`]): never accepted again, whatever their epoch. Written as
    /// the first [`RETIRED_KEY_ID_BYTES`] bytes of the key id (base64url, 16 characters);
    /// full 32-byte ids are read too and compared by the same prefix.
    #[serde(default)]
    pub retired: Vec<String>,
    /// The roster version this account first trusted for the vault: from then on the
    /// vault must come with a trusted roster at least this version (and sealed rows with
    /// a share signature), on every device.
    #[serde(default)]
    pub signed_since: Option<u64>,
    /// The highest member roster version this account trusted for the vault (on any
    /// device): a lower one later is `downgraded`, so a device with no memory of the
    /// vault can't be shown an older (shorter) chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_version_max: Option<u64>,
    /// [`SignedRoster::hash`] of that roster, when known: another roster with the same
    /// version is `roster_forked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_hash: Option<String>,
    /// Set when accepting the vault cleared a tombstone (the account had left it): the
    /// roster version accepted then. In [`KeyPins::merge`] a pin beats a tombstone only
    /// when this is above the tombstone's roster version (review round 4 M2); a pin
    /// without it (a stale copy from before the leave) is folded into the tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejoined_at: Option<u64>,
    /// The account holds (or held) the vault with its own `account` key wrap. A `sealed`
    /// row with a new key for it while the vault has no signed history needs consent
    /// with a warning ([`Admission::Consent`] `own`): a personal vault never silently
    /// turns into one whose key someone else sealed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub own: bool,
}

impl EpochPin {
    /// The current key of a vault: `{key_epoch, key_id}`.
    pub fn of(vault_key: &SymmetricKey, vault_id: &str, key_epoch: u64) -> Result<Self> {
        Ok(Self {
            key_epoch,
            key_id: key_id(vault_key, vault_id)?,
            retired: Vec::new(),
            signed_since: None,
            roster_version_max: None,
            roster_hash: None,
            rejoined_at: None,
            own: false,
        })
    }

    fn check(&self) -> Result<()> {
        key32(&self.key_id, "key id length")?;
        if self.retired.len() > MAX_RETIRED_KEY_IDS {
            return Err(Error::Malformed("too many retired key ids"));
        }
        if self.retired.iter().any(|r| short_id(r).is_none()) {
            return Err(Error::Malformed("retired key id length"));
        }
        if let Some(h) = &self.roster_hash {
            key32(h, "roster hash length")?;
            if self.roster_version_max.is_none() {
                return Err(Error::Malformed("a roster hash without its version"));
            }
        }
        Ok(())
    }

    /// The lowest roster version the vault may come with now: the highest seen (or,
    /// for pins from before that was kept, the first).
    fn roster_floor(&self) -> Option<u64> {
        self.signed_since.max(self.roster_version_max)
    }

    /// Raise the highest trusted roster to `version` (with `hash`, if known); at the
    /// same version only fills a missing hash.
    fn raise_roster(&mut self, version: Option<u64>, hash: Option<&str>) {
        let Some(v) = version else { return };
        match self.roster_version_max {
            Some(m) if m > v => {}
            Some(m) if m == v => {
                if self.roster_hash.is_none() {
                    self.roster_hash = hash.map(str::to_owned);
                }
            }
            _ => {
                self.roster_version_max = Some(v);
                self.roster_hash = hash.map(str::to_owned);
            }
        }
    }
}

/// The first [`RETIRED_KEY_ID_BYTES`] bytes of a key id (32 bytes) or a retired id (12,
/// or 32 from before); `None` for anything else.
fn short_id(id: &str) -> Option<[u8; RETIRED_KEY_ID_BYTES]> {
    let raw = unb64(id).ok()?;
    if raw.len() != 32 && raw.len() != RETIRED_KEY_ID_BYTES {
        return None;
    }
    raw[..RETIRED_KEY_ID_BYTES].try_into().ok()
}

/// Whether the retired id `retired` names the key with id `key_id`.
fn is_retired_as(retired: &str, key_id: &str) -> bool {
    match (short_id(retired), short_id(key_id)) {
        (Some(a), Some(b)) => bool::from(a.ct_eq(&b)),
        _ => false,
    }
}

/// A retired list from `ids` (oldest first, retired or full key ids): each in the short
/// form once (its newest place kept), without the key `current` (if given), at most
/// [`MAX_RETIRED_KEY_IDS`] (the oldest dropped).
fn retired_list<'a>(
    ids: impl IntoIterator<Item = &'a String>,
    current: Option<&str>,
) -> Vec<String> {
    let all: Vec<[u8; RETIRED_KEY_ID_BYTES]> =
        ids.into_iter().filter_map(|i| short_id(i)).collect();
    let current = current.and_then(short_id);
    let mut seen = BTreeSet::new();
    let mut out: Vec<String> = all
        .into_iter()
        .rev()
        .filter(|s| current.is_none_or(|c| !bool::from(c.ct_eq(s))))
        .filter(|s| seen.insert(*s))
        .map(|s| b64(&s))
        .collect();
    out.truncate(MAX_RETIRED_KEY_IDS);
    out.reverse();
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    /// No pin yet: remember this one.
    New,
    /// The pinned key.
    Same,
    /// A higher epoch with a key never seen: remember this one.
    Newer,
    /// A lower epoch than pinned, or a retired key under any epoch: refuse it (an
    /// older key served again).
    Older,
    /// The pinned epoch with another key, or the pinned key under another epoch:
    /// refuse it.
    Conflict,
    /// The vault was seen signed (since roster version N, or up to version M) and comes
    /// without a trusted roster, or with an older one: refuse it.
    Downgraded,
}

/// Compare a vault's current key (`{key_epoch, key_id}`) with a pin.
pub fn epoch_check(pinned: Option<&EpochPin>, current: &EpochPin) -> EpochStatus {
    let Some(p) = pinned else {
        return EpochStatus::New;
    };
    if p.retired.iter().any(|r| is_retired_as(r, &current.key_id)) {
        return EpochStatus::Older;
    }
    let same_key = same(&p.key_id, &current.key_id);
    match current.key_epoch.cmp(&p.key_epoch) {
        Ordering::Less => EpochStatus::Older,
        Ordering::Equal if same_key => EpochStatus::Same,
        Ordering::Equal => EpochStatus::Conflict,
        Ordering::Greater if same_key => EpochStatus::Conflict,
        Ordering::Greater => EpochStatus::Newer,
    }
}

// --------------------------------------------------------------- key pins

/// One identity this account has seen for another user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPin {
    pub user_id: String,
    /// The email the server listed when pinned (shown with the pin, before any email
    /// the server lists later).
    pub email: String,
    pub public_key: String,
    #[serde(default)]
    pub signing_key: Option<String>,
    /// Identity hash (from the three above), base64url.
    pub identity: String,
    /// Checked out of band (the fingerprint compared with the person).
    pub verified: bool,
    /// Unix seconds when this identity was first pinned.
    pub first_seen: i64,
    /// Fields of newer apps, kept.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A vault this account left or deleted ([`KeyPins::leave`]): never accepted again
/// unless re-shared with a newer roster ([`KeyPins::admit`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// The epoch pin the vault had (none if it was never pinned).
    pub pin: Option<EpochPin>,
    /// The trusted roster version when leaving (0: none).
    pub roster_version: u64,
    /// Unix seconds.
    pub left_at: i64,
}

/// An account's key pins (sealed with [`UnlockedAccount::seal_key_pins`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPins {
    /// Equals the server's `seq` for the stored copy (set when sealing).
    pub version: u64,
    pub pins: Vec<KeyPin>,
    /// Per vault id this account accepted: its key epoch pin. A vault id with no entry
    /// here was never accepted (a sealed row for it needs the user's consent).
    #[serde(default)]
    pub epochs: BTreeMap<String, EpochPin>,
    /// This account's own identity hash (base64url), written once when its signing
    /// identity was first opened: `/sync` listing none or another is
    /// `identity_mismatch`.
    #[serde(default)]
    pub own_identity: Option<String>,
    /// The shared vault ids the account had at its first signed sync (written once):
    /// these stay usable without a consent even unsigned ("Not yet signed").
    #[serde(default)]
    pub grandfathered: Option<BTreeSet<String>>,
    /// Vaults this account left or deleted.
    #[serde(default)]
    pub left: BTreeMap<String, Tombstone>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinStatus {
    /// No pin for this user: pin it (trust on first use) and show the fingerprint.
    New,
    /// The pinned identity.
    Match,
    /// Another identity than pinned: stop and ask (keys changed).
    Changed,
    /// The pinned legacy identity (same X25519 key) now has a signing key, which the
    /// X25519 key cross-signed: re-pin it (unverified: the new fingerprint wasn't
    /// compared yet). Grants no signing authority by itself (rosters name the full
    /// identity for that).
    Upgraded,
    /// No pin for this user id, but the email the server lists for it is pinned for
    /// another user id: stop and ask (a server-made account posing as a known person).
    EmailConflict,
}

/// What [`KeyPins::check_own_identity`] says about the identity `/sync` lists for the
/// account itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnIdentityStatus {
    /// Nothing remembered yet: remember it ([`KeyPins::set_own_identity`]).
    New,
    Match,
    /// None listed, or another one: `identity_mismatch` (sharing paused).
    Mismatch,
}

/// A vault row as [`KeyPins::admit`] sees it, after the app opened its key and checked
/// its signatures and roster chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultObservation {
    pub vault_id: String,
    /// `account` or `sealed` (the row's `key_kind`).
    pub key_kind: String,
    /// [`EpochPin::of`] the opened key at the row's `key_epoch`; `None` when the row has
    /// no `key_epoch`.
    #[serde(default)]
    pub key: Option<EpochPin>,
    /// The version of the roster this device trusts for the vault after the chain
    /// ended at the row's `member_roster` (`None`: the row has none, and the device
    /// remembers none).
    #[serde(default)]
    pub roster_version: Option<u64>,
    /// [`SignedRoster::hash`] of that roster (`rosterHash`): remembered with the highest
    /// version, so another roster with that version is refused (`roster_forked`).
    /// Optional; without it only the version is compared.
    #[serde(default)]
    pub roster_hash: Option<String>,
    /// The rosters this device verified for the vault in this check, as `{"<version>":
    /// "<rosterHash>"}`: the trusted roster the chain started from (if any) and every
    /// newer one [`verify_roster_chain`] checked (at most [`MAX_ROSTER_CHAIN`] + 1).
    /// **Send it whenever a chain was fetched** (also an invitation's chain from version
    /// 1): if it covers the highest roster version the key pins remember for the vault
    /// (`roster_version_max`, also a tombstone's), that roster must have the pinned hash,
    /// else `roster_forked` — so a chain re-signed from version 1 by an account the
    /// server made up can't replace a history this account saw signed. `None`: no chain
    /// fetched (only the roster this device already trusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hashes: Option<BTreeMap<String, String>>,
    /// The row is sealed and its share verified (`verifyShare`, signer an owner or
    /// admin of the trusted roster, signer pin not `changed`).
    /// Required (no default: a missing field fails closed, review round 4 I2).
    pub signed_share: bool,
    /// Sharing is paused on this device (`identity_mismatch`).
    /// Required (no default).
    pub paused: bool,
}

/// [`KeyPins::admit`]'s verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Admission {
    /// Use the vault. `pin`: the key pins learn something (a new or newer key, the
    /// first or a higher trusted roster, a roster hash): pin it
    /// ([`KeyPins::set_epoch`] with the roster version, or [`KeyPins::observe`], which
    /// does it) and write the key pins.
    Ok {
        epoch: EpochStatus,
        trust: Trust,
        pin: bool,
    },
    /// A sealed vault this account never accepted (or left, and was re-shared with a
    /// newer roster: `rejoin`; or whose key was replaced while the vault has no signed
    /// history — without a signature, by an app from before, or signed for the first
    /// time, possibly by an account the server made up: `replaced`): don't open it;
    /// show it as an invitation needing the user's consent. `own`: the account held this
    /// vault with its own key wrap before (show "This was your own vault…": a personal
    /// vault turned into one whose key someone else sealed). Accepting =
    /// [`KeyPins::accept`].
    Consent {
        rejoin: bool,
        replaced: bool,
        own: bool,
    },
    /// Never use it; show why.
    Refused { reason: RefuseReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// The account's own key (`account` wrap).
    Own,
    /// A verified share signature and trusted roster.
    Signed,
    /// A share from before, grandfathered or accepted before: "Not yet signed".
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefuseReason {
    /// The row has no key epoch.
    MissingEpoch,
    /// Sharing is paused (identity mismatch): every sealed row is refused.
    Paused,
    /// The account left or deleted this vault.
    Left,
    Older,
    Conflict,
    /// Seen signed before; now unsigned, without a roster, or with an older one; or a
    /// signed share with no roster (stripped).
    Downgraded,
    /// Another roster with the highest version this account trusted for the vault.
    RosterForked,
}

/// [`KeyPins::observe`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observed {
    pub admission: Admission,
    /// The key pins with what `admission` says to pin (unchanged otherwise).
    pub pins: KeyPins,
    /// `pins` differ from the ones given: write them (once per sync, batched).
    pub changed: bool,
}

/// Characters that change how an email looks without being seen (review round 4 M3): the
/// general categories Cf (format: zero-width spaces and joiners, bidi controls, the byte
/// order mark U+FEFF, tags), Cc (controls), Zl and Zp (line and paragraph separators), and
/// the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0. The same set the web vault strips
/// from names it shows (`web/src/lib/text.ts`).
fn invisible(c: char) -> bool {
    use icu_properties::CodePointMapData;
    use icu_properties::props::GeneralCategory as Gc;
    matches!(c, '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}')
        || matches!(
            CodePointMapData::<Gc>::new().get(c),
            Gc::Format | Gc::Control | Gc::LineSeparator | Gc::ParagraphSeparator
        )
}

fn strip_invisible(s: &str) -> String {
    s.chars().filter(|c| !invisible(*c)).collect()
}

/// `s` with every character outside ASCII, and the backslash, written as `\u{hex}`.
fn escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() && c != '\\' {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        }
    }
    out
}

/// An email as pins compare it (and as apps show it): invisible characters removed
/// ([`invisible`]: format, control and separator characters, Hangul fillers), NFKC, lower
/// case, NFKC again, invisible characters removed again, trimmed; then the domain (after
/// the last `@`) without trailing dots, in IDNA ASCII (punycode) form (UTS #46 as the URL
/// Standard's "domain to ASCII", forbidden domain code points refused). When there is no
/// domain or IDNA refuses it, the whole address with every non-ASCII character (and `\`)
/// written as `\u{hex}`: it can't pass for an ASCII address. Local parts are compared
/// as they are after this (no confusable skeleton: a look-alike local part is a new
/// identity, shown with its fingerprint).
pub fn normalize_email(email: &str) -> String {
    let nfkc = icu_normalizer::ComposingNormalizerBorrowed::new_nfkc();
    let folded = nfkc.normalize(&strip_invisible(email)).to_lowercase();
    let lower = strip_invisible(&nfkc.normalize(&folded)).trim().to_owned();
    if let Some((local, domain)) = lower.rsplit_once('@') {
        let domain = domain.trim_end_matches('.');
        if !domain.is_empty()
            && let Ok(ascii) =
                idna::domain_to_ascii_cow(domain.as_bytes(), idna::AsciiDenyList::URL)
            && !ascii.is_empty()
        {
            return format!("{local}@{ascii}");
        }
    }
    escape_non_ascii(&lower)
}

fn check_email(email: &str) -> Result<()> {
    if email.len() > MAX_PIN_EMAIL || email.chars().any(|c| c.is_control()) {
        return Err(Error::Malformed("pin email"));
    }
    Ok(())
}

/// Whether `pin`'s retired list names the key `key_id`.
fn retires(pin: &EpochPin, key_id: &str) -> bool {
    pin.retired.iter().any(|r| is_retired_as(r, key_id))
}

/// The epoch pin worth keeping of two for the same vault (review round 4 H1: retired ids
/// only ever grow). `R` = both retired lists. A key either side retired (in `R`) never
/// wins: the other side's pin does, whatever the epochs. Else the higher epoch's key wins
/// (at the same epoch `base`'s: a different key at the same epoch is a fork, which then
/// shows as `conflict` wherever the other key is served). The losing key is retired when
/// it was superseded (a lower epoch, or retired by either side), never at a same-epoch
/// conflict. If both keys are retired (only a server mixing histories gets there), the
/// higher epoch's stays pinned *and* retired, so neither is accepted until a newer key
/// comes. Also: the earlier `signed_since`, the higher trusted roster (at the same
/// version `base`'s hash, else the one known), the higher `rejoined_at`, `own` from
/// either.
fn merge_epoch(base: &EpochPin, other: &EpochPin) -> EpochPin {
    let dead = |p: &EpochPin| retires(base, &p.key_id) || retires(other, &p.key_id);
    let (base_dead, other_dead) = (dead(base), dead(other));
    let other_first = match (base_dead, other_dead) {
        (true, false) => true,
        (false, true) => false,
        _ => other.key_epoch > base.key_epoch,
    };
    let (win, lose) = if other_first {
        (other, base)
    } else {
        (base, other)
    };
    let both_dead = base_dead && other_dead;
    let superseded =
        !same(&win.key_id, &lose.key_id) && (lose.key_epoch < win.key_epoch || dead(lose));
    let mut ids: Vec<&String> = lose.retired.iter().collect();
    if superseded {
        ids.push(&lose.key_id);
    }
    ids.extend(win.retired.iter());
    if both_dead {
        ids.push(&win.key_id);
    }
    let mut out = win.clone();
    out.retired = retired_list(ids, (!both_dead).then_some(win.key_id.as_str()));
    out.signed_since = match (base.signed_since, other.signed_since) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let (max, hash) = match (base.roster_version_max, other.roster_version_max) {
        (Some(a), Some(b)) if b > a => (Some(b), other.roster_hash.clone()),
        (Some(a), Some(b)) if a == b => (
            Some(a),
            base.roster_hash
                .clone()
                .or_else(|| other.roster_hash.clone()),
        ),
        (Some(a), _) => (Some(a), base.roster_hash.clone()),
        (None, b) => (b, other.roster_hash.clone()),
    };
    out.roster_version_max = max;
    out.roster_hash = hash;
    out.rejoined_at = base.rejoined_at.max(other.rejoined_at);
    out.own = base.own || other.own;
    out
}

/// Two pins of one vault, either missing: [`merge_epoch`] when both are there.
fn merge_opt_epoch(base: Option<&EpochPin>, other: Option<&EpochPin>) -> Option<EpochPin> {
    match (base, other) {
        (Some(a), Some(b)) => Some(merge_epoch(a, b)),
        (a, b) => a.or(b).cloned(),
    }
}

impl Tombstone {
    /// Fold an epoch pin the tombstone wins over into it (review round 4 L4): its key
    /// knowledge goes into the tombstone's pin, its highest trusted roster into the
    /// tombstone's version (a re-join must then come with a newer one).
    fn absorb(&mut self, pin: &EpochPin) {
        self.pin = merge_opt_epoch(self.pin.as_ref(), Some(pin));
        self.roster_version = self.roster_version.max(pin.roster_floor().unwrap_or(0));
    }

    /// Two tombstones of one vault: the higher roster version, both pins merged, the
    /// later time.
    fn merged(&self, other: &Tombstone) -> Tombstone {
        Tombstone {
            pin: merge_opt_epoch(self.pin.as_ref(), other.pin.as_ref()),
            roster_version: self.roster_version.max(other.roster_version),
            left_at: self.left_at.max(other.left_at),
        }
    }

    /// Keep only what a re-join check needs: the key, the newest
    /// [`MAX_TOMBSTONE_RETIRED_KEY_IDS`] retired ids, the roster versions and the highest
    /// roster's hash (a re-join's chain must contain it: [`VaultObservation::chain_hashes`])
    /// (review round 4 L5).
    fn compact(&mut self) {
        if let Some(p) = &mut self.pin {
            let extra = p
                .retired
                .len()
                .saturating_sub(MAX_TOMBSTONE_RETIRED_KEY_IDS);
            p.retired.drain(..extra);
            p.rejoined_at = None;
        }
    }
}

impl KeyPins {
    /// Each user once, each pin's identity hash its keys' own, emails short and plain;
    /// epoch pins, tombstones, own identity and grandfathered ids well formed.
    pub fn check(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for p in &self.pins {
            if !seen.insert(p.user_id.as_str()) {
                return Err(Error::Malformed("a user is pinned twice"));
            }
            check_email(&p.email)?;
            let public_key = key32(&p.public_key, "public key length")?;
            let signing = p
                .signing_key
                .as_deref()
                .map(|k| key32(k, "signing key length"))
                .transpose()?;
            check_id(&p.user_id)?;
            let hash = identity_hash(&p.user_id, &public_key, signing.as_ref());
            if !same(&b64(&hash), &p.identity) {
                return Err(Error::Malformed("a pin's identity hash isn't its keys'"));
            }
        }
        for (vault, pin) in &self.epochs {
            check_id(vault)?;
            pin.check()?;
        }
        for (vault, t) in &self.left {
            check_id(vault)?;
            if let Some(p) = &t.pin {
                p.check()?;
            }
        }
        if let Some(own) = &self.own_identity {
            key32(own, "identity hash length")?;
        }
        for vault in self.grandfathered.iter().flatten() {
            check_id(vault)?;
        }
        Ok(())
    }

    /// [`epoch_check`] of a vault's current key against this account's pin for it, and
    /// `downgraded` when the pin says the vault was signed since roster version N, or
    /// trusted up to roster version M, and `roster_version` (the roster this device
    /// trusts for it now) is none or below that.
    pub fn check_epoch(
        &self,
        vault_id: &str,
        current: &EpochPin,
        roster_version: Option<u64>,
    ) -> EpochStatus {
        let pin = self.epochs.get(vault_id);
        let status = epoch_check(pin, current);
        if matches!(status, EpochStatus::Same | EpochStatus::Newer)
            && let Some(floor) = pin.and_then(EpochPin::roster_floor)
            && roster_version.is_none_or(|v| v < floor)
        {
            return EpochStatus::Downgraded;
        }
        status
    }

    /// Pin `current` for `vault_id` (accepting it; with the trusted roster version, if
    /// any) when it is new or newer: the previous key's id is retired (at most
    /// [`MAX_RETIRED_KEY_IDS`] kept). At the same key, only marks it signed since
    /// `roster_version` if not yet. Either way the highest trusted roster version is
    /// raised to `roster_version`. Older or conflicting keys are never pinned. Clears
    /// the vault's tombstone when the re-share qualifies ([`Error::Rollback`] when it
    /// doesn't: see [`admit`](Self::admit)), marking the pin re-joined. Prefer
    /// [`accept`](Self::accept) (consents, invitations), which also checks the row and
    /// remembers the roster's hash.
    pub fn set_epoch(
        &self,
        vault_id: &str,
        current: &EpochPin,
        roster_version: Option<u64>,
    ) -> Result<KeyPins> {
        self.accept_key(vault_id, current, roster_version, None, false)
    }

    /// Accept a vault row the user agreed to (an invitation, a consent prompt) or that
    /// [`admit`](Self::admit) said to pin (review round 4 I1): `admit` must not refuse it
    /// (refusals become errors: `left`, `older`, `conflict` and `downgraded`
    /// [`Error::Rollback`], `roster_forked` [`Error::RosterForked`], `paused`
    /// [`Error::IdentityMismatch`], `missing_epoch` malformed); then its key is pinned as
    /// [`set_epoch`](Self::set_epoch) does, with the observation's roster version *and*
    /// hash, and an `account` row marks the pin `own`.
    pub fn accept(&self, o: &VaultObservation) -> Result<KeyPins> {
        if let Admission::Refused { reason } = self.admit(o)? {
            return Err(match reason {
                RefuseReason::RosterForked => Error::RosterForked,
                RefuseReason::Paused => Error::IdentityMismatch,
                RefuseReason::MissingEpoch => Error::Malformed("the vault row has no key epoch"),
                RefuseReason::Left
                | RefuseReason::Older
                | RefuseReason::Conflict
                | RefuseReason::Downgraded => Error::Rollback,
            });
        }
        let key = o
            .key
            .as_ref()
            .ok_or(Error::Malformed("the vault row has no key epoch"))?;
        self.accept_key(
            &o.vault_id,
            key,
            o.roster_version,
            o.roster_hash.as_deref(),
            o.key_kind == "account",
        )
    }

    /// [`set_epoch`](Self::set_epoch), also remembering the trusted roster's hash and
    /// (`own`) that the row was the account's own wrap.
    fn accept_key(
        &self,
        vault_id: &str,
        current: &EpochPin,
        roster_version: Option<u64>,
        roster_hash: Option<&str>,
        own: bool,
    ) -> Result<KeyPins> {
        check_id(vault_id)?;
        current.check()?;
        if let Some(h) = roster_hash {
            key32(h, "roster hash length")?;
        }
        let mut out = self.clone();
        let tomb = out.left.get(vault_id).cloned();
        if let Some(t) = &tomb
            && !rejoin_ok(t, current, roster_version)
        {
            return Err(Error::Rollback);
        }
        let old = match &tomb {
            Some(t) => t.pin.clone(),
            None => out.epochs.get(vault_id).cloned(),
        };
        let mut pin = match epoch_check(old.as_ref(), current) {
            EpochStatus::New | EpochStatus::Newer => {
                let previous = old
                    .iter()
                    .flat_map(|o| o.retired.iter().chain(std::iter::once(&o.key_id)));
                EpochPin {
                    key_epoch: current.key_epoch,
                    key_id: current.key_id.clone(),
                    retired: retired_list(previous, Some(&current.key_id)),
                    signed_since: match (&tomb, &old) {
                        (None, Some(o)) => o.signed_since.or(roster_version),
                        _ => roster_version,
                    },
                    roster_version_max: old.as_ref().and_then(|o| o.roster_version_max),
                    roster_hash: old.as_ref().and_then(|o| o.roster_hash.clone()),
                    rejoined_at: old.as_ref().and_then(|o| o.rejoined_at),
                    own: old.as_ref().is_some_and(|o| o.own),
                }
            }
            EpochStatus::Same => {
                let mut pin = old.expect("same means pinned");
                if tomb.is_some() || pin.signed_since.is_none() {
                    pin.signed_since = roster_version;
                }
                pin
            }
            _ => return Ok(out),
        };
        pin.raise_roster(roster_version, roster_hash);
        pin.own |= own;
        if tomb.is_some() {
            // rejoin_ok: a roster version above the tombstone's.
            pin.rejoined_at = roster_version;
        }
        out.epochs.insert(vault_id.to_owned(), pin);
        out.left.remove(vault_id);
        out.compact();
        Ok(out)
    }

    /// Keep the retired key ids within their budget (review round 4 L5): tombstones keep
    /// [`MAX_TOMBSTONE_RETIRED_KEY_IDS`] each; accepted vaults together keep
    /// [`MAX_TOTAL_RETIRED_KEY_IDS`] (the longest lists lose their oldest ids first, none
    /// below [`MAX_TOMBSTONE_RETIRED_KEY_IDS`]).
    fn compact(&mut self) {
        for t in self.left.values_mut() {
            t.compact();
        }
        let total: usize = self.epochs.values().map(|p| p.retired.len()).sum();
        if total <= MAX_TOTAL_RETIRED_KEY_IDS {
            return;
        }
        // The highest per-vault cap (not below the floor) that fits the budget.
        let kept =
            |cap: usize| -> usize { self.epochs.values().map(|p| p.retired.len().min(cap)).sum() };
        let (mut low, mut high) = (MAX_TOMBSTONE_RETIRED_KEY_IDS, MAX_RETIRED_KEY_IDS);
        while low < high {
            let mid = (low + high).div_ceil(2);
            if kept(mid) <= MAX_TOTAL_RETIRED_KEY_IDS {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        for p in self.epochs.values_mut() {
            let extra = p.retired.len().saturating_sub(low);
            p.retired.drain(..extra);
        }
    }

    /// Whether an `account` wrap of `vault_id` may be in the v1 format (associated data
    /// without the epoch). Always, while the apps write v1
    /// ([`ACCOUNT_WRAPS_BOUND`](crate::keys::ACCOUNT_WRAPS_BOUND) off: every wrap is
    /// v1). Once every client writes v2, only while the vault has no signed history
    /// (no epoch pin with `signed_since`); tighten further then by remembering, per
    /// epoch pin, that the key arrived in a v2 wrap and refusing v1 for it. Old-key
    /// replay is stopped by key ids and retired key ids either way.
    pub fn legacy_wrap_allowed(&self, vault_id: &str) -> bool {
        !crate::keys::ACCOUNT_WRAPS_BOUND
            || !self
                .epochs
                .get(vault_id)
                .is_some_and(|p| p.signed_since.is_some())
    }

    /// Record that this account left or deleted `vault_id` (instead of forgetting it):
    /// its epoch pin moves into a tombstone with the trusted roster version then (0:
    /// none; never below what the pin already knew: its `signed_since` and highest
    /// roster), so the vault isn't accepted again unless re-shared with a newer roster.
    pub fn leave(&self, vault_id: &str, roster_version: u64, now: i64) -> Result<KeyPins> {
        check_id(vault_id)?;
        let mut out = self.clone();
        let before = out.left.get(vault_id).cloned();
        let pin = out
            .epochs
            .remove(vault_id)
            .or_else(|| before.as_ref().and_then(|t| t.pin.clone()));
        let known = pin.as_ref().and_then(EpochPin::roster_floor).unwrap_or(0);
        out.left.insert(
            vault_id.to_owned(),
            Tombstone {
                pin,
                roster_version: roster_version
                    .max(before.map_or(0, |t| t.roster_version))
                    .max(known),
                left_at: now,
            },
        );
        out.compact();
        Ok(out)
    }

    /// Write the grandfathered vault ids, once (at the account's first signed sync).
    /// Unchanged when already written. `created_identity`: this unlock created the
    /// account's signing identity (`/sync` `user.identity` was null and `PUT
    /// /account/identity` answered `created: true`). Only then are `vault_ids` (the
    /// shared vaults it has now) written; otherwise (the account has an identity but no
    /// key pins: the server withheld them, or the device that created the identity never
    /// wrote them) an empty list is written: "trust memory missing", every sealed vault
    /// then needs the user's consent. Grandfathering applies to unsigned rows only
    /// ([`admit`](Self::admit)).
    pub fn grandfather(&self, vault_ids: &[String], created_identity: bool) -> Result<KeyPins> {
        let mut out = self.clone();
        if out.grandfathered.is_none() {
            for id in vault_ids {
                check_id(id)?;
            }
            out.grandfathered = Some(if created_identity {
                vault_ids.iter().cloned().collect()
            } else {
                BTreeSet::new()
            });
        }
        Ok(out)
    }

    /// The identity `/sync` lists for the account itself (its hash, from
    /// `SigningIdentity::identity_hash` after opening it; `None` when `user.identity` is
    /// null) against the one remembered.
    pub fn check_own_identity(&self, listed: Option<&str>) -> OwnIdentityStatus {
        match (&self.own_identity, listed) {
            (None, _) => OwnIdentityStatus::New,
            (Some(own), Some(l)) if same(own, l) => OwnIdentityStatus::Match,
            _ => OwnIdentityStatus::Mismatch,
        }
    }

    /// Remember the account's own identity hash (once; another one is
    /// [`Error::IdentityMismatch`]).
    pub fn set_own_identity(&self, hash: &str) -> Result<KeyPins> {
        key32(hash, "identity hash length")?;
        match &self.own_identity {
            Some(own) if same(own, hash) => Ok(self.clone()),
            Some(_) => Err(Error::IdentityMismatch),
            None => {
                let mut out = self.clone();
                out.own_identity = Some(hash.to_owned());
                Ok(out)
            }
        }
    }

    /// What to do with a vault row (see [`VaultObservation`]), in this order: no key
    /// epoch → refused (`missing_epoch`); a sealed row while paused → refused; a vault
    /// the account left → `consent` (rejoin) only for a sealed row with a verified
    /// share, a trusted roster newer than the one at leaving and a key not older than
    /// the one then, else refused (`left`); the epoch pin (`older`, `conflict`,
    /// `downgraded` refuse; a roster below the highest trusted one is `downgraded`, the
    /// same version with another hash `roster_forked`); a sealed row with a share but no
    /// roster, or without a share where a roster is trusted or the pin says signed →
    /// `downgraded`; an `account` row → ok (own); a sealed row → ok when pinned, or
    /// grandfathered and unsigned, else `consent`; a pinned sealed row with a new key while
    /// the pin has no signed history (no `signed_since`, no trusted roster), signed or
    /// not → `consent` (`replaced`; `own` when the account held it with its own wrap).
    /// `ok` says whether to `pin` (also an `account` row whose pin isn't marked `own`).
    pub fn admit(&self, o: &VaultObservation) -> Result<Admission> {
        check_id(&o.vault_id)?;
        let sealed = match o.key_kind.as_str() {
            "sealed" => true,
            "account" => false,
            _ => return Err(Error::Malformed("key_kind must be account or sealed")),
        };
        if let Some(h) = &o.roster_hash {
            key32(h, "roster hash length")?;
        }
        let refuse = |reason| Ok(Admission::Refused { reason });
        let Some(key) = &o.key else {
            return refuse(RefuseReason::MissingEpoch);
        };
        key.check()?;
        if sealed && o.paused {
            return refuse(RefuseReason::Paused);
        }
        let remembered = match self.left.get(&o.vault_id) {
            Some(t) => t.pin.as_ref(),
            None => self.epochs.get(&o.vault_id),
        };
        if !chain_matches(remembered, o)? {
            return refuse(RefuseReason::RosterForked);
        }
        if let Some(t) = self.left.get(&o.vault_id) {
            return if sealed && o.signed_share && rejoin_ok(t, key, o.roster_version) {
                Ok(Admission::Consent {
                    rejoin: true,
                    replaced: false,
                    own: false,
                })
            } else {
                refuse(RefuseReason::Left)
            };
        }
        let status = self.check_epoch(&o.vault_id, key, o.roster_version);
        match status {
            EpochStatus::Older => return refuse(RefuseReason::Older),
            EpochStatus::Conflict => return refuse(RefuseReason::Conflict),
            EpochStatus::Downgraded => return refuse(RefuseReason::Downgraded),
            _ => {}
        }
        let pinned = self.epochs.get(&o.vault_id);
        if let (Some(p), Some(v), Some(h)) = (pinned, o.roster_version, &o.roster_hash)
            && p.roster_version_max == Some(v)
            && p.roster_hash
                .as_deref()
                .is_some_and(|known| !same(known, h))
        {
            return refuse(RefuseReason::RosterForked);
        }
        let pin = matches!(status, EpochStatus::New | EpochStatus::Newer)
            || (!sealed && pinned.is_some_and(|p| !p.own))
            || o.roster_version.is_some_and(|v| {
                pinned.is_some_and(|p| {
                    p.signed_since.is_none()
                        || p.roster_version_max.is_none_or(|m| v > m)
                        || (p.roster_version_max == Some(v)
                            && p.roster_hash.is_none()
                            && o.roster_hash.is_some())
                })
            });
        if !sealed {
            return Ok(Admission::Ok {
                epoch: status,
                trust: Trust::Own,
                pin,
            });
        }
        let seen_signed = pinned.is_some_and(|p| p.roster_floor().is_some());
        if (o.signed_share && o.roster_version.is_none())
            || (!o.signed_share && (o.roster_version.is_some() || seen_signed))
        {
            return refuse(RefuseReason::Downgraded);
        }
        // From here a row is either signed (share and roster) or unsigned (neither).
        let unsigned = !o.signed_share;
        let grandfathered = unsigned
            && self
                .grandfathered
                .as_ref()
                .is_some_and(|g| g.contains(&o.vault_id));
        if status == EpochStatus::New && !grandfathered {
            return Ok(Admission::Consent {
                rejoin: false,
                replaced: false,
                own: false,
            });
        }
        if status == EpochStatus::Newer
            && (unsigned || pinned.is_some_and(|p| p.roster_floor().is_none()))
        {
            // A new key on a vault never seen signed: nobody this account trusts vouches
            // for it. Unsigned, it is a server-chosen key unless the user expected it (an
            // app from before replaced it); signed, the roster chain may start at a
            // version 1 signed by an account the server made up (review round 4,
            // puppet signer). The first signed key replacement of an old vault therefore
            // needs one confirmation.
            return Ok(Admission::Consent {
                rejoin: false,
                replaced: true,
                own: pinned.is_some_and(|p| p.own),
            });
        }
        Ok(Admission::Ok {
            epoch: status,
            trust: if unsigned {
                Trust::Unsigned
            } else {
                Trust::Signed
            },
            pin,
        })
    }

    /// [`admit`](Self::admit), and the key pins with what it says to pin applied (for
    /// `ok` with `pin`: [`set_epoch`](Self::set_epoch) with the observation's roster
    /// version and hash). Chain it over a sync's rows and write the pins once if any
    /// answer was `changed`.
    pub fn observe(&self, o: &VaultObservation) -> Result<Observed> {
        let admission = self.admit(o)?;
        let pins = match (&admission, &o.key) {
            (Admission::Ok { pin: true, .. }, Some(key)) => self.accept_key(
                &o.vault_id,
                key,
                o.roster_version,
                o.roster_hash.as_deref(),
                o.key_kind == "account",
            )?,
            _ => self.clone(),
        };
        Ok(Observed {
            changed: pins != *self,
            admission,
            pins,
        })
    }

    fn get(&self, user_id: &str) -> Option<&KeyPin> {
        self.pins.iter().find(|p| p.user_id == user_id)
    }

    /// How `identity` (which must verify) compares with this account's pin for its
    /// user. `email` is the one the server lists with it: a user id without a pin whose
    /// email (trimmed, case-insensitive) is pinned for another user id is
    /// `email_conflict`.
    pub fn check_identity(
        &self,
        identity: &PublicIdentity,
        email: Option<&str>,
    ) -> Result<PinStatus> {
        let verified = identity.verify()?;
        let Some(pin) = self.get(verified.user_id()) else {
            let listed = email.map(normalize_email).filter(|e| !e.is_empty());
            if let Some(e) = listed
                && self.pins.iter().any(|p| normalize_email(&p.email) == e)
            {
                return Ok(PinStatus::EmailConflict);
            }
            return Ok(PinStatus::New);
        };
        Ok(if same(&pin.identity, &verified.hash_b64()) {
            PinStatus::Match
        } else if pin.signing_key.is_none()
            && verified.is_signing()
            && same(&pin.public_key, &identity.public_key)
        {
            PinStatus::Upgraded
        } else {
            PinStatus::Changed
        })
    }

    /// Pin `identity` (which must verify) for its user with `email`: a new pin, or one
    /// replacing another identity (first seen `now`, `verified` as given), or the same
    /// identity again (keeps when it was first seen and its email; verified stays
    /// verified).
    pub fn set(
        &self,
        identity: &PublicIdentity,
        email: &str,
        verified: bool,
        now: i64,
    ) -> Result<KeyPins> {
        check_email(email)?;
        let v = identity.verify()?;
        let mut out = self.clone();
        let pin = KeyPin {
            user_id: v.user_id().to_owned(),
            email: email.to_owned(),
            public_key: identity.public_key.clone(),
            signing_key: identity.signing_key.clone(),
            identity: v.hash_b64(),
            verified,
            first_seen: now,
            extra: serde_json::Map::new(),
        };
        match out.pins.iter_mut().find(|p| p.user_id == pin.user_id) {
            Some(old) if same(&old.identity, &pin.identity) => {
                old.verified |= verified;
            }
            Some(old) => *old = pin,
            None => out.pins.push(pin),
        }
        out.pins.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        Ok(out)
    }

    /// Merge this device's pins (`ours`: its own last-known pins) into `self` (the
    /// server's newest): pins only one has are kept; for the same identity, verified if
    /// either is and first seen at the earlier time; for different identities, `ours`
    /// wins (this device's newer decision). Epoch pins: [`merge_epoch`] per vault
    /// (retired ids only grow; a retired key never comes back). Tombstones: both, merged
    /// per vault (higher roster version, merged pins, later time). A vault with both a
    /// tombstone and an epoch pin keeps the pin only if it was re-joined after that
    /// tombstone (`rejoined_at` above the tombstone's roster version; a stale pin from
    /// before the leave isn't); else the pin is folded into the tombstone (its keys and
    /// its highest roster). Own identity: `self`'s, else `ours`. Grandfathered ids: the
    /// union when both wrote a list (only the unlock that created the identity writes a
    /// non-empty one), else the one written. The version is the higher one. Apps merge
    /// whenever they read a newer server copy, not only with unsent changes.
    pub fn merge(&self, ours: &KeyPins) -> Result<KeyPins> {
        self.check()?;
        ours.check()?;
        let mut out = self.clone();
        for p in &ours.pins {
            match out.pins.iter_mut().find(|o| o.user_id == p.user_id) {
                Some(o) if same(&o.identity, &p.identity) => {
                    o.verified |= p.verified;
                    o.first_seen = o.first_seen.min(p.first_seen);
                }
                Some(o) => *o = p.clone(),
                None => out.pins.push(p.clone()),
            }
        }
        for (vault, pin) in &ours.epochs {
            let merged = match out.epochs.get(vault) {
                Some(o) => merge_epoch(o, pin),
                None => pin.clone(),
            };
            out.epochs.insert(vault.clone(), merged);
        }
        for (vault, t) in &ours.left {
            let merged = match out.left.get(vault) {
                Some(o) => o.merged(t),
                None => t.clone(),
            };
            out.left.insert(vault.clone(), merged);
        }
        let both: Vec<String> = out
            .left
            .keys()
            .filter(|v| out.epochs.contains_key(*v))
            .cloned()
            .collect();
        for vault in both {
            let tomb = out.left.remove(&vault).expect("listed above");
            let pin = out.epochs.remove(&vault).expect("listed above");
            if pin.rejoined_at.is_some_and(|r| r > tomb.roster_version) {
                // Re-joined after this tombstone: keep what the tombstone knew too.
                let pin = match &tomb.pin {
                    Some(t) => merge_epoch(&pin, t),
                    None => pin,
                };
                out.epochs.insert(vault, pin);
            } else {
                let mut tomb = tomb;
                tomb.absorb(&pin);
                out.left.insert(vault, tomb);
            }
        }
        if out.own_identity.is_none() {
            out.own_identity = ours.own_identity.clone();
        }
        out.grandfathered = match (out.grandfathered.take(), &ours.grandfathered) {
            (Some(mut a), Some(b)) => {
                a.extend(b.iter().cloned());
                Some(a)
            }
            (a, b) => a.or_else(|| b.clone()),
        };
        out.version = self.version.max(ours.version);
        out.pins.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        out.compact();
        Ok(out)
    }
}

/// [`VaultObservation::chain_hashes`] against the roster the pin remembers: well formed
/// (versions as decimal numbers from 1, 32-byte hashes, at most [`MAX_ROSTER_CHAIN`] + 1,
/// the observation's own `roster_hash` the one listed for its `roster_version`), and when
/// the chain reaches the pinned `roster_version_max` it lists that version with the pinned
/// `roster_hash` (`false`: another roster there, a fork). A chain that skips the pinned
/// version inside its range is malformed.
fn chain_matches(pin: Option<&EpochPin>, o: &VaultObservation) -> Result<bool> {
    let Some(chain) = &o.chain_hashes else {
        return Ok(true);
    };
    if chain.len() > MAX_ROSTER_CHAIN + 1 {
        return Err(Error::TooLarge);
    }
    let mut hashes = BTreeMap::new();
    for (version, hash) in chain {
        let v = version
            .parse::<u64>()
            .ok()
            .filter(|v| *v >= 1 && v.to_string() == *version)
            .ok_or(Error::Malformed(
                "chain_hashes versions are roster versions",
            ))?;
        key32(hash, "roster hash length")?;
        hashes.insert(v, hash.as_str());
    }
    if let (Some(v), Some(h)) = (o.roster_version, &o.roster_hash)
        && hashes.get(&v).is_some_and(|listed| !same(listed, h))
    {
        return Err(Error::Malformed(
            "chain_hashes lists another hash for the trusted roster",
        ));
    }
    let Some((m, pinned)) = pin.and_then(|p| p.roster_version_max.zip(p.roster_hash.as_deref()))
    else {
        return Ok(true);
    };
    match hashes.get(&m) {
        Some(h) => Ok(same(h, pinned)),
        None => {
            let (first, last) = (hashes.keys().next(), hashes.keys().next_back());
            if first.is_some_and(|f| *f < m) && last.is_some_and(|l| *l > m) {
                return Err(Error::Malformed(
                    "chain_hashes skips the pinned roster version",
                ));
            }
            Ok(true)
        }
    }
}

/// Whether a vault the account left may come back: a trusted roster newer than the
/// one at leaving (and than any the tombstoned pin knew), and a key not older than the
/// one then (a new key, or the same one at the same epoch).
fn rejoin_ok(t: &Tombstone, key: &EpochPin, roster_version: Option<u64>) -> bool {
    let known = t.pin.as_ref().and_then(EpochPin::roster_floor).unwrap_or(0);
    roster_version.is_some_and(|v| v > t.roster_version && v > known)
        && matches!(
            epoch_check(t.pin.as_ref(), key),
            EpochStatus::New | EpochStatus::Same | EpochStatus::Newer
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    const VAULT: &str = "vault-1";

    fn account(id: &str, n: u8) -> UnlockedAccount {
        UnlockedAccount {
            account_id: id.into(),
            account_key: SymmetricKey::from_bytes([n; 32]),
            keypair: KeyPair::from_secret_bytes([n.wrapping_add(100); 32]),
        }
    }

    /// An account with a signing identity: (account, identity, public identity).
    fn signer(id: &str, n: u8) -> (UnlockedAccount, SigningIdentity, PublicIdentity) {
        let a = account(id, n);
        let new = a.new_signing_identity().unwrap();
        let public = new.identity.public();
        (a, new.identity, public)
    }

    fn input(p: &PublicIdentity, role: &str) -> RosterMemberInput {
        RosterMemberInput {
            identity: p.clone(),
            role: role.into(),
            email: None,
        }
    }

    fn inputs(members: &[(&PublicIdentity, &str)]) -> Vec<RosterMemberInput> {
        members.iter().map(|(p, r)| input(p, r)).collect()
    }

    /// The next roster through the protocol: review, then sign what was reviewed.
    fn next(
        by: &SigningIdentity,
        key: &SymmetricKey,
        prev: Option<&SignedRoster>,
        epoch: u64,
        members: &[(&PublicIdentity, &str)],
    ) -> Result<SignedRoster> {
        let members = inputs(members);
        let review = roster_review(VAULT, prev, &by.public(), &members, &KeyPins::default())?;
        by.sign_roster(key, VAULT, prev, epoch, &members, &review.digest)
    }

    /// A roster signed without the protocol's checks (as a rogue app could).
    fn raw(
        by: &SigningIdentity,
        key: &SymmetricKey,
        version: u64,
        epoch: u64,
        members: &[(&PublicIdentity, &str)],
    ) -> SignedRoster {
        by.sign_roster_unchecked(key, VAULT, version, epoch, &inputs(members))
            .unwrap()
    }

    fn chain(trusted: Option<&SignedRoster>, newer: &[SignedRoster]) -> Result<SignedRoster> {
        let latest = newer.last().or(trusted).unwrap().clone();
        verify_roster_chain(VAULT, trusted, newer, &latest)
    }

    #[test]
    fn xeddsa_signs_with_the_x25519_key() {
        for n in 0..20u8 {
            let kp = KeyPair::from_secret_bytes([n.wrapping_mul(37).wrapping_add(1); 32]);
            let u = kp.public_bytes();
            let z = [n; 64];
            let sig = xeddsa_sign(&kp.secret_bytes(), b"message", &z);
            assert!(xeddsa_verify(&u, b"message", &sig));
            assert!(!xeddsa_verify(&u, b"messagE", &sig));
            // The verifying key is the X25519 key's Edwards form, sign bit 0, and the
            // signature is a plain Ed25519 one under it.
            let a = xeddsa_public_key(&u).unwrap();
            assert_eq!(a[31] >> 7, 0);
            let ed = VerifyingKey::from_bytes(&a).unwrap();
            ed.verify_strict(b"message", &Signature::from_bytes(&sig))
                .unwrap();
            assert_eq!(
                EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(clamp_integer(
                    kp.secret_bytes()
                )))
                .to_montgomery()
                .to_bytes(),
                u
            );
            // Another nonce: another signature, also valid.
            let again = xeddsa_sign(&kp.secret_bytes(), b"message", &[n ^ 0xff; 64]);
            assert_ne!(again, sig);
            assert!(xeddsa_verify(&u, b"message", &again));
            // Another key doesn't verify it; a tampered signature neither.
            let other = KeyPair::from_secret_bytes([n.wrapping_add(200); 32]).public_bytes();
            assert!(!xeddsa_verify(&other, b"message", &sig));
            let mut bad = sig;
            bad[40] ^= 1;
            assert!(!xeddsa_verify(&u, b"message", &bad));
            // A non-canonical encoding of the same u (top bit set) is refused.
            let mut high = u;
            high[31] |= 0x80;
            assert!(!xeddsa_verify(&high, b"message", &sig));
        }
        // Low-order and off-curve keys.
        assert!(xeddsa_public_key(&[0; 32]).is_none());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(xeddsa_public_key(&one).is_none());
        // u = p (≡ 0) is non-canonical.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(xeddsa_public_key(&p).is_none());
    }

    #[test]
    fn identities_open_only_for_their_account_and_keys() {
        let a = account("alice", 1);
        let new = a.new_signing_identity().unwrap();
        let again = a.open_signing_identity(&new.record).unwrap();
        assert_eq!(again.public(), new.identity.public());
        assert_eq!(again.public(), again.public(), "the same every time");
        let v = again.public().verify().unwrap();
        assert!(v.is_signing());
        assert_eq!(v.hash(), again.identity_hash());
        assert_eq!(v.fingerprint().len(), 29);
        assert_ne!(v.hash(), v.legacy_hash());

        // Another account (other key) can't open it; the same key under another id neither.
        assert!(
            account("bob", 2)
                .open_signing_identity(&new.record)
                .is_err()
        );
        let mut other = account("bob", 1);
        other.keypair = a.keypair.clone();
        assert!(other.open_signing_identity(&new.record).is_err());

        // The server lists another public key or signature: identity_mismatch.
        let mallory = account("alice", 1).new_signing_identity().unwrap();
        for swap in [
            |r: &mut IdentityRecord, m: &IdentityRecord| r.signing_key = m.signing_key.clone(),
            |r: &mut IdentityRecord, m: &IdentityRecord| {
                r.identity_signature = m.identity_signature.clone()
            },
            |r: &mut IdentityRecord, _: &IdentityRecord| r.x25519_signature = b64(&[1; 64]),
            |r: &mut IdentityRecord, m: &IdentityRecord| {
                r.x25519_signature = m.x25519_signature.clone()
            },
        ] {
            let mut swapped = new.record.clone();
            swap(&mut swapped, &mallory.record);
            assert!(matches!(
                a.open_signing_identity(&swapped),
                Err(Error::IdentityMismatch)
            ));
        }
    }

    #[test]
    fn identity_signatures_bind_user_and_both_keys() {
        let (_, _, p) = signer("alice", 1);
        p.verify().unwrap();
        let (_, _, q) = signer("bob", 2);
        // Another user's X25519 key, user id or signature: refused.
        let mut x = p.clone();
        x.public_key = q.public_key.clone();
        assert!(matches!(x.verify(), Err(Error::BadSignature)));
        let mut x = p.clone();
        x.user_id = "bob".into();
        assert!(matches!(x.verify(), Err(Error::BadSignature)));
        let mut x = p.clone();
        x.identity_signature = q.identity_signature.clone();
        assert!(matches!(x.verify(), Err(Error::BadSignature)));
        let mut x = p.clone();
        x.x25519_signature = q.x25519_signature.clone();
        assert!(matches!(x.verify(), Err(Error::BadSignature)));
        // Part of an identity, or a weak key.
        for strip in [
            |x: &mut PublicIdentity| x.identity_signature = None,
            |x: &mut PublicIdentity| x.x25519_signature = None,
            |x: &mut PublicIdentity| x.signing_key = None,
        ] {
            let mut x = p.clone();
            strip(&mut x);
            assert!(matches!(x.verify(), Err(Error::Malformed(_))));
        }
        let mut x = p.clone();
        x.signing_key = Some(b64(&[0; 32]));
        assert!(x.verify().is_err());
        // Legacy: X25519 only.
        let legacy = PublicIdentity {
            signing_key: None,
            identity_signature: None,
            x25519_signature: None,
            ..p.clone()
        };
        let l = legacy.verify().unwrap();
        assert!(!l.is_signing());
        assert_eq!(l.hash(), p.verify().unwrap().legacy_hash());
        // The forged upgrade (review H1): Bob's user id and X25519 key with Mallory's
        // Ed25519 key, its Ed25519 signature valid, but no X25519 signature Bob made.
        let bob = account("bob", 2);
        let mallory = SigningKey::from_bytes(&[9; 32]);
        let statement = identity_statement(
            "bob",
            &bob.keypair.public_bytes(),
            &mallory.verifying_key().to_bytes(),
        );
        let own_x = account("mallory", 9).keypair.secret_bytes();
        let forged = PublicIdentity {
            user_id: "bob".into(),
            public_key: b64(&bob.keypair.public_bytes()),
            signing_key: Some(b64(&mallory.verifying_key().to_bytes())),
            identity_signature: Some(b64(&mallory.sign(&statement).to_bytes())),
            x25519_signature: Some(b64(&xeddsa_sign(&own_x, &statement, &[0; 64]))),
        };
        assert!(matches!(forged.verify(), Err(Error::BadSignature)));
    }

    #[test]
    fn shares_verify_only_unchanged() {
        let (_, alice, alice_pub) = signer("alice", 1);
        let (bob_acct, _, bob_pub) = signer("bob", 2);
        let vault_key = SymmetricKey::from_bytes([7; 32]);
        let share = alice
            .seal_and_sign_share(&vault_key, "v1", &bob_pub, "write", 3)
            .unwrap();
        assert_eq!(
            bob_acct
                .open_shared_vault_key("v1", &share.sealed_key)
                .unwrap()
                .as_bytes(),
            vault_key.as_bytes()
        );
        let ok = |vault: &str,
                  role: &str,
                  epoch: u64,
                  sealed: &str,
                  signer: &PublicIdentity,
                  sig: &str| {
            verify_share(vault, &bob_pub, role, epoch, sealed, signer, sig)
        };
        let s = &share.signature;
        assert_eq!(
            ok("v1", "write", 3, &share.sealed_key, &alice_pub, s)
                .unwrap()
                .user_id(),
            "alice"
        );
        for (vault, role, epoch) in [("v2", "write", 3), ("v1", "admin", 3), ("v1", "write", 2)] {
            assert!(matches!(
                ok(vault, role, epoch, &share.sealed_key, &alice_pub, s),
                Err(Error::BadSignature)
            ));
        }
        let other = alice
            .seal_and_sign_share(&vault_key, "v1", &bob_pub, "write", 3)
            .unwrap();
        assert!(matches!(
            ok("v1", "write", 3, &other.sealed_key, &alice_pub, s),
            Err(Error::BadSignature)
        ));
        let (_, _, carol_pub) = signer("carol", 3);
        assert!(ok("v1", "write", 3, &share.sealed_key, &carol_pub, s).is_err());
        assert!(matches!(
            verify_share(
                "v1",
                &carol_pub,
                "write",
                3,
                &share.sealed_key,
                &alice_pub,
                s
            ),
            Err(Error::BadSignature)
        ));
        // A legacy signer can't sign.
        let legacy_alice = PublicIdentity {
            signing_key: None,
            identity_signature: None,
            x25519_signature: None,
            ..alice_pub.clone()
        };
        assert!(ok("v1", "write", 3, &share.sealed_key, &legacy_alice, s).is_err());
    }

    #[test]
    fn a_share_to_a_legacy_identity_still_verifies_after_the_recipient_upgrades() {
        let (_, alice, alice_pub) = signer("alice", 1);
        let (bob_acct, _, bob_pub) = signer("bob", 2);
        let bob_legacy = bob_acct.legacy_identity();
        let key = SymmetricKey::from_bytes([7; 32]);
        let share = alice
            .seal_and_sign_share(&key, "v1", &bob_legacy, "read", 0)
            .unwrap();
        for to in [&bob_legacy, &bob_pub] {
            verify_share(
                "v1",
                to,
                "read",
                0,
                &share.sealed_key,
                &alice_pub,
                &share.signature,
            )
            .unwrap();
        }
        // But not the other way: a share to the full identity doesn't name a legacy one
        // of another key.
        let (_, _, eve_pub) = signer("bob", 9);
        assert!(
            verify_share(
                "v1",
                &eve_pub,
                "read",
                0,
                &share.sealed_key,
                &alice_pub,
                &share.signature
            )
            .is_err()
        );
    }

    #[test]
    fn rosters_sign_and_check() {
        let (_, alice, a) = signer("alice", 1);
        let (bob_acct, bob, b) = signer("bob", 2);
        let key = SymmetricKey::from_bytes([7; 32]);
        let r = next(&alice, &key, None, 0, &[(&b, "write"), (&a, "owner")]).unwrap();
        assert_eq!(r.version, 1);
        assert_eq!(r.members[0].user_id, "alice", "sorted");
        let parsed = SignedRoster::parse(&r.to_json().unwrap()).unwrap();
        assert_eq!(parsed, r);
        assert!(r.commits_to(VAULT, &key).unwrap());
        assert!(!r.commits_to("vault-2", &key).unwrap());
        assert!(
            !r.commits_to(VAULT, &SymmetricKey::from_bytes([8; 32]))
                .unwrap()
        );
        assert_eq!(r.member_role(&b).unwrap().as_deref(), Some("write"));
        assert_eq!(r.signer_role(&a).unwrap().as_deref(), Some("owner"));
        // Listed with his signing identity: the same account served without it is a
        // downgrade, not him.
        assert_eq!(r.member_role(&bob_acct.legacy_identity()).unwrap(), None);
        // Listed as legacy: his identity with a signing key (same X25519 key, which
        // cross-signed it) is him as a member, but carries no authority.
        let old = next(
            &alice,
            &key,
            None,
            0,
            &[(&bob_acct.legacy_identity(), "write"), (&a, "owner")],
        )
        .unwrap();
        assert_eq!(old.member_role(&b).unwrap().as_deref(), Some("write"));
        assert_eq!(old.signer_role(&b).unwrap(), None);
        let (_, _, eve) = signer("bob", 9);
        assert_eq!(r.member_role(&eve).unwrap(), None);

        // Owners and admins need a signing identity.
        assert!(
            next(
                &alice,
                &key,
                None,
                0,
                &[(&bob_acct.legacy_identity(), "admin"), (&a, "owner")]
            )
            .is_err()
        );
        // A writer can't sign one; nobody can sign one without an owner or with two.
        let members = [input(&a, "owner"), input(&b, "write")];
        assert!(matches!(
            roster_review(VAULT, None, &b, &members, &KeyPins::default()),
            Err(Error::RosterUnauthorized)
        ));
        let digest = roster_review(VAULT, None, &a, &members, &KeyPins::default())
            .unwrap()
            .digest;
        assert!(matches!(
            bob.sign_roster(&key, VAULT, None, 0, &members, &digest),
            Err(Error::RosterUnauthorized)
        ));
        assert!(next(&alice, &key, None, 0, &[(&a, "admin")]).is_err());
        assert!(next(&alice, &key, None, 0, &[(&a, "owner"), (&b, "owner")]).is_err());
        assert!(next(&alice, &key, None, 0, &[(&a, "owner"), (&a, "write")]).is_err());
        // Only the reviewed list is signed.
        let (_, _, c) = signer("carol", 3);
        assert!(matches!(
            alice.sign_roster(
                &key,
                VAULT,
                None,
                0,
                &[input(&a, "owner"), input(&b, "write"), input(&c, "read")],
                &digest
            ),
            Err(Error::ReviewMismatch)
        ));
        assert!(matches!(
            alice.sign_roster(
                &key,
                VAULT,
                None,
                0,
                &[input(&a, "owner"), input(&b, "admin")],
                &digest
            ),
            Err(Error::ReviewMismatch)
        ));
        alice
            .sign_roster(&key, VAULT, None, 0, &members, &digest)
            .unwrap();

        // Tampering: any field.
        for tamper in [
            |r: &mut SignedRoster| r.version += 1,
            |r: &mut SignedRoster| r.key_epoch += 1,
            |r: &mut SignedRoster| r.vault_id = "vault-2".into(),
            |r: &mut SignedRoster| r.members[1].role = "admin".into(),
            |r: &mut SignedRoster| r.members.truncate(1),
            |r: &mut SignedRoster| r.key_commitment = b64(&[1; 32]),
        ] {
            let mut t = r.clone();
            tamper(&mut t);
            assert!(t.check().is_err());
            assert!(SignedRoster::parse(&t.to_json().unwrap()).is_err());
        }
        // Unknown fields and unsorted members are refused.
        let mut v: serde_json::Value = serde_json::to_value(&r).unwrap();
        v["extra"] = 1.into();
        assert!(SignedRoster::parse(&v.to_string()).is_err());
        let mut t = r.clone();
        t.members.reverse();
        assert!(t.check().is_err());
        // A roster whose signer is listed only by legacy hash doesn't check.
        let legacy_admin = raw(
            &alice,
            &key,
            1,
            0,
            &[(&a, "owner"), (&bob_acct.legacy_identity(), "admin")],
        );
        let by_bob = raw(&bob, &key, 2, 0, &[(&a, "owner"), (&b, "admin")]);
        assert!(matches!(
            chain(Some(&legacy_admin), std::slice::from_ref(&by_bob)),
            Err(Error::RosterUnauthorized)
        ));
    }

    #[test]
    fn roster_chains_follow_authority_and_the_hierarchy() {
        let (_, alice, a) = signer("alice", 1);
        let (bob_acct, bob, b) = signer("bob", 2);
        let (_, carol, c) = signer("carol", 3);
        let (dave_acct, _, d) = signer("dave", 4);
        let key = SymmetricKey::from_bytes([7; 32]);
        let key2 = SymmetricKey::from_bytes([8; 32]);
        let v1 = next(&alice, &key, None, 0, &[(&a, "owner"), (&b, "admin")]).unwrap();
        let v2 = next(
            &alice,
            &key,
            Some(&v1),
            0,
            &[(&a, "owner"), (&b, "admin"), (&c, "admin")],
        )
        .unwrap();
        let v3 = next(&carol, &key2, Some(&v2), 1, &[(&a, "owner"), (&c, "admin")]).unwrap();
        assert_eq!(v3.version, 3);
        assert_eq!(
            chain(None, &[v1.clone(), v2.clone(), v3.clone()]).unwrap(),
            v3
        );
        assert_eq!(chain(Some(&v1), &[v2.clone(), v3.clone()]).unwrap(), v3);
        assert_eq!(chain(Some(&v3), &[]).unwrap(), v3);
        // Must start at 1 without a trusted one; no gaps; no going back.
        assert!(chain(None, std::slice::from_ref(&v2)).is_err());
        assert!(chain(Some(&v1), std::slice::from_ref(&v3)).is_err());
        assert!(matches!(
            chain(Some(&v2), std::slice::from_ref(&v1)),
            Err(Error::Rollback)
        ));
        // It must end exactly at the vault's roster, of this vault.
        assert!(matches!(
            verify_roster_chain(VAULT, None, &[v1.clone(), v2.clone()], &v3),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            verify_roster_chain(VAULT, None, &[v1.clone(), v2.clone(), v3.clone()], &v2),
            Err(Error::Rollback)
        ));
        let v3b = raw(&carol, &key2, 3, 2, &[(&a, "owner"), (&c, "admin")]);
        assert!(matches!(
            verify_roster_chain(VAULT, Some(&v2), std::slice::from_ref(&v3), &v3b),
            Err(Error::RosterForked)
        ));
        assert!(verify_roster_chain("vault-2", None, std::slice::from_ref(&v1), &v1).is_err());
        // At most MAX_ROSTER_CHAIN versions per call.
        let long = vec![v1.clone(); MAX_ROSTER_CHAIN + 1];
        assert!(matches!(chain(None, &long), Err(Error::TooLarge)));

        // Carol wasn't an admin in v1: she can't sign v2.
        let rogue = raw(&carol, &key, 2, 0, &[(&a, "owner"), (&c, "admin")]);
        assert!(matches!(
            chain(Some(&v1), &[rogue]),
            Err(Error::RosterUnauthorized)
        ));
        // The owner never changes.
        let new_owner = raw(&bob, &key, 2, 0, &[(&b, "admin"), (&d, "owner")]);
        assert!(matches!(
            chain(Some(&v1), &[new_owner]),
            Err(Error::RosterUnauthorized)
        ));
        // A lower key epoch is a rollback; the same epoch keeps its key.
        let older_epoch = raw(&carol, &key2, 4, 0, &[(&a, "owner"), (&c, "admin")]);
        assert!(matches!(
            chain(Some(&v3), &[older_epoch]),
            Err(Error::Rollback)
        ));
        let other_key = raw(&carol, &key, 4, 1, &[(&a, "owner"), (&c, "admin")]);
        assert!(matches!(
            chain(Some(&v3), &[other_key]),
            Err(Error::Malformed(_))
        ));
        // Another vault.
        let other = bob
            .sign_roster_unchecked(
                &key,
                "vault-2",
                2,
                0,
                &inputs(&[(&a, "owner"), (&b, "admin")]),
            )
            .unwrap();
        assert!(chain(Some(&v1), &[other]).is_err());

        // The hierarchy (review M1): an admin can't add or raise an admin, nor change
        // the owner's entry or another member's identity…
        for members in [
            vec![(&a, "owner"), (&b, "admin"), (&d, "admin")],
            vec![(&a, "owner"), (&b, "admin"), (&d, "write")],
        ] {
            let base = next(
                &alice,
                &key,
                Some(&v1),
                0,
                &[(&a, "owner"), (&b, "admin"), (&d, "write")],
            )
            .unwrap();
            let by_bob = raw(&bob, &key, 3, 0, &members);
            if members[2].1 == "admin" {
                assert!(matches!(
                    chain(Some(&base), std::slice::from_ref(&by_bob)),
                    Err(Error::RosterUnauthorized)
                ));
                assert!(matches!(
                    next(&bob, &key, Some(&base), 0, &members),
                    Err(Error::RosterUnauthorized)
                ));
            } else {
                assert_eq!(
                    chain(Some(&base), std::slice::from_ref(&by_bob)).unwrap(),
                    by_bob
                );
            }
        }
        let (_, _, fake_d) = signer("dave", 40);
        let with_d = next(
            &alice,
            &key,
            Some(&v1),
            0,
            &[(&a, "owner"), (&b, "admin"), (&d, "write")],
        )
        .unwrap();
        let swap = raw(
            &bob,
            &key,
            3,
            0,
            &[(&a, "owner"), (&b, "admin"), (&fake_d, "write")],
        );
        assert!(matches!(
            chain(Some(&with_d), &[swap]),
            Err(Error::RosterUnauthorized)
        ));
        // …but the owner can, and any admin may remove an admin (who left) or change a
        // member's role between read and write.
        let swapped = [(&a, "owner"), (&b, "admin"), (&fake_d, "admin")];
        // (The owner's app stops at the review: a changed identity blocks it, and a
        // blocked review has no digest to sign with.)
        assert!(matches!(
            next(&alice, &key, Some(&with_d), 0, &swapped),
            Err(Error::ReviewMismatch)
        ));
        let by_owner = raw(&alice, &key, 3, 0, &swapped);
        assert_eq!(
            chain(Some(&with_d), std::slice::from_ref(&by_owner)).unwrap(),
            by_owner
        );
        let removed = next(&bob, &key2, Some(&v2), 1, &[(&a, "owner"), (&b, "admin")]).unwrap();
        assert_eq!(
            chain(Some(&v2), std::slice::from_ref(&removed)).unwrap(),
            removed
        );
        assert_eq!(by_owner.version, 3);
        let reroled = next(
            &bob,
            &key,
            Some(&with_d),
            0,
            &[(&a, "owner"), (&b, "admin"), (&d, "read")],
        )
        .unwrap();
        assert_eq!(chain(Some(&with_d), &[reroled]).unwrap().version, 3);
        // An admin lowering another admin: refused; lowering themselves: fine.
        assert!(matches!(
            next(
                &bob,
                &key,
                Some(&v2),
                0,
                &[(&a, "owner"), (&b, "admin"), (&c, "write")]
            ),
            Err(Error::RosterUnauthorized)
        ));
        next(
            &carol,
            &key,
            Some(&v2),
            0,
            &[(&a, "owner"), (&b, "admin"), (&c, "admin")],
        )
        .unwrap();

        // Legacy listings: an admin keeps a member's legacy hash (only the owner or the
        // member replaces it).
        let legacy_dave = dave_acct.legacy_identity();
        let l1 = next(
            &alice,
            &key,
            Some(&v1),
            0,
            &[(&a, "owner"), (&b, "admin"), (&legacy_dave, "write")],
        )
        .unwrap();
        let kept = next(
            &bob,
            &key,
            Some(&l1),
            0,
            &[(&a, "owner"), (&b, "admin"), (&d, "read")],
        )
        .unwrap();
        let dave_entry = kept.members.iter().find(|m| m.user_id == "dave").unwrap();
        assert_eq!(dave_entry.identity, b64(&d.verify().unwrap().legacy_hash()));
        assert_eq!(kept.member_role(&d).unwrap().as_deref(), Some("read"));
        let upgraded = next(
            &alice,
            &key,
            Some(&kept),
            0,
            &[(&a, "owner"), (&b, "admin"), (&d, "read")],
        )
        .unwrap();
        let dave_entry = upgraded
            .members
            .iter()
            .find(|m| m.user_id == "dave")
            .unwrap();
        assert_eq!(dave_entry.identity, d.verify().unwrap().hash_b64());
        assert_eq!(chain(Some(&l1), &[kept, upgraded]).unwrap().version, 4);
        let _ = bob_acct;
    }

    #[test]
    fn roster_heads() {
        let (_, alice, a) = signer("alice", 1);
        let key = SymmetricKey::from_bytes([7; 32]);
        let key2 = SymmetricKey::from_bytes([8; 32]);
        let v1 = next(&alice, &key, None, 0, &[(&a, "owner")]).unwrap();
        let v2 = next(&alice, &key, Some(&v1), 0, &[(&a, "owner")]).unwrap();
        let v2b = next(&alice, &key2, Some(&v1), 1, &[(&a, "owner")]).unwrap();
        let head = |r: Option<&SignedRoster>, l: Option<&SignedRoster>| roster_head(VAULT, r, l);
        assert_eq!(head(None, None).unwrap(), RosterHead::Unsigned);
        assert_eq!(
            head(None, Some(&v2)).unwrap(),
            RosterHead::Fetch { after: 0 }
        );
        assert_eq!(
            head(Some(&v1), Some(&v2)).unwrap(),
            RosterHead::Fetch { after: 1 }
        );
        assert_eq!(head(Some(&v2), Some(&v2)).unwrap(), RosterHead::Same);
        assert!(matches!(head(Some(&v2), Some(&v1)), Err(Error::Rollback)));
        assert!(matches!(head(Some(&v2), None), Err(Error::Rollback)));
        assert!(matches!(
            head(Some(&v2), Some(&v2b)),
            Err(Error::RosterForked)
        ));
        assert!(matches!(
            roster_head("vault-2", None, Some(&v2)),
            Err(Error::Malformed(_))
        ));
        assert_eq!(
            serde_json::to_value(RosterHead::Fetch { after: 4 }).unwrap(),
            serde_json::json!({"status": "fetch", "after": 4})
        );
    }

    #[test]
    fn member_lists_are_compared_with_the_roster() {
        let (_, alice, a) = signer("alice", 1);
        let (bob_acct, _, b) = signer("bob", 2);
        let (_, _, c) = signer("carol", 3);
        let (_, _, fake_b) = signer("bob", 8);
        let key = SymmetricKey::from_bytes([7; 32]);
        let r = next(
            &alice,
            &key,
            None,
            0,
            &[(&a, "owner"), (&b, "write"), (&c, "read")],
        )
        .unwrap();
        let same = compare_members(&r, &inputs(&[(&a, "owner"), (&b, "write"), (&c, "read")]));
        assert!(same.is_clean() && same.missing.is_empty());
        let down = compare_members(
            &r,
            &inputs(&[(&a, "owner"), (&bob_acct.legacy_identity(), "write")]),
        );
        assert_eq!(down.identity_changed, ["bob"]);
        let old = next(
            &alice,
            &key,
            None,
            0,
            &[(&a, "owner"), (&bob_acct.legacy_identity(), "write")],
        )
        .unwrap();
        assert!(compare_members(&old, &inputs(&[(&a, "owner"), (&b, "write")])).is_clean());
        let (_, _, d) = signer("dave", 4);
        let diff = compare_members(
            &r,
            &inputs(&[
                (&a, "owner"),
                (&fake_b, "write"),
                (&c, "admin"),
                (&d, "read"),
            ]),
        );
        assert!(!diff.is_clean());
        assert_eq!(diff.unknown, ["dave"]);
        assert_eq!(diff.identity_changed, ["bob"]);
        assert_eq!(diff.role_changed, ["carol"]);
        assert!(diff.missing.is_empty());
        let left = compare_members(&r, &inputs(&[(&a, "owner"), (&b, "write")]));
        assert!(left.is_clean());
        assert_eq!(left.missing, ["carol"]);
    }

    #[test]
    fn reviews_list_every_member_with_its_pin() {
        let (_, alice, a) = signer("alice", 1);
        let (_, _, b) = signer("bob", 2);
        let (_, _, c) = signer("carol", 3);
        let (_, _, fake_b) = signer("bob", 8);
        let (_, _, mallory) = signer("mallory", 9);
        let key = SymmetricKey::from_bytes([7; 32]);
        let pins = KeyPins::default()
            .set(&b, "Bob@Example.com", true, 1)
            .unwrap();
        let mut rows = inputs(&[(&a, "owner"), (&b, "write"), (&c, "read")]);
        rows[1].email = Some("bob@new.example".into());
        rows[2].email = Some("carol@example.com".into());
        // Version 1: every member, first time.
        let review = roster_review(VAULT, None, &a, &rows, &pins).unwrap();
        assert!(review.first && !review.blocked);
        assert_eq!(review.version, 1);
        let by: BTreeMap<_, _> = review
            .members
            .iter()
            .map(|m| (m.user_id.as_str(), m))
            .collect();
        assert!(by["alice"].is_self && by["alice"].pin == PinStatus::Match);
        assert_eq!(by["bob"].pin, PinStatus::Match);
        assert!(by["bob"].verified);
        assert_eq!(by["bob"].pinned_email.as_deref(), Some("Bob@Example.com"));
        assert_eq!(by["bob"].listed_email.as_deref(), Some("bob@new.example"));
        assert_eq!(by["carol"].pin, PinStatus::New);
        assert!(
            review
                .members
                .iter()
                .all(|m| m.change == MemberChange::Added)
        );
        assert_eq!(by["carol"].fingerprint, c.verify().unwrap().fingerprint());
        let v1 = alice
            .sign_roster(&key, VAULT, None, 0, &rows, &review.digest)
            .unwrap();
        assert_eq!(
            review.digest,
            member_list_digest(VAULT, None, &v1.members).unwrap()
        );
        // Bob's keys changed against the pins: blocked; against the roster too.
        let changed = inputs(&[(&a, "owner"), (&fake_b, "write"), (&c, "read")]);
        let r = roster_review(VAULT, Some(&v1), &a, &changed, &pins).unwrap();
        assert!(r.blocked && !r.first);
        assert_eq!(r.members[1].change, MemberChange::IdentityChanged);
        assert_eq!(r.members[1].pin, PinStatus::Changed);
        // A new user id posing with a pinned email: blocked.
        let mut posing = inputs(&[(&a, "owner"), (&b, "write"), (&mallory, "read")]);
        posing[2].email = Some(" BOB@example.COM ".into());
        let r = roster_review(VAULT, Some(&v1), &a, &posing, &pins).unwrap();
        assert!(r.blocked);
        let m = r.members.iter().find(|m| m.user_id == "mallory").unwrap();
        assert_eq!(m.pin, PinStatus::EmailConflict);
        assert_eq!(m.change, MemberChange::Added);
        assert_eq!(r.missing.len(), 1);
        assert_eq!(r.missing[0].user_id, "carol");
        // The server lists another identity for the signer: blocked.
        let (_, _, fake_a) = signer("alice", 11);
        let mut me_swapped = inputs(&[(&fake_a, "owner"), (&b, "write")]);
        me_swapped[0].role = "owner".into();
        assert!(roster_review(VAULT, Some(&v1), &a, &me_swapped, &pins).is_err());
        // A role change.
        let r = roster_review(
            VAULT,
            Some(&v1),
            &a,
            &inputs(&[(&a, "owner"), (&b, "admin"), (&c, "read")]),
            &pins,
        )
        .unwrap();
        assert!(!r.blocked);
        assert_eq!(r.members[1].change, MemberChange::RoleChanged);
        assert_eq!(r.version, 2);
        // The signer must manage the trusted roster.
        assert!(matches!(
            roster_review(VAULT, Some(&v1), &b, &rows, &pins),
            Err(Error::RosterUnauthorized)
        ));
    }

    fn pin(k: &SymmetricKey, e: u64) -> EpochPin {
        EpochPin::of(k, "v", e).unwrap()
    }

    /// A key's id as a retired list holds it.
    fn retired(k: &SymmetricKey) -> String {
        b64(&short_id(&pin(k, 0).key_id).unwrap())
    }

    #[test]
    fn commitments_and_key_ids_use_subkeys() {
        let k = SymmetricKey::from_bytes([1; 32]);
        assert_ne!(
            key_commitment(&k, "v", 1).unwrap(),
            key_commitment(&k, "v", 2).unwrap()
        );
        assert_ne!(
            key_commitment(&k, "v", 1).unwrap(),
            key_commitment(&k, "w", 1).unwrap()
        );
        assert_eq!(key_id(&k, "v").unwrap(), pin(&k, 9).key_id);
        assert_ne!(key_id(&k, "v").unwrap(), key_id(&k, "w").unwrap());
        // Not HMAC under the vault key itself (review I1).
        let raw = hmac_b64(&k, &Canon::new(COMMITMENT_TAG).text("v").number(1).bytes());
        assert_ne!(raw, key_commitment(&k, "v", 1).unwrap());
    }

    #[test]
    fn epoch_pins_follow_key_ids() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let k2 = SymmetricKey::from_bytes([2; 32]);
        let k3 = SymmetricKey::from_bytes([3; 32]);
        assert_eq!(epoch_check(None, &pin(&k1, 0)), EpochStatus::New);
        assert_eq!(
            epoch_check(Some(&pin(&k1, 1)), &pin(&k1, 1)),
            EpochStatus::Same
        );
        assert_eq!(
            epoch_check(Some(&pin(&k1, 1)), &pin(&k2, 2)),
            EpochStatus::Newer
        );
        assert_eq!(
            epoch_check(Some(&pin(&k2, 2)), &pin(&k1, 1)),
            EpochStatus::Older
        );
        assert_eq!(
            epoch_check(Some(&pin(&k2, 2)), &pin(&k1, 2)),
            EpochStatus::Conflict
        );
        // The pinned key relabelled with a higher epoch.
        assert_eq!(
            epoch_check(Some(&pin(&k1, 1)), &pin(&k1, 2)),
            EpochStatus::Conflict
        );

        // In the key pins: only raised; a replaced key is retired for good (review H3).
        let pins = KeyPins::default();
        assert_eq!(pins.check_epoch("v", &pin(&k1, 1), None), EpochStatus::New);
        let pins = pins.set_epoch("v", &pin(&k1, 1), None).unwrap();
        assert_eq!(pins.check_epoch("v", &pin(&k1, 1), None), EpochStatus::Same);
        assert_eq!(
            pins.set_epoch("v", &pin(&k1, 0), None).unwrap(),
            pins,
            "never lowered"
        );
        assert_eq!(
            pins.set_epoch("v", &pin(&k2, 1), None).unwrap(),
            pins,
            "never replaced"
        );
        let higher = pins.set_epoch("v", &pin(&k2, 2), None).unwrap();
        assert_eq!(higher.epochs["v"].retired, [retired(&k1)]);
        assert_eq!(
            higher.check_epoch("v", &pin(&k1, 1), None),
            EpochStatus::Older
        );
        // The old key served again as "epoch 3": still older.
        assert_eq!(
            higher.check_epoch("v", &pin(&k1, 3), None),
            EpochStatus::Older
        );
        assert_eq!(
            higher.check_epoch("v", &pin(&k3, 3), None),
            EpochStatus::Newer
        );
        // Merged: the higher epoch, both retired lists.
        assert_eq!(pins.merge(&higher).unwrap().epochs["v"], higher.epochs["v"]);
        assert_eq!(higher.merge(&pins).unwrap().epochs["v"], higher.epochs["v"]);
        let third = higher.set_epoch("v", &pin(&k3, 3), None).unwrap();
        let other_dev = pins.set_epoch("v", &pin(&k3, 3), None).unwrap();
        let merged = higher.merge(&other_dev).unwrap();
        assert_eq!(merged.epochs["v"].key_id, pin(&k3, 0).key_id);
        assert_eq!(merged.epochs["v"].retired.len(), 2);
        assert_eq!(third.epochs["v"].retired.len(), 2);
        let other = KeyPins::default()
            .set_epoch("w", &pin(&k1, 5), None)
            .unwrap();
        assert_eq!(higher.merge(&other).unwrap().epochs.len(), 2);
        let conflict = KeyPins::default()
            .set_epoch("v", &pin(&k1, 2), None)
            .unwrap();
        assert_eq!(
            higher.merge(&conflict).unwrap().epochs["v"].key_id,
            pin(&k2, 2).key_id,
            "the server's stays"
        );
        // Retired ids are capped.
        let mut many = KeyPins::default();
        for e in 0..(MAX_RETIRED_KEY_IDS as u64 + 5) {
            let mut bytes = [7u8; 32];
            bytes[..8].copy_from_slice(&e.to_be_bytes());
            let k = SymmetricKey::from_bytes(bytes);
            many = many.set_epoch("v", &pin(&k, e), None).unwrap();
        }
        assert_eq!(many.epochs["v"].retired.len(), MAX_RETIRED_KEY_IDS);
        many.check().unwrap();
        // Signed since: a later roster-less answer is a downgrade.
        let signed = pins.set_epoch("v", &pin(&k1, 1), Some(3)).unwrap();
        assert_eq!(signed.epochs["v"].signed_since, Some(3));
        // v1 stays readable while the apps write it.
        assert!(signed.legacy_wrap_allowed("v"));
        assert!(pins.legacy_wrap_allowed("v"));
        assert_eq!(
            signed.check_epoch("v", &pin(&k1, 1), None),
            EpochStatus::Downgraded
        );
        assert_eq!(
            signed.check_epoch("v", &pin(&k1, 1), Some(2)),
            EpochStatus::Downgraded
        );
        assert_eq!(
            signed.check_epoch("v", &pin(&k1, 1), Some(3)),
            EpochStatus::Same
        );
        let raised = signed.set_epoch("v", &pin(&k2, 2), Some(5)).unwrap();
        assert_eq!(
            raised.epochs["v"].signed_since,
            Some(3),
            "kept from the first"
        );
        // Sealed with the pins.
        let me = account("me", 5);
        let sealed = me.seal_key_pins(&raised, 1).unwrap();
        assert_eq!(me.open_key_pins(&sealed, 1).unwrap().epochs, raised.epochs);
        let mut bad = raised.clone();
        bad.epochs.get_mut("v").unwrap().key_id = "short".into();
        assert!(me.seal_key_pins(&bad, 2).is_err());
    }

    fn obs(
        kind: &str,
        key: Option<EpochPin>,
        roster: Option<u64>,
        signed: bool,
    ) -> VaultObservation {
        VaultObservation {
            vault_id: "v".into(),
            key_kind: kind.into(),
            key,
            roster_version: roster,
            chain_hashes: None,
            signed_share: signed,
            paused: false,
            roster_hash: None,
        }
    }

    #[test]
    fn vaults_are_admitted_only_when_accepted() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let k2 = SymmetricKey::from_bytes([2; 32]);
        let none = KeyPins::default();
        let ok = |epoch, trust, pin| Admission::Ok { epoch, trust, pin };
        let refused = |reason| Admission::Refused { reason };
        // Own vaults: always the account's key; epochs still checked.
        assert_eq!(
            none.admit(&obs("account", Some(pin(&k1, 0)), None, false))
                .unwrap(),
            ok(EpochStatus::New, Trust::Own, true)
        );
        assert_eq!(
            none.admit(&obs("account", None, None, false)).unwrap(),
            refused(RefuseReason::MissingEpoch)
        );
        // A sealed vault never accepted needs consent (review H2), signed or not…
        assert_eq!(
            none.admit(&obs("sealed", Some(pin(&k1, 0)), Some(1), true))
                .unwrap(),
            Admission::Consent {
                rejoin: false,
                replaced: false,
                own: false
            }
        );
        assert_eq!(
            none.admit(&obs("sealed", Some(pin(&k1, 0)), None, false))
                .unwrap(),
            Admission::Consent {
                rejoin: false,
                replaced: false,
                own: false
            }
        );
        // …unless it was there at the first signed sync.
        let old = none.grandfather(&["v".into()], true).unwrap();
        assert_eq!(old.grandfather(&[], true).unwrap(), old, "written once");
        assert_eq!(
            old.admit(&obs("sealed", Some(pin(&k1, 0)), None, false))
                .unwrap(),
            ok(EpochStatus::New, Trust::Unsigned, true)
        );
        // Accepted: pinned.
        let pins = none.set_epoch("v", &pin(&k1, 0), Some(1)).unwrap();
        assert_eq!(
            pins.admit(&obs("sealed", Some(pin(&k1, 0)), Some(1), true))
                .unwrap(),
            ok(EpochStatus::Same, Trust::Signed, false)
        );
        assert_eq!(
            pins.admit(&obs("sealed", Some(pin(&k2, 1)), Some(2), true))
                .unwrap(),
            ok(EpochStatus::Newer, Trust::Signed, true)
        );
        // Seen signed: unsigned, roster-less or older-roster answers are refused.
        for o in [
            obs("sealed", Some(pin(&k1, 0)), Some(1), false),
            obs("sealed", Some(pin(&k1, 0)), None, true),
            obs("sealed", Some(pin(&k1, 0)), None, false),
            obs("account", Some(pin(&k1, 0)), None, false),
        ] {
            assert_eq!(
                pins.admit(&o).unwrap(),
                refused(RefuseReason::Downgraded),
                "{o:?}"
            );
        }
        // A signed share with no roster (stripped) is refused even when grandfathered.
        assert_eq!(
            old.admit(&obs("sealed", Some(pin(&k1, 0)), None, true))
                .unwrap(),
            refused(RefuseReason::Downgraded)
        );
        // A share null where a roster is trusted.
        assert_eq!(
            old.admit(&obs("sealed", Some(pin(&k1, 0)), Some(1), false))
                .unwrap(),
            refused(RefuseReason::Downgraded)
        );
        // Older keys and conflicts.
        let two = pins.set_epoch("v", &pin(&k2, 1), Some(2)).unwrap();
        assert_eq!(
            two.admit(&obs("sealed", Some(pin(&k1, 5)), Some(3), true))
                .unwrap(),
            refused(RefuseReason::Older)
        );
        assert_eq!(
            two.admit(&obs("sealed", Some(pin(&k1, 1)), Some(3), true))
                .unwrap(),
            refused(RefuseReason::Older)
        );
        // Paused: every sealed row refused; own vaults still checked.
        let mut paused = obs("sealed", Some(pin(&k2, 1)), Some(2), true);
        paused.paused = true;
        assert_eq!(two.admit(&paused).unwrap(), refused(RefuseReason::Paused));
        paused.key_kind = "account".into();
        assert!(matches!(two.admit(&paused).unwrap(), Admission::Ok { .. }));
        let mut bad = paused.clone();
        bad.key_kind = "other".into();
        assert!(two.admit(&bad).is_err());

        // Tombstones (review L3): a vault left stays refused…
        let left = two.leave("v", 2, 100).unwrap();
        assert!(!left.epochs.contains_key("v"));
        assert_eq!(
            left.admit(&obs("sealed", Some(pin(&k2, 1)), Some(2), true))
                .unwrap(),
            refused(RefuseReason::Left)
        );
        assert_eq!(
            left.admit(&obs("account", Some(pin(&k2, 1)), Some(3), false))
                .unwrap(),
            refused(RefuseReason::Left)
        );
        assert!(matches!(
            left.set_epoch("v", &pin(&k2, 1), Some(2)),
            Err(Error::Rollback)
        ));
        // …unless re-shared with a newer roster and a key not older.
        assert_eq!(
            left.admit(&obs("sealed", Some(pin(&k1, 1)), Some(3), true))
                .unwrap(),
            refused(RefuseReason::Left)
        );
        let k3 = SymmetricKey::from_bytes([3; 32]);
        assert_eq!(
            left.admit(&obs("sealed", Some(pin(&k3, 2)), Some(3), true))
                .unwrap(),
            Admission::Consent {
                rejoin: true,
                replaced: false,
                own: false
            }
        );
        assert_eq!(
            left.admit(&obs("sealed", Some(pin(&k2, 1)), Some(3), true))
                .unwrap(),
            Admission::Consent {
                rejoin: true,
                replaced: false,
                own: false
            }
        );
        let back = left.set_epoch("v", &pin(&k3, 2), Some(3)).unwrap();
        assert!(back.left.is_empty());
        assert_eq!(back.epochs["v"].signed_since, Some(3));
        assert!(back.epochs["v"].retired.contains(&retired(&k1)));
        assert_eq!(
            back.admit(&obs("sealed", Some(pin(&k3, 2)), Some(3), true))
                .unwrap(),
            ok(EpochStatus::Same, Trust::Signed, false)
        );
        // Merging: a tombstone beats a stale pin; a re-join beats the tombstone.
        assert!(left.merge(&two).unwrap().epochs.is_empty());
        assert!(two.merge(&left).unwrap().epochs.is_empty());
        let m = left.merge(&back).unwrap();
        assert!(m.left.is_empty() && m.epochs.contains_key("v"));
    }

    #[test]
    fn own_identity_is_remembered_once() {
        let (_, me, _) = signer("me", 5);
        let (_, other, _) = signer("me", 6);
        let mine = b64(&me.identity_hash());
        let pins = KeyPins::default();
        assert_eq!(pins.check_own_identity(Some(&mine)), OwnIdentityStatus::New);
        let pins = pins.set_own_identity(&mine).unwrap();
        assert_eq!(
            pins.check_own_identity(Some(&mine)),
            OwnIdentityStatus::Match
        );
        assert_eq!(pins.check_own_identity(None), OwnIdentityStatus::Mismatch);
        let theirs = b64(&other.identity_hash());
        assert_eq!(
            pins.check_own_identity(Some(&theirs)),
            OwnIdentityStatus::Mismatch
        );
        assert!(matches!(
            pins.set_own_identity(&theirs),
            Err(Error::IdentityMismatch)
        ));
        assert_eq!(pins.set_own_identity(&mine).unwrap(), pins);
        assert_eq!(
            KeyPins::default().merge(&pins).unwrap().own_identity,
            Some(mine)
        );
    }

    #[test]
    fn key_pins_check_set_merge_and_seal() {
        let me = account("me", 5);
        let (bob_acct, _, b) = signer("bob", 2);
        let (_, _, c) = signer("carol", 3);
        let (_, _, fake_b) = signer("bob", 8);
        let empty = KeyPins::default();
        assert_eq!(empty.check_identity(&b, None).unwrap(), PinStatus::New);
        let pins = empty
            .set(&bob_acct.legacy_identity(), "bob@example.com", false, 100)
            .unwrap();
        assert_eq!(
            pins.check_identity(&bob_acct.legacy_identity(), None)
                .unwrap(),
            PinStatus::Match
        );
        assert_eq!(pins.check_identity(&b, None).unwrap(), PinStatus::Upgraded);
        assert_eq!(
            pins.check_identity(&fake_b, None).unwrap(),
            PinStatus::Changed
        );
        let pins = pins.set(&b, "bob@example.com", false, 200).unwrap();
        assert_eq!(pins.check_identity(&b, None).unwrap(), PinStatus::Match);
        assert_eq!(
            pins.check_identity(&fake_b, None).unwrap(),
            PinStatus::Changed
        );
        // A signing identity going back to legacy is a change, not an upgrade.
        assert_eq!(
            pins.check_identity(&bob_acct.legacy_identity(), None)
                .unwrap(),
            PinStatus::Changed
        );
        // Another user id with Bob's email (review H2).
        assert_eq!(
            pins.check_identity(&c, Some("  BOB@example.com")).unwrap(),
            PinStatus::EmailConflict
        );
        assert_eq!(
            pins.check_identity(&c, Some("carol@example.com")).unwrap(),
            PinStatus::New
        );
        // Verified stays verified for the same identity; first seen and email are kept.
        let pins = pins.set(&b, "bob@example.com", true, 300).unwrap();
        let pins = pins.set(&b, "bob@new.example", false, 400).unwrap();
        let bob = pins.get("bob").unwrap();
        assert!(bob.verified);
        assert_eq!(bob.first_seen, 200);
        assert_eq!(bob.email, "bob@example.com");
        // A new identity replaces it, unverified.
        let changed = pins.set(&fake_b, "bob@example.com", false, 500).unwrap();
        assert!(!changed.get("bob").unwrap().verified);

        // Merge: ours wins on conflicts; both kept otherwise.
        let theirs = KeyPins::default()
            .set(&c, "carol@example.com", true, 10)
            .unwrap();
        let theirs = theirs.set(&fake_b, "bob@example.com", false, 10).unwrap();
        let merged = theirs.merge(&pins).unwrap();
        assert_eq!(merged.pins.len(), 2);
        assert_eq!(merged.check_identity(&b, None).unwrap(), PinStatus::Match);
        assert_eq!(merged.check_identity(&c, None).unwrap(), PinStatus::Match);

        // Sealed: only for this account, unchanged, at the version given.
        let sealed = me.seal_key_pins(&merged, 7).unwrap();
        let opened = me.open_key_pins(&sealed, 7).unwrap();
        assert_eq!(opened.version, 7);
        assert_eq!(opened.pins, merged.pins);
        assert!(matches!(me.open_key_pins(&sealed, 8), Err(Error::Rollback)));
        assert!(account("other", 5).open_key_pins(&sealed, 7).is_err());
        assert!(account("me", 6).open_key_pins(&sealed, 7).is_err());

        // Unknown fields survive; inconsistent pins are refused.
        let mut v = serde_json::to_value(&opened).unwrap();
        v["future"] = "x".into();
        v["pins"][0]["note"] = 1.into();
        let with_extra: KeyPins = serde_json::from_value(v).unwrap();
        let reopened = me
            .open_key_pins(&me.seal_key_pins(&with_extra, 9).unwrap(), 9)
            .unwrap();
        assert_eq!(reopened.extra["future"], "x");
        assert_eq!(reopened.pins[0].extra["note"], 1);
        let mut bad = opened.clone();
        bad.pins[0].public_key = c.public_key.clone();
        assert!(me.seal_key_pins(&bad, 1).is_err());
        let mut twice = opened.clone();
        twice.pins.push(twice.pins[0].clone());
        assert!(me.seal_key_pins(&twice, 1).is_err());

        // Size: refused, never trimmed.
        let mut big = KeyPins::default();
        for i in 0..2000 {
            let (_, _, p) = signer(&format!("user-{i:05}-{}", "x".repeat(90)), (i % 250) as u8);
            big = big
                .set(&p, &format!("{}@example.com", "y".repeat(60)), false, 0)
                .unwrap();
            if serde_json::to_vec(&big).unwrap().len() > MAX_KEY_PINS_JSON {
                break;
            }
        }
        assert!(matches!(me.seal_key_pins(&big, 1), Err(Error::TooLarge)));
    }

    /// Fixed inputs and the bytes they must give (cross-checked with Node's Ed25519 and
    /// SHA-256 by testdata/generate-vectors.mjs).
    #[test]
    fn canonical_bytes() {
        let bytes = share_statement(&ShareStatement {
            vault_id: "v",
            recipient_id: "r",
            recipient_identity: &[0xaa; 32],
            role: "read",
            key_epoch: 258,
            sealed_key: "",
            signer_id: "s",
        })
        .unwrap();
        let mut expected = Vec::new();
        for f in [
            &b"passauth/share/v1"[..],
            b"v",
            b"r",
            &[0xaa; 32],
            b"read",
            &258u64.to_be_bytes(),
            &sha256(b""),
            b"s",
        ] {
            expected.extend_from_slice(&(f.len() as u32).to_be_bytes());
            expected.extend_from_slice(f);
        }
        assert_eq!(bytes, expected);
        // Ids that would make fields ambiguous or huge are refused.
        assert!(check_id("").is_err());
        assert!(check_id(&"x".repeat(129)).is_err());
        assert!(check_id("a\nb").is_err());
    }

    fn obs_hash(
        kind: &str,
        key: Option<EpochPin>,
        roster: Option<u64>,
        signed: bool,
        hash: Option<&str>,
    ) -> VaultObservation {
        VaultObservation {
            roster_hash: hash.map(str::to_owned),
            ..obs(kind, key, roster, signed)
        }
    }

    /// Round 3, finding 1: re-signing (same key, same epoch) marks the vault signed in
    /// the key pins, so a device with no memory of it refuses a stripped answer later.
    #[test]
    fn resigning_at_the_same_key_pins_the_vault_signed() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let k2 = SymmetricKey::from_bytes([2; 32]);
        // Grandfathered and pinned unsigned (created the identity at this unlock).
        let pins = KeyPins::default().grandfather(&["v".into()], true).unwrap();
        let first = pins
            .observe(&obs("sealed", Some(pin(&k1, 0)), None, false))
            .unwrap();
        assert!(first.changed);
        assert_eq!(first.pins.epochs["v"].signed_since, None);
        // Re-signed: the same key at the same epoch, now with a roster and a share.
        let resigned = obs("sealed", Some(pin(&k1, 0)), Some(1), true);
        assert_eq!(
            first.pins.admit(&resigned).unwrap(),
            Admission::Ok {
                epoch: EpochStatus::Same,
                trust: Trust::Signed,
                pin: true
            }
        );
        let after = first.pins.observe(&resigned).unwrap();
        assert!(after.changed);
        assert_eq!(after.pins.epochs["v"].signed_since, Some(1));
        assert_eq!(after.pins.epochs["v"].roster_version_max, Some(1));
        // Nothing more to learn the next time.
        let again = after.pins.observe(&resigned).unwrap();
        assert!(!again.changed);
        assert!(matches!(again.admission, Admission::Ok { pin: false, .. }));
        // A device with no memory (only the account's key pins): the roster and share
        // stripped, at the same key or with a server key at epoch + 1 → downgraded.
        for o in [
            obs("sealed", Some(pin(&k1, 0)), None, false),
            obs("sealed", Some(pin(&k2, 1)), None, false),
        ] {
            assert_eq!(
                after.pins.admit(&o).unwrap(),
                Admission::Refused {
                    reason: RefuseReason::Downgraded
                },
                "{o:?}"
            );
        }
        // An account-wrapped vault that gets a roster is marked too.
        let own = KeyPins::default()
            .observe(&obs("account", Some(pin(&k1, 0)), None, false))
            .unwrap()
            .pins;
        let shared = own
            .observe(&obs("account", Some(pin(&k1, 0)), Some(1), false))
            .unwrap();
        assert!(shared.changed);
        assert_eq!(
            shared
                .pins
                .admit(&obs("account", Some(pin(&k1, 0)), None, false))
                .unwrap(),
            Admission::Refused {
                reason: RefuseReason::Downgraded
            }
        );
    }

    /// Round 3, finding 2: a pinned (or grandfathered) vault never seen signed whose key
    /// changes without a signature needs the user's consent.
    #[test]
    fn unsigned_key_replacements_need_consent() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let k2 = SymmetricKey::from_bytes([2; 32]);
        let pins = KeyPins::default()
            .grandfather(&["v".into()], true)
            .unwrap()
            .set_epoch("v", &pin(&k1, 0), None)
            .unwrap();
        let replaced = obs("sealed", Some(pin(&k2, 1)), None, false);
        let consent = Admission::Consent {
            rejoin: false,
            replaced: true,
            own: false,
        };
        assert_eq!(pins.admit(&replaced).unwrap(), consent);
        let o = pins.observe(&replaced).unwrap();
        assert!(!o.changed, "consent pins nothing");
        // Accepting pins the new key and retires the old one.
        let accepted = pins.set_epoch("v", &pin(&k2, 1), None).unwrap();
        assert!(matches!(
            accepted.admit(&replaced).unwrap(),
            Admission::Ok {
                epoch: EpochStatus::Same,
                trust: Trust::Unsigned,
                pin: false
            }
        ));
        // A signed replacement of a vault never seen signed needs consent too (round 4:
        // its roster may start at a version 1 a server-made account signed); once the
        // vault has signed history, signed replacements are automatic.
        assert_eq!(
            pins.admit(&obs("sealed", Some(pin(&k2, 1)), Some(1), true))
                .unwrap(),
            consent
        );
        let signed = pins.set_epoch("v", &pin(&k1, 0), Some(1)).unwrap();
        assert!(matches!(
            signed
                .admit(&obs("sealed", Some(pin(&k2, 1)), Some(2), true))
                .unwrap(),
            Admission::Ok {
                epoch: EpochStatus::Newer,
                trust: Trust::Signed,
                pin: true
            }
        ));
        // The account's own key replacements stay automatic.
        assert!(matches!(
            pins.admit(&obs("account", Some(pin(&k2, 1)), None, false))
                .unwrap(),
            Admission::Ok {
                epoch: EpochStatus::Newer,
                trust: Trust::Own,
                ..
            }
        ));
    }

    /// Round 3, finding 3: grandfathering only at the unlock that created the identity,
    /// and only for unsigned rows; lists of several devices are joined.
    #[test]
    fn grandfathering_needs_the_identity_created_now() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let consent = Admission::Consent {
            rejoin: false,
            replaced: false,
            own: false,
        };
        // Key pins withheld on a fresh device (the identity existed): nothing grandfathered.
        let missing = KeyPins::default()
            .grandfather(&["v".into()], false)
            .unwrap();
        assert_eq!(missing.grandfathered, Some(BTreeSet::new()));
        assert_eq!(
            missing
                .grandfather(&["v".into()], true)
                .unwrap()
                .grandfathered,
            Some(BTreeSet::new()),
            "written once"
        );
        assert_eq!(
            missing
                .admit(&obs("sealed", Some(pin(&k1, 0)), None, false))
                .unwrap(),
            consent
        );
        // Created now: unsigned rows are grandfathered, signed ones need consent.
        let created = KeyPins::default().grandfather(&["v".into()], true).unwrap();
        assert!(matches!(
            created
                .admit(&obs("sealed", Some(pin(&k1, 0)), None, false))
                .unwrap(),
            Admission::Ok {
                trust: Trust::Unsigned,
                ..
            }
        ));
        assert_eq!(
            created
                .admit(&obs("sealed", Some(pin(&k1, 0)), Some(1), true))
                .unwrap(),
            consent
        );
        // Merged: the union (only a creating unlock writes a non-empty list).
        assert_eq!(
            missing.merge(&created).unwrap().grandfathered,
            created.grandfathered
        );
        assert_eq!(
            created.merge(&missing).unwrap().grandfathered,
            created.grandfathered
        );
    }

    /// Round 3, finding 4: retired ids are 12-byte prefixes; full ids from before count.
    #[test]
    fn retired_ids_are_short_and_old_ones_still_count() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let k2 = SymmetricKey::from_bytes([2; 32]);
        let k3 = SymmetricKey::from_bytes([3; 32]);
        let mut old = pin(&k2, 2);
        old.retired = vec![pin(&k1, 0).key_id];
        old.check().unwrap();
        assert_eq!(epoch_check(Some(&old), &pin(&k1, 9)), EpochStatus::Older);
        let pins = KeyPins {
            epochs: [("v".to_owned(), old)].into_iter().collect(),
            ..KeyPins::default()
        };
        let raised = pins.set_epoch("v", &pin(&k3, 3), None).unwrap();
        assert_eq!(raised.epochs["v"].retired, [retired(&k1), retired(&k2)]);
        assert_eq!(retired(&k1).len(), 16);
        assert_eq!(
            raised.check_epoch("v", &pin(&k1, 4), None),
            EpochStatus::Older
        );
        let mut bad = pin(&k2, 2);
        bad.retired = vec![b64(&[1; 20])];
        assert!(bad.check().is_err());
    }

    /// Round 3, finding 5: the highest trusted roster (and its hash) per vault.
    #[test]
    fn the_highest_roster_is_remembered_with_its_hash() {
        let (_, alice, a) = signer("alice", 1);
        let (_, _, b) = signer("bob", 2);
        let key = SymmetricKey::from_bytes([9; 32]);
        let v1 = next(&alice, &key, None, 0, &[(&a, "owner")]).unwrap();
        let v2 = next(&alice, &key, Some(&v1), 0, &[(&a, "owner"), (&b, "read")]).unwrap();
        let forked = next(&alice, &key, Some(&v1), 0, &[(&a, "owner"), (&b, "write")]).unwrap();
        let (h1, h2, hf) = (
            v1.hash().unwrap(),
            v2.hash().unwrap(),
            forked.hash().unwrap(),
        );
        assert_ne!(h2, hf);
        assert_ne!(h1, h2);
        assert_eq!(
            v2.hash().unwrap(),
            SignedRoster::parse(&v2.to_json().unwrap())
                .unwrap()
                .hash()
                .unwrap()
        );
        let vk = SymmetricKey::from_bytes([1; 32]);
        let k = |e| EpochPin::of(&vk, "v", e).unwrap();
        let pins = KeyPins::default()
            .set_epoch("v", &k(0), Some(1))
            .unwrap()
            .observe(&obs_hash("sealed", Some(k(0)), Some(2), true, Some(&h2)))
            .unwrap();
        assert!(pins.changed);
        let pins = pins.pins;
        assert_eq!(pins.epochs["v"].signed_since, Some(1));
        assert_eq!(pins.epochs["v"].roster_version_max, Some(2));
        assert_eq!(pins.epochs["v"].roster_hash.as_deref(), Some(h2.as_str()));
        let refused = |reason| Admission::Refused { reason };
        // An older roster (version 1: still above signed_since) → downgraded.
        assert_eq!(
            pins.admit(&obs_hash("sealed", Some(k(0)), Some(1), true, Some(&h1)))
                .unwrap(),
            refused(RefuseReason::Downgraded)
        );
        // Another roster with version 2 → forked; the same one → fine.
        assert_eq!(
            pins.admit(&obs_hash("sealed", Some(k(0)), Some(2), true, Some(&hf)))
                .unwrap(),
            refused(RefuseReason::RosterForked)
        );
        assert!(matches!(
            pins.admit(&obs_hash("sealed", Some(k(0)), Some(2), true, Some(&h2)))
                .unwrap(),
            Admission::Ok { pin: false, .. }
        ));
        // Merging keeps the higher; at the same version the server's hash.
        let other = KeyPins::default().set_epoch("v", &k(0), Some(1)).unwrap();
        assert_eq!(other.merge(&pins).unwrap().epochs["v"], pins.epochs["v"]);
        assert_eq!(pins.merge(&other).unwrap().epochs["v"], pins.epochs["v"]);
        // Left: the tombstone keeps the highest version even when leaving said 0.
        let left = pins.leave("v", 0, 5).unwrap();
        assert_eq!(left.left["v"].roster_version, 2);
        let mut bad = pins.epochs["v"].clone();
        bad.roster_version_max = None;
        assert!(bad.check().is_err(), "a hash without its version");
    }

    /// Round 3, finding 8: a stale pin merged with a tombstone is not a re-join.
    #[test]
    fn stale_pins_do_not_undo_leaving() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let k2 = SymmetricKey::from_bytes([2; 32]);
        let pins = KeyPins::default()
            .set_epoch("v", &pin(&k1, 0), Some(3))
            .unwrap();
        // Left with "no roster" (0): the tombstone still says 3.
        let left = pins.leave("v", 0, 10).unwrap();
        assert_eq!(left.left["v"].roster_version, 3);
        // An old tombstone written before (version 0) and the stale pin: still left.
        let mut old_tomb = left.clone();
        old_tomb.left.get_mut("v").unwrap().roster_version = 0;
        for t in [&left, &old_tomb] {
            let m = t.merge(&pins).unwrap();
            assert!(m.epochs.is_empty() && m.left.contains_key("v"));
            // A device that saw a newer key before learning of the leave: still left.
            let newer = pins.set_epoch("v", &pin(&k2, 1), Some(3)).unwrap();
            assert!(t.merge(&newer).unwrap().epochs.is_empty());
            // The stale roster can't bring it back either.
            assert!(matches!(
                t.set_epoch("v", &pin(&k2, 1), Some(3)),
                Err(Error::Rollback)
            ));
        }
        // A real re-join (a newer roster) wins.
        let back = left.set_epoch("v", &pin(&k2, 1), Some(4)).unwrap();
        let m = left.merge(&back).unwrap();
        assert!(m.left.is_empty() && m.epochs.contains_key("v"));
    }

    /// Round 3, finding 9: emails compare NFKC-normalized with ASCII (punycode) domains.
    #[test]
    fn emails_compare_normalized() {
        assert_eq!(normalize_email("  Bob@Example.COM "), "bob@example.com");
        assert_eq!(
            normalize_email("ＢＯＢ@ｅｘａｍｐｌｅ.com"),
            "bob@example.com"
        );
        assert_eq!(
            normalize_email("erin@Bücher.example"),
            "erin@xn--bcher-kva.example"
        );
        assert_eq!(
            normalize_email("erin@xn--bcher-kva.example"),
            "erin@xn--bcher-kva.example"
        );
        assert_eq!(normalize_email("no-at-sign"), "no-at-sign");
        let (_, _, b) = signer("bob", 2);
        let (_, _, c) = signer("carol", 3);
        let (_, _, e) = signer("erin", 4);
        let pins = KeyPins::default()
            .set(&b, "bob@example.com", false, 1)
            .unwrap()
            .set(&e, "erin@bücher.example", false, 1)
            .unwrap();
        for email in [
            "ＢＯＢ@example.com",
            "bob@ｅｘａｍｐｌｅ.com",
            "ERIN@XN--BCHER-KVA.example",
        ] {
            assert_eq!(
                pins.check_identity(&c, Some(email)).unwrap(),
                PinStatus::EmailConflict,
                "{email}"
            );
        }
    }

    /// Round 3, findings 7 and 11: no signing from a blocked review; `sign_roster` checks
    /// the previous roster.
    #[test]
    fn blocked_reviews_and_bad_previous_rosters_sign_nothing() {
        let (_, alice, a) = signer("alice", 1);
        let (_, _, b) = signer("bob", 2);
        let (_, _, fake_b) = signer("bob", 8);
        let key = SymmetricKey::from_bytes([9; 32]);
        let v1 = next(&alice, &key, None, 0, &[(&a, "owner"), (&b, "read")]).unwrap();
        let rows = inputs(&[(&a, "owner"), (&fake_b, "read")]);
        let review = roster_review(VAULT, Some(&v1), &a, &rows, &KeyPins::default()).unwrap();
        assert!(review.blocked);
        assert!(review.digest.is_empty());
        assert!(matches!(
            alice.sign_roster(&key, VAULT, Some(&v1), 0, &rows, &review.digest),
            Err(Error::ReviewMismatch)
        ));
        let rows = inputs(&[(&a, "owner"), (&b, "write")]);
        let review = roster_review(VAULT, Some(&v1), &a, &rows, &KeyPins::default()).unwrap();
        let mut tampered = v1.clone();
        tampered.members[1].role = "write".into();
        assert!(matches!(
            alice.sign_roster(&key, VAULT, Some(&tampered), 0, &rows, &review.digest),
            Err(Error::BadSignature)
        ));
        alice
            .sign_roster(&key, VAULT, Some(&v1), 0, &rows, &review.digest)
            .unwrap();
    }

    // ------------------------------------------------------------- round 4

    /// A pin with made-up ids (`[id; 32]` as its key, `[r; 12]` retired), as the review
    /// round 3 probe built them.
    fn fake_pin(epoch: u64, id: u8, retired: &[u8]) -> EpochPin {
        EpochPin {
            key_epoch: epoch,
            key_id: b64(&[id; 32]),
            retired: retired.iter().map(|r| b64(&[*r; 12])).collect(),
            signed_since: None,
            roster_version_max: None,
            roster_hash: None,
            rejoined_at: None,
            own: false,
        }
    }

    fn with_pin(vault: &str, p: EpochPin) -> KeyPins {
        KeyPins {
            epochs: [(vault.to_owned(), p)].into_iter().collect(),
            ..KeyPins::default()
        }
    }

    /// Review round 4 H1: merging never un-retires a key, in either order.
    #[test]
    fn merging_never_unretires_a_key() {
        let cur = |e, id| fake_pin(e, id, &[]);
        // Same epoch: the server's copy K2@3, this device K3@3 having retired K2.
        let server = with_pin("v", fake_pin(3, 2, &[1]));
        let ours = with_pin("v", fake_pin(3, 3, &[1, 2]));
        for m in [server.merge(&ours).unwrap(), ours.merge(&server).unwrap()] {
            assert_eq!(m.epochs["v"].key_id, b64(&[3; 32]));
            assert_eq!(m.check_epoch("v", &cur(3, 2), None), EpochStatus::Older);
            assert_eq!(m.check_epoch("v", &cur(9, 2), None), EpochStatus::Older);
            assert_eq!(m.check_epoch("v", &cur(3, 3), None), EpochStatus::Same);
            assert_eq!(m.check_epoch("v", &cur(4, 4), None), EpochStatus::Newer);
        }
        // The retired key relabelled at a higher epoch in the server's copy.
        let server = with_pin("v", fake_pin(4, 2, &[1]));
        for m in [server.merge(&ours).unwrap(), ours.merge(&server).unwrap()] {
            let p = &m.epochs["v"];
            assert_eq!((p.key_epoch, p.key_id.clone()), (3, b64(&[3; 32])));
            assert!(retires(p, &b64(&[2; 32])) && retires(p, &b64(&[1; 32])));
            assert_eq!(m.check_epoch("v", &cur(4, 2), None), EpochStatus::Older);
        }
        // A true conflict (same epoch, neither retired): the base's key stays, and the
        // other key shows as a conflict wherever it is served.
        let a = with_pin("v", fake_pin(3, 2, &[1]));
        let b = with_pin("v", fake_pin(3, 3, &[1]));
        let m = a.merge(&b).unwrap();
        assert_eq!(m.epochs["v"].key_id, b64(&[2; 32]));
        assert_eq!(m.check_epoch("v", &cur(3, 3), None), EpochStatus::Conflict);
        assert!(!retires(&m.epochs["v"], &b64(&[3; 32])));
        let m = b.merge(&a).unwrap();
        assert_eq!(m.check_epoch("v", &cur(3, 2), None), EpochStatus::Conflict);
        // A lower epoch is retired by the higher one as before.
        let m = with_pin("v", fake_pin(2, 2, &[1]))
            .merge(&with_pin("v", fake_pin(5, 5, &[])))
            .unwrap();
        assert_eq!(m.epochs["v"].key_epoch, 5);
        assert_eq!(m.check_epoch("v", &cur(6, 2), None), EpochStatus::Older);
        // Both keys retired by the other side (mixed histories): neither is accepted
        // until a newer key comes.
        let x = with_pin("v", fake_pin(3, 2, &[3]));
        let y = with_pin("v", fake_pin(4, 3, &[2]));
        for m in [x.merge(&y).unwrap(), y.merge(&x).unwrap()] {
            assert_eq!(m.check_epoch("v", &cur(4, 3), None), EpochStatus::Older);
            assert_eq!(m.check_epoch("v", &cur(3, 2), None), EpochStatus::Older);
            assert_eq!(m.check_epoch("v", &cur(5, 7), None), EpochStatus::Newer);
            m.check().unwrap();
        }
    }

    /// Review round 4 M2 and L4: a stale pin never undoes a leave, and the tombstone
    /// keeps what the dropped pin knew.
    #[test]
    fn tombstones_beat_stale_pins_and_keep_their_knowledge() {
        let o = |key: EpochPin, roster: u64| VaultObservation {
            vault_id: "v".into(),
            key_kind: "sealed".into(),
            key: Some(key),
            roster_version: Some(roster),
            roster_hash: None,
            chain_hashes: None,
            signed_share: true,
            paused: false,
        };
        let signed = |mut p: EpochPin, v: u64| {
            p.signed_since = Some(v);
            p.roster_version_max = Some(v);
            p
        };
        // Probe 2: the server's copy has a pin with a higher signed_since than the one
        // the leaving device knew (it left with "no roster").
        let server = with_pin("v", signed(fake_pin(1, 1, &[]), 1));
        let left = with_pin("v", fake_pin(1, 1, &[]))
            .leave("v", 0, 100)
            .unwrap();
        let m = server.merge(&left).unwrap();
        assert!(m.epochs.is_empty() && m.left.contains_key("v"));
        assert_eq!(m.left["v"].roster_version, 1, "raised to the dropped pin's");
        assert_eq!(
            m.admit(&o(fake_pin(1, 1, &[]), 1)).unwrap(),
            Admission::Refused {
                reason: RefuseReason::Left
            }
        );
        assert!(matches!(
            m.admit(&o(fake_pin(1, 1, &[]), 2)).unwrap(),
            Admission::Consent { rejoin: true, .. }
        ));
        // Probe 3: the tombstone wins and keeps the newer pin's retired key.
        let server = with_pin("v", signed(fake_pin(2, 2, &[1]), 1));
        let left = with_pin("v", signed(fake_pin(1, 1, &[]), 1))
            .leave("v", 1, 100)
            .unwrap();
        for m in [server.merge(&left).unwrap(), left.merge(&server).unwrap()] {
            let t = &m.left["v"];
            assert_eq!(t.pin.as_ref().unwrap().key_epoch, 2);
            assert!(retires(t.pin.as_ref().unwrap(), &b64(&[1; 32])));
            assert_eq!(
                m.admit(&o(fake_pin(1, 1, &[]), 5)).unwrap(),
                Admission::Refused {
                    reason: RefuseReason::Left
                },
                "the old key can't re-join"
            );
        }
        // A real re-join is marked and beats the tombstone it cleared; a stale copy of
        // the pin from before the leave doesn't.
        let before = with_pin("v", signed(fake_pin(1, 1, &[]), 3));
        let left = before.leave("v", 3, 10).unwrap();
        let back = left.set_epoch("v", &fake_pin(2, 2, &[]), Some(4)).unwrap();
        assert_eq!(back.epochs["v"].rejoined_at, Some(4));
        let m = left.merge(&back).unwrap();
        assert!(m.left.is_empty());
        assert_eq!(m.epochs["v"].key_epoch, 2);
        assert!(retires(&m.epochs["v"], &b64(&[1; 32])));
        assert!(left.merge(&before).unwrap().epochs.is_empty());
        // Left again after the re-join (seen at roster 4): that tombstone wins.
        let again = back.leave("v", 4, 20).unwrap();
        let m = again.merge(&back).unwrap();
        assert!(m.epochs.is_empty() && m.left["v"].roster_version == 4);
        // Tombstone against tombstone: the higher version, both pins, the later time.
        let t1 = with_pin("v", signed(fake_pin(2, 2, &[1]), 2))
            .leave("v", 2, 50)
            .unwrap();
        let t2 = with_pin("v", signed(fake_pin(3, 3, &[]), 5))
            .leave("v", 0, 40)
            .unwrap();
        for m in [t1.merge(&t2).unwrap(), t2.merge(&t1).unwrap()] {
            let t = &m.left["v"];
            assert_eq!((t.roster_version, t.left_at), (5, 50));
            let p = t.pin.as_ref().unwrap();
            assert_eq!(p.key_epoch, 3);
            assert!(retires(p, &b64(&[1; 32])) && retires(p, &b64(&[2; 32])));
        }
    }

    /// Review round 4 L5: retired ids stay within their budget.
    #[test]
    fn retired_ids_have_a_budget() {
        let many = |id: u8, n: usize| {
            let mut p = fake_pin(n as u64, id, &[]);
            p.retired = (0..n)
                .map(|i| {
                    let mut b = [id; 12];
                    b[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    b64(&b)
                })
                .collect();
            p
        };
        // Tombstones keep the newest 64.
        let full = with_pin("v", many(1, MAX_RETIRED_KEY_IDS));
        let left = full.leave("v", 0, 1).unwrap();
        let t = left.left["v"].pin.as_ref().unwrap();
        assert_eq!(t.retired.len(), MAX_TOMBSTONE_RETIRED_KEY_IDS);
        assert_eq!(t.retired.last(), full.epochs["v"].retired.last());
        // Accepted vaults: at most the total budget together, longest lists first.
        let mut pins = KeyPins::default();
        for (i, id) in (10u8..16).enumerate() {
            pins.epochs
                .insert(format!("v{i}"), many(id, MAX_RETIRED_KEY_IDS));
        }
        pins.epochs.insert("small".into(), many(20, 10));
        let merged = KeyPins::default().merge(&pins).unwrap();
        let total: usize = merged.epochs.values().map(|p| p.retired.len()).sum();
        assert!(total <= MAX_TOTAL_RETIRED_KEY_IDS, "{total}");
        assert_eq!(merged.epochs["small"].retired.len(), 10);
        assert!(merged.epochs["v0"].retired.len() >= MAX_TOMBSTONE_RETIRED_KEY_IDS);
        assert_eq!(
            merged.epochs["v0"].retired.last(),
            pins.epochs["v0"].retired.last(),
            "the newest kept"
        );
        // The sealed pins stay well under their size limit.
        let json = serde_json::to_vec(&merged).unwrap();
        assert!(json.len() < MAX_KEY_PINS_JSON / 2, "{}", json.len());
    }

    /// Review round 4 I1: `accept` checks the row, records the roster's hash and refuses
    /// what `admit` refuses.
    #[test]
    fn accept_records_the_roster_and_refuses_refused_rows() {
        let k1 = SymmetricKey::from_bytes([1; 32]);
        let hash = b64(&[5; 32]);
        let invitation = obs_hash("sealed", Some(pin(&k1, 0)), Some(2), true, Some(&hash));
        let none = KeyPins::default();
        assert!(matches!(
            none.admit(&invitation).unwrap(),
            Admission::Consent { .. }
        ));
        let accepted = none.accept(&invitation).unwrap();
        let p = &accepted.epochs["v"];
        assert_eq!(p.signed_since, Some(2));
        assert_eq!(p.roster_version_max, Some(2));
        assert_eq!(p.roster_hash.as_deref(), Some(hash.as_str()));
        assert!(!p.own);
        // Refusals become errors.
        let forked = obs_hash(
            "sealed",
            Some(pin(&k1, 0)),
            Some(2),
            true,
            Some(&b64(&[6; 32])),
        );
        assert!(matches!(accepted.accept(&forked), Err(Error::RosterForked)));
        let stripped = obs("sealed", Some(pin(&k1, 0)), None, false);
        assert!(matches!(accepted.accept(&stripped), Err(Error::Rollback)));
        let mut paused = invitation.clone();
        paused.paused = true;
        assert!(matches!(none.accept(&paused), Err(Error::IdentityMismatch)));
        assert!(none.accept(&obs("sealed", None, None, false)).is_err());
        // A re-join through accept: marked, the tombstone cleared.
        let left = accepted.leave("v", 2, 10).unwrap();
        let k2 = SymmetricKey::from_bytes([2; 32]);
        let rejoin = obs_hash("sealed", Some(pin(&k2, 1)), Some(3), true, Some(&hash));
        assert!(matches!(
            left.admit(&rejoin).unwrap(),
            Admission::Consent { rejoin: true, .. }
        ));
        let back = left.accept(&rejoin).unwrap();
        assert!(back.left.is_empty());
        assert_eq!(back.epochs["v"].rejoined_at, Some(3));
        // Observation JSON must say `signed_share` and `paused` (review round 4 I2).
        let json = serde_json::json!({
            "vault_id": "v", "key_kind": "sealed", "key": pin(&k1, 0),
            "roster_version": null, "signed_share": false,
        });
        assert!(serde_json::from_value::<VaultObservation>(json).is_err());
        let json = serde_json::json!({
            "vault_id": "v", "key_kind": "sealed", "key": pin(&k1, 0),
            "roster_version": null, "paused": false,
        });
        assert!(serde_json::from_value::<VaultObservation>(json).is_err());
    }

    /// Lead's round 4 finding: a server-made "puppet" account signs a version 1 roster
    /// and a share of a key it chose for a vault the account pinned without signed
    /// history (grandfathered, or its own vault served as sealed): consent, never ok.
    #[test]
    fn a_puppet_signed_key_on_a_vault_never_seen_signed_needs_consent() {
        let (_, _, me) = signer("me", 1);
        let (_, puppet, p) = signer("puppet", 66);
        let old = SymmetricKey::from_bytes([1; 32]);
        let server_key = SymmetricKey::from_bytes([77; 32]);
        // The server's key, a roster v1 by the puppet listing it and me, and its share.
        let roster = next(
            &puppet,
            &server_key,
            None,
            1,
            &[(&p, "owner"), (&me, "write")],
        )
        .unwrap();
        let trusted =
            verify_roster_chain(VAULT, None, std::slice::from_ref(&roster), &roster).unwrap();
        assert_eq!(trusted.signer_role(&p).unwrap().as_deref(), Some("owner"));
        let share = puppet
            .seal_and_sign_share(&server_key, VAULT, &me, "write", 1)
            .unwrap();
        verify_share(
            VAULT,
            &me,
            "write",
            1,
            &share.sealed_key,
            &p,
            &share.signature,
        )
        .unwrap();
        let key = |k: &SymmetricKey, e| EpochPin::of(k, VAULT, e).unwrap();
        let row = VaultObservation {
            vault_id: VAULT.into(),
            key_kind: "sealed".into(),
            key: Some(key(&server_key, 1)),
            roster_version: Some(1),
            roster_hash: Some(trusted.hash().unwrap()),
            chain_hashes: None,
            signed_share: true,
            paused: false,
        };
        // A grandfathered share pinned unsigned.
        let grand = KeyPins::default()
            .grandfather(&[VAULT.into()], true)
            .unwrap()
            .set_epoch(VAULT, &key(&old, 0), None)
            .unwrap();
        assert_eq!(
            grand.admit(&row).unwrap(),
            Admission::Consent {
                rejoin: false,
                replaced: true,
                own: false
            }
        );
        assert!(!grand.observe(&row).unwrap().changed);
        // The account's own vault, then served as sealed with the server's key.
        let own_row = VaultObservation {
            key_kind: "account".into(),
            key: Some(key(&old, 0)),
            roster_version: None,
            roster_hash: None,
            chain_hashes: None,
            signed_share: false,
            ..row.clone()
        };
        let mine = KeyPins::default().observe(&own_row).unwrap().pins;
        assert!(mine.epochs[VAULT].own);
        assert_eq!(
            mine.admit(&row).unwrap(),
            Admission::Consent {
                rejoin: false,
                replaced: true,
                own: true
            }
        );
        // Pins from before (no `own` mark) learn it from the next account row.
        let legacy = KeyPins::default()
            .set_epoch(VAULT, &key(&old, 0), None)
            .unwrap();
        assert!(matches!(
            legacy.admit(&own_row).unwrap(),
            Admission::Ok { pin: true, .. }
        ));
        let learned = legacy.observe(&own_row).unwrap();
        assert!(learned.changed && learned.pins.epochs[VAULT].own);
        assert!(matches!(
            learned.pins.admit(&own_row).unwrap(),
            Admission::Ok { pin: false, .. }
        ));
        // Accepted anyway (the user's choice): the server's key is pinned, not silently.
        let accepted = mine.accept(&row).unwrap();
        assert_eq!(accepted.epochs[VAULT].key_epoch, 1);
        assert!(accepted.epochs[VAULT].own, "the mark stays");
    }

    /// Review round 4 I3: the reviewed digest binds the version, `first` and the previous
    /// roster.
    #[test]
    fn review_digests_bind_the_previous_roster() {
        let (_, alice, a) = signer("alice", 1);
        let (_, _, b) = signer("bob", 2);
        let key = SymmetricKey::from_bytes([9; 32]);
        let v1 = next(&alice, &key, None, 0, &[(&a, "owner"), (&b, "read")]).unwrap();
        let v1b = next(&alice, &key, None, 0, &[(&a, "owner"), (&b, "write")]).unwrap();
        let rows = inputs(&[(&a, "owner"), (&b, "read")]);
        let review = roster_review(VAULT, Some(&v1), &a, &rows, &KeyPins::default()).unwrap();
        // Not valid for a version 1 of the same list, nor after another version 1.
        assert!(matches!(
            alice.sign_roster(&key, VAULT, None, 0, &rows, &review.digest),
            Err(Error::ReviewMismatch)
        ));
        assert!(matches!(
            alice.sign_roster(&key, VAULT, Some(&v1b), 0, &rows, &review.digest),
            Err(Error::ReviewMismatch)
        ));
        let first = roster_review(VAULT, None, &a, &rows, &KeyPins::default()).unwrap();
        assert_ne!(first.digest, review.digest);
        alice
            .sign_roster(&key, VAULT, Some(&v1), 0, &rows, &review.digest)
            .unwrap();
    }

    /// Review round 4 M3: invisible characters, trailing dots and IDNA failures.
    #[test]
    fn emails_lose_invisible_characters() {
        let alice = normalize_email("alice@example.com");
        for email in [
            "ali\u{200B}ce@example.com",
            "alice@example.com.",
            "alice@example.com\u{200B}",
            "\u{FEFF}alice@example.com",
            "alice\u{2028}@example.com",
            "alice@exam\u{3164}ple.com",
            "alice@example.com\u{E0001}",
            "al\u{202E}ice@example.com",
        ] {
            assert_eq!(normalize_email(email), alice, "{email:?}");
        }
        // A look-alike domain is punycode, so not equal and plainly different.
        let fake = normalize_email("alice@ex\u{0430}mple.com\u{E0001}");
        assert_ne!(fake, alice);
        assert!(fake.is_ascii() && fake.contains("xn--"), "{fake}");
        // A domain IDNA refuses: no non-ASCII character left that could look like one.
        let refused = normalize_email("al\u{0456}ce@b\u{00FC} cher.example");
        assert_eq!(refused, "al\\u{456}ce@b\\u{fc} cher.example");
        assert_eq!(normalize_email("a\\b@"), "a\\u{5c}b@");
    }

    /// Round 4 follow-up: a chain verified from an older (or no) remembered roster must
    /// contain the roster the key pins remember at their highest version, with its hash.
    #[test]
    fn fetched_chains_must_contain_the_pinned_roster() {
        let k = SymmetricKey::from_bytes([1; 32]);
        let h = |n: u8| b64(&[n; 32]);
        let chain = |items: &[(u64, u8)]| {
            Some(
                items
                    .iter()
                    .map(|(v, n)| (v.to_string(), h(*n)))
                    .collect::<BTreeMap<_, _>>(),
            )
        };
        let row = |version: u64, hash: u8, hashes| VaultObservation {
            chain_hashes: hashes,
            ..obs_hash(
                "sealed",
                Some(pin(&k, 0)),
                Some(version),
                true,
                Some(&h(hash)),
            )
        };
        // Seen signed up to roster version 2 (hash 2).
        let pins = KeyPins::default().accept(&row(2, 2, None)).unwrap();
        assert_eq!(pins.epochs["v"].roster_hash, Some(h(2)));
        let forked = Admission::Refused {
            reason: RefuseReason::RosterForked,
        };
        // A device without the remembered roster is shown a chain from version 1 that a
        // server-made account signed (hashes 11, 12, 13): refused.
        let puppet = row(3, 13, chain(&[(1, 11), (2, 12), (3, 13)]));
        assert_eq!(pins.admit(&puppet).unwrap(), forked);
        assert!(matches!(pins.accept(&puppet), Err(Error::RosterForked)));
        assert!(!pins.observe(&puppet).unwrap().changed);
        // The real chain (through hash 2 at version 2), or one from a remembered roster
        // at or after it: fine.
        for c in [
            chain(&[(1, 1), (2, 2), (3, 3)]),
            chain(&[(2, 2), (3, 3)]),
            chain(&[(3, 3)]),
            None,
        ] {
            assert!(
                matches!(
                    pins.admit(&row(3, 3, c.clone())).unwrap(),
                    Admission::Ok { pin: true, .. }
                ),
                "{c:?}"
            );
        }
        // Malformed: a gap over the pinned version, another hash for the trusted roster,
        // versions that aren't plain numbers from 1.
        assert!(pins.admit(&row(3, 3, chain(&[(1, 1), (3, 3)]))).is_err());
        assert!(pins.admit(&row(3, 3, chain(&[(2, 2), (3, 4)]))).is_err());
        for bad in ["0", "02", "x", "-1"] {
            let mut c = chain(&[(3, 3)]).unwrap();
            c.insert(bad.into(), h(3));
            assert!(pins.admit(&row(3, 3, Some(c))).is_err(), "{bad}");
        }
        let mut short = chain(&[(3, 3)]).unwrap();
        short.insert("1".into(), "short".into());
        assert!(pins.admit(&row(3, 3, Some(short))).is_err());
        // A tombstone remembers the hash too: a re-share whose chain from version 1 was
        // signed by someone else can't even ask to re-join.
        let left = pins.leave("v", 2, 10).unwrap();
        assert_eq!(left.left["v"].pin.as_ref().unwrap().roster_hash, Some(h(2)));
        assert_eq!(left.admit(&puppet).unwrap(), forked);
        assert!(matches!(left.accept(&puppet), Err(Error::RosterForked)));
        let real = row(3, 3, chain(&[(1, 1), (2, 2), (3, 3)]));
        assert!(matches!(
            left.admit(&real).unwrap(),
            Admission::Consent { rejoin: true, .. }
        ));
        left.accept(&real).unwrap();
        // Merged tombstones and pins keep the hash.
        let merged = left.merge(&pins).unwrap();
        assert_eq!(merged.admit(&puppet).unwrap(), forked);
    }
}
