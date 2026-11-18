//! Vault manifests: a small sealed record of what a vault holds, so a server can't
//! serve an older copy of an item, hide a new item or a deletion, or bring a deleted
//! item back without the apps noticing.
//!
//! A manifest is `{version, live, trashed, acc}`: how many items the vault has outside
//! and inside the trash, and `acc`, the sum mod 2^256 of one term per item:
//!
//! ```text
//! term = HMAC-SHA256(mac key, item id ‖ 0x00 ‖ state ‖ 0x00 ‖ SHA-256(data))
//! ```
//!
//! `state` is one byte (0 = live, 1 = in the trash) and `data` the item's `data` string
//! exactly as the server stores it (its UTF-8 bytes, the base64url text, not the decoded
//! ciphertext). The wrapped item key is not covered. The terms are added as 256-bit
//! big-endian numbers, so a write updates the sum without the other items: subtract the
//! old term, add the new one.
//!
//! Both keys come from the vault key (HKDF-SHA256, no salt): the mac key with info
//! `passauth/vault-manifest-mac/v1`, the sealing key with `passauth/vault-manifest-key/v1`.
//! Replacing the vault key replaces both keys: the rotation carries a manifest computed
//! afresh.
//!
//! # The chain
//!
//! Every manifest names the one it replaces. A manifest's **link** is
//!
//! ```text
//! link = SHA-256("passauth/vault-manifest-link/v1" ‖ 0x00 ‖ version (8 bytes, big-endian)
//!                ‖ prev (32 bytes) ‖ SHA-256(sealed text))
//! ```
//!
//! where `sealed text` is the manifest's sealed form as the server stores it (the
//! base64url characters, like an item's `data`) and `prev` the link of the manifest it
//! replaces: 32 zero bytes for a vault's first manifest. A manifest is sealed
//! (XChaCha20-Poly1305, the usual ciphertext layout, base64url) with the associated data
//!
//! ```text
//! passauth/vault-manifest/v1/<vault id>/<key epoch>/<version>/<prev, 64 hex digits>
//! ```
//!
//! so the server can't pass off another vault's, epoch's or version's manifest, nor one
//! with another predecessor: whoever opens the newest manifest (the head) knows the link
//! its writer built on. The server stores `prev` in clear next to the sealed text and
//! keeps a log `(version, prev, SHA-256(sealed text))` of the manifests before it, from
//! which every earlier link follows by hashing alone. That matters because earlier
//! manifests may be sealed under vault keys a device no longer (or never) had: the chain
//! is checked by hashes and never by opening anything but the head.
//!
//! What this gives ([`verify`]): a device remembers the version and link of the last
//! manifest it checked or wrote. A later head must be that very manifest (the same
//! version: the same link) or descend from it: its authenticated `prev`, followed back
//! through the log's hashes, arrives at the remembered link. Each step is fixed by the
//! hash above it, so a server can't splice in, leave out or invent entries without a
//! SHA-256 collision; it can only withhold the log (the vault then doesn't check out).
//! So a server that kept two groups of devices on two histories can't bring a device
//! over to the other history unnoticed: that history doesn't contain what the device
//! last saw.
//!
//! What it doesn't give: a device that remembers nothing trusts the first manifest it
//! sees; a server can keep devices on separate histories for as long as it never joins
//! them; the log is finite (the server keeps the newest entries), so a device further
//! behind than the log reaches gets a mismatch, not a pass; and manifests are sealed,
//! not signed, so anyone holding the vault key (a read-only member too) who works with
//! the server can seal a matching manifest for an altered item set.
//!
//! # Accepting the server's copy
//!
//! A device whose memory the served vault doesn't continue (a restored backup, a log
//! that no longer reaches back, another history) keeps its warning until its user
//! accepts what the server shows. [`accept`] is that step's check: the vault as served,
//! judged with nothing remembered. When the head opens and records exactly the served
//! items, the device replaces its memory with that head (also when it remembered a
//! higher version) and goes on from there; nothing is written to the server, so every
//! member's device can do it, whatever its role. Only when the head itself is wrong (it
//! doesn't open, or the items aren't what it records) does someone who may write have
//! to store a new one over the served items: a baseline, one version up and naming the
//! served head like any other manifest ([`start`] with [`row_link`]), which its writer
//! then remembers in place of whatever it remembered before. The chain stays sound
//! through both: memory only ever becomes a head that was checked against the served
//! items (or sealed by this device over them), and everything after it must descend
//! from that head; what the device knew before is given up on the user's word, which is
//! the one thing no check can replace.
//!
//! The server replaces the manifest only together with the write it describes. Apps
//! check every sync ([`verify`]); see `docs/ARCHITECTURE.md`.

use std::collections::{HashMap, HashSet};

use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{SymmetricKey, hkdf_key};
use crate::item::{b64, unb64};
use crate::{Error, Result};

const MAC_INFO: &[u8] = b"passauth/vault-manifest-mac/v1";
const KEY_INFO: &[u8] = b"passauth/vault-manifest-key/v1";
const AAD_PREFIX: &str = "passauth/vault-manifest/v1";
const LINK_INFO: &[u8] = b"passauth/vault-manifest-link/v1";

/// The highest manifest version (and item count): whole numbers every binding carries
/// exactly (JavaScript's 2^53 − 1).
pub const MAX_VERSION: u64 = 9_007_199_254_740_991;

/// A manifest's link (see the module docs).
pub type Link = [u8; 32];

/// What a vault's first manifest names as its predecessor.
pub const NO_LINK: Link = [0; 32];

/// SHA-256 of a sealed manifest's text as stored (the log's `digest`).
pub fn sealed_digest(sealed: &str) -> [u8; 32] {
    Sha256::digest(sealed.as_bytes()).into()
}

/// The link of the manifest of `version` that replaced `prev` and whose sealed text
/// hashes to `digest`.
pub fn link(version: u64, prev: &Link, digest: &[u8; 32]) -> Link {
    let mut h = Sha256::new();
    h.update(LINK_INFO);
    h.update([0]);
    h.update(version.to_be_bytes());
    h.update(prev);
    h.update(digest);
    h.finalize().into()
}

/// A link (or digest) from its base64url text: exactly 32 bytes.
pub fn parse_link(text: &str) -> Result<Link> {
    unb64(text)?
        .try_into()
        .map_err(|_| Error::Malformed("manifest link"))
}

/// The link of a vault row's manifest (`manifest_seq`, `manifest_prev`, `manifest`) in
/// base64url: what the next manifest names as its predecessor. Nothing is opened, so
/// this also works for a manifest the device can't or won't accept (a new baseline is
/// built on whatever the server shows).
pub fn row_link(manifest_seq: u64, prev: &str, sealed: &str) -> Result<String> {
    check_version(manifest_seq)?;
    Ok(b64(&link(
        manifest_seq,
        &parse_link(prev)?,
        &sealed_digest(sealed),
    )))
}

/// Whether an item is in the trash, as a `/sync` row's `deleted_at` says it: absent or
/// null = live, a whole number above zero (Unix seconds) = in the trash. Anything else
/// (0, a negative number, a fraction, text, a boolean) is refused when the entry is
/// counted, so no row shape can flip an item's state between two apps' readings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeletedAt {
    #[default]
    Live,
    Trashed,
    /// Not a value `deleted_at` may have: the entry is malformed.
    Invalid,
}

impl<'de> Deserialize<'de> for DeletedAt {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = DeletedAt;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("null or a whole number of seconds above zero")
            }
            fn visit_unit<E>(self) -> std::result::Result<DeletedAt, E> {
                Ok(DeletedAt::Live)
            }
            fn visit_none<E>(self) -> std::result::Result<DeletedAt, E> {
                Ok(DeletedAt::Live)
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> std::result::Result<DeletedAt, D::Error> {
                d.deserialize_any(V)
            }
            fn visit_u64<E>(self, n: u64) -> std::result::Result<DeletedAt, E> {
                Ok(if (1..=MAX_VERSION).contains(&n) {
                    DeletedAt::Trashed
                } else {
                    DeletedAt::Invalid
                })
            }
            fn visit_i64<E>(self, n: i64) -> std::result::Result<DeletedAt, E> {
                Ok(if n >= 1 && n as u64 <= MAX_VERSION {
                    DeletedAt::Trashed
                } else {
                    DeletedAt::Invalid
                })
            }
            /// JavaScript has one number type: a whole number arrives here from some
            /// bindings. A fraction, NaN or an infinity is not a time.
            fn visit_f64<E>(self, n: f64) -> std::result::Result<DeletedAt, E> {
                Ok(if n.fract() == 0.0 && n >= 1.0 && n <= MAX_VERSION as f64 {
                    DeletedAt::Trashed
                } else {
                    DeletedAt::Invalid
                })
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<DeletedAt, E> {
                Ok(DeletedAt::Invalid)
            }
            fn visit_str<E>(self, _: &str) -> std::result::Result<DeletedAt, E> {
                Ok(DeletedAt::Invalid)
            }
        }
        d.deserialize_any(V)
    }
}

/// One item as a manifest counts it. Deserializes from a `/sync` item row as it is
/// (unknown fields are ignored): `id`, `deleted_at` (see [`DeletedAt`]; nothing else
/// in a row says whether the item is in the trash), and `data` or, for a row sent
/// without it (`trash=summary`), the server's `data_sha256`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Entry {
    pub id: String,
    #[serde(default)]
    pub deleted_at: DeletedAt,
    /// The item's `data` as stored. Wins over `data_sha256` when both are given.
    #[serde(default)]
    pub data: Option<String>,
    /// base64url SHA-256 of the `data` string, for a row that came without it.
    #[serde(default)]
    pub data_sha256: Option<String>,
}

impl Entry {
    pub fn new(id: &str, trashed: bool, data: &str) -> Self {
        Self {
            id: id.to_owned(),
            deleted_at: if trashed {
                DeletedAt::Trashed
            } else {
                DeletedAt::Live
            },
            data: Some(data.to_owned()),
            data_sha256: None,
        }
    }

    fn is_trashed(&self) -> Result<bool> {
        match self.deleted_at {
            DeletedAt::Live => Ok(false),
            DeletedAt::Trashed => Ok(true),
            DeletedAt::Invalid => Err(Error::Malformed("deleted_at")),
        }
    }

    /// SHA-256 of the data; `None` when the entry has neither data nor a usable hash.
    fn hash(&self) -> Option<[u8; 32]> {
        match (&self.data, &self.data_sha256) {
            (Some(data), _) => Some(data_hash(data)),
            (None, Some(h)) => unb64(h).ok()?.try_into().ok(),
            (None, None) => None,
        }
    }
}

/// SHA-256 of an item's `data` string as stored (what `data_sha256` holds, in base64url).
pub fn data_hash(data: &str) -> [u8; 32] {
    Sha256::digest(data.as_bytes()).into()
}

/// The keys a vault key gives its manifests.
pub struct ManifestKeys {
    mac: SymmetricKey,
    seal: SymmetricKey,
}

impl ManifestKeys {
    pub fn derive(vault_key: &SymmetricKey) -> Self {
        Self {
            mac: hkdf_key(vault_key.as_bytes(), &[], MAC_INFO),
            seal: hkdf_key(vault_key.as_bytes(), &[], KEY_INFO),
        }
    }

    /// One item's term (see the module docs).
    pub fn term(&self, item_id: &str, trashed: bool, data_sha256: &[u8; 32]) -> Result<[u8; 32]> {
        if item_id.is_empty() || item_id.as_bytes().contains(&0) {
            return Err(Error::Malformed("item id"));
        }
        let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(self.mac.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(item_id.as_bytes());
        mac.update(&[0, u8::from(trashed), 0]);
        mac.update(data_sha256);
        Ok(mac.finalize().into_bytes().into())
    }

    /// An entry's state and term.
    fn entry_term(&self, e: &Entry) -> Result<(bool, [u8; 32])> {
        let trashed = e.is_trashed()?;
        let hash = e.hash().ok_or(Error::Malformed("item without data"))?;
        Ok((trashed, self.term(&e.id, trashed, &hash)?))
    }

    /// Counts and sum of a vault's complete item set. `Ok(None)` when an entry has
    /// neither `data` nor `data_sha256` (nothing can be said about the vault then); an
    /// item id listed twice or a `deleted_at` that is no time is an error.
    pub fn summarize(&self, items: &[Entry]) -> Result<Option<Summary>> {
        let mut seen = HashSet::with_capacity(items.len());
        let mut sum = Summary::default();
        let mut complete = true;
        for e in items {
            if !seen.insert(e.id.as_str()) {
                return Err(Error::Malformed("item listed twice"));
            }
            e.is_trashed()?;
            if e.hash().is_none() {
                complete = false;
                continue;
            }
            let (trashed, term) = self.entry_term(e)?;
            sum.add(trashed, &term)?;
        }
        Ok(complete.then_some(sum))
    }
}

/// What a set of items adds up to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub live: u64,
    pub trashed: u64,
    pub acc: [u8; 32],
}

impl Summary {
    fn count(&mut self, trashed: bool) -> &mut u64 {
        if trashed {
            &mut self.trashed
        } else {
            &mut self.live
        }
    }

    fn add(&mut self, trashed: bool, term: &[u8; 32]) -> Result<()> {
        let n = self.count(trashed);
        *n = n
            .checked_add(1)
            .filter(|n| *n <= MAX_VERSION)
            .ok_or(Error::Malformed("manifest counts"))?;
        self.acc = add(&self.acc, term);
        Ok(())
    }

    fn remove(&mut self, trashed: bool, term: &[u8; 32]) -> Result<()> {
        let n = self.count(trashed);
        *n = n
            .checked_sub(1)
            .ok_or(Error::Malformed("manifest counts"))?;
        self.acc = sub(&self.acc, term);
        Ok(())
    }

    /// Equal counts and sum; the sum compared in constant time.
    fn matches(&self, other: &Summary) -> bool {
        let same_acc: bool = self.acc.ct_eq(&other.acc).into();
        same_acc && self.live == other.live && self.trashed == other.trashed
    }
}

/// a + b mod 2^256, big-endian.
fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    out
}

/// a − b mod 2^256, big-endian.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        out[i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    out
}

/// A vault's manifest at one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: u64,
    /// The link of the manifest this one replaces ([`NO_LINK`] for a vault's first).
    pub prev: Link,
    pub summary: Summary,
}

/// The sealed JSON. Unknown fields are ignored (room for later additions).
#[derive(Serialize, Deserialize)]
struct Wire {
    version: u64,
    live: u64,
    trashed: u64,
    acc: String,
}

fn aad(vault_id: &str, key_epoch: u64, version: u64, prev: &Link) -> Vec<u8> {
    let mut hex = String::with_capacity(64);
    for b in prev {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("{AAD_PREFIX}/{vault_id}/{key_epoch}/{version}/{hex}").into_bytes()
}

fn check_version(version: u64) -> Result<()> {
    if version == 0 || version > MAX_VERSION {
        return Err(Error::Malformed("manifest version"));
    }
    Ok(())
}

impl Manifest {
    pub fn new(version: u64, prev: Link, summary: Summary) -> Result<Self> {
        check_version(version)?;
        Ok(Self {
            version,
            prev,
            summary,
        })
    }

    /// The sealed text the server stores, for `vault_id` at `key_epoch` (the epoch of
    /// `vault_key`).
    pub fn seal(&self, vault_key: &SymmetricKey, vault_id: &str, key_epoch: u64) -> Result<String> {
        check_version(self.version)?;
        let json = serde_json::to_vec(&Wire {
            version: self.version,
            live: self.summary.live,
            trashed: self.summary.trashed,
            acc: b64(&self.summary.acc),
        })?;
        let keys = ManifestKeys::derive(vault_key);
        Ok(b64(&keys.seal.encrypt(
            &json,
            &aad(vault_id, key_epoch, self.version, &self.prev),
        )?))
    }

    /// Seal and describe: what a write sends and what its writer remembers.
    fn written(&self, vault_key: &SymmetricKey, vault_id: &str, key_epoch: u64) -> Result<Written> {
        let sealed = self.seal(vault_key, vault_id, key_epoch)?;
        Ok(Written {
            seq: self.version,
            prev: b64(&self.prev),
            link: b64(&link(self.version, &self.prev, &sealed_digest(&sealed))),
            sealed,
        })
    }

    /// Open the sealed text the server lists for `vault_id` with `key_epoch`, `version`
    /// (its `manifest_seq`) and `prev` (its `manifest_prev`): any other vault, epoch,
    /// version or predecessor fails.
    pub fn open(
        vault_key: &SymmetricKey,
        vault_id: &str,
        key_epoch: u64,
        version: u64,
        prev: &Link,
        sealed: &str,
    ) -> Result<Self> {
        check_version(version)?;
        let keys = ManifestKeys::derive(vault_key);
        let json = keys
            .seal
            .decrypt(&unb64(sealed)?, &aad(vault_id, key_epoch, version, prev))?;
        let wire: Wire = serde_json::from_slice(&json)?;
        let acc: [u8; 32] = unb64(&wire.acc)?
            .try_into()
            .map_err(|_| Error::Malformed("manifest sum"))?;
        if wire.version != version {
            return Err(Error::Malformed("manifest version"));
        }
        Ok(Self {
            version,
            prev: *prev,
            summary: Summary {
                live: wire.live,
                trashed: wire.trashed,
                acc,
            },
        })
    }

    /// The manifest after a write, replacing this one whose link is `link`: `removed`
    /// are the items as they were before it (an edited, trashed, restored, deleted or
    /// moved-out item's earlier state), `added` as they are after it (a new, edited,
    /// trashed, restored or moved-in item). One version up. Fails when it would take a
    /// count below zero or an entry has no data or hash.
    pub fn next(
        &self,
        link: Link,
        vault_key: &SymmetricKey,
        removed: &[Entry],
        added: &[Entry],
    ) -> Result<Self> {
        let keys = ManifestKeys::derive(vault_key);
        let mut summary = self.summary.clone();
        for e in removed {
            let (trashed, term) = keys.entry_term(e)?;
            summary.remove(trashed, &term)?;
        }
        for e in added {
            let (trashed, term) = keys.entry_term(e)?;
            summary.add(trashed, &term)?;
        }
        Self::new(self.version + 1, link, summary)
    }
}

/// A vault row's manifest as `/sync` lists it: `manifest_seq` (0 = none),
/// `manifest_prev` and `manifest`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Row<'a> {
    pub seq: u64,
    pub prev: Option<&'a str>,
    pub sealed: Option<&'a str>,
}

/// What a device remembers per vault: the version and link of the last manifest it
/// checked ([`Status::Ok`]) or wrote itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub version: u64,
    pub link: Link,
}

impl Seen {
    /// From the stored pair (`link` in base64url). The all-zero link is refused: no
    /// manifest has it (it is what a first manifest names as its predecessor), and a
    /// memory holding it would follow any history that begins above its version.
    pub fn parse(version: u64, link: &str) -> Result<Self> {
        let seen = Self {
            version,
            link: parse_link(link).map_err(|_| Error::Malformed("remembered manifest"))?,
        };
        seen.check()?;
        Ok(seen)
    }

    fn check(&self) -> Result<()> {
        if check_version(self.version).is_err() || self.link == NO_LINK {
            return Err(Error::Malformed("remembered manifest"));
        }
        Ok(())
    }
}

/// One entry of the server's manifest log (`GET /vaults/{id}/manifest-log`): an earlier
/// manifest's version, the link it replaced and the SHA-256 of its sealed text (both
/// base64url). Nothing in it is trusted: it counts only where its hash is the `prev` of
/// the entry (or head) above it.
///
/// Reading a log never fails on an entry: one that isn't an object, lacks a field or has
/// one of the wrong kind (a `seq` that is no whole number from 1 to [`MAX_VERSION`], a
/// `prev` or `digest` that is no text) becomes an entry with `seq` 0, which no walk
/// reaches. So a server can't turn a check into an error by slipping rubbish into the
/// log; it can only fail to supply the entries that connect. (A log that isn't a list
/// at all is still an error.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogEntry {
    pub seq: u64,
    pub prev: String,
    pub digest: String,
}

/// One field of a log entry, whatever the server put there.
#[derive(Default)]
struct Loose {
    number: Option<u64>,
    text: Option<String>,
}

impl Loose {
    fn number(n: u64) -> Self {
        Self {
            number: (1..=MAX_VERSION).contains(&n).then_some(n),
            text: None,
        }
    }
}

impl<'de> Deserialize<'de> for Loose {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Loose;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("anything")
            }
            fn visit_u64<E>(self, n: u64) -> std::result::Result<Loose, E> {
                Ok(Loose::number(n))
            }
            fn visit_i64<E>(self, n: i64) -> std::result::Result<Loose, E> {
                Ok(Loose::number(u64::try_from(n).unwrap_or(0)))
            }
            /// A whole number that arrives as a float (JavaScript has one number type).
            fn visit_f64<E>(self, n: f64) -> std::result::Result<Loose, E> {
                let whole = n.fract() == 0.0 && n >= 1.0 && n <= MAX_VERSION as f64;
                Ok(Loose::number(if whole { n as u64 } else { 0 }))
            }
            fn visit_str<E>(self, s: &str) -> std::result::Result<Loose, E> {
                Ok(Loose {
                    number: None,
                    text: Some(s.to_owned()),
                })
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<Loose, E> {
                Ok(Loose::default())
            }
            fn visit_bytes<E>(self, _: &[u8]) -> std::result::Result<Loose, E> {
                Ok(Loose::default())
            }
            fn visit_unit<E>(self) -> std::result::Result<Loose, E> {
                Ok(Loose::default())
            }
            fn visit_none<E>(self) -> std::result::Result<Loose, E> {
                Ok(Loose::default())
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> std::result::Result<Loose, D::Error> {
                d.deserialize_any(V)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Loose, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Loose::default())
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Loose, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(Loose::default())
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for LogEntry {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = LogEntry;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a manifest log entry")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<LogEntry, A::Error> {
                let (mut seq, mut prev, mut digest) = (None, None, None);
                let mut twice = false;
                while let Some((name, value)) = map.next_entry::<Loose, Loose>()? {
                    let slot = match name.text.as_deref() {
                        Some("seq") => {
                            twice |= seq.is_some();
                            seq = value.number;
                            continue;
                        }
                        Some("prev") => &mut prev,
                        Some("digest") => &mut digest,
                        _ => continue,
                    };
                    twice |= slot.is_some();
                    *slot = value.text;
                }
                Ok(match (seq, prev, digest) {
                    (Some(seq), Some(prev), Some(digest)) if !twice => {
                        LogEntry { seq, prev, digest }
                    }
                    _ => LogEntry::default(),
                })
            }
            // Anything that isn't an object is an entry no walk reaches.
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<LogEntry, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(LogEntry::default())
            }
            fn visit_u64<E>(self, _: u64) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_i64<E>(self, _: i64) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_str<E>(self, _: &str) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_bytes<E>(self, _: &[u8]) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_unit<E>(self) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_none<E>(self) -> std::result::Result<LogEntry, E> {
                Ok(LogEntry::default())
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> std::result::Result<LogEntry, D::Error> {
                d.deserialize_any(V)
            }
        }
        d.deserialize_any(V)
    }
}

/// Whether the manifest `seen` is an ancestor of the head of version `head_seq` whose
/// authenticated predecessor is `head_prev`: following `prev` back through `log` by
/// hashes arrives at `seen.link`. Versions must fall on the way and stay above
/// `seen.version`, so the walk ends; entries that are malformed (see [`LogEntry`]),
/// out of that range or off the chain are simply never reached.
fn descends(head_seq: u64, head_prev: &Link, seen: &Seen, log: &[LogEntry]) -> bool {
    let mut by_link: HashMap<Link, (u64, Link)> = HashMap::with_capacity(log.len());
    for e in log {
        if e.seq <= seen.version || e.seq >= head_seq {
            continue;
        }
        if let (Ok(prev), Ok(digest)) = (parse_link(&e.prev), parse_link(&e.digest)) {
            by_link.insert(link(e.seq, &prev, &digest), (e.seq, prev));
        }
    }
    let (mut want, mut below) = (*head_prev, head_seq);
    loop {
        if want == seen.link {
            return true;
        }
        match by_link.get(&want) {
            Some(&(seq, prev)) if seq < below => (want, below) = (prev, seq),
            _ => return false,
        }
    }
}

/// [`verify`]'s verdict on a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The vault has no manifest and this device never saw one for it.
    None,
    /// The items are exactly what the manifest records, and the manifest is the one
    /// this device remembers or a successor of it: remember `version` and `link`.
    Ok,
    /// The server lists a lower version than this device remembers, or no manifest
    /// after one was seen. Never remember the lower number.
    Rollback,
    /// The manifest doesn't open, the items aren't what it records, or it isn't on the
    /// history this device saw (another manifest with the remembered version, or a
    /// newer one whose predecessors, as far as the log shows them, don't include the
    /// remembered one).
    Mismatch,
    /// Some item came without `data` and without `data_sha256`: nothing was checked.
    /// Fetch the vault in full once; still incomplete then counts as a mismatch.
    Incomplete,
    /// Everything else checks out, but the manifest is more than one version ahead of
    /// the remembered one: fetch the vault's manifest log after the remembered version
    /// and check again with it. Remember nothing yet. (Exactly one version ahead needs
    /// no log: the manifest names the remembered one or it is a mismatch.)
    NeedLog,
}

/// What [`verify`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub status: Status,
    /// The version to remember from now on: the served one for `ok`, otherwise the
    /// remembered one unchanged (0 = none).
    pub version: u64,
    /// The link to remember with `version` (base64url), likewise; `None` = none.
    pub link: Option<String>,
    /// The manifest's counts when it opened (0 otherwise).
    pub live: u64,
    pub trashed: u64,
}

/// Check a vault as one sync answer shows it: its row's manifest (`row`), the vault's
/// complete item set after applying that answer, what this device remembers for the
/// vault (`None`: never saw a manifest for it), and, after a [`Status::NeedLog`], the
/// server's log of the manifests after the remembered version.
///
/// In this order: a lower version than remembered (or none) is a rollback; no manifest
/// and nothing remembered is `none`; a manifest that doesn't open for (this key, vault,
/// epoch, version, `prev`) is a mismatch; so is another manifest at the remembered
/// version, the next version when it names another predecessor (nothing can lie between
/// the two), and a newer one that the log shows not to descend from the remembered one;
/// then the items are counted (`incomplete`, `mismatch`); and last, a manifest two or
/// more versions ahead that doesn't name the remembered one needs the log.
pub fn verify(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    row: Row,
    remembered: Option<&Seen>,
    log: Option<&[LogEntry]>,
    items: &[Entry],
) -> Result<Check> {
    if let Some(r) = remembered {
        r.check()?;
    }
    let verdict = |status, live, trashed| Check {
        status,
        version: remembered.map_or(0, |r| r.version),
        link: remembered.map(|r| b64(&r.link)),
        live,
        trashed,
    };
    if remembered.is_some_and(|r| row.seq < r.version) {
        return Ok(verdict(Status::Rollback, 0, 0));
    }
    if row.seq == 0 {
        return Ok(verdict(Status::None, 0, 0));
    }
    // A version without its text or its predecessor is unusable.
    let (Some(sealed), Some(Ok(prev))) = (row.sealed, row.prev.map(parse_link)) else {
        return Ok(verdict(Status::Mismatch, 0, 0));
    };
    let Ok(manifest) = Manifest::open(vault_key, vault_id, key_epoch, row.seq, &prev, sealed)
    else {
        return Ok(verdict(Status::Mismatch, 0, 0));
    };
    let (live, trashed) = (manifest.summary.live, manifest.summary.trashed);
    let head = link(row.seq, &prev, &sealed_digest(sealed));
    // The chain: `prev` is authenticated by the opening above.
    let mut need_log = false;
    match remembered {
        None => {}
        Some(r) if r.version == row.seq => {
            if r.link != head {
                return Ok(verdict(Status::Mismatch, live, trashed));
            }
        }
        Some(r) if r.link == prev => {}
        // The very next version naming something else: no log entry fits in between,
        // so no log can connect the two.
        Some(r) if row.seq == r.version + 1 => {
            return Ok(verdict(Status::Mismatch, live, trashed));
        }
        Some(r) => match log {
            Some(log) if descends(row.seq, &prev, r, log) => {}
            Some(_) => return Ok(verdict(Status::Mismatch, live, trashed)),
            None => need_log = true,
        },
    }
    let keys = ManifestKeys::derive(vault_key);
    let status = match keys.summarize(items)? {
        None => Status::Incomplete,
        Some(sum) if !sum.matches(&manifest.summary) => Status::Mismatch,
        Some(_) if need_log => Status::NeedLog,
        Some(_) => {
            return Ok(Check {
                status: Status::Ok,
                version: row.seq,
                link: Some(b64(&head)),
                live,
                trashed,
            });
        }
    };
    Ok(verdict(status, live, trashed))
}

/// The check behind "Use the server's copy" (see the module docs): the vault as one sync
/// answer shows it, judged with nothing remembered. What the device may do on its
/// user's confirmation follows from the status alone:
///
/// - `ok`: the head opens and records exactly these items. Replace the device's memory
///   for the vault with `version` and `link` (the head's), whatever it held before.
/// - `none`: the server shows no manifest. Forget the vault's memory (`version` 0, no
///   link); the vault is then one that never had a manifest on this device.
/// - `mismatch` (or `incomplete` after a full fetch): the head is wrong in itself.
///   Nothing may be remembered; someone who can write stores a baseline
///   (`start(…, row.seq + 1, row_link(row), items)`) and remembers what [`start`]
///   returned once the server stored it.
///
/// Never `rollback` or `need_log`: those need a memory. This is [`verify`] without one,
/// under a name of its own so that an acceptance can't be built from a verdict that
/// took the old memory into account.
pub fn accept(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    row: Row,
    items: &[Entry],
) -> Result<Check> {
    verify(vault_key, vault_id, key_epoch, row, None, None, items)
}

/// What a write sends (`seq`, `prev`, `sealed`) and what its writer remembers once the
/// server stored it (`seq` and `link`). All but `seq` in base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Written {
    pub seq: u64,
    pub prev: String,
    pub sealed: String,
    pub link: String,
}

/// A manifest of `version` for exactly `items`, sealed for `key_epoch`, replacing the
/// manifest whose link is `prev`: `None` for a vault's first manifest; for a new
/// baseline and for the one a key replacement carries, [`row_link`] of the vault row's
/// current manifest (for a baseline whatever the server shows, checked or not: the
/// baseline is the user's acceptance of it). Both are exactly one version above the
/// row's, like every other write; the server takes nothing else.
pub fn start(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    version: u64,
    prev: Option<&str>,
    items: &[Entry],
) -> Result<Written> {
    let prev = prev.map(parse_link).transpose()?.unwrap_or(NO_LINK);
    let summary = ManifestKeys::derive(vault_key)
        .summarize(items)?
        .ok_or(Error::Malformed("item without data"))?;
    Manifest::new(version, prev, summary)?.written(vault_key, vault_id, key_epoch)
}

/// The next manifest for a write into a vault whose row lists `row` (checked with
/// [`verify`] first): one version up, naming the row's manifest as its predecessor.
pub fn advance(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    row: Row,
    removed: &[Entry],
    added: &[Entry],
) -> Result<Written> {
    let (Some(sealed), Some(prev)) = (row.sealed, row.prev) else {
        return Err(Error::Malformed("manifest"));
    };
    let prev = parse_link(prev)?;
    let base = Manifest::open(vault_key, vault_id, key_epoch, row.seq, &prev, sealed)?;
    let head = link(row.seq, &prev, &sealed_digest(sealed));
    base.next(head, vault_key, removed, added)?
        .written(vault_key, vault_id, key_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "8c6f2b8e-7a51-4c1e-9d55-2f1f5c2b7a10";

    fn key(n: u8) -> SymmetricKey {
        SymmetricKey::from_bytes([n; 32])
    }

    fn row(id: &str, trashed: bool, data: &str) -> Entry {
        Entry::new(id, trashed, data)
    }

    fn set() -> Vec<Entry> {
        vec![
            row("a", false, "data-a"),
            row("b", false, "data-b"),
            row("c", true, "data-c"),
        ]
    }

    /// The vault row a stored manifest makes.
    fn served(w: &Written) -> Row<'_> {
        Row {
            seq: w.seq,
            prev: Some(&w.prev),
            sealed: Some(&w.sealed),
        }
    }

    fn seen(w: &Written) -> Seen {
        Seen::parse(w.seq, &w.link).unwrap()
    }

    /// What the server's log holds for a stored manifest.
    fn logged(w: &Written) -> LogEntry {
        LogEntry {
            seq: w.seq,
            prev: w.prev.clone(),
            digest: b64(&sealed_digest(&w.sealed)),
        }
    }

    fn status(
        k: &SymmetricKey,
        w: &Written,
        mem: Option<&Seen>,
        log: Option<&[LogEntry]>,
        items: &[Entry],
    ) -> Status {
        verify(k, VAULT, 0, served(w), mem, log, items)
            .unwrap()
            .status
    }

    #[test]
    fn sums_wrap_and_undo() {
        let max = [0xff; 32];
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(add(&max, &one), [0u8; 32]);
        assert_eq!(sub(&[0u8; 32], &one), max);
        let a: [u8; 32] = Sha256::digest(b"a").into();
        let b: [u8; 32] = Sha256::digest(b"b").into();
        assert_eq!(sub(&add(&a, &b), &b), a);
        assert_eq!(add(&a, &b), add(&b, &a));
    }

    #[test]
    fn a_term_binds_id_state_data_and_key() {
        let keys = ManifestKeys::derive(&key(1));
        let h = data_hash("data");
        let t = keys.term("a", false, &h).unwrap();
        assert_ne!(t, keys.term("b", false, &h).unwrap());
        assert_ne!(t, keys.term("a", true, &h).unwrap());
        assert_ne!(t, keys.term("a", false, &data_hash("datb")).unwrap());
        assert_ne!(
            t,
            ManifestKeys::derive(&key(2)).term("a", false, &h).unwrap()
        );
        assert!(keys.term("", false, &h).is_err());
        assert!(keys.term("a\0b", false, &h).is_err());
    }

    #[test]
    fn a_link_binds_version_predecessor_and_text() {
        let (p, d) = ([1u8; 32], [2u8; 32]);
        let l = link(7, &p, &d);
        assert_ne!(l, link(8, &p, &d));
        assert_ne!(l, link(7, &[3; 32], &d));
        assert_ne!(l, link(7, &p, &[3; 32]));
        // Spelled out: SHA-256(info ‖ 0 ‖ version BE ‖ prev ‖ digest).
        let mut bytes = b"passauth/vault-manifest-link/v1\0".to_vec();
        bytes.extend([0, 0, 0, 0, 0, 0, 0, 7]);
        bytes.extend(p);
        bytes.extend(d);
        assert_eq!(l, <[u8; 32]>::from(Sha256::digest(&bytes)));
        // A row's link is that of its text as stored.
        let w = start(&key(1), VAULT, 0, 7, Some(&b64(&p)), &set()).unwrap();
        assert_eq!(w.link, b64(&link(7, &p, &sealed_digest(&w.sealed))));
        assert_eq!(row_link(w.seq, &w.prev, &w.sealed).unwrap(), w.link);
        assert_eq!(w.prev, b64(&p));
        assert!(row_link(0, &w.prev, &w.sealed).is_err());
        assert!(row_link(7, "AAAA", &w.sealed).is_err());
        // A first manifest names nothing.
        let first = start(&key(1), VAULT, 0, 1, None, &set()).unwrap();
        assert_eq!(first.prev, b64(&NO_LINK));
        assert!(start(&key(1), VAULT, 0, 1, Some("not a link"), &set()).is_err());
    }

    #[test]
    fn a_sealed_manifest_opens_only_where_it_belongs() {
        let k = key(1);
        let p = [9u8; 32];
        let w = start(&k, VAULT, 3, 7, Some(&b64(&p)), &set()).unwrap();
        let sealed = w.sealed.as_str();
        let m = Manifest::open(&k, VAULT, 3, 7, &p, sealed).unwrap();
        assert_eq!((m.version, m.summary.live, m.summary.trashed), (7, 2, 1));
        assert_eq!(m.prev, p);
        assert!(
            Manifest::open(&k, VAULT, 3, 8, &p, sealed).is_err(),
            "version"
        );
        assert!(
            Manifest::open(&k, VAULT, 4, 7, &p, sealed).is_err(),
            "epoch"
        );
        assert!(
            Manifest::open(&k, "other", 3, 7, &p, sealed).is_err(),
            "vault"
        );
        assert!(
            Manifest::open(&k, VAULT, 3, 7, &NO_LINK, sealed).is_err(),
            "predecessor"
        );
        assert!(
            Manifest::open(&key(2), VAULT, 3, 7, &p, sealed).is_err(),
            "key"
        );
        assert!(Manifest::open(&k, VAULT, 3, 0, &p, sealed).is_err());
        assert!(start(&k, VAULT, 0, 0, None, &set()).is_err(), "version 0");
        assert!(start(&k, VAULT, 0, MAX_VERSION + 1, None, &set()).is_err());
    }

    #[test]
    fn verify_tells_ok_rollback_and_mismatch() {
        let k = key(1);
        let items = set();
        let before = start(&k, VAULT, 0, 4, None, &items).unwrap();
        let w = advance(&k, VAULT, 0, served(&before), &[], &[]).unwrap();
        let ok = verify(&k, VAULT, 0, served(&w), None, None, &items).unwrap();
        assert_eq!(
            (ok.status, ok.version, ok.live, ok.trashed),
            (Status::Ok, 5, 2, 1)
        );
        assert_eq!(ok.link.as_deref(), Some(w.link.as_str()));
        assert_eq!(status(&k, &w, Some(&seen(&w)), None, &items), Status::Ok);
        assert_eq!(
            status(&k, &w, Some(&seen(&before)), None, &items),
            Status::Ok
        );
        // Order doesn't matter.
        let mut shuffled = items.clone();
        shuffled.reverse();
        assert_eq!(status(&k, &w, None, None, &shuffled), Status::Ok);
        // A lower version than remembered, or none at all after one was seen.
        let later = Seen {
            version: 6,
            link: [7; 32],
        };
        let back = verify(&k, VAULT, 0, served(&w), Some(&later), None, &items).unwrap();
        assert_eq!(
            (back.status, back.version, back.link),
            (Status::Rollback, 6, Some(b64(&[7; 32])))
        );
        let none = Row::default();
        let gone = verify(&k, VAULT, 0, none, Some(&seen(&before)), None, &items).unwrap();
        assert_eq!(gone.status, Status::Rollback);
        let never = verify(&k, VAULT, 0, none, None, None, &items).unwrap();
        assert_eq!(
            (never.status, never.version, never.link),
            (Status::None, 0, None)
        );
        let zero = Row {
            seq: 0,
            ..served(&w)
        };
        assert_eq!(
            verify(&k, VAULT, 0, zero, None, None, &items)
                .unwrap()
                .status,
            Status::None,
            "seq 0 ignores a text"
        );
        // A version without its text, or without (or with another) predecessor.
        for broken in [
            Row {
                sealed: None,
                ..served(&w)
            },
            Row {
                prev: None,
                ..served(&w)
            },
            Row {
                prev: Some("AAAA"),
                ..served(&w)
            },
            Row {
                prev: Some(&b64(&NO_LINK)),
                ..served(&w)
            },
            Row {
                seq: 6,
                ..served(&w)
            },
            Row {
                sealed: Some("AAAA"),
                ..served(&w)
            },
        ] {
            let check = verify(&k, VAULT, 0, broken, None, None, &items).unwrap();
            assert_eq!(check.status, Status::Mismatch, "{broken:?}");
        }
        // Hidden, resurrected, older, trashed/restored behind the manifest's back.
        assert_eq!(status(&k, &w, None, None, &items[..2]), Status::Mismatch);
        let mut more = items.clone();
        more.push(row("d", false, "data-d"));
        assert_eq!(status(&k, &w, None, None, &more), Status::Mismatch);
        let mut older = items.clone();
        older[0] = row("a", false, "data-a-old");
        assert_eq!(status(&k, &w, None, None, &older), Status::Mismatch);
        let mut restored = items.clone();
        restored[2] = row("c", false, "data-c");
        assert_eq!(status(&k, &w, None, None, &restored), Status::Mismatch);
        // Another key.
        assert_eq!(status(&key(2), &w, None, None, &items), Status::Mismatch);
        let mem = seen(&before);
        let mismatch = verify(&k, VAULT, 0, served(&w), Some(&mem), None, &older).unwrap();
        assert_eq!(
            (mismatch.version, mismatch.link.as_deref()),
            (4, Some(before.link.as_str())),
            "nothing new is remembered"
        );
        // The same id twice is refused outright; so is a memory that can't be one.
        let mut twice = items.clone();
        twice.push(row("a", false, "data-a"));
        assert!(verify(&k, VAULT, 0, served(&w), None, None, &twice).is_err());
        let zero = Seen {
            version: 0,
            link: [1; 32],
        };
        assert!(verify(&k, VAULT, 0, served(&w), Some(&zero), None, &items).is_err());
        assert!(Seen::parse(0, &w.link).is_err());
        assert!(Seen::parse(1, "AAAA").is_err());
    }

    /// A history: every manifest written, oldest first.
    struct Branch {
        key: SymmetricKey,
        epoch: u64,
        all: Vec<Written>,
    }

    impl Branch {
        fn begin(k: u8) -> Self {
            let key = key(k);
            let first = start(&key, VAULT, 0, 1, None, &[]).unwrap();
            Self {
                key,
                epoch: 0,
                all: vec![first],
            }
        }
        fn head(&self) -> &Written {
            self.all.last().unwrap()
        }
        /// An ordinary write that changes nothing (the chain is what counts here).
        fn write(&mut self) -> Written {
            let w = advance(&self.key, VAULT, self.epoch, served(self.head()), &[], &[]).unwrap();
            self.all.push(w.clone());
            w
        }
        fn fork(&self, at: usize) -> Self {
            Self {
                key: SymmetricKey::from_bytes(*self.key.as_bytes()),
                epoch: self.epoch,
                all: self.all[..at].to_vec(),
            }
        }
        /// The log the server would return after `after`.
        fn log(&self, after: u64) -> Vec<LogEntry> {
            self.all
                .iter()
                .filter(|w| w.seq > after)
                .map(logged)
                .collect()
        }
        fn check(&self, mem: Option<&Seen>, log: Option<&[LogEntry]>) -> Status {
            verify(
                &self.key,
                VAULT,
                self.epoch,
                served(self.head()),
                mem,
                log,
                &[],
            )
            .unwrap()
            .status
        }
    }

    #[test]
    fn a_newer_manifest_must_descend_from_the_remembered_one() {
        let mut main = Branch::begin(1);
        let v1 = main.head().clone();
        let v2 = main.write();
        let v3 = main.write();
        assert_eq!((v2.seq, v3.seq), (2, 3));
        assert_eq!(v3.prev, v2.link);
        // One step ahead: the head names what the device remembers.
        assert_eq!(main.check(Some(&seen(&v2)), None), Status::Ok);
        // Further ahead: the log is needed, and nothing is remembered meanwhile.
        let behind = seen(&v1);
        let ask = verify(&main.key, VAULT, 0, served(&v3), Some(&behind), None, &[]).unwrap();
        assert_eq!(
            (ask.status, ask.version, ask.link.as_deref()),
            (Status::NeedLog, 1, Some(v1.link.as_str()))
        );
        let log = main.log(1);
        let got = verify(
            &main.key,
            VAULT,
            0,
            served(&v3),
            Some(&behind),
            Some(&log),
            &[],
        )
        .unwrap();
        assert_eq!(
            (got.status, got.version, got.link.as_deref()),
            (Status::Ok, 3, Some(v3.link.as_str()))
        );
        // The log may come in any order, with entries before, at and after the range,
        // and with rubbish in it.
        let mut noisy = main.log(0);
        noisy.reverse();
        noisy.push(LogEntry {
            seq: 2,
            prev: "!".into(),
            digest: "!".into(),
        });
        noisy.push(LogEntry {
            seq: 9,
            prev: v3.link.clone(),
            digest: b64(&[0; 32]),
        });
        assert_eq!(main.check(Some(&behind), Some(&noisy)), Status::Ok);
        // A long way ahead.
        for _ in 0..40 {
            main.write();
        }
        assert_eq!(main.check(Some(&behind), None), Status::NeedLog);
        assert_eq!(main.check(Some(&behind), Some(&main.log(1))), Status::Ok);
        // A log that stops short (pruned, or withheld), or has a hole: not a pass.
        assert_eq!(
            main.check(Some(&behind), Some(&main.log(10))),
            Status::Mismatch
        );
        let mut holed = main.log(1);
        holed.remove(20);
        assert_eq!(main.check(Some(&behind), Some(&holed)), Status::Mismatch);
        assert_eq!(main.check(Some(&behind), Some(&[])), Status::Mismatch);
        // An entry changed on the way breaks every hash above it.
        let mut bent = main.log(1);
        bent[5].digest = b64(&[1; 32]);
        assert_eq!(main.check(Some(&behind), Some(&bent)), Status::Mismatch);
        let mut renumbered = main.log(1);
        renumbered[5].seq += 1;
        assert_eq!(
            main.check(Some(&behind), Some(&renumbered)),
            Status::Mismatch
        );
        // The items are still what decides in the end, and come first.
        let extra = [row("x", false, "data-x")];
        let wrong = verify(
            &main.key,
            VAULT,
            0,
            served(main.head()),
            Some(&behind),
            None,
            &extra,
        );
        assert_eq!(wrong.unwrap().status, Status::Mismatch);
    }

    /// The review's case: the server keeps device A on one history and lets device B
    /// build another from an older state, then shows B's to A.
    #[test]
    fn a_fork_can_not_be_joined() {
        let mut a = Branch::begin(1);
        for _ in 0..4 {
            a.write(); // v2 … v5, seen by both
        }
        let common = seen(a.head());
        let mut b = a.fork(a.all.len());
        let a6 = a.write();
        let b6 = b.write();
        assert_eq!((a6.seq, b6.seq), (6, 6));
        assert_ne!(a6.link, b6.link);
        // Each device on its own history is fine, as is one that saw neither.
        assert_eq!(a.check(Some(&seen(&a6)), None), Status::Ok);
        assert_eq!(b.check(Some(&seen(&b6)), None), Status::Ok);
        assert_eq!(a.check(Some(&common), None), Status::Ok);
        assert_eq!(b.check(Some(&common), None), Status::Ok);
        assert_eq!(b.check(None, None), Status::Ok);
        // Fork at the same version: A is shown B's version 6.
        assert_eq!(b.check(Some(&seen(&a6)), None), Status::Mismatch);
        // Fork joined later: B's history moved on, A is shown its version 7 or 9. One
        // version ahead naming another predecessor is settled without a log.
        b.write();
        assert_eq!(b.check(Some(&seen(&a6)), None), Status::Mismatch);
        assert_eq!(b.check(Some(&seen(&a6)), Some(&b.log(6))), Status::Mismatch);
        assert_eq!(b.check(Some(&seen(&a6)), Some(&a.log(0))), Status::Mismatch);
        b.write();
        b.write();
        assert_eq!(b.check(Some(&seen(&a6)), None), Status::NeedLog);
        for log in [b.log(6), b.log(0), a.log(0), Vec::new()] {
            assert_eq!(b.check(Some(&seen(&a6)), Some(&log)), Status::Mismatch);
        }
        // Entries of A's own history mixed in don't help: nothing links them to B's head.
        let mut mixed = b.log(0);
        mixed.extend(a.log(0));
        assert_eq!(b.check(Some(&seen(&a6)), Some(&mixed)), Status::Mismatch);
        // And B, moved onto A's history, is told the same.
        assert_eq!(a.check(Some(&seen(b.head())), None), Status::Rollback);
        for _ in 0..4 {
            a.write();
        }
        assert_eq!(
            a.check(Some(&seen(b.head())), Some(&a.log(0))),
            Status::Mismatch,
        );
        // A device that only saw the common part follows either.
        assert_eq!(a.check(Some(&common), Some(&a.log(5))), Status::Ok);
        assert_eq!(b.check(Some(&common), Some(&b.log(5))), Status::Ok);
    }

    #[test]
    fn a_key_replacement_and_a_baseline_stay_on_the_chain() {
        let mut v = Branch::begin(1);
        v.write();
        let old = seen(v.head()); // version 2, under the first key
        let old_key = SymmetricKey::from_bytes(*v.key.as_bytes());
        // Key replacement: a new key, the next epoch, a manifest computed afresh that
        // names the old head.
        let (new_key, items) = (key(2), [row("a", false, "re-encrypted")]);
        let prev = row_link(v.head().seq, &v.head().prev, &v.head().sealed).unwrap();
        let rotated = start(&new_key, VAULT, 1, 3, Some(&prev), &items).unwrap();
        assert_eq!(rotated.prev, v.head().link);
        let check = |mem: Option<&Seen>, log: Option<&[LogEntry]>, w: &Written| {
            verify(&new_key, VAULT, 1, served(w), mem, log, &items)
                .unwrap()
                .status
        };
        assert_eq!(check(Some(&old), None, &rotated), Status::Ok);
        assert_eq!(check(None, None, &rotated), Status::Ok);
        // The old key opens nothing of it, whatever it remembers.
        let by_old = verify(
            &old_key,
            VAULT,
            1,
            served(&rotated),
            Some(&old),
            None,
            &items,
        );
        assert_eq!(by_old.unwrap().status, Status::Mismatch);
        // Two writes later a device that last saw the old epoch follows by hashes alone:
        // the log's entries include manifests of both epochs, and it opens only the head.
        let w4 = advance(&new_key, VAULT, 1, served(&rotated), &[], &[]).unwrap();
        let w5 = advance(&new_key, VAULT, 1, served(&w4), &[], &[]).unwrap();
        let first = seen(&v.all[0]);
        let mut log = v.log(1);
        log.extend([logged(&rotated), logged(&w4), logged(&w5)]);
        assert_eq!(check(Some(&first), None, &w5), Status::NeedLog);
        assert_eq!(check(Some(&first), Some(&log), &w5), Status::Ok);
        assert_eq!(check(Some(&old), Some(&log[1..]), &w5), Status::Ok);
        // A rotation that doesn't name the head it replaced is off the chain.
        let loose = start(&new_key, VAULT, 1, 3, None, &items).unwrap();
        assert_eq!(check(Some(&old), None, &loose), Status::Mismatch);
        assert_eq!(check(Some(&old), Some(&[]), &loose), Status::Mismatch);

        // A baseline: the next version like any write, built on whatever the server
        // showed (here a manifest the device couldn't open at all).
        let shown = Written {
            seq: 5,
            prev: w4.link.clone(),
            sealed: "AAAA".into(),
            link: row_link(5, &w4.link, "AAAA").unwrap(),
        };
        let unopened = verify(&new_key, VAULT, 1, served(&shown), None, None, &items);
        assert_eq!(unopened.unwrap().status, Status::Mismatch);
        let base = start(&new_key, VAULT, 1, 6, Some(&shown.link), &items).unwrap();
        assert_eq!(
            check(Some(&seen(&base)), None, &base),
            Status::Ok,
            "its writer"
        );
        assert_eq!(check(None, None, &base), Status::Ok, "a new device");
        // A device that was on the history under the shown head follows through the
        // log; one that saw the real version 5 doesn't (settled at once: the baseline is
        // the very next version), and neither does one further on.
        let mut log = vec![logged(&rotated), logged(&w4), logged(&shown)];
        assert_eq!(check(Some(&old), None, &base), Status::NeedLog);
        assert_eq!(check(Some(&old), Some(&log), &base), Status::Ok);
        assert_eq!(check(Some(&seen(&shown)), None, &base), Status::Ok);
        assert_eq!(check(Some(&seen(&w5)), None, &base), Status::Mismatch);
        log.push(logged(&w5));
        assert_eq!(check(Some(&seen(&w5)), Some(&log), &base), Status::Mismatch);
        let ahead = Seen {
            version: 30,
            link: [3; 32],
        };
        assert_eq!(check(Some(&ahead), None, &base), Status::Rollback);
    }

    /// "Use the server's copy": the vault as served, judged with nothing remembered.
    /// What a device may remember afterwards, and that the chain goes on from there.
    #[test]
    fn accepting_the_servers_copy_replaces_the_memory_with_a_checked_head() {
        let k = key(1);
        let items = set();
        // The server was restored from a backup: its history ends at version 3, the
        // device remembers version 9 of what was lost.
        let v1 = start(&k, VAULT, 0, 1, None, &items).unwrap();
        let v2 = advance(&k, VAULT, 0, served(&v1), &[], &[]).unwrap();
        let v3 = advance(&k, VAULT, 0, served(&v2), &[], &[]).unwrap();
        let lost = Seen {
            version: 9,
            link: [4; 32],
        };
        assert_eq!(status(&k, &v3, Some(&lost), None, &items), Status::Rollback);
        // The served head stands on its own: the device may take it, also though its
        // version is lower than the remembered one.
        let got = accept(&k, VAULT, 0, served(&v3), &items).unwrap();
        assert_eq!(
            (got.status, got.version, got.link.as_deref()),
            (Status::Ok, 3, Some(v3.link.as_str()))
        );
        let mem = Seen::parse(got.version, got.link.as_deref().unwrap()).unwrap();
        assert_eq!(status(&k, &v3, Some(&mem), None, &items), Status::Ok);
        // From there the chain holds as for any memory: the vault's own continuation
        // is followed, also through the versions the lost history had used…
        let mut all = vec![v3.clone()];
        for _ in 4..=12 {
            let w = advance(&k, VAULT, 0, served(all.last().unwrap()), &[], &[]).unwrap();
            all.push(w);
        }
        let log: Vec<LogEntry> = all.iter().map(logged).collect();
        let head = all.last().unwrap();
        assert_eq!(status(&k, head, Some(&mem), None, &items), Status::NeedLog);
        assert_eq!(status(&k, head, Some(&mem), Some(&log), &items), Status::Ok);
        // …while a device that didn't accept still doesn't pass at, or beyond, the
        // version it remembers, and can accept in its turn.
        let at_9 = &all[9 - 3];
        assert_eq!(at_9.seq, 9);
        assert_eq!(
            status(&k, at_9, Some(&lost), None, &items),
            Status::Mismatch
        );
        assert_eq!(
            status(&k, head, Some(&lost), Some(&log), &items),
            Status::Mismatch
        );
        assert_eq!(
            accept(&k, VAULT, 0, served(head), &items).unwrap().status,
            Status::Ok
        );
        // …and another history shown to the accepting device is refused as before.
        let other = advance(&k, VAULT, 0, served(&v2), &[], &[]).unwrap();
        assert_ne!(other.link, v3.link);
        assert_eq!(
            status(&k, &other, Some(&mem), None, &items),
            Status::Mismatch
        );
        let other_4 = advance(&k, VAULT, 0, served(&other), &[], &[]).unwrap();
        assert_eq!(
            status(&k, &other_4, Some(&mem), None, &items),
            Status::Mismatch
        );

        // Nothing to accept when the head is wrong in itself: the items aren't what it
        // records, it doesn't open, or its predecessor was swapped.
        let nothing = (Status::Mismatch, 0, None);
        let wrong = accept(&k, VAULT, 0, served(&v3), &items[..2]).unwrap();
        assert_eq!((wrong.status, wrong.version, wrong.link), nothing);
        let closed = accept(&key(2), VAULT, 0, served(&v3), &items).unwrap();
        assert_eq!((closed.status, closed.version, closed.link), nothing);
        let swapped = Row {
            prev: Some(&v1.link),
            ..served(&v3)
        };
        let moved = accept(&k, VAULT, 0, swapped, &items).unwrap();
        assert_eq!((moved.status, moved.version, moved.link), nothing);
        let bare = [Entry {
            id: "a".into(),
            ..Entry::default()
        }];
        assert_eq!(
            accept(&k, VAULT, 0, served(&v3), &bare).unwrap().status,
            Status::Incomplete
        );
        // A writer then stores a baseline: one version up, naming the served head, over
        // the served items; it remembers that, whatever it held before. Devices on the
        // served history follow it by themselves, the others accept it locally.
        let base = start(
            &k,
            VAULT,
            0,
            v3.seq + 1,
            Some(&row_link(v3.seq, &v3.prev, &v3.sealed).unwrap()),
            &items[..2],
        )
        .unwrap();
        assert_eq!((base.seq, &base.prev), (4, &v3.link));
        assert_eq!(
            status(&k, &base, Some(&seen(&base)), None, &items[..2]),
            Status::Ok
        );
        assert_eq!(
            status(&k, &base, Some(&seen(&v3)), None, &items[..2]),
            Status::Ok
        );
        assert_eq!(
            status(&k, &base, Some(&lost), None, &items[..2]),
            Status::Rollback
        );
        assert_eq!(
            accept(&k, VAULT, 0, served(&base), &items[..2])
                .unwrap()
                .link,
            Some(base.link.clone())
        );

        // No manifest served (a backup from before the vault's first one): the status
        // says so, and there is nothing to remember: the device forgets the vault.
        let gone = accept(&k, VAULT, 0, Row::default(), &items).unwrap();
        assert_eq!(
            (gone.status, gone.version, gone.link),
            (Status::None, 0, None)
        );
    }

    #[test]
    fn a_memory_is_never_the_empty_link() {
        let k = key(1);
        let items = set();
        // The review's case: a first manifest above the remembered version, and a
        // memory holding the link every first manifest names.
        let first = start(&k, VAULT, 0, 5, None, &items).unwrap();
        assert!(Seen::parse(3, &b64(&NO_LINK)).is_err());
        assert!(Seen::parse(3, &first.link).is_ok());
        let zero = Seen {
            version: 3,
            link: NO_LINK,
        };
        assert!(verify(&k, VAULT, 0, served(&first), Some(&zero), None, &items).is_err());
        let next = advance(&k, VAULT, 0, served(&first), &[], &[]).unwrap();
        let log = [logged(&first)];
        assert!(verify(&k, VAULT, 0, served(&next), Some(&zero), Some(&log), &items).is_err());
    }

    #[test]
    fn rubbish_in_a_log_is_skipped_not_fatal() {
        let mut main = Branch::begin(1);
        let v1 = main.head().clone();
        for _ in 0..4 {
            main.write();
        }
        let good = serde_json::to_value(
            main.log(1)
                .iter()
                .map(|e| serde_json::json!({ "seq": e.seq, "prev": e.prev, "digest": e.digest }))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let parse = |v: &serde_json::Value| serde_json::from_value::<Vec<LogEntry>>(v.clone());
        assert_eq!(parse(&good).unwrap(), main.log(1));
        // Every kind of entry a server could slip in, around the real ones.
        let p = &v1.link;
        let rubbish = serde_json::json!([
            null, true, 7, -7, 1.5, "text", [], [1, [2]], {}, { "seq": 3 },
            { "seq": -1, "prev": p, "digest": p },
            { "seq": 0, "prev": p, "digest": p },
            { "seq": 2.5, "prev": p, "digest": p },
            { "seq": "3", "prev": p, "digest": p },
            { "seq": 9_007_199_254_740_992_u64, "prev": p, "digest": p },
            { "seq": 18_446_744_073_709_551_615_u64, "prev": p, "digest": p },
            { "seq": null, "prev": p, "digest": p },
            { "seq": 3, "prev": 4, "digest": p },
            { "seq": 3, "prev": p, "digest": null },
            { "seq": 3, "prev": p, "digest": [p] },
            { "seq": 3, "prev": p },
            { "seq": { "n": 3 }, "prev": p, "digest": p },
        ]);
        let skipped = parse(&rubbish).unwrap();
        assert_eq!(skipped.len(), rubbish.as_array().unwrap().len());
        assert!(skipped.iter().all(|e| *e == LogEntry::default()));
        let mut mixed = rubbish.as_array().unwrap().clone();
        mixed.extend(good.as_array().unwrap().iter().cloned());
        mixed.extend(rubbish.as_array().unwrap().iter().cloned());
        let log = parse(&serde_json::Value::Array(mixed)).unwrap();
        assert_eq!(main.check(Some(&seen(&v1)), Some(&log)), Status::Ok);
        // Rubbish alone connects nothing.
        assert_eq!(
            main.check(Some(&seen(&v1)), Some(&skipped)),
            Status::Mismatch
        );
        // Whole numbers written as floats count (JavaScript), a key given twice doesn't.
        let floats = r#"[{"seq":2.0,"prev":"a","digest":"b","more":{"x":[1]}}]"#;
        assert_eq!(
            serde_json::from_str::<Vec<LogEntry>>(floats).unwrap()[0].seq,
            2
        );
        let twice = r#"[{"seq":2,"seq":3,"prev":"a","digest":"b"}]"#;
        assert_eq!(
            serde_json::from_str::<Vec<LogEntry>>(twice).unwrap(),
            [LogEntry::default()]
        );
        // A log that is no list at all is an error.
        assert!(serde_json::from_str::<Vec<LogEntry>>(r#"{"entries":[]}"#).is_err());
        assert!(serde_json::from_str::<Vec<LogEntry>>("7").is_err());
    }

    /// The re-review's log attacks on a device kept on another branch (all refused),
    /// with the very next version now settled without asking for the log.
    #[test]
    fn log_tricks_do_not_join_a_fork() {
        let k = key(1);
        let base = vec![row("a", false, "a1")];
        let mut chain = vec![start(&k, VAULT, 0, 1, None, &base).unwrap()];
        let mut items = base.clone();
        for i in 2..=3 {
            let add = row(&format!("c{i}"), false, "d");
            let last = chain.last().unwrap();
            let w = advance(&k, VAULT, 0, served(last), &[], std::slice::from_ref(&add)).unwrap();
            items.push(add);
            chain.push(w);
        }
        let fork = |tag: &str, n: usize| {
            let (mut c, mut it) = (vec![chain[2].clone()], items.clone());
            for i in 0..n {
                let add = row(&format!("{tag}{i}"), false, tag);
                let w = advance(
                    &k,
                    VAULT,
                    0,
                    served(c.last().unwrap()),
                    &[],
                    std::slice::from_ref(&add),
                )
                .unwrap();
                it.push(add);
                c.push(w);
            }
            (c, it)
        };
        let (x, _) = fork("x", 3);
        let (y, yi) = fork("y", 5);
        let mem = seen(x.last().unwrap()); // the device: branch X at version 6
        let ylog: Vec<LogEntry> = y.iter().map(logged).collect();
        let xlog: Vec<LogEntry> = x.iter().map(logged).collect();
        let mut mixed = xlog.clone();
        mixed.extend(ylog.clone());
        let mut reversed = mixed.clone();
        reversed.reverse();
        // Y at version 7 (the very next) and at version 8 (the log is asked for).
        let next_one = &y[4];
        assert_eq!(next_one.seq, 7);
        let at_7 = &yi[..yi.len() - 1];
        assert_eq!(
            status(&k, next_one, Some(&mem), None, at_7),
            Status::Mismatch
        );
        let head = y.last().unwrap();
        assert_eq!(head.seq, 8);
        assert_eq!(status(&k, head, Some(&mem), None, &yi), Status::NeedLog);
        let mut relabel = ylog.clone();
        for (i, l) in relabel.iter_mut().enumerate() {
            l.seq = 7 + i as u64;
        }
        // Entries that claim X's manifests as predecessors of Y's.
        let mut graft = ylog.clone();
        graft.push(LogEntry {
            seq: 7,
            prev: x[3].link.clone(),
            digest: b64(&sealed_digest(&y[4].sealed)),
        });
        graft.push(LogEntry {
            seq: 8,
            prev: x[3].link.clone(),
            digest: b64(&sealed_digest(&head.sealed)),
        });
        for log in [&ylog, &mixed, &reversed, &relabel, &graft, &Vec::new()] {
            assert_eq!(
                status(&k, head, Some(&mem), Some(log), &yi),
                Status::Mismatch
            );
            assert_eq!(
                status(&k, next_one, Some(&mem), Some(log), at_7),
                Status::Mismatch
            );
        }
        // The same version on the other branch.
        assert_eq!(
            status(&k, &y[3], Some(&mem), Some(&mixed), &yi[..yi.len() - 2]),
            Status::Mismatch
        );
        // A device at the common version 3 follows Y in any order, with extra entries.
        let common = seen(&chain[2]);
        for log in [&ylog, &mixed, &reversed] {
            assert_eq!(status(&k, head, Some(&common), Some(log), &yi), Status::Ok);
        }
        // Documented: a manifest sealed on X's head for Y's items passes on X's devices
        // (whoever holds the key and works with the server can do that).
        let laundered = start(&k, VAULT, 0, 7, Some(&x[3].link), &yi).unwrap();
        assert_eq!(status(&k, &laundered, Some(&mem), None, &yi), Status::Ok);
    }

    #[test]
    fn rows_without_data_count_by_their_hash() {
        let k = key(1);
        let items = set();
        let w = start(&k, VAULT, 0, 1, None, &items).unwrap();
        let rows: Vec<Entry> = serde_json::from_value(serde_json::json!([
            { "id": "a", "vault_id": VAULT, "data": "data-a", "deleted_at": null, "revision": 4 },
            { "id": "b", "data": "data-b" },
            { "id": "c", "deleted_at": 1700000000, "data_sha256": b64(&data_hash("data-c")) },
        ]))
        .unwrap();
        assert_eq!(status(&k, &w, None, None, &rows), Status::Ok);
        let mut wrong = rows.clone();
        wrong[2].data_sha256 = Some(b64(&data_hash("data-x")));
        assert_eq!(status(&k, &w, None, None, &wrong), Status::Mismatch);
        let mut bare = rows.clone();
        bare[2].data_sha256 = None;
        assert_eq!(status(&k, &w, None, None, &bare), Status::Incomplete);
        bare[2].data_sha256 = Some("AAAA".into());
        assert_eq!(
            status(&k, &w, None, None, &bare),
            Status::Incomplete,
            "not a hash"
        );
        assert!(start(&k, VAULT, 0, 1, None, &bare).is_err());
    }

    /// Review fix: only `deleted_at` says whether a row is in the trash, and only null
    /// or a time above zero are values it may have.
    #[test]
    fn only_deleted_at_decides_the_trash_and_only_as_a_time() {
        let k = key(1);
        let w = start(&k, VAULT, 0, 1, None, &set()).unwrap();
        let rows = |c: serde_json::Value| -> Vec<Entry> {
            let mut c = c;
            c["id"] = "c".into();
            c["data"] = "data-c".into();
            serde_json::from_value(serde_json::json!([
                { "id": "a", "data": "data-a" },
                { "id": "b", "data": "data-b", "deleted_at": null },
                c,
            ]))
            .unwrap()
        };
        let verdict = |c: serde_json::Value| verify(&k, VAULT, 0, served(&w), None, None, &rows(c));
        for trashed in [
            serde_json::json!({ "deleted_at": 1 }),
            serde_json::json!({ "deleted_at": 1700000000 }),
            serde_json::json!({ "deleted_at": 1700000000.0 }),
            // A `trashed` field in a row is not read, whatever it says.
            serde_json::json!({ "deleted_at": 5, "trashed": false }),
        ] {
            assert_eq!(
                verdict(trashed.clone()).unwrap().status,
                Status::Ok,
                "{trashed}"
            );
        }
        for live in [
            serde_json::json!({}),
            serde_json::json!({ "deleted_at": null }),
            serde_json::json!({ "trashed": true }),
        ] {
            assert_eq!(
                verdict(live.clone()).unwrap().status,
                Status::Mismatch,
                "{live}"
            );
        }
        for bad in [
            serde_json::json!({ "deleted_at": 0 }),
            serde_json::json!({ "deleted_at": -1 }),
            serde_json::json!({ "deleted_at": 0.5 }),
            serde_json::json!({ "deleted_at": 1700000000.5 }),
            serde_json::json!({ "deleted_at": 1e300 }),
            serde_json::json!({ "deleted_at": u64::MAX }),
            serde_json::json!({ "deleted_at": "1700000000" }),
            serde_json::json!({ "deleted_at": "" }),
            serde_json::json!({ "deleted_at": true }),
            serde_json::json!({ "deleted_at": false }),
        ] {
            let items = rows(bad.clone());
            assert!(
                matches!(verdict(bad.clone()), Err(Error::Malformed("deleted_at"))),
                "{bad}"
            );
            assert!(start(&k, VAULT, 0, 1, None, &items).is_err(), "{bad}");
            assert!(advance(&k, VAULT, 0, served(&w), &items[2..], &[]).is_err());
            assert!(advance(&k, VAULT, 0, served(&w), &[], &items[2..]).is_err());
        }
        // Nor does a malformed row hide behind one without data.
        let mut mixed = rows(serde_json::json!({ "deleted_at": 0 }));
        mixed[0].data = None;
        assert!(verify(&k, VAULT, 0, served(&w), None, None, &mixed).is_err());
    }

    #[test]
    fn advancing_equals_recomputing() {
        let k = key(1);
        let mut items = set();
        let mut head = start(&k, VAULT, 2, 1, None, &items).unwrap();
        let mut step = |items: &mut Vec<Entry>, removed: Vec<Entry>, added: Vec<Entry>| {
            let w = advance(&k, VAULT, 2, served(&head), &removed, &added).unwrap();
            assert_eq!(w.seq, head.seq + 1);
            assert_eq!(w.prev, head.link, "names the manifest it replaces");
            items.retain(|i| !removed.iter().any(|r| r.id == i.id));
            items.extend(added);
            let mem = seen(&head);
            head = w;
            let check = verify(&k, VAULT, 2, served(&head), Some(&mem), None, items).unwrap();
            assert_eq!(check.status, Status::Ok);
            assert_eq!(check.link.as_deref(), Some(head.link.as_str()));
            let prev = parse_link(&head.prev).unwrap();
            assert_eq!(
                Manifest::open(&k, VAULT, 2, head.seq, &prev, &head.sealed)
                    .unwrap()
                    .summary,
                ManifestKeys::derive(&k).summarize(items).unwrap().unwrap()
            );
        };
        // Create, edit, trash, restore, delete for good, several at once.
        step(&mut items, vec![], vec![row("d", false, "data-d")]);
        step(
            &mut items,
            vec![row("a", false, "data-a")],
            vec![row("a", false, "data-a2")],
        );
        step(
            &mut items,
            vec![row("b", false, "data-b")],
            vec![row("b", true, "data-b")],
        );
        step(
            &mut items,
            vec![row("c", true, "data-c")],
            vec![row("c", false, "data-c")],
        );
        step(&mut items, vec![row("b", true, "data-b")], vec![]);
        step(
            &mut items,
            vec![row("a", false, "data-a2"), row("d", false, "data-d")],
            vec![row("e", false, "data-e"), row("f", true, "data-f")],
        );
        assert_eq!(head.seq, 7);
        // Removing what isn't counted is refused.
        let empty = start(&k, VAULT, 2, 1, None, &[]).unwrap();
        assert!(advance(&k, VAULT, 2, served(&empty), &[row("a", false, "x")], &[]).is_err());
        // The wrong base (another version, another predecessor, none) doesn't open.
        let other = Row {
            seq: head.seq + 1,
            ..served(&head)
        };
        assert!(advance(&k, VAULT, 2, other, &[], &[]).is_err());
        let other = Row {
            prev: Some(&empty.link),
            ..served(&head)
        };
        assert!(advance(&k, VAULT, 2, other, &[], &[]).is_err());
        assert!(advance(&k, VAULT, 2, Row::default(), &[], &[]).is_err());
    }

    #[test]
    fn statuses_have_stable_names() {
        let names: Vec<_> = [
            Status::None,
            Status::Ok,
            Status::Rollback,
            Status::Mismatch,
            Status::Incomplete,
            Status::NeedLog,
        ]
        .iter()
        .map(|s| serde_json::to_value(s).unwrap())
        .collect();
        assert_eq!(
            serde_json::json!(names),
            serde_json::json!([
                "none",
                "ok",
                "rollback",
                "mismatch",
                "incomplete",
                "need_log"
            ])
        );
    }
}
