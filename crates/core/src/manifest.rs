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
//! A manifest is sealed (XChaCha20-Poly1305, the usual ciphertext layout, base64url) with
//! the associated data `passauth/vault-manifest/v1/<vault id>/<key epoch>/<version>`, so
//! the server can't pass off another vault's, epoch's or version's manifest. Replacing
//! the vault key replaces both keys: the rotation carries a manifest computed afresh.
//!
//! The server stores the sealed text and its version (`manifest_seq`) and replaces them
//! only together with the write they describe. Apps check every sync ([`verify`]) and
//! remember the highest version they saw per vault; see `docs/ARCHITECTURE.md`.

use std::collections::HashSet;

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

/// The highest manifest version (and item count): whole numbers every binding carries
/// exactly (JavaScript's 2^53 − 1).
pub const MAX_VERSION: u64 = 9_007_199_254_740_991;

/// One item as a manifest counts it. Deserializes from a `/sync` item row as it is
/// (unknown fields are ignored): `id`, `deleted_at` (not null = in the trash; an
/// explicit `trashed` wins), and `data` or, for a row sent without it
/// (`trash=summary`), the server's `data_sha256`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Entry {
    pub id: String,
    #[serde(default)]
    pub trashed: Option<bool>,
    #[serde(default)]
    pub deleted_at: Option<i64>,
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
            trashed: Some(trashed),
            data: Some(data.to_owned()),
            ..Self::default()
        }
    }

    fn is_trashed(&self) -> bool {
        self.trashed.unwrap_or(self.deleted_at.is_some())
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

    fn entry_term(&self, e: &Entry) -> Result<[u8; 32]> {
        let hash = e.hash().ok_or(Error::Malformed("item without data"))?;
        self.term(&e.id, e.is_trashed(), &hash)
    }

    /// Counts and sum of a vault's complete item set. `Ok(None)` when an entry has
    /// neither `data` nor `data_sha256` (nothing can be said about the vault then); an
    /// item id listed twice is an error.
    pub fn summarize(&self, items: &[Entry]) -> Result<Option<Summary>> {
        let mut seen = HashSet::with_capacity(items.len());
        let mut sum = Summary::default();
        for e in items {
            if !seen.insert(e.id.as_str()) {
                return Err(Error::Malformed("item listed twice"));
            }
            if e.hash().is_none() {
                return Ok(None);
            }
            sum.add(e.is_trashed(), &self.entry_term(e)?)?;
        }
        Ok(Some(sum))
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

fn aad(vault_id: &str, key_epoch: u64, version: u64) -> Vec<u8> {
    format!("{AAD_PREFIX}/{vault_id}/{key_epoch}/{version}").into_bytes()
}

fn check_version(version: u64) -> Result<()> {
    if version == 0 || version > MAX_VERSION {
        return Err(Error::Malformed("manifest version"));
    }
    Ok(())
}

impl Manifest {
    pub fn new(version: u64, summary: Summary) -> Result<Self> {
        check_version(version)?;
        Ok(Self { version, summary })
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
        Ok(b64(&keys
            .seal
            .encrypt(&json, &aad(vault_id, key_epoch, self.version))?))
    }

    /// Open the sealed text the server lists for `vault_id` with `key_epoch` and
    /// `version` (its `manifest_seq`): any other vault, epoch or version fails.
    pub fn open(
        vault_key: &SymmetricKey,
        vault_id: &str,
        key_epoch: u64,
        version: u64,
        sealed: &str,
    ) -> Result<Self> {
        check_version(version)?;
        let keys = ManifestKeys::derive(vault_key);
        let json = keys
            .seal
            .decrypt(&unb64(sealed)?, &aad(vault_id, key_epoch, version))?;
        let wire: Wire = serde_json::from_slice(&json)?;
        let acc: [u8; 32] = unb64(&wire.acc)?
            .try_into()
            .map_err(|_| Error::Malformed("manifest sum"))?;
        if wire.version != version {
            return Err(Error::Malformed("manifest version"));
        }
        Ok(Self {
            version,
            summary: Summary {
                live: wire.live,
                trashed: wire.trashed,
                acc,
            },
        })
    }

    /// The manifest after a write: `removed` are the items as they were before it (an
    /// edited, trashed, restored, deleted or moved-out item's earlier state), `added` as
    /// they are after it (a new, edited, trashed, restored or moved-in item). One version
    /// up. Fails when it would take a count below zero or an entry has no data or hash.
    pub fn next(
        &self,
        vault_key: &SymmetricKey,
        removed: &[Entry],
        added: &[Entry],
    ) -> Result<Self> {
        let keys = ManifestKeys::derive(vault_key);
        let mut summary = self.summary.clone();
        for e in removed {
            summary.remove(e.is_trashed(), &keys.entry_term(e)?)?;
        }
        for e in added {
            summary.add(e.is_trashed(), &keys.entry_term(e)?)?;
        }
        Self::new(self.version + 1, summary)
    }
}

/// [`verify`]'s verdict on a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The vault has no manifest and this device never saw one for it.
    None,
    /// The items are exactly what the manifest records: remember `version`.
    Ok,
    /// The server lists a lower version than this device remembers, or no manifest
    /// after one was seen. Never remember the lower number.
    Rollback,
    /// The manifest doesn't open, or the items aren't what it records.
    Mismatch,
    /// Some item came without `data` and without `data_sha256`: nothing was checked.
    /// Fetch the vault in full once; still incomplete then counts as a mismatch.
    Incomplete,
}

/// What [`verify`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub status: Status,
    /// The version to remember from now on (`ok` only; the higher of the remembered
    /// and the served one otherwise unchanged), 0 = none.
    pub version: u64,
    /// The manifest's counts when it opened (0 otherwise).
    pub live: u64,
    pub trashed: u64,
}

/// Check a vault as one sync answer shows it: its row's `manifest_seq` and `manifest`
/// (`None`/0 = none), the vault's complete item set after applying that answer, and
/// the highest manifest version this device remembers for the vault (`None`: never
/// saw one).
pub fn verify(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    manifest_seq: u64,
    sealed: Option<&str>,
    remembered: Option<u64>,
    items: &[Entry],
) -> Result<Check> {
    let remembered = remembered.unwrap_or(0);
    let verdict = |status, live, trashed| Check {
        status,
        version: if status == Status::Ok {
            manifest_seq.max(remembered)
        } else {
            remembered
        },
        live,
        trashed,
    };
    let sealed = sealed.filter(|_| manifest_seq > 0);
    if manifest_seq < remembered {
        return Ok(verdict(Status::Rollback, 0, 0));
    }
    let Some(sealed) = sealed else {
        // Version 0 with nothing remembered; a version without its text is unusable.
        let status = if manifest_seq == 0 {
            Status::None
        } else {
            Status::Mismatch
        };
        return Ok(verdict(status, 0, 0));
    };
    let Ok(manifest) = Manifest::open(vault_key, vault_id, key_epoch, manifest_seq, sealed) else {
        return Ok(verdict(Status::Mismatch, 0, 0));
    };
    let (live, trashed) = (manifest.summary.live, manifest.summary.trashed);
    let keys = ManifestKeys::derive(vault_key);
    let status = match keys.summarize(items)? {
        None => Status::Incomplete,
        Some(sum) if sum.matches(&manifest.summary) => Status::Ok,
        Some(_) => Status::Mismatch,
    };
    Ok(verdict(status, live, trashed))
}

/// A manifest of `version` for exactly `items` (a vault's first manifest, a new
/// baseline, or the one a key replacement carries), sealed for `key_epoch`.
pub fn start(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    version: u64,
    items: &[Entry],
) -> Result<String> {
    let summary = ManifestKeys::derive(vault_key)
        .summarize(items)?
        .ok_or(Error::Malformed("item without data"))?;
    Manifest::new(version, summary)?.seal(vault_key, vault_id, key_epoch)
}

/// The next manifest for a write into a vault whose row lists `manifest_seq` and
/// `sealed` (checked with [`verify`] first): `(seq, sealed)` to send with the write.
pub fn advance(
    vault_key: &SymmetricKey,
    vault_id: &str,
    key_epoch: u64,
    manifest_seq: u64,
    sealed: &str,
    removed: &[Entry],
    added: &[Entry],
) -> Result<(u64, String)> {
    let next = Manifest::open(vault_key, vault_id, key_epoch, manifest_seq, sealed)?
        .next(vault_key, removed, added)?;
    Ok((next.version, next.seal(vault_key, vault_id, key_epoch)?))
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

    fn status(
        k: &SymmetricKey,
        seq: u64,
        sealed: Option<&str>,
        mem: Option<u64>,
        items: &[Entry],
    ) -> Status {
        verify(k, VAULT, 0, seq, sealed, mem, items).unwrap().status
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
    fn a_sealed_manifest_opens_only_where_it_belongs() {
        let k = key(1);
        let sealed = start(&k, VAULT, 3, 7, &set()).unwrap();
        let m = Manifest::open(&k, VAULT, 3, 7, &sealed).unwrap();
        assert_eq!((m.version, m.summary.live, m.summary.trashed), (7, 2, 1));
        assert!(Manifest::open(&k, VAULT, 3, 8, &sealed).is_err(), "version");
        assert!(Manifest::open(&k, VAULT, 4, 7, &sealed).is_err(), "epoch");
        assert!(Manifest::open(&k, "other", 3, 7, &sealed).is_err(), "vault");
        assert!(
            Manifest::open(&key(2), VAULT, 3, 7, &sealed).is_err(),
            "key"
        );
        assert!(Manifest::open(&k, VAULT, 3, 0, &sealed).is_err());
        assert!(start(&k, VAULT, 0, 0, &set()).is_err(), "version 0");
        assert!(start(&k, VAULT, 0, MAX_VERSION + 1, &set()).is_err());
    }

    #[test]
    fn verify_tells_ok_rollback_and_mismatch() {
        let k = key(1);
        let items = set();
        let sealed = start(&k, VAULT, 0, 5, &items).unwrap();
        let s = Some(sealed.as_str());
        let ok = verify(&k, VAULT, 0, 5, s, None, &items).unwrap();
        assert_eq!(
            (ok.status, ok.version, ok.live, ok.trashed),
            (Status::Ok, 5, 2, 1)
        );
        assert_eq!(status(&k, 5, s, Some(5), &items), Status::Ok);
        assert_eq!(status(&k, 5, s, Some(4), &items), Status::Ok);
        // Order doesn't matter.
        let mut shuffled = items.clone();
        shuffled.reverse();
        assert_eq!(status(&k, 5, s, None, &shuffled), Status::Ok);
        // A lower version than remembered, or none at all after one was seen.
        let back = verify(&k, VAULT, 0, 5, s, Some(6), &items).unwrap();
        assert_eq!((back.status, back.version), (Status::Rollback, 6));
        assert_eq!(status(&k, 0, None, Some(1), &items), Status::Rollback);
        assert_eq!(status(&k, 0, None, None, &items), Status::None);
        assert_eq!(
            status(&k, 0, s, None, &items),
            Status::None,
            "seq 0 ignores a text"
        );
        assert_eq!(status(&k, 5, None, None, &items), Status::Mismatch);
        // Hidden, resurrected, older, trashed/restored behind the manifest's back.
        assert_eq!(status(&k, 5, s, None, &items[..2]), Status::Mismatch);
        let mut more = items.clone();
        more.push(row("d", false, "data-d"));
        assert_eq!(status(&k, 5, s, None, &more), Status::Mismatch);
        let mut older = items.clone();
        older[0] = row("a", false, "data-a-old");
        assert_eq!(status(&k, 5, s, None, &older), Status::Mismatch);
        let mut restored = items.clone();
        restored[2] = row("c", false, "data-c");
        assert_eq!(status(&k, 5, s, None, &restored), Status::Mismatch);
        // Another version's manifest relabelled, another key, garbage.
        assert_eq!(status(&k, 6, s, None, &items), Status::Mismatch);
        assert_eq!(status(&key(2), 5, s, None, &items), Status::Mismatch);
        assert_eq!(status(&k, 5, Some("AAAA"), None, &items), Status::Mismatch);
        let mismatch = verify(&k, VAULT, 0, 5, s, Some(3), &older).unwrap();
        assert_eq!(mismatch.version, 3, "nothing new is remembered");
        // The same id twice is refused outright.
        let mut twice = items.clone();
        twice.push(row("a", false, "data-a"));
        assert!(verify(&k, VAULT, 0, 5, s, None, &twice).is_err());
    }

    #[test]
    fn rows_without_data_count_by_their_hash() {
        let k = key(1);
        let items = set();
        let sealed = start(&k, VAULT, 0, 1, &items).unwrap();
        let s = Some(sealed.as_str());
        let rows: Vec<Entry> = serde_json::from_value(serde_json::json!([
            { "id": "a", "vault_id": VAULT, "data": "data-a", "deleted_at": null, "revision": 4 },
            { "id": "b", "data": "data-b" },
            { "id": "c", "deleted_at": 1700000000, "data_sha256": b64(&data_hash("data-c")) },
        ]))
        .unwrap();
        assert_eq!(status(&k, 1, s, None, &rows), Status::Ok);
        let mut wrong = rows.clone();
        wrong[2].data_sha256 = Some(b64(&data_hash("data-x")));
        assert_eq!(status(&k, 1, s, None, &wrong), Status::Mismatch);
        let mut bare = rows.clone();
        bare[2].data_sha256 = None;
        assert_eq!(status(&k, 1, s, None, &bare), Status::Incomplete);
        bare[2].data_sha256 = Some("AAAA".into());
        assert_eq!(
            status(&k, 1, s, None, &bare),
            Status::Incomplete,
            "not a hash"
        );
        assert!(start(&k, VAULT, 0, 1, &bare).is_err());
        // `trashed` wins over `deleted_at`.
        let mut explicit = rows.clone();
        explicit[2].trashed = Some(false);
        assert_eq!(status(&k, 1, s, None, &explicit), Status::Mismatch);
    }

    #[test]
    fn advancing_equals_recomputing() {
        let k = key(1);
        let mut items = set();
        let mut seq = 1;
        let mut sealed = start(&k, VAULT, 2, seq, &items).unwrap();
        let mut step = |items: &mut Vec<Entry>, removed: Vec<Entry>, added: Vec<Entry>| {
            let (n, s) = advance(&k, VAULT, 2, seq, &sealed, &removed, &added).unwrap();
            assert_eq!(n, seq + 1);
            items.retain(|i| !removed.iter().any(|r| r.id == i.id));
            items.extend(added);
            (seq, sealed) = (n, s);
            let check = verify(&k, VAULT, 2, seq, Some(&sealed), Some(seq - 1), items).unwrap();
            assert_eq!(check.status, Status::Ok);
            assert_eq!(
                Manifest::open(&k, VAULT, 2, seq, &sealed).unwrap().summary,
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
        assert_eq!(seq, 7);
        // Removing what isn't counted is refused.
        let empty = start(&k, VAULT, 2, 1, &[]).unwrap();
        assert!(advance(&k, VAULT, 2, 1, &empty, &[row("a", false, "x")], &[]).is_err());
        // The wrong base (another version) doesn't open.
        assert!(advance(&k, VAULT, 2, seq + 1, &sealed, &[], &[]).is_err());
    }

    #[test]
    fn statuses_have_stable_names() {
        let names: Vec<_> = [
            Status::None,
            Status::Ok,
            Status::Rollback,
            Status::Mismatch,
            Status::Incomplete,
        ]
        .iter()
        .map(|s| serde_json::to_value(s).unwrap())
        .collect();
        assert_eq!(
            serde_json::json!(names),
            serde_json::json!(["none", "ok", "rollback", "mismatch", "incomplete"])
        );
    }
}
