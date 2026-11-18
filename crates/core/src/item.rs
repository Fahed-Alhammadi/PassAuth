//! Vault item model and per-item encryption.
//!
//! The whole [`Item`] (name, URLs, secrets, passkeys…) is serialized and
//! encrypted as one blob under its own Item Key, which is wrapped by the
//! Vault Key. Only [`EncryptedItem`] is ever sent to the server.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::SymmetricKey;
use crate::{Error, Result};

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::Malformed("base64"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
}

/// Current item format. Items are upgraded on decrypt and stamped on encrypt.
/// - 0/1: before PassAuth 0.2.1. "domain" was the default URL match.
/// - 2: URL match "default" follows the client setting; "domain" is an explicit choice.
pub const ITEM_FORMAT: u32 = 2;

/// Unknown JSON fields of an item (see the `extra` field of each item struct).
pub type Extra = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Item {
    /// Schema version of the decrypted data (see [`ITEM_FORMAT`]).
    pub format: u32,
    pub name: String,
    pub notes: String,
    pub favorite: bool,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub login: Option<Login>,
    pub card: Option<Card>,
    pub identity: Option<Identity>,
    pub ssh_key: Option<SshKey>,
    pub fields: Vec<Field>,
    pub password_history: Vec<PasswordHistory>,
    /// Unix seconds.
    pub created_at: i64,
    pub updated_at: i64,
    /// Edit counter, inside the encrypted data (so the server can't change it): 1 for a
    /// new item, one more with every re-encryption by the core ([`EncryptedItem::encrypt`]
    /// writes `rev + 1` of the item it is given, [`EncryptedItem::update`] one more than
    /// the higher of the stored and the given item's). 0 = written before it existed.
    /// Apps remember the highest per item and flag a lower one ([`item_rev_check`]): a
    /// server serving an older copy of the item. Apps from before keep it unchanged
    /// through an edit (as an unknown field), which is never flagged.
    ///
    /// Never above [`MAX_ITEM_REV`]: a stored number beyond it (anyone with the vault
    /// key can write one) reads as [`MAX_ITEM_REV`] and the next write stays there, so
    /// no value of the counter makes an item impossible to open or to save again.
    #[serde(deserialize_with = "rev_in")]
    pub rev: u64,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The highest edit counter an item is read with: 2^53 − 2, so the counter a write
/// stores (one more) is still a whole number every binding carries exactly.
pub const MAX_ITEM_REV: u64 = 9_007_199_254_740_990;

/// An item's stored `rev`, whatever number it is: at most [`MAX_ITEM_REV`], and 0 for
/// what can't be a count (a negative number, NaN). A fraction counts by its whole part.
fn rev_in<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
    struct V;
    impl serde::de::Visitor<'_> for V {
        type Value = u64;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a number")
        }
        fn visit_u64<E>(self, n: u64) -> std::result::Result<u64, E> {
            Ok(n.min(MAX_ITEM_REV))
        }
        fn visit_i64<E>(self, n: i64) -> std::result::Result<u64, E> {
            Ok(u64::try_from(n).unwrap_or(0).min(MAX_ITEM_REV))
        }
        fn visit_f64<E>(self, n: f64) -> std::result::Result<u64, E> {
            // `as` saturates and takes NaN to 0.
            Ok((n as u64).min(MAX_ITEM_REV))
        }
    }
    d.deserialize_any(V)
}

/// [`item_rev_check`]'s verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevCheck {
    /// Nothing remembered for the item (a new device or a new item): remember `served`.
    New,
    /// The remembered edit counter (equal: also when the content differs, an edit by an
    /// app from before that keeps the counter).
    Same,
    /// Newer than remembered: remember `served`.
    Newer,
    /// Lower than remembered: the server sent an older version of the item. Keep the
    /// newer copy if the app has one, show the item with a warning, never remember the
    /// lower number.
    Rollback,
}

/// Compare an item's edit counter (`Item::rev` of what the server sent now) with the
/// highest this device remembers for it.
pub fn item_rev_check(remembered: Option<u64>, served: u64) -> RevCheck {
    match remembered {
        None => RevCheck::New,
        Some(r) if served > r => RevCheck::Newer,
        Some(r) if served == r => RevCheck::Same,
        Some(_) => RevCheck::Rollback,
    }
}

impl Item {
    /// Bring older item data up to [`ITEM_FORMAT`].
    fn upgrade(&mut self) {
        if self.format < 2 {
            // Before format 2 every website was saved as "domain" because that was the default.
            for u in self.login.iter_mut().flat_map(|l| l.urls.iter_mut()) {
                if u.match_type == UrlMatch::Domain {
                    u.match_type = UrlMatch::Default;
                }
            }
        }
        // Never stamp a newer client's format down: its extra fields are kept as they are.
        self.format = self.format.max(ITEM_FORMAT);
    }

    pub fn item_type(&self) -> ItemType {
        if self.login.is_some() {
            ItemType::Login
        } else if self.card.is_some() {
            ItemType::Card
        } else if self.identity.is_some() {
            ItemType::Identity
        } else if self.ssh_key.is_some() {
            ItemType::SshKey
        } else {
            ItemType::Note
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    pub username: String,
    pub password: String,
    pub urls: Vec<LoginUrl>,
    /// `otpauth://` URI or bare base32 secret.
    pub totp: Option<String>,
    pub passkeys: Vec<Passkey>,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMatch {
    /// Use the client's "default match detection" setting.
    #[default]
    Default,
    /// Same registrable domain (example.com matches login.example.com).
    Domain,
    Host,
    StartsWith,
    Exact,
    /// `url` is a case-insensitive regular expression tested against the page URL.
    Regex,
    Never,
}

impl UrlMatch {
    /// The name items store ("default", "domain", "host", "starts_with", "exact", "regex",
    /// "never").
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Domain => "domain",
            Self::Host => "host",
            Self::StartsWith => "starts_with",
            Self::Exact => "exact",
            Self::Regex => "regex",
            Self::Never => "never",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginUrl {
    pub url: String,
    #[serde(rename = "match")]
    pub match_type: UrlMatch,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

/// A WebAuthn credential stored by PassAuth acting as an authenticator.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Passkey {
    /// base64url credential ID.
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    /// base64url user handle.
    pub user_handle: String,
    pub user_name: String,
    pub user_display_name: String,
    /// COSE algorithm (-7 = ES256).
    pub algorithm: i32,
    /// base64url PKCS#8 private key.
    pub private_key: String,
    pub counter: u32,
    pub discoverable: bool,
    pub created_at: i64,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Card {
    pub cardholder_name: String,
    pub brand: String,
    pub number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub code: String,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub title: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub company: String,
    pub email: String,
    pub phone: String,
    pub address1: String,
    pub address2: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
    pub username: String,
    pub ssn: String,
    pub passport_number: String,
    pub license_number: String,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshKey {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    #[default]
    Text,
    Hidden,
    Boolean,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Field {
    pub name: String,
    pub value: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordHistory {
    pub password: String,
    pub changed_at: i64,
    /// Fields from newer clients, kept so they survive an edit by an older one.
    #[serde(flatten)]
    pub extra: Extra,
}

/// What the server stores for an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    pub id: String,
    pub vault_id: String,
    /// Item Key wrapped by the Vault Key.
    pub key: String,
    /// Encrypted [`Item`] JSON.
    pub data: String,
}

fn item_key_aad(vault_id: &str, item_id: &str) -> Vec<u8> {
    format!("passauth/item-key/v1/{vault_id}/{item_id}").into_bytes()
}

fn item_data_aad(vault_id: &str, item_id: &str) -> Vec<u8> {
    format!("passauth/item/v1/{vault_id}/{item_id}").into_bytes()
}

impl EncryptedItem {
    /// Encrypt with a new Item Key: a new item (its `rev` 0 → 1), or an item moved to
    /// another vault or re-encrypted after a key replacement (the decrypted item, so
    /// `rev` + 1). Always `item.rev + 1`.
    pub fn encrypt(
        item: &Item,
        id: &str,
        vault_id: &str,
        vault_key: &SymmetricKey,
    ) -> Result<Self> {
        let item_key = SymmetricKey::generate()?;
        Self::encrypt_with_key(item, item.rev, id, vault_id, vault_key, &item_key)
    }

    /// Writes `rev` + 1 as the item's edit counter (never above [`MAX_ITEM_REV`] + 1).
    fn encrypt_with_key(
        item: &Item,
        rev: u64,
        id: &str,
        vault_id: &str,
        vault_key: &SymmetricKey,
        item_key: &SymmetricKey,
    ) -> Result<Self> {
        let mut item = item.clone();
        item.upgrade();
        item.rev = rev.min(MAX_ITEM_REV) + 1;
        let mut json = serde_json::to_vec(&item)?;
        let data = item_key.encrypt(&json, &item_data_aad(vault_id, id));
        json.zeroize();
        Ok(Self {
            id: id.to_owned(),
            vault_id: vault_id.to_owned(),
            key: b64(&vault_key.wrap(item_key, &item_key_aad(vault_id, id))?),
            data: b64(&data?),
        })
    }

    pub fn decrypt(&self, vault_key: &SymmetricKey) -> Result<Item> {
        let item_key = self.item_key(vault_key)?;
        self.decrypt_with_key(&item_key)
    }

    fn decrypt_with_key(&self, item_key: &SymmetricKey) -> Result<Item> {
        let mut json = item_key.decrypt(
            &unb64(&self.data)?,
            &item_data_aad(&self.vault_id, &self.id),
        )?;
        let item = serde_json::from_slice::<Item>(&json);
        json.zeroize();
        let mut item = item?;
        item.upgrade();
        Ok(item)
    }

    /// Re-encrypt after an edit, keeping the same Item Key. The edit counter becomes one
    /// more than the higher of the stored item's (`self`, decrypted here, so apps needn't
    /// carry it) and `item`'s: restoring an earlier version (whose `rev` is lower) counts
    /// up from the current one.
    pub fn update(&self, item: &Item, vault_key: &SymmetricKey) -> Result<Self> {
        let item_key = self.item_key(vault_key)?;
        let stored = self.decrypt_with_key(&item_key)?;
        Self::encrypt_with_key(
            item,
            stored.rev.max(item.rev),
            &self.id,
            &self.vault_id,
            vault_key,
            &item_key,
        )
    }

    /// Move to another vault. Re-encrypts with a fresh Item Key, since both the
    /// key and the data AAD name the vault (edit counter + 1).
    pub fn move_to(
        &self,
        vault_key: &SymmetricKey,
        new_vault_id: &str,
        new_vault_key: &SymmetricKey,
    ) -> Result<Self> {
        let item = self.decrypt(vault_key)?;
        Self::encrypt(&item, &self.id, new_vault_id, new_vault_key)
    }

    fn item_key(&self, vault_key: &SymmetricKey) -> Result<SymmetricKey> {
        vault_key.unwrap_key(&unb64(&self.key)?, &item_key_aad(&self.vault_id, &self.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Item {
        Item {
            format: ITEM_FORMAT,
            name: "GitHub".into(),
            login: Some(Login {
                extra: Default::default(),
                username: "octo".into(),
                password: "s3cret".into(),
                urls: vec![LoginUrl {
                    url: "https://github.com".into(),
                    ..Default::default()
                }],
                totp: Some("JBSWY3DPEHPK3PXP".into()),
                passkeys: vec![],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn item_roundtrip() {
        let vk = SymmetricKey::generate().unwrap();
        let enc = EncryptedItem::encrypt(&sample(), "i1", "v1", &vk).unwrap();
        assert!(!enc.data.contains("GitHub"));
        let back = enc.decrypt(&vk).unwrap();
        assert_eq!(back.rev, 1, "a new item starts at 1");
        assert_eq!(Item { rev: 0, ..back }, sample());
        assert_eq!(sample().item_type(), ItemType::Login);
    }

    #[test]
    fn rev_counts_every_reencryption() {
        let vk = SymmetricKey::generate().unwrap();
        let vk2 = SymmetricKey::generate().unwrap();
        let enc = EncryptedItem::encrypt(&sample(), "i1", "v1", &vk).unwrap();
        let first = enc.decrypt(&vk).unwrap();
        assert_eq!(first.rev, 1);
        // An edit: one more than the stored item's, whatever the app passed.
        let mut edited = first.clone();
        edited.name = "GitHub work".into();
        let upd = enc.update(&edited, &vk).unwrap();
        assert_eq!(upd.decrypt(&vk).unwrap().rev, 2);
        // An app that dropped the counter (rev 0) still counts up from the stored one.
        let stale = Item {
            rev: 0,
            ..edited.clone()
        };
        let upd2 = upd.update(&stale, &vk).unwrap();
        assert_eq!(upd2.decrypt(&vk).unwrap().rev, 3);
        // Restoring an earlier version (a lower rev) counts up from the current one.
        let restored = upd2.update(&first, &vk).unwrap().decrypt(&vk).unwrap();
        assert_eq!((restored.rev, restored.name.as_str()), (4, "GitHub"));
        // A move (fresh key, other vault) counts too, and so does re-encrypting the
        // decrypted item with `encrypt` (moves and key replacements in the apps).
        let moved = upd2.move_to(&vk, "v2", &vk2).unwrap();
        assert_eq!(moved.decrypt(&vk2).unwrap().rev, 4);
        let rekeyed =
            EncryptedItem::encrypt(&moved.decrypt(&vk2).unwrap(), "i1", "v2", &vk).unwrap();
        assert_eq!(rekeyed.decrypt(&vk).unwrap().rev, 5);
        // The counter is inside the authenticated data: the server can't change it.
        let json = serde_json::to_value(rekeyed.decrypt(&vk).unwrap()).unwrap();
        assert_eq!(json["rev"], 5);
        assert!(!rekeyed.data.contains("rev"));
    }

    /// Review fix: no value of the counter makes an item impossible to open, edit, move
    /// or re-encrypt.
    #[test]
    fn no_rev_jams_an_item() {
        let (vk, vk2) = (
            SymmetricKey::generate().unwrap(),
            SymmetricKey::generate().unwrap(),
        );
        // What someone with the vault key could store: the item's JSON with any `rev`.
        let stored = |rev: &str| {
            let item_key = SymmetricKey::generate().unwrap();
            let json = serde_json::to_string(&sample())
                .unwrap()
                .replace("\"rev\":0", &format!("\"rev\":{rev}"));
            assert!(json.contains(&format!("\"rev\":{rev}")));
            EncryptedItem {
                id: "i".into(),
                vault_id: "v".into(),
                key: b64(&vk.wrap(&item_key, &item_key_aad("v", "i")).unwrap()),
                data: b64(&item_key
                    .encrypt(json.as_bytes(), &item_data_aad("v", "i"))
                    .unwrap()),
            }
        };
        for (rev, reads_as) in [
            ("18446744073709551615", MAX_ITEM_REV),
            ("18446744073709551616", MAX_ITEM_REV),
            ("1e300", MAX_ITEM_REV),
            ("9007199254740993", MAX_ITEM_REV),
            ("9007199254740991", MAX_ITEM_REV),
            ("9007199254740990", MAX_ITEM_REV),
            ("9007199254740989", MAX_ITEM_REV - 1),
            ("7", 7),
            ("7.9", 7),
            ("-3", 0),
            ("-1e300", 0),
        ] {
            let enc = stored(rev);
            let item = enc.decrypt(&vk).unwrap();
            assert_eq!(item.rev, reads_as, "{rev}");
            assert_eq!(item.name, sample().name);
            let top = (reads_as + 1).min(MAX_ITEM_REV);
            let edited = enc.update(&item, &vk).unwrap().decrypt(&vk).unwrap();
            assert_eq!(edited.rev, top, "{rev}: update");
            let moved = enc.move_to(&vk, "v2", &vk2).unwrap();
            assert_eq!(moved.decrypt(&vk2).unwrap().rev, top, "{rev}: move");
            let again = EncryptedItem::encrypt(&item, "i", "v", &vk).unwrap();
            assert_eq!(again.decrypt(&vk).unwrap().rev, top, "{rev}: encrypt");
            // An app's own copy of the item with the number as it was stored.
            let given = Item {
                rev: u64::MAX,
                ..item
            };
            let saved = enc.update(&given, &vk).unwrap().decrypt(&vk).unwrap();
            assert_eq!(saved.rev, MAX_ITEM_REV, "{rev}: given");
        }
        // At the top the counter stays where it is; the check reads that as unchanged.
        let top = stored("9007199254740991");
        assert_eq!(
            item_rev_check(Some(MAX_ITEM_REV), top.decrypt(&vk).unwrap().rev),
            RevCheck::Same
        );
        // What the core writes at the top is a number JavaScript carries exactly.
        let maxed = Item {
            rev: u64::MAX,
            ..sample()
        };
        let enc = EncryptedItem::encrypt(&maxed, "i", "v", &vk).unwrap();
        let item_key = enc.item_key(&vk).unwrap();
        let json = item_key
            .decrypt(&unb64(&enc.data).unwrap(), &item_data_aad("v", "i"))
            .unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(raw["rev"], 9_007_199_254_740_991_u64);
        // A `rev` that is no number at all is as malformed as any other field.
        assert!(stored("\"x\"").decrypt(&vk).is_err());
    }

    /// An app from before the counter keeps it as an unknown field through an edit (equal
    /// rev, other content: never flagged), and items written before it read as 0.
    #[test]
    fn rev_survives_an_edit_by_an_app_from_before() {
        #[derive(Serialize, Deserialize)]
        struct OldItem {
            name: String,
            #[serde(flatten)]
            extra: Extra,
        }
        let vk = SymmetricKey::generate().unwrap();
        let enc = EncryptedItem::encrypt(&sample(), "i1", "v1", &vk).unwrap();
        let enc = enc.update(&enc.decrypt(&vk).unwrap(), &vk).unwrap();
        // What an older core does: decrypt into its own model, edit, encrypt the JSON.
        let item_key = enc.item_key(&vk).unwrap();
        let plain = item_key
            .decrypt(&unb64(&enc.data).unwrap(), &item_data_aad("v1", "i1"))
            .unwrap();
        let mut old: OldItem = serde_json::from_slice(&plain).unwrap();
        old.name = "Edited by an older app".into();
        let data = item_key
            .encrypt(
                &serde_json::to_vec(&old).unwrap(),
                &item_data_aad("v1", "i1"),
            )
            .unwrap();
        let by_old = EncryptedItem {
            data: b64(&data),
            ..enc.clone()
        };
        let back = by_old.decrypt(&vk).unwrap();
        assert_eq!(
            (back.rev, back.name.as_str()),
            (2, "Edited by an older app")
        );
        assert_eq!(item_rev_check(Some(2), back.rev), RevCheck::Same);
        // The next edit by a current app counts on from there.
        assert_eq!(
            by_old.update(&back, &vk).unwrap().decrypt(&vk).unwrap().rev,
            3
        );
        // Items from before the counter read as 0 and count from there.
        let mut legacy = serde_json::to_value(sample()).unwrap();
        legacy.as_object_mut().unwrap().remove("rev");
        let item: Item = serde_json::from_value(legacy).unwrap();
        assert_eq!(item.rev, 0);
    }

    #[test]
    fn rev_check_flags_only_a_lower_counter() {
        assert_eq!(item_rev_check(None, 0), RevCheck::New);
        assert_eq!(item_rev_check(None, 7), RevCheck::New);
        assert_eq!(item_rev_check(Some(3), 4), RevCheck::Newer);
        assert_eq!(item_rev_check(Some(3), 3), RevCheck::Same);
        assert_eq!(item_rev_check(Some(3), 2), RevCheck::Rollback);
        assert_eq!(item_rev_check(Some(1), 0), RevCheck::Rollback);
        assert_eq!(item_rev_check(Some(0), 0), RevCheck::Same);
        assert_eq!(
            serde_json::to_value(RevCheck::Rollback).unwrap(),
            serde_json::json!("rollback")
        );
    }

    #[test]
    fn swapped_ids_fail() {
        let vk = SymmetricKey::generate().unwrap();
        let mut enc = EncryptedItem::encrypt(&sample(), "i1", "v1", &vk).unwrap();
        enc.id = "i2".into();
        assert!(enc.decrypt(&vk).is_err());
    }

    #[test]
    fn update_keeps_key_and_move_rekeys() {
        let vk = SymmetricKey::generate().unwrap();
        let vk2 = SymmetricKey::generate().unwrap();
        let enc = EncryptedItem::encrypt(&sample(), "i1", "v1", &vk).unwrap();
        let mut edited = sample();
        edited.name = "GitHub work".into();
        let upd = enc.update(&edited, &vk).unwrap();
        assert_eq!(upd.decrypt(&vk).unwrap().name, "GitHub work");
        let moved = upd.move_to(&vk, "v2", &vk2).unwrap();
        assert_eq!(moved.decrypt(&vk2).unwrap().name, "GitHub work");
        assert!(moved.decrypt(&vk).is_err());
    }

    /// An item written by a newer client keeps its unknown fields and format
    /// when an older client decrypts, edits and re-encrypts it.
    #[test]
    fn newer_fields_and_format_survive_an_edit() {
        let vk = SymmetricKey::generate().unwrap();
        let newer = serde_json::json!({
            "format": ITEM_FORMAT + 1,
            "name": "GitHub",
            "future_top": { "a": 1 },
            "login": {
                "username": "octo",
                "password": "s3cret",
                "future_login": [1, 2, 3],
                "urls": [{ "url": "https://github.com", "match": "host", "future_url": true }],
                "passkeys": [{ "credential_id": "c", "future_passkey": "x" }]
            },
            "fields": [{ "name": "n", "value": "v", "type": "text", "future_field": 7 }],
            "password_history": [{ "password": "old", "changed_at": 1, "future_ph": null }]
        });
        let item: Item = serde_json::from_value(newer.clone()).unwrap();
        let enc = EncryptedItem::encrypt(&item, "i1", "v1", &vk).unwrap();
        let mut edited = enc.decrypt(&vk).unwrap();
        assert_eq!(edited.format, ITEM_FORMAT + 1, "format is never downgraded");
        edited.name = "GitHub (work)".into();
        let back = enc.update(&edited, &vk).unwrap().decrypt(&vk).unwrap();
        let json = serde_json::to_value(&back).unwrap();
        assert_eq!(json["format"], ITEM_FORMAT + 1);
        assert_eq!(json["name"], "GitHub (work)");
        assert_eq!(json["future_top"], newer["future_top"]);
        assert_eq!(
            json["login"]["future_login"],
            newer["login"]["future_login"]
        );
        assert_eq!(json["login"]["urls"][0]["future_url"], true);
        assert_eq!(json["login"]["urls"][0]["match"], "host");
        assert_eq!(json["login"]["passkeys"][0]["future_passkey"], "x");
        assert_eq!(json["fields"][0]["future_field"], 7);
        assert!(
            json["password_history"][0]
                .as_object()
                .unwrap()
                .contains_key("future_ph")
        );
        // Known fields are not duplicated into `extra`.
        assert!(back.extra.get("name").is_none());
    }

    #[test]
    fn legacy_domain_match_becomes_default() {
        let key = SymmetricKey::generate().unwrap();
        let mut legacy = sample();
        legacy.login.as_mut().unwrap().urls[0].match_type = UrlMatch::Domain;
        legacy.login.as_mut().unwrap().urls.push(LoginUrl {
            extra: Default::default(),
            url: "https://x.io".into(),
            match_type: UrlMatch::Exact,
        });
        // Write the legacy JSON (no "format" field) directly, as 0.1 did.
        let mut json = serde_json::to_value(&legacy).unwrap();
        json.as_object_mut().unwrap().remove("format");
        let item_key = SymmetricKey::generate().unwrap();
        let enc = EncryptedItem {
            id: "i".into(),
            vault_id: "v".into(),
            key: b64(&key.wrap(&item_key, &item_key_aad("v", "i")).unwrap()),
            data: b64(&item_key
                .encrypt(
                    &serde_json::to_vec(&json).unwrap(),
                    &item_data_aad("v", "i"),
                )
                .unwrap()),
        };
        let item = enc.decrypt(&key).unwrap();
        let urls = &item.login.as_ref().unwrap().urls;
        assert_eq!(item.format, ITEM_FORMAT);
        assert_eq!(urls[0].match_type, UrlMatch::Default);
        assert_eq!(urls[1].match_type, UrlMatch::Exact);

        // From format 2 on, an explicit "domain" choice is kept.
        let mut chosen = item.clone();
        chosen.login.as_mut().unwrap().urls[0].match_type = UrlMatch::Domain;
        let again = enc.update(&chosen, &key).unwrap().decrypt(&key).unwrap();
        assert_eq!(again.login.unwrap().urls[0].match_type, UrlMatch::Domain);
    }
}
