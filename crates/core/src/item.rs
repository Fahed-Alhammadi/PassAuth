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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Item {
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
}

impl Item {
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMatch {
    /// Same registrable domain (example.com matches login.example.com).
    #[default]
    Domain,
    Host,
    StartsWith,
    Exact,
    Never,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginUrl {
    pub url: String,
    #[serde(rename = "match")]
    pub match_type: UrlMatch,
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
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshKey {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
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
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordHistory {
    pub password: String,
    pub changed_at: i64,
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
    pub fn encrypt(
        item: &Item,
        id: &str,
        vault_id: &str,
        vault_key: &SymmetricKey,
    ) -> Result<Self> {
        let item_key = SymmetricKey::generate()?;
        Self::encrypt_with_key(item, id, vault_id, vault_key, &item_key)
    }

    fn encrypt_with_key(
        item: &Item,
        id: &str,
        vault_id: &str,
        vault_key: &SymmetricKey,
        item_key: &SymmetricKey,
    ) -> Result<Self> {
        let mut json = serde_json::to_vec(item)?;
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
        let mut json = item_key.decrypt(
            &unb64(&self.data)?,
            &item_data_aad(&self.vault_id, &self.id),
        )?;
        let item = serde_json::from_slice(&json);
        json.zeroize();
        Ok(item?)
    }

    /// Re-encrypt after an edit, keeping the same Item Key.
    pub fn update(&self, item: &Item, vault_key: &SymmetricKey) -> Result<Self> {
        let item_key = self.item_key(vault_key)?;
        Self::encrypt_with_key(item, &self.id, &self.vault_id, vault_key, &item_key)
    }

    /// Move to another vault. Re-encrypts with a fresh Item Key, since both the
    /// key and the data AAD name the vault.
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
            name: "GitHub".into(),
            login: Some(Login {
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
        assert_eq!(enc.decrypt(&vk).unwrap(), sample());
        assert_eq!(sample().item_type(), ItemType::Login);
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
}
