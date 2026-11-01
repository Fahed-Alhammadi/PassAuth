//! Vault export, shared by every client. Runs on the client only, like import.
//!
//! - `json`: `{"format":"passauth","version":1,"exported_at":…,"items":[Item…]}`; every item kind.
//! - `encrypted`: the same JSON encrypted with a key from the export password
//!   (Argon2id with the account defaults + XChaCha20-Poly1305), as
//!   `{"format":"passauth-encrypted","version":1,"kdf":{…},"data":"<base64url>"}`.
//! - `csv`: logins and secure notes only (columns other managers read).
//!
//! `import::import` reads all three back.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::SymmetricKey;
use crate::item::{Item, ItemType, b64, unb64};
use crate::kdf::KdfParams;
use crate::{Error, Result};

pub const FORMAT: &str = "passauth";
pub const FORMAT_ENCRYPTED: &str = "passauth-encrypted";
const AAD: &[u8] = b"passauth/export/v1";
/// Export passwords are typed by people and guessed offline if the file leaks.
pub const MIN_PASSWORD_LEN: usize = 10;

#[derive(Serialize, Deserialize)]
pub(crate) struct Plain {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub exported_at: i64,
    pub items: Vec<Item>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Encrypted {
    pub format: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub data: String,
}

/// Unix seconds. Not available in the browser (wasm32): use the `*_at` variants there.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Plaintext PassAuth JSON (pretty-printed).
pub fn json(items: &[Item]) -> Result<String> {
    json_at(items, now())
}

/// [`json`] with the export time given by the caller (unix seconds).
pub fn json_at(items: &[Item], exported_at: i64) -> Result<String> {
    let doc = Plain {
        format: FORMAT.into(),
        version: 1,
        exported_at,
        items: items.to_vec(),
    };
    Ok(serde_json::to_string_pretty(&doc)?)
}

fn export_key(password: &str, kdf: &KdfParams) -> Result<SymmetricKey> {
    kdf.validate()?;
    let salt = unb64(&kdf.salt)?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::Kdf)?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    let key = SymmetricKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// Password-protected PassAuth JSON.
pub fn encrypted(items: &[Item], password: &str) -> Result<String> {
    encrypted_at(items, password, now())
}

/// [`encrypted`] with the export time given by the caller (unix seconds).
pub fn encrypted_at(items: &[Item], password: &str, exported_at: i64) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::Import(format!(
            "use an export password of at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    let kdf = KdfParams::new_default()?;
    let key = export_key(password, &kdf)?;
    let mut plain = json_at(items, exported_at)?.into_bytes();
    let data = key.encrypt(&plain, AAD);
    plain.zeroize();
    let doc = Encrypted {
        format: FORMAT_ENCRYPTED.into(),
        version: 1,
        kdf,
        data: b64(&data?),
    };
    Ok(serde_json::to_string_pretty(&doc)?)
}

/// Decrypt a [`encrypted`] export back to its plaintext JSON document.
pub(crate) fn decrypt(doc: &Encrypted, password: &str) -> Result<Plain> {
    if doc.version != 1 {
        return Err(Error::UnsupportedVersion(doc.version as u8));
    }
    let key = export_key(password, &doc.kdf)?;
    let mut plain = key.decrypt(&unb64(&doc.data)?, AAD)?;
    let parsed = serde_json::from_slice(&plain);
    plain.zeroize();
    Ok(parsed?)
}

/// CSV with the widely understood column names. Cards, identities and SSH keys
/// don't fit these columns and are left out; use JSON to export everything.
pub fn csv(items: &[Item]) -> Result<String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    let io = |e: csv::Error| Error::Import(e.to_string());
    w.write_record([
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ])
    .map_err(io)?;
    for i in items {
        let kind = match i.item_type() {
            ItemType::Login => "login",
            ItemType::Note => "note",
            _ => continue,
        };
        let login = i.login.as_ref();
        let uris = login
            .map(|l| {
                l.urls
                    .iter()
                    .map(|u| u.url.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        w.write_record([
            i.folder.as_deref().unwrap_or(""),
            if i.favorite { "1" } else { "" },
            kind,
            &i.name,
            &i.notes,
            &uris,
            login.map_or("", |l| l.username.as_str()),
            login.map_or("", |l| l.password.as_str()),
            login.and_then(|l| l.totp.as_deref()).unwrap_or(""),
        ])
        .map_err(io)?;
    }
    let bytes = w.into_inner().map_err(|e| Error::Import(e.to_string()))?;
    String::from_utf8(bytes).map_err(|_| Error::Import("CSV is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Card, Login, LoginUrl, UrlMatch};

    fn items() -> Vec<Item> {
        vec![
            Item {
                name: "GitHub".into(),
                folder: Some("Work".into()),
                favorite: true,
                login: Some(Login {
                    username: "octo".into(),
                    password: "p, \"quoted\"".into(),
                    urls: vec![LoginUrl {
                        url: "https://github.com".into(),
                        match_type: UrlMatch::Default,
                    }],
                    totp: Some("JBSWY3DPEHPK3PXP".into()),
                    passkeys: vec![],
                }),
                ..Default::default()
            },
            Item {
                name: "Wi-Fi".into(),
                notes: "line 1\nline 2".into(),
                ..Default::default()
            },
            Item {
                name: "Visa".into(),
                card: Some(Card {
                    number: "4111111111111111".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn json_roundtrips_through_import() {
        let out = json(&items()).unwrap();
        let r = crate::import::import(out.as_bytes(), None).unwrap();
        assert_eq!(r.format, crate::import::Format::PassAuthJson);
        assert_eq!(r.items.len(), 3);
        assert_eq!(r.items[0].login.as_ref().unwrap().password, "p, \"quoted\"");
        assert_eq!(r.items[2].card.as_ref().unwrap().number, "4111111111111111");
    }

    #[test]
    fn encrypted_needs_the_password() {
        let out = encrypted(&items(), "correct horse battery").unwrap();
        assert!(!out.contains("octo"));
        assert!(matches!(
            crate::import::import(out.as_bytes(), None),
            Err(Error::PasswordRequired)
        ));
        assert!(matches!(
            crate::import::import(out.as_bytes(), Some("wrong password!!")),
            Err(Error::Decrypt)
        ));
        let r = crate::import::import(out.as_bytes(), Some("correct horse battery")).unwrap();
        assert_eq!(r.items.len(), 3);
        assert!(encrypted(&items(), "short").is_err());
    }

    #[test]
    fn csv_has_logins_and_notes_and_reimports() {
        let out = csv(&items()).unwrap();
        assert!(out.starts_with(
            "folder,favorite,type,name,notes,login_uri,login_username,login_password,login_totp"
        ));
        assert!(!out.contains("4111"));
        let r = crate::import::import(out.as_bytes(), None).unwrap();
        assert_eq!(r.items.len(), 2);
        let gh = r.items.iter().find(|i| i.name == "GitHub").unwrap();
        assert_eq!(gh.login.as_ref().unwrap().password, "p, \"quoted\"");
        assert_eq!(gh.folder.as_deref(), Some("Work"));
    }
}
