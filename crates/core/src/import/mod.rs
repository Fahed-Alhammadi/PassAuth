//! Import vault exports from other password managers. Runs on the client
//! only; plaintext exports never reach the server. Format details:
//! `docs/IMPORT_FORMATS.md`.

mod bitwarden;
mod csv_generic;
mod keepass;
mod onepassword;

use serde::Serialize;

use crate::item::{Item, Login, LoginUrl};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// PassAuth's own export (plain or password-protected), see `crate::export`.
    PassAuthJson,
    BitwardenJson,
    BitwardenCsv,
    OnePassword1pux,
    OnePasswordCsv,
    PassboltCsv,
    Kdbx,
    LastpassCsv,
    ChromeCsv,
    GenericCsv,
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub format: Format,
    pub items: Vec<Item>,
    /// Non-fatal notes for the user (skipped entries, unsupported data).
    pub warnings: Vec<String>,
}

/// Detect the export format and parse it. `password` unlocks
/// password-protected Bitwarden exports and KDBX files.
pub fn import(data: &[u8], password: Option<&str>) -> Result<ImportResult> {
    let mut result = if data.starts_with(b"PK\x03\x04") {
        onepassword::parse_1pux(data)?
    } else if data.starts_with(&[0x03, 0xd9, 0xa2, 0x9a]) {
        keepass::parse(data, password)?
    } else {
        let text = std::str::from_utf8(data)
            .map_err(|_| err("file is not UTF-8 text, a .1pux archive or a KeePass database"))?
            .trim_start_matches('\u{feff}');
        if text.trim_start().starts_with('{') {
            match passauth_export(text, password)? {
                Some(r) => r,
                None => bitwarden::parse_json(text, password)?,
            }
        } else {
            csv_generic::parse(text)?
        }
    };
    result.items.retain(|i| !is_empty(i));
    if result.items.is_empty() {
        result.warnings.push("no items found in this file".into());
    }
    Ok(result)
}

/// PassAuth's own export formats; `None` when the JSON is something else.
fn passauth_export(text: &str, password: Option<&str>) -> Result<Option<ImportResult>> {
    use crate::export::{Encrypted, FORMAT, FORMAT_ENCRYPTED, Plain, decrypt};
    let v: serde_json::Value = serde_json::from_str(text)?;
    let plain = match v.get("format").and_then(|f| f.as_str()) {
        Some(FORMAT) => serde_json::from_value::<Plain>(v)?,
        Some(FORMAT_ENCRYPTED) => {
            let password = password.ok_or(Error::PasswordRequired)?;
            decrypt(&serde_json::from_value::<Encrypted>(v)?, password)?
        }
        _ => return Ok(None),
    };
    Ok(Some(ImportResult {
        format: Format::PassAuthJson,
        items: plain.items,
        warnings: vec![],
    }))
}

pub(crate) fn err(msg: impl Into<String>) -> Error {
    Error::Import(msg.into())
}

fn is_empty(i: &Item) -> bool {
    i.name.is_empty()
        && i.notes.is_empty()
        && i.login
            .as_ref()
            .is_none_or(|l| l.username.is_empty() && l.password.is_empty() && l.urls.is_empty())
        && i.card.is_none()
        && i.identity.is_none()
        && i.ssh_key.is_none()
        && i.fields.is_empty()
}

/// Build a login item from the common columns every format has.
pub(crate) fn login_item(
    name: &str,
    username: &str,
    password: &str,
    urls: Vec<String>,
    totp: Option<String>,
    notes: &str,
) -> Item {
    let urls: Vec<LoginUrl> = urls
        .into_iter()
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty())
        .map(|url| LoginUrl {
            url,
            ..Default::default()
        })
        .collect();
    let name = if name.trim().is_empty() {
        urls.first()
            .map(|u| host_of(&u.url))
            .unwrap_or_else(|| "Untitled".into())
    } else {
        name.trim().to_owned()
    };
    Item {
        name,
        notes: notes.to_owned(),
        login: Some(Login {
            username: username.to_owned(),
            password: password.to_owned(),
            urls,
            totp: totp.filter(|t| !t.trim().is_empty()),
            passkeys: vec![],
        }),
        ..Default::default()
    }
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_owned()
}

/// `otpauth://` URI from KeePass-style separate TOTP settings.
pub(crate) fn totp_uri(
    secret: &str,
    algorithm: Option<&str>,
    digits: Option<&str>,
    period: Option<&str>,
) -> String {
    let mut uri = format!("otpauth://totp/PassAuth?secret={}", secret.replace(' ', ""));
    if let Some(a) = algorithm {
        let a = a.to_ascii_uppercase().replace("HMAC-", "").replace('-', "");
        uri.push_str(&format!("&algorithm={a}"));
    }
    if let Some(d) = digits {
        uri.push_str(&format!("&digits={d}"));
    }
    if let Some(p) = period {
        uri.push_str(&format!("&period={p}"));
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_binary_garbage() {
        assert!(import(&[0xff, 0xfe, 0x00, 0x01], None).is_err());
    }

    #[test]
    fn untitled_name_from_url() {
        let i = login_item(
            "",
            "u",
            "p",
            vec!["https://login.example.com/a".into()],
            None,
            "",
        );
        assert_eq!(i.name, "login.example.com");
    }
}
