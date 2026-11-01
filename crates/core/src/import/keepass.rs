//! KeePass KDBX databases (Passbolt's KDBX export, KeePassXC, KeePass 2).

use std::io::Cursor;

use keepass::{Database, DatabaseKey};

use super::{Format, ImportResult, err, login_item, totp_uri};
use crate::item::{Field, FieldType};
use crate::{Error, Result};

const STANDARD: &[&str] = &["Title", "UserName", "Password", "URL", "Notes", "otp"];

pub fn parse(data: &[u8], password: Option<&str>) -> Result<ImportResult> {
    let password = password.ok_or(Error::PasswordRequired)?;
    let db = Database::open(
        &mut Cursor::new(data),
        DatabaseKey::new().with_password(password),
    )
    .map_err(|e| {
        err(format!(
            "could not open KeePass database (wrong password or key file required?): {e}"
        ))
    })?;

    let mut items = Vec::new();
    for entry in db.iter_all_entries() {
        let get = |k: &str| entry.get(k).unwrap_or("").to_owned();
        let mut urls = vec![get("URL")];
        let mut extra: Vec<(&String, String)> = entry
            .fields
            .iter()
            .filter(|(k, _)| k.starts_with("KP2A_URL"))
            .map(|(k, v)| (k, v.get().to_string()))
            .collect();
        extra.sort();
        urls.extend(extra.into_iter().map(|(_, v)| v));

        let totp = entry
            .get("otp")
            .map(str::to_owned)
            .or_else(|| {
                entry.get("TimeOtp-Secret-Base32").map(|secret| {
                    totp_uri(
                        secret,
                        entry.get("TimeOtp-Algorithm"),
                        entry.get("TimeOtp-Length"),
                        entry.get("TimeOtp-Period"),
                    )
                })
            })
            .or_else(|| {
                entry
                    .get("TOTP Seed")
                    .map(|seed| totp_uri(seed, None, None, None))
            });

        let mut item = login_item(
            &get("Title"),
            &get("UserName"),
            &get("Password"),
            urls,
            totp,
            &get("Notes"),
        );
        item.folder = group_path(&entry);
        let mut fields: Vec<Field> = entry
            .fields
            .iter()
            .filter(|(k, _)| {
                !STANDARD.contains(&k.as_str())
                    && !k.starts_with("KP2A_URL")
                    && !k.starts_with("TimeOtp-")
                    && !k.starts_with("TOTP ")
            })
            .map(|(k, v)| Field {
                name: k.clone(),
                value: v.get().to_string(),
                field_type: if matches!(v, keepass::db::Value::Protected(_)) {
                    FieldType::Hidden
                } else {
                    FieldType::Text
                },
            })
            .collect();
        fields.sort_by(|a, b| a.name.cmp(&b.name));
        item.fields = fields;
        items.push(item);
    }
    Ok(ImportResult {
        format: Format::Kdbx,
        items,
        warnings: vec![],
    })
}

/// `Parent/Child` path of the entry's group, excluding the database root.
fn group_path(entry: &keepass::db::EntryRef<'_>) -> Option<String> {
    fn walk(g: &keepass::db::GroupRef<'_>, names: &mut Vec<String>) {
        if let Some(parent) = g.parent() {
            walk(&parent, names);
            names.push(g.name.clone());
        }
    }
    let mut names = Vec::new();
    walk(&entry.parent(), &mut names);
    (!names.is_empty()).then(|| names.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::Value;

    #[test]
    fn kdbx_roundtrip() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut group = root.add_group();
            group.name = "Work".into();
            let mut e = group.add_entry();
            e.set("Title", Value::Unprotected(String::from("Mail")));
            e.set("UserName", Value::Unprotected(String::from("me")));
            e.set("Password", Value::protected("pw"));
            e.set(
                "URL",
                Value::Unprotected(String::from("https://mail.example")),
            );
            e.set(
                "KP2A_URL_1",
                Value::Unprotected(String::from("https://alt.example")),
            );
            e.set(
                "TimeOtp-Secret-Base32",
                Value::Unprotected(String::from("JBSWY3DPEHPK3PXP")),
            );
            e.set("TimeOtp-Period", Value::Unprotected(String::from("30")));
            e.set("PIN", Value::protected("1234"));
        }
        let mut out = Vec::new();
        db.save(&mut out, DatabaseKey::new().with_password("kp"))
            .unwrap();

        assert!(matches!(parse(&out, None), Err(Error::PasswordRequired)));
        assert!(parse(&out, Some("wrong")).is_err());
        let r = super::super::import(&out, Some("kp")).unwrap();
        assert_eq!(r.format, Format::Kdbx);
        let item = &r.items[0];
        assert_eq!(item.folder.as_deref(), Some("Work"));
        let l = item.login.as_ref().unwrap();
        assert_eq!(
            (l.username.as_str(), l.password.as_str(), l.urls.len()),
            ("me", "pw", 2)
        );
        let totp = crate::totp::Totp::parse(l.totp.as_deref().unwrap()).unwrap();
        assert_eq!(totp.period, 30);
        assert_eq!(item.fields[0].name, "PIN");
        assert_eq!(item.fields[0].field_type, FieldType::Hidden);
    }
}
