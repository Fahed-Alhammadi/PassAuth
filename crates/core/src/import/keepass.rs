//! KeePass KDBX databases (Passbolt's KDBX export, KeePassXC, KeePass 2).

use std::io::Cursor;

use keepass::{Database, DatabaseKey};

use super::{Format, ImportResult, err, login_item, totp_uri};
use crate::item::{Field, FieldType};
use crate::{Error, Result};

const STANDARD: &[&str] = &["Title", "UserName", "Password", "URL", "Notes", "otp"];

/// Upper bounds for the key-derivation settings a KDBX file may ask for. A
/// hostile file could otherwise make the import allocate gigabytes or spin
/// for hours before the password is even checked.
const MAX_ARGON2_MEMORY: u64 = 1 << 30;
const MAX_ARGON2_ITERATIONS: u64 = 1_000;
const MAX_ARGON2_PARALLELISM: u64 = 64;
const MAX_AES_ROUNDS: u64 = 1_000_000_000;

pub fn parse(data: &[u8], password: Option<&str>) -> Result<ImportResult> {
    let password = password.ok_or(Error::PasswordRequired)?;
    check_kdf_bounds(data)?;
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
                extra: Default::default(),
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

/// Read the KDF settings from the unencrypted KDBX header and reject values
/// outside sane bounds. Unknown or unparsable headers are left to the parser.
fn check_kdf_bounds(data: &[u8]) -> Result<()> {
    let too_costly = || {
        err("this KeePass file asks for key-derivation settings that are too costly to open here")
    };
    let le = |b: &[u8]| {
        b.iter()
            .rev()
            .fold(0u64, |acc, x| (acc << 8) | u64::from(*x))
    };
    if data.len() < 12 || data[..4] != [0x03, 0xd9, 0xa2, 0x9a] {
        return Ok(());
    }
    let major = le(&data[10..12]);
    let mut pos = 12;
    loop {
        let Some(&id) = data.get(pos) else {
            return Ok(());
        };
        let (len, start) = if major >= 4 {
            (data.get(pos + 1..pos + 5).map(le), pos + 5)
        } else {
            (data.get(pos + 1..pos + 3).map(le), pos + 3)
        };
        let Some(len) = len.and_then(|l| usize::try_from(l).ok()) else {
            return Ok(());
        };
        let Some(value) = data.get(start..start.saturating_add(len)) else {
            return Ok(());
        };
        match id {
            0 => return Ok(()),
            // KDBX 3: AES-KDF transform rounds.
            6 if major < 4 && le(value) > MAX_AES_ROUNDS => return Err(too_costly()),
            // KDBX 4: KDF parameters (a VariantDictionary).
            11 if major >= 4 => {
                for (key, v) in variant_dictionary(value) {
                    let n = le(v);
                    let over = match key {
                        b"M" => n > MAX_ARGON2_MEMORY,
                        b"I" => n > MAX_ARGON2_ITERATIONS,
                        b"P" => n > MAX_ARGON2_PARALLELISM,
                        b"R" => n > MAX_AES_ROUNDS,
                        _ => false,
                    };
                    if over {
                        return Err(too_costly());
                    }
                }
            }
            _ => {}
        }
        pos = start + len;
    }
}

/// `(key, value)` pairs of a KDBX 4 VariantDictionary (values as raw bytes).
fn variant_dictionary(mut b: &[u8]) -> Vec<(&[u8], &[u8])> {
    let mut out = Vec::new();
    if b.len() < 2 {
        return out;
    }
    b = &b[2..];
    let read = |b: &[u8], at: usize| -> Option<usize> {
        let n = b.get(at..at + 4)?;
        usize::try_from(u32::from_le_bytes(n.try_into().ok()?)).ok()
    };
    while let Some(&kind) = b.first() {
        if kind == 0 {
            break;
        }
        let Some(klen) = read(b, 1) else { break };
        let Some(key) = b.get(5..5 + klen) else { break };
        let Some(vlen) = read(b, 5 + klen) else { break };
        let vstart = 9 + klen;
        let Some(value) = b.get(vstart..vstart + vlen) else {
            break;
        };
        out.push((key, value));
        b = &b[vstart + vlen..];
    }
    out
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

    #[test]
    fn rejects_costly_kdf_settings() {
        // KDBX 4 header whose Argon2 memory ("M") asks for 64 GiB.
        let mut dict = vec![0x00, 0x01];
        dict.push(0x05);
        dict.extend(1u32.to_le_bytes());
        dict.extend(b"M");
        dict.extend(8u32.to_le_bytes());
        dict.extend((64u64 << 30).to_le_bytes());
        dict.push(0);
        let mut file = vec![
            0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x01, 0x00, 0x04, 0x00,
        ];
        file.push(11);
        file.extend((dict.len() as u32).to_le_bytes());
        file.extend(&dict);
        file.push(0);
        file.extend(4u32.to_le_bytes());
        file.extend([0x0d, 0x0a, 0x0d, 0x0a]);
        let e = parse(&file, Some("pw")).unwrap_err();
        assert!(e.to_string().contains("too costly"), "{e}");
    }
}
