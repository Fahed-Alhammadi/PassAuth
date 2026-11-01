//! Bitwarden / Vaultwarden JSON exports, plain or password-protected.

use std::collections::HashMap;

use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use hmac::{KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{Format, ImportResult, err};
use crate::item::{
    Card, Field, FieldType, Identity, Item, Login, LoginUrl, Passkey, PasswordHistory, SshKey,
    UrlMatch,
};
use crate::{Error, Result};

pub fn parse_json(text: &str, password: Option<&str>) -> Result<ImportResult> {
    let v: Value = serde_json::from_str(text).map_err(|e| err(format!("invalid JSON: {e}")))?;
    if v["encrypted"].as_bool() == Some(true) {
        if v["passwordProtected"].as_bool() != Some(true) {
            return Err(err(
                "this Bitwarden export is locked to the Bitwarden account. Export again choosing \"Password protected\" or unencrypted JSON",
            ));
        }
        let mut plain = decrypt_protected(&v, password.ok_or(Error::PasswordRequired)?)?;
        let inner: Result<Value> =
            serde_json::from_str(&plain).map_err(|_| err("decrypted export is not valid JSON"));
        plain.zeroize();
        return parse_plain(&inner?);
    }
    if v.get("items").is_none() {
        return Err(err(
            "unrecognized JSON file: expected a Bitwarden or Vaultwarden export",
        ));
    }
    parse_plain(&v)
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn parse_plain(v: &Value) -> Result<ImportResult> {
    let mut folders: HashMap<String, String> = HashMap::new();
    for key in ["folders", "collections"] {
        for f in v[key].as_array().into_iter().flatten() {
            folders.insert(s(&f["id"]), s(&f["name"]));
        }
    }
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for it in v["items"].as_array().into_iter().flatten() {
        if !it["deletedDate"].is_null() {
            continue;
        }
        let mut item = Item {
            name: s(&it["name"]),
            notes: s(&it["notes"]),
            favorite: it["favorite"].as_bool().unwrap_or(false),
            folder: it["folderId"]
                .as_str()
                .or_else(|| it["collectionIds"][0].as_str())
                .and_then(|id| folders.get(id).cloned()),
            ..Default::default()
        };
        if !it["archivedDate"].is_null() {
            item.tags.push("archived".into());
        }
        item.fields = it["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(field)
            .collect();
        item.password_history = it["passwordHistory"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|h| PasswordHistory {
                password: s(&h["password"]),
                changed_at: 0,
            })
            .collect();
        match it["type"].as_i64() {
            Some(1) => item.login = Some(login(&it["login"], &mut warnings)),
            Some(2) => {}
            Some(3) => {
                let c = &it["card"];
                item.card = Some(Card {
                    cardholder_name: s(&c["cardholderName"]),
                    brand: s(&c["brand"]),
                    number: s(&c["number"]),
                    exp_month: s(&c["expMonth"]),
                    exp_year: s(&c["expYear"]),
                    code: s(&c["code"]),
                });
            }
            Some(4) => item.identity = Some(identity(&it["identity"])),
            Some(5) => {
                let k = &it["sshKey"];
                item.ssh_key = Some(SshKey {
                    private_key: s(&k["privateKey"]),
                    public_key: s(&k["publicKey"]),
                    fingerprint: s(&k["keyFingerprint"]),
                });
            }
            other => {
                // Newer types (bank account, licence, passport…) keep their data as fields.
                if let Some(obj) = it.as_object() {
                    for (k, val) in obj {
                        if let Some(inner) = val.as_object().filter(|_| {
                            !matches!(
                                k.as_str(),
                                "login" | "card" | "identity" | "sshKey" | "secureNote"
                            )
                        }) {
                            for (fk, fv) in inner {
                                if !s(fv).is_empty() {
                                    item.fields.push(Field {
                                        name: fk.clone(),
                                        value: s(fv),
                                        field_type: FieldType::Text,
                                    });
                                }
                            }
                        }
                    }
                }
                warnings.push(format!(
                    "\"{}\": item type {:?} imported as a note",
                    item.name,
                    other.unwrap_or(0)
                ));
            }
        }
        items.push(item);
    }
    Ok(ImportResult {
        format: Format::BitwardenJson,
        items,
        warnings,
    })
}

fn field(f: &Value) -> Option<Field> {
    let field_type = match f["type"].as_i64() {
        Some(1) => FieldType::Hidden,
        Some(2) => FieldType::Boolean,
        Some(3) => return None, // linked fields point at username/password, which we already keep
        _ => FieldType::Text,
    };
    Some(Field {
        name: s(&f["name"]),
        value: s(&f["value"]),
        field_type,
    })
}

fn login(l: &Value, warnings: &mut Vec<String>) -> Login {
    let urls = l["uris"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|u| LoginUrl {
            url: s(&u["uri"]),
            match_type: match u["match"].as_i64() {
                Some(1) => UrlMatch::Host,
                Some(2) => UrlMatch::StartsWith,
                Some(3) => UrlMatch::Exact,
                Some(5) => UrlMatch::Never,
                Some(4) => {
                    warnings.push(format!(
                        "regex URL match for {} imported as domain match",
                        s(&u["uri"])
                    ));
                    UrlMatch::Domain
                }
                _ => UrlMatch::Domain,
            },
        })
        .filter(|u| !u.url.is_empty())
        .collect();
    let passkeys = l["fido2Credentials"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(passkey)
        .collect();
    Login {
        username: s(&l["username"]),
        password: s(&l["password"]),
        urls,
        totp: Some(s(&l["totp"])).filter(|t| !t.is_empty()),
        passkeys,
    }
}

fn passkey(p: &Value) -> Option<Passkey> {
    if s(&p["keyAlgorithm"]) != "ECDSA" || s(&p["keyCurve"]) != "P-256" {
        return None;
    }
    let raw_id = s(&p["credentialId"]);
    let credential_id = match raw_id.strip_prefix("b64.") {
        Some(b) => b.to_owned(),
        None => URL_SAFE_NO_PAD.encode(uuid::Uuid::parse_str(&raw_id).ok()?.as_bytes()),
    };
    Some(Passkey {
        credential_id,
        rp_id: s(&p["rpId"]),
        rp_name: s(&p["rpName"]),
        user_handle: s(&p["userHandle"]),
        user_name: s(&p["userName"]),
        user_display_name: s(&p["userDisplayName"]),
        algorithm: -7,
        private_key: s(&p["keyValue"]),
        counter: s(&p["counter"]).parse().unwrap_or(0),
        discoverable: s(&p["discoverable"]) == "true",
        created_at: 0,
    })
}

fn identity(i: &Value) -> Identity {
    Identity {
        title: s(&i["title"]),
        first_name: s(&i["firstName"]),
        middle_name: s(&i["middleName"]),
        last_name: s(&i["lastName"]),
        company: s(&i["company"]),
        email: s(&i["email"]),
        phone: s(&i["phone"]),
        address1: s(&i["address1"]),
        address2: s(&i["address2"]),
        city: s(&i["city"]),
        state: s(&i["state"]),
        postal_code: s(&i["postalCode"]),
        country: s(&i["country"]),
        username: s(&i["username"]),
        ssn: s(&i["ssn"]),
        passport_number: s(&i["passportNumber"]),
        license_number: s(&i["licenseNumber"]),
    }
}

// ------------------------------------------------- password-protected export

fn decrypt_protected(v: &Value, password: &str) -> Result<String> {
    let salt = s(&v["salt"]);
    let iterations = v["kdfIterations"].as_u64().unwrap_or(0) as u32;
    let mut key = [0u8; 32];
    match v["kdfType"].as_i64() {
        Some(0) => {
            if !(5_000..=2_000_000).contains(&iterations) {
                return Err(err("export has out-of-range PBKDF2 iterations"));
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                iterations,
                &mut key,
            );
        }
        Some(1) => {
            let memory = v["kdfMemory"].as_u64().unwrap_or(0) as u32;
            let parallelism = v["kdfParallelism"].as_u64().unwrap_or(0) as u32;
            if !(2..=10).contains(&iterations)
                || !(16..=1024).contains(&memory)
                || !(1..=16).contains(&parallelism)
            {
                return Err(err("export has out-of-range Argon2 parameters"));
            }
            let salt = Sha256::digest(salt.as_bytes());
            Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(memory * 1024, iterations, parallelism, Some(32))
                    .map_err(|_| Error::Kdf)?,
            )
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|_| Error::Kdf)?;
        }
        _ => return Err(err("unknown KDF in export")),
    }
    let hk = Hkdf::<Sha256>::from_prk(&key).map_err(|_| Error::Kdf)?;
    key.zeroize();
    let (mut enc, mut mac) = ([0u8; 32], [0u8; 32]);
    hk.expand(b"enc", &mut enc).map_err(|_| Error::Kdf)?;
    hk.expand(b"mac", &mut mac).map_err(|_| Error::Kdf)?;

    let result = decrypt_enc_string(&s(&v["encKeyValidation_DO_NOT_EDIT"]), &enc, &mac)
        .map_err(|_| err("wrong password for this export"))
        .and_then(|_| decrypt_enc_string(&s(&v["data"]), &enc, &mac));
    enc.zeroize();
    mac.zeroize();
    String::from_utf8(result?).map_err(|_| err("decrypted export is not text"))
}

/// Bitwarden type-2 EncString: `2.<iv>|<ct>|<mac>` (standard base64),
/// AES-256-CBC with HMAC-SHA256 over iv‖ct.
fn decrypt_enc_string(s: &str, enc: &[u8; 32], mac_key: &[u8; 32]) -> Result<Vec<u8>> {
    let body = s
        .strip_prefix("2.")
        .ok_or(err("unsupported encryption type in export"))?;
    let parts: Vec<&str> = body.split('|').collect();
    let [iv, ct, mac] = parts[..] else {
        return Err(err("malformed encrypted value"));
    };
    let (iv, ct, mac) = (b64std(iv)?, b64std(ct)?, b64std(mac)?);
    let mut m = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(mac_key).expect("any key length");
    m.update(&iv);
    m.update(&ct);
    m.verify_slice(&mac).map_err(|_| Error::Decrypt)?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| err("bad IV"))?;
    let mut buf = ct;
    let len = cbc::Decryptor::<Aes256>::new(enc.into(), &iv.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| Error::Decrypt)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

fn b64std(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|_| err("malformed base64 in export"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt;

    const PLAIN: &str = r#"{"encrypted":false,
      "folders":[{"id":"f1","name":"Work"}],
      "items":[
        {"type":1,"name":"GitHub","folderId":"f1","favorite":true,"notes":"n",
         "fields":[{"name":"PIN","value":"1234","type":1},{"name":"l","value":null,"type":3,"linkedId":100}],
         "login":{"username":"octo","password":"pw","totp":"JBSWY3DPEHPK3PXP",
           "uris":[{"uri":"https://github.com","match":null},{"uri":"https://x.io","match":3}],
           "fido2Credentials":[{"credentialId":"b64.AAEC","keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256",
             "keyValue":"MIGH","rpId":"github.com","userHandle":"dQ","userName":"octo","counter":"5","discoverable":"true"}]}},
        {"type":3,"name":"Visa","card":{"cardholderName":"O C","number":"4111","expMonth":"1","expYear":"2030","code":"123"}},
        {"type":2,"name":"Note","notes":"secret","secureNote":{"type":0}},
        {"type":1,"name":"Gone","deletedDate":"2024-01-01T00:00:00Z","login":{}}
      ]}"#;

    #[test]
    fn plain_json() {
        let r = parse_json(PLAIN, None).unwrap();
        assert_eq!(r.items.len(), 3);
        let gh = &r.items[0];
        assert_eq!(gh.folder.as_deref(), Some("Work"));
        assert_eq!(gh.fields.len(), 1);
        assert_eq!(gh.fields[0].field_type, FieldType::Hidden);
        let l = gh.login.as_ref().unwrap();
        assert_eq!(l.urls[1].match_type, UrlMatch::Exact);
        assert_eq!(l.passkeys[0].credential_id, "AAEC");
        assert_eq!(l.passkeys[0].counter, 5);
        assert!(l.passkeys[0].discoverable);
        assert_eq!(r.items[1].card.as_ref().unwrap().code, "123");
        assert!(r.items[2].login.is_none());
    }

    fn enc_string(data: &[u8], enc: &[u8; 32], mac_key: &[u8; 32]) -> String {
        let iv = [7u8; 16];
        let mut buf = data.to_vec();
        buf.resize(data.len() + 16, 0);
        let ct = cbc::Encryptor::<Aes256>::new(enc.into(), &iv.into())
            .encrypt_padded::<Pkcs7>(&mut buf, data.len())
            .unwrap()
            .to_vec();
        let mut m = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(mac_key).unwrap();
        m.update(&iv);
        m.update(&ct);
        let mac = m.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(ct),
            STANDARD.encode(mac)
        )
    }

    #[test]
    fn password_protected_json() {
        let salt = "c2FsdHNhbHQ=";
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"export-pw", salt.as_bytes(), 5000, &mut key);
        let hk = Hkdf::<Sha256>::from_prk(&key).unwrap();
        let (mut enc, mut mac) = ([0u8; 32], [0u8; 32]);
        hk.expand(b"enc", &mut enc).unwrap();
        hk.expand(b"mac", &mut mac).unwrap();
        let file = serde_json::json!({
            "encrypted": true, "passwordProtected": true, "salt": salt, "kdfType": 0, "kdfIterations": 5000,
            "encKeyValidation_DO_NOT_EDIT": enc_string(b"validation", &enc, &mac),
            "data": enc_string(PLAIN.as_bytes(), &enc, &mac),
        })
        .to_string();
        assert!(matches!(
            parse_json(&file, None),
            Err(Error::PasswordRequired)
        ));
        assert!(
            parse_json(&file, Some("nope"))
                .unwrap_err()
                .to_string()
                .contains("wrong password")
        );
        assert_eq!(parse_json(&file, Some("export-pw")).unwrap().items.len(), 3);
    }

    #[test]
    fn account_restricted_rejected() {
        let e = parse_json(
            r#"{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.x","items":[]}"#,
            None,
        )
        .unwrap_err();
        assert!(e.to_string().contains("Password protected"));
    }
}
