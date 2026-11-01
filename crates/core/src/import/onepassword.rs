//! 1Password `.1pux` exports (zip containing `export.data` JSON).

use std::io::{Cursor, Read};

use serde_json::Value;

use super::{Format, ImportResult, err, login_item};
use crate::Result;
use crate::item::{Card, Field, FieldType, Identity, Item, PasswordHistory, SshKey};

pub fn parse_1pux(data: &[u8]) -> Result<ImportResult> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(data)).map_err(|_| err("not a valid .1pux archive"))?;
    let mut json = String::new();
    zip.by_name("export.data")
        .map_err(|_| err(".1pux archive has no export.data"))?
        .read_to_string(&mut json)
        .map_err(|_| err("could not read export.data"))?;
    let v: Value = serde_json::from_str(&json).map_err(|_| err("export.data is not valid JSON"))?;

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for account in v["accounts"].as_array().into_iter().flatten() {
        for vault in account["vaults"].as_array().into_iter().flatten() {
            let vault_name = s(&vault["attrs"]["name"]);
            for it in vault["items"].as_array().into_iter().flatten() {
                if s(&it["state"]) == "deleted" {
                    continue;
                }
                let item = convert(it, &vault_name, &mut warnings);
                items.push(item);
            }
        }
    }
    let attachments = zip
        .file_names()
        .filter(|n| n.as_ref().is_ok_and(|n| n.starts_with("files/")))
        .count();
    if attachments > 0 {
        warnings.push(format!("{attachments} attached file(s) were not imported"));
    }
    Ok(ImportResult {
        format: Format::OnePassword1pux,
        items,
        warnings,
    })
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn convert(it: &Value, vault: &str, warnings: &mut Vec<String>) -> Item {
    let ov = &it["overview"];
    let d = &it["details"];
    let category = s(&it["categoryUuid"]);
    let title = s(&ov["title"]);

    let mut urls: Vec<String> = ov["urls"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|u| s(&u["url"]))
        .collect();
    if urls.is_empty() {
        urls.push(s(&ov["url"]));
    }
    let (mut username, mut password) = (String::new(), s(&d["password"]));
    let mut fields = Vec::new();
    for lf in d["loginFields"].as_array().into_iter().flatten() {
        match s(&lf["designation"]).as_str() {
            "username" => username = s(&lf["value"]),
            "password" => password = s(&lf["value"]),
            _ => {
                let value = s(&lf["value"]);
                if !value.is_empty() {
                    let field_type = if s(&lf["fieldType"]) == "P" {
                        FieldType::Hidden
                    } else {
                        FieldType::Text
                    };
                    fields.push(Field {
                        name: s(&lf["name"]),
                        value,
                        field_type,
                    });
                }
            }
        }
    }

    // Section fields: pull out well-known values, keep the rest as custom fields.
    let mut totp = None;
    let mut by_id = std::collections::HashMap::new();
    for section in d["sections"].as_array().into_iter().flatten() {
        for f in section["fields"].as_array().into_iter().flatten() {
            let id = s(&f["id"]);
            let (value, hidden, kind) = field_value(&f["value"]);
            if kind == "totp" || id.starts_with("TOTP_") {
                totp.get_or_insert(value);
                continue;
            }
            if value.is_empty() {
                continue;
            }
            by_id.insert(id.to_ascii_lowercase(), value.clone());
            let name = Some(s(&f["title"])).filter(|t| !t.is_empty()).unwrap_or(id);
            fields.push(Field {
                name,
                value,
                field_type: if hidden {
                    FieldType::Hidden
                } else {
                    FieldType::Text
                },
            });
        }
    }
    let get = |ids: &[&str]| {
        ids.iter()
            .find_map(|i| by_id.get(*i).cloned())
            .unwrap_or_default()
    };

    let mut item = login_item(
        &title,
        &username,
        &password,
        urls,
        totp,
        &s(&d["notesPlain"]),
    );
    item.folder = Some(vault.to_owned()).filter(|v| !v.is_empty());
    item.tags = ov["tags"].as_array().into_iter().flatten().map(s).collect();
    item.favorite = it["favIndex"].as_i64().unwrap_or(0) > 0;
    if s(&it["state"]) == "archived" {
        item.tags.push("archived".into());
    }
    item.password_history = d["passwordHistory"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| PasswordHistory {
            password: s(&h["value"]),
            changed_at: h["time"].as_i64().unwrap_or(0),
        })
        .collect();

    match category.as_str() {
        "001" | "005" => {}
        "002" => {
            let expiry = get(&["expiry"]);
            item.card = Some(Card {
                cardholder_name: get(&["cardholder"]),
                brand: get(&["type"]),
                number: get(&["ccnum", "number"]),
                exp_month: expiry
                    .get(4..)
                    .map(|m| m.trim_start_matches('0').to_owned())
                    .unwrap_or_default(),
                exp_year: expiry.get(..4).unwrap_or("").to_owned(),
                code: get(&["cvv"]),
            });
            item.login = None;
        }
        "004" => {
            item.identity = Some(Identity {
                first_name: get(&["firstname"]),
                middle_name: get(&["initial"]),
                last_name: get(&["lastname"]),
                company: get(&["company"]),
                email: get(&["email"]),
                phone: get(&["defphone", "cellphone", "homephone"]),
                address1: get(&["address"]),
                username: get(&["username"]),
                ..Default::default()
            });
            item.login = None;
        }
        "114" => {
            item.ssh_key = ssh_key(d);
            item.login = None;
        }
        "003" => item.login = None,
        other => {
            // Bank accounts, licences, servers, databases…: keep the data as fields.
            let keep_login = item
                .login
                .as_ref()
                .is_some_and(|l| !l.username.is_empty() || !l.password.is_empty());
            if !keep_login {
                item.login = None;
            }
            if !matches!(other, "") {
                warnings.push(format!(
                    "\"{title}\": 1Password category {other} imported with custom fields"
                ));
            }
        }
    }
    item.fields = fields;
    item
}

fn ssh_key(d: &Value) -> Option<SshKey> {
    d["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|sec| {
            sec["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|f| {
                    let k = &f["value"]["sshKey"];
                    k.is_object().then(|| SshKey {
                        private_key: s(&k["privateKey"]),
                        public_key: s(&k["metadata"]["publicKey"]),
                        fingerprint: s(&k["metadata"]["fingerprint"]),
                    })
                })
        })
}

/// `(text, hidden, kind)` for a section field's single-key value object.
fn field_value(v: &Value) -> (String, bool, String) {
    let Some((kind, inner)) = v.as_object().and_then(|o| o.iter().next()) else {
        return (String::new(), false, String::new());
    };
    let text = match kind.as_str() {
        "email" => s(&inner["email_address"]),
        "address" => ["street", "city", "state", "zip", "country"]
            .iter()
            .map(|k| s(&inner[*k]))
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        "sshKey" => s(&inner["privateKey"]),
        "file" => String::new(),
        _ => s(inner),
    };
    let hidden = matches!(kind.as_str(), "concealed" | "creditCardNumber" | "sshKey");
    (text, hidden, kind.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn pux(json: &str) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("export.data", zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(json.as_bytes()).unwrap();
        z.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn parses_login_card_and_totp() {
        let data = pux(
            r#"{"accounts":[{"attrs":{"name":"me"},"vaults":[{"attrs":{"name":"Private"},"items":[
          {"uuid":"a","favIndex":1,"state":"active","categoryUuid":"001",
           "overview":{"title":"GitHub","urls":[{"label":"","url":"https://github.com"}],"tags":["dev"]},
           "details":{"loginFields":[{"value":"octo","designation":"username","fieldType":"T"},
                                    {"value":"pw","designation":"password","fieldType":"P"}],
             "notesPlain":"n","sections":[{"title":"","fields":[{"title":"one-time password","id":"TOTP_1","value":{"totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
                                                               {"title":"PIN","id":"pin","value":{"concealed":"9999"}}]}]}},
          {"uuid":"b","favIndex":0,"state":"active","categoryUuid":"002","overview":{"title":"Visa"},
           "details":{"sections":[{"fields":[{"title":"number","id":"ccnum","value":{"creditCardNumber":"4111"}},
             {"title":"expiry","id":"expiry","value":{"monthYear":203007}},{"title":"cvv","id":"cvv","value":{"concealed":"123"}}]}]}}
        ]}]}]}"#,
        );
        let r = super::super::import(&data, None).unwrap();
        assert_eq!(r.format, Format::OnePassword1pux);
        let gh = &r.items[0];
        assert_eq!(gh.folder.as_deref(), Some("Private"));
        assert!(gh.favorite);
        let l = gh.login.as_ref().unwrap();
        assert_eq!((l.username.as_str(), l.password.as_str()), ("octo", "pw"));
        assert!(l.totp.as_deref().unwrap().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(gh.fields[0].field_type, FieldType::Hidden);
        let card = r.items[1].card.as_ref().unwrap();
        assert_eq!(
            (
                card.number.as_str(),
                card.exp_month.as_str(),
                card.exp_year.as_str()
            ),
            ("4111", "7", "2030")
        );
        assert!(r.items[1].login.is_none());
    }
}
