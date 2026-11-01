//! CSV exports. Columns are looked up by header name (never position), so
//! Bitwarden, Passbolt (all variants), 1Password, LastPass and browser CSVs
//! share one parser.

use std::collections::HashMap;

use super::{Format, ImportResult, err, login_item};
use crate::Result;
use crate::item::{Field, FieldType};

struct Columns(HashMap<String, usize>);

impl Columns {
    fn find(&self, aliases: &[&str]) -> Option<usize> {
        aliases.iter().find_map(|a| self.0.get(*a).copied())
    }
    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

pub fn parse(text: &str) -> Result<ImportResult> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = rdr
        .headers()
        .map_err(|e| err(format!("invalid CSV: {e}")))?
        .clone();
    let cols = Columns(
        headers
            .iter()
            .enumerate()
            .map(|(i, h)| (h.trim().to_ascii_lowercase(), i))
            .collect(),
    );
    let format = detect(&cols);

    let name = cols.find(&["name", "title"]);
    let user = cols.find(&["login_username", "username", "user name", "login"]);
    let pass = cols.find(&["login_password", "password"]);
    let url = cols.find(&["login_uri", "url", "uri", "website", "web site"]);
    let totp = cols.find(&["login_totp", "totp", "otpauth", "otp"]);
    let notes = cols.find(&["notes", "extra", "note", "comments"]);
    let folder = cols.find(&["folder", "group", "grouping", "collections"]);
    let tags = cols.find(&["tags"]);
    let fav = cols.find(&["favorite", "fav"]);
    let kind = cols.find(&["type"]);
    let fields = cols.find(&["fields"]);
    let archived = cols.find(&["archived"]);
    if name.is_none() && user.is_none() && pass.is_none() && url.is_none() {
        return Err(err(
            "unrecognized CSV: expected columns like name, username, password, url",
        ));
    }

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for (row, rec) in rdr.records().enumerate() {
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!("row {}: skipped ({e})", row + 2));
                continue;
            }
        };
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("").to_owned();

        let kind_v = get(kind).to_ascii_lowercase();
        // Bitwarden's login_uri holds several URIs in one comma-joined cell.
        let urls = if format == Format::BitwardenCsv {
            split_csv_cell(&get(url))
        } else {
            vec![get(url)]
        };
        let mut item = login_item(
            &get(name),
            &get(user),
            &get(pass),
            urls,
            Some(get(totp)),
            &get(notes),
        );

        if kind_v == "note" || kind_v == "secure note" || kind_v == "securenote" {
            item.login = None;
        } else if !kind_v.is_empty() && !matches!(kind_v.as_str(), "login" | "password") {
            warnings.push(format!("row {}: imported {kind_v:?} as a login", row + 2));
        }

        let folder_v = get(folder);
        item.folder = (!folder_v.is_empty()).then(|| normalize_folder(&folder_v, format));
        let tags_v = get(tags);
        if !tags_v.is_empty() {
            item.tags = tags_v
                .split([';', ','])
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect();
            if item.folder.is_none() {
                item.folder = item.tags.first().cloned();
            }
        }
        item.favorite = matches!(get(fav).to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        if format == Format::BitwardenCsv {
            item.fields = parse_bitwarden_fields(&get(fields));
        }
        if get(archived).eq_ignore_ascii_case("true") {
            item.tags.push("archived".into());
        }
        items.push(item);
    }
    Ok(ImportResult {
        format,
        items,
        warnings,
    })
}

fn detect(c: &Columns) -> Format {
    if c.has("login_uri") && c.has("type") {
        Format::BitwardenCsv
    } else if c.has("login_uri") || (c.has("title") && c.has("group") && c.has("totp")) {
        Format::PassboltCsv
    } else if c.has("otpauth") && c.has("archived")
        || c.has("title") && c.has("url") && c.has("type")
    {
        Format::OnePasswordCsv
    } else if c.has("grouping") && c.has("extra") {
        Format::LastpassCsv
    } else if c.0.len() == 4
        && c.has("name")
        && c.has("url")
        && c.has("username")
        && c.has("password")
    {
        Format::ChromeCsv
    } else {
        Format::GenericCsv
    }
}

/// Passbolt writes a literal `/` inside a folder name as ` / `. PassAuth
/// folders are `/`-separated paths, so such a name becomes a nested folder.
fn normalize_folder(v: &str, format: Format) -> String {
    let v = v.trim();
    if format == Format::PassboltCsv {
        v.replace(" / ", "/")
    } else {
        v.to_owned()
    }
}

fn split_csv_cell(cell: &str) -> Vec<String> {
    if cell.is_empty() {
        return vec![];
    }
    csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(cell.as_bytes())
        .records()
        .next()
        .and_then(|r| r.ok())
        .map(|r| r.iter().map(str::to_owned).collect())
        .unwrap_or_else(|| vec![cell.to_owned()])
}

/// Bitwarden CSV `fields`: newline-separated `name: value`, split on the last `": "`.
fn parse_bitwarden_fields(cell: &str) -> Vec<Field> {
    cell.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (name, value) = l.rsplit_once(": ").unwrap_or((l, ""));
            Field {
                name: name.to_owned(),
                value: value.to_owned(),
                field_type: FieldType::Text,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_csv() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,GitHub,hi,\"Team: core\nPIN: 1: 2\",0,\"https://github.com,https://gist.github.com\",octo,pw,JBSWY3DPEHPK3PXP\n\
                   ,,note,Wifi,the code,,0,,,,\n";
        let r = parse(csv).unwrap();
        assert_eq!(r.format, Format::BitwardenCsv);
        let gh = &r.items[0];
        assert_eq!(gh.folder.as_deref(), Some("Work"));
        assert!(gh.favorite);
        let login = gh.login.as_ref().unwrap();
        assert_eq!(login.urls.len(), 2);
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(gh.fields[1].name, "PIN: 1");
        assert_eq!(gh.fields[1].value, "2");
        assert!(r.items[1].login.is_none());
    }

    #[test]
    fn passbolt_csv() {
        let csv = "\"Title\",\"Username\",\"URL\",\"Password\",\"Notes\",\"Group\",\"TOTP\"\r\n\
                   \"Mail\",\"me\",\"https://mail.example\",\"pw\",\"\",\"Root/A / B\",\"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\"\r\n";
        let r = parse(csv).unwrap();
        assert_eq!(r.format, Format::PassboltCsv);
        assert_eq!(r.items[0].folder.as_deref(), Some("Root/A/B"));
        assert!(
            r.items[0]
                .login
                .as_ref()
                .unwrap()
                .totp
                .as_deref()
                .unwrap()
                .starts_with("otpauth://")
        );
    }

    #[test]
    fn onepassword_csv() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Bank,https://bank.example,me,pw,,true,false,Finance;Personal,note\n";
        let r = parse(csv).unwrap();
        assert_eq!(r.format, Format::OnePasswordCsv);
        assert_eq!(r.items[0].folder.as_deref(), Some("Finance"));
        assert_eq!(r.items[0].tags, vec!["Finance", "Personal"]);
        assert!(r.items[0].favorite);
    }

    #[test]
    fn chrome_csv() {
        let r = parse("name,url,username,password\nsite,https://s.example,a,b\n").unwrap();
        assert_eq!(r.format, Format::ChromeCsv);
        assert_eq!(r.items[0].login.as_ref().unwrap().password, "b");
    }
}
