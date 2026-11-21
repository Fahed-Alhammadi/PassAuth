//! macOS: AutoFill settings shared with the AutoFill extension (`desktop/macos/AutoFill/DesktopSettings.swift`).
//! One Keychain item in the extension's access group: service `io.passauth.desktop.autofill-settings`, account
//! `settings`, data `{"defaultMatch":"host","changedAt":<unix ms>}`. Both sides write it when the user changes the
//! setting there; the newer `changedAt` wins (the extension adopts it on its next request).

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
const SERVICE: &str = "io.passauth.desktop.autofill-settings";
#[cfg(target_os = "macos")]
const ACCOUNT: &str = "settings";

/// The values the extension's "Default URI match detection" picker offers (`UrlMatch` raw values).
const MATCHES: [&str; 6] = ["domain", "host", "starts_with", "regex", "exact", "never"];

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AutofillSettings {
    pub default_match: String,
    pub changed_at: i64,
}

/// The item's data, or None when it isn't JSON of this shape or names an unknown match. (Read on macOS only.)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn parse(bytes: &[u8]) -> Option<AutofillSettings> {
    let s: AutofillSettings = serde_json::from_slice(bytes).ok()?;
    MATCHES.contains(&s.default_match.as_str()).then_some(s)
}

pub(crate) fn encode(default_match: &str, changed_at: i64) -> Result<Vec<u8>, String> {
    if !MATCHES.contains(&default_match) {
        return Err(format!("unknown match: {default_match}"));
    }
    serde_json::to_vec(&AutofillSettings {
        default_match: default_match.to_owned(),
        changed_at,
    })
    .map_err(|e| e.to_string())
}

/// What the item holds now; None when it's missing or unreadable (Settings then shows the extension's default).
#[tauri::command]
pub(crate) async fn autofill_settings_get() -> Result<Option<AutofillSettings>, String> {
    #[cfg(target_os = "macos")]
    {
        crate::read_group_item(SERVICE, ACCOUNT)
            .await
            .map(|bytes| bytes.as_deref().and_then(parse))
    }
    #[cfg(not(target_os = "macos"))]
    Ok(None)
}

/// The user picked `default_match` in the desktop's Settings.
#[tauri::command]
pub(crate) async fn autofill_settings_set(default_match: String) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as i64;
    let json = encode(&default_match, now)?;
    #[cfg(target_os = "macos")]
    {
        crate::write_group_item(SERVICE, ACCOUNT, json).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = json;
        Err("AutoFill settings exist only on macOS".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_shape_the_extension_reads() {
        let json = encode("starts_with", 1_700_000_000_123).unwrap();
        assert_eq!(
            String::from_utf8(json.clone()).unwrap(),
            r#"{"defaultMatch":"starts_with","changedAt":1700000000123}"#
        );
        assert_eq!(
            parse(&json),
            Some(AutofillSettings {
                default_match: "starts_with".into(),
                changed_at: 1_700_000_000_123
            })
        );
    }

    #[test]
    fn refuses_unknown_matches_and_malformed_data() {
        assert!(encode("default", 1).is_err());
        assert!(encode("", 1).is_err());
        assert_eq!(parse(br#"{"defaultMatch":"default","changedAt":1}"#), None);
        assert_eq!(parse(br#"{"defaultMatch":"host"}"#), None);
        assert_eq!(parse(b"{}"), None);
        assert_eq!(parse(b"not json"), None);
        assert_eq!(
            parse(br#"{"defaultMatch":"never","changedAt":5,"extra":true}"#)
                .map(|s| s.default_match),
            Some("never".into())
        );
    }
}
