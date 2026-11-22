//! macOS: AutoFill settings shared with the AutoFill extension (`desktop/macos/AutoFill/DesktopSettings.swift`).
//! One Keychain item in the extension's access group: service `io.passauth.desktop.autofill-settings`, account
//! `settings`, data `{"defaultMatch":"host","changedAt":<unix ms>,"fillSingleMatch":true,"suggestAllLogins":false}`
//! (the two switches since 0.15.10; older items lack them, and the extension completes them). Both sides write all
//! of it when the user changes any of these there; the newer `changedAt` wins (the extension adopts it on its next
//! request).

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
    /// "Fill at once when one login matches" (extension default on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_single_match: Option<bool>,
    /// "Suggest every login in Safari's AutoFill list" (extension default off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggest_all_logins: Option<bool>,
}

/// The item's data, or None when it isn't JSON of this shape or names an unknown match. (Read on macOS only.)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn parse(bytes: &[u8]) -> Option<AutofillSettings> {
    let s: AutofillSettings = serde_json::from_slice(bytes).ok()?;
    MATCHES.contains(&s.default_match.as_str()).then_some(s)
}

pub(crate) fn encode(
    default_match: &str,
    changed_at: i64,
    fill_single_match: bool,
    suggest_all_logins: bool,
) -> Result<Vec<u8>, String> {
    if !MATCHES.contains(&default_match) {
        return Err(format!("unknown match: {default_match}"));
    }
    serde_json::to_vec(&AutofillSettings {
        default_match: default_match.to_owned(),
        changed_at,
        fill_single_match: Some(fill_single_match),
        suggest_all_logins: Some(suggest_all_logins),
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

/// The user changed one of these in the desktop's Settings (all are written, as shown there).
#[tauri::command]
pub(crate) async fn autofill_settings_set(
    default_match: String,
    fill_single_match: bool,
    suggest_all_logins: bool,
) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as i64;
    let json = encode(&default_match, now, fill_single_match, suggest_all_logins)?;
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
        let json = encode("starts_with", 1_700_000_000_123, false, true).unwrap();
        assert_eq!(
            String::from_utf8(json.clone()).unwrap(),
            r#"{"defaultMatch":"starts_with","changedAt":1700000000123,"fillSingleMatch":false,"suggestAllLogins":true}"#
        );
        assert_eq!(
            parse(&json),
            Some(AutofillSettings {
                default_match: "starts_with".into(),
                changed_at: 1_700_000_000_123,
                fill_single_match: Some(false),
                suggest_all_logins: Some(true),
            })
        );
        // Written by an extension before 0.15.10: no switches.
        let old = parse(br#"{"defaultMatch":"host","changedAt":5}"#).unwrap();
        assert_eq!(
            (old.fill_single_match, old.suggest_all_logins),
            (None, None)
        );
    }

    #[test]
    fn refuses_unknown_matches_and_malformed_data() {
        assert!(encode("default", 1, true, false).is_err());
        assert!(encode("", 1, true, false).is_err());
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
