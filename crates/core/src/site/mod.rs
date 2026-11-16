//! Which saved logins belong to which site: the logic every client used to implement on its
//! own (extension TypeScript, Swift, Kotlin), now in one place.
//!
//! - Hosts and sites: [`normalize_host`], [`public_suffix`], [`registrable_domain`],
//!   [`is_public_suffix`], [`base_domain`] over the full Public Suffix List (see `psl.rs`).
//! - Website matching: [`matches_url`] / [`Page`], [`resolve_match`], [`downgrade`],
//!   [`regex_error`], [`regex_warning`].
//! - The save rule: [`plan_save`], [`chosen_target`].
//! - Passkeys: [`passkey_save_targets`], [`passkey_default_target`], [`effective_rp_id`].
//!
//! Everything here is a pure function over plain data. Hosts are compared in ASCII (IDNA
//! UTS #46 nontransitional, like browsers).

mod host;
mod passkey_targets;
mod psl;
mod rp_id;
mod save_plan;
mod urls;

pub use host::normalize_host;
pub use passkey_targets::{
    PasskeyLogin, PasskeyTarget, passkey_default_target, passkey_save_targets,
};
pub use psl::{
    PUBLIC_SUFFIX_LIST_COMMIT, PUBLIC_SUFFIX_LIST_DATE, base_domain, is_public_suffix,
    public_suffix, public_suffix_list_version, registrable_domain,
};
pub use rp_id::{RpIdError, effective_rp_id};
pub use save_plan::{
    NEW_LOGIN, SaveCandidate, SavePlan, SaveReason, SaveTarget, chosen_target, plan_save,
};
pub use urls::{
    MAX_REGEX_INPUT, MAX_REGEX_LENGTH, Page, downgrade, matches_url, parse_url_match, regex_error,
    regex_warning, resolve_match,
};

pub use crate::item::UrlMatch;

/// Vault name shown for a login in a shared vault whose name isn't known.
pub const SHARED_VAULT: &str = "Shared vault";

/// The vault a "Save in" row names: none for the user's own vault, else the shared vault's name.
fn shared_vault_label(personal: bool, vault: Option<&str>) -> Option<String> {
    (!personal).then(|| match vault {
        Some(v) if !v.is_empty() => v.to_owned(),
        _ => SHARED_VAULT.to_owned(),
    })
}

/// JavaScript's `String.prototype.trim` white space (WhiteSpace and LineTerminator), so user
/// names compare the same as they did in the extension.
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// Trimmed and lower-cased, for comparing user names.
fn norm(s: &str) -> String {
    s.trim_matches(is_js_space).to_lowercase()
}

/// Length in UTF-16 code units (JavaScript's `length`), for limits shared with the clients.
fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_trim_and_length() {
        assert_eq!(
            norm("\u{feff} Alex@Example.COM \u{3000}\n"),
            "alex@example.com"
        );
        // U+0085 is white space for Rust but not for JavaScript's trim.
        assert_eq!(norm("\u{85}a"), "\u{85}a");
        assert_eq!(utf16_len("a😀"), 3);
    }
}
