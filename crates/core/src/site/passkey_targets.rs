//! Where a new passkey can be saved ("Save in" in the passkey confirmation).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use super::host::host_or_lowercase;
use super::urls::{is_web, parse};
use super::{NEW_LOGIN, norm, shared_vault_label};

/// A vault login, reduced to what choosing a place for a passkey needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasskeyLogin {
    pub id: String,
    pub name: String,
    pub username: String,
    /// The login's website addresses, as saved (scheme optional).
    pub urls: Vec<String>,
    /// In a vault the user can edit.
    pub writable: bool,
    /// In the user's own vault, not one somebody shared with them.
    pub personal: bool,
    /// Name of the vault, shown when it is a shared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// A login offered under "Save in".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasskeyTarget {
    pub id: String,
    pub name: String,
    pub username: String,
    /// Preselected: the user's own login for this exact site. Never a login in a shared vault.
    pub preferred: bool,
    /// Set when the login lives in a shared vault: that vault's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// Host names of a login's websites: http(s) addresses only (an `androidapp://` entry is not a
/// website), scheme optional, in ASCII, without a trailing dot.
fn hosts_of(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|u| parse(u))
        .filter(is_web)
        .filter_map(|u| u.host_str().map(host_or_lowercase))
        .collect()
}

/// Logins a new passkey can be saved in: ones the user can edit whose website is this exact
/// host, the RP ID, or a subdomain of the RP ID (where the passkey also works). Never just "the
/// same base domain": cloudy.example.com and bazarr.example.com are different sites.
///
/// Order: the user's own logins first (this exact host, then a matching user name, then by
/// name), logins in shared vaults after them. Only an own login for the exact host is
/// `preferred` (preselected): anyone on the server can share a vault with the user and put a
/// login for the site in it, and a passkey saved there is handed to that vault's other members.
/// A shared login can still be picked on purpose; its row names the vault.
pub fn passkey_save_targets(
    logins: &[PasskeyLogin],
    host: &str,
    rp_id: &str,
    user_name: &str,
    display_name: &str,
) -> Vec<PasskeyTarget> {
    let host = host_or_lowercase(host);
    let rp = host_or_lowercase(rp_id);
    let below_rp = format!(".{rp}");
    let names: Vec<String> = [user_name, display_name]
        .iter()
        .map(|n| norm(n))
        .filter(|n| !n.is_empty())
        .collect();
    let mut rows: Vec<(u8, &PasskeyLogin, bool)> = logins
        .iter()
        .filter(|l| l.writable)
        .filter_map(|l| {
            let hosts = hosts_of(&l.urls);
            if !hosts
                .iter()
                .any(|h| *h == host || *h == rp || h.ends_with(&below_rp))
            {
                return None;
            }
            let exact = hosts.contains(&host);
            let user = norm(&l.username);
            let local = user.split('@').next().unwrap_or("");
            let named = !user.is_empty() && names.iter().any(|n| *n == user || n == local);
            let score = u8::from(l.personal) * 4 + u8::from(exact) * 2 + u8::from(named);
            Some((score, l, exact))
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| collate(&a.1.name, &b.1.name)));
    rows.into_iter()
        .map(|(_, l, exact)| PasskeyTarget {
            id: l.id.clone(),
            name: l.name.clone(),
            username: l.username.clone(),
            preferred: l.personal && exact,
            vault: shared_vault_label(l.personal, l.vault.as_deref()),
        })
        .collect()
}

/// The preselected choice: the first `preferred` target, else [`NEW_LOGIN`].
pub fn passkey_default_target(targets: &[PasskeyTarget]) -> String {
    targets
        .iter()
        .find(|t| t.preferred)
        .map_or_else(|| NEW_LOGIN.to_owned(), |t| t.id.clone())
}

/// Name order close to `localeCompare` (ICU root collation) for the usual names: letters
/// without regard to case, lower case before upper case on a tie, then code points.
fn collate(a: &str, b: &str) -> Ordering {
    let fold = |s: &str| {
        s.chars()
            .flat_map(char::to_lowercase)
            .collect::<Vec<char>>()
    };
    fold(a)
        .cmp(&fold(b))
        .then_with(|| {
            a.chars()
                .map(char::is_uppercase)
                .cmp(b.chars().map(char::is_uppercase))
        })
        .then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str, name: &str, username: &str, urls: &[&str], personal: bool) -> PasskeyLogin {
        PasskeyLogin {
            id: id.into(),
            name: name.into(),
            username: username.into(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            writable: true,
            personal,
            vault: (!personal).then(|| "Team".into()),
        }
    }

    #[test]
    fn order_preference_and_sites() {
        let logins = [
            login(
                "s",
                "AAA shared",
                "alex@example.com",
                &["https://login.example.com"],
                false,
            ),
            login("b", "Bravo", "sam", &["https://example.com"], true),
            login("c", "Charlie", "alex", &["https://example.com"], true),
            login(
                "d",
                "Delta",
                "someone",
                &["https://login.example.com"],
                true,
            ),
            login(
                "e",
                "Echo",
                "alex@example.com",
                &["https://LOGIN.example.com."],
                true,
            ),
            login("f", "Sibling", "x", &["https://bazarr.example.com"], true),
            login("g", "Other", "x", &["https://example.org"], true),
            login("h", "App", "x", &["androidapp://login.example.com"], true),
        ];
        let t = passkey_save_targets(
            &logins,
            "login.example.com",
            "example.com",
            "alex@example.com",
            "Alex",
        );
        let ids: Vec<&str> = t.iter().map(|t| t.id.as_str()).collect();
        // bazarr.example.com is under the RP ID, so the passkey works there too.
        assert_eq!(ids, ["e", "d", "c", "b", "f", "s"]);
        assert!(t[0].preferred && t[1].preferred && !t[2].preferred);
        assert_eq!(t[5].vault.as_deref(), Some("Team"));
        assert!(!t[5].preferred);
        assert_eq!(passkey_default_target(&t), "e");
        assert_eq!(passkey_default_target(&t[2..]), NEW_LOGIN);
    }

    #[test]
    fn collation_is_case_insensitive() {
        let mut names = ["bravo", "Alpha", "alpha", "Charlie", "1st", "a b"];
        names.sort_by(|a, b| collate(a, b));
        assert_eq!(names, ["1st", "a b", "alpha", "Alpha", "bravo", "Charlie"]);
    }
}
