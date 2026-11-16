//! The save rule: what to do with a user name and password just submitted on a page that has
//! (or hasn't) logins in the vault. docs/ARCHITECTURE.md "Save rule".

use serde::{Deserialize, Serialize, Serializer};

use super::{norm, shared_vault_label};

/// Save target meaning "create a new login" (never an item id: those are UUIDs).
pub const NEW_LOGIN: &str = "new";

/// A vault login that matches the page, in the matching function's order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SaveCandidate {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    /// In a vault the user can edit.
    pub writable: bool,
    /// In the user's own vault (wrapped with their account key), not one somebody shared.
    pub personal: bool,
    /// Name of the vault, shown when it is a shared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// A login the prompt offers under "Save in". Never carries a password.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SaveTarget {
    pub id: String,
    pub name: String,
    pub username: String,
    /// Set for a login in a shared vault: that vault's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// Which rule chose the login to update: the user's own login with the `Same` user name,
/// their own `Blank`-user-name login, or their `Only` login for the site. Clients that can save
/// without showing their own prompt must not apply an `Only` update silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveReason {
    Same,
    Blank,
    Only,
}

/// What the save prompt offers. Serialises as the extension's shape:
/// `{"action":"none"}`, `{"action":"create","target":"new","targets":[…]}`,
/// `{"action":"update","reason":"same","target":"<id>","targets":[…]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavePlan {
    /// Nothing to offer (no password, or it is already saved).
    None,
    /// A new login, preselected; `targets`: logins the user may pick instead (own ones, then
    /// shared ones under the typed user name).
    Create { targets: Vec<SaveTarget> },
    /// Update `target`, always one of the user's own logins, preselected.
    Update {
        reason: SaveReason,
        target: String,
        targets: Vec<SaveTarget>,
    },
}

impl SavePlan {
    /// The preselected choice: a login id, [`NEW_LOGIN`], or `None` when there is nothing to save.
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Create { .. } => Some(NEW_LOGIN),
            Self::Update { target, .. } => Some(target),
        }
    }

    /// The logins offered under "Save in" (empty when there is nothing to save).
    pub fn targets(&self) -> &[SaveTarget] {
        match self {
            Self::None => &[],
            Self::Create { targets } | Self::Update { targets, .. } => targets,
        }
    }
}

impl Serialize for SavePlan {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            action: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<SaveReason>,
            #[serde(skip_serializing_if = "Option::is_none")]
            target: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            targets: Option<&'a [SaveTarget]>,
        }
        let (action, reason) = match self {
            Self::None => ("none", None),
            Self::Create { .. } => ("create", None),
            Self::Update { reason, .. } => ("update", Some(*reason)),
        };
        let targets = (!matches!(self, Self::None)).then(|| self.targets());
        Wire {
            action,
            reason,
            target: self.target(),
            targets,
        }
        .serialize(serializer)
    }
}

fn as_target(c: &SaveCandidate) -> SaveTarget {
    SaveTarget {
        id: c.id.clone(),
        name: c.name.clone(),
        username: c.username.clone(),
        vault: shared_vault_label(c.personal, c.vault.as_deref()),
    }
}

/// The default plan for the typed user name (may be empty: the page showed no user-name field)
/// and password, given the logins that match the page.
///
/// Anyone on the server can share a vault with the user and put a login for a site in it,
/// with the victim's email as its user name. So nothing is ever preselected in a vault somebody
/// else controls: rule 1 updates only the user's own login with the typed user name (else it is
/// a new login), and lists a writable shared-vault login with that very user name as an extra,
/// unselected choice that names its vault. Rules 2 and 3 (which guess) and the other "Save in"
/// choices use the user's own logins only.
pub fn plan_save(candidates: &[SaveCandidate], typed_user: &str, password: &str) -> SavePlan {
    if password.is_empty() {
        return SavePlan::None;
    }
    let user = norm(typed_user);
    let own: Vec<&SaveCandidate> = candidates
        .iter()
        .filter(|c| c.writable && c.personal)
        .collect();
    let targets: Vec<SaveTarget> = own.iter().map(|c| as_target(c)).collect();

    // 1. Logins saved under this very user name (for an empty one: logins saved with only a
    // password). A shared-vault login counts only when a user name was typed and it has that
    // exact name: an empty user name matches any login saved without one, which is exactly
    // what somebody could plant.
    let same: Vec<&SaveCandidate> = candidates
        .iter()
        .filter(|c| norm(&c.username) == user)
        .collect();
    if same.iter().any(|c| c.password == password) {
        return SavePlan::None;
    }
    let mine: Vec<&SaveCandidate> = same
        .into_iter()
        .filter(|c| !user.is_empty() || c.personal)
        .collect();
    if !mine.is_empty() {
        // Shared-vault logins under this user name: after the user's own, never preselected.
        let mut all = targets;
        all.extend(
            mine.iter()
                .filter(|c| c.writable && !c.personal)
                .map(|c| as_target(c)),
        );
        return match mine.iter().find(|c| c.writable && c.personal) {
            Some(first) => SavePlan::Update {
                reason: SaveReason::Same,
                target: first.id.clone(),
                targets: all,
            },
            None => SavePlan::Create { targets: all },
        };
    }

    // 2. A new user name: complete one of the user's own logins that was saved with only a
    // password (prefer the one with this password), else it is a new login.
    if !user.is_empty() {
        let blank = || own.iter().filter(|c| norm(&c.username).is_empty());
        let pick = blank()
            .find(|c| c.password == password)
            .or_else(|| blank().next());
        return match pick {
            Some(c) => SavePlan::Update {
                reason: SaveReason::Blank,
                target: c.id.clone(),
                targets,
            },
            None => SavePlan::Create { targets },
        };
    }

    // 3. No user name on the page: the password belongs to the user's only own login for the
    // site, if there is exactly one.
    if candidates.iter().any(|c| c.password == password) {
        return SavePlan::None;
    }
    match own.as_slice() {
        [only] => SavePlan::Update {
            reason: SaveReason::Only,
            target: only.id.clone(),
            targets,
        },
        _ => SavePlan::Create { targets },
    }
}

/// The target the prompt answered with, if this save offered it: [`NEW_LOGIN`] or the id of
/// one of `targets`. Anything else is refused (`None`): what gets applied is what the prompt
/// displayed, never a default worked out again later.
pub fn chosen_target(targets: &[SaveTarget], answer: &str) -> Option<String> {
    (answer == NEW_LOGIN || targets.iter().any(|t| t.id == answer)).then(|| answer.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own(id: &str, username: &str, password: &str) -> SaveCandidate {
        SaveCandidate {
            id: id.into(),
            name: format!("Login {id}"),
            username: username.into(),
            password: password.into(),
            writable: true,
            personal: true,
            vault: None,
        }
    }

    fn shared(id: &str, username: &str, password: &str) -> SaveCandidate {
        SaveCandidate {
            personal: false,
            vault: Some("Team".into()),
            ..own(id, username, password)
        }
    }

    fn ids(plan: &SavePlan) -> Vec<&str> {
        plan.targets().iter().map(|t| t.id.as_str()).collect()
    }

    #[test]
    fn rule_one_never_selects_a_shared_login() {
        let plan = plan_save(
            &[shared("s", "alex", "old"), own("b", "sam", "x")],
            "alex",
            "new",
        );
        assert_eq!(plan.target(), Some(NEW_LOGIN));
        assert_eq!(ids(&plan), ["b", "s"]);
        assert_eq!(plan.targets()[1].vault.as_deref(), Some("Team"));

        let plan = plan_save(
            &[shared("s", "alex", "old"), own("a", "alex", "old2")],
            " ALEX ",
            "new",
        );
        assert!(
            matches!(&plan, SavePlan::Update { reason: SaveReason::Same, target, .. } if target == "a")
        );
        assert_eq!(ids(&plan), ["a", "s"]);

        // An empty user name proves nothing: a shared login without one never counts.
        let plan = plan_save(&[shared("s", "", "x"), own("a", "alex", "old")], "", "new");
        assert!(matches!(
            plan,
            SavePlan::Update {
                reason: SaveReason::Only,
                ..
            }
        ));
        assert_eq!(
            plan_save(&[shared("s", "", "new")], "", "new"),
            SavePlan::None
        );
    }

    #[test]
    fn rules_two_and_three() {
        let plan = plan_save(&[own("a", "", "one"), own("b", "", "two")], "alex", "two");
        assert!(
            matches!(&plan, SavePlan::Update { reason: SaveReason::Blank, target, .. } if target == "b")
        );
        let plan = plan_save(&[own("a", "", "one"), own("b", "", "two")], "alex", "three");
        assert_eq!(plan.target(), Some("a"));
        assert_eq!(
            plan_save(&[own("a", "sam", "pw")], "alex", "pw").target(),
            Some(NEW_LOGIN)
        );
        assert_eq!(
            plan_save(&[own("a", "alex", "pw")], "", "pw"),
            SavePlan::None
        );
        assert!(matches!(
            plan_save(&[own("a", "alex", "old")], "", "new"),
            SavePlan::Update {
                reason: SaveReason::Only,
                ..
            }
        ));
        assert_eq!(
            plan_save(&[own("a", "alex", "a"), own("b", "sam", "b")], "", "new").target(),
            Some(NEW_LOGIN)
        );
        assert_eq!(
            plan_save(&[own("a", "alex", "old")], "alex", ""),
            SavePlan::None
        );
    }

    #[test]
    fn wire_shape_and_choice() {
        let plan = plan_save(
            &[own("a", "alex", "old"), shared("s", "alex", "x")],
            "alex",
            "new",
        );
        assert_eq!(
            serde_json::to_value(&plan).unwrap(),
            serde_json::json!({"action": "update", "reason": "same", "target": "a", "targets": [
                {"id": "a", "name": "Login a", "username": "alex"},
                {"id": "s", "name": "Login s", "username": "alex", "vault": "Team"},
            ]})
        );
        assert_eq!(
            serde_json::to_value(plan_save(&[], "alex", "pw")).unwrap(),
            serde_json::json!({"action": "create", "target": "new", "targets": []})
        );
        assert_eq!(
            serde_json::to_value(SavePlan::None).unwrap(),
            serde_json::json!({"action": "none"})
        );
        assert_eq!(chosen_target(plan.targets(), "s").as_deref(), Some("s"));
        assert_eq!(
            chosen_target(plan.targets(), NEW_LOGIN).as_deref(),
            Some(NEW_LOGIN)
        );
        assert_eq!(chosen_target(plan.targets(), "planted"), None);
        // A missing vault name reads "Shared vault".
        let unnamed = SaveCandidate {
            vault: None,
            ..shared("s", "alex", "x")
        };
        assert_eq!(
            as_target(&unnamed).vault.as_deref(),
            Some(crate::site::SHARED_VAULT)
        );
    }
}
