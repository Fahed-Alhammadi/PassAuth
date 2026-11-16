//! Signed sharing for the native apps (`passauth_core::sharing`; docs/ARCHITECTURE.md
//! "Signed sharing"): signing identities, sealing and signing vault keys for members,
//! member rosters, key pins and key epoch pins. Identities, records, member rows and
//! pins cross as JSON in the server's shape; member rosters as the JSON text the
//! server stores.

use std::sync::Arc;

use passauth_core::item::b64;
use passauth_core::keys;
use passauth_core::sharing::{
    self as core, EpochPin, IdentityRecord, KeyPins, PublicIdentity, RosterMemberInput,
    SignedRoster, VaultObservation, VerifiedIdentity,
};

use super::{Account, CoreError, R, VaultKey, json_in, json_out};

fn roster(json: &str) -> R<SignedRoster> {
    Ok(SignedRoster::parse(json)?)
}

fn info(v: &VerifiedIdentity) -> R<String> {
    json_out(&serde_json::json!({
        "user_id": v.user_id(),
        "signing": v.is_signing(),
        "hash": v.hash_b64(),
        "legacy_hash": b64(&v.legacy_hash()),
        "fingerprint": v.fingerprint(),
    }))
}

fn name<T: serde::Serialize>(v: &T) -> R<String> {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(CoreError::Invalid("unexpected value".into())),
    }
}

fn pins_or_empty(json: Option<String>) -> R<KeyPins> {
    json.map(|j| json_in(&j))
        .transpose()
        .map(Option::unwrap_or_default)
}

/// A vault key sealed to a member and the signature over the share.
#[derive(uniffi::Record)]
pub struct SignedShare {
    /// Send as the member's `sealed_key` / `wrapped_key`.
    pub sealed_key: String,
    /// Send as the share's `signature`.
    pub signature: String,
}

/// An account's own signing identity (private key inside; drop it when the vault locks).
#[derive(uniffi::Object)]
pub struct SigningIdentity(core::SigningIdentity);

/// `Account.new_signing_identity`'s answer.
#[derive(uniffi::Record)]
pub struct NewSigningIdentity {
    pub identity: Arc<SigningIdentity>,
    /// `{signing_key, identity_signature, wrapped_signing_key}`: upload once with
    /// `PUT /account/identity`.
    pub record_json: String,
}

#[uniffi::export]
impl SigningIdentity {
    pub fn user_id(&self) -> String {
        self.0.user_id().to_owned()
    }

    /// `{user_id, public_key, signing_key, identity_signature}`.
    pub fn public_identity_json(&self) -> R<String> {
        json_out(&self.0.public())
    }

    /// The identity fingerprint to show and compare out of band.
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }

    /// The identity hash, base64url.
    pub fn identity_hash(&self) -> String {
        b64(&self.0.identity_hash())
    }

    /// Sign a share of an already sealed key (`sealed_key`, the exact text sent).
    pub fn sign_share(
        &self,
        vault_id: String,
        recipient_json: String,
        role: String,
        key_epoch: u64,
        sealed_key: String,
    ) -> R<String> {
        let recipient: PublicIdentity = json_in(&recipient_json)?;
        Ok(self
            .0
            .sign_share(&vault_id, &recipient, &role, key_epoch, &sealed_key)?)
    }

    /// Seal `vault_key` to the member `recipient_json` (a member or lookup row; its
    /// identity must verify, and the app checks its key pin first) and sign the share
    /// at `key_epoch` (for a key replacement: the new epoch) with `role`.
    pub fn seal_and_sign_share(
        &self,
        vault_key: Arc<VaultKey>,
        vault_id: String,
        recipient_json: String,
        role: String,
        key_epoch: u64,
    ) -> R<SignedShare> {
        let recipient: PublicIdentity = json_in(&recipient_json)?;
        let s =
            self.0
                .seal_and_sign_share(&vault_key.0, &vault_id, &recipient, &role, key_epoch)?;
        Ok(SignedShare {
            sealed_key: s.sealed_key,
            signature: s.signature,
        })
    }

    /// Sign the next member roster of `vault_id` at `key_epoch` (whose key is
    /// `vault_key`) listing `members_json` (member rows after the change): version
    /// `previous.version + 1` (`previous` = the trusted roster's JSON text, or none for
    /// version 1). `reviewed` = `roster_review(…)`'s `digest` of the list the user saw
    /// (another list: `ReviewMismatch`). Returns the roster's JSON text, sent as `roster`.
    pub fn sign_roster(
        &self,
        vault_key: Arc<VaultKey>,
        vault_id: String,
        previous: Option<String>,
        key_epoch: u64,
        members_json: String,
        reviewed: String,
    ) -> R<String> {
        let previous = previous.map(|t| roster(&t)).transpose()?;
        let members: Vec<RosterMemberInput> = json_in(&members_json)?;
        Ok(self
            .0
            .sign_roster(
                &vault_key.0,
                &vault_id,
                previous.as_ref(),
                key_epoch,
                &members,
                &reviewed,
            )?
            .to_json()?)
    }
}

#[uniffi::export]
impl Account {
    /// A new signing identity (when `/sync` `user.identity` is null).
    pub fn new_signing_identity(&self) -> R<NewSigningIdentity> {
        let new = self.0.new_signing_identity()?;
        Ok(NewSigningIdentity {
            identity: Arc::new(SigningIdentity(new.identity)),
            record_json: json_out(&new.record)?,
        })
    }

    /// This account's signing identity from `/sync` `user.identity` (JSON).
    /// `IdentityMismatch` when the server lists keys that aren't this account's.
    pub fn open_signing_identity(&self, record_json: String) -> R<Arc<SigningIdentity>> {
        let record: IdentityRecord = json_in(&record_json)?;
        Ok(Arc::new(SigningIdentity(
            self.0.open_signing_identity(&record)?,
        )))
    }

    /// This account without a signing key, as JSON.
    pub fn legacy_identity_json(&self) -> R<String> {
        json_out(&self.0.legacy_identity())
    }

    /// Seal key pins (JSON) as version `seq` for `PUT /account/key-pins`.
    pub fn seal_key_pins(&self, pins_json: String, seq: u64) -> R<String> {
        let pins: KeyPins = json_in(&pins_json)?;
        Ok(self.0.seal_key_pins(&pins, seq)?)
    }

    /// Open key pins from `GET /account/key-pins`; `Rollback` for another version.
    pub fn open_key_pins(&self, sealed: String, seq: u64) -> R<String> {
        json_out(&self.0.open_key_pins(&sealed, seq)?)
    }
}

#[uniffi::export]
impl VaultKey {
    /// Seal this vault key to a member's X25519 public key (base64url), without a
    /// signature: for servers without `signed_sharing` and vaults without a member
    /// roster. With signing, use `SigningIdentity.seal_and_sign_share`.
    pub fn share_to(&self, vault_id: String, recipient_public_key: String) -> R<String> {
        Ok(keys::share_vault_key(
            &vault_id,
            &self.0,
            &recipient_public_key,
        )?)
    }

    /// Wrap this key with the account's own key (`key_kind` `account`, after a key
    /// replacement by the vault's owner). The v1 format every released app reads
    /// (epoch-bound v2 wraps are read by `Account.open_vault_key` but not written yet).
    pub fn wrap_for(&self, account: Arc<Account>, vault_id: String) -> R<String> {
        Ok(account.0.wrap_vault_key(&self.0, &vault_id)?)
    }

    /// The key's commitment at `key_epoch` (what a member roster carries).
    pub fn commitment(&self, vault_id: String, key_epoch: u64) -> R<String> {
        Ok(core::key_commitment(&self.0, &vault_id, key_epoch)?)
    }

    /// The key's id (independent of the epoch), base64url.
    pub fn key_id(&self, vault_id: String) -> R<String> {
        Ok(core::key_id(&self.0, &vault_id)?)
    }

    /// The vault's current key as the epoch pins compare it: `{key_epoch, key_id}` (JSON;
    /// `key_epoch` = the row's).
    pub fn epoch_pin_json(&self, vault_id: String, key_epoch: u64) -> R<String> {
        json_out(&EpochPin::of(&self.0, &vault_id, key_epoch)?)
    }

    /// Whether this is the key the member roster commits to, and the roster is
    /// `vault_id`'s.
    pub fn matches_roster(&self, vault_id: String, roster_json: String) -> R<bool> {
        Ok(roster(&roster_json)?.commits_to(&vault_id, &self.0)?)
    }
}

/// Check a public identity (JSON): `{user_id, signing, hash, legacy_hash, fingerprint}`.
#[uniffi::export]
pub fn verify_identity(identity_json: String) -> R<String> {
    let identity: PublicIdentity = json_in(&identity_json)?;
    info(&identity.verify()?)
}

/// Check a share signature; returns the signer's identity info (JSON).
#[uniffi::export]
pub fn verify_share(
    vault_id: String,
    recipient_json: String,
    role: String,
    key_epoch: u64,
    sealed_key: String,
    signer_json: String,
    signature: String,
) -> R<String> {
    let recipient: PublicIdentity = json_in(&recipient_json)?;
    let signer: PublicIdentity = json_in(&signer_json)?;
    info(&core::verify_share(
        &vault_id,
        &recipient,
        &role,
        key_epoch,
        &sealed_key,
        &signer,
        &signature,
    )?)
}

/// Check a member roster chain of `vault_id` (`newer`: JSON texts after `trusted`,
/// oldest first, at most 1000) ending exactly at `latest` (the row's `member_roster`);
/// returns the newest roster's JSON text.
#[uniffi::export]
pub fn verify_roster_chain(
    vault_id: String,
    trusted: Option<String>,
    newer: Vec<String>,
    latest: String,
) -> R<String> {
    if newer.len() > core::MAX_ROSTER_CHAIN {
        return Err(CoreError::TooLarge);
    }
    let trusted = trusted.map(|t| roster(&t)).transpose()?;
    let latest = roster(&latest)?;
    let newer = newer.iter().map(|r| roster(r)).collect::<R<Vec<_>>>()?;
    Ok(core::verify_roster_chain(&vault_id, trusted.as_ref(), &newer, &latest)?.to_json()?)
}

/// `{"status": "unsigned" | "same" | "fetch", "after"}` for the server's latest roster
/// of `vault_id` against the one this device trusted last.
#[uniffi::export]
pub fn roster_head(
    vault_id: String,
    remembered: Option<String>,
    latest: Option<String>,
) -> R<String> {
    let remembered = remembered.map(|t| roster(&t)).transpose()?;
    let latest = latest.map(|t| roster(&t)).transpose()?;
    json_out(&core::roster_head(
        &vault_id,
        remembered.as_ref(),
        latest.as_ref(),
    )?)
}

/// `{unknown, identity_changed, role_changed, missing}` (JSON) for the server's member
/// rows against a trusted roster.
#[uniffi::export]
pub fn compare_members(roster_json: String, members_json: String) -> R<String> {
    let members: Vec<RosterMemberInput> = json_in(&members_json)?;
    json_out(&core::compare_members(&roster(&roster_json)?, &members))
}

/// The role a trusted roster gives the identity as a member (its full or legacy hash).
#[uniffi::export]
pub fn roster_member_role(roster_json: String, identity_json: String) -> R<Option<String>> {
    let identity: PublicIdentity = json_in(&identity_json)?;
    Ok(roster(&roster_json)?.member_role(&identity)?)
}

/// The role a trusted roster gives a signer: only when listed with exactly its full
/// (signing) identity; a legacy listing carries no authority.
#[uniffi::export]
pub fn roster_signer_role(roster_json: String, signer_json: String) -> R<Option<String>> {
    let signer: PublicIdentity = json_in(&signer_json)?;
    Ok(roster(&roster_json)?.signer_role(&signer)?)
}

/// The review (JSON `{vault_id, version, first, blocked, members, missing, digest}`) of
/// the next roster of `vault_id` that `signer_json` (this account's public identity)
/// would sign for `members_json` after `previous` (the trusted roster's JSON text, or
/// none: version 1, always shown), with the account's key pins.
#[uniffi::export]
pub fn roster_review(
    vault_id: String,
    previous: Option<String>,
    signer_json: String,
    members_json: String,
    pins_json: Option<String>,
) -> R<String> {
    let previous = previous.map(|t| roster(&t)).transpose()?;
    let signer: PublicIdentity = json_in(&signer_json)?;
    let members: Vec<RosterMemberInput> = json_in(&members_json)?;
    let pins = pins_or_empty(pins_json)?;
    json_out(&core::roster_review(
        &vault_id,
        previous.as_ref(),
        &signer,
        &members,
        &pins,
    )?)
}

/// "new" | "same" | "newer" | "older" | "conflict" for a vault's current key
/// (`{key_epoch, key_id}`) against a pin.
#[uniffi::export]
pub fn epoch_check(pinned_json: Option<String>, current_json: String) -> R<String> {
    let pinned: Option<EpochPin> = pinned_json.map(|j| json_in(&j)).transpose()?;
    let current: EpochPin = json_in(&current_json)?;
    name(&core::epoch_check(pinned.as_ref(), &current))
}

/// "new" | "match" | "changed" | "upgraded" | "email_conflict" for an identity against
/// the key pins (`email`: the one the server lists with it).
#[uniffi::export]
pub fn pin_check(
    pins_json: Option<String>,
    identity_json: String,
    email: Option<String>,
) -> R<String> {
    let identity: PublicIdentity = json_in(&identity_json)?;
    name(&pins_or_empty(pins_json)?.check_identity(&identity, email.as_deref())?)
}

/// The key pins (JSON) with the identity pinned (`now`: Unix seconds).
#[uniffi::export]
pub fn pin_set(
    pins_json: Option<String>,
    identity_json: String,
    email: String,
    verified: bool,
    now: i64,
) -> R<String> {
    let identity: PublicIdentity = json_in(&identity_json)?;
    json_out(&pins_or_empty(pins_json)?.set(&identity, &email, verified, now)?)
}

/// Merge this device's pins (`ours_json`) into the server's newest (`base_json`).
#[uniffi::export]
pub fn merge_pins(base_json: String, ours_json: String) -> R<String> {
    let base: KeyPins = json_in(&base_json)?;
    let ours: KeyPins = json_in(&ours_json)?;
    json_out(&base.merge(&ours)?)
}

/// A vault's current key (`{key_epoch, key_id}`) against the account's epoch pin for it,
/// with the trusted roster version: "new" | "same" | "newer" | "older" | "conflict" |
/// "downgraded".
#[uniffi::export]
pub fn pins_epoch_check(
    pins_json: Option<String>,
    vault_id: String,
    current_json: String,
    roster_version: Option<u64>,
) -> R<String> {
    let current: EpochPin = json_in(&current_json)?;
    name(&pins_or_empty(pins_json)?.check_epoch(&vault_id, &current, roster_version))
}

/// The key pins (JSON) with `current_json` pinned (accepted) for the vault when new or
/// newer (`roster_version`: the trusted roster's). `Rollback` for a vault the account
/// left that doesn't qualify to come back.
#[uniffi::export]
pub fn pins_set_epoch(
    pins_json: Option<String>,
    vault_id: String,
    current_json: String,
    roster_version: Option<u64>,
) -> R<String> {
    let current: EpochPin = json_in(&current_json)?;
    json_out(&pins_or_empty(pins_json)?.set_epoch(&vault_id, &current, roster_version)?)
}

/// The key pins (JSON) with the vault left or deleted by this account (a tombstone with
/// the trusted roster version then, 0: none).
#[uniffi::export]
pub fn pins_leave(
    pins_json: Option<String>,
    vault_id: String,
    roster_version: u64,
    now: i64,
) -> R<String> {
    json_out(&pins_or_empty(pins_json)?.leave(&vault_id, roster_version, now)?)
}

/// The key pins (JSON) with the grandfathered vault ids written (once).
/// `created_identity`: this unlock created the account's signing identity (`user.identity`
/// was null, `PUT /account/identity` answered `created: true`); false (identity without
/// key pins: "trust memory missing") writes an empty list.
#[uniffi::export]
pub fn pins_grandfather(
    pins_json: Option<String>,
    vault_ids: Vec<String>,
    created_identity: bool,
) -> R<String> {
    json_out(&pins_or_empty(pins_json)?.grandfather(&vault_ids, created_identity)?)
}

/// What to do with a vault row (`observation_json`: `{vault_id, key_kind, key,
/// roster_version, roster_hash?, signed_share, paused}`): JSON `{"status": "ok", "epoch",
/// "trust", "pin"}` | `{"status": "consent", "rejoin", "replaced"}` | `{"status":
/// "refused", "reason"}`.
#[uniffi::export]
pub fn pins_admit(pins_json: Option<String>, observation_json: String) -> R<String> {
    let observation: VaultObservation = json_in(&observation_json)?;
    json_out(&pins_or_empty(pins_json)?.admit(&observation)?)
}

/// `pins_admit`, and the key pins with what it says to pin applied: JSON `{admission,
/// pins, changed}` (write the pins once per sync if any was `changed`).
#[uniffi::export]
pub fn pins_observe(pins_json: Option<String>, observation_json: String) -> R<String> {
    let observation: VaultObservation = json_in(&observation_json)?;
    json_out(&pins_or_empty(pins_json)?.observe(&observation)?)
}

/// A member roster's hash (base64url; the observation's `roster_hash`).
#[uniffi::export]
pub fn roster_hash(roster_json: String) -> R<String> {
    Ok(roster(&roster_json)?.hash()?)
}

/// An email as key pins compare it (trimmed, NFKC, lower case, IDNA ASCII domain); show
/// pinned emails in this form.
#[uniffi::export]
pub fn normalize_email(email: String) -> String {
    core::normalize_email(&email)
}

/// Whether an `account` wrap of the vault may be a legacy v1 wrap (no signed history).
#[uniffi::export]
pub fn pins_legacy_wrap_allowed(pins_json: Option<String>, vault_id: String) -> R<bool> {
    Ok(pins_or_empty(pins_json)?.legacy_wrap_allowed(&vault_id))
}

/// "new" | "match" | "mismatch" for the identity `/sync` lists for the account itself
/// (its hash; none when `user.identity` is null).
#[uniffi::export]
pub fn pins_check_own_identity(pins_json: Option<String>, listed: Option<String>) -> R<String> {
    name(&pins_or_empty(pins_json)?.check_own_identity(listed.as_deref()))
}

/// The key pins (JSON) with the account's own identity hash remembered (once; another
/// one is `IdentityMismatch`).
#[uniffi::export]
pub fn pins_set_own_identity(pins_json: Option<String>, hash: String) -> R<String> {
    json_out(&pins_or_empty(pins_json)?.set_own_identity(&hash)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_account, new_id};

    fn member(identity_json: &str, role: &str) -> serde_json::Value {
        let mut v: serde_json::Value = serde_json::from_str(identity_json).unwrap();
        v["role"] = role.into();
        v
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    /// The flow a phone runs to replace a shared vault's key: review, seal and sign for
    /// every member, sign the roster, and the member checks it all.
    #[test]
    fn phones_seal_sign_and_check_shares_and_rosters() {
        let owner =
            create_account(new_id().unwrap(), "correct horse battery".into(), false).unwrap();
        let bob = create_account(new_id().unwrap(), "correct horse battery".into(), false).unwrap();
        let (owner, bob) = (owner.account, bob.account);
        let mine = owner.new_signing_identity().unwrap();
        let theirs = bob.new_signing_identity().unwrap();
        assert!(json(&mine.record_json)["x25519_signature"].is_string());
        // The record opens again; another account's doesn't.
        let again = owner
            .open_signing_identity(mine.record_json.clone())
            .unwrap();
        assert_eq!(again.fingerprint(), mine.identity.fingerprint());
        assert_eq!(
            again.public_identity_json().unwrap(),
            mine.identity.public_identity_json().unwrap()
        );
        assert!(matches!(
            bob.open_signing_identity(mine.record_json.clone()),
            Err(CoreError::DecryptFailed)
        ));

        let vault = new_id().unwrap();
        let new_key = owner.new_vault_key(vault.clone()).unwrap();
        let key = new_key.key.clone();
        // Account wraps are written as v1 (released apps read only that): they open under
        // any epoch, only when v1 is allowed.
        for epoch in [0, 4] {
            assert!(
                owner
                    .open_vault_key(
                        vault.clone(),
                        new_key.wrapped.clone(),
                        "account".into(),
                        epoch,
                        true
                    )
                    .is_ok()
            );
        }
        assert!(
            owner
                .open_vault_key(
                    vault.clone(),
                    new_key.wrapped.clone(),
                    "account".into(),
                    0,
                    false
                )
                .is_err()
        );
        let rewrapped = key.wrap_for(owner.clone(), vault.clone()).unwrap();
        assert!(
            owner
                .open_vault_key(vault.clone(), rewrapped, "account".into(), 4, true)
                .is_ok()
        );
        let owner_pub = mine.identity.public_identity_json().unwrap();
        let bob_pub = theirs.identity.public_identity_json().unwrap();

        let share = mine
            .identity
            .seal_and_sign_share(
                key.clone(),
                vault.clone(),
                bob_pub.clone(),
                "write".into(),
                1,
            )
            .unwrap();
        let opened = bob
            .open_vault_key(
                vault.clone(),
                share.sealed_key.clone(),
                "sealed".into(),
                0,
                false,
            )
            .unwrap();
        assert_eq!(opened.0.as_bytes(), key.0.as_bytes());
        let signer = json(
            &verify_share(
                vault.clone(),
                bob_pub.clone(),
                "write".into(),
                1,
                share.sealed_key.clone(),
                owner_pub.clone(),
                share.signature.clone(),
            )
            .unwrap(),
        );
        assert_eq!(signer["fingerprint"], mine.identity.fingerprint());
        assert!(matches!(
            verify_share(
                vault.clone(),
                bob_pub.clone(),
                "admin".into(),
                1,
                share.sealed_key.clone(),
                owner_pub.clone(),
                share.signature.clone()
            ),
            Err(CoreError::BadSignature)
        ));
        // Unsigned sealing still works (servers without signed sharing).
        let plain = key.share_to(vault.clone(), bob.public_key()).unwrap();
        assert!(
            bob.open_vault_key(vault.clone(), plain, "sealed".into(), 0, false)
                .is_ok()
        );

        // Review, then sign exactly what was reviewed.
        let mut bob_row = member(&bob_pub, "write");
        bob_row["email"] = "bob@example.com".into();
        let members = serde_json::json!([member(&owner_pub, "owner"), bob_row]).to_string();
        let review = json(
            &roster_review(
                vault.clone(),
                None,
                owner_pub.clone(),
                members.clone(),
                None,
            )
            .unwrap(),
        );
        assert_eq!(review["first"], true);
        assert_eq!(review["blocked"], false);
        let bob_id = json(&bob_pub)["user_id"].clone();
        let reviewed_bob = review["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["user_id"] == bob_id)
            .unwrap();
        assert_eq!(reviewed_bob["pin"], "new");
        assert_eq!(reviewed_bob["listed_email"], "bob@example.com");
        let digest = review["digest"].as_str().unwrap().to_owned();
        assert!(matches!(
            mine.identity.sign_roster(
                key.clone(),
                vault.clone(),
                None,
                1,
                serde_json::json!([member(&owner_pub, "owner")]).to_string(),
                digest.clone()
            ),
            Err(CoreError::ReviewMismatch)
        ));
        let roster_json = mine
            .identity
            .sign_roster(key.clone(), vault.clone(), None, 1, members.clone(), digest)
            .unwrap();
        assert_eq!(
            verify_roster_chain(
                vault.clone(),
                None,
                vec![roster_json.clone()],
                roster_json.clone()
            )
            .unwrap(),
            roster_json
        );
        assert!(matches!(
            verify_roster_chain(
                new_id().unwrap(),
                None,
                vec![roster_json.clone()],
                roster_json.clone()
            ),
            Err(CoreError::Invalid(_))
        ));
        assert!(
            opened
                .matches_roster(vault.clone(), roster_json.clone())
                .unwrap()
        );
        assert!(
            !opened
                .matches_roster(new_id().unwrap(), roster_json.clone())
                .unwrap()
        );
        assert_eq!(
            roster_member_role(roster_json.clone(), bob_pub.clone())
                .unwrap()
                .as_deref(),
            Some("write")
        );
        assert_eq!(
            roster_signer_role(roster_json.clone(), bob.legacy_identity_json().unwrap()).unwrap(),
            None
        );
        let diff = json(&compare_members(roster_json.clone(), members).unwrap());
        assert_eq!(diff["unknown"], serde_json::json!([]));
        let head = json(
            &roster_head(
                vault.clone(),
                Some(roster_json.clone()),
                Some(roster_json.clone()),
            )
            .unwrap(),
        );
        assert_eq!(head["status"], "same");
        // Bob (a writer) can sign a roster making himself admin, but it doesn't follow
        // from version 1: the core refuses to sign it.
        let promoted =
            serde_json::json!([member(&owner_pub, "owner"), member(&bob_pub, "admin")]).to_string();
        assert!(matches!(
            roster_review(
                vault.clone(),
                Some(roster_json.clone()),
                bob_pub.clone(),
                promoted,
                None
            ),
            Err(CoreError::RosterUnauthorized)
        ));

        // Epoch pins: key ids, retired keys, signed since.
        let pin = key.epoch_pin_json(vault.clone(), 1).unwrap();
        assert_eq!(json(&pin)["key_id"], key.key_id(vault.clone()).unwrap());
        assert_eq!(epoch_check(None, pin.clone()).unwrap(), "new");
        assert_eq!(epoch_check(Some(pin.clone()), pin.clone()).unwrap(), "same");
        assert_eq!(
            pins_epoch_check(None, vault.clone(), pin.clone(), None).unwrap(),
            "new"
        );
        let with_epoch = pins_set_epoch(None, vault.clone(), pin.clone(), Some(1)).unwrap();
        assert_eq!(
            pins_epoch_check(
                Some(with_epoch.clone()),
                vault.clone(),
                pin.clone(),
                Some(1)
            )
            .unwrap(),
            "same"
        );
        assert_eq!(
            pins_epoch_check(Some(with_epoch.clone()), vault.clone(), pin.clone(), None).unwrap(),
            "downgraded"
        );
        // v1 account wraps stay readable while the apps write them.
        assert!(pins_legacy_wrap_allowed(Some(with_epoch.clone()), vault.clone()).unwrap());
        let other = owner.new_vault_key(vault.clone()).unwrap().key;
        let newer = other.epoch_pin_json(vault.clone(), 2).unwrap();
        let raised =
            pins_set_epoch(Some(with_epoch.clone()), vault.clone(), newer, Some(2)).unwrap();
        let relabelled = key.epoch_pin_json(vault.clone(), 3).unwrap();
        assert_eq!(
            pins_epoch_check(Some(raised.clone()), vault.clone(), relabelled, Some(2)).unwrap(),
            "older"
        );
        let sealed = owner.seal_key_pins(raised.clone(), 1).unwrap();
        let reopened = owner.open_key_pins(sealed, 1).unwrap();
        assert_eq!(json(&reopened)["epochs"], json(&raised)["epochs"]);

        // Admission: a sealed vault never accepted needs consent; accepted, it's fine;
        // left, it's refused; grandfathered only unsigned and only when the identity was
        // created at this unlock.
        let row = |signed: bool| {
            serde_json::json!({
                "vault_id": vault, "key_kind": "sealed",
                "key": json(&key.epoch_pin_json(vault.clone(), 1).unwrap()),
                "roster_version": if signed { Some(1) } else { None },
                "signed_share": signed, "paused": false,
            })
            .to_string()
        };
        let observe =
            |pins: Option<String>, signed: bool| json(&pins_admit(pins, row(signed)).unwrap());
        assert_eq!(observe(None, true)["status"], "consent");
        let ok = observe(Some(with_epoch.clone()), true);
        assert_eq!(
            (ok["status"].as_str(), ok["pin"].as_bool()),
            (Some("ok"), Some(false))
        );
        let left = pins_leave(Some(with_epoch.clone()), vault.clone(), 1, 10).unwrap();
        assert_eq!(observe(Some(left.clone()), true)["reason"], "left");
        let grand = pins_grandfather(None, vec![vault.clone()], true).unwrap();
        assert_eq!(observe(Some(grand.clone()), false)["status"], "ok");
        assert_eq!(observe(Some(grand.clone()), true)["status"], "consent");
        let withheld = pins_grandfather(None, vec![vault.clone()], false).unwrap();
        assert_eq!(observe(Some(withheld), false)["status"], "consent");
        let observed = json(&pins_observe(Some(grand), row(false)).unwrap());
        assert_eq!(observed["changed"], true);
        assert_eq!(observed["admission"]["pin"], true);
        assert_eq!(
            observed["pins"]["epochs"][&vault]["key_id"],
            json(&key.epoch_pin_json(vault.clone(), 1).unwrap())["key_id"]
        );
        assert_eq!(roster_hash(roster_json.clone()).unwrap().len(), 43);
        assert_eq!(
            normalize_email(" ＢＯＢ@Bücher.example".into()),
            "bob@xn--bcher-kva.example"
        );

        // Own identity, remembered once.
        let own = mine.identity.identity_hash();
        assert_eq!(
            pins_check_own_identity(None, Some(own.clone())).unwrap(),
            "new"
        );
        let pins = pins_set_own_identity(None, own.clone()).unwrap();
        assert_eq!(
            pins_check_own_identity(Some(pins.clone()), None).unwrap(),
            "mismatch"
        );
        assert!(matches!(
            pins_set_own_identity(Some(pins), theirs.identity.identity_hash()),
            Err(CoreError::IdentityMismatch)
        ));

        // Key pins: pin, check, seal, open.
        assert_eq!(pin_check(None, bob_pub.clone(), None).unwrap(), "new");
        let pins = pin_set(None, bob_pub.clone(), "bob@example.com".into(), false, 1).unwrap();
        assert_eq!(
            pin_check(Some(pins.clone()), bob_pub.clone(), None).unwrap(),
            "match"
        );
        assert_eq!(
            pin_check(
                Some(pins.clone()),
                bob.legacy_identity_json().unwrap(),
                None
            )
            .unwrap(),
            "changed"
        );
        assert_eq!(
            pin_check(
                Some(pins.clone()),
                owner_pub.clone(),
                Some("BOB@example.com".into())
            )
            .unwrap(),
            "email_conflict"
        );
        let merged = merge_pins(pins.clone(), pins.clone()).unwrap();
        let sealed = owner.seal_key_pins(merged, 3).unwrap();
        let back = json(&owner.open_key_pins(sealed.clone(), 3).unwrap());
        assert_eq!(back["version"], 3);
        assert!(matches!(
            owner.open_key_pins(sealed, 2),
            Err(CoreError::Rollback)
        ));
        let verified = json(&verify_identity(bob_pub).unwrap());
        assert_eq!(verified["signing"], true);
    }
}
