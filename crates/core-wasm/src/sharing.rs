//! Signed sharing (`passauth_core::sharing`; docs/ARCHITECTURE.md "Signed sharing"):
//! signing identities, share signatures, member rosters, key pins and key epoch pins.
//!
//! Objects (identities, records, pins, member rows) cross as plain JavaScript objects
//! in the server's JSON shape; member rosters as the JSON text the server stores.
//! String parameters are checked first, before any object is read (see the crate
//! docs).

use passauth_core::sharing::{
    self as core, EpochPin, IdentityRecord, KeyPins, PublicIdentity, RosterMemberInput,
    SignedRoster, VaultObservation,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{Account, R, VaultKey, from_js, js_err, opt_string, string, to_js};

#[wasm_bindgen(typescript_custom_section)]
const SHARING_TYPES: &str = r#"
/** A user's public identity as the server lists it (`signing_key`/`identity_signature`/`x25519_signature` all null: legacy). */
export interface PublicIdentity { user_id: string; public_key: string; signing_key?: string | null; identity_signature?: string | null; x25519_signature?: string | null }
/** `PUT /account/identity` body and `/sync` `user.identity`. */
export interface IdentityRecord { signing_key: string; identity_signature: string; x25519_signature: string; wrapped_signing_key: string }
/** `verifyIdentity`'s answer: hashes base64url; `fingerprint` over user id and both keys. */
export interface IdentityInfo { user_id: string; signing: boolean; hash: string; legacy_hash: string; fingerprint: string }
/** A vault key sealed to a member and the share signature. */
export interface SignedShare { sealed_key: string; signature: string }
/** A member for `rosterReview` / `signRoster` / `compareMembers`: a member row of `GET /vaults/{id}/members` (`email` as the server lists it, never signed). */
export interface RosterMemberInput extends PublicIdentity { role: string; email?: string | null }
/** `rosterHead`'s answer. */
export type RosterHead = { status: "unsigned" } | { status: "same" } | { status: "fetch"; after: number };
/** `compareMembers`' answer (user ids). Clean when `unknown`, `identity_changed` and `role_changed` are empty. */
export interface MemberDiff { unknown: string[]; identity_changed: string[]; role_changed: string[]; missing: string[] }
/** One member of a `RosterReview`. Show `pinned_email` first; `listed_email` (the server's) as "listed by your server as …" when it differs, never next to "Verified". */
export interface ReviewMember { user_id: string; role: string; identity: string; fingerprint: string; is_self: boolean; pin: PinStatus; verified: boolean; pinned_email: string | null; listed_email: string | null; change: "same" | "added" | "identity_changed" | "role_changed" }
/** A trusted-roster member the server no longer lists (confirm by user id). */
export interface ReviewMissing { user_id: string; role: string; identity: string; pinned_email: string | null }
/** `rosterReview`'s answer: show it (always when `first`), stop when `blocked`, sign with `digest`. */
export interface RosterReview { vault_id: string; version: number; first: boolean; blocked: boolean; members: ReviewMember[]; missing: ReviewMissing[]; digest: string }
/** One pinned identity. */
export interface KeyPin { user_id: string; email: string; public_key: string; signing_key?: string | null; identity: string; verified: boolean; first_seen: number; [extra: string]: unknown }
/** A vault the account left or deleted. */
export interface Tombstone { pin: EpochPin | null; roster_version: number; left_at: number }
/** An account's key pins. `epochs` keys = the vaults it accepted. */
export interface KeyPins { version: number; pins: KeyPin[]; epochs?: Record<string, EpochPin>; own_identity?: string | null; grandfathered?: string[] | null; left?: Record<string, Tombstone>; [extra: string]: unknown }
/** A vault's key: `{key_epoch, key_id}` as `VaultKey.epochPin` gives it; as a pin also the retired key ids (12-byte prefixes), since which roster version the vault is signed, the highest trusted roster version with its hash, the roster version a re-join (after leaving) accepted, and whether the account held it with its own wrap. */
export interface EpochPin { key_epoch: number; key_id: string; retired?: string[]; signed_since?: number | null; roster_version_max?: number | null; roster_hash?: string | null; rejoined_at?: number | null; own?: boolean }
/** A vault row for `pinsAdmit` / `pinsObserve` / `pinsAccept`, after its key opened and its share and roster chain were checked (`roster_hash`: `rosterHash` of the trusted roster). `signed_share` and `paused` are required. `chain_hashes` (`{"<version>": rosterHash}` of the trusted roster the chain started from and every newer roster verified now): send it whenever a chain was fetched (also an invitation's from version 1); the pinned highest roster must be in it with its hash, else `roster_forked`. */
export interface VaultObservation { vault_id: string; key_kind: "account" | "sealed"; key: EpochPin | null; roster_version: number | null; roster_hash?: string | null; chain_hashes?: Record<string, string> | null; signed_share: boolean; paused: boolean }
/** `pinsAdmit`'s verdict (`ok.pin`: write what it says to pin; `consent.replaced`: a new key on a vault never seen signed, unsigned or signed by anyone; `consent.own`: the account held this vault with its own key wrap: warn that a personal vault now comes as one someone else sealed). Accepting a consent = `pinsAccept`. */
export type Admission =
  | { status: "ok"; epoch: "new" | "same" | "newer"; trust: "own" | "signed" | "unsigned"; pin: boolean }
  | { status: "consent"; rejoin: boolean; replaced: boolean; own: boolean }
  | { status: "refused"; reason: "missing_epoch" | "paused" | "left" | "older" | "conflict" | "downgraded" | "roster_forked" };
/** `pinsObserve`'s answer: the verdict and the key pins with it applied (`changed`: write them). */
export interface Observed { admission: Admission; pins: KeyPins; changed: boolean }
/** "new" | "match" | "changed" | "upgraded" | "email_conflict" */
export type PinStatus = string;
/** "new" | "same" | "newer" | "older" | "conflict" | "downgraded" */
export type EpochStatus = string;
/** "new" | "match" | "mismatch" */
export type OwnIdentityStatus = string;
"#;

/// A whole number from JavaScript, 0 to 2^53 − 1.
pub(crate) fn whole(n: f64) -> Option<u64> {
    (n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_991.0)
        .then_some(n as u64)
}

fn number(n: f64, what: &str) -> R<u64> {
    whole(n).ok_or_else(|| JsError::new(&format!("invalid {what}")))
}

fn enum_name<T: Serialize>(v: &T) -> R<String> {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(JsError::new("unexpected value")),
    }
}

fn roster(json: &str) -> R<SignedRoster> {
    SignedRoster::parse(json).map_err(js_err)
}

fn opt_roster(v: JsValue) -> R<Option<SignedRoster>> {
    opt_string(v)?.map(|t| roster(&t)).transpose()
}

fn opt_number(n: Option<f64>, what: &str) -> R<Option<u64>> {
    n.map(|n| number(n, what)).transpose()
}

/// An account's own signing identity (`Account.newSigningIdentity` /
/// `openSigningIdentity`). The private key stays in WASM memory; call `free()`
/// when the vault locks.
#[wasm_bindgen]
pub struct SigningIdentity(core::SigningIdentity);

#[wasm_bindgen]
impl SigningIdentity {
    #[wasm_bindgen(js_name = userId)]
    pub fn user_id(&self) -> String {
        self.0.user_id().to_owned()
    }

    /// The public identity others verify (`user_id`, `public_key`, `signing_key`,
    /// `identity_signature`).
    #[wasm_bindgen(js_name = publicIdentity, unchecked_return_type = "PublicIdentity")]
    pub fn public_identity(&self) -> R<JsValue> {
        to_js(&self.0.public())
    }

    /// The identity fingerprint to show in Settings and compare out of band.
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }

    /// The identity hash, base64url.
    #[wasm_bindgen(js_name = identityHash)]
    pub fn identity_hash(&self) -> String {
        passauth_core::item::b64(&self.0.identity_hash())
    }

    /// Sign a share of an already sealed key (`sealedKey`, the exact text sent).
    #[wasm_bindgen(js_name = signShare)]
    pub fn sign_share(
        &self,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] recipient: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] role: JsValue,
        #[wasm_bindgen(js_name = "keyEpoch")] key_epoch: f64,
        #[wasm_bindgen(js_name = "sealedKey", unchecked_param_type = "string")] sealed_key: JsValue,
    ) -> R<String> {
        let (vault_id, role, sealed_key) = (string(vault_id)?, string(role)?, string(sealed_key)?);
        let recipient: PublicIdentity = from_js(recipient)?;
        self.0
            .sign_share(
                &vault_id,
                &recipient,
                &role,
                number(key_epoch, "key epoch")?,
                &sealed_key,
            )
            .map_err(js_err)
    }

    /// Seal `vaultKey` to `recipient` (their identity must verify; check its pin first)
    /// and sign the share: `{sealed_key, signature}`.
    #[wasm_bindgen(js_name = sealAndSignShare, unchecked_return_type = "SignedShare")]
    pub fn seal_and_sign_share(
        &self,
        #[wasm_bindgen(js_name = "vaultKey")] vault_key: &VaultKey,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] recipient: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] role: JsValue,
        #[wasm_bindgen(js_name = "keyEpoch")] key_epoch: f64,
    ) -> R<JsValue> {
        let (vault_id, role) = (string(vault_id)?, string(role)?);
        let recipient: PublicIdentity = from_js(recipient)?;
        to_js(
            &self
                .0
                .seal_and_sign_share(
                    &vault_key.0,
                    &vault_id,
                    &recipient,
                    &role,
                    number(key_epoch, "key epoch")?,
                )
                .map_err(js_err)?,
        )
    }

    /// Sign the next member roster of `vaultId` at `keyEpoch` (whose key is `vaultKey`)
    /// listing `members` (rows of the members list after the change): version
    /// `previous.version + 1` (`previous` = the roster this device trusts, JSON text, or
    /// null for version 1). `reviewed` = `rosterReview(…).digest` of the list the user
    /// saw: another list throws `review_mismatch`. Returns the roster's JSON text, sent as
    /// `roster`. Throws `roster_unauthorized` for a change this identity may not make.
    #[wasm_bindgen(js_name = signRoster)]
    pub fn sign_roster(
        &self,
        #[wasm_bindgen(js_name = "vaultKey")] vault_key: &VaultKey,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] previous: JsValue,
        #[wasm_bindgen(js_name = "keyEpoch")] key_epoch: f64,
        #[wasm_bindgen(unchecked_param_type = "RosterMemberInput[]")] members: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] reviewed: JsValue,
    ) -> R<String> {
        let vault_id = string(vault_id)?;
        let previous = opt_string(previous)?;
        let reviewed = string(reviewed)?;
        let previous = previous.map(|t| roster(&t)).transpose()?;
        let members: Vec<RosterMemberInput> = from_js(members)?;
        self.0
            .sign_roster(
                &vault_key.0,
                &vault_id,
                previous.as_ref(),
                number(key_epoch, "key epoch")?,
                &members,
                &reviewed,
            )
            .and_then(|r| r.to_json())
            .map_err(js_err)
    }
}

/// `Account.newSigningIdentity`'s answer.
#[wasm_bindgen]
pub struct NewSigningIdentity {
    identity: Option<SigningIdentity>,
    record: IdentityRecord,
}

#[wasm_bindgen]
impl NewSigningIdentity {
    /// Upload once with `PUT /account/identity`.
    #[wasm_bindgen(getter, unchecked_return_type = "IdentityRecord")]
    pub fn record(&self) -> R<JsValue> {
        to_js(&self.record)
    }

    /// Take the identity handle (can be called once).
    #[wasm_bindgen(js_name = takeIdentity)]
    pub fn take_identity(&mut self) -> R<SigningIdentity> {
        self.identity
            .take()
            .ok_or_else(|| JsError::new("identity already taken"))
    }
}

#[wasm_bindgen]
impl Account {
    /// A new signing identity for this account (when `/sync` `user.identity` is null):
    /// upload `record` with `PUT /account/identity`, keep `takeIdentity()`.
    #[wasm_bindgen(js_name = newSigningIdentity)]
    pub fn new_signing_identity(&self) -> R<NewSigningIdentity> {
        let new = self.0.new_signing_identity().map_err(js_err)?;
        Ok(NewSigningIdentity {
            identity: Some(SigningIdentity(new.identity)),
            record: new.record,
        })
    }

    /// This account's signing identity from `/sync` `user.identity`. Throws
    /// `identity_mismatch` when the server lists keys that aren't this account's
    /// own, `decrypt_failed` for another account's record.
    #[wasm_bindgen(js_name = openSigningIdentity)]
    pub fn open_signing_identity(
        &self,
        #[wasm_bindgen(unchecked_param_type = "IdentityRecord")] record: JsValue,
    ) -> R<SigningIdentity> {
        let record: IdentityRecord = from_js(record)?;
        self.0
            .open_signing_identity(&record)
            .map(SigningIdentity)
            .map_err(js_err)
    }

    /// This account without a signing key (what shares to it from before name).
    #[wasm_bindgen(js_name = legacyIdentity, unchecked_return_type = "PublicIdentity")]
    pub fn legacy_identity(&self) -> R<JsValue> {
        to_js(&self.0.legacy_identity())
    }

    /// Seal key pins with this account's key as version `seq` (the `seq` sent with
    /// `PUT /account/key-pins`). Throws `too_large` past the size limit.
    #[wasm_bindgen(js_name = sealKeyPins)]
    pub fn seal_key_pins(
        &self,
        #[wasm_bindgen(unchecked_param_type = "KeyPins")] pins: JsValue,
        seq: f64,
    ) -> R<String> {
        let pins: KeyPins = from_js(pins)?;
        self.0
            .seal_key_pins(&pins, number(seq, "seq")?)
            .map_err(js_err)
    }

    /// Open key pins from `GET /account/key-pins` (`key_pins`, `seq`). Throws
    /// `decrypt_failed` (not this account's, or changed) and `rollback` (a version
    /// other than `seq`).
    #[wasm_bindgen(js_name = openKeyPins, unchecked_return_type = "KeyPins")]
    pub fn open_key_pins(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] sealed: JsValue,
        seq: f64,
    ) -> R<JsValue> {
        let sealed = string(sealed)?;
        to_js(
            &self
                .0
                .open_key_pins(&sealed, number(seq, "seq")?)
                .map_err(js_err)?,
        )
    }
}

#[wasm_bindgen]
impl VaultKey {
    /// The key's commitment at `keyEpoch` (what a member roster carries).
    pub fn commitment(
        &self,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(js_name = "keyEpoch")] key_epoch: f64,
    ) -> R<String> {
        let vault_id = string(vault_id)?;
        core::key_commitment(&self.0, &vault_id, number(key_epoch, "key epoch")?).map_err(js_err)
    }

    /// The key's id (independent of the epoch), base64url.
    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(
        &self,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    ) -> R<String> {
        let vault_id = string(vault_id)?;
        core::key_id(&self.0, &vault_id).map_err(js_err)
    }

    /// The vault's current key as the epoch pins compare it: `{key_epoch, key_id}` (the
    /// row's `key_epoch`).
    #[wasm_bindgen(js_name = epochPin, unchecked_return_type = "EpochPin")]
    pub fn epoch_pin(
        &self,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(js_name = "keyEpoch")] key_epoch: f64,
    ) -> R<JsValue> {
        let vault_id = string(vault_id)?;
        to_js(&EpochPin::of(&self.0, &vault_id, number(key_epoch, "key epoch")?).map_err(js_err)?)
    }

    /// Whether this is the key the member roster commits to (its key epoch's), and the
    /// roster is `vaultId`'s.
    #[wasm_bindgen(js_name = matchesRoster)]
    pub fn matches_roster(
        &self,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(js_name = "rosterJson", unchecked_param_type = "string")]
        roster_json: JsValue,
    ) -> R<bool> {
        let (vault_id, roster_json) = (string(vault_id)?, string(roster_json)?);
        roster(&roster_json)?
            .commits_to(&vault_id, &self.0)
            .map_err(js_err)
    }
}

/// Check a public identity (its identity signature, when it has a signing key):
/// `{user_id, signing, hash, legacy_hash, fingerprint}`. Throws `bad_signature`.
#[wasm_bindgen(js_name = verifyIdentity, unchecked_return_type = "IdentityInfo")]
pub fn verify_identity(
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] identity: JsValue,
) -> R<JsValue> {
    let identity: PublicIdentity = from_js(identity)?;
    let v = identity.verify().map_err(js_err)?;
    to_js(&serde_json::json!({
        "user_id": v.user_id(),
        "signing": v.is_signing(),
        "hash": v.hash_b64(),
        "legacy_hash": passauth_core::item::b64(&v.legacy_hash()),
        "fingerprint": v.fingerprint(),
    }))
}

/// Check a share signature: `signer` signed that `sealedKey` gives `recipient` the key
/// of `vaultId` at `keyEpoch` with `role`. Returns the signer's `IdentityInfo`; throws
/// `bad_signature`.
#[wasm_bindgen(js_name = verifyShare, unchecked_return_type = "IdentityInfo")]
pub fn verify_share(
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] recipient: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] role: JsValue,
    #[wasm_bindgen(js_name = "keyEpoch")] key_epoch: f64,
    #[wasm_bindgen(js_name = "sealedKey", unchecked_param_type = "string")] sealed_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] signer: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] signature: JsValue,
) -> R<JsValue> {
    let (vault_id, role, sealed_key, signature) = (
        string(vault_id)?,
        string(role)?,
        string(sealed_key)?,
        string(signature)?,
    );
    let recipient: PublicIdentity = from_js(recipient)?;
    let signer: PublicIdentity = from_js(signer)?;
    let v = core::verify_share(
        &vault_id,
        &recipient,
        &role,
        number(key_epoch, "key epoch")?,
        &sealed_key,
        &signer,
        &signature,
    )
    .map_err(js_err)?;
    to_js(&serde_json::json!({
        "user_id": v.user_id(),
        "signing": v.is_signing(),
        "hash": v.hash_b64(),
        "legacy_hash": passauth_core::item::b64(&v.legacy_hash()),
        "fingerprint": v.fingerprint(),
    }))
}

/// Check a member roster chain of `vaultId`: `newer` (JSON texts from `GET
/// /vaults/{id}/rosters?after=`, oldest first, at most 1000) after `trusted` (the roster
/// this device trusted last, or null: then `newer` starts at version 1), ending exactly
/// at `latest` (the row's `member_roster`). Returns the newest roster's JSON text. Throws
/// `bad_signature`, `rollback`, `roster_forked`, `roster_unauthorized`, `too_large` or a
/// description.
#[wasm_bindgen(js_name = verifyRosterChain)]
pub fn verify_roster_chain(
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] trusted: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string[]")] newer: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] latest: JsValue,
) -> R<String> {
    let vault_id = string(vault_id)?;
    let trusted = opt_string(trusted)?;
    let latest = string(latest)?;
    let newer: Vec<String> = from_js(newer)?;
    if newer.len() > core::MAX_ROSTER_CHAIN {
        return Err(js_err(passauth_core::Error::TooLarge));
    }
    let trusted = trusted.map(|t| roster(&t)).transpose()?;
    let latest = roster(&latest)?;
    let newer = newer.iter().map(|r| roster(r)).collect::<R<Vec<_>>>()?;
    core::verify_roster_chain(&vault_id, trusted.as_ref(), &newer, &latest)
        .and_then(|r| r.to_json())
        .map_err(js_err)
}

/// Compare the server's latest roster of `vaultId` (`/sync` `member_roster`) with the
/// one this device trusted last: `{status: "unsigned" | "same" | "fetch", after}`.
/// Throws `rollback` and `roster_forked` (and a description for another vault's).
#[wasm_bindgen(js_name = rosterHead, unchecked_return_type = "RosterHead")]
pub fn roster_head(
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] remembered: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] latest: JsValue,
) -> R<JsValue> {
    let vault_id = string(vault_id)?;
    let (remembered, latest) = (opt_string(remembered)?, opt_string(latest)?);
    let remembered = remembered.map(|t| roster(&t)).transpose()?;
    let latest = latest.map(|t| roster(&t)).transpose()?;
    to_js(&core::roster_head(&vault_id, remembered.as_ref(), latest.as_ref()).map_err(js_err)?)
}

/// Compare the server's member rows with a trusted roster before sealing a new key.
#[wasm_bindgen(js_name = compareMembers, unchecked_return_type = "MemberDiff")]
pub fn compare_members(
    #[wasm_bindgen(js_name = "rosterJson", unchecked_param_type = "string")] roster_json: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RosterMemberInput[]")] members: JsValue,
) -> R<JsValue> {
    let roster_json = string(roster_json)?;
    let members: Vec<RosterMemberInput> = from_js(members)?;
    to_js(&core::compare_members(&roster(&roster_json)?, &members))
}

/// The role a trusted roster gives `identity` as a member (listed with its full or
/// legacy hash; null: not listed). For "the roster lists me with my row's role".
#[wasm_bindgen(js_name = rosterMemberRole)]
pub fn roster_member_role(
    #[wasm_bindgen(js_name = "rosterJson", unchecked_param_type = "string")] roster_json: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] identity: JsValue,
) -> R<Option<String>> {
    let roster_json = string(roster_json)?;
    let identity: PublicIdentity = from_js(identity)?;
    roster(&roster_json)?.member_role(&identity).map_err(js_err)
}

/// The role a trusted roster gives `signer` as a signer: only when listed with exactly
/// its full (signing) identity, never by a legacy listing. For "the share's signer is
/// an owner or admin".
#[wasm_bindgen(js_name = rosterSignerRole)]
pub fn roster_signer_role(
    #[wasm_bindgen(js_name = "rosterJson", unchecked_param_type = "string")] roster_json: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] signer: JsValue,
) -> R<Option<String>> {
    let roster_json = string(roster_json)?;
    let signer: PublicIdentity = from_js(signer)?;
    roster(&roster_json)?.signer_role(&signer).map_err(js_err)
}

/// The review of the next roster of `vaultId` that `signer` (this account's
/// `SigningIdentity.publicIdentity()`) would sign for `members` after `previous` (the
/// trusted roster's JSON text, or null: version 1, always shown), with the account's
/// key `pins`. Throws `roster_unauthorized` for a change the signer may not make.
#[wasm_bindgen(js_name = rosterReview, unchecked_return_type = "RosterReview")]
pub fn roster_review(
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] previous: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] signer: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RosterMemberInput[]")] members: JsValue,
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
) -> R<JsValue> {
    let vault_id = string(vault_id)?;
    let previous = opt_roster(previous)?;
    let signer: PublicIdentity = from_js(signer)?;
    let members: Vec<RosterMemberInput> = from_js(members)?;
    let pins = pins_or_empty(pins)?;
    to_js(
        &core::roster_review(&vault_id, previous.as_ref(), &signer, &members, &pins)
            .map_err(js_err)?,
    )
}

/// Compare a vault's current key (`{key_epoch, key_id}`) with a pin (null: none):
/// "new" | "same" | "newer" | "older" | "conflict".
#[wasm_bindgen(js_name = epochCheck, unchecked_return_type = "EpochStatus")]
pub fn epoch_check(
    #[wasm_bindgen(unchecked_param_type = "EpochPin | null | undefined")] pinned: JsValue,
    #[wasm_bindgen(unchecked_param_type = "EpochPin")] current: JsValue,
) -> R<String> {
    let pinned: Option<EpochPin> = if pinned.is_null() || pinned.is_undefined() {
        None
    } else {
        Some(from_js(pinned)?)
    };
    let current: EpochPin = from_js(current)?;
    enum_name(&core::epoch_check(pinned.as_ref(), &current))
}

fn pins_or_empty(pins: JsValue) -> R<KeyPins> {
    if pins.is_null() || pins.is_undefined() {
        Ok(KeyPins::default())
    } else {
        from_js(pins)
    }
}

/// How `identity` compares with the pins (null: none): "new" | "match" | "changed" |
/// "upgraded" | "email_conflict" (`email`: the one the server lists with it).
#[wasm_bindgen(js_name = pinCheck, unchecked_return_type = "PinStatus")]
pub fn pin_check(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] identity: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] email: JsValue,
) -> R<String> {
    let email = opt_string(email)?;
    let identity: PublicIdentity = from_js(identity)?;
    let status = pins_or_empty(pins)?
        .check_identity(&identity, email.as_deref())
        .map_err(js_err)?;
    enum_name(&status)
}

/// The pins with `identity` pinned for its user (`now`: Unix seconds).
#[wasm_bindgen(js_name = pinSet, unchecked_return_type = "KeyPins")]
pub fn pin_set(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PublicIdentity")] identity: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] email: JsValue,
    verified: bool,
    now: f64,
) -> R<JsValue> {
    let email = string(email)?;
    let identity: PublicIdentity = from_js(identity)?;
    let now = number(now, "time")? as i64;
    to_js(
        &pins_or_empty(pins)?
            .set(&identity, &email, verified, now)
            .map_err(js_err)?,
    )
}

/// Merge this device's pins (`ours`) into the server's newest (`base`).
#[wasm_bindgen(js_name = mergePins, unchecked_return_type = "KeyPins")]
pub fn merge_pins(
    #[wasm_bindgen(unchecked_param_type = "KeyPins")] base: JsValue,
    #[wasm_bindgen(unchecked_param_type = "KeyPins")] ours: JsValue,
) -> R<JsValue> {
    let base: KeyPins = from_js(base)?;
    let ours: KeyPins = from_js(ours)?;
    to_js(&base.merge(&ours).map_err(js_err)?)
}

/// A vault's current key (`{key_epoch, key_id}`) against the account's epoch pin for it
/// (null pins: none), with the trusted roster version (null: none): "new" | "same" |
/// "newer" | "older" | "conflict" | "downgraded".
#[wasm_bindgen(js_name = pinsEpochCheck, unchecked_return_type = "EpochStatus")]
pub fn pins_epoch_check(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "EpochPin")] current: JsValue,
    #[wasm_bindgen(js_name = "rosterVersion")] roster_version: Option<f64>,
) -> R<String> {
    let vault_id = string(vault_id)?;
    let current: EpochPin = from_js(current)?;
    let roster_version = opt_number(roster_version, "roster version")?;
    enum_name(&pins_or_empty(pins)?.check_epoch(&vault_id, &current, roster_version))
}

/// The key pins with `current` pinned (accepted) for `vaultId` when it is new or newer
/// (the previous key id retired; `rosterVersion`: the trusted roster's, marks the vault
/// signed since then). Throws `rollback` for a vault the account left that doesn't
/// qualify to come back.
#[wasm_bindgen(js_name = pinsSetEpoch, unchecked_return_type = "KeyPins")]
pub fn pins_set_epoch(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "EpochPin")] current: JsValue,
    #[wasm_bindgen(js_name = "rosterVersion")] roster_version: Option<f64>,
) -> R<JsValue> {
    let vault_id = string(vault_id)?;
    let current: EpochPin = from_js(current)?;
    let roster_version = opt_number(roster_version, "roster version")?;
    to_js(
        &pins_or_empty(pins)?
            .set_epoch(&vault_id, &current, roster_version)
            .map_err(js_err)?,
    )
}

/// The key pins with `vaultId` left or deleted by this account (a tombstone with the
/// trusted roster version then, 0: none; `now`: Unix seconds).
#[wasm_bindgen(js_name = pinsLeave, unchecked_return_type = "KeyPins")]
pub fn pins_leave(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    #[wasm_bindgen(js_name = "rosterVersion")] roster_version: f64,
    now: f64,
) -> R<JsValue> {
    let vault_id = string(vault_id)?;
    let roster_version = number(roster_version, "roster version")?;
    let now = number(now, "time")? as i64;
    to_js(
        &pins_or_empty(pins)?
            .leave(&vault_id, roster_version, now)
            .map_err(js_err)?,
    )
}

/// The key pins with the grandfathered vault ids written (once: unchanged when already
/// written), at the account's first signed sync. `createdIdentity`: this unlock created
/// the account's signing identity (`user.identity` was null and `PUT /account/identity`
/// answered `created: true`); when false (identity without key pins: "trust memory
/// missing") an empty list is written. Throws unless it is a boolean.
#[wasm_bindgen(js_name = pinsGrandfather, unchecked_return_type = "KeyPins")]
pub fn pins_grandfather(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(js_name = "vaultIds", unchecked_param_type = "string[]")] vault_ids: JsValue,
    #[wasm_bindgen(js_name = "createdIdentity", unchecked_param_type = "boolean")]
    created_identity: JsValue,
) -> R<JsValue> {
    let created_identity = created_identity
        .as_bool()
        .ok_or_else(|| JsError::new("createdIdentity must be true or false"))?;
    let vault_ids: Vec<String> = from_js(vault_ids)?;
    to_js(
        &pins_or_empty(pins)?
            .grandfather(&vault_ids, created_identity)
            .map_err(js_err)?,
    )
}

/// What to do with a vault row: `{status: "ok", epoch, trust, pin}` | `{status:
/// "consent", rejoin, replaced, own}` | `{status: "refused", reason}` (see
/// docs/ARCHITECTURE.md "Signed sharing").
#[wasm_bindgen(js_name = pinsAdmit, unchecked_return_type = "Admission")]
pub fn pins_admit(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "VaultObservation")] observation: JsValue,
) -> R<JsValue> {
    let pins = pins_or_empty(pins)?;
    let observation: VaultObservation = from_js(observation)?;
    to_js(&pins.admit(&observation).map_err(js_err)?)
}

/// `pinsAdmit`, and the key pins with what it says to pin applied: `{admission, pins,
/// changed}`. Chain it over a sync's rows; write the pins once if any was `changed`.
#[wasm_bindgen(js_name = pinsObserve, unchecked_return_type = "Observed")]
pub fn pins_observe(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "VaultObservation")] observation: JsValue,
) -> R<JsValue> {
    let pins = pins_or_empty(pins)?;
    let observation: VaultObservation = from_js(observation)?;
    to_js(&pins.observe(&observation).map_err(js_err)?)
}

/// Accept a vault row the user agreed to (an invitation or a consent prompt): the key
/// pins with its key pinned, its roster version *and hash* remembered, a tombstone
/// cleared (marked re-joined) and an `account` row marked `own`. Throws what
/// `pinsAdmit` would refuse (`rollback`: left, older, conflict, downgraded;
/// `roster_forked`; `identity_mismatch`: paused).
#[wasm_bindgen(js_name = pinsAccept, unchecked_return_type = "KeyPins")]
pub fn pins_accept(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "VaultObservation")] observation: JsValue,
) -> R<JsValue> {
    let pins = pins_or_empty(pins)?;
    let observation: VaultObservation = from_js(observation)?;
    to_js(&pins.accept(&observation).map_err(js_err)?)
}

/// A member roster's hash (base64url; for `VaultObservation.roster_hash`).
#[wasm_bindgen(js_name = rosterHash)]
pub fn roster_hash(
    #[wasm_bindgen(js_name = "rosterJson", unchecked_param_type = "string")] roster_json: JsValue,
) -> R<String> {
    let roster_json = string(roster_json)?;
    roster(&roster_json)?.hash().map_err(js_err)
}

/// An email as key pins compare it: invisible characters removed (Cf, Cc, Zl, Zp, Hangul
/// fillers), NFKC, lower case, trimmed, the domain without trailing dots in IDNA ASCII
/// (punycode); when IDNA refuses it, non-ASCII characters written as `\u{hex}`. Show
/// emails of pinned identities in this form.
#[wasm_bindgen(js_name = normalizeEmail)]
pub fn normalize_email(
    #[wasm_bindgen(unchecked_param_type = "string")] email: JsValue,
) -> R<String> {
    Ok(core::normalize_email(&string(email)?))
}

/// Whether an `account` wrap of `vaultId` may be a legacy v1 wrap (no signed history):
/// pass it to `Account.openVaultKey`.
#[wasm_bindgen(js_name = pinsLegacyWrapAllowed)]
pub fn pins_legacy_wrap_allowed(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
) -> R<bool> {
    let vault_id = string(vault_id)?;
    Ok(pins_or_empty(pins)?.legacy_wrap_allowed(&vault_id))
}

/// The identity `/sync` lists for the account itself (`SigningIdentity.identityHash()`
/// after opening it; null when `user.identity` is null) against the one remembered:
/// "new" | "match" | "mismatch".
#[wasm_bindgen(js_name = pinsCheckOwnIdentity, unchecked_return_type = "OwnIdentityStatus")]
pub fn pins_check_own_identity(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] listed: JsValue,
) -> R<String> {
    let listed = opt_string(listed)?;
    enum_name(&pins_or_empty(pins)?.check_own_identity(listed.as_deref()))
}

/// The key pins with the account's own identity hash remembered (once; another one
/// throws `identity_mismatch`).
#[wasm_bindgen(js_name = pinsSetOwnIdentity, unchecked_return_type = "KeyPins")]
pub fn pins_set_own_identity(
    #[wasm_bindgen(unchecked_param_type = "KeyPins | null | undefined")] pins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] hash: JsValue,
) -> R<JsValue> {
    let hash = string(hash)?;
    to_js(
        &pins_or_empty(pins)?
            .set_own_identity(&hash)
            .map_err(js_err)?,
    )
}
