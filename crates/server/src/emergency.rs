//! Emergency access, view only. A user (the grantor) names someone with an account
//! on the same server (the grantee, their trusted contact) and picks a waiting
//! period (`wait_days`, 1–90). The contact accepts; the grantor's app checks the
//! contact's fingerprint with them, makes an emergency key for this access and
//! sends it sealed to the contact's public key (`sealed_key`), wrapped by the
//! grantor's account key (`grantor_key`, for the grantor's apps), and each of the
//! grantor's personal vault keys wrapped with it (`emergency_vault_keys`); the
//! server can open none of it. When the contact asks for access, the grantor is
//! emailed and may approve or reject at once; with no answer, the sweeper approves
//! the request once `wait_days` have passed. An approved contact can read the sealed
//! key and the grantor's personal vaults that have a wrap for the access (vaults the
//! grantor owns that nobody else is in, not even invited: names, wrapped keys and
//! items, trash included) and their attachments, and nothing else: no shared vaults,
//! no account bundle, account key or private key, no Sends, no sessions, no
//! settings. Taking over the account is not possible.
//!
//! Statuses: `invited` → (the contact accepts) `accepted` → (the grantor confirms
//! with the keys) `confirmed` → (the contact asks) `requested` → (the grantor
//! approves, or the waiting period ends) `approved`. The grantor may reject a request
//! or end an approved access, which makes it `rejected` (the contact may ask again).
//! Either side may remove it at any time (`DELETE`). Repeating a step that already
//! happened answers the access as it is. Approving, and shortening the waiting
//! period, need the grantor's master password again (a reauth token), so a stolen
//! session alone can't let a contact in sooner.
//!
//! The grantor's apps keep their roster of contacts here (`PUT /roster`, changed only
//! by compare-and-swap): sealed with the account key, so the server can neither read
//! nor change which accesses the apps add wraps for, and versioned inside, so a
//! device that saw a newer one refuses an older one.
//!
//! The wraps follow the personal vaults: confirming must wrap exactly the grantor's
//! personal vaults; a vault that becomes personal later (created, or no longer
//! shared) is listed in the grantor's `missing_vaults` until one of their apps adds
//! its wrap (`PUT /{id}/vault-keys`). A vault's wraps go when it is deleted, shared
//! (someone invited) or its key replaced; the grantor's apps then wrap the new key.
//! Removing an access that held a key (by either side, or with either account)
//! deletes its wraps and marks the vaults that had one for a key replacement
//! (`rotation_pending`, as when a member leaves), so a contact who kept the key
//! can't read what the grantor adds afterwards. Ending an approved access while
//! keeping the contact (reject) changes no key.
//!
//! What a compromised server can still do: hand the sealed key and the wraps out
//! before the waiting period (the period is server policy, not cryptography), which
//! opens the personal vaults wrapped for the access, never anything else. Accesses
//! confirmed before migration 13 sealed the account key itself (v1); the migration
//! sent them back to `accepted` (`reconfirm`) and marked them `v1_exposed`: a contact
//! who already had that key keeps what it opens, and the grantor's apps say so (move
//! to a new account if they no longer trust such a contact).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use passauth_core::item::unb64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Any, AnyConnection, Transaction};

use crate::auth::{AuthUser, REAUTH_FIRST, check_reauth, require_reauth_or};
use crate::db::{is_postgres, now};
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::mail::Email;
use crate::settings::Flag;
use crate::state::{AppState, Class, SyncNotice, normalize_email};

const INVITED: &str = "invited";
const ACCEPTED: &str = "accepted";
const CONFIRMED: &str = "confirmed";
const REQUESTED: &str = "requested";
const APPROVED: &str = "approved";
const REJECTED: &str = "rejected";

/// Statuses in which the access holds its keys (confirmed or later).
fn keyed(status: &str) -> bool {
    matches!(status, CONFIRMED | REQUESTED | APPROVED | REJECTED)
}

/// The key scheme the server takes (`key_version`): an emergency key per access
/// over the personal vault keys. 1 was the grantor's account key itself.
const KEY_VERSION: i64 = 2;

/// Longest waiting period, in days.
const MAX_WAIT_DAYS: i64 = 90;
/// Most emergency contacts one user may name.
const MAX_CONTACTS: i64 = 50;
/// New emergency contacts per user per hour (unknown emails count too).
const INVITES_PER_HOUR: u32 = 20;
/// Requests per access per day: each one emails the grantor.
const REQUESTS_PER_DAY: u32 = 3;
/// Views of the vaults per contact per hour (all their accesses together), counted
/// once the access is known to be theirs.
const VIEWS_PER_HOUR: u32 = 30;
/// Attachment downloads per contact per hour (all their accesses together), counted
/// once the access is known to be theirs.
const FILES_PER_HOUR: u32 = 600;
/// Vault-key additions (`PUT /{id}/vault-keys`) per grantor per hour: the grantor's
/// apps add wraps after unlocking, creating a vault and replacing a vault key.
const FILLS_PER_HOUR: u32 = 120;
/// Largest sealed key, wrapped key or vault-key wrap accepted (base64url).
const MAX_KEY: usize = 4096;
/// Most vault-key wraps in one request.
const MAX_VAULT_KEYS: usize = 1000;
/// Largest sealed roster accepted (base64url): the most contacts one user may name
/// (50), each with an email address and a name, take up to about 37 KiB. Below the
/// request size limit (64 KiB).
const MAX_ROSTER: usize = 48 * 1024;
/// Roster changes per user per hour.
const ROSTERS_PER_HOUR: u32 = 120;
/// Tries of a removal whose access got more wraps between reading them and locking
/// their vaults; the last one locks a new vault late instead.
const REMOVE_TRIES: usize = 4;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(invite))
        .route("/roster", put(put_roster))
        .route("/{id}", put(update).delete(remove))
        .route("/{id}/accept", post(accept))
        .route("/{id}/confirm", post(confirm))
        .route("/{id}/vault-keys", put(add_vault_keys))
        .route("/{id}/request", post(request))
        .route("/{id}/approve", post(approve))
        .route("/{id}/reject", post(reject))
        .route("/{id}/vault", get(vault))
        .route("/{id}/attachments/{attachment}", get(attachment))
}

fn enabled(state: &AppState) -> ApiResult<()> {
    if state.flag(Flag::EmergencyAccess) {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::EMERGENCY_ACCESS_DISABLED,
            "emergency access is turned off on this server",
        ))
    }
}

fn check_wait(days: i64) -> ApiResult<()> {
    if (1..=MAX_WAIT_DAYS).contains(&days) {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "wait_days must be a whole number from 1 to {MAX_WAIT_DAYS}"
        )))
    }
}

/// One access, with both people (`public_key` so apps can show fingerprints).
#[derive(sqlx::FromRow)]
struct Grant {
    id: String,
    status: String,
    wait_days: i64,
    created_at: i64,
    updated_at: i64,
    requested_at: Option<i64>,
    approved_at: Option<i64>,
    key_version: i64,
    /// The emergency key wrapped by the grantor's account key (for the grantor only).
    grantor_key: Option<String>,
    /// 1: confirmed before emergency keys (migration 13); to confirm again.
    reconfirm: i64,
    /// 1: the access held the grantor's account key itself (v1, before migration 13):
    /// the contact may keep it, which no key change takes back.
    v1_exposed: i64,
    grantor_id: String,
    grantor_email: String,
    grantor_name: String,
    grantor_public_key: String,
    grantee_id: String,
    grantee_email: String,
    grantee_name: String,
    grantee_public_key: String,
}

macro_rules! grants {
    ($filter:literal) => {
        concat!(
            "SELECT g.id, g.status, g.wait_days, g.created_at, g.updated_at, g.requested_at,
                    g.approved_at, g.key_version, g.grantor_key, g.reconfirm, g.v1_exposed,
                    g.grantor_id, a.email AS grantor_email,
                    a.name AS grantor_name, a.public_key AS grantor_public_key,
                    g.grantee_id, b.email AS grantee_email, b.name AS grantee_name,
                    b.public_key AS grantee_public_key
             FROM emergency_access g
             JOIN users a ON a.id = g.grantor_id
             JOIN users b ON b.id = g.grantee_id
             WHERE ",
            $filter
        )
    };
}

impl Grant {
    /// [`Self::json`] for the grantor, with what their apps need for the keys:
    /// `key_version`, `grantor_key` (once confirmed), `reconfirm` (confirmed before
    /// emergency keys: to confirm again), `v1_exposed` (the contact may hold the
    /// grantor's account key from back then) and `missing_vaults` (personal vaults
    /// without a wrap for this access; for an `accepted` access, the vaults to wrap
    /// when confirming).
    fn grantor_json(&self, missing: &[String]) -> Value {
        let mut v = self.json();
        v["key_version"] = self.key_version.into();
        v["grantor_key"] = self.grantor_key.clone().into();
        v["reconfirm"] = (self.reconfirm != 0).into();
        v["v1_exposed"] = (self.v1_exposed != 0).into();
        v["missing_vaults"] = missing.into();
        v
    }

    /// `{"id", "status", "wait_days", "created_at", "updated_at", "requested_at",
    /// "approved_at", "auto_approve_at", "grantor": {...}, "grantee": {...}}`; never
    /// a key.
    fn json(&self) -> Value {
        // While a request waits: when the sweeper approves it without an answer.
        let auto = self
            .requested_at
            .filter(|_| self.status == REQUESTED)
            .map(|r| r + self.wait_days * 86_400);
        json!({
            "id": self.id,
            "status": self.status,
            "wait_days": self.wait_days,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "auto_approve_at": auto,
            "grantor": {
                "id": self.grantor_id, "email": self.grantor_email,
                "name": self.grantor_name, "public_key": self.grantor_public_key,
            },
            "grantee": {
                "id": self.grantee_id, "email": self.grantee_email,
                "name": self.grantee_name, "public_key": self.grantee_public_key,
            },
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Grantor,
    Grantee,
}

async fn load(conn: &mut AnyConnection, id: &str) -> ApiResult<Grant> {
    sqlx::query_as(grants!("g.id = $1"))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Access `id` as `me` sees it: 404 when it doesn't exist or `me` is on neither
/// side, 403 when `me` is on the other side than `side`.
async fn grant_for(conn: &mut AnyConnection, id: &str, me: &str, side: Side) -> ApiResult<Grant> {
    let g = load(conn, id).await?;
    let mine = if g.grantor_id == me {
        Side::Grantor
    } else if g.grantee_id == me {
        Side::Grantee
    } else {
        return Err(ApiError::NotFound);
    };
    if mine != side {
        return Err(ApiError::Forbidden(
            match side {
                Side::Grantor => "only the person who named the emergency contact can do this",
                Side::Grantee => "only the emergency contact can do this",
            }
            .into(),
        ));
    }
    Ok(g)
}

/// Begin a change of access `id` by `me` on `side`: its row locked (a write first,
/// so SQLite never upgrades a read transaction) and the access as it is now.
async fn begin(
    state: &AppState,
    id: &str,
    me: &str,
    side: Side,
) -> ApiResult<(Transaction<'static, Any>, Grant)> {
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE emergency_access SET updated_at = updated_at WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let g = grant_for(&mut tx, id, me, side).await?;
    Ok((tx, g))
}

/// The reauth token of a request (`x-reauth-token`), if any.
fn reauth_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-reauth-token").and_then(|v| v.to_str().ok())
}

// --------------------------------------------------------------------- keys

/// The 400 for a confirmation without emergency keys (an app from before them).
fn update_required() -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        code::UPDATE_REQUIRED,
        "update PassAuth to confirm emergency contacts: this server gives them a key to your personal vaults only",
    )
}

/// A sealed or wrapped key: base64url, not empty, at most [`MAX_KEY`] long.
fn check_key(key: &str, what: &str) -> ApiResult<()> {
    if key.is_empty() || key.len() > MAX_KEY || unb64(key).is_err() {
        return Err(ApiError::bad(format!("{what} must be a key in base64url")));
    }
    Ok(())
}

/// A personal vault's key wrapped with an access's emergency key.
#[derive(Deserialize)]
struct VaultKey {
    vault_id: String,
    wrapped_key: String,
    /// The epoch of the vault key that was wrapped (required): a key replaced since is
    /// a 409 `vault_key_changed` (nothing is stored).
    key_epoch: Option<i64>,
}

/// Shape checks: ids are UUIDs, each vault once, keys in base64url, every wrap with
/// the epoch of the key it wraps.
fn check_vault_keys(keys: &[VaultKey]) -> ApiResult<()> {
    if keys.len() > MAX_VAULT_KEYS {
        return Err(ApiError::bad(format!(
            "at most {MAX_VAULT_KEYS} vault keys at once"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for k in keys {
        if uuid::Uuid::parse_str(&k.vault_id).is_err() || !seen.insert(k.vault_id.as_str()) {
            return Err(ApiError::bad(
                "vault_keys must name each vault once, by its id",
            ));
        }
        check_key(&k.wrapped_key, "wrapped_key")?;
        if k.key_epoch.is_none() {
            return Err(ApiError::bad(
                "every vault key needs the key_epoch of the key it wraps",
            ));
        }
    }
    Ok(())
}

/// The grantor's personal vaults, oldest first: owned with their account key, and
/// nobody else a member or invited.
async fn personal_vaults(conn: &mut AnyConnection, grantor: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT v.id FROM vaults v JOIN vault_members m ON m.vault_id = v.id
         WHERE m.user_id = $1 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = v.id AND o.user_id <> $1)
         ORDER BY v.created_at, v.id",
    )
    .bind(grantor)
    .fetch_all(&mut *conn)
    .await?)
}

/// The vaults with a wrap for access `id`.
async fn wrapped_vaults(conn: &mut AnyConnection, id: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT vault_id FROM emergency_vault_keys WHERE access_id = $1 ORDER BY vault_id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?)
}

/// The personal vaults (`personal`) without a wrap for access `g`; none while the
/// contact hasn't accepted.
fn missing(g: &Grant, personal: &[String], wrapped: &[String]) -> Vec<String> {
    if g.status == INVITED {
        return Vec::new();
    }
    personal
        .iter()
        .filter(|v| !wrapped.contains(v))
        .cloned()
        .collect()
}

/// The 409 when the wraps sent don't fit the grantor's personal vaults: `expected`
/// names the vaults to wrap (all personal vaults when confirming, the ones still
/// without a wrap when adding).
fn vaults_changed(expected: &[String]) -> ApiError {
    let mut extra = serde_json::Map::new();
    extra.insert("expected".into(), expected.into());
    ApiError::with_fields(
        StatusCode::CONFLICT,
        code::EMERGENCY_VAULTS_CHANGED,
        "your personal vaults changed: wrap the keys of the vaults in `expected` and try again",
        extra,
    )
}

/// A change of access `id` by `me` (the grantor) that stores wraps: `me`'s personal
/// vaults are locked first (in id order, like every vault write, and before the
/// access's row, as account deletion does, so no two writes wait on each other in
/// a circle), then the access as [`begin`] locks it. Nobody shares one of those
/// vaults, replaces its key or deletes it until the transaction ends. Returns the
/// personal vaults as they are now; one that became personal after the locking (not
/// locked) is a 409 `emergency_vaults_changed`, naming them.
async fn begin_with_vaults(
    state: &AppState,
    id: &str,
    me: &str,
) -> ApiResult<(Transaction<'static, Any>, Grant, Vec<String>)> {
    let locked = {
        let mut conn = state.db.acquire().await?;
        let mut ids = personal_vaults(&mut conn, me).await?;
        ids.sort_unstable();
        ids
    };
    let mut tx = state.db.begin().await?;
    for vault in &locked {
        sqlx::query("UPDATE vaults SET updated_at = updated_at WHERE id = $1")
            .bind(vault)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE emergency_access SET updated_at = updated_at WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let g = grant_for(&mut tx, id, me, Side::Grantor).await?;
    let personal = personal_vaults(&mut tx, me).await?;
    if personal.iter().any(|v| !locked.contains(v)) {
        return Err(vaults_changed(&personal));
    }
    Ok((tx, g, personal))
}

/// 409 `vault_key_changed` when a wrap names a key epoch the vault has left.
async fn check_epochs(conn: &mut AnyConnection, keys: &[VaultKey]) -> ApiResult<()> {
    for k in keys {
        let now: Option<i64> = sqlx::query_scalar("SELECT key_epoch FROM vaults WHERE id = $1")
            .bind(&k.vault_id)
            .fetch_optional(&mut *conn)
            .await?;
        if now.is_none() || now != k.key_epoch {
            return Err(ApiError::vault_key_changed());
        }
    }
    Ok(())
}

/// Store the wraps of access `id`, keeping any it has already (they are only ever
/// added). Returns how many were added.
async fn insert_vault_keys(
    conn: &mut AnyConnection,
    id: &str,
    keys: &[VaultKey],
) -> ApiResult<u64> {
    let t = now();
    let mut added = 0;
    for k in keys {
        added += sqlx::query(
            "INSERT INTO emergency_vault_keys (access_id, vault_id, wrapped_key, created_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT (access_id, vault_id) DO NOTHING",
        )
        .bind(id)
        .bind(&k.vault_id)
        .bind(&k.wrapped_key)
        .bind(t)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    }
    Ok(added)
}

/// Forget every wrap of `vault`, inside the caller's vault write (it holds the
/// vault's lock): its key was replaced, it stopped being personal (shared), or it is
/// deleted. The grantor's apps wrap the vault again when it is (still) personal.
/// Returns how many wraps went.
pub(crate) async fn forget_vault_keys(conn: &mut AnyConnection, vault: &str) -> ApiResult<u64> {
    Ok(
        sqlx::query("DELETE FROM emergency_vault_keys WHERE vault_id = $1")
            .bind(vault)
            .execute(&mut *conn)
            .await?
            .rows_affected(),
    )
}

/// Account deletion of `user_id`, inside its transaction: the vaults that have a
/// wrap for an access in which they are the contact (the vaults to mark for a key
/// replacement), in id order. Read before locking the vaults.
pub(crate) async fn vaults_wrapped_for_contact(
    conn: &mut AnyConnection,
    user_id: &str,
) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT k.vault_id FROM emergency_vault_keys k
         JOIN emergency_access g ON g.id = k.access_id
         WHERE g.grantee_id = $1 ORDER BY k.vault_id",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?)
}

/// Account deletion of `user_id`, inside its transaction (the vaults locked): every
/// access they are on ends. Vaults wrapped for an access in which they were the
/// contact are marked for a key replacement; the wraps go with the accesses.
/// Returns the vaults marked.
pub(crate) async fn end_accesses_of(
    conn: &mut AnyConnection,
    user_id: &str,
) -> ApiResult<Vec<String>> {
    let flagged = vaults_wrapped_for_contact(conn, user_id).await?;
    for vault in &flagged {
        sqlx::query("UPDATE vaults SET rotation_pending = 1 WHERE id = $1")
            .bind(vault)
            .execute(&mut *conn)
            .await?;
    }
    for stmt in [
        "DELETE FROM emergency_vault_keys WHERE access_id IN (
             SELECT id FROM emergency_access WHERE grantor_id = $1 OR grantee_id = $1)",
        "DELETE FROM emergency_access WHERE grantor_id = $1 OR grantee_id = $1",
    ] {
        sqlx::query(stmt).bind(user_id).execute(&mut *conn).await?;
    }
    Ok(flagged)
}

/// Migration 13 (`db.rs`): accesses confirmed with the grantor's account key itself
/// (v1) go back to `accepted` without it, flagged `reconfirm` (the grantor confirms
/// the contact again with an emergency key) and `v1_exposed` (the contact may keep
/// the account key: the apps say so). One `emergency.reconfirm` event by nobody (the
/// server) for each side. Returns how many accesses.
pub(crate) async fn reconfirm_v1_accesses(conn: &mut AnyConnection) -> anyhow::Result<usize> {
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, grantor_id, grantee_id, status FROM emergency_access
         WHERE (status <> $1 AND status <> $2) OR sealed_key IS NOT NULL ORDER BY id",
    )
    .bind(INVITED)
    .bind(ACCEPTED)
    .fetch_all(&mut *conn)
    .await?;
    let t = now();
    for (id, grantor, grantee, status) in &rows {
        sqlx::query(
            "UPDATE emergency_access SET status = $1, sealed_key = NULL, grantor_key = NULL,
                 requested_at = NULL, approved_at = NULL, reconfirm = 1, v1_exposed = 1,
                 key_version = $2, updated_at = $3
             WHERE id = $4",
        )
        .bind(ACCEPTED)
        .bind(KEY_VERSION)
        .bind(t)
        .bind(id)
        .execute(&mut *conn)
        .await?;
        for target in [grantor, grantee] {
            Event::new("emergency.reconfirm")
                .target(target)
                .data(json!({ "grant": id, "status": status }))
                .record_with(&mut *conn, false)
                .await?;
        }
    }
    Ok(rows.len())
}

// ------------------------------------------------------------------- emails

/// "Name (email)", or the email alone. The name is the user's own text: one short line.
fn person(name: &str, email: &str) -> String {
    let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    let name = name.trim();
    if name.is_empty() {
        email.to_owned()
    } else {
        format!("{name} ({email})")
    }
}

fn days(n: i64) -> String {
    if n == 1 {
        "1 day".into()
    } else {
        format!("{n} days")
    }
}

/// Email `to` (when email is set up), with a button to the web vault's emergency
/// access page.
fn tell(state: &AppState, to: &str, subject: &str, body: String) {
    if !state.mailer.enabled() {
        return;
    }
    state.mailer.send_later(
        to.to_owned(),
        Email {
            subject: subject.into(),
            heading: subject.into(),
            body,
            action: Some((
                "Open emergency access".into(),
                format!("{}/settings/emergency", state.config.domain),
            )),
            code: None,
        },
    );
}

impl Grant {
    fn grantor(&self) -> String {
        person(&self.grantor_name, &self.grantor_email)
    }

    fn grantee(&self) -> String {
        person(&self.grantee_name, &self.grantee_email)
    }
}

// ----------------------------------------------------------------- handlers

/// `GET /emergency-access`: `{"as_grantor": [...], "as_grantee": [...], "roster",
/// "roster_seq"}`, oldest first: the contacts the user named (with `key_version`,
/// `grantor_key`, `reconfirm`, `v1_exposed` and `missing_vaults`, see
/// [`Grant::grantor_json`]), the people who named the user, and the user's sealed
/// roster of contacts (null until their apps store one) with its sequence number.
/// Read in one snapshot.
async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    if is_postgres(&state.config.database_url) {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
    }
    let rows: Vec<Grant> = sqlx::query_as(grants!(
        "g.grantor_id = $1 OR g.grantee_id = $1 ORDER BY g.created_at, g.id"
    ))
    .bind(&user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    let (mine, theirs): (Vec<&Grant>, Vec<&Grant>) =
        rows.iter().partition(|g| g.grantor_id == user.user_id);
    let mut as_grantor = Vec::with_capacity(mine.len());
    if !mine.is_empty() {
        let personal = personal_vaults(&mut tx, &user.user_id).await?;
        let wraps: Vec<(String, String)> = sqlx::query_as(
            "SELECT k.access_id, k.vault_id FROM emergency_vault_keys k
             JOIN emergency_access g ON g.id = k.access_id WHERE g.grantor_id = $1",
        )
        .bind(&user.user_id)
        .fetch_all(&mut *tx)
        .await?;
        for g in mine {
            let wrapped: Vec<String> = wraps
                .iter()
                .filter(|(access, _)| *access == g.id)
                .map(|(_, vault)| vault.clone())
                .collect();
            as_grantor.push(g.grantor_json(&missing(g, &personal, &wrapped)));
        }
    }
    let (roster, roster_seq): (Option<String>, i64) =
        sqlx::query_as("SELECT emergency_roster, emergency_roster_seq FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Json(json!({
        "as_grantor": as_grantor,
        "as_grantee": theirs.iter().map(|g| g.json()).collect::<Vec<_>>(),
        "roster": roster,
        "roster_seq": roster_seq,
    })))
}

#[derive(Deserialize)]
struct Roster {
    /// The roster sealed by the user's apps with their account key (base64url).
    roster: String,
    /// The stored `roster_seq` + 1.
    seq: i64,
}

/// `PUT /emergency-access/roster {roster, seq}`: store the user's roster of
/// emergency contacts, a compare-and-swap: `seq` must be the stored `roster_seq` + 1,
/// else 409 `roster_changed` (another app changed it: read it again). The server
/// can't read the roster: the apps seal it with the account key, version it inside,
/// and add vault keys only for the accesses it lists. Works while emergency access
/// is turned off (removing someone from it only takes access away).
async fn put_roster(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Roster>,
) -> ApiResult<Json<Value>> {
    if b.roster.is_empty() || b.roster.len() > MAX_ROSTER || unb64(&b.roster).is_err() {
        return Err(ApiError::bad(
            "roster must be the sealed roster in base64url",
        ));
    }
    if b.seq < 1 {
        return Err(roster_changed());
    }
    state.limiter.limit(
        Class::Target,
        &format!("emergency-roster:{}", user.user_id),
        ROSTERS_PER_HOUR,
        3600,
    )?;
    let done = sqlx::query(
        "UPDATE users SET emergency_roster = $1, emergency_roster_seq = $2
         WHERE id = $3 AND emergency_roster_seq = $4",
    )
    .bind(&b.roster)
    .bind(b.seq)
    .bind(&user.user_id)
    .bind(b.seq - 1)
    .execute(&state.db)
    .await?;
    if done.rows_affected() != 1 {
        return Err(roster_changed());
    }
    Ok(Json(json!({ "roster_seq": b.seq })))
}

/// 409 `roster_changed`: the roster's sequence number isn't the one the app read.
fn roster_changed() -> ApiError {
    ApiError::coded(
        StatusCode::CONFLICT,
        code::ROSTER_CHANGED,
        "your list of emergency contacts changed on another device; read it again",
    )
}

#[derive(Deserialize)]
struct Invite {
    grantee_email: String,
    wait_days: i64,
}

/// `POST /emergency-access {grantee_email, wait_days}`: name a verified user of this
/// server (as for sharing: unknown, unverified and disabled accounts are 404) as an
/// emergency contact; emailed to them. 409 when they already are one.
async fn invite(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Invite>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    check_wait(b.wait_days)?;
    state.limiter.limit(
        Class::Target,
        &format!("emergency-invite:{}", user.user_id),
        INVITES_PER_HOUR,
        3600,
    )?;
    let grantee: Option<String> = sqlx::query_scalar(
        "SELECT id FROM users WHERE email = $1 AND email_verified = 1 AND disabled = 0",
    )
    .bind(normalize_email(&b.grantee_email))
    .fetch_optional(&state.db)
    .await?;
    let grantee = grantee.ok_or(ApiError::NotFound)?;
    if grantee == user.user_id {
        return Err(ApiError::bad("you can't be your own emergency contact"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let t = now();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO emergency_access (id, grantor_id, grantee_id, status, wait_days, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&grantee)
    .bind(INVITED)
    .bind(b.wait_days)
    .bind(t)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        ApiError::conflict_on_unique(e, "conflict", "this person is your emergency contact already")
    })?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM emergency_access WHERE grantor_id = $1")
            .bind(&user.user_id)
            .fetch_one(&mut *tx)
            .await?;
    if count > MAX_CONTACTS {
        return Err(ApiError::bad(format!(
            "you can name at most {MAX_CONTACTS} emergency contacts"
        )));
    }
    Event::new("emergency.invited")
        .by(&user)
        .target(&grantee)
        .data(json!({ "grant": id, "wait_days": b.wait_days }))
        .record(&mut tx, &state)
        .await?;
    let g = load(&mut tx, &id).await?;
    tx.commit().await?;
    tell(
        &state,
        &g.grantee_email,
        "You've been named as an emergency contact",
        format!(
            "{} named you as their emergency contact on your PassAuth server. If you accept, you can ask to view their vaults if they ever can't: they are told at once and have {} to say no. Open PassAuth to accept or decline.",
            g.grantor(),
            days(g.wait_days)
        ),
    );
    Ok(Json(g.json()))
}

/// `POST /emergency-access/{id}/accept` (the contact): `invited` → `accepted`.
async fn accept(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantee).await?;
    if g.status != INVITED {
        return Ok(Json(g.json()));
    }
    sqlx::query("UPDATE emergency_access SET status = $1, updated_at = $2 WHERE id = $3")
        .bind(ACCEPTED)
        .bind(now())
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    Event::new("emergency.accepted")
        .by(&user)
        .target(&g.grantor_id)
        .data(json!({ "grant": id }))
        .record(&mut tx, &state)
        .await?;
    let g = load(&mut tx, &id).await?;
    tx.commit().await?;
    tell(
        &state,
        &g.grantor_email,
        "Your emergency contact accepted",
        format!(
            "{} accepted being your emergency contact. To finish, open PassAuth and confirm them. Before you do, check with them in person or by phone that the fingerprint PassAuth shows for them matches theirs.",
            g.grantee()
        ),
    );
    Ok(Json(g.json()))
}

#[derive(Deserialize)]
struct Confirm {
    /// The access's emergency key sealed to the contact's public key.
    sealed_key: String,
    /// The same key wrapped by the grantor's account key. Missing: an app from
    /// before emergency keys (400 `update_required`).
    grantor_key: Option<String>,
    /// Each personal vault's key wrapped with the emergency key: exactly the
    /// grantor's personal vaults.
    vault_keys: Option<Vec<VaultKey>>,
}

/// `POST /emergency-access/{id}/confirm {sealed_key, grantor_key, vault_keys:
/// [{vault_id, wrapped_key, key_epoch}]}` (the grantor, after checking the contact's
/// fingerprint): `accepted` → `confirmed`. `vault_keys` must name exactly the
/// grantor's personal vaults (else 409 `emergency_vaults_changed` with `expected`),
/// each with its current key (a `key_epoch` the vault has left is a 409
/// `vault_key_changed`). The same sealed key again is a retry; another one once
/// confirmed is a 409. A body without `grantor_key` and `vault_keys` (an app from
/// before emergency keys) is a 400 `update_required`.
async fn confirm(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Confirm>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let (Some(grantor_key), Some(vault_keys)) = (b.grantor_key.as_deref(), b.vault_keys.as_deref())
    else {
        return Err(update_required());
    };
    check_key(&b.sealed_key, "sealed_key")?;
    check_key(grantor_key, "grantor_key")?;
    check_vault_keys(vault_keys)?;
    let (mut tx, g, personal) = begin_with_vaults(&state, &id, &user.user_id).await?;
    match g.status.as_str() {
        ACCEPTED => {}
        INVITED => {
            return Err(ApiError::Conflict(
                "your contact hasn't accepted yet".into(),
            ));
        }
        _ => {
            let stored: Option<String> =
                sqlx::query_scalar("SELECT sealed_key FROM emergency_access WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&mut *tx)
                    .await?;
            if stored.as_deref() == Some(b.sealed_key.as_str()) {
                return Ok(Json(g.json()));
            }
            return Err(ApiError::Conflict(
                "this emergency contact is confirmed already".into(),
            ));
        }
    }
    let given: std::collections::BTreeSet<&str> =
        vault_keys.iter().map(|k| k.vault_id.as_str()).collect();
    if given != personal.iter().map(String::as_str).collect() {
        return Err(vaults_changed(&personal));
    }
    check_epochs(&mut tx, vault_keys).await?;
    sqlx::query(
        "UPDATE emergency_access SET status = $1, sealed_key = $2, grantor_key = $3, key_version = $4,
             reconfirm = 0, updated_at = $5
         WHERE id = $6",
    )
    .bind(CONFIRMED)
    .bind(&b.sealed_key)
    .bind(grantor_key)
    .bind(KEY_VERSION)
    .bind(now())
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    // Nothing of an earlier key may stay with the new one.
    sqlx::query("DELETE FROM emergency_vault_keys WHERE access_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    insert_vault_keys(&mut tx, &id, vault_keys).await?;
    Event::new("emergency.confirmed")
        .by(&user)
        .target(&g.grantee_id)
        .data(json!({ "grant": id, "vaults": vault_keys.len() }))
        .record(&mut tx, &state)
        .await?;
    let g = load(&mut tx, &id).await?;
    tx.commit().await?;
    tell(
        &state,
        &g.grantee_email,
        "You're an emergency contact now",
        format!(
            "{} confirmed you as their emergency contact. If you ever need to, you can ask for access in PassAuth: they are told at once, and unless they say no, it is granted after {}.",
            g.grantor(),
            days(g.wait_days)
        ),
    );
    Ok(Json(g.json()))
}

#[derive(Deserialize)]
struct AddVaultKeys {
    vault_keys: Vec<VaultKey>,
}

/// `PUT /emergency-access/{id}/vault-keys {vault_keys: [{vault_id, wrapped_key,
/// key_epoch}]}` (the grantor, once the access is confirmed or later): wraps for
/// personal vaults that have none yet (a vault created, no longer shared, or whose
/// key was replaced). Only added: a vault that has a wrap keeps it. A vault that
/// isn't personal is a 409 `emergency_vaults_changed` (`expected`: the personal
/// vaults still without a wrap), a replaced key a 409 `vault_key_changed`; nothing is
/// stored then. Answers the access as `GET` lists it for the grantor.
async fn add_vault_keys(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<AddVaultKeys>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    check_vault_keys(&b.vault_keys)?;
    let (mut tx, g, personal) = begin_with_vaults(&state, &id, &user.user_id).await?;
    if !keyed(&g.status) {
        return Err(ApiError::Conflict(
            "confirm your emergency contact first".into(),
        ));
    }
    state.limiter.limit(
        Class::Target,
        &format!("emergency-keys:{}", user.user_id),
        FILLS_PER_HOUR,
        3600,
    )?;
    if b.vault_keys.iter().any(|k| !personal.contains(&k.vault_id)) {
        let wrapped = wrapped_vaults(&mut tx, &id).await?;
        return Err(vaults_changed(&missing(&g, &personal, &wrapped)));
    }
    check_epochs(&mut tx, &b.vault_keys).await?;
    let added = insert_vault_keys(&mut tx, &id, &b.vault_keys).await?;
    if added > 0 {
        Event::new("emergency.vaults_added")
            .by(&user)
            .data(json!({ "grant": id, "vaults": added }))
            .record(&mut tx, &state)
            .await?;
    }
    let wrapped = wrapped_vaults(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(g.grantor_json(&missing(&g, &personal, &wrapped))))
}

#[derive(Deserialize)]
struct Update {
    wait_days: i64,
}

/// `PUT /emergency-access/{id} {wait_days}` (the grantor), at any status: a request
/// waiting now is approved by itself `wait_days` after it was made. Shortening the
/// period needs a reauth token (`x-reauth-token`; without one 403 `reauth_required`),
/// as approving does: a stolen session alone can't let a contact in sooner.
async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Update>,
) -> ApiResult<Json<Value>> {
    check_wait(b.wait_days)?;
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantor).await?;
    if g.wait_days == b.wait_days {
        return Ok(Json(g.json()));
    }
    let shorter = b.wait_days < g.wait_days;
    let reauth = reauth_header(&headers);
    if shorter {
        check_reauth(&state, &user, reauth, REAUTH_FIRST)?;
    }
    sqlx::query("UPDATE emergency_access SET wait_days = $1, updated_at = $2 WHERE id = $3")
        .bind(b.wait_days)
        .bind(now())
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    Event::new("emergency.updated")
        .by(&user)
        .target(&g.grantee_id)
        .data(json!({ "grant": id, "wait_days": b.wait_days }))
        .record(&mut tx, &state)
        .await?;
    let g = load(&mut tx, &id).await?;
    if shorter {
        require_reauth_or(&state, &user, reauth, REAUTH_FIRST)?;
    }
    tx.commit().await?;
    Ok(Json(g.json()))
}

/// `DELETE /emergency-access/{id}`: the grantor revokes it, or the contact declines
/// or steps down, at any status. Its wraps go, and the vaults that had one are
/// marked for a key replacement (`rotation_pending`), which the grantor's apps make:
/// the contact may have kept the key. `{"ok": true}`, for the grantor also with
/// `rotation_pending` (the ids of those vaults; the contact's apps never replace
/// anyone's keys, so their answer names none).
async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut tries = 0;
    let (mut tx, (grantor, grantee, status), rotate) = loop {
        tries += 1;
        // The vaults with a wrap, when the access is the caller's: locked first, in id
        // order, like every vault write (and as account deletion does).
        let locked: Vec<String> = {
            let mut conn = state.db.acquire().await?;
            sqlx::query_scalar(
                "SELECT k.vault_id FROM emergency_vault_keys k JOIN emergency_access g ON g.id = k.access_id
                 WHERE g.id = $1 AND (g.grantor_id = $2 OR g.grantee_id = $2) ORDER BY k.vault_id",
            )
            .bind(&id)
            .bind(&user.user_id)
            .fetch_all(&mut *conn)
            .await?
        };
        let mut tx = state.db.begin().await?;
        for vault in &locked {
            crate::vault::lock_vault(&mut tx, vault).await?;
        }
        let gone: Option<(String, String, String)> = sqlx::query_as(
            "DELETE FROM emergency_access WHERE id = $1 AND (grantor_id = $2 OR grantee_id = $2)
             RETURNING grantor_id, grantee_id, status",
        )
        .bind(&id)
        .bind(&user.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let gone = gone.ok_or(ApiError::NotFound)?;
        // A wrap added while this waited for the access is marked too. Its vault's lock
        // belongs before the access's, so the removal starts again (rolled back); only
        // the last try takes it late.
        let rotate = wrapped_vaults(&mut tx, &id).await?;
        let late: Vec<&String> = rotate.iter().filter(|v| !locked.contains(v)).collect();
        if late.is_empty() {
            break (tx, gone, rotate);
        }
        if tries < REMOVE_TRIES {
            continue;
        }
        for vault in late {
            crate::vault::lock_vault(&mut tx, vault).await?;
        }
        break (tx, gone, rotate);
    };
    for vault in &rotate {
        sqlx::query("UPDATE vaults SET rotation_pending = 1 WHERE id = $1")
            .bind(vault)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM emergency_vault_keys WHERE access_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let notices: Vec<(String, SyncNotice)> = crate::vault::bump_members(
        &mut tx,
        is_postgres(&state.config.database_url),
        &rotate,
        &[],
    )
    .await?
    .into_iter()
    .map(|(u, revision)| (u, SyncNotice::new(revision, None)))
    .collect();
    let by_grantor = grantor == user.user_id;
    let (by, other) = if by_grantor {
        ("grantor", grantee)
    } else {
        ("grantee", grantor)
    };
    let mut data = json!({ "grant": id, "status": status, "by": by });
    if !rotate.is_empty() {
        data["rotate_vaults"] = rotate.len().into();
    }
    Event::new("emergency.removed")
        .by(&user)
        .target(&other)
        .data(data)
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    state.notify_sync(notices);
    Ok(Json(if by_grantor {
        json!({ "ok": true, "rotation_pending": rotate })
    } else {
        json!({ "ok": true })
    }))
}

/// `POST /emergency-access/{id}/request` (the contact): `confirmed` or `rejected` →
/// `requested`; the grantor is emailed. Asking again while a request waits, or once
/// approved, changes nothing.
async fn request(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantee).await?;
    match g.status.as_str() {
        CONFIRMED | REJECTED => {}
        REQUESTED | APPROVED => return Ok(Json(g.json())),
        _ => {
            return Err(ApiError::Conflict(
                "they haven't confirmed you as their emergency contact yet".into(),
            ));
        }
    }
    state.limiter.limit(
        Class::Target,
        &format!("emergency-request:{id}"),
        REQUESTS_PER_DAY,
        86_400,
    )?;
    let t = now();
    sqlx::query(
        "UPDATE emergency_access SET status = $1, requested_at = $2, approved_at = NULL, updated_at = $2
         WHERE id = $3",
    )
    .bind(REQUESTED)
    .bind(t)
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    Event::new("emergency.requested")
        .by(&user)
        .target(&g.grantor_id)
        .data(json!({ "grant": id, "wait_days": g.wait_days }))
        .record(&mut tx, &state)
        .await?;
    let g = load(&mut tx, &id).await?;
    tx.commit().await?;
    tell(
        &state,
        &g.grantor_email,
        "Someone asked for emergency access to your vaults",
        format!(
            "{} asked for emergency access to your PassAuth vaults. Unless you reject it, they can view your own vaults (not the ones you share) in {}. Open PassAuth to approve or reject it now. If you didn't expect this, reject it and talk to them.",
            g.grantee(),
            days(g.wait_days)
        ),
    );
    Ok(Json(g.json()))
}

/// `POST /emergency-access/{id}/approve` (the grantor): `requested` → `approved` now.
/// Needs a reauth token (`x-reauth-token`; without one 403 `reauth_required`), used up
/// when the access is approved: a stolen session alone can't let a contact in.
async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantor).await?;
    match g.status.as_str() {
        REQUESTED => {}
        APPROVED => return Ok(Json(g.json())),
        _ => return Err(ApiError::Conflict("there is no request to approve".into())),
    }
    let reauth = reauth_header(&headers);
    check_reauth(&state, &user, reauth, REAUTH_FIRST)?;
    let t = now();
    sqlx::query(
        "UPDATE emergency_access SET status = $1, approved_at = $2, updated_at = $2 WHERE id = $3",
    )
    .bind(APPROVED)
    .bind(t)
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    Event::new("emergency.approved")
        .by(&user)
        .target(&g.grantee_id)
        .data(json!({ "grant": id, "automatic": false }))
        .record(&mut tx, &state)
        .await?;
    let g = load(&mut tx, &id).await?;
    require_reauth_or(&state, &user, reauth, REAUTH_FIRST)?;
    tx.commit().await?;
    tell(
        &state,
        &g.grantee_email,
        "Your emergency access was approved",
        format!(
            "{} approved your emergency access. You can now view their vaults in PassAuth.",
            g.grantor()
        ),
    );
    Ok(Json(g.json()))
}

/// `POST /emergency-access/{id}/reject` (the grantor): a waiting request, or an
/// approved access, → `rejected` (the contact may ask again). Works while the admin
/// has emergency access turned off: it only takes access away.
async fn reject(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantor).await?;
    match g.status.as_str() {
        REQUESTED | APPROVED => {}
        REJECTED => return Ok(Json(g.json())),
        _ => return Err(ApiError::Conflict("there is no request to reject".into())),
    }
    sqlx::query(
        "UPDATE emergency_access SET status = $1, approved_at = NULL, updated_at = $2 WHERE id = $3",
    )
    .bind(REJECTED)
    .bind(now())
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    Event::new("emergency.rejected")
        .by(&user)
        .target(&g.grantee_id)
        .data(json!({ "grant": id, "status": g.status }))
        .record(&mut tx, &state)
        .await?;
    let was_approved = g.status == APPROVED;
    let g = load(&mut tx, &id).await?;
    tx.commit().await?;
    let (subject, body) = if was_approved {
        (
            "Your emergency access was ended",
            format!(
                "{} ended your emergency access to their vaults.",
                g.grantor()
            ),
        )
    } else {
        (
            "Your emergency access request was rejected",
            format!("{} rejected your emergency access request.", g.grantor()),
        )
    };
    tell(&state, &g.grantee_email, subject, body);
    Ok(Json(g.json()))
}

// -------------------------------------------------------------------- viewing

/// The sealed key of an approved access: 403 while it isn't approved, 404 while
/// the grantor's account is disabled (their data stays where it is).
async fn released_key(conn: &mut AnyConnection, g: &Grant) -> ApiResult<String> {
    if g.status != APPROVED {
        return Err(ApiError::Forbidden(
            "emergency access is not approved".into(),
        ));
    }
    let row: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT g.sealed_key, u.disabled FROM emergency_access g JOIN users u ON u.id = g.grantor_id
         WHERE g.id = $1",
    )
    .bind(&g.id)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some((Some(key), 0)) => Ok(key),
        _ => Err(ApiError::NotFound),
    }
}

/// A personal vault of the grantor's, with its key wrapped for the access.
#[derive(Serialize, sqlx::FromRow)]
struct VaultRow {
    id: String,
    meta: String,
    wrapped_key: String,
    key_epoch: i64,
}

#[derive(Serialize, sqlx::FromRow)]
struct ItemRow {
    id: String,
    vault_id: String,
    item_key: String,
    data: String,
    revision: i64,
    deleted_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

/// `GET /emergency-access/{id}/vault` (the contact, once approved):
/// `{"grant", "key_version", "sealed_key", "vaults": [{id, meta, wrapped_key,
/// key_epoch}], "items": [{id, vault_id, item_key, data, revision, deleted_at,
/// created_at, updated_at}]}` — the grantor's personal vaults (owned, key wrapped by
/// their account key, nobody else a member or invited) that have a wrap for this
/// access (`wrapped_key` is that wrap), with every item, trash included, read in one
/// snapshot. Logged for both (`emergency.viewed`).
async fn vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let mut tx = state.db.begin().await?;
    if is_postgres(&state.config.database_url) {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
    }
    let g = grant_for(&mut tx, &id, &user.user_id, Side::Grantee).await?;
    // Only once the access is known to be theirs: unknown ids make no keys.
    state.limiter.limit(
        Class::Target,
        &format!("emergency-view:{}", user.user_id),
        VIEWS_PER_HOUR,
        3600,
    )?;
    let sealed_key = released_key(&mut tx, &g).await?;
    let vaults: Vec<VaultRow> = sqlx::query_as(
        "SELECT v.id, v.meta, k.wrapped_key, v.key_epoch
         FROM vaults v JOIN vault_members m ON m.vault_id = v.id
         JOIN emergency_vault_keys k ON k.vault_id = v.id AND k.access_id = $2
         WHERE m.user_id = $1 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = v.id AND o.user_id <> $1)
         ORDER BY v.created_at, v.id",
    )
    .bind(&g.grantor_id)
    .bind(&g.id)
    .fetch_all(&mut *tx)
    .await?;
    let items: Vec<ItemRow> = sqlx::query_as(
        "SELECT i.id, i.vault_id, i.item_key, i.data, i.revision, i.deleted_at, i.created_at, i.updated_at
         FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
         JOIN emergency_vault_keys k ON k.vault_id = i.vault_id AND k.access_id = $2
         WHERE m.user_id = $1 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = i.vault_id AND o.user_id <> $1)
         ORDER BY i.vault_id, i.created_at, i.id",
    )
    .bind(&g.grantor_id)
    .bind(&g.id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut conn = state.db.acquire().await?;
    Event::new("emergency.viewed")
        .by(&user)
        .target(&g.grantor_id)
        .data(json!({ "grant": id, "vaults": vaults.len(), "items": items.len() }))
        .record(&mut conn, &state)
        .await?;
    drop(conn);
    Ok(Json(json!({
        "grant": g.json(),
        "key_version": g.key_version,
        "sealed_key": sealed_key,
        "vaults": vaults,
        "items": items,
    })))
}

/// `GET /emergency-access/{id}/attachments/{attachment}` (the contact, once
/// approved): a ready attachment of an item in one of the vaults `/vault` lists (a
/// personal vault with a wrap for the access), as `GET /attachments/{id}` sends it.
async fn attachment(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, attachment)): Path<(String, String)>,
) -> ApiResult<Response> {
    enabled(&state)?;
    let attachment = crate::files::canonical_id(&attachment).ok_or(ApiError::NotFound)?;
    let (grant, grantor) = {
        let mut conn = state.db.acquire().await?;
        let g = grant_for(&mut conn, &id, &user.user_id, Side::Grantee).await?;
        // Only once the access is known to be theirs: unknown ids make no keys.
        state.limiter.limit(
            Class::Target,
            &format!("emergency-file:{}", user.user_id),
            FILES_PER_HOUR,
            3600,
        )?;
        released_key(&mut conn, &g).await?;
        (g.id, g.grantor_id)
    };
    let size: Option<i64> = sqlx::query_scalar(
        "SELECT a.size FROM attachments a JOIN vault_members m ON m.vault_id = a.vault_id
         JOIN emergency_vault_keys k ON k.vault_id = a.vault_id AND k.access_id = $3
         WHERE a.id = $1 AND a.state = 'ready'
           AND m.user_id = $2 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = a.vault_id AND o.user_id <> $2)",
    )
    .bind(&attachment)
    .bind(&grantor)
    .bind(&grant)
    .fetch_optional(&state.db)
    .await?;
    let size = size.ok_or(ApiError::NotFound)?;
    crate::vault::file_response(&state, &attachment, size).await
}

// -------------------------------------------------------------------- sweeper

/// Approve the requests whose waiting period has passed without an answer (the
/// sweeper, every minute), unless the admin turned emergency access off. Each side
/// gets an event and an email. Returns how many.
pub async fn approve_waited(state: &AppState) -> ApiResult<u64> {
    if !state.flag(Flag::EmergencyAccess) {
        return Ok(0);
    }
    let t = now();
    // Most minutes there is nothing to do: no write transaction for that.
    let due: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM emergency_access WHERE status = $1 AND requested_at + wait_days * 86400 <= $2",
    )
    .bind(REQUESTED)
    .bind(t)
    .fetch_one(&state.db)
    .await?;
    if due == 0 {
        return Ok(0);
    }
    let mut tx = state.db.begin().await?;
    let approved: Vec<(String, String, String)> = sqlx::query_as(
        "UPDATE emergency_access SET status = $1, approved_at = $2, updated_at = $2
         WHERE status = $3 AND requested_at + wait_days * 86400 <= $2
         RETURNING id, grantor_id, grantee_id",
    )
    .bind(APPROVED)
    .bind(t)
    .bind(REQUESTED)
    .fetch_all(&mut *tx)
    .await?;
    for (id, grantor, grantee) in &approved {
        for target in [grantor, grantee] {
            Event::new("emergency.approved")
                .target(target)
                .data(json!({ "grant": id, "automatic": true }))
                .record(&mut tx, state)
                .await?;
        }
    }
    let mut granted = Vec::new();
    for (id, ..) in &approved {
        granted.push(load(&mut tx, id).await?);
    }
    tx.commit().await?;
    for g in &granted {
        tell(
            state,
            &g.grantee_email,
            "Your emergency access was approved",
            format!(
                "Your emergency access to {}'s vaults was granted: the waiting period ended without an answer. You can now view their vaults in PassAuth.",
                g.grantor()
            ),
        );
        tell(
            state,
            &g.grantor_email,
            "Emergency access to your vaults was granted",
            format!(
                "{} can now view your own vaults: their emergency access request waited {} without an answer. If this is wrong, end their access in PassAuth now, and change the passwords that matter: what they already viewed stays with them.",
                g.grantee(),
                days(g.wait_days)
            ),
        );
    }
    if !granted.is_empty() {
        tracing::info!(
            count = granted.len(),
            "approved emergency access requests whose waiting period ended"
        );
    }
    Ok(granted.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_in_emails_stay_on_one_short_line() {
        assert_eq!(person("", "a@example.com"), "a@example.com");
        assert_eq!(
            person(" Ann\r\nBcc: x@evil.test ", "a@example.com"),
            "AnnBcc: x@evil.test (a@example.com)"
        );
        assert_eq!(
            person(&"x".repeat(100), "a@b.c").len(),
            64 + " (a@b.c)".len()
        );
        assert_eq!(days(1), "1 day");
        assert_eq!(days(7), "7 days");
    }
}
