//! Emergency access, view only. A user (the grantor) names someone with an account
//! on the same server (the grantee, their trusted contact) and picks a waiting
//! period (`wait_days`, 1–90). The contact accepts; the grantor's app checks the
//! contact's fingerprint with them and seals the grantor's account key to the
//! contact's public key (`sealed_key`; the server can't open it). When the contact
//! asks for access, the grantor is emailed and may approve or reject at once; with
//! no answer, the sweeper approves the request once `wait_days` have passed. An
//! approved contact can read the sealed key and the grantor's own vaults (the ones
//! nobody else is in, not even invited: wrapped vault keys, names and items, trash
//! included) and their attachments, and nothing else: no shared vaults, no account
//! bundle or private key, no sessions, no settings. Taking over the account is not
//! possible.
//!
//! Statuses: `invited` → (the contact accepts) `accepted` → (the grantor confirms
//! with the sealed key) `confirmed` → (the contact asks) `requested` → (the grantor
//! approves, or the waiting period ends) `approved`. The grantor may reject a request
//! or end an approved access, which makes it `rejected` (the contact may ask again).
//! Either side may remove it at any time (`DELETE`). Repeating a step that already
//! happened answers the access as it is.
//!
//! What revoking can't undo: the account key never changes (a new master password
//! wraps the same key again), so a contact who was approved keeps whatever they
//! viewed, and the key they hold opens anything of the grantor's they might get
//! later (say, a stolen copy of the database, with the private key that opens the
//! grantor's shared vaults). Ending access or removing the contact stops the server
//! handing out anything more, nothing else. A grantor who stops trusting a contact
//! who was approved should change the passwords that matter, or move to a new
//! account. The waiting period, the email at each request and the activity log are
//! what protect a grantor before that.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use passauth_core::item::unb64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Any, AnyConnection, Transaction};

use crate::auth::AuthUser;
use crate::db::{is_postgres, now};
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::mail::Email;
use crate::settings::Flag;
use crate::state::{AppState, Class, normalize_email};

const INVITED: &str = "invited";
const ACCEPTED: &str = "accepted";
const CONFIRMED: &str = "confirmed";
const REQUESTED: &str = "requested";
const APPROVED: &str = "approved";
const REJECTED: &str = "rejected";

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
/// Largest sealed account key accepted.
const MAX_SEALED_KEY: usize = 4096;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(invite))
        .route("/{id}", put(update).delete(remove))
        .route("/{id}/accept", post(accept))
        .route("/{id}/confirm", post(confirm))
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
                    g.approved_at, g.grantor_id, a.email AS grantor_email,
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
    /// `{"id", "status", "wait_days", "created_at", "updated_at", "requested_at",
    /// "approved_at", "auto_approve_at", "grantor": {...}, "grantee": {...}}`; never
    /// the sealed key.
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

/// `GET /emergency-access`: `{"as_grantor": [...], "as_grantee": [...]}`, oldest
/// first: the contacts the user named, and the people who named the user.
async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<Grant> = sqlx::query_as(grants!(
        "g.grantor_id = $1 OR g.grantee_id = $1 ORDER BY g.created_at, g.id"
    ))
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let (mine, theirs): (Vec<&Grant>, Vec<&Grant>) =
        rows.iter().partition(|g| g.grantor_id == user.user_id);
    Ok(Json(json!({
        "as_grantor": mine.iter().map(|g| g.json()).collect::<Vec<_>>(),
        "as_grantee": theirs.iter().map(|g| g.json()).collect::<Vec<_>>(),
    })))
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
    /// The grantor's account key sealed to the contact's public key.
    sealed_key: String,
}

/// `POST /emergency-access/{id}/confirm {sealed_key}` (the grantor, after checking
/// the contact's fingerprint): `accepted` → `confirmed`. The same key again is a
/// retry; another one once confirmed is a 409.
async fn confirm(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Confirm>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    if b.sealed_key.is_empty()
        || b.sealed_key.len() > MAX_SEALED_KEY
        || unb64(&b.sealed_key).is_err()
    {
        return Err(ApiError::bad(
            "sealed_key must be the sealed account key in base64url",
        ));
    }
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantor).await?;
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
    sqlx::query(
        "UPDATE emergency_access SET status = $1, sealed_key = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(CONFIRMED)
    .bind(&b.sealed_key)
    .bind(now())
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    Event::new("emergency.confirmed")
        .by(&user)
        .target(&g.grantee_id)
        .data(json!({ "grant": id }))
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
struct Update {
    wait_days: i64,
}

/// `PUT /emergency-access/{id} {wait_days}` (the grantor), at any status: a request
/// waiting now is approved by itself `wait_days` after it was made.
async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Update>,
) -> ApiResult<Json<Value>> {
    check_wait(b.wait_days)?;
    let (mut tx, g) = begin(&state, &id, &user.user_id, Side::Grantor).await?;
    if g.wait_days == b.wait_days {
        return Ok(Json(g.json()));
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
    tx.commit().await?;
    Ok(Json(g.json()))
}

/// `DELETE /emergency-access/{id}`: the grantor revokes it, or the contact declines
/// or steps down, at any status. `{"ok": true}`.
async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let gone: Option<(String, String, String)> = sqlx::query_as(
        "DELETE FROM emergency_access WHERE id = $1 AND (grantor_id = $2 OR grantee_id = $2)
         RETURNING grantor_id, grantee_id, status",
    )
    .bind(&id)
    .bind(&user.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (grantor, grantee, status) = gone.ok_or(ApiError::NotFound)?;
    let (by, other) = if grantor == user.user_id {
        ("grantor", grantee)
    } else {
        ("grantee", grantor)
    };
    Event::new("emergency.removed")
        .by(&user)
        .target(&other)
        .data(json!({ "grant": id, "status": status, "by": by }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
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
async fn approve(
    State(state): State<AppState>,
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

/// A vault of the grantor's, with its key wrapped by their account key.
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
/// `{"grant", "sealed_key", "vaults": [{id, meta, wrapped_key, key_epoch}],
/// "items": [{id, vault_id, item_key, data, revision, deleted_at, created_at,
/// updated_at}]}` — the grantor's own vaults (owned, key wrapped by their account
/// key, nobody else a member or invited) with every item, trash included, read in
/// one snapshot. Logged for both (`emergency.viewed`).
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
        "SELECT v.id, v.meta, m.wrapped_key, v.key_epoch
         FROM vaults v JOIN vault_members m ON m.vault_id = v.id
         WHERE m.user_id = $1 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = v.id AND o.user_id <> $1)
         ORDER BY v.created_at, v.id",
    )
    .bind(&g.grantor_id)
    .fetch_all(&mut *tx)
    .await?;
    let items: Vec<ItemRow> = sqlx::query_as(
        "SELECT i.id, i.vault_id, i.item_key, i.data, i.revision, i.deleted_at, i.created_at, i.updated_at
         FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
         WHERE m.user_id = $1 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = i.vault_id AND o.user_id <> $1)
         ORDER BY i.vault_id, i.created_at, i.id",
    )
    .bind(&g.grantor_id)
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
        "sealed_key": sealed_key,
        "vaults": vaults,
        "items": items,
    })))
}

/// `GET /emergency-access/{id}/attachments/{attachment}` (the contact, once
/// approved): a ready attachment of an item in one of the vaults `/vault` lists, as
/// `GET /attachments/{id}` sends it.
async fn attachment(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, attachment)): Path<(String, String)>,
) -> ApiResult<Response> {
    enabled(&state)?;
    let attachment = crate::files::canonical_id(&attachment).ok_or(ApiError::NotFound)?;
    let grantor = {
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
        g.grantor_id
    };
    let size: Option<i64> = sqlx::query_scalar(
        "SELECT a.size FROM attachments a JOIN vault_members m ON m.vault_id = a.vault_id
         WHERE a.id = $1 AND a.state = 'ready'
           AND m.user_id = $2 AND m.role = 'owner' AND m.key_kind = 'account' AND m.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = a.vault_id AND o.user_id <> $2)",
    )
    .bind(&attachment)
    .bind(&grantor)
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
