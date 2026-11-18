//! Send: text shared through a link, `/send/<id>#<key>`. The sender's app makes a
//! random 256-bit send key, encrypts the name and the text with it and puts the
//! key only in the link's fragment, which browsers never send to a server; the
//! owner keeps the key wrapped by their account key (`owner_key`) to view and edit
//! the Send later. The server stores ciphertext only and decides who may fetch it,
//! how often and until when.
//!
//! Owner (signed in): `POST /sends`, `GET /sends`, `GET/PUT/DELETE /sends/{id}`.
//! Public, no account: `GET /api/public/sends/{id}` (what the page needs before
//! opening it: never the text, nor the name of a Send with a password) and
//! `POST /api/public/sends/{id}/access` (the name and the text; counts a view).
//! Unknown, disabled, expired, deleted and used-up Sends, and every Send while the
//! admin has turned the feature off or disabled the owner, answer the same 404. An
//! optional password is checked with a verifier the visitor's app derives from it on
//! the device (`access_salt` is opaque to the server and handed to visitors for
//! that); the server keeps only the verifier's SHA-256 and compares in constant
//! time. Wrong ones are counted in the Send's row (at most
//! [`WRONG_PASSWORDS_PER_HOUR`] from every address together; kept across restarts,
//! reset when the owner sets a new password). Neither the verifier nor anything
//! else from the body is ever logged, and the fragment never reaches the server at
//! all.
//!
//! Send v2 (migration 16, feature `send_v2`): a Send with a password may have its name
//! and text encrypted with a key made from the link's key *and* the password, so the
//! link alone doesn't open it. Its owner keeps that key wrapped by their account key
//! (`owner_content_key`, returned only to the owner). The server can't tell the formats
//! apart and doesn't need to; it only keeps `owner_content_key` consistent with the
//! password: none without a password, and while a Send has one, changing or removing
//! the password must bring the re-encrypted `name`, `data` and `owner_content_key`
//! (`null` when going back to the link key alone), so an app from before can't leave
//! the text encrypted with a password visitors no longer have.
//!
//! The sweeper deletes Sends once their `delete_at` (at most `send_max_days` ahead)
//! has passed; their bytes count toward the owner's storage quota until then.

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use passauth_core::crypto::random_bytes;
use passauth_core::item::b64;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use sqlx::AnyConnection;

use crate::auth::{AuthUser, client_ip};
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::{self, Event};
use crate::settings::{Flag, Num};
use crate::state::{App, AppState, Class, ct_eq, hash_token};

/// Largest encrypted text (`data`, as sent).
pub const MAX_DATA: usize = 1024 * 1024;
/// Largest encrypted name.
const MAX_NAME: usize = 8 * 1024;
/// Largest wrapped send key.
const MAX_OWNER_KEY: usize = 4 * 1024;
/// `access_salt` and `access_verifier`: visible ASCII of this length.
const ACCESS_FIELD: std::ops::RangeInclusive<usize> = 8..=512;
const MAX_VIEWS: i64 = 1_000_000;
const BODY_LIMIT: usize = MAX_DATA + MAX_NAME + MAX_OWNER_KEY + 16 * 1024;
/// How far an app's clock may be ahead when it picks the longest `delete_at`.
const CLOCK_SLACK: i64 = 3600;
/// New Sends per account per hour.
const CREATES_PER_HOUR: u32 = 100;
/// Public requests (page and access together) per address per minute.
const PUBLIC_PER_MINUTE: u32 = 60;
/// Access attempts per address and Send per minute (right or wrong password).
const ACCESS_PER_MINUTE: u32 = 10;
/// Wrong passwords per Send per hour from every address together; then the Send
/// answers 429 until the hour is over, so spreading guesses over many addresses
/// doesn't help either. Counted in the Send's row (`wrong_passwords` since
/// `wrong_since`), so neither a restart nor a flood of other requests resets it.
const WRONG_PASSWORDS_PER_HOUR: i64 = 100;
const WRONG_PASSWORDS_WINDOW: i64 = 3600;
/// The only kind so far; files can come later with their own columns.
const TEXT: &str = "text";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sends", get(list).post(create))
        .route("/sends/{id}", get(read).put(update).delete(remove))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

/// Mounted at `/api/public`: no account, rate-limited per address.
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/sends/{id}", get(public_info))
        .route("/sends/{id}/access", post(public_access))
}

/// A Send id: 128 random bits, base64url (22 characters), chosen by the server.
fn new_id() -> String {
    b64(&random_bytes::<16>().expect("OS RNG available"))
}

fn valid_id(id: &str) -> bool {
    id.len() == 22
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// What the server keeps of a password's verifier.
fn verifier_hash(verifier: &str) -> String {
    hash_token(verifier)
}

// ------------------------------------------------------------------- owner

/// Columns of a Send for its owner (`data` only where asked for).
#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    kind: String,
    name: String,
    data: Option<String>,
    owner_key: String,
    owner_content_key: Option<String>,
    access_salt: Option<String>,
    access_verifier: Option<String>,
    max_views: Option<i64>,
    views: i64,
    expires_at: Option<i64>,
    delete_at: i64,
    disabled: i64,
    hide_email: i64,
    created_at: i64,
    updated_at: i64,
    /// Bytes counted toward the owner's storage (name + data + owner keys).
    size: i64,
}

macro_rules! row_columns {
    ($data:literal) => {
        concat!(
            "id, kind, name, ",
            $data,
            ", owner_key, owner_content_key, access_salt, access_verifier, max_views, views,
             expires_at, delete_at, disabled, hide_email, created_at, updated_at,
             CAST(octet_length(name) + octet_length(data) + octet_length(owner_key)
                  + COALESCE(octet_length(owner_content_key), 0) AS BIGINT) AS size"
        )
    };
}

/// A Send as its owner sees it. `available`: a visitor can open it right now.
fn owner_json(state: &App, r: Row, t: i64) -> Value {
    let available = state.flag(Flag::Sends)
        && r.disabled == 0
        && r.delete_at > t
        && r.expires_at.is_none_or(|e| e > t)
        && r.max_views.is_none_or(|m| r.views < m);
    let mut v = json!({
        "id": r.id,
        "path": format!("/send/{}", r.id),
        "kind": r.kind,
        "name": r.name,
        "owner_key": r.owner_key,
        "owner_content_key": r.owner_content_key,
        "size": r.size,
        "has_password": r.access_verifier.is_some(),
        "access_salt": r.access_salt,
        "max_views": r.max_views,
        "views": r.views,
        "expires_at": r.expires_at,
        "delete_at": r.delete_at,
        "disabled": r.disabled != 0,
        "hide_email": r.hide_email != 0,
        "available": available,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    });
    if let Some(data) = r.data {
        v["data"] = data.into();
    }
    v
}

fn bad_field(name: &str, max: usize) -> ApiError {
    ApiError::bad(format!("{name} is missing or longer than {max} bytes"))
}

fn check_blob(name: &str, value: &str, max: usize) -> ApiResult<()> {
    if value.is_empty() || value.len() > max {
        return Err(bad_field(name, max));
    }
    Ok(())
}

fn check_access_field(name: &str, value: &str) -> ApiResult<()> {
    if !ACCESS_FIELD.contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::bad(format!(
            "{name} must be {} to {} visible ASCII characters",
            ACCESS_FIELD.start(),
            ACCESS_FIELD.end()
        )));
    }
    Ok(())
}

/// `delete_at`: in the future and at most the admin's `send_max_days` away.
fn check_delete_at(state: &App, delete_at: i64, t: i64) -> ApiResult<()> {
    let days = state.num(Num::SendMaxDays);
    if delete_at <= t || delete_at > t + days * 86_400 + CLOCK_SLACK {
        return Err(ApiError::bad(format!(
            "delete_at must be in the future and at most {days} days away"
        )));
    }
    Ok(())
}

fn check_expires_at(expires_at: i64, t: i64) -> ApiResult<()> {
    if expires_at <= t {
        return Err(ApiError::bad("expires_at must be in the future"));
    }
    Ok(())
}

fn check_max_views(max_views: i64) -> ApiResult<()> {
    if !(1..=MAX_VIEWS).contains(&max_views) {
        return Err(ApiError::bad(format!(
            "max_views must be from 1 to {MAX_VIEWS}"
        )));
    }
    Ok(())
}

/// A new password: both fields, checked; stored as (salt, verifier hash).
fn new_password(
    salt: Option<String>,
    verifier: Option<String>,
) -> ApiResult<Option<(String, String)>> {
    match (salt, verifier) {
        (None, None) => Ok(None),
        (Some(salt), Some(verifier)) => {
            check_access_field("access_salt", &salt)?;
            check_access_field("access_verifier", &verifier)?;
            Ok(Some((salt, verifier_hash(&verifier))))
        }
        _ => Err(ApiError::bad(
            "send access_salt and access_verifier together",
        )),
    }
}

/// A write that grows the owner's storage must stay within the admin's quota
/// (checked inside the caller's transaction, after the write; on PostgreSQL with
/// the owner's row locked first, so Sends and vault writes at once take turns).
async fn check_quota(
    conn: &mut AnyConnection,
    state: &AppState,
    owner: &str,
    growth: i64,
) -> ApiResult<()> {
    let (_, max_bytes) = crate::vault::quota(state);
    if growth <= 0 || max_bytes == 0 {
        return Ok(());
    }
    let postgres = crate::db::is_postgres(&state.config.database_url);
    crate::vault::lock_users(conn, postgres, &[owner.to_owned()]).await?;
    let (_, size) = crate::vault::usage(conn, owner).await?;
    if size > max_bytes {
        return Err(ApiError::quota_exceeded());
    }
    Ok(())
}

fn content_key_without_password() -> ApiError {
    ApiError::bad("owner_content_key needs a password (access_salt and access_verifier)")
}

fn sends_disabled() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        code::SENDS_DISABLED,
        "Send is turned off on this server",
    )
}

#[derive(Deserialize)]
struct NewSend {
    #[serde(default = "text_kind")]
    kind: String,
    name: String,
    data: String,
    owner_key: String,
    /// Send v2: the content key wrapped by the owner's account key (only with a password).
    owner_content_key: Option<String>,
    access_salt: Option<String>,
    access_verifier: Option<String>,
    max_views: Option<i64>,
    expires_at: Option<i64>,
    delete_at: i64,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    hide_email: bool,
}

fn text_kind() -> String {
    TEXT.into()
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<NewSend>,
) -> ApiResult<Json<Value>> {
    if !state.flag(Flag::Sends) {
        return Err(sends_disabled());
    }
    if b.kind != TEXT {
        return Err(ApiError::bad("only text Sends are supported"));
    }
    check_blob("name", &b.name, MAX_NAME)?;
    check_blob("data", &b.data, MAX_DATA)?;
    check_blob("owner_key", &b.owner_key, MAX_OWNER_KEY)?;
    let t = now();
    check_delete_at(&state, b.delete_at, t)?;
    if let Some(e) = b.expires_at {
        check_expires_at(e, t)?;
    }
    if let Some(m) = b.max_views {
        check_max_views(m)?;
    }
    let password = new_password(b.access_salt, b.access_verifier)?;
    if let Some(key) = &b.owner_content_key {
        check_blob("owner_content_key", key, MAX_OWNER_KEY)?;
        if password.is_none() {
            return Err(content_key_without_password());
        }
    }
    state.limiter.limit(
        Class::Target,
        &format!("send-create:{}", user.user_id),
        CREATES_PER_HOUR,
        3600,
    )?;
    let size = (b.name.len()
        + b.data.len()
        + b.owner_key.len()
        + b.owner_content_key.as_ref().map_or(0, String::len)) as i64;
    crate::disk::ensure_room(&state, size as u64).await?;
    let id = new_id();
    let (salt, verifier) = password.unzip();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO sends (id, user_id, kind, name, data, owner_key, access_salt, access_verifier,
           max_views, views, expires_at, delete_at, disabled, hide_email, created_at, updated_at,
           owner_content_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $10, $11, $12, $13, $14, $14, $15)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&b.kind)
    .bind(&b.name)
    .bind(&b.data)
    .bind(&b.owner_key)
    .bind(salt)
    .bind(verifier)
    .bind(b.max_views)
    .bind(b.expires_at)
    .bind(b.delete_at)
    .bind(b.disabled as i64)
    .bind(b.hide_email as i64)
    .bind(t)
    .bind(&b.owner_content_key)
    .execute(&mut *tx)
    .await?;
    check_quota(&mut tx, &state, &user.user_id, size).await?;
    Event::new("send.created")
        .by(&user)
        .data(json!({ "send": id }))
        .record(&mut tx, &state)
        .await?;
    let row = owned(&mut tx, &user.user_id, &id).await?;
    tx.commit().await?;
    let row = row.ok_or(ApiError::NotFound)?;
    Ok(Json(owner_json(&state, row, t)))
}

/// One of the user's Sends, with its `data`.
async fn owned(conn: &mut AnyConnection, user_id: &str, id: &str) -> ApiResult<Option<Row>> {
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        row_columns!("data"),
        " FROM sends WHERE id = $1 AND user_id = $2"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?)
}

/// The user's Sends, newest first, without their `data` (`GET /sends/{id}` has it).
async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<Row> = sqlx::query_as(concat!(
        "SELECT ",
        row_columns!("CAST(NULL AS TEXT) AS data"),
        " FROM sends WHERE user_id = $1 ORDER BY created_at DESC, id"
    ))
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let t = now();
    let sends: Vec<Value> = rows.into_iter().map(|r| owner_json(&state, r, t)).collect();
    Ok(Json(json!({ "sends": sends })))
}

async fn read(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_id(&id) {
        return Err(ApiError::NotFound);
    }
    let mut conn = state.db.acquire().await?;
    let row = owned(&mut conn, &user.user_id, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    drop(conn);
    Ok(Json(owner_json(&state, row, now())))
}

/// `Some(value)` for a field that was sent, also when it was `null` (`Some(None)`);
/// a field left out stays `None` (unchanged).
fn sent<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// `PUT /sends/{id}`: only what is sent changes, so the whole owner view may go
/// back with a change (its read-only fields, and its unchanged `access_salt`, are
/// ignored). `null` clears `max_views` and `expires_at`, and `access_verifier:
/// null` removes the password; a new password sends `access_salt` and
/// `access_verifier` together. The text stays encrypted with the same send key
/// (the link holds it). `owner_content_key` (Send v2): `null` clears it; while the Send
/// has one, a new password or removing it needs `name`, `data` and `owner_content_key`
/// in the same request (400 otherwise); removing the password clears it.
#[derive(Deserialize)]
struct SendChanges {
    name: Option<String>,
    data: Option<String>,
    owner_key: Option<String>,
    #[serde(default, deserialize_with = "sent")]
    owner_content_key: Option<Option<String>>,
    access_salt: Option<String>,
    #[serde(default, deserialize_with = "sent")]
    access_verifier: Option<Option<String>>,
    #[serde(default, deserialize_with = "sent")]
    max_views: Option<Option<i64>>,
    #[serde(default, deserialize_with = "sent")]
    expires_at: Option<Option<i64>>,
    delete_at: Option<i64>,
    disabled: Option<bool>,
    hide_email: Option<bool>,
}

async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<SendChanges>,
) -> ApiResult<Json<Value>> {
    if !valid_id(&id) {
        return Err(ApiError::NotFound);
    }
    if let Some(name) = &b.name {
        check_blob("name", name, MAX_NAME)?;
    }
    if let Some(data) = &b.data {
        check_blob("data", data, MAX_DATA)?;
    }
    if let Some(key) = &b.owner_key {
        check_blob("owner_key", key, MAX_OWNER_KEY)?;
    }
    if let Some(Some(key)) = &b.owner_content_key {
        check_blob("owner_content_key", key, MAX_OWNER_KEY)?;
    }
    if let Some(Some(m)) = b.max_views {
        check_max_views(m)?;
    }
    // A new password, `Some(None)` to remove it, `None` to keep it (a salt sent
    // without a verifier is the owner view going back unchanged).
    let password = match b.access_verifier {
        None => None,
        Some(None) => Some(None),
        Some(Some(verifier)) => Some(new_password(b.access_salt.clone(), Some(verifier))?),
    };
    let t = now();
    let mut tx = state.db.begin().await?;
    // A write first: it locks the row (and on SQLite the database) for the rest.
    let locked = sqlx::query("UPDATE sends SET views = views WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    if locked.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let old = owned(&mut tx, &user.user_id, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if password.is_none() && b.access_salt.is_some() && b.access_salt != old.access_salt {
        return Err(ApiError::bad(
            "send access_salt and access_verifier together",
        ));
    }
    // Send v2: the text is encrypted with the password too, so a new password (or none)
    // must come with the text re-encrypted and the new content key (or `null`).
    if old.owner_content_key.is_some()
        && password.is_some()
        && (b.owner_content_key.is_none() || b.name.is_none() || b.data.is_none())
    {
        return Err(ApiError::bad(
            "this Send is encrypted with its password: a new password or none needs name, data and owner_content_key",
        ));
    }
    let mut changed: Vec<&str> = Vec::new();
    let mut pick = |field: &'static str, new: Option<String>, old: &str| -> String {
        match new {
            Some(v) if v != old => {
                changed.push(field);
                v
            }
            _ => old.to_owned(),
        }
    };
    let old_data = old.data.clone().unwrap_or_default();
    let name = pick("name", b.name, &old.name);
    let data = pick("data", b.data, &old_data);
    let owner_key = pick("owner_key", b.owner_key, &old.owner_key);
    let (salt, verifier) = match password {
        None => (old.access_salt.clone(), old.access_verifier.clone()),
        Some(new) => {
            changed.push("password");
            new.unzip()
        }
    };
    let content_key = match b.owner_content_key {
        Some(v) => v,
        // Removing the password removes the content key (checked above for v2 Sends).
        None if verifier.is_none() => None,
        None => old.owner_content_key.clone(),
    };
    if content_key.is_some() && verifier.is_none() {
        return Err(content_key_without_password());
    }
    if content_key != old.owner_content_key {
        changed.push("owner_content_key");
    }
    let max_views = match b.max_views {
        Some(v) if v != old.max_views => {
            changed.push("max_views");
            v
        }
        _ => old.max_views,
    };
    let expires_at = match b.expires_at {
        Some(v) if v != old.expires_at => {
            if let Some(e) = v {
                check_expires_at(e, t)?;
            }
            changed.push("expires_at");
            v
        }
        _ => old.expires_at,
    };
    let delete_at = match b.delete_at {
        Some(v) if v != old.delete_at => {
            check_delete_at(&state, v, t)?;
            changed.push("delete_at");
            v
        }
        _ => old.delete_at,
    };
    let mut flag = |field: &'static str, new: Option<bool>, old: i64| -> i64 {
        match new {
            Some(on) if on as i64 != old => {
                changed.push(field);
                on as i64
            }
            _ => old,
        }
    };
    let disabled = flag("disabled", b.disabled, old.disabled);
    let hide_email = flag("hide_email", b.hide_email, old.hide_email);
    if changed.is_empty() {
        // Nothing to write, nothing to log.
        return Ok(Json(owner_json(&state, old, t)));
    }
    let growth =
        (name.len() + data.len() + owner_key.len() + content_key.as_ref().map_or(0, String::len))
            as i64
            - old.size;
    if growth > 0 {
        crate::disk::ensure_room(&state, growth as u64).await?;
    }
    // A new password (or none) starts the count of wrong ones afresh.
    let new_password = changed.contains(&"password");
    sqlx::query(
        "UPDATE sends SET name = $1, data = $2, owner_key = $3, access_salt = $4, access_verifier = $5,
           max_views = $6, expires_at = $7, delete_at = $8, disabled = $9, hide_email = $10,
           updated_at = $11,
           wrong_passwords = CASE WHEN $13 = 1 THEN 0 ELSE wrong_passwords END,
           wrong_since = CASE WHEN $13 = 1 THEN 0 ELSE wrong_since END,
           owner_content_key = $14
         WHERE id = $12",
    )
    .bind(&name)
    .bind(&data)
    .bind(&owner_key)
    .bind(salt)
    .bind(verifier)
    .bind(max_views)
    .bind(expires_at)
    .bind(delete_at)
    .bind(disabled)
    .bind(hide_email)
    .bind(t)
    .bind(&id)
    .bind(new_password as i64)
    .bind(&content_key)
    .execute(&mut *tx)
    .await?;
    check_quota(&mut tx, &state, &user.user_id, growth).await?;
    Event::new("send.updated")
        .by(&user)
        .data(json!({ "send": id, "changed": changed }))
        .record(&mut tx, &state)
        .await?;
    let row = owned(&mut tx, &user.user_id, &id).await?;
    tx.commit().await?;
    let row = row.ok_or(ApiError::NotFound)?;
    Ok(Json(owner_json(&state, row, t)))
}

async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_id(&id) {
        return Err(ApiError::NotFound);
    }
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("DELETE FROM sends WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Event::new("send.deleted")
        .by(&user)
        .data(json!({ "send": id }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
}

/// Delete the Sends whose `delete_at` has passed (the sweeper, every ten
/// minutes). Their owners' logs say so. Returns how many.
pub async fn purge(state: &AppState) -> ApiResult<u64> {
    let mut tx = state.db.begin().await?;
    let gone: Vec<(String, String)> =
        sqlx::query_as("DELETE FROM sends WHERE delete_at <= $1 RETURNING id, user_id")
            .bind(now())
            .fetch_all(&mut *tx)
            .await?;
    for (id, owner) in &gone {
        Event::new("send.deleted")
            .target(owner)
            .data(json!({ "send": id, "reason": "deletion_date" }))
            .record(&mut tx, state)
            .await?;
    }
    tx.commit().await?;
    if !gone.is_empty() {
        tracing::info!(sends = gone.len(), "deleted Sends past their deletion date");
    }
    Ok(gone.len() as u64)
}

// ------------------------------------------------------------------ public

/// Whether a visitor may open a Send: on, not disabled, owner not disabled, not
/// past `delete_at` or `expires_at`, views left. `$2` is the time.
macro_rules! available {
    () => {
        "s.disabled = 0 AND u.disabled = 0 AND s.delete_at > $2
         AND (s.expires_at IS NULL OR s.expires_at > $2)
         AND (s.max_views IS NULL OR s.views < s.max_views)"
    };
}

#[derive(sqlx::FromRow)]
struct Public {
    id: String,
    kind: String,
    name: String,
    access_salt: Option<String>,
    access_verifier: Option<String>,
    expires_at: Option<i64>,
    delete_at: i64,
    hide_email: i64,
    email: String,
    /// Wrong passwords counted since `wrong_since` (Unix seconds).
    wrong_passwords: i64,
    wrong_since: i64,
}

/// A Send a visitor may open, or `None` (one answer for every reason why not).
async fn open_send(state: &AppState, id: &str) -> ApiResult<Option<Public>> {
    if !state.flag(Flag::Sends) || !valid_id(id) {
        return Ok(None);
    }
    Ok(sqlx::query_as(concat!(
        "SELECT s.id, s.kind, s.name, s.access_salt, s.access_verifier, s.expires_at, s.delete_at,
                s.hide_email, u.email, s.wrong_passwords, s.wrong_since
         FROM sends s JOIN users u ON u.id = s.user_id
         WHERE s.id = $1 AND ",
        available!()
    ))
    .bind(id)
    .bind(now())
    .fetch_optional(&state.db)
    .await?)
}

/// Every public request counts toward its address's per-minute cap.
fn public_limit(state: &AppState, ip: &str) -> ApiResult<()> {
    state.limiter.limit(
        Class::Address,
        &format!("send-ip:{ip}"),
        PUBLIC_PER_MINUTE,
        60,
    )
}

/// Seconds until the Send takes passwords again, while this hour's wrong ones are
/// used up.
fn locked_for(wrong: i64, since: i64, t: i64) -> Option<u64> {
    (wrong >= WRONG_PASSWORDS_PER_HOUR && t - since < WRONG_PASSWORDS_WINDOW)
        .then(|| (since + WRONG_PASSWORDS_WINDOW - t).max(1) as u64)
}

/// Count a wrong password against Send `id`, in the statement that checks the
/// hour's budget isn't used up: 401 `wrong_password`, or 429 once
/// [`WRONG_PASSWORDS_PER_HOUR`] came within the hour (so at most that many guesses
/// an hour get an answer, however many arrive at once), or 404 when it went away.
async fn wrong_password(state: &AppState, id: &str, t: i64) -> ApiResult<ApiError> {
    let counted = sqlx::query(
        "UPDATE sends SET
           wrong_passwords = CASE WHEN wrong_since <= $2 THEN 1 ELSE wrong_passwords + 1 END,
           wrong_since = CASE WHEN wrong_since <= $2 THEN $3 ELSE wrong_since END
         WHERE id = $1 AND (wrong_since <= $2 OR wrong_passwords < $4)",
    )
    .bind(id)
    .bind(t - WRONG_PASSWORDS_WINDOW)
    .bind(t)
    .bind(WRONG_PASSWORDS_PER_HOUR)
    .execute(&state.db)
    .await?;
    if counted.rows_affected() == 1 {
        return Ok(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            code::WRONG_PASSWORD,
            "wrong password",
        ));
    }
    let since: Option<i64> = sqlx::query_scalar("SELECT wrong_since FROM sends WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    Ok(match since {
        Some(since) => {
            ApiError::TooManyRequests((since + WRONG_PASSWORDS_WINDOW - t).max(1) as u64)
        }
        None => ApiError::NotFound,
    })
}

/// `GET /api/public/sends/{id}`: what the page shows before opening a Send. Never
/// the text, and no view is counted. A Send with a password keeps its name too
/// (`null`) until the password is right: the open answer has it.
async fn public_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    public_limit(&state, &client_ip(&state, &headers))?;
    let s = open_send(&state, &id).await?.ok_or(ApiError::NotFound)?;
    let needs_password = s.access_verifier.is_some();
    Ok(Json(json!({
        "id": s.id,
        "kind": s.kind,
        "name": (!needs_password).then_some(s.name),
        "needs_password": needs_password,
        "access_salt": if needs_password { s.access_salt } else { None },
        "expires_at": s.expires_at,
        "delete_at": s.delete_at,
        "sender": (s.hide_email == 0).then_some(s.email),
    })))
}

#[derive(Deserialize)]
struct AccessBody {
    /// Derived from the password on the visitor's device; never logged.
    #[serde(default)]
    verifier: Option<String>,
}

/// `POST /api/public/sends/{id}/access` (`{"verifier"}` for a Send with a
/// password; no body otherwise): the encrypted name and text, counting one view.
/// The count is taken in the same statement that checks a view is left, so
/// visitors at once never get more than `max_views` between them.
async fn public_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<AccessBody>>,
) -> ApiResult<Json<Value>> {
    let verifier = body.and_then(|Json(b)| b.verifier);
    let ip = client_ip(&state, &headers);
    public_limit(&state, &ip)?;
    let s = open_send(&state, &id).await?.ok_or(ApiError::NotFound)?;
    // Only for a Send that exists: unknown ids make no limiter keys.
    state.limiter.limit(
        Class::Address,
        &format!("send-access:{ip}:{id}"),
        ACCESS_PER_MINUTE,
        60,
    )?;
    if let Some(expected) = &s.access_verifier {
        let t = now();
        let right = verifier
            .as_deref()
            .is_some_and(|v| ct_eq(&verifier_hash(v), expected));
        if !right {
            return Err(wrong_password(&state, &id, t).await?);
        }
        // While the hour's wrong passwords are used up, the right one waits too:
        // otherwise its answer would tell a guesser which guess was right.
        if let Some(wait) = locked_for(s.wrong_passwords, s.wrong_since, t) {
            return Err(ApiError::TooManyRequests(wait));
        }
    }
    let mut tx = state.db.begin().await?;
    // Still available, still the password that was checked, and a view left:
    // all in the statement that counts the view.
    let counted: Option<(String, String)> = sqlx::query_as(
        "UPDATE sends SET views = views + 1
         WHERE id = $1 AND disabled = 0 AND delete_at > $2
           AND (expires_at IS NULL OR expires_at > $2)
           AND (max_views IS NULL OR views < max_views)
           AND COALESCE(access_verifier, '') = $3
           AND user_id IN (SELECT id FROM users WHERE disabled = 0)
         RETURNING data, user_id",
    )
    .bind(&id)
    .bind(now())
    .bind(s.access_verifier.as_deref().unwrap_or_default())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((data, owner)) = counted else {
        return Err(ApiError::NotFound);
    };
    events::count_send_access(&mut tx, &owner, &id).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "kind": s.kind, "name": s.name, "data": data }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_128_random_bits_in_base64url() {
        let a = new_id();
        assert!(valid_id(&a), "{a}");
        assert_ne!(a, new_id());
        for bad in [
            "",
            "short",
            "../../../../etc/passwd",
            "AAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn passwords_need_both_fields() {
        assert!(new_password(None, None).unwrap().is_none());
        assert!(new_password(Some("salt-salt".into()), None).is_err());
        assert!(new_password(None, Some("verifier-1".into())).is_err());
        assert!(new_password(Some("short".into()), Some("verifier-1".into())).is_err());
        assert!(new_password(Some("salt salt".into()), Some("verifier-1".into())).is_err());
        let (salt, hash) = new_password(Some("salt-salt".into()), Some("verifier-1".into()))
            .unwrap()
            .unwrap();
        assert_eq!(salt, "salt-salt");
        assert_eq!(hash, hash_token("verifier-1"), "only a hash is kept");
    }
}
