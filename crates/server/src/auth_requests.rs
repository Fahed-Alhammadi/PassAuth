//! Approve a sign-in from another device (feature `login_with_device` while the admin
//! switch of the same name is on, the default).
//!
//! A new device that knows the account's email asks to sign in (`POST
//! /auth/requests`) with a fresh X25519 public key and a random access code that it
//! keeps (only the code's SHA-256 is stored). The account's apps that are online hear
//! about it on the live-sync socket (`{"type":"auth_request","id"}`) and list it
//! (`GET /account/auth-requests`) with a fingerprint phrase derived from the public
//! key ([`fingerprint_phrase`]); the new device shows the same words, derived on its
//! own. The user compares them and approves on an unlocked app: it seals the account
//! key to the public key and opens the request's `challenge`, a random value the
//! server sealed to the account's own public key, to prove it holds the account's
//! keys (`POST /account/auth-requests/{id}`; the server never sees the account key).
//! Phones with a push token registered for one of the account's sessions are woken
//! through the push relay as well (`push.rs`).
//! A stolen session alone can't approve. The first answer wins. The new device polls
//! (`GET /auth/requests/{id}` with the code in [`ACCESS_CODE_HEADER`]) and exchanges
//! an approved request exactly once, for a session; the sealed key only ever goes
//! out together with the session's tokens. The approval is the second step: an
//! account with two-step login isn't asked for it again (the 6-digit confirmation
//! code the core shows on the approving app and the new device types stays, and an
//! owner who approves a request they didn't start would still have to give that
//! code away). The admin's `require_two_step` still applies to approving and to the
//! new session (`policies.rs`).
//!
//! Emails without an account that may sign in (unknown, disabled, or not verified
//! while the server requires it) get the same answer after the same time, and their
//! request is stored the same way, with no account: nobody sees it, it stays pending
//! and expires. So do requests past an account's [`SHOWN_PER_EMAIL`]: at most that
//! many reach its devices within [`TTL`], however many addresses ask. Requests live
//! [`TTL`]; the sweeper marks them expired and deletes them a day later. A new master
//! password, signing out the other sessions, the admin revoking the sessions or
//! disabling the account end the account's open requests; deleting it removes them.
//!
//! The server can't check the sealed key, and the phrase is only as good as the
//! comparison the user makes: a server that swapped the public key would be caught
//! there, because each app derives the phrase from the key it holds (never from the
//! server's `fingerprint_phrase`, which is a convenience).

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use passauth_core::item::{b64, unb64};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::AnyConnection;

use crate::auth::{self, AuthUser, DeviceBody, SignIn, client_app, client_ip, visitor_ip};
use crate::config::canonical;
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::settings::Flag;
use crate::state::{
    App, AppState, Class, DeviceInfo, DeviceLogin, Notice, ct_eq, hash_token, normalize_email,
};
use crate::twofactor;

/// How long a request waits for its answer and its exchange, in seconds.
pub const TTL: i64 = 15 * 60;
/// Rows are deleted this long after they expired.
const KEEP: i64 = 86_400;
/// New requests per address ([`address_bucket`]: IPv6 by /48) per [`PER_ADDRESS_WINDOW`].
const PER_ADDRESS: u32 = 10;
const PER_ADDRESS_WINDOW: i64 = 600;
/// New requests per email and address within [`TTL`] (429 after that): someone
/// asking from elsewhere can't block the user's own new device.
const PER_EMAIL_AND_ADDRESS: u32 = 3;
/// Requests per email within [`TTL`] that reach the account's devices, from every
/// address together; later ones are answered the same and stored with no account.
/// Counted in memory (one at a time, in a [`crate::state::SlotCounter`] that treats
/// every email alike and that no flood resets) and in the table (kept across restarts).
pub const SHOWN_PER_EMAIL: i64 = 5;
/// New requests on the whole server per [`SERVER_WINDOW`]: rows for unknown emails
/// are cheap to ask for, so their number has a ceiling.
const PER_SERVER: u32 = 1000;
const SERVER_WINDOW: i64 = 600;
/// Rate-limiter key of [`PER_SERVER`].
pub const SERVER_LIMIT_KEY: &str = "auth-requests";
/// Polls per address per minute (a device polls every few seconds).
const POLLS_PER_MINUTE: u32 = 120;
/// Largest sealed account key accepted (base64url characters).
const MAX_SEALED_KEY: usize = 4096;
/// Longest device name and app name a request keeps (characters): the approving
/// app shows them as the new device claims them.
const MAX_CLAIMED_TEXT: usize = 64;
/// Access codes: 22 to 128 base64url characters (22 = 128 random bits).
const ACCESS_CODE_MIN: usize = 22;
const ACCESS_CODE_MAX: usize = 128;
/// A new request is answered no sooner than this after it arrived, with or without
/// an account behind the email: the only work that differs (one activity-log row, an
/// in-memory notice and starting the push task) hides well inside it.
const MIN_CREATE_TIME: Duration = Duration::from_millis(100);

/// Header carrying the access code when polling. Never in the URL: reverse proxies
/// often log query strings, and the code is worth a session once the request is
/// approved.
pub const ACCESS_CODE_HEADER: &str = "x-passauth-access-code";

/// Associated data of a request's `challenge`, followed by the request's id.
pub const CHALLENGE_AAD: &[u8] = b"passauth/login-with-device/challenge/v1:";

const PENDING: &str = "pending";
const APPROVED: &str = "approved";
const DENIED: &str = "denied";
const EXPIRED: &str = "expired";
const USED: &str = "used";

/// Words in a fingerprint phrase (about 64.6 bits).
pub const PHRASE_WORDS: usize = 5;
/// Hashed in front of the public key for [`fingerprint_phrase`].
pub const PHRASE_LABEL: &[u8] = b"passauth/login-with-device/phrase/v1";
/// Words in the EFF large wordlist.
const WORDLIST_LEN: u32 = 7776;

/// The EFF large wordlist (one word per line, in file order; the core's passphrase list).
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("../../core/src/eff_large_wordlist.txt")
        .lines()
        .collect()
});

/// The words both screens show for a request. `d` = SHA-256([`PHRASE_LABEL`] ‖ the
/// 32 raw bytes of the requester's X25519 public key); word `i` (0..5) is line
/// `u32::from_be_bytes(d[4i..4i+4]) % 7776` of the EFF large wordlist (0-based);
/// the words are joined by single spaces. Apps compute it themselves from the key
/// they hold.
pub fn fingerprint_phrase(public_key: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(PHRASE_LABEL)
        .chain_update(public_key)
        .finalize();
    let words = &*WORDS;
    digest[..]
        .as_chunks::<4>()
        .0
        .iter()
        .take(PHRASE_WORDS)
        .map(|c| words[(u32::from_be_bytes(*c) % WORDLIST_LEN) as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// 403 `login_with_device_disabled` while the admin switch is off.
pub(crate) fn enabled(state: &AppState) -> ApiResult<()> {
    if state.flag(Flag::LoginWithDevice) {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::LOGIN_WITH_DEVICE_DISABLED,
            "signing in with another device's approval is turned off on this server",
        ))
    }
}

/// The requester's X25519 public key: 32 bytes (base64url) that a sealed box can be
/// made for. A low-order point is refused like the core's `seal_to` refuses it: its
/// "shared" secret is one anyone can compute.
fn public_key(s: &str) -> ApiResult<[u8; 32]> {
    let bad = || ApiError::bad("public_key must be an X25519 public key (32 bytes, base64url)");
    let key: [u8; 32] = unb64(s)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(bad)?;
    passauth_core::crypto::seal_to(&key, &[], b"").map_err(|_| bad())?;
    Ok(key)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The visitor's rate-limit bucket for new requests: the IPv4 address, or the IPv6
/// /48 (one site often holds a whole /48: /64 buckets would give it 65,536).
fn address_bucket(state: &AppState, headers: &HeaderMap) -> String {
    match auth::client_addr(state, headers).map(canonical) {
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        Some(ip) => ip.to_string(),
        None => "direct".into(),
    }
}

/// What the approving app must find in a request's `challenge`: 32 bytes that only
/// the server can work out (keyed with its secret) and, once sealed to the account's
/// public key, only the account's own apps can read.
fn approval_nonce(state: &AppState, request_id: &str) -> [u8; 32] {
    auth::keyed(state, "auth-request-approval", request_id)
}

/// `pending` or `approved` past its expiry reads as `expired` (the sweeper may not
/// have marked it yet).
fn effective(status: &str, expires_at: i64, t: i64) -> &str {
    match status {
        PENDING | APPROVED if expires_at <= t => EXPIRED,
        s => s,
    }
}

// ----------------------------------------------------------- the new device

#[derive(Deserialize)]
pub struct NewRequest {
    email: String,
    /// X25519 public key made for this request only (base64url, 32 bytes).
    public_key: String,
    /// Random secret the device keeps to poll (base64url, at least 128 bits).
    access_code: String,
    device_id: String,
    device_name: String,
    #[serde(default = "default_kind")]
    device_kind: String,
    // `remember_token`, sent by apps for servers before 0.16.1 (a remembered device
    // skipped two-step login here), is ignored like any unknown field: the approval
    // is the second step now.
}

fn default_kind() -> String {
    "web".into()
}

/// `POST /auth/requests` (no session): `{id, fingerprint_phrase, expires_at}`, the
/// same for every email.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<NewRequest>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let started = tokio::time::Instant::now();
    let address = address_bucket(&state, &headers);
    state.limiter.limit(
        Class::Address,
        &format!("auth-request:{address}"),
        PER_ADDRESS,
        PER_ADDRESS_WINDOW,
    )?;
    let key = public_key(&b.public_key)?;
    if !(ACCESS_CODE_MIN..=ACCESS_CODE_MAX).contains(&b.access_code.len())
        || !b
            .access_code
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(ApiError::bad(
            "access_code must be 22 to 128 base64url characters (at least 128 random bits)",
        ));
    }
    let mut device = DeviceBody {
        id: b.device_id,
        name: b.device_name,
        kind: b.device_kind,
    }
    .validated()?;
    // Shown on the account's devices as the new device claims it: one short line,
    // no control or format characters (no bidi tricks), at most 64 characters.
    device.name = auth::display_text(&device.name, MAX_CLAIMED_TEXT);
    let email = normalize_email(&b.email);
    if !email.contains('@') || email.len() > 254 {
        return Err(ApiError::bad("invalid email address"));
    }
    state
        .limiter
        .limit(Class::Target, SERVER_LIMIT_KEY, PER_SERVER, SERVER_WINDOW)?;
    // Everything below is the same for every email, with an account or not.
    let email_hash = hex(&auth::keyed(&state, "auth-request-email", &email));
    state.limiter.limit(
        Class::Address,
        &format!("auth-request-email:{email_hash}:{address}"),
        PER_EMAIL_AND_ADDRESS,
        TTL,
    )?;
    let t = now();
    let shown_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_requests
         WHERE email_hash = $1 AND created_at > $2 AND user_id IS NOT NULL",
    )
    .bind(&email_hash)
    .bind(t - TTL)
    .fetch_one(&state.db)
    .await?;
    // Counted first in memory: of many requests at once, only so many get through.
    let room = state.limiter.auth_request_shown.hit(&email_hash).is_ok();
    // An account that could sign in with its password right now, while it hasn't
    // been asked too often; anything else gets a request nobody sees.
    let account: Option<(String, i64, i64)> =
        sqlx::query_as("SELECT id, disabled, email_verified FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    let user_id = account
        .and_then(|(id, disabled, verified)| {
            (disabled == 0 && (verified != 0 || !state.signups_verify())).then_some(id)
        })
        .filter(|_| room && shown_before < SHOWN_PER_EMAIL);
    let id = uuid::Uuid::new_v4().to_string();
    // The address is shown to the approving app; kept only while the admin lets the
    // activity log keep addresses (`event_ip`).
    let client = client_app(&headers).map(|c| auth::display_text(&c, MAX_CLAIMED_TEXT));
    let ip = visitor_ip(&state, &headers);
    let stored_ip = ip.clone().filter(|_| state.numbers.event_ip());
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO auth_requests (id, user_id, email_hash, requester_public_key, device_id,
             device_name, device_kind, client, ip, access_code_hash, status, created_at,
             expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(&id)
    .bind(&user_id)
    .bind(&email_hash)
    .bind(b64(&key))
    .bind(&device.id)
    .bind(&device.name)
    .bind(&device.kind)
    .bind(&client)
    .bind(&stored_ip)
    .bind(hash_token(&b.access_code))
    .bind(PENDING)
    .bind(t)
    .bind(t + TTL)
    .execute(&mut *tx)
    .await?;
    if let Some(user) = &user_id {
        Event::new("auth.request_created")
            .target(user)
            .from(client, ip)
            .data(json!({ "request": id, "device_kind": device.kind }))
            .record(&mut tx, &state)
            .await?;
    }
    tx.commit().await?;
    if let Some(user) = &user_id {
        state.notify_user(user, Notice::AuthRequest(id.clone()));
        // Phones with a push token hear about it too, from a task of its own: this
        // answer never waits for the database or the relay (`push.rs`).
        crate::push::notify_auth_request(&state, user);
    }
    tokio::time::sleep_until(started + MIN_CREATE_TIME).await;
    Ok(Json(json!({
        "id": id,
        "fingerprint_phrase": fingerprint_phrase(&key),
        "expires_at": t + TTL,
    })))
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    user_id: Option<String>,
    device_id: String,
    device_name: String,
    device_kind: String,
    access_code_hash: String,
    status: String,
    sealed_key: Option<String>,
    expires_at: i64,
}

/// `GET /auth/requests/{id}` with the access code in [`ACCESS_CODE_HEADER`] (no
/// session): `{status}` while `pending`, and when `denied`, `expired` or `used`
/// (exchanged already); once `approved`, the exchange (see [`exchange`]). 404 for an
/// unknown id or a wrong or missing code.
pub async fn poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    state.limiter.limit(
        Class::Address,
        &format!("auth-request-poll:{}", client_ip(&state, &headers)),
        POLLS_PER_MINUTE,
        60,
    )?;
    let code = headers
        .get(ACCESS_CODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|c| !c.is_empty())
        .ok_or(ApiError::NotFound)?;
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, user_id, device_id, device_name, device_kind, access_code_hash, status,
                sealed_key, expires_at
         FROM auth_requests WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?;
    let row = row
        .filter(|r| ct_eq(&r.access_code_hash, &hash_token(code)))
        .ok_or(ApiError::NotFound)?;
    let status = effective(&row.status, row.expires_at, now());
    if status != APPROVED {
        return Ok(Json(json!({ "status": status })));
    }
    exchange(&state, &headers, row).await
}

/// An approved request, exchanged exactly once for `{status: "approved", sealed_key,
/// access_token, refresh_token, expires_in, remember_token (always null), user_id,
/// email, bundle}` (the session answer of a password sign-in). Never for a two-step
/// challenge: the approval by the account's own signed-in, unlocked app is the second
/// step (since 0.16.1; older servers asked an account with two-step login for it
/// here). A poll that loses the race for it answers `{status: "used"}`.
async fn exchange(state: &AppState, headers: &HeaderMap, row: Row) -> ApiResult<Json<Value>> {
    let (Some(user_id), Some(sealed_key)) = (row.user_id, row.sealed_key) else {
        return Err(anyhow::anyhow!("approved sign-in request without an account or a key").into());
    };
    let claimed = sqlx::query(
        "UPDATE auth_requests SET status = 'used', sealed_key = NULL, remember_hash = NULL
         WHERE id = $1 AND status = 'approved' AND expires_at > $2",
    )
    .bind(&row.id)
    .bind(now())
    .execute(&state.db)
    .await?;
    if claimed.rows_affected() != 1 {
        let now_status: Option<(String, i64)> =
            sqlx::query_as("SELECT status, expires_at FROM auth_requests WHERE id = $1")
                .bind(&row.id)
                .fetch_optional(&state.db)
                .await?;
        let (status, expires_at) = now_status.ok_or(ApiError::NotFound)?;
        return Ok(Json(
            json!({ "status": effective(&status, expires_at, now()) }),
        ));
    }
    // As at a password sign-in: the account may have changed since it approved.
    let account: Option<(i64, i64)> =
        sqlx::query_as("SELECT disabled, email_verified FROM users WHERE id = $1")
            .bind(&user_id)
            .fetch_optional(&state.db)
            .await?;
    let (disabled, verified) = account.ok_or(ApiError::NotFound)?;
    if disabled != 0 {
        auth::failed(state, headers, &user_id, "account_disabled");
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::ACCOUNT_DISABLED,
            "this account is disabled",
        ));
    }
    if verified == 0 && state.signups_verify() {
        auth::failed(state, headers, &user_id, "email_not_verified");
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::EMAIL_NOT_VERIFIED,
            "email_not_verified",
        ));
    }
    let device = DeviceInfo {
        id: row.device_id,
        name: row.device_name,
        kind: row.device_kind,
    };
    let login = DeviceLogin {
        request_id: row.id,
        sealed_key,
    };
    // The approval came from the account's own signed-in, unlocked app: that is the
    // second step, so no two-step challenge here (the event says so).
    let two_step = (!twofactor::enabled_providers(&state.db, &user_id)
        .await?
        .is_empty())
    .then_some("device_approval");
    let mut out = auth::issue_session(
        state,
        headers,
        &user_id,
        &device,
        None,
        two_step,
        SignIn::Device(&login),
    )
    .await?;
    out["status"] = APPROVED.into();
    Ok(Json(out))
}

// ------------------------------------------------------- approving devices

#[derive(sqlx::FromRow)]
struct Listed {
    id: String,
    requester_public_key: String,
    device_name: String,
    device_kind: String,
    client: Option<String>,
    ip: Option<String>,
    created_at: i64,
    expires_at: i64,
}

/// `GET /account/auth-requests`: `{requests: [{id, public_key, fingerprint_phrase,
/// challenge, device_name, device_kind, client, ip, created_at, expires_at}]}`, the
/// account's unanswered, unexpired requests, newest first. `challenge` is sealed to
/// the account's public key with associated data [`CHALLENGE_AAD`] + the request's
/// id; its plaintext, sent back as `proof`, shows an approval comes from an app that
/// holds the account's keys.
pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let account_key: String = sqlx::query_scalar("SELECT public_key FROM users WHERE id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    let account_key: [u8; 32] = unb64(&account_key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the account's public key is unreadable"))?;
    let rows: Vec<Listed> = sqlx::query_as(
        "SELECT id, requester_public_key, device_name, device_kind, client, ip, created_at, expires_at
         FROM auth_requests WHERE user_id = $1 AND status = 'pending' AND expires_at > $2
         ORDER BY created_at DESC, id DESC",
    )
    .bind(&user.user_id)
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    let mut requests = Vec::with_capacity(rows.len());
    for r in rows {
        let phrase = unb64(&r.requester_public_key)
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .map(|k| fingerprint_phrase(&k));
        let aad = [CHALLENGE_AAD, r.id.as_bytes()].concat();
        let challenge =
            passauth_core::crypto::seal_to(&account_key, &approval_nonce(&state, &r.id), &aad)
                .map_err(|e| anyhow::anyhow!("sealing a sign-in request's challenge: {e}"))?;
        requests.push(json!({
            "id": r.id,
            "public_key": r.requester_public_key,
            "fingerprint_phrase": phrase,
            "challenge": b64(&challenge),
            "device_name": r.device_name,
            "device_kind": r.device_kind,
            "client": r.client,
            "ip": r.ip,
            "created_at": r.created_at,
            "expires_at": r.expires_at,
        }));
    }
    Ok(Json(json!({ "requests": requests })))
}

#[derive(Deserialize)]
pub struct Answer {
    approve: bool,
    /// With `approve: true`: the account key sealed to the request's public key.
    #[serde(default)]
    sealed_key: Option<String>,
    /// With `approve: true`: the request's `challenge` opened with the account's
    /// private key (base64url).
    #[serde(default)]
    proof: Option<String>,
}

/// `POST /account/auth-requests/{id} {approve: true, sealed_key, proof}` or
/// `{approve: false}`: `{id, status}`. Approving needs the opened challenge (403
/// otherwise); denying works from any session of the account. Only the account's own
/// requests (else 404), only while pending and unexpired (400 `expired`); the first
/// answer wins (409 `conflict` for any later one, except the same answer again from
/// the session that gave it, a retry).
pub async fn answer(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Answer>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let sealed = match (b.approve, b.sealed_key) {
        (false, _) => None,
        (true, Some(k)) if !k.is_empty() && k.len() <= MAX_SEALED_KEY && unb64(&k).is_ok() => {
            Some(k)
        }
        (true, _) => {
            return Err(ApiError::bad(
                "sealed_key must be the account key sealed to the request's public key, in base64url",
            ));
        }
    };
    if b.approve {
        let proof = b.proof.ok_or_else(|| {
            ApiError::bad("proof must be the request's challenge, opened with the account's keys")
        })?;
        if !ct_eq(&proof, &b64(&approval_nonce(&state, &id))) {
            return Err(ApiError::Forbidden(
                "approving needs an unlocked app: the challenge's proof is wrong".into(),
            ));
        }
    }
    let status = if b.approve { APPROVED } else { DENIED };
    let t = now();
    let mut tx = state.db.begin().await?;
    // Compare-and-swap on the status: of two answers at once, one changes the row
    // and the other finds it answered.
    let won: Option<String> = sqlx::query_scalar(
        "UPDATE auth_requests SET status = $1, sealed_key = $2, approved_by_session = $3, answered_at = $4,
             ip = NULL
         WHERE id = $5 AND user_id = $6 AND status = 'pending' AND expires_at > $4
         RETURNING device_kind",
    )
    .bind(status)
    .bind(&sealed)
    .bind(&user.session_id)
    .bind(t)
    .bind(&id)
    .bind(&user.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(device_kind) = won else {
        drop(tx);
        return answered_before(&state, &user, &id, status).await;
    };
    let kind = if b.approve {
        "auth.request_approved"
    } else {
        "auth.request_denied"
    };
    Event::new(kind)
        .by(&user)
        .data(json!({ "request": id, "device_kind": device_kind }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    state.notify_user(&user.user_id, Notice::AuthRequestAnswered(id.clone()));
    Ok(Json(json!({ "id": id, "status": status })))
}

/// Why an answer found nothing to change: 404 (not this account's), 400 `expired`,
/// 409 `conflict` (answered already), or the stored answer when this session gave
/// the same one before (a retry whose first try landed; the first sealed key stays).
async fn answered_before(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    status: &str,
) -> ApiResult<Json<Value>> {
    let row: Option<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT status, expires_at, approved_by_session FROM auth_requests
         WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let (stored, expires_at, by) = row.ok_or(ApiError::NotFound)?;
    let stored = effective(&stored, expires_at, now());
    let same = by.as_deref() == Some(user.session_id.as_str())
        && match stored {
            APPROVED | USED => status == APPROVED,
            DENIED => status == DENIED,
            _ => false,
        };
    if same {
        return Ok(Json(json!({ "id": id, "status": status })));
    }
    if stored == EXPIRED {
        return Err(ApiError::expired("this sign-in request expired"));
    }
    Err(ApiError::Conflict(
        "this sign-in request was already answered".into(),
    ))
}

// ------------------------------------------------------------ housekeeping

/// End the account's requests that could still become a session (inside the
/// caller's transaction): after a new master password, signing out the other
/// sessions, the admin revoking the sessions or disabling the account. Returns how
/// many.
pub async fn cancel_open(conn: &mut AnyConnection, user_id: &str) -> ApiResult<u64> {
    let done = sqlx::query(
        "UPDATE auth_requests SET status = 'expired', sealed_key = NULL, remember_hash = NULL, ip = NULL
         WHERE user_id = $1 AND status IN ('pending', 'approved')",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected())
}

/// Every minute: mark requests past their time `expired` (dropping any sealed key
/// that was never taken, the device's remember-token hash and the address), and
/// delete those that expired more than a day ago.
pub async fn sweep(state: &App) -> ApiResult<()> {
    let t = now();
    sqlx::query(
        "UPDATE auth_requests SET status = 'expired', sealed_key = NULL, remember_hash = NULL, ip = NULL
         WHERE status IN ('pending', 'approved') AND expires_at <= $1",
    )
    .bind(t)
    .execute(&state.db)
    .await?;
    sqlx::query("DELETE FROM auth_requests WHERE expires_at < $1")
        .bind(t - KEEP)
        .execute(&state.db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_phrases_follow_the_documented_derivation() {
        assert_eq!(WORDS.len(), WORDLIST_LEN as usize);
        assert_eq!(
            (WORDS[0], WORDS[7775]),
            ("abacus", "zoom"),
            "the EFF large wordlist, in file order"
        );
        // Vectors for the apps, computed by an independent implementation.
        for (key, phrase) in [
            (
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "lung spout ashen sudoku gloating",
            ),
            (
                "__________________________________________8",
                "granddad hate dangle spectrum dexterous",
            ),
            (
                "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
                "casket thwarting commodity blasphemy ramp",
            ),
        ] {
            let key: [u8; 32] = unb64(key).unwrap().try_into().unwrap();
            assert_eq!(fingerprint_phrase(&key), phrase);
        }
    }

    #[test]
    fn low_order_and_malformed_public_keys_are_refused() {
        let real = passauth_core::crypto::KeyPair::generate().unwrap();
        assert!(public_key(&b64(&real.public_bytes())).is_ok());
        for bad in [
            b64(&[0; 32]),
            b64(&[1; 31]),
            "not base64!".into(),
            String::new(),
        ] {
            assert!(public_key(&bad).is_err(), "{bad}");
        }
        // The point of order 8 with u = 325606250916557431795983626356110631294008115727848805560023387167927233504.
        let mut order8 = [0u8; 32];
        order8[..8].copy_from_slice(&[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae]);
        order8[8..16].copy_from_slice(&[0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a]);
        order8[16..24].copy_from_slice(&[0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd]);
        order8[24..].copy_from_slice(&[0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00]);
        assert!(public_key(&b64(&order8)).is_err());
    }
}
