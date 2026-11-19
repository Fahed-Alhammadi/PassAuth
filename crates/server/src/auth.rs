//! Registration, OPAQUE login, two-factor, sessions.
//!
//! Login never reveals whether an email exists: unknown emails get a
//! deterministic fake prelogin answer and the OPAQUE exchange runs against a
//! fake record, failing only at the final step like a wrong password.

use std::net::IpAddr;

use axum::extract::{FromRequestParts, State};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::routing::{get, post};
use axum::{Json, Router};
use passauth_core::item::{b64, unb64};
use passauth_core::kdf::KdfParams;
use passauth_core::keys::AccountBundle;
use passauth_core::opaque::Suite;
use passauth_core::opaque::opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand_core06::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::canonical;
use crate::db::{now, now_ms};
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::mail::Email;
use crate::passkeys;
use crate::policies;
use crate::settings::Num;
use crate::state::{
    AppState, Class, DeviceInfo, DeviceLogin, KeyContext, PendingLogin, PendingRegistration,
    PendingTwoFactor, Sessions, SyncNotice, ct_eq, hash_token, normalize_email, random_token,
};
use crate::twofactor;

pub const ACCESS_TTL: i64 = 15 * 60;

/// An admin setting in days, as seconds. Read at each use: `session_days` (a
/// session ends this long after sign-in however often it is refreshed),
/// `refresh_days` (a device may stay away this long), `remember_device_days`.
fn days(state: &AppState, n: Num) -> i64 {
    state.num(n) * 86_400
}

/// `X-PassAuth-Client: <name>/<version>`, sent by every client app.
pub const CLIENT_HEADER: &str = "x-passauth-client";

/// The client app from [`CLIENT_HEADER`] (e.g. `ios/0.6.0`), if well-formed.
pub fn client_app(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CLIENT_HEADER)?.to_str().ok()?.trim();
    let (name, version) = value.split_once('/')?;
    let part = |s: &str| {
        !s.is_empty()
            && s.len() <= 32
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
    };
    (part(name) && part(version)).then(|| value.to_owned())
}

/// The first release of each app that reads epoch-bound (v2) account wraps (signed
/// sharing, 2026-11-16): `<name>/<version>` as the apps send it. The web vault is
/// served by the server (0.12.0 and later read them); the macOS AutoFill extension
/// carries the desktop app's version. Any other name is unknown here.
const READS_BOUND_WRAPS: &[(&str, (u64, u64, u64))] = &[
    ("web", (0, 12, 0)),
    ("desktop", (0, 9, 0)),
    ("macos-autofill", (0, 9, 0)),
    ("extension", (0, 8, 0)),
    ("ios", (0, 8, 0)),
    ("android", (0, 8, 0)),
];

/// Whether the app of a session (its [`CLIENT_HEADER`], `None` when it never said)
/// reads epoch-bound account wraps: a known app at or above its first such release.
/// Missing, unknown or unparseable = no (an app from before API 2 sent nothing).
/// Version: `X[.Y[.Z]]`, anything from the first `-` or `+` on ignored.
pub fn reads_bound_wraps(client: Option<&str>) -> bool {
    client_at_least(client, READS_BOUND_WRAPS)
}

/// The first release of each app that keeps vault manifests (2026-11-18): it sends
/// the next manifest with every write into a vault that has one, so a vault's first
/// manifest waits until every signed-in app of every member is one of these
/// (`manifest_ok` in `/sync`).
const KEEPS_MANIFESTS: &[(&str, (u64, u64, u64))] = &[
    ("web", (0, 15, 0)),
    ("desktop", (0, 13, 0)),
    ("macos-autofill", (0, 13, 0)),
    ("extension", (0, 12, 0)),
    ("ios", (0, 12, 0)),
    ("android", (0, 12, 0)),
];

/// Whether the app of a session keeps vault manifests ([`KEEPS_MANIFESTS`]; missing,
/// unknown or unparseable = no).
pub fn keeps_manifests(client: Option<&str>) -> bool {
    client_at_least(client, KEEPS_MANIFESTS)
}

/// Whether `client` (`<name>/<version>`) is a known app at or above its version in
/// `table`. Version: `X[.Y[.Z]]`, anything from the first `-` or `+` on ignored.
fn client_at_least(client: Option<&str>, table: &[(&str, (u64, u64, u64))]) -> bool {
    let Some((name, version)) = client.and_then(|c| c.split_once('/')) else {
        return false;
    };
    let Some(&(_, min)) = table.iter().find(|(n, _)| *n == name) else {
        return false;
    };
    let core = version.split(['-', '+']).next().unwrap_or_default();
    let mut parts = core.split('.');
    let mut next = |required: bool| -> Option<u64> {
        match parts.next() {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok(),
            None if !required => Some(0),
            _ => None,
        }
    };
    let (Some(major), Some(minor), Some(patch)) = (next(true), next(false), next(false)) else {
        return false;
    };
    parts.next().is_none() && (major, minor, patch) >= min
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/prelogin", post(prelogin))
        .route("/register/init", post(register_init))
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/login/start", post(login_start))
        .route("/login/finish", post(login_finish))
        .route("/2fa/verify", post(two_factor_verify))
        .route("/2fa/email", post(two_factor_send_email))
        .route("/2fa/passkey/start", post(two_factor_passkey_start))
        .route("/2fa/passkey/finish", post(two_factor_passkey_finish))
        .route("/2fa/passkey/context", get(two_factor_passkey_context))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/verify-email", post(verify_email))
        .route("/verify-email/resend", post(resend_verification))
        .route("/requests", post(crate::auth_requests::create))
        .route("/requests/{id}", get(crate::auth_requests::poll))
}

// ---------------------------------------------------------------- extractor

/// An authenticated request (valid, unexpired access token).
#[derive(Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub session_id: String,
    pub email: String,
    /// The app that sent the request ([`CLIENT_HEADER`]), for the activity log.
    pub client: Option<String>,
    /// The visitor's address ([`visitor_ip`]), for the activity log.
    pub ip: Option<String>,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        // Header only: `?access_token=` is accepted on the WebSocket route alone (`ws::WsUser`).
        let token = bearer(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let mut user = authenticate(state, &token).await?;
        policies::two_step_gate(
            state,
            &user.user_id,
            &parts.method,
            policies::request_path(parts),
        )
        .await?;
        user.client = client_app(&parts.headers);
        user.ip = visitor_ip(state, &parts.headers);
        Ok(user)
    }
}

pub async fn authenticate(state: &AppState, token: &str) -> ApiResult<AuthUser> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT s.id, s.user_id, u.email FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.access_hash = $1 AND s.access_expires > $2 AND u.disabled = 0",
    )
    .bind(hash_token(token))
    .bind(now())
    .fetch_optional(&state.db)
    .await?;
    let (session_id, user_id, email) = row.ok_or(ApiError::Unauthorized)?;
    Ok(AuthUser {
        user_id,
        session_id,
        email,
        client: None,
        ip: None,
    })
}

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_owned())
}

/// Internal header set by the server from the TCP peer address (see `main::peer_ip`).
pub const PEER_IP_HEADER: &str = "x-passauth-peer-ip";

/// Client address for rate limiting.
///
/// The `IP_HEADER` value is believed only when the TCP peer is a trusted proxy
/// (`TRUSTED_PROXIES`, default loopback and private networks), and then the
/// right-most address that isn't itself a trusted proxy is used: entries to
/// its left were written by the client and can be anything. IPv6 addresses
/// are bucketed by /64, since one host usually controls a whole /64.
pub fn client_ip(state: &AppState, headers: &HeaderMap) -> String {
    client_addr(state, headers).map_or_else(|| "direct".into(), rate_key)
}

/// The visitor's address as text (IPv4-mapped IPv6 as IPv4), for the activity log.
pub fn visitor_ip(state: &AppState, headers: &HeaderMap) -> Option<String> {
    client_addr(state, headers).map(|ip| canonical(ip).to_string())
}

/// The visitor's address: `IP_HEADER` when the peer is a trusted proxy, else the TCP peer.
pub fn client_addr(state: &AppState, headers: &HeaderMap) -> Option<IpAddr> {
    let peer: Option<IpAddr> = headers
        .get(PEER_IP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    let trusted = |ip: IpAddr| match &state.config.trusted_proxies {
        Some(nets) => nets.iter().any(|n| n.contains(ip)),
        None => is_private(ip),
    };
    let forwarded = state
        .config
        .ip_header
        .as_deref()
        .filter(|_| peer.is_some_and(trusted))
        .and_then(|name| headers.get(name))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let hops: Vec<IpAddr> = v.split(',').filter_map(|h| parse_hop(h.trim())).collect();
            hops.iter()
                .rev()
                .find(|ip| !trusted(**ip))
                .or(hops.first())
                .copied()
        });
    forwarded.or(peer)
}

/// An address from a forwarding header: `1.2.3.4`, `1.2.3.4:567`, `[::1]:80` or `::1`.
fn parse_hop(h: &str) -> Option<IpAddr> {
    h.parse()
        .ok()
        .or_else(|| h.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
        .or_else(|| h.trim_start_matches('[').trim_end_matches(']').parse().ok())
}

fn is_private(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Rate-limit bucket for an address (IPv6 by /64).
fn rate_key(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// A per-address limit ([`Class::Address`]).
fn limit(state: &AppState, key: String, n: u32, window: i64) -> ApiResult<()> {
    state.limiter.limit(Class::Address, &key, n, window)
}

/// A limit of an account a sign-in in progress has proven exists ([`Class::Target`]).
fn limit_account(state: &AppState, key: String, n: u32, window: i64) -> ApiResult<()> {
    state.limiter.limit(Class::Target, &key, n, window)
}

/// Sign-in attempts per email within [`LOGIN_PER_EMAIL_WINDOW`] from every address
/// together. Counted in a [`crate::state::SlotCounter`]: every email, with an account
/// or not, the same way, and no flood of other emails resets it.
pub const LOGIN_PER_EMAIL: u32 = 100;
pub const LOGIN_PER_EMAIL_WINDOW: i64 = 300;

// ---------------------------------------------------------------- prelogin

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

#[derive(Serialize)]
pub struct Prelogin {
    pub account_id: String,
    pub kdf: KdfParams,
    pub secret_key_required: bool,
}

async fn prelogin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<EmailBody>,
) -> ApiResult<Json<Prelogin>> {
    // Every sign-in starts here, so twice the sign-in attempts (60 by default).
    let attempts = state.num(Num::SigninAttemptsPerMinute) as u32;
    limit(
        &state,
        format!("prelogin:{}", client_ip(&state, &headers)),
        attempts * 2,
        60,
    )?;
    let email = normalize_email(&b.email);
    let bundle: Option<String> = sqlx::query_scalar("SELECT bundle FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(match bundle {
        Some(json) => {
            let b: AccountBundle = serde_json::from_str(&json).map_err(anyhow::Error::from)?;
            Prelogin {
                account_id: b.account_id,
                kdf: b.kdf,
                secret_key_required: b.secret_key_enabled,
            }
        }
        None => fake_prelogin(&state, &email),
    }))
}

pub(crate) fn keyed(state: &AppState, label: &str, email: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(state.prelogin_secret);
    h.update(label.as_bytes());
    h.update(email.as_bytes());
    h.finalize().into()
}

/// The answer for an email without an account: stable, and shaped like a new
/// account's under the server's policies (key derivation, Secret Key), so it
/// doesn't stand out from real ones.
fn fake_prelogin(state: &AppState, email: &str) -> Prelogin {
    let id: [u8; 16] = keyed(state, "id", email)[..16]
        .try_into()
        .expect("16 bytes");
    let salt = &keyed(state, "salt", email)[..16];
    let (memory_kib, iterations) = policies::new_account_kdf(state);
    Prelogin {
        account_id: uuid::Builder::from_random_bytes(id).into_uuid().to_string(),
        kdf: KdfParams {
            memory_kib,
            iterations,
            parallelism: 1,
            salt: b64(salt),
        },
        secret_key_required: state.flag(crate::settings::Flag::RequireSecretKey),
    }
}

// ------------------------------------------------------------ registration

async fn register_init(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<EmailBody>,
) -> ApiResult<Json<Value>> {
    limit(
        &state,
        format!("register:{}", client_ip(&state, &headers)),
        10,
        3600,
    )?;
    let email = normalize_email(&b.email);
    if !email.contains('@') || email.len() > 254 {
        return Err(ApiError::bad("invalid email address"));
    }
    let invited: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM invites WHERE email = $1 AND expires_at > $2",
    )
    .bind(&email)
    .bind(now())
    .fetch_one(&state.db)
    .await?
        > 0;
    let permitted = state
        .signups
        .read()
        .expect("signup policy lock")
        .permits(&email);
    if !invited && !permitted {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::SIGNUPS_CLOSED,
            "registration is closed on this server",
        ));
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&state.db)
        .await?;
    if exists > 0 {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::ACCOUNT_EXISTS,
            "an account with this email already exists",
        ));
    }
    let account_id = uuid::Uuid::new_v4().to_string();
    let registration_id = state.registrations.insert(
        PendingRegistration {
            email,
            account_id: account_id.clone(),
        },
        15 * 60,
    );
    Ok(Json(
        json!({ "registration_id": registration_id, "account_id": account_id }),
    ))
}

#[derive(Deserialize)]
struct RegisterStart {
    registration_id: String,
    message: String,
}

async fn register_start(
    State(state): State<AppState>,
    Json(b): Json<RegisterStart>,
) -> ApiResult<Json<Value>> {
    let (exp, pending) = state
        .registrations
        .take(&b.registration_id)
        .ok_or(ApiError::expired("registration expired"))?;
    let req = RegistrationRequest::<Suite>::deserialize(&unb64(&b.message)?)
        .map_err(|_| ApiError::bad("bad message"))?;
    let resp =
        ServerRegistration::<Suite>::start(&state.opaque, req, pending.account_id.as_bytes())
            .map_err(|_| ApiError::bad("bad message"))?;
    state
        .registrations
        .put_back(b.registration_id, pending, exp);
    Ok(Json(json!({ "message": b64(&resp.message.serialize()) })))
}

#[derive(Deserialize)]
pub struct NewVault {
    pub id: String,
    pub meta: String,
    pub wrapped_key: String,
}

#[derive(Deserialize)]
struct RegisterFinish {
    registration_id: String,
    upload: String,
    bundle: AccountBundle,
    #[serde(default)]
    name: String,
    vault: NewVault,
}

async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<RegisterFinish>,
) -> ApiResult<Json<Value>> {
    let (_, pending) = state
        .registrations
        .take(&b.registration_id)
        .ok_or(ApiError::expired("registration expired"))?;
    if b.bundle.account_id != pending.account_id {
        return Err(ApiError::bad("bundle does not match registration"));
    }
    b.bundle.kdf.validate()?;
    policies::check_new_keys(&state, &b.bundle)?;
    let name = b.name.trim();
    if name.chars().count() > 100 {
        return Err(ApiError::bad("name too long"));
    }
    let upload = RegistrationUpload::<Suite>::deserialize(&unb64(&b.upload)?)
        .map_err(|_| ApiError::bad("bad upload"))?;
    let record = b64(&ServerRegistration::<Suite>::finish(upload).serialize());
    let t = now();
    let verified = !state.mailer.enabled();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, disabled, opaque_record, bundle, public_key, revision, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8, $9, $9)",
    )
    .bind(&pending.account_id)
    .bind(&pending.email)
    .bind(name)
    .bind(verified as i64)
    .bind(&record)
    .bind(serde_json::to_string(&b.bundle).map_err(anyhow::Error::from)?)
    .bind(&b.bundle.public_key)
    .bind(now_ms())
    .bind(t)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        ApiError::conflict_on_unique(
            e,
            code::ACCOUNT_EXISTS,
            "an account with this email already exists",
        )
    })?;
    crate::vault::insert_vault(&mut tx, &pending.account_id, &b.vault, "owner", "account").await?;
    sqlx::query("DELETE FROM invites WHERE email = $1")
        .bind(&pending.email)
        .execute(&mut *tx)
        .await?;
    let (client, ip) = (client_app(&headers), visitor_ip(&state, &headers));
    for event in [
        Event::new("account.created"),
        Event::new("vault.created").vault(&b.vault.id),
    ] {
        event
            .actor(&pending.account_id)
            .from(client.clone(), ip.clone())
            .record(&mut tx, &state)
            .await?;
    }
    tx.commit().await?;

    if !verified {
        send_verification(&state, &pending.account_id, &pending.email).await?;
    }
    tracing::info!(user = %pending.account_id, "account registered");
    Ok(Json(
        json!({ "user_id": pending.account_id, "email_verification_required": !verified }),
    ))
}

async fn send_verification(state: &AppState, user_id: &str, email: &str) -> ApiResult<()> {
    let token = random_token();
    sqlx::query("DELETE FROM email_tokens WHERE user_id = $1 AND purpose = 'verify'")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO email_tokens (id, user_id, purpose, token_hash, attempts, expires_at) VALUES ($1, $2, 'verify', $3, 0, $4)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(hash_token(&token))
        .bind(now() + 48 * 3600)
        .execute(&state.db)
        .await?;
    state.mailer.send_later(
        email.to_owned(),
        Email {
            subject: "Verify your PassAuth email".into(),
            heading: "Confirm your email address".into(),
            body: "Welcome to PassAuth! Confirm this address to finish setting up your account. The link expires in 48 hours.".into(),
            action: Some(("Verify email".into(), format!("{}/verify-email?token={token}", state.config.domain))),
            code: None,
        },
    );
    Ok(())
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

async fn verify_email(
    State(state): State<AppState>,
    Json(b): Json<TokenBody>,
) -> ApiResult<Json<Value>> {
    let user_id: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM email_tokens WHERE purpose = 'verify' AND token_hash = $1 AND expires_at > $2",
    )
    .bind(hash_token(&b.token))
    .bind(now())
    .fetch_optional(&state.db)
    .await?;
    let user_id = user_id.ok_or(ApiError::expired("invalid or expired link"))?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET email_verified = 1, updated_at = $1 WHERE id = $2")
        .bind(now())
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM email_tokens WHERE user_id = $1 AND purpose = 'verify'")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    // `/sync` reports `email_verified`: signed-in devices pick the change up.
    let revision = crate::vault::bump_user(&mut tx, &user_id).await?;
    tx.commit().await?;
    if let Some(revision) = revision {
        state.notify_sync(vec![(user_id, SyncNotice::new(revision, None))]);
    }
    Ok(Json(json!({ "verified": true })))
}

async fn resend_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<EmailBody>,
) -> ApiResult<Json<Value>> {
    limit(
        &state,
        format!("resend:{}", client_ip(&state, &headers)),
        5,
        3600,
    )?;
    let email = normalize_email(&b.email);
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT id, email_verified FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    if let Some((id, 0)) = row {
        send_verification(&state, &id, &email).await?;
    }
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------------- login

#[derive(Deserialize)]
struct LoginStart {
    email: String,
    message: String,
}

async fn login_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<LoginStart>,
) -> ApiResult<Json<Value>> {
    let email = normalize_email(&b.email);
    limit(
        &state,
        format!("login-ip:{}", client_ip(&state, &headers)),
        state.num(Num::SigninAttemptsPerMinute) as u32,
        60,
    )?;
    // Per (email, address), so nobody can lock an account out from elsewhere;
    // the higher per-email ceiling still slows a distributed guesser.
    let ip = client_ip(&state, &headers);
    limit(&state, format!("login-email:{email}:{ip}"), 10, 300)?;
    state.limiter.login_email.limit(&email)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT id, opaque_record FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    let (user_id, record, credential_id) = match row {
        Some((id, rec)) => {
            let rec = ServerRegistration::<Suite>::deserialize(&unb64(&rec)?)
                .map_err(|_| anyhow::anyhow!("corrupt OPAQUE record"))?;
            (Some(id.clone()), Some(rec), id)
        }
        None => (None, None, fake_prelogin(&state, &email).account_id),
    };
    let req = CredentialRequest::<Suite>::deserialize(&unb64(&b.message)?)
        .map_err(|_| ApiError::bad("bad message"))?;
    let start = ServerLogin::start(
        &mut OsRng,
        &state.opaque,
        record,
        req,
        credential_id.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|_| ApiError::bad("bad message"))?;
    let login_id = state.logins.insert(
        PendingLogin {
            user_id,
            state: start.state.serialize().to_vec(),
        },
        120,
    );
    Ok(Json(
        json!({ "login_id": login_id, "message": b64(&start.message.serialize()) }),
    ))
}

#[derive(Deserialize)]
pub struct DeviceBody {
    pub id: String,
    pub name: String,
    #[serde(default = "default_kind")]
    pub kind: String,
}

fn default_kind() -> String {
    "web".into()
}

/// Unicode format characters (general category Cf: bidi embeddings, overrides and
/// isolates, zero-width characters, the byte order mark, tags…) and the line and
/// paragraph separators: invisible, or able to make a text read differently from
/// what it is (`evil\u{202E}moc.elgoog`).
fn is_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// Text someone else's screen or email shows as it was sent (a device name):
/// without control and format characters, at most `max` characters, trimmed.
pub(crate) fn display_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_format(*c))
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

impl DeviceBody {
    /// Bounded, printable device details (they appear in emails and the session list).
    pub(crate) fn validated(self) -> ApiResult<DeviceInfo> {
        let id = self.id.trim();
        if id.is_empty()
            || id.len() > 128
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c))
        {
            return Err(ApiError::bad("invalid device id"));
        }
        let kind = self.kind.trim().to_ascii_lowercase();
        if kind.is_empty()
            || kind.len() > 32
            || !kind
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        {
            return Err(ApiError::bad("invalid device kind"));
        }
        Ok(DeviceInfo {
            id: id.to_owned(),
            name: display_text(&self.name, 100),
            kind,
        })
    }
}

#[derive(Deserialize)]
struct LoginFinish {
    login_id: String,
    message: String,
    device: DeviceBody,
    /// "session" (default) or "reauth" (fresh proof of password for sensitive actions).
    #[serde(default)]
    purpose: Option<String>,
    remember_token: Option<String>,
}

async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<LoginFinish>,
) -> ApiResult<Json<Value>> {
    let (_, pending) = state
        .logins
        .take(&b.login_id)
        .ok_or(ApiError::expired("login expired, try again"))?;
    let server_login = ServerLogin::<Suite>::deserialize(&pending.state)
        .map_err(|_| anyhow::anyhow!("corrupt login state"))?;
    // A finalization that doesn't even parse is a wrong password too (and counted).
    let fin = CredentialFinalization::<Suite>::deserialize(&unb64(&b.message)?).ok();
    let ok = fin.is_some_and(|fin| {
        server_login
            .finish(fin, ServerLoginParameters::default())
            .is_ok()
    });
    let reauth = b.purpose.as_deref() == Some("reauth");
    let user_id = match (ok, pending.user_id) {
        (true, Some(id)) => id,
        (_, known) => {
            if let Some(id) = known {
                let reason = if reauth { "reauth" } else { "password" };
                failed(&state, &headers, &id, reason);
            }
            return Err(ApiError::InvalidCredentials);
        }
    };

    if reauth {
        let current = match bearer(&headers) {
            Some(t) => authenticate(&state, &t).await?,
            None => return Err(ApiError::Unauthorized),
        };
        if current.user_id != user_id {
            return Err(ApiError::Forbidden(
                "re-authentication must use the signed-in account".into(),
            ));
        }
        let token = state.reauth.insert(user_id, 5 * 60);
        return Ok(Json(json!({ "reauth_token": token })));
    }

    let (disabled, verified): (i64, i64) =
        sqlx::query_as("SELECT disabled, email_verified FROM users WHERE id = $1")
            .bind(&user_id)
            .fetch_one(&state.db)
            .await?;
    if disabled != 0 {
        failed(&state, &headers, &user_id, "account_disabled");
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::ACCOUNT_DISABLED,
            "this account is disabled",
        ));
    }
    if verified == 0 && state.signups_verify() {
        failed(&state, &headers, &user_id, "email_not_verified");
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::EMAIL_NOT_VERIFIED,
            "email_not_verified",
        ));
    }

    let device = b.device.validated()?;
    let providers = twofactor::enabled_providers(&state.db, &user_id).await?;
    let remembered = match &b.remember_token {
        Some(t) => remembered_device(&state, &user_id, &device.id, &hash_token(t)).await?,
        None => false,
    };
    if !providers.is_empty() && !remembered {
        return Ok(Json(two_factor_challenge(
            &state, user_id, device, providers,
        )));
    }
    let two_step = remembered.then_some("remembered_device");
    Ok(Json(
        issue_session(
            &state,
            &headers,
            &user_id,
            &device,
            None,
            two_step,
            SignIn::Password,
        )
        .await?,
    ))
}

/// The answer that asks a password sign-in for two-step login
/// (`two_factor_required`, a five-minute `two_factor_token`, the account's
/// `providers` plus `recovery`).
fn two_factor_challenge(
    state: &AppState,
    user_id: String,
    device: DeviceInfo,
    providers: Vec<String>,
) -> Value {
    let token = state.two_factor.insert(
        PendingTwoFactor {
            user_id,
            device,
            attempts: 0,
            passkey: None,
            key_context: None,
        },
        5 * 60,
    );
    let mut all = providers;
    all.push(twofactor::RECOVERY.into());
    json!({ "two_factor_required": true, "two_factor_token": token, "providers": all })
}

/// Count a failed sign-in to an existing account in the activity log, after the
/// answer has gone out (`events::FailureLog`): the answer takes as long as one
/// for an email without an account, which writes nothing. Best effort: the
/// sign-in already failed, and the answer stays the same.
pub(crate) fn failed(state: &AppState, headers: &HeaderMap, user_id: &str, reason: &'static str) {
    state.failures.record(
        user_id,
        reason,
        client_app(headers),
        visitor_ip(state, headers),
        state.numbers.event_ip(),
    );
}

/// Whether `device_id` holds an unexpired "remember this device" token for the
/// account whose SHA-256 is `token_hash` (it then skips two-step login).
pub(crate) async fn remembered_device(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    token_hash: &str,
) -> ApiResult<bool> {
    let hash: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT remember_hash, remember_expires FROM devices WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(matches!(hash, Some((Some(h), Some(exp))) if exp > now() && ct_eq(&h, token_hash)))
}

#[derive(Deserialize)]
struct TwoFactorVerify {
    two_factor_token: String,
    provider: String,
    code: String,
    #[serde(default)]
    remember: bool,
}

async fn two_factor_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<TwoFactorVerify>,
) -> ApiResult<Json<Value>> {
    let (exp, pending) = state
        .two_factor
        .take(&b.two_factor_token)
        .ok_or(ApiError::expired("sign-in expired, start again"))?;
    if let Some(left) = twofactor::lockout_left(&state.db, &pending.user_id).await? {
        return Err(ApiError::TooManyRequests(left));
    }
    if !twofactor::verify(&state.db, &pending.user_id, &b.provider, &b.code).await? {
        return Err(two_factor_failed(&state, &headers, b.two_factor_token, pending, exp).await?);
    }
    twofactor::clear_failures(&state.db, &pending.user_id).await?;
    let remember = b.remember.then(random_token);
    let method = match b.provider.as_str() {
        twofactor::TOTP => twofactor::TOTP,
        twofactor::EMAIL => twofactor::EMAIL,
        _ => twofactor::RECOVERY,
    };
    Ok(Json(
        issue_session(
            &state,
            &headers,
            &pending.user_id,
            &pending.device,
            remember,
            Some(method),
            SignIn::Password,
        )
        .await?,
    ))
}

/// Count a wrong code or failed security-key assertion against the account
/// (lockout after too many), keep the sign-in alive for a few more tries, and
/// give the error to answer with.
async fn two_factor_failed(
    state: &AppState,
    headers: &HeaderMap,
    token: String,
    mut pending: PendingTwoFactor,
    exp: i64,
) -> ApiResult<ApiError> {
    let max = state.num(Num::TwoStepAttemptsPerHour);
    failed(state, headers, &pending.user_id, "two_step");
    let mut tx = state.db.begin().await?;
    let locked = twofactor::record_failure(&mut tx, &pending.user_id, max).await?;
    if locked {
        Event::new("auth.two_step_locked")
            .target(&pending.user_id)
            .from(client_app(headers), visitor_ip(state, headers))
            .data(json!({ "seconds": twofactor::LOCKOUT }))
            .record(&mut tx, state)
            .await?;
    }
    tx.commit().await?;
    if locked {
        alert_two_factor_lockout(state, &pending.user_id).await?;
        return Ok(ApiError::TooManyRequests(twofactor::LOCKOUT as u64));
    }
    pending.attempts += 1;
    pending.passkey = None;
    if pending.attempts < 5 {
        state.two_factor.put_back(token, pending, exp);
    }
    Ok(ApiError::invalid_code("invalid two-factor code"))
}

// ------------------------------------------------- security keys / passkeys

/// Assertion options for the account's security keys (`allowCredentials`).
async fn two_factor_passkey_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<TwoFactorEmail>,
) -> ApiResult<Json<Value>> {
    let (exp, mut pending) = state
        .two_factor
        .take(&b.two_factor_token)
        .ok_or(ApiError::expired("sign-in expired, start again"))?;
    if let Some(left) = twofactor::lockout_left(&state.db, &pending.user_id).await? {
        state.two_factor.put_back(b.two_factor_token, pending, exp);
        return Err(ApiError::TooManyRequests(left));
    }
    let webauthn = match passkeys::relying_party(&state) {
        Ok(w) => w,
        Err(e) => {
            state.two_factor.put_back(b.two_factor_token, pending, exp);
            return Err(e);
        }
    };
    if let Err(e) = limit_account(&state, format!("2fa-passkey:{}", pending.user_id), 20, 300) {
        state.two_factor.put_back(b.two_factor_token, pending, exp);
        return Err(e);
    }
    let keys = passkeys::list(&state.db, &pending.user_id).await?;
    if keys.is_empty() {
        state.two_factor.put_back(b.two_factor_token, pending, exp);
        return Err(ApiError::bad("this account has no security keys"));
    }
    let creds: Vec<_> = keys.into_iter().map(|k| k.key).collect();
    let (options, auth_state) = webauthn
        .start_securitykey_authentication(&creds)
        .map_err(|e| anyhow::anyhow!("webauthn authentication start: {e:?}"))?;
    let options = passkeys::options(&options)?;
    pending.passkey = Some(auth_state);
    if let Some(challenge) = options["publicKey"]["challenge"].as_str() {
        pending.key_context = Some(KeyContext {
            challenge: challenge.to_owned(),
            client: key_page_client(&headers),
            ip: visitor_ip(&state, &headers),
            started_at: now(),
        });
        state.passkey_challenges.put_back(
            challenge.to_owned(),
            b.two_factor_token.clone(),
            exp.min(now() + passkeys::CHALLENGE_TTL),
        );
    }
    state.two_factor.put_back(b.two_factor_token, pending, exp);
    Ok(Json(json!({
        "options": options,
        "key_page": passkeys::key_page(&state),
    })))
}

/// The app types the key page names (`X-PassAuth-Client` name part).
const KEY_PAGE_CLIENTS: &[&str] = &[
    "web",
    "desktop",
    "extension",
    "ios",
    "android",
    "macos-autofill",
];

fn key_page_client(headers: &HeaderMap) -> Option<String> {
    let app = client_app(headers)?;
    let name = app.split_once('/').map_or(app.as_str(), |(n, _)| n);
    KEY_PAGE_CLIENTS.contains(&name).then(|| name.to_owned())
}

#[derive(Deserialize)]
struct KeyContextQuery {
    challenge: String,
}

/// `GET /auth/2fa/passkey/context?challenge=…`: what the key page shows about the
/// sign-in waiting for this security-key challenge (which app, device name,
/// address, when), so a person sent a key page by someone else can see it isn't
/// theirs. Public; never the email, user id or token. 404 for an unknown, finished
/// or expired challenge alike. Challenges are not logged.
async fn two_factor_passkey_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<KeyContextQuery>,
) -> ApiResult<Json<Value>> {
    let ip = client_ip(&state, &headers);
    limit(&state, format!("2fa-key-context:{ip}"), 30, 60)?;
    if q.challenge.is_empty() || q.challenge.len() > 128 {
        return Err(ApiError::NotFound);
    }
    let token = state
        .passkey_challenges
        .peek(&q.challenge, Clone::clone)
        .ok_or(ApiError::NotFound)?;
    let found = state.two_factor.peek(&token, |p| {
        let ctx = p.key_context.as_ref()?;
        // Only the latest challenge of a sign-in still waiting for its key.
        (p.passkey.is_some() && ctx.challenge == q.challenge).then(|| {
            json!({
                "client": ctx.client,
                "device_name": (!p.device.name.trim().is_empty()).then(|| p.device.name.clone()),
                "ip": ctx.ip,
                "started_at": ctx.started_at,
            })
        })
    });
    found.flatten().map(Json).ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
struct TwoFactorPasskeyFinish {
    two_factor_token: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
    #[serde(default)]
    remember: bool,
}

async fn two_factor_passkey_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<TwoFactorPasskeyFinish>,
) -> ApiResult<Json<Value>> {
    let (exp, mut pending) = state
        .two_factor
        .take(&b.two_factor_token)
        .ok_or(ApiError::expired("sign-in expired, start again"))?;
    if let Some(left) = twofactor::lockout_left(&state.db, &pending.user_id).await? {
        state.two_factor.put_back(b.two_factor_token, pending, exp);
        return Err(ApiError::TooManyRequests(left));
    }
    let Some(auth_state) = pending.passkey.take() else {
        state.two_factor.put_back(b.two_factor_token, pending, exp);
        return Err(ApiError::bad("ask for security key options first"));
    };
    let webauthn = passkeys::relying_party(&state)?;
    let result = match webauthn.finish_securitykey_authentication(&b.credential, &auth_state) {
        Ok(r) => r,
        Err(e) => {
            use webauthn_rs::prelude::WebauthnError;
            let cred = b64(&b.credential.raw_id);
            match e {
                WebauthnError::CredentialPossibleCompromise => {
                    tracing::warn!(user = %pending.user_id, credential = %cred, "security key counter went backwards: possible cloned key");
                    alert_passkey_compromise(&state, &pending.user_id).await?;
                }
                WebauthnError::UserNotVerified | WebauthnError::InvalidRPOrigin => {
                    tracing::warn!(user = %pending.user_id, credential = %cred, error = ?e, "security key assertion rejected (check DOMAIN / authenticator settings)");
                }
                _ => tracing::debug!(error = ?e, "security key assertion rejected"),
            }
            return Err(
                two_factor_failed(&state, &headers, b.two_factor_token, pending, exp).await?,
            );
        }
    };
    let mut keys = passkeys::list(&state.db, &pending.user_id).await?;
    passkeys::record_use(&state.db, &pending.user_id, &mut keys, &result).await?;
    twofactor::clear_failures(&state.db, &pending.user_id).await?;
    let remember = b.remember.then(random_token);
    Ok(Json(
        issue_session(
            &state,
            &headers,
            &pending.user_id,
            &pending.device,
            remember,
            Some(twofactor::PASSKEY),
            SignIn::Password,
        )
        .await?,
    ))
}

/// Tell the owner that a security key's signature counter went backwards (a
/// cloned key, or a reset one; either way worth a look).
async fn alert_passkey_compromise(state: &AppState, user_id: &str) -> ApiResult<()> {
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    state.mailer.send_later(
        email,
        Email {
            subject: "PassAuth security key check failed".into(),
            heading: "Unexpected security key response".into(),
            body: "A security key for your account returned an unexpected counter during two-step login; it may have been cloned. The sign-in was refused. If you don't recognise this, remove the key in Settings → Two-step login and change your master password.".into(),
            action: Some(("Review two-step login".into(), format!("{}/settings/two-step", state.config.domain))),
            code: None,
        },
    );
    Ok(())
}

/// Tell the owner that someone with their password is guessing two-factor codes.
async fn alert_two_factor_lockout(state: &AppState, user_id: &str) -> ApiResult<()> {
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    tracing::warn!(user = %user_id, "two-factor sign-in locked after repeated wrong codes");
    state
        .mailer
        .send_later(email, two_factor_lockout_alert(&state.config.domain));
    Ok(())
}

/// The email sent when wrong two-step codes paused sign-in; like the new-device
/// alert, its button opens the web vault's session list.
pub(crate) fn two_factor_lockout_alert(domain: &str) -> Email {
    Email {
        subject: "PassAuth sign-in paused after wrong codes".into(),
        heading: "Too many wrong two-step codes".into(),
        body: "Someone entered your master password correctly but then the wrong two-step login code many times. Two-step sign-in is paused for an hour. If this wasn't you, change your master password now.".into(),
        action: Some((
            "Review sessions".into(),
            format!("{domain}/settings/sessions"),
        )),
        code: None,
    }
}

#[derive(Deserialize)]
struct TwoFactorEmail {
    two_factor_token: String,
}

async fn two_factor_send_email(
    State(state): State<AppState>,
    Json(b): Json<TwoFactorEmail>,
) -> ApiResult<Json<Value>> {
    let (exp, pending) = state
        .two_factor
        .take(&b.two_factor_token)
        .ok_or(ApiError::expired("sign-in expired, start again"))?;
    limit_account(&state, format!("2fa-email:{}", pending.user_id), 5, 600)?;
    let providers = twofactor::enabled_providers(&state.db, &pending.user_id).await?;
    if providers.iter().any(|p| p == twofactor::EMAIL) {
        let code = twofactor::issue_email_code(&state.db, &pending.user_id, "2fa").await?;
        let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(&pending.user_id)
            .fetch_one(&state.db)
            .await?;
        state.mailer.send_later(
            email,
            Email {
                subject: "Your PassAuth sign-in code".into(),
                heading: "Sign-in verification code".into(),
                body: "Enter this code to finish signing in. It expires in 10 minutes.".into(),
                action: None,
                code: Some(code),
            },
        );
    }
    state.two_factor.put_back(b.two_factor_token, pending, exp);
    Ok(Json(json!({ "sent": true })))
}

/// How an account proved who it is when a session starts.
pub(crate) enum SignIn<'a> {
    /// The master password (OPAQUE).
    Password,
    /// A sign-in request another device approved (`auth_requests.rs`). The account
    /// key sealed to the new device goes out with the session, never before it.
    Device(&'a DeviceLogin),
}

/// Create a session for `device`, alerting the user by email on new devices.
/// The app that signed in ([`CLIENT_HEADER`]) is kept with the session; the
/// sign-in goes into the activity log with the two-step method used, if any
/// (`remembered_device` when this device may skip it, `device_approval` for an
/// approved sign-in request of an account with two-step login), and for an approved
/// sign-in request `method: "device"` with the request's id. That sign-in's answer
/// also carries the sealed account key (`sealed_key`).
pub(crate) async fn issue_session(
    state: &AppState,
    headers: &HeaderMap,
    user_id: &str,
    device: &DeviceInfo,
    remember: Option<String>,
    two_step: Option<&str>,
    via: SignIn<'_>,
) -> ApiResult<Value> {
    let client = client_app(headers);
    let t = now();
    let known: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = $1 AND id = $2")
            .bind(user_id)
            .bind(&device.id)
            .fetch_one(&state.db)
            .await?;
    let has_devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    // The device, the session and the sign-in event: all or nothing. A write
    // first (SQLite then never has to upgrade a read transaction), on the account's
    // row: it waits for an admin disabling the account at the same moment and then
    // sees it, so an account disabled since this sign-in began gets no session (nor,
    // for an approved device, the sealed key).
    let mut tx = state.db.begin().await?;
    let open =
        sqlx::query("UPDATE users SET updated_at = updated_at WHERE id = $1 AND disabled = 0")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    if open.rows_affected() == 0 {
        drop(tx);
        failed(state, headers, user_id, "account_disabled");
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            code::ACCOUNT_DISABLED,
            "this account is disabled",
        ));
    }
    // Upsert: two sign-ins from one device at once must not hit the primary key.
    sqlx::query(
        "INSERT INTO devices (user_id, id, name, kind, created_at, last_seen) VALUES ($1, $2, $3, $4, $5, $5)
         ON CONFLICT (user_id, id) DO UPDATE SET name = excluded.name, last_seen = excluded.last_seen",
    )
    .bind(user_id)
    .bind(&device.id)
    .bind(&device.name)
    .bind(&device.kind)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    if let Some(r) = &remember {
        sqlx::query("UPDATE devices SET remember_hash = $1, remember_expires = $2 WHERE user_id = $3 AND id = $4")
            .bind(hash_token(r))
            .bind(t + days(state, Num::RememberDeviceDays))
            .bind(user_id)
            .bind(&device.id)
            .execute(&mut *tx)
            .await?;
    }

    let (access, refresh) = (random_token(), random_token());
    let session_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, access_hash, access_expires, refresh_hash, refresh_expires, created_at, last_used, client)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)",
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(&device.id)
    .bind(hash_token(&access))
    .bind(t + ACCESS_TTL)
    .bind(hash_token(&refresh))
    .bind(t + days(state, Num::RefreshDays).min(days(state, Num::SessionDays)))
    .bind(t)
    .bind(&client)
    .execute(&mut *tx)
    .await?;
    let mut data = json!({
        "two_step": two_step,
        "device_kind": device.kind,
        "new_device": known == 0,
    });
    if let SignIn::Device(login) = &via {
        data["method"] = "device".into();
        data["request"] = login.request_id.clone().into();
    }
    Event::new("auth.signed_in")
        .actor(user_id)
        .session(&session_id)
        .from(client.clone(), visitor_ip(state, headers))
        .data(data)
        .record(&mut tx, state)
        .await?;
    tx.commit().await?;
    tracing::debug!(user = %user_id, session = %session_id, client = client.as_deref().unwrap_or("-"), "session started");

    let (email, bundle): (String, String) =
        sqlx::query_as("SELECT email, bundle FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    if known == 0 && has_devices > 0 {
        state.mailer.send_later(
            email.clone(),
            new_device_alert(&state.config.domain, device),
        );
    }
    let mut out = json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": ACCESS_TTL,
        "remember_token": remember,
        "user_id": user_id,
        "email": email,
        "bundle": serde_json::from_str::<Value>(&bundle).map_err(anyhow::Error::from)?,
    });
    if let SignIn::Device(login) = via {
        out["sealed_key"] = login.sealed_key.clone().into();
    }
    Ok(out)
}

/// The email sent when a device signs in for the first time; its button opens
/// the web vault's session list.
pub(crate) fn new_device_alert(domain: &str, device: &DeviceInfo) -> Email {
    Email {
        subject: "New sign-in to your PassAuth account".into(),
        heading: "New device signed in".into(),
        body: format!(
            "Your account was just accessed from a new device: {} ({}).\nIf this wasn't you, change your master password and review your sessions.",
            device.name, device.kind
        ),
        action: Some((
            "Review sessions".into(),
            format!("{domain}/settings/sessions"),
        )),
        code: None,
    }
}

// ---------------------------------------------------------------- sessions

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

/// Rotate the refresh token. Presenting an already-rotated token means it
/// leaked: the whole session is revoked. A session can't be refreshed past
/// `session_days` (admin page) after sign-in.
async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<RefreshBody>,
) -> ApiResult<Json<Value>> {
    let h = hash_token(&b.refresh_token);
    let t = now();
    let reused: Option<(String, String)> =
        sqlx::query_as("SELECT id, user_id FROM sessions WHERE prev_refresh_hash = $1")
            .bind(&h)
            .fetch_optional(&state.db)
            .await?;
    if let Some((id, user_id)) = reused {
        let mut tx = state.db.begin().await?;
        let done = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() > 0 {
            Event::new("session.revoked")
                .target(&user_id)
                .from(client_app(&headers), visitor_ip(&state, &headers))
                .data(json!({ "session": id, "reason": "refresh_token_reused" }))
                .record(&mut tx, &state)
                .await?;
        }
        tx.commit().await?;
        tracing::warn!(user = %user_id, "refresh token reuse detected; session revoked");
        state.notify_logout(&user_id, Sessions::Only(id));
        return Err(ApiError::Unauthorized);
    }
    let row: Option<(String, i64, String, String)> = sqlx::query_as(
        "SELECT s.id, s.created_at, s.user_id, s.device_id FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.refresh_hash = $1 AND s.refresh_expires > $2 AND u.disabled = 0",
    )
    .bind(&h)
    .bind(t)
    .fetch_optional(&state.db)
    .await?;
    let (id, created, user_id, device_id) = row.ok_or(ApiError::Unauthorized)?;
    let end = created + days(&state, Num::SessionDays);
    if t >= end {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            code::SESSION_EXPIRED,
            "authentication required",
        ));
    }
    let (access, refresh) = (random_token(), random_token());
    // Conditional on the token presented: of two concurrent refreshes with the
    // same token only one rotates; the other gets 401 instead of silently
    // replacing the first one's tokens.
    let done = sqlx::query(
        "UPDATE sessions SET access_hash = $1, access_expires = $2, prev_refresh_hash = refresh_hash,
         refresh_hash = $3, refresh_expires = $4, last_used = $5, client = COALESCE($6, client)
         WHERE id = $7 AND refresh_hash = $8",
    )
    .bind(hash_token(&access))
    .bind((t + ACCESS_TTL).min(end))
    .bind(hash_token(&refresh))
    .bind((t + days(&state, Num::RefreshDays)).min(end))
    .bind(t)
    .bind(client_app(&headers))
    .bind(&id)
    .bind(&h)
    .execute(&state.db)
    .await?;
    if done.rows_affected() != 1 {
        return Err(ApiError::Unauthorized);
    }
    // The device was seen (at most one write an hour): the admin page's "last
    // seen", and the sweeper forgets devices unseen for 90 days without a session.
    sqlx::query(
        "UPDATE devices SET last_seen = $1 WHERE user_id = $2 AND id = $3 AND last_seen < $4",
    )
    .bind(t)
    .bind(&user_id)
    .bind(&device_id)
    .bind(t - 3600)
    .execute(&state.db)
    .await?;
    Ok(Json(
        json!({ "access_token": access, "refresh_token": refresh, "expires_in": ACCESS_TTL.min(end - t) }),
    ))
}

async fn logout(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&user.session_id)
        .execute(&mut *tx)
        .await?;
    Event::new("session.signed_out")
        .by(&user)
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    state.notify_logout(&user.user_id, Sessions::Only(user.session_id));
    Ok(Json(json!({ "ok": true })))
}

/// Consume a reauth token issued by `login/finish` with `purpose: "reauth"`.
pub fn require_reauth(state: &AppState, user: &AuthUser, token: Option<&str>) -> ApiResult<()> {
    let token = token.ok_or_else(ApiError::reauth_required)?;
    match state.reauth.take(token) {
        Some((_, uid)) if uid == user.user_id => Ok(()),
        _ => Err(ApiError::reauth_required()),
    }
}

/// The message of 403 `reauth_required` on steps older apps took without
/// confirming the master password (turning on an authenticator app or email
/// codes), for those apps to show as it is.
pub const REAUTH_FIRST: &str =
    "Confirm your master password first. Update the app if it doesn't ask for it.";

fn reauth_required_with(message: &str) -> ApiError {
    ApiError::coded(StatusCode::FORBIDDEN, code::REAUTH_REQUIRED, message)
}

/// Check a reauth token of `user` without using it up (403 `reauth_required`
/// with `message` otherwise); [`require_reauth_or`] uses it once the change goes
/// through, so a step that fails on a mistyped code can be tried again.
pub fn check_reauth(
    state: &AppState,
    user: &AuthUser,
    token: Option<&str>,
    message: &str,
) -> ApiResult<()> {
    let theirs = token
        .and_then(|t| state.reauth.peek(t, |uid| *uid == user.user_id))
        .unwrap_or(false);
    if theirs {
        Ok(())
    } else {
        Err(reauth_required_with(message))
    }
}

/// [`require_reauth`] answering with `message`.
pub fn require_reauth_or(
    state: &AppState,
    user: &AuthUser,
    token: Option<&str>,
    message: &str,
) -> ApiResult<()> {
    let token = token.ok_or_else(|| reauth_required_with(message))?;
    match state.reauth.take(token) {
        Some((_, uid)) if uid == user.user_id => Ok(()),
        _ => Err(reauth_required_with(message)),
    }
}
