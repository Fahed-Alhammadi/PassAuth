//! Admin API, on when `PASSAUTH_ADMIN_USERNAME` + `PASSAUTH_ADMIN_PASSWORD` (or the
//! older `ADMIN_TOKEN`) are set. The admin page signs in at `/admin/login` and gets a
//! session token. There are deliberately no settings here that execute programs or
//! touch the filesystem.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admin_security;
use crate::auth::{bearer, client_app, client_ip, visitor_ip};
use crate::config::{SignupPolicy, SmtpConfig, SmtpSecurity};
use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::events::{self, Event};
use crate::mail::Email;
use crate::settings::{self, BREACH_CHECK, EVENT_IP, Flag, Num};
use crate::state::{
    AdminLogin, AppState, Class, Sessions, ct_eq, hash_token, normalize_email, random_token,
};

/// An admin session ends after this long without a request…
const SESSION_IDLE_SECS: i64 = 3600;
/// …and at the latest this long after signing in.
const SESSION_MAX_SECS: i64 = 12 * 3600;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_mode).post(login))
        .route("/login/2fa", post(login_two_factor))
        .route("/logout", post(logout))
        .route("/overview", get(overview))
        .route("/users", get(list_users))
        .route("/users/{id}", delete(delete_user))
        .route("/users/{id}/disable", post(disable_user))
        .route("/users/{id}/enable", post(enable_user))
        .route("/users/{id}/sessions/revoke", post(revoke_sessions))
        .route("/users/{id}/two-factor/reset", post(reset_two_factor))
        .route("/invites", get(list_invites).post(invite))
        .route("/invites/{email}", delete(delete_invite))
        .route("/smtp/test", post(smtp_test))
        .route("/settings/signups", put(set_signups))
        .route("/settings", get(get_settings).put(set_settings))
        .route("/settings/smtp", put(set_smtp).delete(smtp_off))
        .route("/events", get(events::admin_events))
        .merge(crate::admin_security::routes())
}

/// A request from a signed-in admin page. Carries the request's app and address
/// for the activity log (the admin page is not a user account).
pub struct Admin {
    pub client: Option<String>,
    pub ip: Option<String>,
}

impl Admin {
    fn of(state: &AppState, headers: &HeaderMap) -> Self {
        Self {
            client: client_app(headers),
            ip: visitor_ip(state, headers),
        }
    }
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        admin_security::check_network(state, &parts.headers)?;
        if matches!(state.admin, AdminLogin::Off { .. }) {
            return Err(ApiError::NotFound);
        }
        let given = bearer(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let digest = hash_token(&given);
        let t = now();
        if let Some(mut session) = state.admin_sessions.get_mut(&digest) {
            let (idle, absolute) = *session;
            if idle > t && absolute > t {
                session.0 = (t + SESSION_IDLE_SECS).min(absolute);
                return Ok(Admin::of(state, &parts.headers));
            }
        }
        // Scripts may still send ADMIN_TOKEN itself as the bearer token, unless
        // two-step login is on (that needs a session from /admin/login).
        let AdminLogin::Token(configured) = &state.admin else {
            return Err(ApiError::Unauthorized);
        };
        if admin_security::enabled(&state.db).await? {
            return Err(ApiError::Unauthorized);
        }
        // A token that passed the Argon2 check recently is accepted by its
        // SHA-256, so the admin API doesn't run Argon2 on every request.
        let cached = state
            .admin_verified
            .lock()
            .expect("admin cache lock")
            .as_ref()
            .is_some_and(|(h, exp)| *exp > t && ct_eq(h, &digest));
        if cached {
            return Ok(Admin::of(state, &parts.headers));
        }
        if !check_secret(state, parts, configured.clone(), given, None).await? {
            return Err(ApiError::Unauthorized);
        }
        *state.admin_verified.lock().expect("admin cache lock") = Some((digest, now() + 600));
        Ok(Admin::of(state, &parts.headers))
    }
}

/// Rate-limited Argon2 check of an admin secret, off the async threads. With
/// `username`, `configured` is the password hash and both must match.
async fn check_secret(
    state: &AppState,
    parts: &Parts,
    configured: String,
    given: String,
    username: Option<(String, String)>,
) -> ApiResult<bool> {
    let ip = client_ip(state, &parts.headers);
    state
        .limiter
        .limit(Class::Address, &format!("admin:{ip}"), 10, 60)?;
    // At most two Argon2 checks at once (each allocates ~19 MiB).
    let _permit = state
        .admin_verify
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let ok = tokio::task::spawn_blocking(move || {
        // Always run Argon2, so a wrong user name takes as long as a wrong password.
        let secret_ok = verify_token(&configured, &given);
        let user_ok = username.is_none_or(|(want, got)| ct_eq(&want, &got));
        secret_ok && user_ok
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    if !ok {
        tracing::warn!(%ip, "admin sign-in failed");
    }
    Ok(ok)
}

/// How the admin page signs in: `password`, `token` or `off` (`weak` = the
/// password in .env is refused).
async fn login_mode(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    admin_security::check_network(&state, &headers)?;
    let weak = matches!(state.admin, AdminLogin::Off { weak: true });
    Ok(Json(
        json!({ "mode": state.admin.mode(), "weak_password": weak }),
    ))
}

#[derive(Deserialize)]
struct LoginBody {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    token: String,
}

async fn login(
    State(state): State<AppState>,
    parts: Parts,
    Json(b): Json<LoginBody>,
) -> ApiResult<Json<Value>> {
    admin_security::check_network(&state, &parts.headers)?;
    let ok = match &state.admin {
        AdminLogin::Off { .. } => return Err(ApiError::NotFound),
        AdminLogin::Password { username, hash } => {
            check_secret(
                &state,
                &parts,
                hash.clone(),
                b.password,
                Some((username.clone(), b.username.trim().to_owned())),
            )
            .await?
        }
        AdminLogin::Token(configured) => {
            check_secret(
                &state,
                &parts,
                configured.clone(),
                b.token.trim().to_owned(),
                None,
            )
            .await?
        }
    };
    if !ok {
        return Err(ApiError::Unauthorized);
    }
    if admin_security::enabled(&state.db).await? {
        let pending = state.admin_pending.insert(0, TWO_FACTOR_TTL);
        return Ok(Json(json!({ "two_factor": true, "pending": pending })));
    }
    Ok(Json(start_session(&state, &parts.headers).await?))
}

/// Seconds to enter the code after the password, and wrong codes allowed meanwhile.
const TWO_FACTOR_TTL: i64 = 5 * 60;
const TWO_FACTOR_ATTEMPTS: u32 = 5;

#[derive(Deserialize)]
struct TwoFactorBody {
    pending: String,
    code: String,
}

/// Second sign-in step: an authenticator or recovery code for the `pending` token
/// that `/admin/login` returned.
async fn login_two_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<TwoFactorBody>,
) -> ApiResult<Json<Value>> {
    admin_security::check_network(&state, &headers)?;
    let ip = client_ip(&state, &headers);
    state
        .limiter
        .limit(Class::Address, &format!("admin:{ip}"), 10, 60)?;
    let Some((expires, attempts)) = state.admin_pending.take(&b.pending) else {
        return Err(ApiError::expired(
            "this sign-in has expired. Go back and enter your password again",
        ));
    };
    if admin_security::check_code(&state.db, &b.code).await? {
        return Ok(Json(start_session(&state, &headers).await?));
    }
    tracing::warn!(%ip, "admin sign-in: wrong two-step code");
    if attempts + 1 >= TWO_FACTOR_ATTEMPTS {
        return Err(ApiError::expired(
            "too many wrong codes. Go back and enter your password again",
        ));
    }
    state
        .admin_pending
        .put_back(b.pending, attempts + 1, expires);
    Err(ApiError::invalid_code(
        "that code isn't right. Enter the newest code from your authenticator app, or a recovery code",
    ))
}

async fn start_session(state: &AppState, headers: &HeaderMap) -> ApiResult<Value> {
    let mut conn = state.db.acquire().await?;
    Event::new("admin.signed_in")
        .by_admin(&Admin::of(state, headers))
        .record(&mut conn, state)
        .await?;
    drop(conn);
    let token = random_token();
    let t = now();
    state.admin_sessions.insert(
        hash_token(&token),
        (t + SESSION_IDLE_SECS, t + SESSION_MAX_SECS),
    );
    tracing::info!(ip = %client_ip(state, headers), "admin signed in");
    Ok(json!({ "token": token, "expires_in": SESSION_IDLE_SECS }))
}

async fn logout(State(state): State<AppState>, parts: Parts) -> Json<Value> {
    if let Some(token) = bearer(&parts.headers) {
        state.admin_sessions.remove(&hash_token(&token));
    }
    Json(json!({ "ok": true }))
}

pub fn verify_token(configured: &str, given: &str) -> bool {
    if configured.starts_with("$argon2") {
        PasswordHash::new(configured)
            .map(|h| {
                Argon2::default()
                    .verify_password(given.as_bytes(), &h)
                    .is_ok()
            })
            .unwrap_or(false)
    } else {
        ct_eq(configured, given)
    }
}

async fn overview(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    let items: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM items")
        .fetch_one(&state.db)
        .await?;
    let vaults: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vaults")
        .fetch_one(&state.db)
        .await?;
    let sends: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sends")
        .fetch_one(&state.db)
        .await?;
    let (attachments, attachment_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), CAST(COALESCE(SUM(size), 0) AS BIGINT) FROM attachments WHERE state = 'ready'",
    )
    .fetch_one(&state.db)
    .await?;
    let c = &state.config;
    let signups = state.signups.read().expect("signup policy lock").clone();
    let token_hashed = matches!(&state.admin, AdminLogin::Token(t) if t.starts_with("$argon2"));
    // The least free space on the disks holding the database and the attachments
    // (`null` when there is none to measure, e.g. PostgreSQL without attachments),
    // next to the reserve below which new data is refused (`min_free_disk_mb`).
    let disk_free_bytes = state.disk.free().await;
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "users": users, "vaults": vaults, "items": items, "sends": sends,
        "attachments": attachments, "attachment_bytes": attachment_bytes,
        "disk_free_bytes": disk_free_bytes,
        "config": {
            "domain": c.domain,
            "database": if c.database_url.starts_with("postgres") { "postgresql" } else { "sqlite" },
            "signups_allowed": signups.allowed,
            "signups_domains": signups.domains,
            "signups_verify": state.signups_verify(),
            "smtp_enabled": state.mailer.enabled(),
            "admin_login": state.admin.mode(),
            "admin_2fa": admin_security::enabled(&state.db).await?,
            "admin_networks": c.admin_networks.is_some(),
            "admin_token_hashed": token_hashed,
            // Whether the server has a folder for attachment files.
            "attachments_storage": state.files.is_some(),
        }
    })))
}

#[derive(Serialize, sqlx::FromRow)]
struct UserRow {
    id: String,
    email: String,
    name: String,
    email_verified: i64,
    disabled: i64,
    created_at: i64,
    last_seen: Option<i64>,
    /// Items in the vaults the user owns (older name of `item_count`).
    items: i64,
    /// What counts against the quotas: items, and bytes of encrypted key + data
    /// of the items (trash included) and their earlier versions and the size of
    /// their ready attachments, in the vaults the user owns, plus the user's Sends
    /// and the attachment uploads they started that haven't finished.
    #[sqlx(skip)]
    item_count: i64,
    storage_bytes: i64,
    two_factor: i64,
}

async fn list_users(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    let mut users: Vec<UserRow> = sqlx::query_as(
        "SELECT u.id, u.email, u.name, u.email_verified, u.disabled, u.created_at,
           (SELECT MAX(last_seen) FROM devices d WHERE d.user_id = u.id) AS last_seen,
           (SELECT COUNT(*) FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
              WHERE m.user_id = u.id AND m.role = 'owner') AS items,
           CAST((SELECT COALESCE(SUM(octet_length(i.item_key) + octet_length(i.data)), 0)
                 FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
                 WHERE m.user_id = u.id AND m.role = 'owner')
              + (SELECT COALESCE(SUM(octet_length(v.item_key) + octet_length(v.data)), 0)
                 FROM item_versions v JOIN vault_members m ON m.vault_id = v.vault_id
                 WHERE m.user_id = u.id AND m.role = 'owner')
              + (SELECT COALESCE(SUM(a.size), 0)
                 FROM attachments a JOIN vault_members m ON m.vault_id = a.vault_id
                 WHERE m.user_id = u.id AND m.role = 'owner' AND a.state = 'ready')
              + (SELECT COALESCE(SUM(a.size), 0)
                 FROM attachments a WHERE a.created_by = u.id AND a.state = 'pending')
              + (SELECT COALESCE(SUM(octet_length(s.name) + octet_length(s.data) + octet_length(s.owner_key)
                  + COALESCE(octet_length(s.owner_content_key), 0)), 0)
                 FROM sends s WHERE s.user_id = u.id) AS BIGINT) AS storage_bytes,
           (SELECT COUNT(*) FROM two_factor t WHERE t.user_id = u.id AND t.enabled = 1 AND t.provider <> 'recovery') AS two_factor
         FROM users u ORDER BY u.created_at",
    )
    .fetch_all(&state.db)
    .await?;
    for u in &mut users {
        u.item_count = u.items;
    }
    Ok(Json(json!({ "users": users })))
}

async fn set_disabled(
    state: &AppState,
    admin: &Admin,
    id: &str,
    disabled: bool,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("UPDATE users SET disabled = $1, updated_at = $2 WHERE id = $3")
        .bind(disabled as i64)
        .bind(now())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    if disabled {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        crate::push::drop_orphans(&mut tx, id).await?;
        crate::auth_requests::cancel_open(&mut tx, id).await?;
    }
    let kind = if disabled {
        "admin.user_disabled"
    } else {
        "admin.user_enabled"
    };
    Event::new(kind)
        .by_admin(admin)
        .target(id)
        .record(&mut tx, state)
        .await?;
    tx.commit().await?;
    if disabled {
        state.forget_pending_sign_ins(id);
        state.notify_logout(id, Sessions::All);
    }
    Ok(Json(json!({ "ok": true })))
}

async fn disable_user(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    set_disabled(&state, &admin, &id, true).await
}

async fn enable_user(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    set_disabled(&state, &admin, &id, false).await
}

async fn revoke_sessions(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    crate::push::drop_orphans(&mut tx, &id).await?;
    crate::auth_requests::cancel_open(&mut tx, &id).await?;
    Event::new("admin.sessions_revoked")
        .by_admin(&admin)
        .target(&id)
        .data(json!({ "count": done.rows_affected() }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    state.forget_pending_sign_ins(&id);
    state.notify_logout(&id, Sessions::All);
    Ok(Json(json!({ "ok": true })))
}

/// Turn off every two-step login method of a user who lost them all (authenticator,
/// email codes, security keys, recovery codes), forget their "remember this device"
/// tokens and lockout, and tell them by email. Their master password still guards the
/// account and the vault stays encrypted; nothing else changes.
async fn reset_two_factor(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;
    let Some(email) = email else {
        return Err(ApiError::NotFound);
    };
    let mut tx = state.db.begin().await?;
    for stmt in [
        "DELETE FROM two_factor WHERE user_id = $1",
        "DELETE FROM passkey_credentials WHERE user_id = $1",
        "DELETE FROM two_factor_failures WHERE user_id = $1",
        "UPDATE devices SET remember_hash = NULL, remember_expires = NULL WHERE user_id = $1",
    ] {
        sqlx::query(stmt).bind(&id).execute(&mut *tx).await?;
    }
    Event::new("admin.two_step_reset")
        .by_admin(&admin)
        .target(&id)
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    tracing::warn!(user = %id, "admin reset two-step login");
    state.mailer.send_later(
        email,
        Email {
            subject: "Two-step login was turned off".into(),
            heading: "Your two-step login was reset".into(),
            body: "Your PassAuth server administrator turned off two-step login for your account, so signing in now needs only your master password (and Secret Key, if you use one). Turn two-step login on again in Settings. If you didn't ask for this, contact your administrator and change your master password.".into(),
            action: Some(("Open PassAuth".into(), format!("{}/settings", state.config.domain))),
            code: None,
        },
    );
    Ok(Json(
        json!({ "ok": true, "email_sent": state.mailer.enabled() }),
    ))
}

async fn delete_user(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let event = Event::new("admin.user_deleted")
        .by_admin(&admin)
        .target(&id);
    crate::account::delete_user(&state, &id, event).await?;
    state.notify_logout(&id, Sessions::All);
    Ok(Json(json!({ "deleted": true })))
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct InviteRow {
    email: String,
    created_at: i64,
    expires_at: i64,
}

async fn list_invites(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    let rows: Vec<InviteRow> = sqlx::query_as(
        "SELECT email, created_at, expires_at FROM invites ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "invites": rows })))
}

/// `POST /admin/invites {email}`: invite (or invite again) someone to register
/// while sign-ups are closed; logged as `admin.invite_created` with the email
/// (the admin page lists it anyway).
async fn invite(
    State(state): State<AppState>,
    admin: Admin,
    Json(b): Json<InviteBody>,
) -> ApiResult<Json<Value>> {
    let email = normalize_email(&b.email);
    if !email.contains('@') || email.len() > 254 || email.chars().any(char::is_control) {
        return Err(ApiError::bad("invalid email address"));
    }
    let t = now();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO invites (email, created_at, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT (email) DO UPDATE SET created_at = excluded.created_at, expires_at = excluded.expires_at",
    )
    .bind(&email)
    .bind(t)
    .bind(t + 7 * 24 * 3600)
    .execute(&mut *tx)
    .await?;
    Event::new("admin.invite_created")
        .by_admin(&admin)
        .data(json!({ "email": email }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    state.mailer.send_later(
        email.clone(),
        Email {
            subject: "You're invited to PassAuth".into(),
            heading: "You've been invited to PassAuth".into(),
            body: "An administrator invited you to create a PassAuth account, a private, end-to-end encrypted password manager. The invitation is valid for 7 days.".into(),
            action: Some(("Create your account".into(), format!("{}/register?email={}", state.config.domain, crate::account::urlencode(&email)))),
            code: None,
        },
    );
    Ok(Json(
        json!({ "invited": email, "email_sent": state.mailer.enabled() }),
    ))
}

/// `DELETE /admin/invites/{email}`; logged as `admin.invite_deleted` when there was one.
async fn delete_invite(
    State(state): State<AppState>,
    admin: Admin,
    Path(email): Path<String>,
) -> ApiResult<Json<Value>> {
    let email = normalize_email(&email);
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("DELETE FROM invites WHERE email = $1")
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() > 0 {
        Event::new("admin.invite_deleted")
            .by_admin(&admin)
            .data(json!({ "email": email }))
            .record(&mut tx, &state)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct SmtpTest {
    to: String,
}

async fn smtp_test(
    State(state): State<AppState>,
    _: Admin,
    Json(b): Json<SmtpTest>,
) -> ApiResult<Json<Value>> {
    if !state.mailer.enabled() {
        return Err(ApiError::bad("SMTP is not configured"));
    }
    let sent = state
        .mailer
        .send(
            &b.to,
            Email {
                subject: "PassAuth SMTP test".into(),
                heading: "SMTP is working".into(),
                body: "This test message confirms your PassAuth server can send email.".into(),
                action: None,
                code: None,
            },
        )
        .await;
    if let Err(e) = sent {
        let check = state.mailer.check_connection().await.unwrap_or_default();
        return Err(ApiError::bad(
            format!("SMTP error: {e:#}. {check}").trim_end().to_string(),
        ));
    }
    Ok(Json(json!({ "sent": true })))
}

/// Open or close self-registration and limit it to email domains. Invitations keep working.
async fn set_signups(
    admin: Admin,
    State(state): State<AppState>,
    Json(policy): Json<SignupPolicy>,
) -> ApiResult<Json<SignupPolicy>> {
    let mut domains = Vec::new();
    for d in &policy.domains {
        let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
        let valid = !d.is_empty()
            && d.len() <= 253
            && d.contains('.')
            && d.split('.')
                .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if !valid {
            return Err(ApiError::BadRequest(format!(
                "\"{d}\" is not a valid email domain"
            )));
        }
        if !domains.contains(&d) {
            domains.push(d);
        }
    }
    let policy = SignupPolicy {
        allowed: policy.allowed,
        domains,
    };
    let before = state.signups.read().expect("signup policy lock").clone();
    let mut changed = Vec::new();
    if before.allowed != policy.allowed {
        changed.push("signups_allowed");
    }
    if before.domains != policy.domains {
        changed.push("signups_domains");
    }
    let mut tx = state.db.begin().await?;
    db::set_setting(
        &mut *tx,
        "signups_allowed",
        if policy.allowed { "1" } else { "0" },
    )
    .await?;
    db::set_setting(&mut *tx, "signups_domains", &policy.domains.join(",")).await?;
    settings_changed(&mut tx, &admin, &changed, state.numbers.event_ip()).await?;
    tx.commit().await?;
    *state.signups.write().expect("signup policy lock") = policy.clone();
    tracing::info!(allowed = policy.allowed, domains = ?policy.domains, "sign-up policy changed by admin");
    Ok(Json(policy))
}

// ---------------------------------------------------------------- settings

/// `admin.settings_changed` with the names of what changed (never the values),
/// when anything did. `keep_ip` is the `event_ip` switch as this change leaves it:
/// turning addresses off must not keep the admin's own address in this event.
async fn settings_changed(
    conn: &mut sqlx::AnyConnection,
    admin: &Admin,
    changed: &[&str],
    keep_ip: bool,
) -> ApiResult<()> {
    if changed.is_empty() {
        return Ok(());
    }
    Event::new("admin.settings_changed")
        .by_admin(admin)
        .data(json!({ "changed": changed }))
        .record_with(conn, keep_ip)
        .await
}

/// Settings changed on the admin page. They are saved in the database, apply at
/// once and replace the matching `.env` values (which only set the starting
/// values). The numbers (`settings::Num`: lifetimes, limits, quotas, activity
/// log, item history, Send and the account policies) come with their accepted
/// `ranges`; the switches (`settings::Flag`: Send, policies) with their defaults
/// in `switches`.
async fn get_settings(State(state): State<AppState>, _: Admin) -> Json<Value> {
    settings_json(&state)
}

fn settings_json(state: &AppState) -> Json<Value> {
    let smtp = state.mailer.config().map(|c| {
        json!({
            "host": c.host,
            "port": c.port,
            "security": c.security,
            "username": c.username.unwrap_or_default(),
            "password_set": c.password.is_some(),
            "from": c.from,
            "from_name": c.from_name,
        })
    });
    let mut out = json!({
        "log_level": state.log_level.read().expect("log level lock").clone(),
        "log_levels": crate::logging::LEVELS,
        "icons": state.icons.enabled(),
        "signups_verify": state.signups_verify(),
        "breach_check": state.breach_check(),
        "event_ip": state.numbers.event_ip(),
        "push_enabled": state.push.enabled(),
        "push_relay_url": state.push.relay_url(),
        "push_relay_default": crate::push::DEFAULT_RELAY_URL,
        "smtp": smtp,
        "ranges": settings::ranges_json(),
        "switches": settings::switches_json(),
    });
    let map = out.as_object_mut().expect("an object");
    map.extend(state.numbers.values_json());
    Json(out)
}

/// Keys of `GET /admin/settings` that `PUT` ignores (they are changed elsewhere or not at all).
const READ_ONLY: &[&str] = &[
    "log_levels",
    "smtp",
    "ranges",
    "switches",
    "push_relay_default",
];

/// A change on the admin page. Every field may be left out (unchanged), so older
/// admin pages and scripts can send only what they know.
#[derive(Deserialize)]
struct GeneralSettings {
    log_level: Option<String>,
    icons: Option<bool>,
    signups_verify: Option<bool>,
    /// The web vault may check passwords against Have I Been Pwned.
    breach_check: Option<bool>,
    /// The activity log keeps IP addresses (turning it off also erases the kept ones).
    event_ip: Option<bool>,
    /// Sign-in request push notifications (`push.rs`).
    push_enabled: Option<bool>,
    /// Where they are sent (`push::check_relay_url`).
    push_relay_url: Option<String>,
    /// The numbers (`settings::Num`, e.g. `"session_days": 30`) and switches
    /// (`settings::Flag`, e.g. `"require_two_step": true`) by name; `null` = unchanged.
    #[serde(flatten)]
    numbers: serde_json::Map<String, Value>,
}

/// Save the settings sent (all in one transaction with their activity-log
/// event), then apply them.
async fn set_settings(
    State(state): State<AppState>,
    admin: Admin,
    Json(b): Json<GeneralSettings>,
) -> ApiResult<Json<Value>> {
    // Check everything first: a refused value changes nothing.
    let mut numbers = Vec::new();
    let mut flags = Vec::new();
    for (name, value) in &b.numbers {
        // What `GET` adds for reading: an admin page may send it back as it was.
        if READ_ONLY.contains(&name.as_str()) {
            continue;
        }
        if let Some(f) = Flag::from_name(name) {
            if !value.is_null() {
                flags.push((f, settings::validate_flag(f, value).map_err(ApiError::bad)?));
            }
            continue;
        }
        let n = Num::from_name(name)
            .ok_or_else(|| ApiError::bad(format!("unknown setting \"{name}\"")))?;
        if value.is_null() {
            continue;
        }
        numbers.push((n, settings::validate(n, value).map_err(ApiError::bad)?));
    }
    let level = b
        .log_level
        .filter(|level| *state.log_level.read().expect("log level lock") != *level);
    if let Some(level) = &level
        && !crate::logging::LEVELS.contains(&level.as_str())
    {
        return Err(ApiError::bad(format!("unknown log level {level:?}")));
    }
    let relay = b
        .push_relay_url
        .as_deref()
        .map(crate::push::check_relay_url)
        .transpose()
        .map_err(ApiError::bad)?;
    // Names of what changes, for the activity log.
    let mut changed: Vec<&str> = Vec::new();
    let bit = |on: bool| if on { "1" } else { "0" };
    let mut tx = state.db.begin().await?;
    if let Some(level) = &level {
        db::set_setting(&mut *tx, "log_level", level).await?;
        changed.push("log_level");
    }
    let switches = [
        ("icon_service", "icons", b.icons, state.icons.enabled()),
        (
            "signups_verify",
            "signups_verify",
            b.signups_verify,
            state.signups_verify(),
        ),
        (
            BREACH_CHECK,
            "breach_check",
            b.breach_check,
            state.breach_check(),
        ),
        (EVENT_IP, "event_ip", b.event_ip, state.numbers.event_ip()),
        (
            crate::push::ENABLED_SETTING,
            "push_enabled",
            b.push_enabled,
            state.push.enabled(),
        ),
    ];
    for (row, name, value, now_on) in switches {
        if let Some(on) = value {
            db::set_setting(&mut *tx, row, bit(on)).await?;
            if on != now_on {
                changed.push(name);
            }
        }
    }
    if let Some(url) = &relay {
        db::set_setting(&mut *tx, crate::push::RELAY_SETTING, url).await?;
        if *url != state.push.relay_url() {
            changed.push("push_relay_url");
        }
    }
    if b.push_enabled == Some(false) {
        // Off: no phone is kept registered (the apps register again once it is back on).
        sqlx::query("DELETE FROM push_tokens")
            .execute(&mut *tx)
            .await?;
    }
    if b.event_ip == Some(false) {
        // Off also forgets the addresses already kept.
        sqlx::query("UPDATE events SET ip = NULL WHERE ip IS NOT NULL")
            .execute(&mut *tx)
            .await?;
    }
    for (n, value) in &numbers {
        db::set_setting(&mut *tx, n.spec().name, &value.to_string()).await?;
        if state.num(*n) != *value {
            changed.push(n.spec().name);
        }
    }
    for (f, on) in &flags {
        db::set_setting(&mut *tx, f.spec().name, bit(*on)).await?;
        if state.flag(*f) != *on {
            changed.push(f.spec().name);
        }
    }
    // The event follows the address switch as this change leaves it.
    let keep_ip = b.event_ip.unwrap_or_else(|| state.numbers.event_ip());
    settings_changed(&mut tx, &admin, &changed, keep_ip).await?;
    tx.commit().await?;

    if let Some(level) = level {
        if let Err(e) = crate::logging::set_level(&level) {
            tracing::warn!(error = %e, "changing the log level failed");
        }
        *state.log_level.write().expect("log level lock") = level;
    }
    if let Some(on) = b.icons {
        state.icons.set_enabled(on);
    }
    if let Some(on) = b.signups_verify {
        state
            .signups_verify
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(on) = b.breach_check {
        state.numbers.set_breach_check(on);
    }
    if let Some(on) = b.event_ip {
        state.numbers.set_event_ip(on);
    }
    if let Some(on) = b.push_enabled {
        state.push.set_enabled(on);
    }
    if let Some(url) = relay {
        state.push.set_relay_url(url);
    }
    let fewer_versions = numbers
        .iter()
        .any(|(n, v)| *n == Num::ItemVersionsKept && *v < state.num(Num::ItemVersionsKept));
    for (n, value) in &numbers {
        state.numbers.set(*n, *value);
    }
    for (f, on) in &flags {
        state.numbers.set_flag(*f, *on);
    }
    if fewer_versions && let Err(e) = crate::vault::trim_versions(&state).await {
        tracing::warn!(error = %e, "trimming item versions failed; each item is trimmed at its next edit");
    }
    tracing::info!(
        log_level = %state.log_level.read().expect("log level lock"),
        icons = state.icons.enabled(),
        signups_verify = state.signups_verify(),
        breach_check = state.breach_check(),
        event_ip = state.numbers.event_ip(),
        push_enabled = state.push.enabled(),
        push_relay_url = %state.push.relay_url(),
        changed = ?numbers.iter().map(|(n, v)| format!("{}={v}", n.spec().name))
            .chain(flags.iter().map(|(f, on)| format!("{}={on}", f.spec().name)))
            .collect::<Vec<_>>(),
        "server settings changed by admin"
    );
    Ok(settings_json(&state))
}

#[derive(Deserialize)]
struct SmtpBody {
    host: String,
    port: Option<u16>,
    security: SmtpSecurity,
    #[serde(default)]
    username: String,
    /// `None` keeps the saved password; `""` removes it.
    password: Option<String>,
    from: String,
    #[serde(default)]
    from_name: String,
}

async fn set_smtp(
    State(state): State<AppState>,
    admin: Admin,
    Json(b): Json<SmtpBody>,
) -> ApiResult<Json<Value>> {
    let host = b.host.trim().to_owned();
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(ApiError::bad(
            "enter the SMTP server's host name, such as smtp.example.com",
        ));
    }
    let password = match b.password {
        Some(p) => Some(p).filter(|p| !p.is_empty()),
        None => state.mailer.config().and_then(|c| c.password),
    };
    let username = Some(b.username.trim().to_owned()).filter(|u| !u.is_empty());
    let from_name = b.from_name.trim();
    let smtp = SmtpConfig {
        host,
        port: b.port.unwrap_or(match b.security {
            SmtpSecurity::Starttls => 587,
            SmtpSecurity::ForceTls => 465,
            SmtpSecurity::Off => 25,
        }),
        security: b.security,
        username,
        password,
        from: b.from.trim().to_owned(),
        from_name: if from_name.is_empty() {
            "PassAuth".into()
        } else {
            from_name.to_owned()
        },
    };
    state
        .mailer
        .configure(Some(&smtp))
        .map_err(|e| ApiError::bad(format!("{e:#}")))?;
    let json = serde_json::to_string(&smtp).map_err(|e| anyhow::anyhow!(e))?;
    let mut tx = state.db.begin().await?;
    db::set_setting(&mut *tx, "smtp", &json).await?;
    settings_changed(&mut tx, &admin, &["smtp"], state.numbers.event_ip()).await?;
    tx.commit().await?;
    tracing::info!(host = %smtp.host, port = smtp.port, "email settings changed by admin");
    Ok(settings_json(&state))
}

/// Turn email off (also when SMTP_* is set in .env).
async fn smtp_off(State(state): State<AppState>, admin: Admin) -> ApiResult<Json<Value>> {
    state.mailer.configure(None)?;
    let mut tx = state.db.begin().await?;
    db::set_setting(&mut *tx, "smtp", "off").await?;
    settings_changed(&mut tx, &admin, &["smtp"], state.numbers.event_ip()).await?;
    tx.commit().await?;
    tracing::info!("email turned off by admin");
    Ok(settings_json(&state))
}
