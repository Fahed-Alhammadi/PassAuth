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
use crate::auth::{bearer, client_ip};
use crate::config::{SignupPolicy, SmtpConfig, SmtpSecurity};
use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::mail::Email;
use crate::state::{AdminLogin, AppState, ct_eq, hash_token, normalize_email, random_token};

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
        .merge(crate::admin_security::routes())
}

pub struct Admin;

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
                return Ok(Admin);
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
            return Ok(Admin);
        }
        if !check_secret(state, parts, configured.clone(), given, None).await? {
            return Err(ApiError::Unauthorized);
        }
        *state.admin_verified.lock().expect("admin cache lock") = Some((digest, now() + 600));
        Ok(Admin)
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
    if !state.limiter.check(&format!("admin:{ip}"), 10, 60) {
        return Err(ApiError::TooManyRequests);
    }
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
    Ok(Json(start_session(&state, &parts.headers)))
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
    if !state.limiter.check(&format!("admin:{ip}"), 10, 60) {
        return Err(ApiError::TooManyRequests);
    }
    let Some((expires, attempts)) = state.admin_pending.take(&b.pending) else {
        return Err(ApiError::bad(
            "this sign-in has expired. Go back and enter your password again",
        ));
    };
    if admin_security::check_code(&state.db, &b.code).await? {
        return Ok(Json(start_session(&state, &headers)));
    }
    tracing::warn!(%ip, "admin sign-in: wrong two-step code");
    if attempts + 1 >= TWO_FACTOR_ATTEMPTS {
        return Err(ApiError::bad(
            "too many wrong codes. Go back and enter your password again",
        ));
    }
    state
        .admin_pending
        .put_back(b.pending, attempts + 1, expires);
    Err(ApiError::bad(
        "that code isn't right. Enter the newest code from your authenticator app, or a recovery code",
    ))
}

fn start_session(state: &AppState, headers: &HeaderMap) -> Value {
    let token = random_token();
    let t = now();
    state.admin_sessions.insert(
        hash_token(&token),
        (t + SESSION_IDLE_SECS, t + SESSION_MAX_SECS),
    );
    tracing::info!(ip = %client_ip(state, headers), "admin signed in");
    json!({ "token": token, "expires_in": SESSION_IDLE_SECS })
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
    let c = &state.config;
    let signups = state.signups.read().expect("signup policy lock").clone();
    let token_hashed = matches!(&state.admin, AdminLogin::Token(t) if t.starts_with("$argon2"));
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "users": users, "vaults": vaults, "items": items,
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
    items: i64,
    two_factor: i64,
}

async fn list_users(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    let users: Vec<UserRow> = sqlx::query_as(
        "SELECT u.id, u.email, u.name, u.email_verified, u.disabled, u.created_at,
           (SELECT MAX(last_seen) FROM devices d WHERE d.user_id = u.id) AS last_seen,
           (SELECT COUNT(*) FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
              WHERE m.user_id = u.id AND m.role = 'owner') AS items,
           (SELECT COUNT(*) FROM two_factor t WHERE t.user_id = u.id AND t.enabled = 1 AND t.provider <> 'recovery') AS two_factor
         FROM users u ORDER BY u.created_at",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "users": users })))
}

async fn set_disabled(state: &AppState, id: &str, disabled: bool) -> ApiResult<Json<Value>> {
    let done = sqlx::query("UPDATE users SET disabled = $1, updated_at = $2 WHERE id = $3")
        .bind(disabled as i64)
        .bind(now())
        .bind(id)
        .execute(&state.db)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    if disabled {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&state.db)
            .await?;
        state.notify_logout(id);
    }
    Ok(Json(json!({ "ok": true })))
}

async fn disable_user(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    set_disabled(&state, &id, true).await
}

async fn enable_user(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    set_disabled(&state, &id, false).await
}

async fn revoke_sessions(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    state.notify_logout(&id);
    Ok(Json(json!({ "ok": true })))
}

/// Turn off every two-step login method of a user who lost them all (authenticator,
/// email codes, security keys, recovery codes), forget their "remember this device"
/// tokens and lockout, and tell them by email. Their master password still guards the
/// account and the vault stays encrypted; nothing else changes.
async fn reset_two_factor(
    State(state): State<AppState>,
    _: Admin,
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
    _: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    crate::account::delete_user(&state, &id).await?;
    state.notify_logout(&id);
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

async fn invite(
    State(state): State<AppState>,
    _: Admin,
    Json(b): Json<InviteBody>,
) -> ApiResult<Json<Value>> {
    let email = normalize_email(&b.email);
    if !email.contains('@') || email.len() > 254 || email.chars().any(char::is_control) {
        return Err(ApiError::bad("invalid email address"));
    }
    let t = now();
    sqlx::query(
        "INSERT INTO invites (email, created_at, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT (email) DO UPDATE SET created_at = excluded.created_at, expires_at = excluded.expires_at",
    )
    .bind(&email)
    .bind(t)
    .bind(t + 7 * 24 * 3600)
    .execute(&state.db)
    .await?;
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

async fn delete_invite(
    State(state): State<AppState>,
    _: Admin,
    Path(email): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM invites WHERE email = $1")
        .bind(normalize_email(&email))
        .execute(&state.db)
        .await?;
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
    _: Admin,
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
    db::set_setting(
        &state.db,
        "signups_allowed",
        if policy.allowed { "1" } else { "0" },
    )
    .await?;
    db::set_setting(&state.db, "signups_domains", &policy.domains.join(",")).await?;
    *state.signups.write().expect("signup policy lock") = policy.clone();
    tracing::info!(allowed = policy.allowed, domains = ?policy.domains, "sign-up policy changed by admin");
    Ok(Json(policy))
}

// ---------------------------------------------------------------- settings

/// Settings changed on the admin page. They are saved in the database, apply at
/// once and replace the matching `.env` values (which only set the starting values).
async fn get_settings(State(state): State<AppState>, _: Admin) -> Json<Value> {
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
    Json(json!({
        "log_level": state.log_level.read().expect("log level lock").clone(),
        "log_levels": crate::logging::LEVELS,
        "icons": state.icons.enabled(),
        "signups_verify": state.signups_verify(),
        "smtp": smtp,
    }))
}

#[derive(Deserialize)]
struct GeneralSettings {
    log_level: String,
    icons: bool,
    signups_verify: bool,
}

async fn set_settings(
    State(state): State<AppState>,
    _: Admin,
    Json(b): Json<GeneralSettings>,
) -> ApiResult<Json<Value>> {
    let level_changed = *state.log_level.read().expect("log level lock") != b.log_level;
    if level_changed {
        crate::logging::set_level(&b.log_level).map_err(|e| ApiError::bad(e.to_string()))?;
        db::set_setting(&state.db, "log_level", &b.log_level).await?;
        *state.log_level.write().expect("log level lock") = b.log_level.clone();
    }
    let bit = |on: bool| if on { "1" } else { "0" };
    db::set_setting(&state.db, "icon_service", bit(b.icons)).await?;
    state.icons.set_enabled(b.icons);
    db::set_setting(&state.db, "signups_verify", bit(b.signups_verify)).await?;
    state
        .signups_verify
        .store(b.signups_verify, std::sync::atomic::Ordering::Relaxed);
    tracing::info!(
        log_level = %b.log_level,
        icons = b.icons,
        signups_verify = b.signups_verify,
        "server settings changed by admin"
    );
    Ok(get_settings(State(state), Admin).await)
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
    _: Admin,
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
    db::set_setting(&state.db, "smtp", &json).await?;
    tracing::info!(host = %smtp.host, port = smtp.port, "email settings changed by admin");
    Ok(get_settings(State(state), Admin).await)
}

/// Turn email off (also when SMTP_* is set in .env).
async fn smtp_off(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    state.mailer.configure(None)?;
    db::set_setting(&state.db, "smtp", "off").await?;
    tracing::info!("email turned off by admin");
    Ok(get_settings(State(state), Admin).await)
}
