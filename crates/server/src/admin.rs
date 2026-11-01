//! Admin API, enabled only when `ADMIN_TOKEN` is set. The token should be an
//! Argon2 PHC hash (`passauth-server hash-admin-token`). There are
//! deliberately no settings here that execute programs or touch the filesystem.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{bearer, client_ip};
use crate::config::SignupPolicy;
use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::mail::Email;
use crate::state::{AppState, ct_eq, normalize_email};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/users", get(list_users))
        .route("/users/{id}", delete(delete_user))
        .route("/users/{id}/disable", post(disable_user))
        .route("/users/{id}/enable", post(enable_user))
        .route("/users/{id}/sessions/revoke", post(revoke_sessions))
        .route("/invites", get(list_invites).post(invite))
        .route("/invites/{email}", delete(delete_invite))
        .route("/smtp/test", post(smtp_test))
        .route("/settings/signups", put(set_signups))
}

pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let configured = state
            .config
            .admin_token
            .as_deref()
            .ok_or(ApiError::NotFound)?;
        let ip = client_ip(state, &parts.headers);
        if !state.limiter.check(&format!("admin:{ip}"), 120, 60) {
            return Err(ApiError::TooManyRequests);
        }
        let given = bearer(&parts.headers).ok_or(ApiError::Unauthorized)?;
        if verify_token(configured, &given) {
            Ok(Admin)
        } else {
            Err(ApiError::Unauthorized)
        }
    }
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
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "users": users, "vaults": vaults, "items": items,
        "config": {
            "domain": c.domain,
            "database": if c.database_url.starts_with("postgres") { "postgresql" } else { "sqlite" },
            "signups_allowed": signups.allowed,
            "signups_domains": signups.domains,
            "signups_verify": c.signups_verify,
            "smtp_enabled": state.mailer.enabled(),
            "admin_token_hashed": c.admin_token.as_deref().is_some_and(|t| t.starts_with("$argon2")),
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
    if !email.contains('@') {
        return Err(ApiError::bad("invalid email address"));
    }
    let t = now();
    sqlx::query("DELETE FROM invites WHERE email = $1")
        .bind(&email)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO invites (email, created_at, expires_at) VALUES ($1, $2, $3)")
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
            action: Some(("Create your account".into(), format!("{}/register?email={}", state.config.domain, email))),
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
    state
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
        .await
        .map_err(|e| ApiError::bad(format!("SMTP error: {e:#}")))?;
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
