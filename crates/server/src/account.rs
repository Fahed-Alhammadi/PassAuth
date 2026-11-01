//! Account settings: profile, password / Secret Key change, 2FA, sessions,
//! deletion. Sensitive actions need a reauth token (`x-reauth-token`) from a
//! fresh OPAQUE login with `purpose: "reauth"`.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use passauth_core::item::{b64, unb64};
use passauth_core::keys::AccountBundle;
use passauth_core::opaque::Suite;
use passauth_core::opaque::opaque_ke::{
    RegistrationRequest, RegistrationUpload, ServerRegistration,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{AuthUser, require_reauth};
use crate::db::now;
use crate::error::{ApiError, ApiResult};
use crate::mail::Email;
use crate::state::AppState;
use crate::twofactor::{self, TotpData};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(get_account).delete(delete_account))
        .route("/profile", put(update_profile))
        .route("/keys/start", post(keys_start))
        .route("/keys/finish", post(keys_finish))
        .route("/2fa/totp/setup", post(totp_setup))
        .route("/2fa/totp/enable", post(totp_enable))
        .route("/2fa/email/setup", post(email_setup))
        .route("/2fa/email/enable", post(email_enable))
        .route("/2fa/recovery", post(recovery_regenerate))
        .route("/2fa/{provider}", delete(two_factor_disable))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", delete(revoke_session))
}

fn reauth_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-reauth-token").and_then(|v| v.to_str().ok())
}

async fn get_account(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let (name, verified, bundle, created): (String, i64, String, i64) =
        sqlx::query_as("SELECT name, email_verified, bundle, created_at FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    let bundle: AccountBundle = serde_json::from_str(&bundle).map_err(anyhow::Error::from)?;
    let providers = twofactor::enabled_providers(&state.db, &user.user_id).await?;
    let recovery: Option<String> = sqlx::query_scalar(
        "SELECT data FROM two_factor WHERE user_id = $1 AND provider = 'recovery'",
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let recovery_left = recovery
        .and_then(|d| serde_json::from_str::<twofactor::RecoveryData>(&d).ok())
        .map_or(0, |d| d.hashes.len());
    let fingerprint = unb64(&bundle.public_key)
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .map(|k| passauth_core::crypto::fingerprint(&k));
    Ok(Json(json!({
        "user_id": user.user_id,
        "email": user.email,
        "name": name,
        "email_verified": verified != 0,
        "created_at": created,
        "secret_key_enabled": bundle.secret_key_enabled,
        "fingerprint": fingerprint,
        "two_factor": providers,
        "recovery_codes_left": recovery_left,
        "email_enabled": state.mailer.enabled(),
    })))
}

#[derive(Deserialize)]
struct Profile {
    name: String,
}

async fn update_profile(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Profile>,
) -> ApiResult<Json<Value>> {
    let name = b.name.trim();
    if name.len() > 100 {
        return Err(ApiError::bad("name too long"));
    }
    sqlx::query("UPDATE users SET name = $1, updated_at = $2 WHERE id = $3")
        .bind(name)
        .bind(now())
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------- password / Secret Key change

#[derive(Deserialize)]
struct KeysStart {
    message: String,
}

async fn keys_start(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<KeysStart>,
) -> ApiResult<Json<Value>> {
    let req = RegistrationRequest::<Suite>::deserialize(&unb64(&b.message)?)
        .map_err(|_| ApiError::bad("bad message"))?;
    let resp = ServerRegistration::<Suite>::start(&state.opaque, req, user.user_id.as_bytes())
        .map_err(|_| ApiError::bad("bad message"))?;
    Ok(Json(json!({ "message": b64(&resp.message.serialize()) })))
}

#[derive(Deserialize)]
struct KeysFinish {
    upload: String,
    bundle: AccountBundle,
}

/// Replace the OPAQUE record and account bundle (new password and/or Secret
/// Key setting). All other sessions are signed out.
async fn keys_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(b): Json<KeysFinish>,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    let current: String = sqlx::query_scalar("SELECT bundle FROM users WHERE id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    let current: AccountBundle = serde_json::from_str(&current).map_err(anyhow::Error::from)?;
    if b.bundle.account_id != current.account_id
        || b.bundle.public_key != current.public_key
        || b.bundle.wrapped_private_key != current.wrapped_private_key
    {
        return Err(ApiError::bad("only the password wrapping may change"));
    }
    b.bundle.kdf.validate()?;
    let upload = RegistrationUpload::<Suite>::deserialize(&unb64(&b.upload)?)
        .map_err(|_| ApiError::bad("bad upload"))?;
    let record = b64(&ServerRegistration::<Suite>::finish(upload).serialize());
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET opaque_record = $1, bundle = $2, updated_at = $3 WHERE id = $4")
        .bind(&record)
        .bind(serde_json::to_string(&b.bundle).map_err(anyhow::Error::from)?)
        .bind(now())
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
        .bind(&user.user_id)
        .bind(&user.session_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE devices SET remember_hash = NULL, remember_expires = NULL WHERE user_id = $1",
    )
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    state.notify_logout(&user.user_id);
    state.mailer.send_later(
        user.email.clone(),
        Email {
            subject: "Your PassAuth master password was changed".into(),
            heading: "Master password changed".into(),
            body: "Your master password or Secret Key setting was just changed, and other devices were signed out. If this wasn't you, contact your PassAuth administrator immediately.".into(),
            action: None,
            code: None,
        },
    );
    Ok(Json(json!({ "ok": true })))
}

// --------------------------------------------------------------------- 2FA

async fn totp_setup(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let secret = twofactor::new_totp_secret();
    let data = serde_json::to_string(&TotpData {
        secret: secret.clone(),
    })
    .map_err(anyhow::Error::from)?;
    let enabled = twofactor::enabled_providers(&state.db, &user.user_id)
        .await?
        .iter()
        .any(|p| p == twofactor::TOTP);
    if enabled {
        return Err(ApiError::Conflict(
            "authenticator app already enabled; disable it first".into(),
        ));
    }
    twofactor::upsert(&state.db, &user.user_id, twofactor::TOTP, &data, false).await?;
    let label = urlencode(&format!("PassAuth:{}", user.email));
    Ok(Json(json!({
        "secret": secret,
        "uri": format!("otpauth://totp/{label}?secret={secret}&issuer=PassAuth&algorithm=SHA1&digits=6&period=30"),
    })))
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

async fn totp_enable(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Code>,
) -> ApiResult<Json<Value>> {
    let data: Option<String> = sqlx::query_scalar(
        "SELECT data FROM two_factor WHERE user_id = $1 AND provider = 'totp' AND enabled = 0",
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let data: TotpData = serde_json::from_str(&data.ok_or(ApiError::bad("start setup first"))?)
        .map_err(anyhow::Error::from)?;
    let step = twofactor::check_totp(&data.secret, b.code.trim(), 0)
        .ok_or(ApiError::bad("invalid code"))?;
    sqlx::query("UPDATE two_factor SET enabled = 1, last_used = $1 WHERE user_id = $2 AND provider = 'totp'")
        .bind(step)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(
        json!({ "recovery_codes": first_recovery_codes(&state, &user).await? }),
    ))
}

async fn email_setup(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    if !state.mailer.enabled() {
        return Err(ApiError::bad("email is not configured on this server"));
    }
    let code = twofactor::issue_email_code(&state.db, &user.user_id, "2fa-setup").await?;
    state.mailer.send_later(
        user.email.clone(),
        Email {
            subject: "Confirm email two-step login".into(),
            heading: "Turn on email codes".into(),
            body: "Enter this code in PassAuth to turn on two-step login by email.".into(),
            action: None,
            code: Some(code),
        },
    );
    Ok(Json(json!({ "sent": true })))
}

async fn email_enable(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Code>,
) -> ApiResult<Json<Value>> {
    if !twofactor::verify_email_code(&state.db, &user.user_id, "2fa-setup", b.code.trim()).await? {
        return Err(ApiError::bad("invalid code"));
    }
    twofactor::upsert(&state.db, &user.user_id, twofactor::EMAIL, "{}", true).await?;
    Ok(Json(
        json!({ "recovery_codes": first_recovery_codes(&state, &user).await? }),
    ))
}

/// Recovery codes are generated with the first provider and shown once.
async fn first_recovery_codes(state: &AppState, user: &AuthUser) -> ApiResult<Option<Vec<String>>> {
    let has: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM two_factor WHERE user_id = $1 AND provider = 'recovery'",
    )
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await?;
    if has > 0 {
        return Ok(None);
    }
    Ok(Some(
        twofactor::regenerate_recovery_codes(&state.db, &user.user_id).await?,
    ))
}

async fn recovery_regenerate(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    if twofactor::enabled_providers(&state.db, &user.user_id)
        .await?
        .is_empty()
    {
        return Err(ApiError::bad("enable two-step login first"));
    }
    Ok(Json(
        json!({ "recovery_codes": twofactor::regenerate_recovery_codes(&state.db, &user.user_id).await? }),
    ))
}

async fn two_factor_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(provider): Path<String>,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    if provider != twofactor::TOTP && provider != twofactor::EMAIL {
        return Err(ApiError::bad("unknown provider"));
    }
    sqlx::query("DELETE FROM two_factor WHERE user_id = $1 AND provider = $2")
        .bind(&user.user_id)
        .bind(&provider)
        .execute(&state.db)
        .await?;
    if twofactor::enabled_providers(&state.db, &user.user_id)
        .await?
        .is_empty()
    {
        sqlx::query("DELETE FROM two_factor WHERE user_id = $1")
            .bind(&user.user_id)
            .execute(&state.db)
            .await?;
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- sessions

#[derive(Serialize, sqlx::FromRow)]
struct SessionRow {
    id: String,
    device_id: String,
    device_name: String,
    device_kind: String,
    created_at: i64,
    last_used: i64,
}

async fn list_sessions(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT s.id, s.device_id, d.name AS device_name, d.kind AS device_kind, s.created_at, s.last_used
         FROM sessions s JOIN devices d ON d.user_id = s.user_id AND d.id = s.device_id
         WHERE s.user_id = $1 AND s.refresh_expires > $2 ORDER BY s.last_used DESC",
    )
    .bind(&user.user_id)
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        json!({ "current": user.session_id, "sessions": rows }),
    ))
}

async fn revoke_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- deletion

async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    delete_user(&state, &user.user_id).await?;
    state.notify_logout(&user.user_id);
    Ok(Json(json!({ "deleted": true })))
}

/// Remove a user and every vault they own (shared members lose access too).
pub async fn delete_user(state: &AppState, user_id: &str) -> ApiResult<()> {
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT vault_id FROM vault_members WHERE user_id = $1 AND role = 'owner'",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    let mut tx = state.db.begin().await?;
    for v in &owned {
        for stmt in [
            "DELETE FROM items WHERE vault_id = $1",
            "DELETE FROM vault_members WHERE vault_id = $1",
            "DELETE FROM vaults WHERE id = $1",
        ] {
            sqlx::query(stmt).bind(v).execute(&mut *tx).await?;
        }
    }
    for stmt in [
        "DELETE FROM vault_members WHERE user_id = $1",
        "DELETE FROM sessions WHERE user_id = $1",
        "DELETE FROM devices WHERE user_id = $1",
        "DELETE FROM two_factor WHERE user_id = $1",
        "DELETE FROM email_tokens WHERE user_id = $1",
        "DELETE FROM users WHERE id = $1",
    ] {
        sqlx::query(stmt).bind(user_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    tracing::info!(user = %user_id, "account deleted");
    Ok(())
}
