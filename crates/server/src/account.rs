//! Account settings: profile, password / Secret Key change, 2FA, sessions,
//! deletion. Sensitive actions need a reauth token (`x-reauth-token`) from a
//! fresh OPAQUE login with `purpose: "reauth"`.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
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

use crate::auth::{AuthUser, REAUTH_FIRST, check_reauth, require_reauth, require_reauth_or};
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::{self, Event};
use crate::mail::Email;
use crate::passkeys;
use crate::policies;
use crate::state::{AppState, PendingPasskeyRegistration, Sessions, SyncNotice};
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
        .route("/2fa/passkey/register/start", post(passkey_register_start))
        .route(
            "/2fa/passkey/register/finish",
            post(passkey_register_finish),
        )
        .route("/2fa/passkey/{id}", delete(passkey_remove))
        .route("/2fa/{provider}", delete(two_factor_disable))
        .route("/sessions", get(list_sessions))
        .route("/sessions/revoke-others", post(revoke_other_sessions))
        .route("/sessions/{id}", delete(revoke_session))
        .route("/devices/{device_id}/forget", post(forget_device))
        .route("/events", get(events::account_events))
        .route("/auth-requests", get(crate::auth_requests::list))
        .route("/auth-requests/{id}", post(crate::auth_requests::answer))
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
    let passkeys = passkeys::summary(&passkeys::list(&state.db, &user.user_id).await?);
    let (item_count, storage_bytes, attachment_bytes) = {
        let mut conn = state.db.acquire().await?;
        let (items, bytes) = crate::vault::usage(&mut conn, &user.user_id).await?;
        let files = crate::vault::attachment_usage(&mut conn, &user.user_id).await?;
        (items, bytes, files)
    };
    let (max_items, max_storage_bytes) = crate::vault::quota(&state);
    let max_attachment_bytes = crate::vault::attachment_quota(&state);
    let policy_violations = policies::violations(&state, &bundle, providers.len());
    Ok(Json(json!({
        // Items and bytes in the vaults this account owns (plus its Sends and the
        // uploads it started), the attachments' part of them, and the admin's
        // limits for them (0 = no limit).
        "usage": {
            "item_count": item_count,
            "storage_bytes": storage_bytes,
            "attachment_bytes": attachment_bytes,
        },
        "limits": {
            "max_items": max_items,
            "max_storage_bytes": max_storage_bytes,
            "max_attachment_bytes": max_attachment_bytes,
        },
        "passkeys": passkeys,
        "passkeys_available": state.webauthn.is_some(),
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
        // What the account still has to change for the server's policies:
        // `two_step`, `secret_key`, `kdf` (see `policies.rs`).
        "policy_violations": policy_violations,
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
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET name = $1, updated_at = $2 WHERE id = $3")
        .bind(name)
        .bind(now())
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    // `/sync` carries the name: the account's other devices pick it up.
    let revision = crate::vault::bump_user(&mut tx, &user.user_id).await?;
    tx.commit().await?;
    if let Some(revision) = revision {
        let origin = state.origin(&user.session_id);
        state.notify_sync(vec![(
            user.user_id,
            SyncNotice::new(revision, Some(origin)),
        )]);
    }
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
    policies::check_new_keys(&state, &b.bundle)?;
    let upload = RegistrationUpload::<Suite>::deserialize(&unb64(&b.upload)?)
        .map_err(|_| ApiError::bad("bad upload"))?;
    let record = b64(&ServerRegistration::<Suite>::finish(upload).serialize());
    let mut tx = state.db.begin().await?;
    // The account's row first: a sign-in finishing at this moment (it writes the
    // same row first) is either done before, and its session is signed out below,
    // or waits until this is committed.
    sqlx::query("UPDATE users SET opaque_record = $1, bundle = $2, updated_at = $3 WHERE id = $4")
        .bind(&record)
        .bind(serde_json::to_string(&b.bundle).map_err(anyhow::Error::from)?)
        .bind(now())
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    let signed_out = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
        .bind(&user.user_id)
        .bind(&user.session_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(
        "UPDATE devices SET remember_hash = NULL, remember_expires = NULL WHERE user_id = $1",
    )
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await?;
    // Like the other sessions: no sign-in request still waiting becomes one.
    crate::auth_requests::cancel_open(&mut tx, &user.user_id).await?;
    // `/sync` carries the bundle.
    let revision = crate::vault::bump_user(&mut tx, &user.user_id).await?;
    Event::new("account.password_changed")
        .by(&user)
        .data(json!({
            "secret_key": b.bundle.secret_key_enabled,
            "sessions_signed_out": signed_out,
        }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    // Every other session is gone, and so is every sign-in waiting for its two-step
    // login; this device stays signed in.
    state.forget_pending_sign_ins(&user.user_id);
    state.notify_logout(&user.user_id, Sessions::AllExcept(user.session_id.clone()));
    if let Some(revision) = revision {
        let origin = state.origin(&user.session_id);
        state.notify_sync(vec![(
            user.user_id.clone(),
            SyncNotice::new(revision, Some(origin)),
        )]);
    }
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
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::ALREADY_ENABLED,
            "authenticator app already enabled; disable it first",
        ));
    }
    let mut conn = state.db.acquire().await?;
    twofactor::upsert(&mut conn, &user.user_id, twofactor::TOTP, &data, false).await?;
    drop(conn);
    let label = urlencode(&format!("PassAuth:{}", user.email));
    Ok(Json(json!({
        "secret": secret,
        "uri": format!("otpauth://totp/{label}?secret={secret}&issuer=PassAuth&algorithm=SHA1&digits=6&period=30"),
    })))
}

pub(crate) fn urlencode(s: &str) -> String {
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

/// `POST /account/2fa/totp/enable {code}` with a reauth token (`x-reauth-token`;
/// without one 403 `reauth_required`): a stolen session alone can't put its own
/// authenticator on the account. The token is used up only when the method is
/// turned on, so a mistyped code can be tried again with it.
async fn totp_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(b): Json<Code>,
) -> ApiResult<Json<Value>> {
    let reauth = reauth_header(&headers);
    check_reauth(&state, &user, reauth, REAUTH_FIRST)?;
    let data: Option<String> = sqlx::query_scalar(
        "SELECT data FROM two_factor WHERE user_id = $1 AND provider = 'totp' AND enabled = 0",
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let data: TotpData =
        serde_json::from_str(&data.ok_or_else(|| ApiError::expired("start setup first"))?)
            .map_err(anyhow::Error::from)?;
    let step = twofactor::check_totp(&data.secret, b.code.trim(), 0)
        .ok_or_else(|| ApiError::invalid_code("invalid code"))?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE two_factor SET enabled = 1, last_used = $1 WHERE user_id = $2 AND provider = 'totp'")
        .bind(step)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    let codes = first_recovery_codes(&mut tx, &user).await?;
    two_step_enabled(&mut tx, &state, &user, twofactor::TOTP, codes.is_some()).await?;
    require_reauth_or(&state, &user, reauth, REAUTH_FIRST)?;
    tx.commit().await?;
    two_step_changed(&state, &user, TwoStepChange::Enabled(twofactor::TOTP));
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// A change of the account's two-step login, for the email that tells its owner.
enum TwoStepChange<'a> {
    Enabled(&'a str),
    Disabled(&'a str),
    RecoveryCodes,
    SecurityKeyAdded,
    SecurityKeyRemoved,
}

/// Email the account about a change of its two-step login (when email is set
/// up), so someone who got hold of a session and the master password can't
/// quietly add a second factor of their own or take one away.
fn two_step_changed(state: &AppState, user: &AuthUser, change: TwoStepChange) {
    let method = |m: &str| match m {
        twofactor::TOTP => "an authenticator app",
        twofactor::EMAIL => "email codes",
        _ => "another method",
    };
    let what = match change {
        TwoStepChange::Enabled(m) => format!("Two-step login with {} was turned on.", method(m)),
        TwoStepChange::Disabled(m) => {
            format!("Two-step login with {} was turned off.", method(m))
        }
        TwoStepChange::RecoveryCodes => {
            "New recovery codes were created; the old ones no longer work.".into()
        }
        TwoStepChange::SecurityKeyAdded => "A security key was added for two-step login.".into(),
        TwoStepChange::SecurityKeyRemoved => {
            "A security key was removed from two-step login.".into()
        }
    };
    state.mailer.send_later(
        user.email.clone(),
        Email {
            subject: "Two-step login changed on your PassAuth account".into(),
            heading: "Two-step login changed".into(),
            body: format!(
                "{what}\nIf this wasn't you, change your master password now, sign out your other sessions and check your two-step login settings."
            ),
            action: Some((
                "Review two-step login".into(),
                format!("{}/settings/two-step", state.config.domain),
            )),
            code: None,
        },
    );
}

/// `account.two_step_enabled`, with whether recovery codes were made with it.
async fn two_step_enabled(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    user: &AuthUser,
    method: &str,
    recovery_codes: bool,
) -> ApiResult<()> {
    Event::new("account.two_step_enabled")
        .by(user)
        .data(json!({ "method": method, "recovery_codes": recovery_codes }))
        .record(conn, state)
        .await
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

/// `POST /account/2fa/email/enable {code}` with a reauth token, like
/// [`totp_enable`].
async fn email_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(b): Json<Code>,
) -> ApiResult<Json<Value>> {
    let reauth = reauth_header(&headers);
    check_reauth(&state, &user, reauth, REAUTH_FIRST)?;
    if !twofactor::verify_email_code(&state.db, &user.user_id, "2fa-setup", b.code.trim()).await? {
        return Err(ApiError::invalid_code("invalid code"));
    }
    let mut tx = state.db.begin().await?;
    twofactor::upsert(&mut tx, &user.user_id, twofactor::EMAIL, "{}", true).await?;
    let codes = first_recovery_codes(&mut tx, &user).await?;
    two_step_enabled(&mut tx, &state, &user, twofactor::EMAIL, codes.is_some()).await?;
    require_reauth_or(&state, &user, reauth, REAUTH_FIRST)?;
    tx.commit().await?;
    two_step_changed(&state, &user, TwoStepChange::Enabled(twofactor::EMAIL));
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// Recovery codes are generated with the first provider and shown once (inside
/// the caller's transaction, after its first write).
async fn first_recovery_codes(
    conn: &mut sqlx::AnyConnection,
    user: &AuthUser,
) -> ApiResult<Option<Vec<String>>> {
    let has: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM two_factor WHERE user_id = $1 AND provider = 'recovery'",
    )
    .bind(&user.user_id)
    .fetch_one(&mut *conn)
    .await?;
    if has > 0 {
        return Ok(None);
    }
    Ok(Some(
        twofactor::regenerate_recovery_codes(conn, &user.user_id).await?,
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
    let mut tx = state.db.begin().await?;
    let codes = twofactor::regenerate_recovery_codes(&mut tx, &user.user_id).await?;
    Event::new("account.recovery_codes_created")
        .by(&user)
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    two_step_changed(&state, &user, TwoStepChange::RecoveryCodes);
    Ok(Json(json!({ "recovery_codes": codes })))
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
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("DELETE FROM two_factor WHERE user_id = $1 AND provider = $2")
        .bind(&user.user_id)
        .bind(&provider)
        .execute(&mut *tx)
        .await?;
    if twofactor::enabled_providers(&mut *tx, &user.user_id)
        .await?
        .is_empty()
    {
        sqlx::query("DELETE FROM two_factor WHERE user_id = $1")
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await?;
    }
    if done.rows_affected() > 0 {
        policies::keep_last_method(&mut tx, &state, &user.user_id).await?;
        Event::new("account.two_step_disabled")
            .by(&user)
            .data(json!({ "method": provider }))
            .record(&mut tx, &state)
            .await?;
    }
    tx.commit().await?;
    if done.rows_affected() > 0 {
        two_step_changed(&state, &user, TwoStepChange::Disabled(&provider));
    }
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------- security keys / passkeys

/// Creation options for the browser. Needs a reauth token; the returned
/// `registration_id` is single-use and bound to the account.
async fn passkey_register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    let webauthn = passkeys::relying_party(&state)?;
    let existing = passkeys::list(&state.db, &user.user_id).await?;
    if existing.len() as i64 >= passkeys::MAX_PER_USER {
        return Err(ApiError::bad("you can register at most 10 security keys"));
    }
    let (name, _): (String, i64) =
        sqlx::query_as("SELECT name, created_at FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    let exclude: Vec<_> = existing.iter().map(|k| k.key.cred_id().clone()).collect();
    let (options, reg_state) = webauthn
        .start_securitykey_registration(
            passkeys::user_handle(&user.user_id),
            &user.email,
            if name.is_empty() { &user.email } else { &name },
            (!exclude.is_empty()).then_some(exclude),
            None,
            None,
        )
        .map_err(|e| anyhow::anyhow!("webauthn registration start: {e:?}"))?;
    let registration_id = state.passkey_registrations.insert(
        PendingPasskeyRegistration {
            user_id: user.user_id.clone(),
            state: reg_state,
        },
        passkeys::CHALLENGE_TTL,
    );
    Ok(Json(json!({
        "registration_id": registration_id,
        "options": passkeys::options(&options)?,
    })))
}

#[derive(Deserialize)]
struct PasskeyRegisterFinish {
    registration_id: String,
    name: String,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

async fn passkey_register_finish(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<PasskeyRegisterFinish>,
) -> ApiResult<Json<Value>> {
    let name = passkeys::clean_name(&b.name)?;
    let webauthn = passkeys::relying_party(&state)?;
    let (_, pending) = state
        .passkey_registrations
        .take(&b.registration_id)
        .ok_or_else(|| ApiError::expired("security key setup expired, start again"))?;
    if pending.user_id != user.user_id {
        return Err(ApiError::reauth_required());
    }
    let key = webauthn
        .finish_securitykey_registration(&b.credential, &pending.state)
        .map_err(|e| {
            tracing::debug!(error = ?e, "security key registration rejected");
            ApiError::bad("the security key's response couldn't be verified; try again")
        })?;
    let mut tx = state.db.begin().await?;
    let id = passkeys::insert(&mut tx, &user.user_id, &name, &key).await?;
    let codes = first_recovery_codes(&mut tx, &user).await?;
    Event::new("account.security_key_added")
        .by(&user)
        .data(json!({ "key_id": id, "recovery_codes": codes.is_some() }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    two_step_changed(&state, &user, TwoStepChange::SecurityKeyAdded);
    Ok(Json(json!({ "id": id, "recovery_codes": codes })))
}

async fn passkey_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    let mut tx = state.db.begin().await?;
    if !passkeys::remove(&mut tx, &user.user_id, &id).await? {
        return Err(ApiError::NotFound);
    }
    policies::keep_last_method(&mut tx, &state, &user.user_id).await?;
    Event::new("account.security_key_removed")
        .by(&user)
        .data(json!({ "key_id": id }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    two_step_changed(&state, &user, TwoStepChange::SecurityKeyRemoved);
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- sessions

#[derive(Serialize, sqlx::FromRow)]
struct SessionRow {
    id: String,
    device_id: String,
    device_name: String,
    device_kind: String,
    /// The app that signed in (`X-PassAuth-Client`, e.g. `ios/0.6.0`), when it said.
    client: Option<String>,
    created_at: i64,
    last_used: i64,
}

async fn list_sessions(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT s.id, s.device_id, d.name AS device_name, d.kind AS device_kind, s.client, s.created_at, s.last_used
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
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() > 0 {
        Event::new("session.revoked")
            .by(&user)
            .data(json!({ "session": id }))
            .record(&mut tx, &state)
            .await?;
    }
    tx.commit().await?;
    if done.rows_affected() > 0 {
        state.notify_logout(&user.user_id, Sessions::Only(id));
    }
    Ok(Json(json!({ "ok": true })))
}

/// Sign out every other session of the account; this one stays.
async fn revoke_other_sessions(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
        .bind(&user.user_id)
        .bind(&user.session_id)
        .execute(&mut *tx)
        .await?;
    // Nor does a sign-in still on its way (an approved device, a two-step login).
    crate::auth_requests::cancel_open(&mut tx, &user.user_id).await?;
    Event::new("session.revoked_others")
        .by(&user)
        .data(json!({ "count": done.rows_affected() }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    state.forget_pending_sign_ins(&user.user_id);
    state.notify_logout(&user.user_id, Sessions::AllExcept(user.session_id));
    tracing::info!(user = %user.user_id, revoked = done.rows_affected(), "other sessions signed out");
    Ok(Json(json!({ "ok": true, "revoked": done.rows_affected() })))
}

/// Sign a device out and forget it: every session it holds ends at once (its
/// sockets are told), and its record goes with its "remember this device" token,
/// so its next sign-in asks for two-step login again and counts as a new device
/// (alert email). The caller's own device may be forgotten too.
async fn forget_device(
    State(state): State<AppState>,
    user: AuthUser,
    Path(device_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let sessions: Vec<String> = sqlx::query_scalar(
        "DELETE FROM sessions WHERE user_id = $1 AND device_id = $2 RETURNING id",
    )
    .bind(&user.user_id)
    .bind(&device_id)
    .fetch_all(&mut *tx)
    .await?;
    let device = sqlx::query("DELETE FROM devices WHERE user_id = $1 AND id = $2")
        .bind(&user.user_id)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;
    if sessions.is_empty() && device.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Event::new("session.device_forgotten")
        .by(&user)
        .data(json!({ "device": device_id, "count": sessions.len() }))
        .record(&mut tx, &state)
        .await?;
    tx.commit().await?;
    for id in &sessions {
        state.notify_logout(&user.user_id, Sessions::Only(id.clone()));
    }
    tracing::info!(user = %user.user_id, sessions = sessions.len(), "device forgotten");
    Ok(Json(json!({
        "ok": true,
        "signed_out": sessions.len(),
        "current": sessions.contains(&user.session_id),
    })))
}

// ---------------------------------------------------------------- deletion

async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    require_reauth(&state, &user, reauth_header(&headers))?;
    // Like the account's other events, kept without its address.
    let event = Event::new("account.deleted")
        .by(&user)
        .from(user.client.clone(), None);
    delete_user(&state, &user.user_id, event).await?;
    state.notify_logout(&user.user_id, Sessions::All);
    Ok(Json(json!({ "deleted": true })))
}

/// Remove a user, writing `event` in the same transaction (only when they
/// existed). Vaults they own are deleted with their items (and versions)
/// unless another owner remains (then only the membership goes); everyone who
/// shared a vault with them is told to re-sync, and so is everyone invited to a
/// vault deleted with them. Vaults they were a member of, or invited to, are
/// marked for a key replacement. Their Sends go with them, the attachment files of
/// the vaults deleted with them, their emergency access both ways (the personal
/// vaults of people who named them, wrapped for them, are marked for a key
/// replacement too) and their sign-in requests.
pub async fn delete_user(state: &AppState, user_id: &str, event: Event) -> ApiResult<()> {
    let mut vaults: Vec<String> = sqlx::query_scalar(
        "SELECT vault_id FROM vault_members WHERE user_id = $1 ORDER BY vault_id",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    // Their grantors' vaults whose keys they may have: locked and their owners told too.
    {
        let mut conn = state.db.acquire().await?;
        vaults.extend(crate::emergency::vaults_wrapped_for_contact(&mut conn, user_id).await?);
    }
    vaults.sort_unstable();
    vaults.dedup();
    let mut tx = state.db.begin().await?;
    // A write first (SQLite then never has to upgrade a read transaction).
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    // Like every vault write: lock the vaults (in id order) before changing them.
    for v in &vaults {
        crate::vault::lock_vault(&mut tx, v).await?;
    }
    // A vault wrapped for them after the read above: locked now, late but before the
    // accesses, and its owner told like the others.
    for v in crate::emergency::vaults_wrapped_for_contact(&mut tx, user_id).await? {
        if !vaults.contains(&v) {
            crate::vault::lock_vault(&mut tx, &v).await?;
            vaults.push(v);
        }
    }
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT m.vault_id FROM vault_members m WHERE m.user_id = $1 AND m.role = 'owner'
         AND NOT EXISTS (SELECT 1 FROM vault_members o WHERE o.vault_id = m.vault_id
                         AND o.role = 'owner' AND o.user_id <> $1)",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    // Everyone who shared a vault with them re-syncs, and the invitees of the
    // vaults that go with them lose their invitation.
    let postgres = crate::db::is_postgres(&state.config.database_url);
    let notices: Vec<(String, SyncNotice)> =
        crate::vault::bump_members(&mut tx, postgres, &vaults, &owned)
            .await?
            .into_iter()
            .filter(|(u, _)| u != user_id)
            .map(|(u, revision)| (u, SyncNotice::new(revision, None)))
            .collect();
    let mut files = Vec::new();
    for v in &owned {
        files.extend(crate::vault::detach_vault(&mut tx, v).await?);
        crate::emergency::forget_vault_keys(&mut tx, v).await?;
        for stmt in [
            "DELETE FROM items WHERE vault_id = $1",
            "DELETE FROM item_versions WHERE vault_id = $1",
            "DELETE FROM item_tombstones WHERE vault_id = $1",
            "DELETE FROM vault_members WHERE vault_id = $1",
            "DELETE FROM vaults WHERE id = $1",
        ] {
            sqlx::query(stmt).bind(v).execute(&mut *tx).await?;
        }
    }
    // Emergency access both ways; vaults wrapped for them as a contact get new keys,
    // and the owners of any not told above learn it too.
    let flagged = crate::emergency::end_accesses_of(&mut tx, user_id).await?;
    let unseen: Vec<String> = flagged
        .into_iter()
        .filter(|v| !vaults.contains(v))
        .collect();
    let mut notices = notices;
    notices.extend(
        crate::vault::bump_members(&mut tx, postgres, &unseen, &[])
            .await?
            .into_iter()
            .filter(|(u, _)| u != user_id)
            .map(|(u, revision)| (u, SyncNotice::new(revision, None))),
    );
    for stmt in [
        // Shared vaults that stay: the deleted user knew their keys.
        "UPDATE vaults SET rotation_pending = 1 WHERE id IN (SELECT vault_id FROM vault_members WHERE user_id = $1)",
        "DELETE FROM vault_members WHERE user_id = $1",
        "DELETE FROM devices WHERE user_id = $1",
        "DELETE FROM two_factor WHERE user_id = $1",
        "DELETE FROM passkey_credentials WHERE user_id = $1",
        "DELETE FROM two_factor_failures WHERE user_id = $1",
        "DELETE FROM email_tokens WHERE user_id = $1",
        "DELETE FROM sends WHERE user_id = $1",
        "DELETE FROM auth_requests WHERE user_id = $1",
    ] {
        sqlx::query(stmt).bind(user_id).execute(&mut *tx).await?;
    }
    // The account's own events stay in the log until `event_days` (vault members
    // and the admin page still see them), but without its addresses: those it acted
    // from, and those of attempts on it by nobody signed in (failed sign-ins). The
    // addresses of others who acted on it (a vault admin, the admin page) stay.
    sqlx::query(
        "UPDATE events SET ip = NULL WHERE ip IS NOT NULL
         AND (actor_id = $1 OR (target_user_id = $1 AND actor_id IS NULL AND type NOT LIKE 'admin.%'))",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    let gone = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if gone.rows_affected() > 0 {
        event.record(&mut tx, state).await?;
    }
    tx.commit().await?;
    state.forget_pending_sign_ins(user_id);
    crate::vault::remove_files(state, &files).await;
    state.notify_sync(notices);
    tracing::info!(user = %user_id, "account deleted");
    Ok(())
}
