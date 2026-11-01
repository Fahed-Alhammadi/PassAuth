//! Registration, OPAQUE login, two-factor, sessions.
//!
//! Login never reveals whether an email exists: unknown emails get a
//! deterministic fake prelogin answer and the OPAQUE exchange runs against a
//! fake record, failing only at the final step like a wrong password.

use axum::extract::{FromRequestParts, State};
use axum::http::{HeaderMap, request::Parts};
use axum::routing::post;
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

use crate::db::{now, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::mail::Email;
use crate::state::{
    AppState, DeviceInfo, PendingLogin, PendingRegistration, PendingTwoFactor, ct_eq, hash_token,
    normalize_email, random_token,
};
use crate::twofactor;

pub const ACCESS_TTL: i64 = 15 * 60;
pub const REFRESH_TTL: i64 = 30 * 24 * 3600;
const REMEMBER_TTL: i64 = 30 * 24 * 3600;

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
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/verify-email", post(verify_email))
        .route("/verify-email/resend", post(resend_verification))
}

// ---------------------------------------------------------------- extractor

/// An authenticated request (valid, unexpired access token).
pub struct AuthUser {
    pub user_id: String,
    pub session_id: String,
    pub email: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = bearer(&parts.headers)
            .or_else(|| {
                // WebSocket clients cannot set headers; accept ?access_token=.
                parts
                    .uri
                    .query()?
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("access_token="))
                    .map(str::to_owned)
            })
            .ok_or(ApiError::Unauthorized)?;
        authenticate(state, &token).await
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

pub fn client_ip(state: &AppState, headers: &HeaderMap) -> String {
    state
        .config
        .ip_header
        .as_deref()
        .and_then(|h| headers.get(h))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|| "direct".into())
}

fn limit(state: &AppState, key: String, n: u32, window: i64) -> ApiResult<()> {
    if state.limiter.check(&key, n, window) {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests)
    }
}

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
    limit(
        &state,
        format!("prelogin:{}", client_ip(&state, &headers)),
        60,
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

fn keyed(state: &AppState, label: &str, email: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(state.prelogin_secret);
    h.update(label.as_bytes());
    h.update(email.as_bytes());
    h.finalize().into()
}

fn fake_prelogin(state: &AppState, email: &str) -> Prelogin {
    let id: [u8; 16] = keyed(state, "id", email)[..16]
        .try_into()
        .expect("16 bytes");
    let salt = &keyed(state, "salt", email)[..16];
    Prelogin {
        account_id: uuid::Builder::from_random_bytes(id).into_uuid().to_string(),
        kdf: KdfParams {
            memory_kib: 128 * 1024,
            iterations: 3,
            parallelism: 1,
            salt: b64(salt),
        },
        secret_key_required: false,
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
    if !invited && !state.config.signup_permitted(&email) {
        return Err(ApiError::Forbidden(
            "registration is closed on this server".into(),
        ));
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&state.db)
        .await?;
    if exists > 0 {
        return Err(ApiError::Conflict(
            "an account with this email already exists".into(),
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
        .ok_or(ApiError::bad("registration expired"))?;
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
    Json(b): Json<RegisterFinish>,
) -> ApiResult<Json<Value>> {
    let (_, pending) = state
        .registrations
        .take(&b.registration_id)
        .ok_or(ApiError::bad("registration expired"))?;
    if b.bundle.account_id != pending.account_id {
        return Err(ApiError::bad("bundle does not match registration"));
    }
    b.bundle.kdf.validate()?;
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
    .bind(b.name.trim())
    .bind(verified as i64)
    .bind(&record)
    .bind(serde_json::to_string(&b.bundle).map_err(anyhow::Error::from)?)
    .bind(&b.bundle.public_key)
    .bind(now_ms())
    .bind(t)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::Conflict("an account with this email already exists".into()))?;
    crate::vault::insert_vault(&mut tx, &pending.account_id, &b.vault, "owner", "account").await?;
    sqlx::query("DELETE FROM invites WHERE email = $1")
        .bind(&pending.email)
        .execute(&mut *tx)
        .await?;
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
            action: Some(("Verify email".into(), format!("{}/#/verify-email?token={token}", state.config.domain))),
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
    let user_id = user_id.ok_or(ApiError::bad("invalid or expired link"))?;
    sqlx::query("UPDATE users SET email_verified = 1, updated_at = $1 WHERE id = $2")
        .bind(now())
        .bind(&user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM email_tokens WHERE user_id = $1 AND purpose = 'verify'")
        .bind(&user_id)
        .execute(&state.db)
        .await?;
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
        30,
        60,
    )?;
    limit(&state, format!("login-email:{email}"), 10, 300)?;
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
        .ok_or(ApiError::bad("login expired, try again"))?;
    let server_login = ServerLogin::<Suite>::deserialize(&pending.state)
        .map_err(|_| anyhow::anyhow!("corrupt login state"))?;
    let fin = CredentialFinalization::<Suite>::deserialize(&unb64(&b.message)?)
        .map_err(|_| ApiError::InvalidCredentials)?;
    let ok = server_login
        .finish(fin, ServerLoginParameters::default())
        .is_ok();
    let user_id = match (ok, pending.user_id) {
        (true, Some(id)) => id,
        _ => return Err(ApiError::InvalidCredentials),
    };

    if b.purpose.as_deref() == Some("reauth") {
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
        return Err(ApiError::Forbidden("this account is disabled".into()));
    }
    if verified == 0 && state.config.signups_verify {
        return Err(ApiError::Forbidden("email_not_verified".into()));
    }

    let device = DeviceInfo {
        id: b.device.id,
        name: b.device.name,
        kind: b.device.kind,
    };
    let providers = twofactor::enabled_providers(&state.db, &user_id).await?;
    let remembered = match &b.remember_token {
        Some(t) => device_remembered(&state, &user_id, &device.id, t).await?,
        None => false,
    };
    if !providers.is_empty() && !remembered {
        let token = state.two_factor.insert(
            PendingTwoFactor {
                user_id,
                device,
                attempts: 0,
            },
            5 * 60,
        );
        let mut all = providers;
        all.push(twofactor::RECOVERY.into());
        return Ok(Json(
            json!({ "two_factor_required": true, "two_factor_token": token, "providers": all }),
        ));
    }
    Ok(Json(issue_session(&state, &user_id, &device, None).await?))
}

async fn device_remembered(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    token: &str,
) -> ApiResult<bool> {
    let hash: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT remember_hash, remember_expires FROM devices WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(matches!(hash, Some((Some(h), Some(exp))) if exp > now() && ct_eq(&h, &hash_token(token))))
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
    Json(b): Json<TwoFactorVerify>,
) -> ApiResult<Json<Value>> {
    let (exp, mut pending) = state
        .two_factor
        .take(&b.two_factor_token)
        .ok_or(ApiError::bad("sign-in expired, start again"))?;
    if !twofactor::verify(&state.db, &pending.user_id, &b.provider, &b.code).await? {
        pending.attempts += 1;
        if pending.attempts < 5 {
            state.two_factor.put_back(b.two_factor_token, pending, exp);
        }
        return Err(ApiError::bad("invalid two-factor code"));
    }
    let remember = b.remember.then(random_token);
    Ok(Json(
        issue_session(&state, &pending.user_id, &pending.device, remember).await?,
    ))
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
        .ok_or(ApiError::bad("sign-in expired, start again"))?;
    limit(&state, format!("2fa-email:{}", pending.user_id), 5, 600)?;
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

/// Create a session for `device`, alerting the user by email on new devices.
async fn issue_session(
    state: &AppState,
    user_id: &str,
    device: &DeviceInfo,
    remember: Option<String>,
) -> ApiResult<Value> {
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
    if known == 0 {
        sqlx::query("INSERT INTO devices (user_id, id, name, kind, created_at, last_seen) VALUES ($1, $2, $3, $4, $5, $5)")
            .bind(user_id)
            .bind(&device.id)
            .bind(&device.name)
            .bind(&device.kind)
            .bind(t)
            .execute(&state.db)
            .await?;
    } else {
        sqlx::query("UPDATE devices SET name = $1, last_seen = $2 WHERE user_id = $3 AND id = $4")
            .bind(&device.name)
            .bind(t)
            .bind(user_id)
            .bind(&device.id)
            .execute(&state.db)
            .await?;
    }
    if let Some(r) = &remember {
        sqlx::query("UPDATE devices SET remember_hash = $1, remember_expires = $2 WHERE user_id = $3 AND id = $4")
            .bind(hash_token(r))
            .bind(t + REMEMBER_TTL)
            .bind(user_id)
            .bind(&device.id)
            .execute(&state.db)
            .await?;
    }

    let (access, refresh) = (random_token(), random_token());
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, access_hash, access_expires, refresh_hash, refresh_expires, created_at, last_used)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(&device.id)
    .bind(hash_token(&access))
    .bind(t + ACCESS_TTL)
    .bind(hash_token(&refresh))
    .bind(t + REFRESH_TTL)
    .bind(t)
    .execute(&state.db)
    .await?;

    let (email, bundle): (String, String) =
        sqlx::query_as("SELECT email, bundle FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    if known == 0 && has_devices > 0 {
        state.mailer.send_later(
            email.clone(),
            Email {
                subject: "New sign-in to your PassAuth account".into(),
                heading: "New device signed in".into(),
                body: format!(
                    "Your account was just accessed from a new device: {} ({}).\nIf this wasn't you, change your master password and review your sessions.",
                    device.name, device.kind
                ),
                action: Some(("Review sessions".into(), format!("{}/#/settings/security", state.config.domain))),
                code: None,
            },
        );
    }
    Ok(json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": ACCESS_TTL,
        "remember_token": remember,
        "user_id": user_id,
        "email": email,
        "bundle": serde_json::from_str::<Value>(&bundle).map_err(anyhow::Error::from)?,
    }))
}

// ---------------------------------------------------------------- sessions

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

/// Rotate the refresh token. Presenting an already-rotated token means it
/// leaked: the whole session is revoked.
async fn refresh(
    State(state): State<AppState>,
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
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&id)
            .execute(&state.db)
            .await?;
        tracing::warn!(user = %user_id, "refresh token reuse detected; session revoked");
        return Err(ApiError::Unauthorized);
    }
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT s.id, s.user_id FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.refresh_hash = $1 AND s.refresh_expires > $2 AND u.disabled = 0",
    )
    .bind(&h)
    .bind(t)
    .fetch_optional(&state.db)
    .await?;
    let (id, _) = row.ok_or(ApiError::Unauthorized)?;
    let (access, refresh) = (random_token(), random_token());
    sqlx::query(
        "UPDATE sessions SET access_hash = $1, access_expires = $2, prev_refresh_hash = refresh_hash,
         refresh_hash = $3, refresh_expires = $4, last_used = $5 WHERE id = $6",
    )
    .bind(hash_token(&access))
    .bind(t + ACCESS_TTL)
    .bind(hash_token(&refresh))
    .bind(t + REFRESH_TTL)
    .bind(t)
    .bind(&id)
    .execute(&state.db)
    .await?;
    Ok(Json(
        json!({ "access_token": access, "refresh_token": refresh, "expires_in": ACCESS_TTL }),
    ))
}

async fn logout(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&user.session_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// Consume a reauth token issued by `login/finish` with `purpose: "reauth"`.
pub fn require_reauth(state: &AppState, user: &AuthUser, token: Option<&str>) -> ApiResult<()> {
    let token = token.ok_or(ApiError::Forbidden("reauth_required".into()))?;
    match state.reauth.take(token) {
        Some((_, uid)) if uid == user.user_id => Ok(()),
        _ => Err(ApiError::Forbidden("reauth_required".into())),
    }
}
