//! Account policies the admin sets for the whole server (admin page, kept in
//! `settings.rs`). Apps read them before anyone signs in from `GET /api/config`
//! `policies`.
//!
//! Enforced by the server:
//! - `require_two_step`: a signed-in account without any two-step method gets 403
//!   `two_step_required` on every request except reading the account, setting a
//!   method up and signing out ([`TWO_STEP_SETUP`]), and can't turn off its last
//!   method while the policy is on.
//! - `require_secret_key`: new account keys (registration, master password or
//!   Secret Key change) must use a Secret Key (400 `secret_key_required`). The
//!   server sees only the bundle's plaintext `secret_key_enabled`; it can't check
//!   the derivation itself (zero knowledge), so the policy keeps honest apps from
//!   leaving the Secret Key out.
//! - `min_kdf_memory_mib` / `min_kdf_iterations`: new account keys below them get
//!   400 `kdf_too_weak`. They only raise the core's floors (which every client
//!   enforces anyway); at the floors they add nothing.
//!
//! Sign-in is never refused for older account keys: `GET /account` lists what an
//! account still has to change in `policy_violations` (`two_step`, `secret_key`,
//! `kdf`) so the apps can ask for it.
//!
//! Advisory (applied by the apps): `master_password_min_length`,
//! `max_vault_timeout_minutes` (0 = no limit) and `disable_export`.

use axum::extract::OriginalUri;
use axum::http::{Method, StatusCode, request::Parts};
use passauth_core::kdf::KdfParams;
use passauth_core::keys::AccountBundle;
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult, code};
use crate::settings::{Flag, KDF_FLOOR_ITERATIONS, KDF_FLOOR_MEMORY_MIB, Num};
use crate::state::AppState;
use crate::twofactor;

/// `GET /api/config` `policies`.
pub fn config_json(state: &AppState) -> Value {
    json!({
        "require_two_step": state.flag(Flag::RequireTwoStep),
        "require_secret_key": state.flag(Flag::RequireSecretKey),
        "min_kdf_memory_mib": state.num(Num::MinKdfMemoryMib),
        "min_kdf_iterations": state.num(Num::MinKdfIterations),
        "master_password_min_length": state.num(Num::MasterPasswordMinLength),
        "max_vault_timeout_minutes": state.num(Num::MaxVaultTimeoutMinutes),
        "disable_export": state.flag(Flag::DisableExport),
    })
}

/// Key derivation for new account keys: the apps' default (128 MiB, 3 passes),
/// raised to the admin's minimums. Returns (memory in KiB, passes).
pub fn new_account_kdf(state: &AppState) -> (u32, u32) {
    let memory_mib = state.num(Num::MinKdfMemoryMib).max(128);
    let iterations = state.num(Num::MinKdfIterations).max(3);
    (
        u32::try_from(memory_mib * 1024).unwrap_or(u32::MAX),
        u32::try_from(iterations).unwrap_or(u32::MAX),
    )
}

/// Whether `kdf` is below the admin's minimum key derivation.
pub fn kdf_too_weak(state: &AppState, kdf: &KdfParams) -> bool {
    let memory_mib = state.num(Num::MinKdfMemoryMib);
    let iterations = state.num(Num::MinKdfIterations);
    (memory_mib > KDF_FLOOR_MEMORY_MIB && i64::from(kdf.memory_kib) < memory_mib * 1024)
        || (iterations > KDF_FLOOR_ITERATIONS && i64::from(kdf.iterations) < iterations)
}

/// New account keys (registration, master password or Secret Key change) must
/// meet the policies.
pub fn check_new_keys(state: &AppState, bundle: &AccountBundle) -> ApiResult<()> {
    if state.flag(Flag::RequireSecretKey) && !bundle.secret_key_enabled {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            code::SECRET_KEY_REQUIRED,
            "this server requires a Secret Key: turn on \"Use a Secret Key\"",
        ));
    }
    if kdf_too_weak(state, &bundle.kdf) {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            code::KDF_TOO_WEAK,
            format!(
                "this server requires stronger key derivation: at least {} MiB of memory and {} passes",
                state.num(Num::MinKdfMemoryMib),
                state.num(Num::MinKdfIterations)
            ),
        ));
    }
    Ok(())
}

/// What an account still has to change to meet the policies (`GET /account`
/// `policy_violations`): `two_step` (no two-step method while one is required),
/// `secret_key`, `kdf`.
pub fn violations(
    state: &AppState,
    bundle: &AccountBundle,
    two_step_methods: usize,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if state.flag(Flag::RequireTwoStep) && two_step_methods == 0 {
        out.push("two_step");
    }
    if state.flag(Flag::RequireSecretKey) && !bundle.secret_key_enabled {
        out.push("secret_key");
    }
    if kdf_too_weak(state, &bundle.kdf) {
        out.push("kdf");
    }
    out
}

/// What an account without two-step login may still do while the server requires
/// it: read the account, set a method up (its recovery codes come with the first
/// one) and sign out. Re-authentication (`/auth/login/finish` with `purpose:
/// "reauth"`, before adding a security key) and token refresh don't need a session
/// check, so they keep working too. Everything else, the live-sync socket included,
/// answers 403 `two_step_required`.
const TWO_STEP_SETUP: &[(&str, &str)] = &[
    ("GET", "/api/account"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/account/2fa/totp/setup"),
    ("POST", "/api/account/2fa/totp/enable"),
    ("POST", "/api/account/2fa/email/setup"),
    ("POST", "/api/account/2fa/email/enable"),
    ("POST", "/api/account/2fa/passkey/register/start"),
    ("POST", "/api/account/2fa/passkey/register/finish"),
];

/// The request's full path, also inside nested routers (which strip their prefix).
pub fn request_path(parts: &Parts) -> &str {
    parts
        .extensions
        .get::<OriginalUri>()
        .map_or(parts.uri.path(), |u| u.0.path())
}

/// While the server requires two-step login, refuse a signed-in account without
/// a method everything but [`TWO_STEP_SETUP`].
pub async fn two_step_gate(
    state: &AppState,
    user_id: &str,
    method: &Method,
    path: &str,
) -> ApiResult<()> {
    if !state.flag(Flag::RequireTwoStep) {
        return Ok(());
    }
    if TWO_STEP_SETUP
        .iter()
        .any(|(m, p)| *m == method.as_str() && *p == path)
    {
        return Ok(());
    }
    if twofactor::enabled_providers(&state.db, user_id)
        .await?
        .is_empty()
    {
        return Err(two_step_required(
            "this server requires two-step login: turn it on in Settings → Two-step login",
        ));
    }
    Ok(())
}

/// 403 `two_step_required`.
pub fn two_step_required(message: &str) -> ApiError {
    ApiError::coded(StatusCode::FORBIDDEN, code::TWO_STEP_REQUIRED, message)
}

/// Turning off a two-step method left the account without any while the server
/// requires one (checked inside the caller's transaction, after the change).
pub async fn keep_last_method(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    user_id: &str,
) -> ApiResult<()> {
    if state.flag(Flag::RequireTwoStep)
        && twofactor::enabled_providers(&mut *conn, user_id)
            .await?
            .is_empty()
    {
        return Err(two_step_required(
            "this server requires two-step login: turn on another method before turning this one off",
        ));
    }
    Ok(())
}
