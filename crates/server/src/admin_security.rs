//! Admin page protection on top of the user name and password: two-step login with
//! an authenticator app (plus recovery codes), set up on the admin page, and the
//! optional network limit `PASSAUTH_ADMIN_ALLOWED_NETWORKS`.
//!
//! The state is one `server_settings` row (`admin_2fa`) read on every check, so
//! `passauth-server reset-admin-2fa` takes effect on a running server.

use std::net::IpAddr;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::account::urlencode;
use crate::admin::Admin;
use crate::auth::{client_addr, client_ip};
use crate::config::IpNet;
use crate::db::{self, Db, now};
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, ct_eq, hash_token};
use crate::twofactor::{check_totp, new_recovery_codes, new_totp_secret};

pub const SETTING: &str = "admin_2fa";
/// How long a started setup waits for its first code.
const SETUP_TTL: i64 = 10 * 60;

#[derive(Serialize, Deserialize)]
struct Admin2fa {
    /// Base32 authenticator secret.
    secret: String,
    /// Last code step used (each code works once).
    last_step: i64,
    /// SHA-256 of the unused recovery codes.
    recovery: Vec<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/2fa", get(status))
        .route("/2fa/setup", post(setup))
        .route("/2fa/enable", post(enable))
        .route("/2fa/disable", post(disable))
        .route("/2fa/recovery-codes", post(new_codes))
}

// ------------------------------------------------------------------ network

/// Whether `ip` may use the admin page; `nets` = `None` allows everyone.
pub fn network_allows(nets: Option<&[IpNet]>, ip: Option<IpAddr>) -> bool {
    match nets {
        None => true,
        Some(nets) => ip.is_some_and(|ip| nets.iter().any(|n| n.contains(ip))),
    }
}

/// Refuse visitors outside `PASSAUTH_ADMIN_ALLOWED_NETWORKS`.
pub fn check_network(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let ip = client_addr(state, headers);
    if network_allows(state.config.admin_networks.as_deref(), ip) {
        return Ok(());
    }
    tracing::info!(
        ?ip,
        "admin page refused: address outside PASSAUTH_ADMIN_ALLOWED_NETWORKS"
    );
    Err(ApiError::Forbidden(
        "The admin page can only be opened from the networks set in PASSAUTH_ADMIN_ALLOWED_NETWORKS".into(),
    ))
}

// ------------------------------------------------------------ two-step login

async fn load(db: &Db) -> ApiResult<Option<(String, Admin2fa)>> {
    let Some(raw) = db::setting(db, SETTING).await? else {
        return Ok(None);
    };
    let data = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
    Ok(Some((raw, data)))
}

pub async fn enabled(db: &Db) -> ApiResult<bool> {
    Ok(db::setting(db, SETTING).await?.is_some())
}

/// Check an authenticator code or a recovery code and use it up. False when it is
/// wrong, already used, or two-step login is off.
pub async fn check_code(db: &Db, code: &str) -> ApiResult<bool> {
    let Some((raw, mut data)) = load(db).await? else {
        return Ok(false);
    };
    let code = code.trim().replace([' ', '-'], "");
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        let Some(step) = check_totp(&data.secret, &code, data.last_step) else {
            return Ok(false);
        };
        data.last_step = step;
    } else {
        let h = hash_token(&code.to_ascii_uppercase());
        let Some(pos) = data.recovery.iter().position(|x| ct_eq(x, &h)) else {
            return Ok(false);
        };
        data.recovery.remove(pos);
        tracing::warn!(left = data.recovery.len(), "admin recovery code used");
    }
    let new = serde_json::to_string(&data).map_err(anyhow::Error::from)?;
    // Only if nobody used a code in between, so one code can't sign in twice.
    Ok(db::swap_setting(db, SETTING, &raw, &new).await?)
}

/// Wrong codes on these endpoints are limited per address like the sign-in.
fn limit(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if state
        .limiter
        .check(&format!("admin2fa:{}", client_ip(state, headers)), 10, 60)
    {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests)
    }
}

const WRONG_CODE: &str =
    "That code isn't right. Enter the newest code from your authenticator app, or a recovery code.";

async fn status(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    let data = load(&state.db).await?;
    Ok(Json(json!({
        "enabled": data.is_some(),
        "recovery_codes_left": data.map_or(0, |(_, d)| d.recovery.len()),
    })))
}

/// Start setup: a new secret, kept in memory until the first code confirms it.
async fn setup(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Value>> {
    if enabled(&state.db).await? {
        return Err(ApiError::Conflict("two-step login is already on".into()));
    }
    let secret = new_totp_secret();
    *state.admin_2fa_setup.lock().expect("admin 2fa setup lock") =
        Some((secret.clone(), now() + SETUP_TTL));
    let host = url::Url::parse(&state.config.domain)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "server".into());
    let label = urlencode(&format!("PassAuth admin:{host}"));
    let issuer = urlencode("PassAuth admin");
    Ok(Json(json!({
        "secret": secret,
        "uri": format!("otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"),
    })))
}

#[derive(Deserialize)]
struct CodeBody {
    code: String,
}

/// Confirm setup with the first code; returns the recovery codes (shown once).
async fn enable(
    State(state): State<AppState>,
    _: Admin,
    headers: HeaderMap,
    Json(b): Json<CodeBody>,
) -> ApiResult<Json<Value>> {
    limit(&state, &headers)?;
    let pending = state
        .admin_2fa_setup
        .lock()
        .expect("admin 2fa setup lock")
        .clone()
        .filter(|(_, expires)| *expires > now());
    let Some((secret, _)) = pending else {
        return Err(ApiError::bad("the setup has expired. Start it again"));
    };
    let code = b.code.trim().replace(' ', "");
    let Some(step) = check_totp(&secret, &code, -1) else {
        return Err(ApiError::bad(
            "that code isn't right. Check that the time on your phone is correct and enter the newest code",
        ));
    };
    if enabled(&state.db).await? {
        return Err(ApiError::Conflict("two-step login is already on".into()));
    }
    let (codes, hashes) = new_recovery_codes();
    let data = Admin2fa {
        secret,
        last_step: step,
        recovery: hashes,
    };
    let json = serde_json::to_string(&data).map_err(anyhow::Error::from)?;
    db::set_setting(&state.db, SETTING, &json).await?;
    *state.admin_2fa_setup.lock().expect("admin 2fa setup lock") = None;
    tracing::warn!(ip = %client_ip(&state, &headers), "admin two-step login turned on");
    Ok(Json(json!({ "recovery_codes": codes })))
}

async fn disable(
    State(state): State<AppState>,
    _: Admin,
    headers: HeaderMap,
    Json(b): Json<CodeBody>,
) -> ApiResult<Json<Value>> {
    limit(&state, &headers)?;
    if !check_code(&state.db, &b.code).await? {
        return Err(ApiError::bad(WRONG_CODE));
    }
    db::delete_setting(&state.db, SETTING).await?;
    tracing::warn!(ip = %client_ip(&state, &headers), "admin two-step login turned off");
    Ok(Json(json!({ "enabled": false })))
}

/// Replace the recovery codes (the old ones stop working).
async fn new_codes(
    State(state): State<AppState>,
    _: Admin,
    headers: HeaderMap,
    Json(b): Json<CodeBody>,
) -> ApiResult<Json<Value>> {
    limit(&state, &headers)?;
    if !check_code(&state.db, &b.code).await? {
        return Err(ApiError::bad(WRONG_CODE));
    }
    let Some((raw, mut data)) = load(&state.db).await? else {
        return Err(ApiError::Conflict("two-step login is off".into()));
    };
    let (codes, hashes) = new_recovery_codes();
    data.recovery = hashes;
    let new = serde_json::to_string(&data).map_err(anyhow::Error::from)?;
    if !db::swap_setting(&state.db, SETTING, &raw, &new).await? {
        return Err(ApiError::Conflict("try again".into()));
    }
    tracing::info!("admin recovery codes replaced");
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_limit_the_admin_page() {
        let lan = [
            IpNet::parse("192.168.1.0/24").unwrap(),
            IpNet::parse("fd00::/8").unwrap(),
        ];
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert!(network_allows(None, None));
        assert!(network_allows(None, ip("203.0.113.9")));
        assert!(network_allows(Some(&lan), ip("192.168.1.20")));
        assert!(network_allows(Some(&lan), ip("::ffff:192.168.1.20")));
        assert!(network_allows(Some(&lan), ip("fd12::1")));
        assert!(!network_allows(Some(&lan), ip("192.168.2.1")));
        assert!(
            !network_allows(Some(&lan), None),
            "unknown address is refused"
        );
    }
}
