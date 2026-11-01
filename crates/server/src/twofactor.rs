//! Two-factor providers: TOTP, email codes, recovery codes.

use passauth_core::crypto::random_bytes;
use passauth_core::totp::Totp;
use serde::{Deserialize, Serialize};

use crate::db::{Db, now};
use crate::error::{ApiError, ApiResult};
use crate::state::{ct_eq, hash_token};

pub const TOTP: &str = "totp";
pub const EMAIL: &str = "email";
pub const RECOVERY: &str = "recovery";
const EMAIL_CODE_TTL: i64 = 10 * 60;
const EMAIL_CODE_ATTEMPTS: i64 = 5;

#[derive(Serialize, Deserialize)]
pub struct TotpData {
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct RecoveryData {
    pub hashes: Vec<String>,
}

/// Enabled interactive providers (recovery codes are implied when any exist).
pub async fn enabled_providers(db: &Db, user_id: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT provider FROM two_factor WHERE user_id = $1 AND enabled = 1 AND provider <> 'recovery' ORDER BY provider",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

/// Verify a code for `provider`, consuming it where applicable.
pub async fn verify(db: &Db, user_id: &str, provider: &str, code: &str) -> ApiResult<bool> {
    let code = code.trim().replace([' ', '-'], "");
    match provider {
        TOTP => verify_totp(db, user_id, &code).await,
        EMAIL => verify_email_code(db, user_id, "2fa", &code).await,
        RECOVERY => verify_recovery(db, user_id, &code).await,
        _ => Err(ApiError::bad("unknown two-factor provider")),
    }
}

async fn verify_totp(db: &Db, user_id: &str, code: &str) -> ApiResult<bool> {
    let Some((data, last_used)): Option<(String, i64)> = sqlx::query_as(
        "SELECT data, last_used FROM two_factor WHERE user_id = $1 AND provider = 'totp' AND enabled = 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    else {
        return Ok(false);
    };
    let data: TotpData = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
    let Some(step) = check_totp(&data.secret, code, last_used) else {
        return Ok(false);
    };
    sqlx::query("UPDATE two_factor SET last_used = $1 WHERE user_id = $2 AND provider = 'totp'")
        .bind(step)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(true)
}

/// Accept the current step ±1, rejecting any step at or before `last_step`
/// (replay protection). Returns the matched step.
pub fn check_totp(secret: &str, code: &str, last_step: i64) -> Option<i64> {
    let totp = Totp::parse(secret).ok()?;
    let t = now() as u64;
    let period = totp.period;
    for drift in [0i64, -1, 1] {
        let at = (t as i64 + drift * period as i64).max(0) as u64;
        let step = (at / period) as i64;
        if step > last_step && ct_eq(&totp.generate(at), code) {
            return Some(step);
        }
    }
    None
}

pub fn new_totp_secret() -> String {
    data_encoding_base32(&random_bytes::<20>().expect("rng"))
}

fn data_encoding_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Create a 6-digit code for `purpose`, replacing any previous one.
pub async fn issue_email_code(db: &Db, user_id: &str, purpose: &str) -> ApiResult<String> {
    let n = u32::from_le_bytes(random_bytes::<4>()?) % 1_000_000;
    let code = format!("{n:06}");
    sqlx::query("DELETE FROM email_tokens WHERE user_id = $1 AND purpose = $2")
        .bind(user_id)
        .bind(purpose)
        .execute(db)
        .await?;
    sqlx::query(
        "INSERT INTO email_tokens (id, user_id, purpose, token_hash, attempts, expires_at) VALUES ($1, $2, $3, $4, 0, $5)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(purpose)
    .bind(hash_token(&code))
    .bind(now() + EMAIL_CODE_TTL)
    .execute(db)
    .await?;
    Ok(code)
}

pub async fn verify_email_code(
    db: &Db,
    user_id: &str,
    purpose: &str,
    code: &str,
) -> ApiResult<bool> {
    let row: Option<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, token_hash, attempts, expires_at FROM email_tokens WHERE user_id = $1 AND purpose = $2",
    )
    .bind(user_id)
    .bind(purpose)
    .fetch_optional(db)
    .await?;
    let Some((id, hash, attempts, expires)) = row else {
        return Ok(false);
    };
    if expires < now() || attempts >= EMAIL_CODE_ATTEMPTS {
        sqlx::query("DELETE FROM email_tokens WHERE id = $1")
            .bind(&id)
            .execute(db)
            .await?;
        return Ok(false);
    }
    if ct_eq(&hash, &hash_token(code)) {
        sqlx::query("DELETE FROM email_tokens WHERE id = $1")
            .bind(&id)
            .execute(db)
            .await?;
        return Ok(true);
    }
    sqlx::query("UPDATE email_tokens SET attempts = attempts + 1 WHERE id = $1")
        .bind(&id)
        .execute(db)
        .await?;
    Ok(false)
}

async fn verify_recovery(db: &Db, user_id: &str, code: &str) -> ApiResult<bool> {
    let Some(data): Option<String> = sqlx::query_scalar(
        "SELECT data FROM two_factor WHERE user_id = $1 AND provider = 'recovery'",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    else {
        return Ok(false);
    };
    let mut data: RecoveryData = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
    let h = hash_token(&code.to_ascii_uppercase());
    let Some(pos) = data.hashes.iter().position(|x| ct_eq(x, &h)) else {
        return Ok(false);
    };
    data.hashes.remove(pos);
    sqlx::query("UPDATE two_factor SET data = $1, last_used = $2 WHERE user_id = $3 AND provider = 'recovery'")
        .bind(serde_json::to_string(&data).map_err(anyhow::Error::from)?)
        .bind(now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(true)
}

/// Generate 10 fresh recovery codes, replacing any existing set.
pub async fn regenerate_recovery_codes(db: &Db, user_id: &str) -> ApiResult<Vec<String>> {
    let codes: Vec<String> = (0..10)
        .map(|_| {
            let raw = data_encoding_base32(&random_bytes::<6>().expect("rng"));
            format!("{}-{}", &raw[..5], &raw[5..10])
        })
        .collect();
    let data = RecoveryData {
        hashes: codes
            .iter()
            .map(|c| hash_token(&c.replace('-', "")))
            .collect(),
    };
    upsert(
        db,
        user_id,
        RECOVERY,
        &serde_json::to_string(&data).map_err(anyhow::Error::from)?,
        true,
    )
    .await?;
    Ok(codes)
}

pub async fn upsert(
    db: &Db,
    user_id: &str,
    provider: &str,
    data: &str,
    enabled: bool,
) -> ApiResult<()> {
    sqlx::query("DELETE FROM two_factor WHERE user_id = $1 AND provider = $2")
        .bind(user_id)
        .bind(provider)
        .execute(db)
        .await?;
    sqlx::query("INSERT INTO two_factor (user_id, provider, data, enabled, last_used) VALUES ($1, $2, $3, $4, 0)")
        .bind(user_id)
        .bind(provider)
        .bind(data)
        .bind(enabled as i64)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_replay_rejected() {
        let secret = new_totp_secret();
        let t = Totp::parse(&secret).unwrap();
        let code = t.generate(now() as u64);
        let step = check_totp(&secret, &code, 0).unwrap();
        assert!(check_totp(&secret, &code, step).is_none());
        assert!(check_totp(&secret, "000000x", 0).is_none());
    }

    #[test]
    fn base32_secret_parses() {
        let s = new_totp_secret();
        assert_eq!(s.len(), 32);
        assert!(Totp::parse(&s).is_ok());
    }
}
