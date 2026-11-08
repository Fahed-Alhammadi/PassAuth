//! Security keys / passkeys (WebAuthn) as a two-step login method.
//!
//! The relying party is the server's `DOMAIN`: RP ID = its host, allowed
//! origin = the URL itself, so behind a reverse proxy `DOMAIN` must be the
//! public https address. Credentials are webauthn-rs `SecurityKey`s (second
//! factor: user verification preferred, no resident key, no attestation
//! check) stored as JSON in `passkey_credentials`. Registration and
//! authentication state live in memory for a few minutes, like email codes.

use passauth_core::item::b64;
use serde_json::Value;
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;

use crate::db::{Db, now};
use crate::error::{ApiError, ApiResult};
use crate::twofactor;

/// Registration and sign-in challenges stay valid this long.
pub const CHALLENGE_TTL: i64 = 5 * 60;
pub const MAX_PER_USER: i64 = 10;

/// Build the relying party from `DOMAIN`.
pub fn build(domain: &str) -> anyhow::Result<Webauthn> {
    let origin = Url::parse(domain).map_err(|e| anyhow::anyhow!("DOMAIN {domain:?}: {e}"))?;
    let rp_id = origin
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("DOMAIN {domain:?} has no host"))?
        .to_owned();
    WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|e| {
            anyhow::anyhow!("DOMAIN {domain:?} is not usable as a WebAuthn origin: {e:?}")
        })?
        .rp_name("PassAuth")
        .build()
        .map_err(|e| anyhow::anyhow!("WebAuthn setup: {e:?}"))
}

/// The relying party, or the error to show when `DOMAIN` can't serve one.
pub fn relying_party(state: &crate::state::App) -> ApiResult<&Webauthn> {
    state.webauthn.as_ref().ok_or_else(|| {
        ApiError::bad(
            "security keys need the server's DOMAIN setting to be the full public address of this server (for example https://vault.example.com); ask your PassAuth administrator",
        )
    })
}

/// WebAuthn user handle: our user ids are UUIDs; anything else is hashed into one.
pub fn user_handle(user_id: &str) -> Uuid {
    Uuid::parse_str(user_id).unwrap_or_else(|_| {
        let digest = Sha256::digest(user_id.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    })
}

pub struct Stored {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub key: SecurityKey,
}

pub async fn list(db: &Db, user_id: &str) -> ApiResult<Vec<Stored>> {
    let rows: Vec<(String, String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, name, credential, created_at, last_used_at FROM passkey_credentials WHERE user_id = $1 ORDER BY created_at, id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|(id, name, credential, created_at, last_used_at)| {
            Ok(Stored {
                id,
                name,
                created_at,
                last_used_at,
                key: serde_json::from_str(&credential).map_err(anyhow::Error::from)?,
            })
        })
        .collect()
}

/// What `GET /account` shows.
pub fn summary(keys: &[Stored]) -> Vec<Value> {
    keys.iter()
        .map(|k| {
            serde_json::json!({
                "id": k.id,
                "name": k.name,
                "created_at": k.created_at,
                "last_used_at": k.last_used_at,
            })
        })
        .collect()
}

pub fn credential_id(key: &SecurityKey) -> String {
    b64(key.cred_id())
}

/// Store a new credential and mark the method enabled (`two_factor` row).
/// Fails with 409 when the same authenticator is already registered.
pub async fn insert(db: &Db, user_id: &str, name: &str, key: &SecurityKey) -> ApiResult<String> {
    let id = credential_id(key);
    let credential = serde_json::to_string(key).map_err(anyhow::Error::from)?;
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO passkey_credentials (id, user_id, name, credential, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, NULL)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(&credential)
    .bind(now())
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::conflict_on_unique(e, "this security key is already registered"))?;
    sqlx::query(
        "INSERT INTO two_factor (user_id, provider, data, enabled, last_used) VALUES ($1, $2, '{}', 1, 0)
         ON CONFLICT (user_id, provider) DO UPDATE SET enabled = 1",
    )
    .bind(user_id)
    .bind(twofactor::PASSKEY)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Remove one credential. When it was the last, the method is turned off, and
/// when no other method remains the recovery codes go too (as `DELETE /2fa/{provider}`).
pub async fn remove(db: &Db, user_id: &str, id: &str) -> ApiResult<bool> {
    let done = sqlx::query("DELETE FROM passkey_credentials WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    if done.rows_affected() == 0 {
        return Ok(false);
    }
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM passkey_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(db)
            .await?;
    if left == 0 {
        sqlx::query("DELETE FROM two_factor WHERE user_id = $1 AND provider = $2")
            .bind(user_id)
            .bind(twofactor::PASSKEY)
            .execute(db)
            .await?;
        if twofactor::enabled_providers(db, user_id).await?.is_empty() {
            sqlx::query("DELETE FROM two_factor WHERE user_id = $1")
                .bind(user_id)
                .execute(db)
                .await?;
        }
    }
    Ok(true)
}

/// After a successful assertion: persist the counter / backup flags and the use time.
pub async fn record_use(
    db: &Db,
    user_id: &str,
    keys: &mut [Stored],
    result: &AuthenticationResult,
) -> ApiResult<()> {
    for k in keys.iter_mut() {
        if k.key.update_credential(result).is_some() {
            sqlx::query(
                "UPDATE passkey_credentials SET credential = $1, last_used_at = $2 WHERE user_id = $3 AND id = $4",
            )
            .bind(serde_json::to_string(&k.key).map_err(anyhow::Error::from)?)
            .bind(now())
            .bind(user_id)
            .bind(&k.id)
            .execute(db)
            .await?;
        }
    }
    Ok(())
}

/// Options for the browser. Two things webauthn-rs adds for security keys are
/// dropped: the `hints` (platform passkeys such as Touch ID, Windows Hello or a
/// phone are welcome too) and the `credProtect` extension, which browsers
/// refuse next to `userVerification: preferred` ("protection policy is
/// inconsistent"); it was opportunistic anyway (`enforce…: false`), so the
/// server verifies the response the same without it.
pub fn options<T: serde::Serialize>(challenge: &T) -> ApiResult<Value> {
    let mut v = serde_json::to_value(challenge).map_err(anyhow::Error::from)?;
    if let Some(pk) = v.get_mut("publicKey").and_then(Value::as_object_mut) {
        pk.remove("hints");
        if let Some(ext) = pk.get_mut("extensions").and_then(Value::as_object_mut) {
            ext.remove("credentialProtectionPolicy");
            ext.remove("enforceCredentialProtectionPolicy");
        }
    }
    Ok(v)
}

/// A credential name as typed by the user.
pub fn clean_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::bad("give the security key a name"));
    }
    if name.chars().count() > 60 {
        return Err(ApiError::bad("name too long"));
    }
    Ok(name.to_owned())
}
