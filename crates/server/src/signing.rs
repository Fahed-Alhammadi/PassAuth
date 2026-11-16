//! Signed sharing, the account side (docs/ARCHITECTURE.md "Signed sharing"):
//! each account's signing identity, uploaded once by its apps (`PUT
//! /account/identity`), and its key pins, a list of other users' identities its
//! apps have seen, sealed with the account key (`GET`/`PUT /account/key-pins`,
//! compare-and-swap on `seq`). The vault side (share signatures, member rosters,
//! re-signing) is `vault/signed.rs`.
//!
//! The server checks what it can: an identity signature against the account's own
//! X25519 key, and (vault side) share and roster signatures against the signer's
//! stored identity, so garbage never gets stored. It can't vouch for anything: the
//! apps verify every signature themselves against the identities they pinned.

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::put;
use axum::{Json, Router};
use passauth_core::item::unb64;
use passauth_core::sharing::{IdentityRecord, PublicIdentity};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use crate::auth::AuthUser;
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::state::{AppState, Class, SyncNotice};

/// Largest sealed key pins accepted (base64url): the core seals at most 190 KiB of
/// JSON. Below the request size limit.
const MAX_KEY_PINS: usize = 256 * 1024;
/// Key pin writes per user per hour.
const KEY_PINS_PER_HOUR: u32 = 120;
/// Identity uploads per user per hour (set once; retries and refusals count).
const IDENTITIES_PER_HOUR: u32 = 10;
/// Base64url lengths: a 32-byte key, a 64-byte signature, and the wrapped seed (a
/// 1-byte version, 24-byte nonce, 32-byte seed and 16-byte tag: 73 bytes).
const KEY_B64: usize = 43;
const SIGNATURE_B64: usize = 86;
const WRAPPED_SEED_B64: usize = 98;

/// Routes under `/account`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/identity", put(put_identity)).route(
        "/key-pins",
        put(put_key_pins)
            .get(get_key_pins)
            .layer(DefaultBodyLimit::max(MAX_KEY_PINS + 1024)),
    )
}

/// 400 `bad_signature`.
pub(crate) fn bad_signature(what: &str) -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        code::BAD_SIGNATURE,
        format!("the {what} signature doesn't verify"),
    )
}

/// 400 `signing_identity_required`.
pub(crate) fn signing_identity_required() -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        code::SIGNING_IDENTITY_REQUIRED,
        "set up your signing identity first (PUT /account/identity)",
    )
}

/// `user_id`'s public identity as stored (legacy without a signing key); `None` for
/// no such account.
pub(crate) async fn identity_of(
    conn: &mut AnyConnection,
    user_id: &str,
) -> ApiResult<Option<PublicIdentity>> {
    type Row = (String, Option<String>, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT public_key, signing_key, identity_signature, x25519_signature FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(
        |(public_key, signing_key, identity_signature, x25519_signature)| PublicIdentity {
            user_id: user_id.to_owned(),
            public_key,
            signing_key,
            identity_signature,
            x25519_signature,
        },
    ))
}

/// A base64url value of exactly `len` characters that decodes.
fn check_b64(s: &str, len: usize, what: &str) -> ApiResult<()> {
    if s.len() != len || unb64(s).is_err() {
        return Err(ApiError::bad(format!("{what} must be base64url")));
    }
    Ok(())
}

/// `PUT /account/identity {signing_key, identity_signature, x25519_signature,
/// wrapped_signing_key}`: store the account's signing identity, once. Both identity
/// signatures (the Ed25519 one and the X25519 key's XEdDSA cross-signature) must verify
/// over the account's id, its stored X25519 public key and the signing key (else 400
/// `bad_signature`). Sending
/// the stored identity again is fine (`created: false`); another one is 409
/// `identity_exists`: an identity can't be replaced (the apps have no key-change
/// flow; other users pinned it). The account's other devices get a new sync
/// revision.
async fn put_identity(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<IdentityRecord>,
) -> ApiResult<Json<Value>> {
    check_b64(&b.signing_key, KEY_B64, "signing_key")?;
    check_b64(&b.identity_signature, SIGNATURE_B64, "identity_signature")?;
    check_b64(&b.x25519_signature, SIGNATURE_B64, "x25519_signature")?;
    check_b64(
        &b.wrapped_signing_key,
        WRAPPED_SEED_B64,
        "wrapped_signing_key",
    )?;
    state.limiter.limit(
        Class::Target,
        &format!("identity:{}", user.user_id),
        IDENTITIES_PER_HOUR,
        3600,
    )?;
    let mut tx = state.db.begin().await?;
    // A write first (SQLite then never has to upgrade a read transaction).
    sqlx::query("UPDATE users SET updated_at = updated_at WHERE id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    type Stored = (String, String, String, String);
    let (public_key, stored): (String, Option<Stored>) = {
        let row: (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT public_key, signing_key, identity_signature, x25519_signature, wrapped_signing_key
             FROM users WHERE id = $1",
        )
        .bind(&user.user_id)
        .fetch_one(&mut *tx)
        .await?;
        let stored = match (row.1, row.2, row.3, row.4) {
            (Some(k), Some(s), Some(x), Some(w)) => Some((k, s, x, w)),
            _ => None,
        };
        (row.0, stored)
    };
    if let Some((k, s, x, w)) = stored {
        if k == b.signing_key
            && s == b.identity_signature
            && x == b.x25519_signature
            && w == b.wrapped_signing_key
        {
            return Ok(Json(json!({ "ok": true, "created": false })));
        }
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::IDENTITY_EXISTS,
            "this account already has a signing identity",
        ));
    }
    PublicIdentity {
        user_id: user.user_id.clone(),
        public_key,
        signing_key: Some(b.signing_key.clone()),
        identity_signature: Some(b.identity_signature.clone()),
        x25519_signature: Some(b.x25519_signature.clone()),
    }
    .verify()
    .map_err(|_| bad_signature("identity"))?;
    let done = sqlx::query(
        "UPDATE users SET signing_key = $1, identity_signature = $2, x25519_signature = $3,
                wrapped_signing_key = $4, identity_at = $5
         WHERE id = $6 AND signing_key IS NULL",
    )
    .bind(&b.signing_key)
    .bind(&b.identity_signature)
    .bind(&b.x25519_signature)
    .bind(&b.wrapped_signing_key)
    .bind(now())
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await?;
    if done.rows_affected() != 1 {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::IDENTITY_EXISTS,
            "this account already has a signing identity",
        ));
    }
    Event::new("account.identity_created")
        .by(&user)
        .record(&mut tx, &state)
        .await?;
    // `/sync` carries it (`user.identity`): the account's other devices pick it up.
    let revision = crate::vault::bump_user(&mut tx, &user.user_id).await?;
    tx.commit().await?;
    notify_own(&state, &user, revision);
    Ok(Json(json!({ "ok": true, "created": true })))
}

fn notify_own(state: &AppState, user: &AuthUser, revision: Option<i64>) {
    if let Some(revision) = revision {
        let origin = state.origin(&user.session_id);
        state.notify_sync(vec![(
            user.user_id.clone(),
            SyncNotice::new(revision, Some(origin)),
        )]);
    }
}

/// `GET /account/key-pins`: `{"key_pins": <sealed, base64url> | null, "seq"}`.
async fn get_key_pins(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let (pins, seq): (Option<String>, i64) =
        sqlx::query_as("SELECT key_pins, key_pins_seq FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    Ok(Json(json!({ "key_pins": pins, "seq": seq })))
}

#[derive(Deserialize)]
struct KeyPinsBody {
    /// Sealed by the account's apps with the account key (base64url).
    key_pins: String,
    /// The stored `seq` + 1 (also the version sealed inside).
    seq: i64,
}

/// `PUT /account/key-pins {key_pins, seq}`: store the account's key pins by
/// compare-and-swap: `seq` must be the stored one + 1, else 409 `key_pins_changed`
/// (another app wrote them: read, merge, write again). The account's other devices
/// get a new sync revision (`/sync` `user.key_pins_seq`). Answers `{"seq"}`.
async fn put_key_pins(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<KeyPinsBody>,
) -> ApiResult<Json<Value>> {
    if b.key_pins.is_empty() || b.key_pins.len() > MAX_KEY_PINS || unb64(&b.key_pins).is_err() {
        return Err(ApiError::bad(
            "key_pins must be the sealed key pins in base64url",
        ));
    }
    if b.seq < 1 {
        return Err(key_pins_changed());
    }
    state.limiter.limit(
        Class::Target,
        &format!("key-pins:{}", user.user_id),
        KEY_PINS_PER_HOUR,
        3600,
    )?;
    let mut tx = state.db.begin().await?;
    let done = sqlx::query(
        "UPDATE users SET key_pins = $1, key_pins_seq = $2 WHERE id = $3 AND key_pins_seq = $4",
    )
    .bind(&b.key_pins)
    .bind(b.seq)
    .bind(&user.user_id)
    .bind(b.seq - 1)
    .execute(&mut *tx)
    .await?;
    if done.rows_affected() != 1 {
        return Err(key_pins_changed());
    }
    let revision = crate::vault::bump_user(&mut tx, &user.user_id).await?;
    tx.commit().await?;
    notify_own(&state, &user, revision);
    Ok(Json(json!({ "seq": b.seq })))
}

/// 409 `key_pins_changed`.
fn key_pins_changed() -> ApiError {
    ApiError::coded(
        StatusCode::CONFLICT,
        code::KEY_PINS_CHANGED,
        "your key pins changed on another device; read them again",
    )
}
