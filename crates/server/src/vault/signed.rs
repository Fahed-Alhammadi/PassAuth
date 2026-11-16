//! Signed sharing, the vault side (docs/ARCHITECTURE.md "Signed sharing").
//!
//! A membership's sealed vault key may carry a share signature by whoever sealed
//! it (`vault_members.share_signature`, `share_signer`), and a vault may have a
//! signed member roster (`vaults.member_roster`, version `member_roster_seq`, every
//! version kept in `vault_rosters`). Apps that sign send both with every
//! membership change and key replacement (`POST /vaults/{id}/members`, `/rotate`,
//! `/members/{user}/remove`) and can sign a vault from before (`POST
//! /vaults/{id}/resign`: every sealed key sealed again and signed, and a new
//! roster, in one transaction).
//!
//! The server can't vouch for any of it (apps check every signature against the
//! identities they pinned), but it refuses what can't be right: a signature that
//! doesn't verify against the signer's stored identity (400 `bad_signature`), a
//! roster that isn't the stored version + 1 (409 `member_roster_changed`), or that
//! doesn't list exactly the vault's members, roles and identities after the change
//! at its key epoch (409 `members_changed`). Once a vault has a roster, changes
//! that add or re-key members must be signed (400 `update_required` for apps from
//! before); leaving, declining and removing without a new key stay possible.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use passauth_core::Error as CoreError;
use passauth_core::sharing::{
    MAX_ROSTER_JSON, PublicIdentity, RosterMemberInput, SignedRoster, compare_members,
    verify_roster_chain, verify_share,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{Need, Role, VaultWrite, check_blob, check_id, membership};
use crate::auth::AuthUser;
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::signing::{bad_signature, identity_of, signing_identity_required};
use crate::state::{AppState, Class};

/// Rosters in one page of `GET /vaults/{id}/rosters`.
const ROSTERS_PAGE: i64 = 100;
/// Roster history pages one user may read per hour.
const ROSTER_READS_PER_HOUR: u32 = 600;
/// Re-signs one user may make per hour.
const RESIGNS_PER_HOUR: u32 = 30;
/// Base64url length of an Ed25519 signature (64 bytes).
const SIGNATURE_B64: usize = 86;

/// The caller's identity for signing; 400 `signing_identity_required` without one.
pub(super) async fn signer(conn: &mut AnyConnection, user_id: &str) -> ApiResult<PublicIdentity> {
    identity_of(conn, user_id)
        .await?
        .filter(|i| i.signing_key.is_some())
        .ok_or_else(signing_identity_required)
}

/// The vault's member roster version (0: none yet).
async fn roster_seq(conn: &mut AnyConnection, vault: &str) -> ApiResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT member_roster_seq FROM vaults WHERE id = $1")
            .bind(vault)
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// 400 `update_required`: the vault's members are signed, and this change isn't.
fn unsigned_change() -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        code::UPDATE_REQUIRED,
        "this vault's members are signed: update PassAuth to change them",
    )
}

/// Who signs a membership change into `vault` that carries a roster (`signed`):
/// the caller, who needs a signing identity. Without one (an app from before),
/// only while the vault has no roster yet (else 400 `update_required`). Call it
/// inside the write, after the vault is locked.
pub(super) async fn signer_for_change(
    conn: &mut AnyConnection,
    vault: &str,
    caller: &str,
    signed: bool,
) -> ApiResult<Option<PublicIdentity>> {
    if signed {
        return signer(conn, caller).await.map(Some);
    }
    if roster_seq(conn, vault).await? > 0 {
        return Err(unsigned_change());
    }
    Ok(None)
}

/// A share signature's shape (64 bytes, base64url).
pub(super) fn check_signature(s: &str) -> ApiResult<()> {
    if s.len() != SIGNATURE_B64 || passauth_core::item::unb64(s).is_err() {
        return Err(ApiError::bad("signature must be 64 bytes in base64url"));
    }
    Ok(())
}

fn epoch(key_epoch: i64) -> ApiResult<u64> {
    u64::try_from(key_epoch).map_err(|_| ApiError::bad("invalid key epoch"))
}

/// Check `signature` by `signer` over the share of `vault`'s key at `key_epoch`
/// with `role`, sealed to `recipient` as `sealed_key`, against the stored
/// identities (400 `bad_signature`).
#[allow(clippy::too_many_arguments)]
pub(super) async fn check_share(
    conn: &mut AnyConnection,
    vault: &str,
    recipient: &str,
    role: &str,
    key_epoch: i64,
    sealed_key: &str,
    signer: &PublicIdentity,
    signature: &str,
) -> ApiResult<()> {
    check_signature(signature)?;
    let recipient = identity_of(conn, recipient)
        .await?
        .ok_or_else(|| ApiError::bad("unknown user"))?;
    verify_share(
        vault,
        &recipient,
        role,
        epoch(key_epoch)?,
        sealed_key,
        signer,
        signature,
    )
    .map(|_| ())
    .map_err(|e| match e {
        CoreError::BadSignature => bad_signature("share"),
        e => ApiError::bad(format!("invalid share: {e}")),
    })
}

/// Every member of `vault` (invitees too) as a roster lists them.
async fn members(conn: &mut AnyConnection, vault: &str) -> ApiResult<Vec<RosterMemberInput>> {
    type Row = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT m.user_id, m.role, u.public_key, u.signing_key, u.identity_signature, u.x25519_signature
         FROM vault_members m JOIN users u ON u.id = m.user_id WHERE m.vault_id = $1",
    )
    .bind(vault)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(user_id, role, public_key, signing_key, identity_signature, x25519_signature)| {
                RosterMemberInput {
                    identity: PublicIdentity {
                        user_id,
                        public_key,
                        signing_key,
                        identity_signature,
                        x25519_signature,
                    },
                    role,
                    email: None,
                }
            },
        )
        .collect())
}

/// Check the member roster sent with a change (after the change, inside its write)
/// and store it as the vault's next version: signed by `signer` (the caller, with
/// their stored identity), the next version, at `key_epoch` (the vault's after the
/// change), listing exactly its members, roles and identities. Returns the version.
pub(super) async fn store_roster(
    conn: &mut AnyConnection,
    vault: &str,
    json: &str,
    signer: &PublicIdentity,
    key_epoch: i64,
) -> ApiResult<i64> {
    if json.len() > MAX_ROSTER_JSON {
        return Err(ApiError::bad("member roster too large"));
    }
    let roster = SignedRoster::parse(json).map_err(|e| match e {
        CoreError::BadSignature => bad_signature("member roster"),
        e => ApiError::bad(format!("invalid member roster: {e}")),
    })?;
    if roster.vault_id != vault {
        return Err(ApiError::bad("the member roster is for another vault"));
    }
    if roster.signer.user_id != signer.user_id
        || roster.signer.public_key != signer.public_key
        || roster.signer.signing_key != signer.signing_key
        || roster.signer.x25519_signature != signer.x25519_signature
    {
        return Err(bad_signature("member roster"));
    }
    let seq = roster_seq(conn, vault).await?;
    if i64::try_from(roster.version).ok() != Some(seq + 1) {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::MEMBER_ROSTER_CHANGED,
            "the vault's member roster changed; sync and try again",
        ));
    }
    let now_members = members(conn, vault).await?;
    let diff = compare_members(&roster, &now_members);
    if i64::try_from(roster.key_epoch).ok() != Some(key_epoch)
        || !diff.is_clean()
        || !diff.missing.is_empty()
    {
        let mut fields = serde_json::Map::new();
        fields.insert("key_epoch".into(), key_epoch.into());
        fields.insert("unknown".into(), json!(diff.unknown));
        fields.insert("identity_changed".into(), json!(diff.identity_changed));
        fields.insert("role_changed".into(), json!(diff.role_changed));
        fields.insert("missing".into(), json!(diff.missing));
        return Err(ApiError::with_fields(
            StatusCode::CONFLICT,
            code::MEMBERS_CHANGED,
            "the member roster doesn't list the vault's members; sync and try again",
            fields,
        ));
    }
    // The next link of the chain the apps check: signed by an owner or admin of the
    // stored roster (exactly their full identity), within the hierarchy, epoch not
    // lower, the same key commitment at the same epoch. The apps check it themselves;
    // refusing it here keeps a roster every app would refuse out of the vault.
    if seq > 0 {
        let stored: Option<String> =
            sqlx::query_scalar("SELECT member_roster FROM vaults WHERE id = $1")
                .bind(vault)
                .fetch_one(&mut *conn)
                .await?;
        let prev = stored
            .as_deref()
            .map(SignedRoster::parse)
            .transpose()
            .map_err(|e| ApiError::bad(format!("the stored member roster is invalid: {e}")))?
            .ok_or_else(|| ApiError::bad("the stored member roster is missing"))?;
        verify_roster_chain(vault, Some(&prev), std::slice::from_ref(&roster), &roster).map_err(
            |e| match e {
                CoreError::RosterUnauthorized => ApiError::coded(
                    StatusCode::FORBIDDEN,
                    code::ROSTER_UNAUTHORIZED,
                    "this member roster change isn't allowed for you",
                ),
                CoreError::BadSignature => bad_signature("member roster"),
                e => ApiError::bad(format!("invalid member roster: {e}")),
            },
        )?;
    }
    let version = seq + 1;
    sqlx::query(
        "INSERT INTO vault_rosters (vault_id, version, roster, signer_id, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(vault)
    .bind(version)
    .bind(json)
    .bind(&signer.user_id)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE vaults SET member_roster = $1, member_roster_seq = $2 WHERE id = $3")
        .bind(json)
        .bind(version)
        .bind(vault)
        .execute(&mut *conn)
        .await?;
    Ok(version)
}

#[derive(Deserialize)]
pub(super) struct RosterQuery {
    /// Versions after this one (0: from version 1).
    after: Option<i64>,
}

/// `GET /vaults/{id}/rosters?after=N`: the vault's member rosters after version N,
/// oldest first, at most 100 (`more`: there are newer ones; ask again after the
/// last). For members and invitees. `{"rosters": [<roster JSON text>], "latest", "more"}`.
pub(super) async fn rosters(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RosterQuery>,
) -> ApiResult<Json<Value>> {
    check_id(&id)?;
    state.limiter.limit(
        Class::Target,
        &format!("rosters:{}", user.user_id),
        ROSTER_READS_PER_HOUR,
        3600,
    )?;
    let after = q.after.unwrap_or(0).max(0);
    let mut conn = state.db.acquire().await?;
    membership(&mut conn, &user.user_id, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let latest = roster_seq(&mut conn, &id).await?;
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT roster FROM vault_rosters WHERE vault_id = $1 AND version > $2 ORDER BY version LIMIT $3",
    )
    .bind(&id)
    .bind(after)
    .bind(ROSTERS_PAGE + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() as i64 > ROSTERS_PAGE;
    rows.truncate(ROSTERS_PAGE as usize);
    Ok(Json(
        json!({ "rosters": rows, "latest": latest, "more": more }),
    ))
}

#[derive(Deserialize)]
pub(super) struct ResignKey {
    user_id: String,
    /// The vault key sealed again to the member.
    wrapped_key: String,
    signature: String,
}

#[derive(Deserialize)]
pub(super) struct Resign {
    /// The vault's current key epoch (the key isn't replaced).
    key_epoch: i64,
    /// A new sealed key and its signature for exactly the members whose key is sealed.
    keys: Vec<ResignKey>,
    /// The next member roster, signed by the caller.
    roster: String,
}

/// `POST /vaults/{id}/resign {key_epoch, keys, roster}`: sign a vault (owners and
/// admins): every sealed key sealed again (the same vault key, so nothing else is
/// re-encrypted) with a share signature, and the next member roster, in one
/// transaction. Fixes shares from apps from before and shares whose signer's
/// account is gone. Answers `{"revision", "member_roster_seq"}`.
pub(super) async fn resign(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Resign>,
) -> ApiResult<Json<Value>> {
    for k in &b.keys {
        check_id(&k.user_id)?;
        check_blob(&k.wrapped_key)?;
        check_signature(&k.signature)?;
    }
    state.limiter.limit(
        Class::Target,
        &format!("resign:{}", user.user_id),
        RESIGNS_PER_HOUR,
        3600,
    )?;
    let need = Need::new(&id, Role::Admin, Some(b.key_epoch));
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let signer = signer(w.conn(), &user.user_id).await?;
    let snapshot = signer_snapshot(w.conn(), &user.user_id).await?;
    let sealed: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id, role FROM vault_members WHERE vault_id = $1 AND key_kind = 'sealed'",
    )
    .bind(&id)
    .fetch_all(w.conn())
    .await?;
    let mut given: Vec<&str> = b.keys.iter().map(|k| k.user_id.as_str()).collect();
    given.sort_unstable();
    let mut expected: Vec<&str> = sealed.iter().map(|(u, _)| u.as_str()).collect();
    expected.sort_unstable();
    if given != expected {
        return Err(ApiError::bad(
            "a new sealed key is required for exactly the members whose key is sealed",
        ));
    }
    let key_epoch = w.locked(&id).key_epoch;
    for k in &b.keys {
        let role = &sealed
            .iter()
            .find(|(u, _)| *u == k.user_id)
            .expect("checked above")
            .1;
        check_share(
            w.conn(),
            &id,
            &k.user_id,
            role,
            key_epoch,
            &k.wrapped_key,
            &signer,
            &k.signature,
        )
        .await?;
        sqlx::query(
            "UPDATE vault_members SET wrapped_key = $1, share_signature = $2, share_signer = $3,
                 share_signer_identity = $4
             WHERE vault_id = $5 AND user_id = $6",
        )
        .bind(&k.wrapped_key)
        .bind(&k.signature)
        .bind(&user.user_id)
        .bind(&snapshot)
        .bind(&id)
        .bind(&k.user_id)
        .execute(w.conn())
        .await?;
    }
    let version = store_roster(w.conn(), &id, &b.roster, &signer, key_epoch).await?;
    // Invitations carry the sealed key.
    w.tell_invitees(&id);
    w.log(
        Event::new("vault.resigned")
            .vault(&id)
            .data(json!({ "members": b.keys.len(), "member_roster_seq": version })),
    )
    .await?;
    let revision = w.commit(&state).await?;
    Ok(Json(
        json!({ "revision": revision, "member_roster_seq": version }),
    ))
}

/// The share object of a membership row: `{"signature", "signer": {user_id, email,
/// name, public_key, signing_key, identity_signature, x25519_signature} (as when the
/// share was signed),
/// "signer_deleted"}`, or `null` when the share isn't signed (or, for rows from before
/// signer snapshots, has none).
pub(super) fn share_json(signature: Option<String>, snapshot: Option<String>, gone: bool) -> Value {
    match (
        signature,
        snapshot.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
    ) {
        (Some(signature), Some(signer)) => json!({
            "signature": signature,
            "signer": signer,
            "signer_deleted": gone,
        }),
        _ => Value::Null,
    }
}

/// The caller's identity as it is now, kept with every share they sign (so the share
/// still verifies after their account is deleted): `{user_id, email, name,
/// public_key, signing_key, identity_signature, x25519_signature}` as JSON text.
pub(super) async fn signer_snapshot(conn: &mut AnyConnection, user_id: &str) -> ApiResult<String> {
    type Row = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let (email, name, public_key, signing_key, identity_signature, x25519_signature): Row =
        sqlx::query_as(
            "SELECT email, name, public_key, signing_key, identity_signature, x25519_signature
             FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(json!({
        "user_id": user_id,
        "email": email,
        "name": name,
        "public_key": public_key,
        "signing_key": signing_key,
        "identity_signature": identity_signature,
        "x25519_signature": x25519_signature,
    })
    .to_string())
}
