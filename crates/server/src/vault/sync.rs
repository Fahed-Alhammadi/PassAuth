//! `GET /sync`: everything the account can read, or with `?since=<cursor>` only
//! what changed since that response, read in one snapshot; the cheap
//! `GET /sync/revision` poll; and the sweeper that forgets old tombstones.
//!
//! Delta sync: every vault write takes the vault's next sequence number (`seq`)
//! and stamps the item rows it writes with it (see the module docs of `vault`);
//! an item deleted for good or moved out leaves a tombstone with that number. A
//! response's `cursor` holds each vault's `seq` and key epoch as the response
//! saw them. Sent back as `since`, it gets the items written after it, the
//! tombstones (`deleted`), and whole vaults (`reset`) where it can't vouch for
//! the client's copy: a vault it doesn't know, a replaced vault key, or
//! tombstones already forgotten (`horizon`).
//!
//! Only vaults the account is an active member of count, everywhere here: an
//! invited vault's key, name, items and numbers stay out of `vaults`, `items`,
//! the cursor and `/sync/revision` until the invitation is accepted. Both full
//! and delta responses list the pending `invitations` in full instead.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap, StatusCode, Version};
use passauth_core::item::{b64, unb64};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use sqlx::AnyConnection;
use tower_http::compression::predicate::{DefaultPredicate, Predicate};
use tower_http::compression::{CompressionLayer, CompressionLevel};

use crate::auth::AuthUser;
use crate::db::{is_postgres, now};
use crate::error::{ApiError, ApiResult};
use crate::settings::Num;
use crate::state::AppState;

/// gzip or brotli for these two routes only (a whole vault is mostly base64
/// text). Never on the auth routes, and never for errors. Level 4 keeps brotli
/// fast; its default (11) would take seconds on a large vault.
pub(super) fn compression() -> CompressionLayer<impl Predicate> {
    let success =
        |status: StatusCode, _: Version, _: &HeaderMap, _: &Extensions| status.is_success();
    CompressionLayer::new()
        .gzip(true)
        .br(true)
        .quality(CompressionLevel::Precise(4))
        .compress_when(DefaultPredicate::new().and(success))
}

#[derive(Deserialize)]
pub(super) struct SyncQuery {
    /// The `cursor` of an earlier response: answer with what changed since.
    since: Option<String>,
    /// `summary`: items in the trash come without `item_key` and `data`.
    trash: Option<String>,
}

#[derive(Serialize)]
pub(super) struct SyncResponse {
    revision: i64,
    /// Opaque; send it back as `since` for only what changed after this response.
    cursor: String,
    user: SyncUser,
    /// The stored account bundle JSON, passed through as it is.
    bundle: Box<RawValue>,
    /// Every vault the account reads (also in a delta: a vault missing here is
    /// gone for the account, with its items).
    vaults: Vec<VaultRow>,
    /// Vaults shared with the account and not accepted yet (always the full list).
    invitations: Vec<Invitation>,
    /// Everything (full), or items written after the cursor plus every item of
    /// the `reset` vaults (delta). Upserts by id: an item may change vaults.
    items: Vec<ItemRow>,
    /// Delta: items no longer in a vault (deleted for good, or moved to a vault
    /// in `items` or one the account can't read). Apply before `items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<Vec<Deleted>>,
    /// Delta: vaults sent whole; the client replaces all its items of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<Vec<String>>,
    /// Present (true) only on a delta response.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    delta: bool,
}

#[derive(Serialize)]
struct SyncUser {
    id: String,
    email: String,
    name: String,
    email_verified: bool,
    /// Signed sharing: the account's signing identity `{signing_key,
    /// identity_signature, x25519_signature, wrapped_signing_key}`, or `null` until its
    /// apps make one.
    identity: Option<Value>,
    /// Signed sharing: the version of the account's key pins (`GET
    /// /account/key-pins` when it differs from the copy the app has; 0 = none).
    key_pins_seq: i64,
    /// The version of the account's profile picture (`GET /account/avatar` when it
    /// differs from the copy the app has; 0 = never set).
    avatar_seq: i64,
    /// Every active session of the account (refresh or access token still valid) comes
    /// from an app that reads epoch-bound (v2) account wraps
    /// ([`crate::auth::reads_bound_wraps`]): apps write v2 wraps then, else v1. A
    /// compatibility hint, not a security decision (a server saying false only keeps
    /// the v1 format).
    account_wraps_v2: bool,
}

#[derive(Serialize, sqlx::FromRow)]
struct VaultRow {
    id: String,
    meta: String,
    role: String,
    wrapped_key: String,
    key_kind: String,
    /// 1 = someone who knew the key left: an admin's client must rotate it.
    rotation_pending: i64,
    /// Goes up with every key replacement; clients send it with what they encrypt.
    key_epoch: i64,
    /// Goes up with every write into the vault.
    seq: i64,
    /// Tombstones up to this `seq` are forgotten.
    #[serde(skip)]
    horizon: i64,
    /// Signed sharing: the vault's latest signed member roster (JSON text as the
    /// app signed it) and its version (0 = none).
    member_roster: Option<String>,
    member_roster_seq: i64,
    #[serde(skip)]
    share_signature: Option<String>,
    #[serde(skip)]
    share_signer_identity: Option<String>,
    #[serde(skip)]
    signer_gone: i64,
    /// Signed sharing: `{signature, signer, signer_deleted}` of a sealed key, or
    /// `null` (not signed; always for `key_kind` `account`).
    #[sqlx(skip)]
    share: Value,
}

impl VaultRow {
    fn fill_share(&mut self) {
        self.share = super::signed::share_json(
            self.share_signature.take(),
            self.share_signer_identity.take(),
            self.signer_gone != 0,
        );
    }
}

#[derive(Serialize, sqlx::FromRow)]
struct ItemRow {
    id: String,
    vault_id: String,
    /// Left out for items in the trash with `trash=summary`.
    #[serde(skip_serializing_if = "Option::is_none")]
    item_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    revision: i64,
    deleted_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize, sqlx::FromRow)]
struct Deleted {
    id: String,
    vault_id: String,
}

/// A vault shared with the account, waiting for it to accept or decline.
#[derive(Serialize)]
struct Invitation {
    vault_id: String,
    role: String,
    /// The vault key sealed to the account's public key.
    wrapped_key: String,
    /// The vault's name etc., encrypted with that key.
    meta: String,
    /// Who shared it (`id`, read by the core as `user_id`), with their public key so
    /// the app can show its fingerprint (and their signing identity: `signing_key`,
    /// `identity_signature`, `x25519_signature`, null without one); `null` once their
    /// account is deleted. For display only: the share's `signer` is what is verified.
    invited_by: Option<Value>,
    invited_at: Option<i64>,
    /// The vault's key epoch (signed into the share).
    key_epoch: i64,
    /// Signed sharing: `{signature, signer}` or `null` (not signed: apps refuse to
    /// accept a new unsigned invitation from a server with `signed_sharing`).
    share: Value,
    /// Signed sharing: the vault's latest member roster and its version (0 = none).
    member_roster: Option<String>,
    member_roster_seq: i64,
}

/// What a `cursor` holds: the database's sync generation and each vault's
/// sequence number and key epoch. Binary, about 20 bytes a vault, so that the
/// cursor of an account with hundreds of vaults still fits in a URL behind a
/// proxy with an 8 KiB request-line limit:
/// `[version][generation length][generation]` then per vault
/// `[16-byte id][LEB128 seq][LEB128 key epoch]`, all base64url.
#[derive(Debug, PartialEq)]
pub(crate) struct Cursor {
    generation: Vec<u8>,
    vaults: BTreeMap<uuid::Uuid, (i64, i64)>,
}

const CURSOR_VERSION: u8 = 1;

impl Cursor {
    /// The cursor of a response that saw `vaults` as (id, seq, key epoch).
    pub(crate) fn new<'a>(
        generation: &str,
        vaults: impl IntoIterator<Item = (&'a str, i64, i64)>,
    ) -> Self {
        Self {
            generation: generation.as_bytes().to_vec(),
            // Every vault id is a UUID (checked when the vault is made); one that
            // somehow isn't is left out, so it's always sent whole.
            vaults: vaults
                .into_iter()
                .filter_map(|(id, seq, epoch)| {
                    Some((uuid::Uuid::parse_str(id).ok()?, (seq, epoch)))
                })
                .collect(),
        }
    }

    pub(crate) fn encode(&self) -> String {
        let mut out = Vec::with_capacity(2 + self.generation.len() + self.vaults.len() * 20);
        out.push(CURSOR_VERSION);
        out.push(self.generation.len() as u8);
        out.extend_from_slice(&self.generation);
        for (id, (seq, epoch)) in &self.vaults {
            out.extend_from_slice(id.as_bytes());
            put_varint(&mut out, *seq);
            put_varint(&mut out, *epoch);
        }
        b64(&out)
    }

    /// `None` for anything this server can't use (the full response then).
    fn decode(s: &str, generation: &str) -> Option<Self> {
        let bytes = unb64(s).ok()?;
        let (&version, rest) = bytes.split_first()?;
        let (&len, rest) = rest.split_first()?;
        if version != CURSOR_VERSION || rest.len() < len as usize {
            return None;
        }
        let (gen_bytes, mut rest) = rest.split_at(len as usize);
        if gen_bytes != generation.as_bytes() {
            return None;
        }
        let mut vaults = BTreeMap::new();
        while !rest.is_empty() {
            let id = uuid::Uuid::from_slice(rest.get(..16)?).ok()?;
            rest = &rest[16..];
            let seq = take_varint(&mut rest)?;
            let epoch = take_varint(&mut rest)?;
            vaults.insert(id, (seq, epoch));
        }
        Some(Self {
            generation: gen_bytes.to_vec(),
            vaults,
        })
    }

    /// (seq, key epoch) the cursor holds for a vault.
    fn get(&self, vault_id: &str) -> Option<(i64, i64)> {
        self.vaults
            .get(&uuid::Uuid::parse_str(vault_id).ok()?)
            .copied()
    }
}

fn put_varint(out: &mut Vec<u8>, v: i64) {
    let mut v = v.max(0) as u64;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn take_varint(input: &mut &[u8]) -> Option<i64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = input.split_first()?;
        *input = rest;
        v |= u64::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return i64::try_from(v).ok();
        }
    }
    None
}

pub(super) async fn sync(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<SyncQuery>,
) -> ApiResult<Json<SyncResponse>> {
    let summary = q.trash.as_deref() == Some("summary");
    let since = q
        .since
        .as_deref()
        .and_then(|s| Cursor::decode(s, &state.sync_generation));
    let postgres = is_postgres(&state.config.database_url);
    // One snapshot: a key rotation committing between the vault and item
    // queries would otherwise hand out old wrapped keys with new items, and a
    // write committing in between would be missing from the items but not from
    // the cursor.
    let mut tx = state.db.begin().await?;
    if postgres {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
    }
    type UserRow = (
        i64,
        String,
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        i64,
    );
    let (
        revision,
        name,
        verified,
        bundle,
        signing_key,
        identity_signature,
        x25519,
        wrapped,
        pins_seq,
        avatar_seq,
    ): UserRow = sqlx::query_as(
        "SELECT revision, name, email_verified, bundle, signing_key, identity_signature,
                    x25519_signature, wrapped_signing_key, key_pins_seq, avatar_seq
             FROM users WHERE id = $1",
    )
    .bind(&user.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let clients: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT client FROM sessions WHERE user_id = $1 AND (refresh_expires > $2 OR access_expires > $2)",
    )
    .bind(&user.user_id)
    .bind(crate::db::now())
    .fetch_all(&mut *tx)
    .await?;
    let account_wraps_v2 = clients
        .iter()
        .all(|(c,)| crate::auth::reads_bound_wraps(c.as_deref()));
    let identity = match (signing_key, identity_signature, x25519, wrapped) {
        (Some(k), Some(s), Some(x), Some(w)) => Some(json!({
            "signing_key": k,
            "identity_signature": s,
            "x25519_signature": x,
            "wrapped_signing_key": w,
        })),
        _ => None,
    };
    let mut vaults: Vec<VaultRow> = sqlx::query_as(
        "SELECT v.id, v.meta, m.role, m.wrapped_key, m.key_kind, v.rotation_pending, v.key_epoch,
                v.seq, v.horizon, v.member_roster, v.member_roster_seq, m.share_signature,
                m.share_signer_identity,
                CASE WHEN s.id IS NULL THEN 1 ELSE 0 END AS signer_gone
         FROM vaults v JOIN vault_members m ON m.vault_id = v.id
         LEFT JOIN users s ON s.id = m.share_signer
         WHERE m.user_id = $1 AND m.status = 'active' ORDER BY v.created_at",
    )
    .bind(&user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    for v in &mut vaults {
        v.fill_share();
    }
    let invitations = invitations(&mut tx, &user.user_id).await?;
    let (items, deleted, reset) = match &since {
        None => (
            all_items(&mut tx, &user.user_id, summary).await?,
            None,
            None,
        ),
        Some(cursor) => {
            let (items, deleted, reset) =
                changes(&mut tx, postgres, &vaults, cursor, summary).await?;
            (items, Some(deleted), Some(reset))
        }
    };
    tx.commit().await?;
    let cursor = Cursor::new(
        &state.sync_generation,
        vaults.iter().map(|v| (v.id.as_str(), v.seq, v.key_epoch)),
    );
    Ok(Json(SyncResponse {
        revision,
        cursor: cursor.encode(),
        user: SyncUser {
            id: user.user_id,
            email: user.email,
            name,
            email_verified: verified != 0,
            identity,
            key_pins_seq: pins_seq,
            avatar_seq,
            account_wraps_v2,
        },
        bundle: RawValue::from_string(bundle).map_err(anyhow::Error::from)?,
        vaults,
        invitations,
        items,
        deleted,
        reset,
        delta: since.is_some(),
    }))
}

/// The account's pending invitations, oldest first.
async fn invitations(conn: &mut AnyConnection, user_id: &str) -> ApiResult<Vec<Invitation>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        vault_id: String,
        role: String,
        wrapped_key: String,
        meta: String,
        invited_at: Option<i64>,
        key_epoch: i64,
        member_roster: Option<String>,
        member_roster_seq: i64,
        share_signature: Option<String>,
        by_id: Option<String>,
        by_email: Option<String>,
        by_name: Option<String>,
        by_public_key: Option<String>,
        by_signing_key: Option<String>,
        by_identity_signature: Option<String>,
        by_x25519_signature: Option<String>,
        share_signer_identity: Option<String>,
        signer_gone: i64,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT m.vault_id, m.role, m.wrapped_key, v.meta, m.invited_at, v.key_epoch,
                v.member_roster, v.member_roster_seq, m.share_signature,
                b.id AS by_id, b.email AS by_email, b.name AS by_name, b.public_key AS by_public_key,
                b.signing_key AS by_signing_key, b.identity_signature AS by_identity_signature,
                b.x25519_signature AS by_x25519_signature, m.share_signer_identity,
                CASE WHEN s.id IS NULL THEN 1 ELSE 0 END AS signer_gone
         FROM vault_members m JOIN vaults v ON v.id = m.vault_id
         LEFT JOIN users b ON b.id = m.invited_by
         LEFT JOIN users s ON s.id = m.share_signer
         WHERE m.user_id = $1 AND m.status = 'invited'
         ORDER BY m.invited_at, m.vault_id",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Invitation {
            vault_id: r.vault_id,
            role: r.role,
            wrapped_key: r.wrapped_key,
            meta: r.meta,
            invited_by: r.by_id.map(|id| {
                json!({
                    "id": id,
                    "email": r.by_email,
                    "name": r.by_name,
                    "public_key": r.by_public_key,
                    "signing_key": r.by_signing_key,
                    "identity_signature": r.by_identity_signature,
                    "x25519_signature": r.by_x25519_signature,
                })
            }),
            invited_at: r.invited_at,
            key_epoch: r.key_epoch,
            share: super::signed::share_json(
                r.share_signature,
                r.share_signer_identity,
                r.signer_gone != 0,
            ),
            member_roster: r.member_roster,
            member_roster_seq: r.member_roster_seq,
        })
        .collect())
}

/// Every item of every vault the user reads.
async fn all_items(
    conn: &mut AnyConnection,
    user_id: &str,
    summary: bool,
) -> ApiResult<Vec<ItemRow>> {
    Ok(sqlx::query_as(
        "SELECT i.id, i.vault_id,
                CASE WHEN $2 = 1 AND i.deleted_at IS NOT NULL THEN NULL ELSE i.item_key END AS item_key,
                CASE WHEN $2 = 1 AND i.deleted_at IS NOT NULL THEN NULL ELSE i.data END AS data,
                i.revision, i.deleted_at, i.created_at, i.updated_at
         FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
         WHERE m.user_id = $1 AND m.status = 'active'",
    )
    .bind(user_id)
    .bind(summary as i64)
    .fetch_all(&mut *conn)
    .await?)
}

/// What changed in `vaults` since `cursor`: (items, deleted, reset vault ids).
async fn changes(
    conn: &mut AnyConnection,
    postgres: bool,
    vaults: &[VaultRow],
    cursor: &Cursor,
    summary: bool,
) -> ApiResult<(Vec<ItemRow>, Vec<Deleted>, Vec<String>)> {
    // (vault, items above this seq: -1 = all) and (vault, tombstones above this seq).
    let mut wanted = Vec::new();
    let mut gone = Vec::new();
    let mut reset = Vec::new();
    for v in vaults {
        match cursor.get(&v.id) {
            // Known with the current key, every deletion since still remembered,
            // and not from a newer database (a restored backup).
            Some((seq, epoch)) if epoch == v.key_epoch && seq >= v.horizon && seq <= v.seq => {
                if seq < v.seq {
                    wanted.push(json!({ "vault_id": v.id, "since": seq }));
                    gone.push(json!({ "vault_id": v.id, "since": seq }));
                }
            }
            _ => {
                reset.push(v.id.clone());
                wanted.push(json!({ "vault_id": v.id, "since": -1 }));
            }
        }
    }
    let items: Vec<ItemRow> = if wanted.is_empty() {
        Vec::new()
    } else {
        // PostgreSQL guesses 100 rows for json_to_recordset and would rather scan
        // all items; the LATERAL subquery (kept apart by OFFSET 0) makes it one
        // index range scan per vault, as SQLite does by itself.
        let sql = if postgres {
            "SELECT i.id, i.vault_id,
                    CASE WHEN $2 = 1 AND i.deleted_at IS NOT NULL THEN NULL ELSE i.item_key END AS item_key,
                    CASE WHEN $2 = 1 AND i.deleted_at IS NOT NULL THEN NULL ELSE i.data END AS data,
                    i.revision, i.deleted_at, i.created_at, i.updated_at
             FROM json_to_recordset($1::json) AS c(vault_id TEXT, since BIGINT)
             CROSS JOIN LATERAL (SELECT * FROM items
                                 WHERE items.vault_id = c.vault_id AND items.seq > c.since
                                 OFFSET 0) AS i"
        } else {
            "SELECT i.id, i.vault_id,
                    CASE WHEN $2 = 1 AND i.deleted_at IS NOT NULL THEN NULL ELSE i.item_key END AS item_key,
                    CASE WHEN $2 = 1 AND i.deleted_at IS NOT NULL THEN NULL ELSE i.data END AS data,
                    i.revision, i.deleted_at, i.created_at, i.updated_at
             FROM json_each($1) AS c
             JOIN items i ON i.vault_id = json_extract(c.value, '$.vault_id')
                         AND i.seq > json_extract(c.value, '$.since')"
        };
        sqlx::query_as(sql)
            .bind(serde_json::Value::from(wanted).to_string())
            .bind(summary as i64)
            .fetch_all(&mut *conn)
            .await?
    };
    let deleted: Vec<Deleted> = if gone.is_empty() {
        Vec::new()
    } else {
        let sql = if postgres {
            "SELECT t.item_id AS id, t.vault_id
             FROM json_to_recordset($1::json) AS c(vault_id TEXT, since BIGINT)
             CROSS JOIN LATERAL (SELECT * FROM item_tombstones
                                 WHERE item_tombstones.vault_id = c.vault_id
                                   AND item_tombstones.seq > c.since
                                 OFFSET 0) AS t"
        } else {
            "SELECT t.item_id AS id, t.vault_id
             FROM json_each($1) AS c
             JOIN item_tombstones t ON t.vault_id = json_extract(c.value, '$.vault_id')
                                   AND t.seq > json_extract(c.value, '$.since')"
        };
        sqlx::query_as(sql)
            .bind(serde_json::Value::from(gone).to_string())
            .fetch_all(&mut *conn)
            .await?
    };
    Ok((items, deleted, reset))
}

#[derive(Serialize)]
pub(super) struct Revision {
    revision: i64,
    /// The sequence number of every vault the account reads (not invitations).
    vaults: BTreeMap<String, i64>,
}

pub(super) async fn revision(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Revision>> {
    // One statement, so the revision and the numbers come from one snapshot.
    let rows: Vec<(i64, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT u.revision, v.id, v.seq FROM users u
         LEFT JOIN vault_members m ON m.user_id = u.id AND m.status = 'active'
         LEFT JOIN vaults v ON v.id = m.vault_id
         WHERE u.id = $1",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let revision = rows.first().ok_or(ApiError::Unauthorized)?.0;
    let vaults = rows
        .into_iter()
        .filter_map(|(_, id, seq)| Some((id?, seq?)))
        .collect();
    Ok(Json(Revision { revision, vaults }))
}

/// Forget tombstones older than the admin's `tombstone_days`, raising each
/// vault's `horizon` to the newest one forgotten in it: a cursor from before
/// then gets the whole vault again. Returns how many were forgotten.
pub async fn purge_tombstones(state: &AppState) -> ApiResult<u64> {
    let days = state.num(Num::TombstoneDays);
    let cutoff = now() - days * 86_400;
    let vaults: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT vault_id FROM item_tombstones WHERE deleted_at < $1 ORDER BY vault_id",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;
    let mut forgotten = 0;
    for vault in vaults {
        let mut tx = state.db.begin().await?;
        // A write first (the vault's row lock); the horizon only goes up.
        let horizon: Option<i64> = sqlx::query_scalar(
            "UPDATE vaults SET horizon = COALESCE(
                 (SELECT MAX(t.seq) FROM item_tombstones t
                  WHERE t.vault_id = $1 AND t.deleted_at < $2 AND t.seq > vaults.horizon),
                 horizon)
             WHERE id = $1 RETURNING horizon",
        )
        .bind(&vault)
        .bind(cutoff)
        .fetch_optional(&mut *tx)
        .await?;
        let done = match horizon {
            Some(horizon) => {
                sqlx::query("DELETE FROM item_tombstones WHERE vault_id = $1 AND seq <= $2")
                    .bind(&vault)
                    .bind(horizon)
                    .execute(&mut *tx)
                    .await?
            }
            // The vault is gone: so are its tombstones.
            None => {
                sqlx::query("DELETE FROM item_tombstones WHERE vault_id = $1")
                    .bind(&vault)
                    .execute(&mut *tx)
                    .await?
            }
        };
        tx.commit().await?;
        forgotten += done.rows_affected();
    }
    if forgotten > 0 {
        tracing::info!(
            tombstones = forgotten,
            days,
            "forgot old deletions; apps that synced before get those vaults in full"
        );
    }
    Ok(forgotten)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_refuse_anything_else() {
        let a = "8c6f2b8e-7a51-4c1e-9d55-2f1f5c2b7a10";
        let b = "0d5e6a4f-1b2c-4d3e-8f90-a1b2c3d4e5f6";
        let c = Cursor::new("gen-1", [(a, 300, 2), (b, 0, 0), ("not-a-uuid", 5, 0)]);
        let text = c.encode();
        assert!(text.len() < 70, "about 20 bytes a vault: {text}");
        let back = Cursor::decode(&text, "gen-1").unwrap();
        assert_eq!(back, c);
        assert_eq!(back.get(a), Some((300, 2)));
        assert_eq!(
            back.get(&a.to_uppercase()),
            Some((300, 2)),
            "any spelling of the id"
        );
        assert_eq!(back.get("not-a-uuid"), None);
        assert!(Cursor::decode(&text, "gen-2").is_none(), "another database");
        for bad in ["", "AA", "not base64!", &text[..text.len() - 2]] {
            assert!(Cursor::decode(bad, "gen-1").is_none(), "{bad:?}");
        }
        let mut v = Vec::new();
        for n in [0, 1, 127, 128, 300, i64::MAX] {
            put_varint(&mut v, n);
            assert_eq!(take_varint(&mut v.as_slice()), Some(n));
            v.clear();
        }
        assert_eq!(take_varint(&mut [0xff; 11].as_slice()), None);
    }
}
