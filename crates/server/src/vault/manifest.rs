//! Vault manifests (migration 17, feature `vault_manifest`): a small record of what a
//! vault holds, sealed by the apps with a key made from the vault key, so the apps
//! can tell when the server's copy of a vault isn't the one its members wrote (an
//! older item, a hidden or resurrected one). The server can't read it; it stores
//! the sealed text and its version (`vaults.manifest`, `manifest_seq`, 0 = none),
//! hands both out with every vault row of `/sync`, and replaces them only as part
//! of the write they describe:
//!
//! - once a vault has a manifest, every write that changes its items (create,
//!   import, edit, move, trash, restore, delete for good, key replacement) carries
//!   the next one, exactly one version up, stored in the same transaction
//!   ([`super::VaultWrite::manifests`]); a write without it is refused, also from
//!   apps that don't know manifests yet;
//! - `PUT /vaults/{id}/manifest` starts a vault's first manifest, or replaces it
//!   with a new baseline (the user's "Use the server's copy"). A first one waits
//!   until every signed-in app of every member keeps manifests ([`may_start`],
//!   `manifest_ok` in `/sync`), so no app is locked out of writing by surprise;
//! - the server never changes the items of a vault with a manifest by itself: the
//!   trash sweeper leaves such vaults to the apps (`items::purge_trash`).
//!
//! Attachments and item history are separate tables and are not covered.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{Need, Role, VaultWrite, check_id};
use crate::auth::{AuthUser, keeps_manifests};
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::state::AppState;

/// The largest manifest version: whole numbers every app carries exactly.
const MAX_SEQ: i64 = 9_007_199_254_740_991;
/// A sealed manifest is about 200 characters.
const MAX_SEALED: usize = 1024;

/// A vault's next manifest, as a write carries it (`manifests: [{vault_id, seq,
/// sealed}]`).
#[derive(Deserialize)]
pub(super) struct ManifestIn {
    pub vault_id: String,
    pub seq: i64,
    pub sealed: String,
}

impl ManifestIn {
    /// Shape checks that need no database: one entry a vault, a version and a
    /// base64url text of a plausible size.
    pub(super) fn check_all(sent: &[ManifestIn]) -> ApiResult<()> {
        let mut vaults = BTreeSet::new();
        for m in sent {
            check_sealed(m.seq, &m.sealed)?;
            if !vaults.insert(m.vault_id.as_str()) {
                return Err(ApiError::bad("one manifest for each vault"));
            }
        }
        Ok(())
    }
}

fn check_sealed(seq: i64, sealed: &str) -> ApiResult<()> {
    let text = !sealed.is_empty()
        && sealed.len() <= MAX_SEALED
        && sealed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !(1..=MAX_SEQ).contains(&seq) || !text {
        return Err(ApiError::bad("invalid manifest"));
    }
    Ok(())
}

/// The manifest of a write that names it in its query (`manifest_seq`, `manifest`:
/// trash, restore, delete for good), for the item's vault.
pub(super) fn from_query(
    vault: &str,
    seq: Option<i64>,
    sealed: Option<String>,
) -> ApiResult<Vec<ManifestIn>> {
    let sent = match (seq, sealed) {
        (None, None) => Vec::new(),
        (Some(seq), Some(sealed)) => vec![ManifestIn {
            vault_id: vault.to_owned(),
            seq,
            sealed,
        }],
        _ => return Err(ApiError::bad("manifest_seq and manifest go together")),
    };
    ManifestIn::check_all(&sent)?;
    Ok(sent)
}

/// Whether `vault` may get its first manifest: every active session of every
/// active member comes from an app that keeps manifests.
async fn may_start(conn: &mut AnyConnection, vault: &str) -> ApiResult<bool> {
    let clients: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT DISTINCT s.client FROM vault_members m JOIN sessions s ON s.user_id = m.user_id
         WHERE m.vault_id = $1 AND m.status = 'active'
           AND (s.refresh_expires > $2 OR s.access_expires > $2)",
    )
    .bind(vault)
    .bind(now())
    .fetch_all(&mut *conn)
    .await?;
    Ok(clients.iter().all(|(c,)| keeps_manifests(c.as_deref())))
}

/// [`may_start`] for every vault `user_id` reads that has no manifest yet: the ids
/// of those that may not start one (`manifest_ok` false in `/sync`).
pub(super) async fn not_ready(
    conn: &mut AnyConnection,
    user_id: &str,
) -> ApiResult<BTreeSet<String>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT DISTINCT m.vault_id, s.client
         FROM vault_members mine
         JOIN vaults v ON v.id = mine.vault_id AND v.manifest_seq = 0
         JOIN vault_members m ON m.vault_id = mine.vault_id AND m.status = 'active'
         JOIN sessions s ON s.user_id = m.user_id
         WHERE mine.user_id = $1 AND mine.status = 'active'
           AND (s.refresh_expires > $2 OR s.access_expires > $2)",
    )
    .bind(user_id)
    .bind(now())
    .fetch_all(&mut *conn)
    .await?;
    let mut by_vault: BTreeMap<String, bool> = BTreeMap::new();
    for (vault, client) in rows {
        *by_vault.entry(vault).or_insert(true) &= keeps_manifests(client.as_deref());
    }
    Ok(by_vault
        .into_iter()
        .filter_map(|(vault, ok)| (!ok).then_some(vault))
        .collect())
}

#[derive(Deserialize)]
pub(super) struct PutManifest {
    /// The vault's `manifest_seq` as the app's sync saw it (0 = none yet).
    base_seq: i64,
    /// The new version, above `base_seq` (and above what the app remembers).
    seq: i64,
    sealed: String,
    /// The vault's `seq` in the sync answer the manifest was computed from: any
    /// write since then makes it stale.
    vault_seq: i64,
}

/// `PUT /vaults/{id}/manifest` `{base_seq, seq, sealed, vault_seq}` (write access):
/// the vault's first manifest (`base_seq` 0) or a new baseline replacing the current
/// one, computed by the app from the complete item set of one sync answer. Refused
/// with 409 `manifest_conflict` when the vault was written since that answer
/// (`vault_seq`) or its manifest isn't at `base_seq`, and a first one with 409
/// `manifest_not_ready` while some member's signed-in app doesn't keep manifests.
/// Answers `{revision, vault_seq, manifest_seq}`.
pub(super) async fn put_manifest(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<PutManifest>,
) -> ApiResult<Json<Value>> {
    check_id(&id)?;
    check_sealed(b.seq, &b.sealed)?;
    if b.base_seq < 0 || b.seq <= b.base_seq {
        return Err(ApiError::bad("a manifest's version only goes up"));
    }
    let need = Need::new(&id, Role::Write, None);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let vault_seq = w.seq(&id);
    let current = w.manifest_seq(&id);
    if current != b.base_seq || vault_seq - 1 != b.vault_seq {
        return Err(ApiError::manifest_conflict());
    }
    if current == 0 && !may_start(w.conn(), &id).await? {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::MANIFEST_NOT_READY,
            "not every signed-in app of this vault's members is up to date yet",
        ));
    }
    w.store_manifest(&id, current, b.seq, &b.sealed).await?;
    let event = if current == 0 {
        Event::new("vault.manifest_started")
    } else {
        Event::new("vault.manifest_reset")
    };
    w.log(
        event
            .vault(&id)
            .data(json!({ "from": current, "to": b.seq })),
    )
    .await?;
    let revision = w.commit(&state).await?;
    Ok(Json(json!({
        "revision": revision,
        "vault_seq": vault_seq,
        "manifest_seq": b.seq,
    })))
}
