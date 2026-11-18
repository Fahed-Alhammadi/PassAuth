//! Vault manifests (migration 17, feature `vault_manifest`): a small record of what a
//! vault holds, sealed by the apps with a key made from the vault key, so the apps
//! can tell when the server's copy of a vault isn't the one its members wrote (an
//! older item, a hidden or resurrected one). The server can't read it; it stores
//! the sealed text, its version (`vaults.manifest`, `manifest_seq`, 0 = none) and
//! the link of the manifest it replaced (`manifest_prev`), hands them out with every
//! vault row of `/sync`, and replaces them only as part of the write they describe:
//!
//! - once a vault has a manifest, every write that changes its items (create,
//!   import, edit, move, trash, restore, delete for good, key replacement) carries
//!   the next one, exactly one version up and naming the current one as its
//!   predecessor, stored in the same transaction
//!   ([`super::VaultWrite::manifests`]); a write without it is refused, also from
//!   apps that don't know manifests yet;
//! - `PUT /vaults/{id}/manifest` starts a vault's first manifest, or replaces it
//!   with a new baseline (a member's "Use the server's copy" when the stored
//!   manifest doesn't open or doesn't match the items). Both are exactly one version
//!   up, like every other write: no request can make a version jump, so no member
//!   can push a vault's version towards its ceiling. A first one waits until every
//!   signed-in app of every member who can write keeps manifests ([`may_start`],
//!   `manifest_ok` in `/sync`), so no app is locked out of writing by surprise; a
//!   baseline is limited to [`BASELINES_PER_HOUR`] per member and vault;
//! - the server never changes the items of a vault with a manifest by itself: the
//!   trash sweeper leaves such vaults to the apps (`items::purge_trash`).
//!
//! The chain (security review): a manifest's link is a hash over its version, the
//! link of its predecessor and the hash of its sealed text (`passauth_core::manifest`),
//! and the apps seal `prev` into the manifest. An app that remembers the last
//! manifest it saw accepts a newer one only when it descends from that one. For a
//! manifest more than one step ahead it follows the hashes through the vault's log
//! (`vault_manifest_log`, `GET /vaults/{id}/manifest-log`): one entry `(seq, prev,
//! digest)` per stored manifest, kept by age and count ([`LOG_KEEP`]). The server
//! checks only that a new manifest names the current one ([`super::VaultWrite`]); an
//! honest server so never stores a manifest off the chain, and a dishonest one
//! gains nothing from doing it, since the apps check the hashes themselves.
//!
//! Every answer of a write that can carry a manifest names the link of the vault's
//! manifest after the request (`manifest_link`, [`super::VaultWrite::manifest_link`]):
//! an app applies its write to its own copy only when that is the link of the
//! manifest it sent. A version number alone can't tell a stored write from a retried
//! one that found its item already there under another sealing of the manifest.
//!
//! Attachments and item history are separate tables and are not covered.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use passauth_core::manifest::NO_LINK;
pub(super) use passauth_core::manifest::{Link, link, parse_link, sealed_digest};

use super::{Need, Role, VaultWrite, check_id, require};
use crate::auth::{AuthUser, keeps_manifests};
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::state::{AppState, Class};

/// The largest manifest version: whole numbers every app carries exactly.
const MAX_SEQ: i64 = 9_007_199_254_740_991;
/// A sealed manifest is about 200 characters.
const MAX_SEALED: usize = 1024;
/// New baselines (`PUT /vaults/{id}/manifest` on a vault that has a manifest) one
/// member may store in one vault within an hour. A baseline is a rare, deliberate
/// act (one settles a vault for every device on its history), each one writes an
/// activity-log entry every member sees, and a member's app gone wrong shouldn't
/// write them in a loop. Counted per member, not per vault: with one budget for
/// the vault, a member who used it up could keep everyone else from repairing a
/// manifest that same member broke with an ordinary write. First manifests aren't
/// counted (a vault has one).
pub(crate) const BASELINES_PER_HOUR: u32 = 10;

/// What a vault's manifest log keeps: how far behind a device may be and still
/// follow the chain to the current manifest. Further behind, its app shows the
/// vault's warning (it can't tell a pruned log from a withheld one) until its user
/// accepts the server's copy on that device.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LogKeep {
    /// The newest entries, whatever their age.
    pub newest: i64,
    /// Every entry younger than this many seconds: a burst of writes can't cut off
    /// a device that was away for a short while…
    pub age: i64,
    /// …up to this many entries in all; the oldest go first beyond it.
    pub most: i64,
}

pub(crate) const LOG_KEEP: LogKeep = LogKeep {
    newest: 5000,
    age: 90 * 86_400,
    most: 200_000,
};

/// The log is pruned with every this-many-th manifest of a vault, not with each:
/// the entries to drop are found by walking the old end of the log, which a busy
/// vault shouldn't pay for on every write. The bounds of [`LOG_KEEP`] are so
/// exceeded by at most this many entries.
const LOG_PRUNE_EVERY: i64 = 64;
/// Log entries in one answer of `GET /vaults/{id}/manifest-log`.
const LOG_PAGE: i64 = 2000;

/// A vault's next manifest, as a write carries it (`manifests: [{vault_id, seq,
/// prev, sealed}]`).
#[derive(Deserialize)]
pub(super) struct ManifestIn {
    pub vault_id: String,
    pub seq: i64,
    /// The link of the manifest it replaces (base64url, 32 bytes).
    pub prev: String,
    pub sealed: String,
}

impl ManifestIn {
    /// Shape checks that need no database: one entry a vault, a version and a
    /// base64url text of a plausible size.
    pub(super) fn check_all(sent: &[ManifestIn]) -> ApiResult<()> {
        let mut vaults = BTreeSet::new();
        for m in sent {
            check_sealed(m.seq, &m.prev, &m.sealed)?;
            if !vaults.insert(m.vault_id.as_str()) {
                return Err(ApiError::bad("one manifest for each vault"));
            }
        }
        Ok(())
    }
}

fn check_sealed(seq: i64, prev: &str, sealed: &str) -> ApiResult<()> {
    let text = !sealed.is_empty()
        && sealed.len() <= MAX_SEALED
        && sealed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !(1..=MAX_SEQ).contains(&seq) || !text || parse_link(prev).is_err() {
        return Err(ApiError::bad("invalid manifest"));
    }
    Ok(())
}

/// The link of a vault's stored manifest: what its next one must name as `prev`.
/// All zero for a vault without one.
pub(super) fn head_link(seq: i64, prev: Option<&str>, sealed: Option<&str>) -> Link {
    match (u64::try_from(seq), prev.map(parse_link), sealed) {
        (Ok(seq @ 1..), Some(Ok(prev)), Some(sealed)) => link(seq, &prev, &sealed_digest(sealed)),
        _ => NO_LINK,
    }
}

/// Add a stored manifest to its vault's log, and now and then drop what the log no
/// longer keeps ([`LOG_KEEP`], [`LOG_PRUNE_EVERY`]).
pub(super) async fn log(
    conn: &mut AnyConnection,
    vault: &str,
    seq: i64,
    prev: &str,
    digest: &[u8; 32],
) -> ApiResult<()> {
    let t = now();
    sqlx::query(
        "INSERT INTO vault_manifest_log (vault_id, seq, prev, digest, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(vault)
    .bind(seq)
    .bind(prev)
    .bind(passauth_core::item::b64(digest))
    .bind(t)
    .execute(&mut *conn)
    .await?;
    if seq % LOG_PRUNE_EVERY == 0 {
        prune_log(conn, vault, seq, LOG_KEEP, t).await?;
    }
    Ok(())
}

/// Drop from the log of a vault whose newest manifest is version `head` what `keep`
/// doesn't hold at time `t`: entries that are neither among the newest `keep.newest`
/// nor younger than `keep.age`, and everything beyond the newest `keep.most`.
/// Versions go up by exactly one per stored manifest, so "the newest n" are the
/// versions above `head - n`.
pub(crate) async fn prune_log(
    conn: &mut AnyConnection,
    vault: &str,
    head: i64,
    keep: LogKeep,
    t: i64,
) -> ApiResult<()> {
    sqlx::query(
        "DELETE FROM vault_manifest_log
         WHERE vault_id = $1 AND (seq <= $2 OR (seq <= $3 AND created_at < $4))",
    )
    .bind(vault)
    .bind(head - keep.most)
    .bind(head - keep.newest)
    .bind(t - keep.age)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct LogQuery {
    /// Entries above this version (default 0: from the oldest kept).
    #[serde(default)]
    after: i64,
    /// At most this many entries (1…[`LOG_PAGE`], the default).
    limit: Option<i64>,
}

/// `GET /vaults/{id}/manifest-log?after=<seq>` (any member; 404 for others):
/// `{"entries": [{seq, prev, digest}], "more"}`: the vault's manifests above version
/// `after`, oldest first, at most [`LOG_PAGE`] an answer or `limit` if that is less
/// (`more`: ask again with `after` = the last `seq`). `prev` is the link of the manifest an entry replaced
/// and `digest` the SHA-256 of its sealed text, both base64url. An app that
/// remembers version N asks with `after=N` to follow the chain from there to the
/// manifest its sync answer shows; entries the log no longer keeps ([`LOG_KEEP`]) are
/// gone. Nothing here is secret from a member, and nothing in it is trusted by the
/// apps beyond what the hashes prove.
pub(super) async fn get_log(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<Value>> {
    check_id(&id)?;
    require(&state, &user.user_id, &id, Role::Read).await?;
    let page = q.limit.unwrap_or(LOG_PAGE);
    if q.after < 0 || !(1..=LOG_PAGE).contains(&page) {
        return Err(ApiError::bad("invalid manifest log range"));
    }
    let mut rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT seq, prev, digest FROM vault_manifest_log
         WHERE vault_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
    )
    .bind(&id)
    .bind(q.after)
    .bind(page + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() as i64 > page;
    rows.truncate(page as usize);
    let entries: Vec<Value> = rows
        .into_iter()
        .map(|(seq, prev, digest)| json!({ "seq": seq, "prev": prev, "digest": digest }))
        .collect();
    Ok(Json(json!({ "entries": entries, "more": more })))
}

/// The manifest of a write that names it in its query (`manifest_seq`,
/// `manifest_prev`, `manifest`: trash, restore, delete for good), for the item's vault.
pub(super) fn from_query(
    vault: &str,
    seq: Option<i64>,
    prev: Option<String>,
    sealed: Option<String>,
) -> ApiResult<Vec<ManifestIn>> {
    let sent = match (seq, prev, sealed) {
        (None, None, None) => Vec::new(),
        (Some(seq), Some(prev), Some(sealed)) => vec![ManifestIn {
            vault_id: vault.to_owned(),
            seq,
            prev,
            sealed,
        }],
        _ => {
            return Err(ApiError::bad(
                "manifest_seq, manifest_prev and manifest go together",
            ));
        }
    };
    ManifestIn::check_all(&sent)?;
    Ok(sent)
}

/// Whether `vault` may get its first manifest: every active session of every
/// active member who can write comes from an app that keeps manifests (members
/// who only read never send one, so their apps don't hold it off).
async fn may_start(conn: &mut AnyConnection, vault: &str) -> ApiResult<bool> {
    let clients: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT DISTINCT s.client FROM vault_members m JOIN sessions s ON s.user_id = m.user_id
         WHERE m.vault_id = $1 AND m.status = 'active' AND m.role <> 'read'
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
              AND m.role <> 'read'
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
    /// The new version: `base_seq + 1`.
    seq: i64,
    /// The link of the manifest it replaces: all zero for a first one, else the link
    /// of the vault row's current manifest as the app's sync showed it.
    prev: String,
    sealed: String,
    /// The vault's `seq` in the sync answer the manifest was computed from: any
    /// write since then makes it stale.
    vault_seq: i64,
}

/// `PUT /vaults/{id}/manifest` `{base_seq, seq, prev, sealed, vault_seq}` (write
/// access): the vault's first manifest (`base_seq` 0, `seq` 1) or a new baseline
/// replacing the current one (`seq` = `base_seq + 1`), computed by the app from the
/// complete item set of one sync answer. A baseline stays on the chain: it names the
/// manifest it replaces like any other and is one version above it, so devices on
/// the replaced history follow it by themselves; a device that saw another history,
/// or a later version on one the server no longer has, keeps its warning until its
/// user accepts the server's copy there (which needs no request). Refused with 400
/// when `seq` isn't `base_seq + 1`; with 409 `manifest_conflict` when the vault was
/// written since that answer (`vault_seq`), its manifest isn't at `base_seq` or `prev`
/// isn't the current manifest's link; a first one with 409 `manifest_not_ready`
/// while the signed-in app of some member who can write doesn't keep manifests; a
/// baseline with 429 beyond [`BASELINES_PER_HOUR`] of this member in this vault.
/// Answers `{revision, vault_seq, manifest_seq, manifest_link}`.
pub(super) async fn put_manifest(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<PutManifest>,
) -> ApiResult<Json<Value>> {
    check_id(&id)?;
    check_sealed(b.seq, &b.prev, &b.sealed)?;
    // One version up, always: a first manifest is version 1, a baseline the next
    // one. (`seq` is at most `MAX_SEQ`, so the sum can't overflow.)
    if b.base_seq < 0 || b.seq - 1 != b.base_seq {
        return Err(ApiError::bad(
            "a new manifest is one version above the current one",
        ));
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
    w.store_manifest(&id, current, b.seq, &b.prev, &b.sealed)
        .await?;
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
    if current > 0 {
        // Counted only once every check passed and the baseline is stored in this
        // transaction, before the commit: a refused request (a conflict, a stale
        // sync) costs nothing, an over-limit one rolls back. The key names a vault
        // and a member the request has proven to exist (a [`Class::Target`] key).
        state.limiter.limit(
            Class::Target,
            &format!("manifest-baseline:{id}:{}", user.user_id),
            BASELINES_PER_HOUR,
            3600,
        )?;
    }
    let manifest_link = w.manifest_link(&id);
    let revision = w.commit(&state).await?;
    Ok(Json(json!({
        "revision": revision,
        "vault_seq": vault_seq,
        "manifest_seq": b.seq,
        "manifest_link": manifest_link,
    })))
}
