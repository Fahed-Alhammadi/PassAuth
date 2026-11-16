//! Items: create (safe to retry), import, edit or move, trash, restore, purge,
//! and the sweeper that empties old trash. Each row remembers who saved it
//! (`updated_by`); an edit or trash first keeps the previous row as a version
//! (`history.rs`).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{
    MAX_ITEM_BLOB, Need, Role, VaultWrite, attachment_quota, check_id, check_item_blob, check_size,
    item_bytes, quota,
};
use super::{attachments, history};
use crate::auth::AuthUser;
use crate::db::{now, now_ms};
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::settings::Num;
use crate::state::AppState;

#[derive(Deserialize)]
pub(super) struct ItemBody {
    pub id: String,
    pub vault_id: String,
    pub key: String,
    pub data: String,
    /// Optimistic concurrency: reject if the stored revision differs.
    pub revision: Option<i64>,
    /// Key epoch of the vault key the item was encrypted with (of the target
    /// vault when moving); a replaced key gets 409 `vault_key_changed`.
    pub key_epoch: Option<i64>,
}

impl ItemBody {
    /// A new or edited item: an id and blobs within the admin's `max_item_kib`.
    fn check(&self, state: &AppState) -> ApiResult<()> {
        check_id(&self.id)?;
        check_item_blob(state, &self.key)?;
        check_item_blob(state, &self.data)
    }

    /// An item re-encrypted by a key rotation: only the hard ceiling, so a
    /// lowered `max_item_kib` never blocks replacing a vault key.
    pub(super) fn check_rotated(&self) -> ApiResult<()> {
        check_size(&self.key, MAX_ITEM_BLOB)?;
        check_size(&self.data, MAX_ITEM_BLOB)
    }

    fn bytes(&self) -> i64 {
        item_bytes(&self.key, &self.data)
    }
}

fn changed_elsewhere() -> ApiError {
    ApiError::revision_conflict("item changed on another device; sync and retry")
}

/// Insert `i` with sequence number `seq`, saved by user `by`. A create retried
/// after a lost response finds its own item (same vault, key and data) and gets
/// its stored revision back instead of an error; any other item with this id is
/// a 409 `item_exists`. Returns `None` when inserted, `Some(revision)` for such a
/// repeat.
async fn insert_item(
    conn: &mut AnyConnection,
    i: &ItemBody,
    rev: i64,
    seq: i64,
    by: Option<&str>,
) -> ApiResult<Option<i64>> {
    let done = sqlx::query(
        "INSERT INTO items (id, vault_id, item_key, data, revision, created_at, updated_at, seq, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&i.id)
    .bind(&i.vault_id)
    .bind(&i.key)
    .bind(&i.data)
    .bind(rev)
    .bind(now())
    .bind(seq)
    .bind(by)
    .execute(&mut *conn)
    .await?;
    if done.rows_affected() == 1 {
        return Ok(None);
    }
    let stored: Option<(String, String, String, i64)> =
        sqlx::query_as("SELECT vault_id, item_key, data, revision FROM items WHERE id = $1")
            .bind(&i.id)
            .fetch_optional(&mut *conn)
            .await?;
    match stored {
        Some((vault, key, data, revision))
            if vault == i.vault_id && key == i.key && data == i.data =>
        {
            Ok(Some(revision))
        }
        _ => Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::ITEM_EXISTS,
            "item id already exists",
        )),
    }
}

/// `{"id", "revision", "vault_seq"}`: `vault_seq` is the vault's sequence number
/// after the write (for a retried create that found its item, the current one).
pub(super) async fn create_item(
    State(state): State<AppState>,
    user: AuthUser,
    Json(i): Json<ItemBody>,
) -> ApiResult<Json<Value>> {
    i.check(&state)?;
    crate::disk::ensure_room(&state, i.bytes() as u64).await?;
    let need = Need::new(&i.vault_id, Role::Write, i.key_epoch);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let seq = w.seq(&i.vault_id);
    let rev = now_ms();
    let (revision, vault_seq) =
        match insert_item(w.conn(), &i, rev, seq, Some(&user.user_id)).await? {
            None => {
                w.untombstone(&i.vault_id).await?;
                w.charge(&i.vault_id, 1, i.bytes());
                w.log(Event::new("item.created").vault(&i.vault_id).item(&i.id))
                    .await?;
                w.commit(&state).await?;
                (rev, seq)
            }
            // Nothing to write: dropping `w` rolls back the lock and the number it took.
            Some(stored) => (stored, seq - 1),
        };
    Ok(Json(
        json!({ "id": i.id, "revision": revision, "vault_seq": vault_seq }),
    ))
}

#[derive(Deserialize)]
pub(super) struct Import {
    items: Vec<ItemBody>,
}

/// Up to the admin's `max_import_items` new items, all or nothing. Items
/// already stored exactly like this (a retried import) count as imported.
/// Answers `{"imported", "vault_seqs": {vault: seq}}`, plus `vault_seq` when
/// every item went into one vault (the usual case).
pub(super) async fn import_items(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Import>,
) -> ApiResult<Json<Value>> {
    let max = state.num(Num::MaxImportItems);
    if b.items.len() as i64 > max {
        return Err(ApiError::bad(format!(
            "import at most {max} items at a time"
        )));
    }
    for i in &b.items {
        i.check(&state)?;
    }
    let bytes: i64 = b.items.iter().map(ItemBody::bytes).sum();
    crate::disk::ensure_room(&state, bytes as u64).await?;
    let needs: Vec<Need> = b
        .items
        .iter()
        .map(|i| Need::new(&i.vault_id, Role::Write, i.key_epoch))
        .collect();
    let mut w = VaultWrite::begin(&state, &user, &needs).await?;
    let rev = now_ms();
    let mut seqs: BTreeMap<String, i64> = BTreeMap::new();
    // Items created in each vault (a retried import may find some already there).
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for i in &b.items {
        let seq = w.seq(&i.vault_id);
        seqs.insert(i.vault_id.clone(), seq);
        let count = counts.entry(i.vault_id.clone()).or_default();
        if insert_item(w.conn(), i, rev, seq, Some(&user.user_id))
            .await?
            .is_none()
        {
            *count += 1;
            w.charge(&i.vault_id, 1, i.bytes());
        }
    }
    let created: i64 = counts.values().sum();
    if created > 0 {
        for vault in seqs.keys() {
            w.untombstone(vault).await?;
        }
        for (vault, count) in counts.into_iter().filter(|(_, n)| *n > 0) {
            w.log(
                Event::new("item.imported")
                    .vault(&vault)
                    .data(json!({ "count": count })),
            )
            .await?;
        }
        w.commit(&state).await?;
    } else {
        // Nothing written: every vault keeps its current number.
        seqs.values_mut().for_each(|s| *s -= 1);
    }
    let mut out = json!({ "imported": b.items.len(), "vault_seqs": seqs });
    if let [(_, seq)] = seqs.iter().collect::<Vec<_>>()[..] {
        out["vault_seq"] = (*seq).into();
    }
    Ok(Json(out))
}

async fn item_vault(state: &AppState, id: &str) -> ApiResult<(String, i64)> {
    sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Edit an item, or move it to another vault (write access to both). A move
/// takes a sequence number in both vaults and leaves a tombstone in the old one;
/// `vault_seq` in the answer is the item's (new) vault's.
pub(super) async fn update_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(i): Json<ItemBody>,
) -> ApiResult<Json<Value>> {
    if i.id != id {
        return Err(ApiError::bad("id mismatch"));
    }
    check_item_blob(&state, &i.key)?;
    check_item_blob(&state, &i.data)?;
    crate::disk::ensure_room(&state, i.bytes() as u64).await?;
    let (old_vault, current) = item_vault(&state, &id).await?;
    let needs = [
        Need::new(&old_vault, Role::Write, None),
        Need::new(&i.vault_id, Role::Write, i.key_epoch),
    ];
    let mut w = VaultWrite::begin(&state, &user, &needs).await?;
    if i.revision.is_some_and(|r| r != current) {
        return Err(changed_elsewhere());
    }
    let moved = old_vault != i.vault_id;
    // Its size before the edit, for the owners' storage (only with quotas on); a
    // move also takes its ready attachments to the new vault's owner.
    let quotas_on = quota(&state) != (0, 0) || attachment_quota(&state) > 0;
    let old_bytes: Option<i64> = if quotas_on {
        sqlx::query_scalar(
            "SELECT CAST(octet_length(item_key) + octet_length(data) AS BIGINT) FROM items WHERE id = $1",
        )
        .bind(&id)
        .fetch_optional(w.conn())
        .await?
    } else {
        None
    };
    let attached = if moved && old_bytes.is_some() {
        attachments::item_bytes(w.conn(), &id).await?
    } else {
        0
    };
    let seq = w.seq(&i.vault_id);
    let rev = now_ms();
    // The row as it is now becomes a version. A move starts the history afresh:
    // earlier versions are encrypted with the old vault's key, which the new
    // vault's members may not have (as after a key replacement).
    let kept = w.versions_kept;
    if moved {
        history::forget(w.conn(), &id).await?;
    } else {
        history::save(w.conn(), &id, kept).await?;
    }
    // Conditional on the vault and revision read above: an edit or move that
    // committed in between makes this a conflict instead of a lost update.
    let done = sqlx::query(
        "UPDATE items SET vault_id = $1, item_key = $2, data = $3, revision = $4, updated_at = $5, seq = $6,
                          updated_by = $7
         WHERE id = $8 AND vault_id = $9 AND revision = $10",
    )
    .bind(&i.vault_id)
    .bind(&i.key)
    .bind(&i.data)
    .bind(rev)
    .bind(now())
    .bind(seq)
    .bind(&user.user_id)
    .bind(&id)
    .bind(&old_vault)
    .bind(current)
    .execute(w.conn())
    .await?;
    if done.rows_affected() != 1 {
        return Err(changed_elsewhere());
    }
    if moved {
        attachments::follow_item(w.conn(), &id, &i.vault_id).await?;
        w.tombstone(&old_vault, &id).await?;
        w.untombstone(&i.vault_id).await?;
        w.log(
            Event::new("item.moved")
                .vault(&old_vault)
                .item(&id)
                .data(json!({ "to": i.vault_id })),
        )
        .await?;
        w.log(
            Event::new("item.moved")
                .vault(&i.vault_id)
                .item(&id)
                .data(json!({ "from": old_vault })),
        )
        .await?;
    } else {
        w.log(Event::new("item.updated").vault(&i.vault_id).item(&id))
            .await?;
    }
    if let Some(old) = old_bytes {
        w.charge(&old_vault, -1, -old);
        w.charge(&i.vault_id, 1, i.bytes());
        w.charge_files(&old_vault, -attached);
        w.charge_files(&i.vault_id, attached);
    }
    w.commit(&state).await?;
    Ok(Json(json!({ "id": id, "revision": rev, "vault_seq": seq })))
}

/// Optional optimistic-concurrency check for trash / restore / purge.
#[derive(Deserialize)]
pub(super) struct RevisionQuery {
    revision: Option<i64>,
}

async fn set_deleted(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    expected: Option<i64>,
    deleted_at: Option<i64>,
) -> ApiResult<Json<Value>> {
    let (vault, current) = item_vault(state, id).await?;
    let need = Need::new(&vault, Role::Write, None);
    let mut w = VaultWrite::begin(state, user, &[need]).await?;
    if expected.is_some_and(|r| r != current) {
        return Err(changed_elsewhere());
    }
    let seq = w.seq(&vault);
    let rev = now_ms();
    if deleted_at.is_some() {
        let kept = w.versions_kept;
        history::save(w.conn(), id, kept).await?;
    }
    let done = sqlx::query(
        "UPDATE items SET deleted_at = $1, revision = $2, updated_at = $3, seq = $4
         WHERE id = $5 AND vault_id = $6 AND revision = $7",
    )
    .bind(deleted_at)
    .bind(rev)
    .bind(now())
    .bind(seq)
    .bind(id)
    .bind(&vault)
    .bind(current)
    .execute(w.conn())
    .await?;
    if done.rows_affected() != 1 {
        return Err(changed_elsewhere());
    }
    let kind = if deleted_at.is_some() {
        "item.trashed"
    } else {
        "item.restored"
    };
    w.log(Event::new(kind).vault(&vault).item(id)).await?;
    w.commit(state).await?;
    Ok(Json(json!({ "id": id, "revision": rev, "vault_seq": seq })))
}

pub(super) async fn trash_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    set_deleted(&state, &user, &id, q.revision, Some(now())).await
}

pub(super) async fn restore_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    set_deleted(&state, &user, &id, q.revision, None).await
}

pub(super) async fn purge_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let (vault, current) = item_vault(&state, &id).await?;
    let need = Need::new(&vault, Role::Write, None);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    if q.revision.is_some_and(|r| r != current) {
        return Err(changed_elsewhere());
    }
    let done = sqlx::query("DELETE FROM items WHERE id = $1 AND vault_id = $2 AND revision = $3")
        .bind(&id)
        .bind(&vault)
        .bind(current)
        .execute(w.conn())
        .await?;
    if done.rows_affected() != 1 {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM items WHERE id = $1")
            .bind(&id)
            .fetch_one(w.conn())
            .await?;
        return Err(if exists > 0 {
            changed_elsewhere()
        } else {
            ApiError::NotFound
        });
    }
    w.tombstone(&vault, &id).await?;
    history::forget(w.conn(), &id).await?;
    let files = attachments::detach_item(w.conn(), &id).await?;
    w.log(Event::new("item.deleted").vault(&vault).item(&id))
        .await?;
    let vault_seq = w.seq(&vault);
    let revision = w.commit(&state).await?;
    attachments::remove_files(&state, &files).await;
    Ok(Json(
        json!({ "revision": revision, "vault_seq": vault_seq }),
    ))
}

/// Permanently delete items that have been in the trash longer than the
/// admin's `trash_days` (0 = keep them). Each vault is locked like any other
/// write, so a restore in progress wins, and its members re-sync. Returns how
/// many items were deleted.
pub async fn purge_trash(state: &AppState) -> ApiResult<u64> {
    let days = state.trash_days();
    if days <= 0 {
        return Ok(0);
    }
    let cutoff = now() - days * 86_400;
    let vaults: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT vault_id FROM items WHERE deleted_at IS NOT NULL AND deleted_at < $1
         ORDER BY vault_id",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;
    let mut purged = 0;
    for vault in vaults {
        let mut w = match VaultWrite::system(state, &vault).await {
            Ok(w) => w,
            Err(ApiError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        // Tombstones first, for apps that sync changes only.
        let seq = w.seq(&vault);
        sqlx::query(
            "INSERT INTO item_tombstones (vault_id, item_id, seq, deleted_at)
             SELECT vault_id, id, $2, $3 FROM items
             WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at < $4
             ON CONFLICT (vault_id, item_id) DO UPDATE SET seq = excluded.seq, deleted_at = excluded.deleted_at",
        )
        .bind(&vault)
        .bind(seq)
        .bind(now())
        .bind(cutoff)
        .execute(w.conn())
        .await?;
        sqlx::query(
            "DELETE FROM item_versions WHERE item_id IN
               (SELECT id FROM items WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at < $2)",
        )
        .bind(&vault)
        .bind(cutoff)
        .execute(w.conn())
        .await?;
        let files = attachments::detach_trash(w.conn(), &vault, cutoff).await?;
        let done = sqlx::query(
            "DELETE FROM items WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at < $2",
        )
        .bind(&vault)
        .bind(cutoff)
        .execute(w.conn())
        .await?;
        if done.rows_affected() > 0 {
            purged += done.rows_affected();
            w.log(
                Event::new("trash.emptied")
                    .vault(&vault)
                    .data(json!({ "count": done.rows_affected(), "days": days })),
            )
            .await?;
            w.commit(state).await?;
            attachments::remove_files(state, &files).await;
        }
    }
    if purged > 0 {
        tracing::info!(
            items = purged,
            days,
            "deleted items kept in the trash too long"
        );
    }
    Ok(purged)
}
