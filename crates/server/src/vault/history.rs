//! Item version history. Before an item is edited or moved to the trash, its
//! row as stored (encrypted key and data) is kept as a version, unless the
//! newest version already holds exactly that (trash then restore then edit keeps
//! one copy). A version's `seq` is the vault sequence number of the write that
//! saved that row, so it is unique per item and only grows; `saved_at` and
//! `saved_by` say when and by whom that row was saved. The newest
//! `item_versions_kept` (admin page, 0–100, default 10; 0 = off) are kept per
//! item and listed. Restoring a version is an ordinary `PUT /items/{id}` by the
//! client with the version's key and data.
//!
//! Versions are encrypted with the vault key of their time. A key replacement
//! re-encrypts only the current items, so it deletes the vault's versions; a
//! move to another vault deletes the item's versions (the new vault's members may
//! not have the old key); deleting an item for good, or its vault, deletes them
//! too. Versions count toward the vault owner's storage.

use axum::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{Role, require};
use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::settings::Num;
use crate::state::AppState;

/// Keep item `item_id`'s current row as a version (inside the write that is
/// about to change it), then only the newest `kept`.
pub(super) async fn save(conn: &mut AnyConnection, item_id: &str, kept: i64) -> ApiResult<()> {
    if kept > 0 {
        sqlx::query(
            "INSERT INTO item_versions (item_id, vault_id, seq, item_key, data, saved_at, saved_by)
             SELECT i.id, i.vault_id, i.seq, i.item_key, i.data, i.updated_at, i.updated_by
             FROM items i
             WHERE i.id = $1 AND NOT EXISTS (
                 SELECT 1 FROM item_versions v
                 WHERE v.item_id = i.id AND v.item_key = i.item_key AND v.data = i.data
                   AND v.seq = (SELECT MAX(n.seq) FROM item_versions n WHERE n.item_id = i.id))
             ON CONFLICT (item_id, seq) DO NOTHING",
        )
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(
        "DELETE FROM item_versions WHERE item_id = $1
         AND (SELECT COUNT(*) FROM item_versions n
              WHERE n.item_id = $1 AND n.seq > item_versions.seq) >= $2",
    )
    .bind(item_id)
    .bind(kept)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Delete every version of an item (deleted for good, or moved to another vault).
pub(super) async fn forget(conn: &mut AnyConnection, item_id: &str) -> ApiResult<()> {
    sqlx::query("DELETE FROM item_versions WHERE item_id = $1")
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Keep only the newest `item_versions_kept` versions of every item, after the
/// admin lowered it (each item is also trimmed at its next edit). Returns how
/// many were deleted.
pub async fn trim_versions(state: &AppState) -> ApiResult<u64> {
    let kept = state.num(Num::ItemVersionsKept);
    let done = sqlx::query(
        "DELETE FROM item_versions
         WHERE (SELECT COUNT(*) FROM item_versions n
                WHERE n.item_id = item_versions.item_id AND n.seq > item_versions.seq) >= $1",
    )
    .bind(kept)
    .execute(&state.db)
    .await?;
    if done.rows_affected() > 0 {
        tracing::info!(
            versions = done.rows_affected(),
            kept,
            "deleted item versions beyond the new limit"
        );
    }
    Ok(done.rows_affected())
}

/// The vault of an item the caller may read (404 otherwise).
async fn readable_item(state: &AppState, user: &AuthUser, item_id: &str) -> ApiResult<String> {
    let vault: Option<String> = sqlx::query_scalar("SELECT vault_id FROM items WHERE id = $1")
        .bind(item_id)
        .fetch_optional(&state.db)
        .await?;
    let vault = vault.ok_or(ApiError::NotFound)?;
    require(state, &user.user_id, &vault, Role::Read).await?;
    Ok(vault)
}

/// `{"id", "email", "name"}` of who saved a version (`null` when unknown, e.g.
/// rows saved before history existed).
fn saved_by(id: Option<String>, email: Option<String>, name: Option<String>) -> Value {
    id.map_or(
        Value::Null,
        |id| json!({ "id": id, "email": email, "name": name }),
    )
}

/// `GET /items/{id}/versions`: `{"versions": [{"seq", "saved_at", "saved_by"}]}`,
/// newest first, for any member of the item's vault.
pub(super) async fn list_versions(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let vault = readable_item(&state, &user, &id).await?;
    type Row = (i64, i64, Option<String>, Option<String>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT v.seq, v.saved_at, v.saved_by, u.email, u.name
         FROM item_versions v LEFT JOIN users u ON u.id = v.saved_by
         WHERE v.item_id = $1 AND v.vault_id = $2
         ORDER BY v.seq DESC LIMIT $3",
    )
    .bind(&id)
    .bind(&vault)
    .bind(state.num(Num::ItemVersionsKept))
    .fetch_all(&state.db)
    .await?;
    let versions: Vec<Value> = rows
        .into_iter()
        .map(|(seq, saved_at, by, email, name)| {
            json!({ "seq": seq, "saved_at": saved_at, "saved_by": saved_by(by, email, name) })
        })
        .collect();
    Ok(Json(json!({ "versions": versions })))
}

/// `GET /items/{id}/versions/{seq}`: one version as stored,
/// `{"seq", "vault_id", "item_key", "data", "saved_at", "saved_by"}`.
pub(super) async fn get_version(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, seq)): Path<(String, i64)>,
) -> ApiResult<Json<Value>> {
    let vault = readable_item(&state, &user, &id).await?;
    type Row = (
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT v.item_key, v.data, v.saved_at, v.saved_by, u.email, u.name
         FROM item_versions v LEFT JOIN users u ON u.id = v.saved_by
         WHERE v.item_id = $1 AND v.vault_id = $2 AND v.seq = $3
           AND (SELECT COUNT(*) FROM item_versions n WHERE n.item_id = $1 AND n.seq > $3) < $4",
    )
    .bind(&id)
    .bind(&vault)
    .bind(seq)
    .bind(state.num(Num::ItemVersionsKept))
    .fetch_optional(&state.db)
    .await?;
    let (item_key, data, saved_at, by, email, name) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "seq": seq,
        "vault_id": vault,
        "item_key": item_key,
        "data": data,
        "saved_at": saved_at,
        "saved_by": saved_by(by, email, name),
    })))
}
