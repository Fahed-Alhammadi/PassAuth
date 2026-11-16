//! Attachments: files an app encrypts, each with a random key of its own, and lists
//! with that key, its name and its size inside the encrypted item
//! (`attachments: [{id, name, size, key}]`). The server stores each file's
//! ciphertext under the attachment's id (`files.rs`) and keeps one row per file:
//! its item and vault, its encrypted size, who added it, and whether its upload
//! finished (`pending` → `ready`). It never sees a file's name, key or contents.
//!
//! Adding one: `POST /items/{id}/attachments {id, size}` (write access to the item's
//! vault; `size` is the encrypted size, within `max_attachment_mb`; while pending it
//! counts toward the storage and attachment limits of whoever added it, and once
//! ready toward the vault owner's) makes a pending row; `PUT /attachments/{id}` by
//! the same user with exactly `size` bytes (streamed to disk, refused as soon as it
//! runs over or once it takes longer than `files::upload_deadline`) makes it ready;
//! then the app saves the item with the attachment in its list. Both steps first
//! check the server keeps its free-disk reserve (`disk.rs`, 507).
//! `GET /attachments/{id}` sends a ready file to any active member of the item's vault,
//! `GET /items/{id}/attachments` lists an item's files, `DELETE /attachments/{id}`
//! (write access) deletes one. Every change is a `VaultWrite` like any vault write;
//! when a file becomes ready or goes, the item's row takes the write's sequence
//! number (its content and revision stay), so apps that sync changes get the item
//! again and notice.
//!
//! The files follow their item: trashing keeps them; deleting the item for good, its
//! vault or its owner's account, and the trash sweeper delete them; moving the item
//! to another vault moves the rows (the files stay as they are, and the new vault's
//! owner is charged for them). A key replacement re-encrypts the items, so the file
//! keys inside them are wrapped anew, but the files themselves are not re-encrypted:
//! someone who kept a file's key and its ciphertext could still read that file after
//! leaving the vault. The sweeper deletes uploads left pending for an hour and files
//! without a row.

use std::collections::HashSet;
use std::io;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{Need, Role, VaultWrite, require};
use crate::auth::AuthUser;
use crate::db::{is_postgres, now};
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::files::{Busy, FileStore, UploadError, canonical_id};
use crate::settings::{Flag, Num};
use crate::state::{AppState, Class};

/// `attachments.state` until the upload has finished.
const PENDING: &str = "pending";
/// `attachments.state` once the file is stored.
const READY: &str = "ready";
/// Pending uploads not touched (made or started) for this long are deleted.
pub const PENDING_TTL: i64 = 3600;
/// New attachments per user per hour.
const CREATES_PER_HOUR: u32 = 1000;

fn disabled() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        code::ATTACHMENTS_DISABLED,
        "attachments are turned off on this server",
    )
}

/// The store, for adding files: attachments must be on and have a folder.
fn store_for_new(state: &AppState) -> ApiResult<&FileStore> {
    match &state.files {
        Some(store) if state.flag(Flag::Attachments) => Ok(store),
        _ => Err(disabled()),
    }
}

fn too_large(message: String) -> ApiError {
    ApiError::coded(StatusCode::PAYLOAD_TOO_LARGE, code::TOO_LARGE, message)
}

fn already_uploaded() -> ApiError {
    ApiError::coded(
        StatusCode::CONFLICT,
        code::ALREADY_UPLOADED,
        "this attachment was already uploaded",
    )
}

/// A row with who added it.
#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    item_id: String,
    vault_id: String,
    size: i64,
    state: String,
    created_at: i64,
    created_by: String,
    updated_at: i64,
    email: Option<String>,
    name: Option<String>,
}

macro_rules! select {
    ($filter:literal) => {
        concat!(
            "SELECT a.id, a.item_id, a.vault_id, a.size, a.state, a.created_at, a.created_by,
                    a.updated_at, u.email, u.name
             FROM attachments a LEFT JOIN users u ON u.id = a.created_by
             WHERE ",
            $filter
        )
    };
}

/// `{"id", "item_id", "vault_id", "size", "state", "created_at", "updated_at",
/// "created_by": {"id", "email", "name"}}` (`email` and `name` are `null` once
/// that account is deleted).
fn to_json(r: &Row) -> Value {
    json!({
        "id": r.id,
        "item_id": r.item_id,
        "vault_id": r.vault_id,
        "size": r.size,
        "state": r.state,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
        "created_by": { "id": r.created_by, "email": r.email, "name": r.name },
    })
}

async fn load(conn: &mut AnyConnection, id: &str) -> ApiResult<Option<Row>> {
    Ok(sqlx::query_as(select!("a.id = $1"))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?)
}

/// Lock the vault item `item_id` is in, for a write by `user` with at least `min`,
/// following the item should it move meanwhile. Returns the write and the vault.
async fn lock_item(
    state: &AppState,
    user: &AuthUser,
    item_id: &str,
    min: Role,
) -> ApiResult<(VaultWrite, String)> {
    for _ in 0..3 {
        let vault: String = sqlx::query_scalar("SELECT vault_id FROM items WHERE id = $1")
            .bind(item_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError::NotFound)?;
        let mut w = VaultWrite::begin(state, user, &[Need::new(&vault, min, None)]).await?;
        let now_in: Option<String> = sqlx::query_scalar("SELECT vault_id FROM items WHERE id = $1")
            .bind(item_id)
            .fetch_optional(w.conn())
            .await?;
        match now_in {
            Some(v) if v == vault => return Ok((w, vault)),
            // Moved while this write waited for the lock: lock its new vault.
            Some(_) => continue,
            None => return Err(ApiError::NotFound),
        }
    }
    Err(ApiError::Conflict(
        "the item keeps moving; try again".into(),
    ))
}

/// Lock the vault attachment `id` is in (as [`lock_item`]); the write and the row.
async fn lock_attachment(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    min: Role,
) -> ApiResult<(VaultWrite, Row)> {
    for _ in 0..3 {
        let vault: String = sqlx::query_scalar("SELECT vault_id FROM attachments WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError::NotFound)?;
        let mut w = VaultWrite::begin(state, user, &[Need::new(&vault, min, None)]).await?;
        let row = load(w.conn(), id).await?.ok_or(ApiError::NotFound)?;
        if row.vault_id == vault {
            return Ok((w, row));
        }
    }
    Err(ApiError::Conflict(
        "the item keeps moving; try again".into(),
    ))
}

/// The item's row takes this write's sequence number in its vault (content and
/// revision unchanged), so apps that sync changes get it again: its files changed.
async fn stamp(w: &mut VaultWrite, vault: &str, item: &str) -> ApiResult<()> {
    let seq = w.seq(vault);
    sqlx::query("UPDATE items SET seq = $1 WHERE id = $2 AND vault_id = $3")
        .bind(seq)
        .bind(item)
        .bind(vault)
        .execute(w.conn())
        .await?;
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct NewAttachment {
    /// Chosen by the app (a UUID; the server answers in lowercase).
    id: String,
    /// Bytes of the encrypted file the app will upload.
    size: i64,
}

/// `POST /items/{id}/attachments {id, size}`: a pending attachment, answered with
/// `{"attachment", "revision", "vault_seq"}`. Safe to retry: the same id for the
/// same item and size answers the stored attachment (nothing written, the vault's
/// current number); the id for anything else is a 409 `attachment_exists`.
pub(super) async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(item_id): Path<String>,
    Json(b): Json<NewAttachment>,
) -> ApiResult<Json<Value>> {
    store_for_new(&state)?;
    let id = canonical_id(&b.id).ok_or_else(|| ApiError::bad("attachment ids must be UUIDs"))?;
    let max_mb = state.num(Num::MaxAttachmentMb);
    if b.size < 1 {
        return Err(ApiError::bad("size must be at least 1 byte"));
    }
    if b.size > max_mb * 1024 * 1024 {
        return Err(too_large(format!(
            "attachments may be at most {max_mb} MB on this server"
        )));
    }
    state.limiter.limit(
        Class::Target,
        &format!("attachment:{}", user.user_id),
        CREATES_PER_HOUR,
        3600,
    )?;
    crate::disk::ensure_room(&state, b.size as u64).await?;
    let (mut w, vault) = lock_item(&state, &user, &item_id, Role::Write).await?;
    let seq = w.seq(&vault);
    let t = now();
    let done = sqlx::query(
        "INSERT INTO attachments (id, item_id, vault_id, size, state, created_at, created_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $6) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&id)
    .bind(&item_id)
    .bind(&vault)
    .bind(b.size)
    .bind(PENDING)
    .bind(t)
    .bind(&user.user_id)
    .execute(w.conn())
    .await?;
    let row = load(w.conn(), &id).await?.ok_or(ApiError::NotFound)?;
    if done.rows_affected() == 0 {
        if row.item_id != item_id || row.size != b.size {
            return Err(ApiError::coded(
                StatusCode::CONFLICT,
                code::ATTACHMENT_EXISTS,
                "attachment id already exists",
            ));
        }
        // An earlier try landed: nothing to write (dropping `w` rolls back the number it took).
        drop(w);
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
        return Ok(Json(json!({
            "attachment": to_json(&row), "revision": revision, "vault_seq": seq - 1,
        })));
    }
    // Pending: whoever adds it pays until it is ready.
    w.charge_uploader(&user.user_id, b.size);
    let revision = w.commit(&state).await?;
    Ok(Json(json!({
        "attachment": to_json(&row), "revision": revision, "vault_seq": seq,
    })))
}

/// `GET /items/{id}/attachments`: `{"attachments": [...]}`, oldest first, pending ones
/// included, for any member of the item's vault. The item's own list (encrypted)
/// says which belong to it; this says which exist on the server.
pub(super) async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(item_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let vault: String = sqlx::query_scalar("SELECT vault_id FROM items WHERE id = $1")
        .bind(&item_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    require(&state, &user.user_id, &vault, Role::Read).await?;
    let rows: Vec<Row> = sqlx::query_as(select!(
        "a.item_id = $1 AND a.vault_id = $2 ORDER BY a.created_at, a.id"
    ))
    .bind(&item_id)
    .bind(&vault)
    .fetch_all(&state.db)
    .await?;
    let attachments: Vec<Value> = rows.iter().map(to_json).collect();
    Ok(Json(json!({ "attachments": attachments })))
}

/// The request's `Content-Length`, when it sent one.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

fn upload_error(e: UploadError) -> ApiError {
    match e {
        UploadError::TooLong => too_large("the upload is larger than the attachment's size".into()),
        UploadError::TooShort(n) => ApiError::bad(format!(
            "the upload ended after {n} bytes, short of the attachment's size"
        )),
        UploadError::Stalled => ApiError::bad("the upload stalled"),
        UploadError::TooSlow(secs) => ApiError::bad(format!(
            "the upload was too slow: this file must arrive within {secs} seconds"
        )),
        UploadError::Interrupted => ApiError::bad("the upload was interrupted"),
        UploadError::Io(e) => {
            ApiError::Internal(anyhow::Error::from(e).context("writing an attachment"))
        }
    }
}

fn busy(state: &AppState, b: Busy) -> ApiError {
    match b {
        Busy::Attachment => ApiError::coded(
            StatusCode::CONFLICT,
            code::UPLOAD_IN_PROGRESS,
            "this attachment is being uploaded already",
        ),
        Busy::User | Busy::Server => ApiError::TooManyRequests(10),
        Busy::Disk => crate::disk::full(state),
    }
}

/// `PUT /attachments/{id}`: the encrypted file, exactly the attachment's `size` bytes
/// (any `Content-Type`), only from whoever added the attachment (403 for other
/// members). Streamed to a temp file, never held in memory: refused with 413 as soon
/// as it passes the size, 400 when it ends short, stalls for a minute or runs past
/// its deadline (`files::upload_deadline`). Then, under the vault's lock, the file is
/// renamed into place and the attachment is ready: `{"attachment", "revision",
/// "vault_seq"}`. 409 `already_uploaded` when it is ready already (an earlier try
/// landed), 409 `upload_in_progress` while another upload of it runs, 507
/// `insufficient_storage` when the disk would drop below the admin's reserve.
pub(super) async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Json<Value>> {
    let store = store_for_new(&state)?;
    let id = canonical_id(&id).ok_or(ApiError::NotFound)?;
    let row = {
        let mut conn = state.db.acquire().await?;
        load(&mut conn, &id).await?.ok_or(ApiError::NotFound)?
    };
    require(&state, &user.user_id, &row.vault_id, Role::Write).await?;
    if row.created_by != user.user_id {
        return Err(ApiError::Forbidden(
            "only whoever added this attachment can upload its file".into(),
        ));
    }
    if row.state == READY {
        return Err(already_uploaded());
    }
    // The admin's limit as it is now (it may have been lowered since the attachment was made).
    let max_mb = state.num(Num::MaxAttachmentMb);
    if row.size > max_mb * 1024 * 1024 {
        return Err(too_large(format!(
            "attachments may be at most {max_mb} MB on this server"
        )));
    }
    let size = row.size as u64;
    match content_length(&headers) {
        Some(len) if len > size => {
            return Err(too_large(
                "the upload is larger than the attachment's size".into(),
            ));
        }
        Some(len) if len < size => {
            return Err(ApiError::bad(
                "the upload is shorter than the attachment's size",
            ));
        }
        _ => {}
    }
    // The disk's room above the reserve, taken together with the uploads running.
    let room = crate::disk::room(&state).await;
    let upload = store
        .begin_upload(&id, &user.user_id, size, room)
        .map_err(|b| busy(&state, b))?;
    // Started: the sweeper keeps a pending upload for an hour from now (and for as
    // long as this one runs).
    let touched =
        sqlx::query("UPDATE attachments SET updated_at = $1 WHERE id = $2 AND state = $3")
            .bind(now())
            .bind(&id)
            .bind(PENDING)
            .execute(&state.db)
            .await?;
    if touched.rows_affected() == 0 {
        let mut conn = state.db.acquire().await?;
        return Err(match load(&mut conn, &id).await? {
            Some(r) if r.state == READY => already_uploaded(),
            _ => ApiError::NotFound,
        });
    }
    let temp = store
        .receive(&upload, size, body)
        .await
        .map_err(upload_error)?;
    let done = finish(&state, &user, store, &id, &temp).await;
    if done.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
    }
    drop(upload);
    done.map(Json)
}

/// Put a received file in place and mark its attachment ready, under the lock of
/// the vault it is in now (it may have moved, or gone, during the upload).
async fn finish(
    state: &AppState,
    user: &AuthUser,
    store: &FileStore,
    id: &str,
    temp: &std::path::Path,
) -> ApiResult<Value> {
    let (w, row) = lock_attachment(state, user, id, Role::Write).await?;
    if row.state != PENDING {
        return Err(already_uploaded());
    }
    // Renamed before the row says ready: a crash in between leaves a pending row
    // (and its file), which the sweeper deletes; never a ready row without a file.
    store
        .place(temp, id)
        .await
        .map_err(|e| anyhow::Error::from(e).context("storing an attachment"))?;
    let done = mark_ready(state, w, &row).await;
    if done.is_err() {
        store.remove(&[id.to_owned()]).await;
    }
    done
}

async fn mark_ready(state: &AppState, mut w: VaultWrite, row: &Row) -> ApiResult<Value> {
    sqlx::query("UPDATE attachments SET state = $1, updated_at = $2 WHERE id = $3 AND state = $4")
        .bind(READY)
        .bind(now())
        .bind(&row.id)
        .bind(PENDING)
        .execute(w.conn())
        .await?;
    stamp(&mut w, &row.vault_id, &row.item_id).await?;
    // Ready: the vault's owners pay for it from now on, no longer its uploader.
    w.charge_files(&row.vault_id, row.size);
    w.charge_uploader(&row.created_by, -row.size);
    w.log(
        Event::new("attachment.added")
            .vault(&row.vault_id)
            .item(&row.item_id)
            .data(json!({ "attachment": row.id, "size": row.size })),
    )
    .await?;
    let ready = load(w.conn(), &row.id).await?.ok_or(ApiError::NotFound)?;
    let vault_seq = w.seq(&row.vault_id);
    let revision = w.commit(state).await?;
    Ok(json!({ "attachment": to_json(&ready), "revision": revision, "vault_seq": vault_seq }))
}

/// `GET /attachments/{id}`: a ready file, for any active member of its item's vault
/// (404 for everyone else, and while it is pending).
pub(super) async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = canonical_id(&id).ok_or(ApiError::NotFound)?;
    let row: Option<(String, i64, String)> =
        sqlx::query_as("SELECT vault_id, size, state FROM attachments WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await?;
    let (vault, size, file_state) = row.ok_or(ApiError::NotFound)?;
    require(&state, &user.user_id, &vault, Role::Read).await?;
    if file_state != READY {
        return Err(ApiError::NotFound);
    }
    file_response(&state, &id, size).await
}

/// A ready attachment's file as a download: `application/octet-stream`, saved as a
/// file, never cached, never run (CSP `default-src 'none'; sandbox`).
pub(crate) async fn file_response(state: &AppState, id: &str, size: i64) -> ApiResult<Response> {
    let store = state.files.as_ref().ok_or(ApiError::NotFound)?;
    let body = match store.read(id, size as u64).await {
        Ok(body) => body,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::warn!(attachment = %id, "the file of a ready attachment is missing");
            return Err(ApiError::NotFound);
        }
        Err(e) => {
            return Err(ApiError::Internal(
                anyhow::Error::from(e).context("reading an attachment"),
            ));
        }
    };
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    Ok(resp)
}

/// `DELETE /attachments/{id}` (write access to its item's vault, pending or ready):
/// `{"revision", "vault_seq"}`. Its bytes stop counting at once; the file is deleted
/// after the commit (an upload still running finds its attachment gone).
pub(super) async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = canonical_id(&id).ok_or(ApiError::NotFound)?;
    let (mut w, row) = lock_attachment(&state, &user, &id, Role::Write).await?;
    sqlx::query("DELETE FROM attachments WHERE id = $1")
        .bind(&id)
        .execute(w.conn())
        .await?;
    if row.state == READY {
        w.charge_files(&row.vault_id, -row.size);
    } else {
        w.charge_uploader(&row.created_by, -row.size);
    }
    // Only a ready file was ever there for others to see.
    if row.state == READY {
        stamp(&mut w, &row.vault_id, &row.item_id).await?;
        w.log(
            Event::new("attachment.deleted")
                .vault(&row.vault_id)
                .item(&row.item_id)
                .data(json!({ "attachment": id, "size": row.size })),
        )
        .await?;
    }
    let vault_seq = w.seq(&row.vault_id);
    let revision = w.commit(&state).await?;
    remove_files(&state, &[id]).await;
    Ok(Json(
        json!({ "revision": revision, "vault_seq": vault_seq }),
    ))
}

// -------------------------------------------------- with items, vaults, users

/// Delete the rows of item `item_id`'s attachments (it is deleted for good) inside
/// the caller's write. Returns their ids: delete the files after the commit
/// ([`remove_files`]).
pub(super) async fn detach_item(conn: &mut AnyConnection, item_id: &str) -> ApiResult<Vec<String>> {
    Ok(
        sqlx::query_scalar("DELETE FROM attachments WHERE item_id = $1 RETURNING id")
            .bind(item_id)
            .fetch_all(&mut *conn)
            .await?,
    )
}

/// [`detach_item`] for every item of a vault that is deleted.
pub(crate) async fn detach_vault(
    conn: &mut AnyConnection,
    vault_id: &str,
) -> ApiResult<Vec<String>> {
    Ok(
        sqlx::query_scalar("DELETE FROM attachments WHERE vault_id = $1 RETURNING id")
            .bind(vault_id)
            .fetch_all(&mut *conn)
            .await?,
    )
}

/// [`detach_item`] for the items of `vault_id` in the trash since before `cutoff`.
pub(super) async fn detach_trash(
    conn: &mut AnyConnection,
    vault_id: &str,
    cutoff: i64,
) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "DELETE FROM attachments WHERE vault_id = $1 AND item_id IN
           (SELECT id FROM items WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at < $2)
         RETURNING id",
    )
    .bind(vault_id)
    .bind(cutoff)
    .fetch_all(&mut *conn)
    .await?)
}

/// Bytes of item `item_id`'s ready attachments (what its vault's owners pay for;
/// uploads that haven't finished count against whoever started them).
pub(super) async fn item_bytes(conn: &mut AnyConnection, item_id: &str) -> ApiResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) FROM attachments WHERE item_id = $1 AND state = 'ready'",
    )
    .bind(item_id)
    .fetch_one(&mut *conn)
    .await?)
}

/// The item moved to `vault_id`: its attachments go with it (the files stay).
pub(super) async fn follow_item(
    conn: &mut AnyConnection,
    item_id: &str,
    vault_id: &str,
) -> ApiResult<()> {
    sqlx::query("UPDATE attachments SET vault_id = $1 WHERE item_id = $2")
        .bind(vault_id)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Delete the files of attachments whose rows a committed write deleted.
pub(crate) async fn remove_files(state: &AppState, ids: &[String]) {
    if let Some(store) = &state.files
        && !ids.is_empty()
    {
        store.remove(ids).await;
    }
}

// ------------------------------------------------------------------- sweeper

/// What [`sweep`] deleted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Uploads left pending.
    pub pending: u64,
    /// Files without a row.
    pub orphans: u64,
}

/// Delete uploads left pending (not made or started within [`PENDING_TTL`], and not
/// running) with any file they left; with `files`, also delete the files that have no
/// row (a crash between a delete and its file, or a database restored from an older
/// backup) and leftover temp files.
pub async fn sweep(state: &AppState, files: bool) -> ApiResult<Swept> {
    let cutoff = now() - PENDING_TTL;
    let stale: Vec<String> =
        sqlx::query_scalar("SELECT id FROM attachments WHERE state = $1 AND updated_at < $2")
            .bind(PENDING)
            .bind(cutoff)
            .fetch_all(&state.db)
            .await?;
    let mut gone = Vec::new();
    for id in stale {
        if state.files.as_ref().is_some_and(|s| s.is_uploading(&id)) {
            continue;
        }
        // Still pending and still old: an upload that started meanwhile touched it.
        let done =
            sqlx::query("DELETE FROM attachments WHERE id = $1 AND state = $2 AND updated_at < $3")
                .bind(&id)
                .bind(PENDING)
                .bind(cutoff)
                .execute(&state.db)
                .await?;
        if done.rows_affected() == 1 {
            gone.push(id);
        }
    }
    remove_files(state, &gone).await;
    let mut swept = Swept {
        pending: gone.len() as u64,
        orphans: 0,
    };
    if files && let Some(store) = &state.files {
        let stored = store
            .scan()
            .await
            .map_err(|e| anyhow::Error::from(e).context("listing attachment files"))?;
        let orphans = without_rows(state, &stored).await?;
        store.remove(&orphans).await;
        swept.orphans = orphans.len() as u64;
    }
    if swept != Swept::default() {
        tracing::info!(
            pending = swept.pending,
            orphans = swept.orphans,
            "deleted abandoned attachment uploads and files without an attachment"
        );
    }
    Ok(swept)
}

/// The ids among `ids` that have no row.
async fn without_rows(state: &AppState, ids: &[String]) -> ApiResult<Vec<String>> {
    let sql = if is_postgres(&state.config.database_url) {
        "SELECT id FROM attachments WHERE id IN (SELECT json_array_elements_text($1::json))"
    } else {
        "SELECT id FROM attachments WHERE id IN (SELECT value FROM json_each($1))"
    };
    let mut out = Vec::new();
    for chunk in ids.chunks(500) {
        let list = serde_json::to_string(chunk).map_err(anyhow::Error::from)?;
        let known: HashSet<String> = sqlx::query_scalar::<_, String>(sql)
            .bind(list)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();
        out.extend(chunk.iter().filter(|id| !known.contains(*id)).cloned());
    }
    Ok(out)
}
