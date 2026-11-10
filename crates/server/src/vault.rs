//! Vaults, membership/sharing, items and sync. Everything stored here is
//! ciphertext produced by clients; the server only enforces access control.

use std::collections::HashSet;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{AuthUser, NewVault};
use crate::db::{now, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, normalize_email};

const MAX_BLOB: usize = 2 * 1024 * 1024;
const MAX_IMPORT: usize = 10_000;
/// Request bodies: one item (two blobs) for ordinary routes, whole vaults for
/// import and key rotation.
const ITEM_BODY_LIMIT: usize = 2 * MAX_BLOB + 64 * 1024;
const BULK_BODY_LIMIT: usize = 64 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    let bulk = || DefaultBodyLimit::max(BULK_BODY_LIMIT);
    Router::new()
        .route("/sync", get(sync))
        .route("/sync/revision", get(revision))
        .route("/vaults", post(create_vault))
        .route("/vaults/{id}", put(update_vault).delete(delete_vault))
        .route("/vaults/{id}/members", get(list_members).post(add_member))
        .route("/vaults/{id}/members/{user_id}", delete(remove_member))
        .route(
            "/vaults/{id}/members/{user_id}/remove",
            post(remove_member_and_rotate).layer(bulk()),
        )
        .route("/vaults/{id}/rotate", post(rotate_vault).layer(bulk()))
        .route("/users/lookup", get(lookup_user))
        .route("/items", post(create_item))
        .route("/items/import", post(import_items).layer(bulk()))
        .route("/items/{id}", put(update_item).delete(trash_item))
        .route("/items/{id}/restore", post(restore_item))
        .route("/items/{id}/permanent", delete(purge_item))
        .layer(DefaultBodyLimit::max(ITEM_BODY_LIMIT))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Read,
    Write,
    Admin,
    Owner,
}

impl Role {
    fn parse(s: &str) -> ApiResult<Self> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "admin" => Ok(Self::Admin),
            "owner" => Ok(Self::Owner),
            _ => Err(ApiError::bad("role must be read, write, admin or owner")),
        }
    }
}

pub async fn insert_vault(
    conn: &mut sqlx::AnyConnection,
    user_id: &str,
    v: &NewVault,
    role: &str,
    key_kind: &str,
) -> ApiResult<()> {
    check_id(&v.id)?;
    check_blob(&v.meta)?;
    check_blob(&v.wrapped_key)?;
    let t = now();
    sqlx::query("INSERT INTO vaults (id, meta, created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)")
        .bind(&v.id)
        .bind(&v.meta)
        .bind(user_id)
        .bind(t)
        .execute(&mut *conn)
        .await
        .map_err(|e| ApiError::conflict_on_unique(e, "vault id already exists"))?;
    sqlx::query(
        "INSERT INTO vault_members (vault_id, user_id, role, wrapped_key, key_kind, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&v.id)
    .bind(user_id)
    .bind(role)
    .bind(&v.wrapped_key)
    .bind(key_kind)
    .bind(t)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn check_id(id: &str) -> ApiResult<()> {
    uuid::Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| ApiError::bad("ids must be UUIDs"))
}

fn check_blob(s: &str) -> ApiResult<()> {
    if s.is_empty() || s.len() > MAX_BLOB {
        return Err(ApiError::bad("encrypted value missing or too large"));
    }
    Ok(())
}

async fn member_role(
    conn: &mut sqlx::AnyConnection,
    user_id: &str,
    vault_id: &str,
) -> ApiResult<Option<Role>> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM vault_members WHERE vault_id = $1 AND user_id = $2")
            .bind(vault_id)
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;
    role.as_deref().map(Role::parse).transpose()
}

async fn role_in(state: &AppState, user_id: &str, vault_id: &str) -> ApiResult<Role> {
    let mut conn = state.db.acquire().await?;
    member_role(&mut conn, user_id, vault_id)
        .await?
        .ok_or(ApiError::NotFound)
}

fn at_least(role: Role, min: Role) -> ApiResult<Role> {
    if role < min {
        return Err(ApiError::Forbidden(
            "insufficient permission for this vault".into(),
        ));
    }
    Ok(role)
}

async fn require(state: &AppState, user_id: &str, vault_id: &str, min: Role) -> ApiResult<Role> {
    at_least(role_in(state, user_id, vault_id).await?, min)
}

/// [`require`] inside a transaction that has already locked the vault.
async fn require_in(
    conn: &mut sqlx::AnyConnection,
    user_id: &str,
    vault_id: &str,
    min: Role,
) -> ApiResult<Role> {
    at_least(
        member_role(conn, user_id, vault_id)
            .await?
            .ok_or(ApiError::NotFound)?,
        min,
    )
}

/// Take the vault's row lock (PostgreSQL) / the write lock (SQLite) for the
/// rest of the transaction, so key rotation, membership changes and item
/// writes into the vault are serialized.
async fn lock_vault(conn: &mut sqlx::AnyConnection, vault_id: &str) -> ApiResult<()> {
    let done = sqlx::query("UPDATE vaults SET updated_at = $1 WHERE id = $2")
        .bind(now())
        .bind(vault_id)
        .execute(&mut *conn)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// Bump the sync revision of every member of `vault_id` and notify them.
/// Returns `me`'s new revision.
async fn touch_vault(state: &AppState, vault_id: &str, me: &str) -> ApiResult<i64> {
    let members: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_all(&state.db)
            .await?;
    touch_users(state, &members, me).await
}

/// Bump these users' sync revisions and notify their clients. A revision
/// never goes backwards, even if the clock does (NTP step, VM restore), or
/// clients would ignore every change until the clock caught up. Returns
/// `me`'s new revision (or the highest, if `me` isn't among `users`).
pub(crate) async fn touch_users(state: &AppState, users: &[String], me: &str) -> ApiResult<i64> {
    let rev = now_ms();
    let mut revisions = Vec::with_capacity(users.len());
    for u in users {
        sqlx::query(
            "UPDATE users SET revision = CASE WHEN revision >= $1 THEN revision + 1 ELSE $1 END WHERE id = $2",
        )
        .bind(rev)
        .bind(u)
        .execute(&state.db)
        .await?;
        let r: Option<i64> = sqlx::query_scalar("SELECT revision FROM users WHERE id = $1")
            .bind(u)
            .fetch_optional(&state.db)
            .await?;
        if let Some(r) = r {
            revisions.push((u.clone(), r));
        }
    }
    state.notify_sync(&revisions);
    Ok(revisions
        .iter()
        .find(|(u, _)| u == me)
        .or_else(|| revisions.iter().max_by_key(|(_, r)| *r))
        .map_or(rev, |(_, r)| *r))
}

// -------------------------------------------------------------------- sync

#[derive(Serialize, sqlx::FromRow)]
struct VaultRow {
    id: String,
    meta: String,
    role: String,
    wrapped_key: String,
    key_kind: String,
    /// 1 = someone who knew the key left: an admin's client must rotate it.
    rotation_pending: i64,
}

#[derive(Serialize, sqlx::FromRow)]
struct ItemRow {
    id: String,
    vault_id: String,
    item_key: String,
    data: String,
    revision: i64,
    deleted_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

async fn sync(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    // One snapshot: a key rotation committing between the vault and item
    // queries would otherwise hand out old wrapped keys with new items.
    let mut tx = state.db.begin().await?;
    if crate::db::is_postgres(&state.config.database_url) {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
    }
    let (revision, name, verified, bundle): (i64, String, i64, String) =
        sqlx::query_as("SELECT revision, name, email_verified, bundle FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&mut *tx)
            .await?;
    let vaults: Vec<VaultRow> = sqlx::query_as(
        "SELECT v.id, v.meta, m.role, m.wrapped_key, m.key_kind, v.rotation_pending FROM vaults v
         JOIN vault_members m ON m.vault_id = v.id WHERE m.user_id = $1 ORDER BY v.created_at",
    )
    .bind(&user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    let items: Vec<ItemRow> = sqlx::query_as(
        "SELECT i.id, i.vault_id, i.item_key, i.data, i.revision, i.deleted_at, i.created_at, i.updated_at FROM items i
         JOIN vault_members m ON m.vault_id = i.vault_id WHERE m.user_id = $1",
    )
    .bind(&user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({
        "revision": revision,
        "user": { "id": user.user_id, "email": user.email, "name": name, "email_verified": verified != 0 },
        "bundle": serde_json::from_str::<Value>(&bundle).map_err(anyhow::Error::from)?,
        "vaults": vaults,
        "items": items,
    })))
}

async fn revision(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rev: i64 = sqlx::query_scalar("SELECT revision FROM users WHERE id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({ "revision": rev })))
}

// ------------------------------------------------------------------ vaults

async fn create_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Json(v): Json<NewVault>,
) -> ApiResult<Json<Value>> {
    let mut conn = state.db.acquire().await?;
    insert_vault(&mut conn, &user.user_id, &v, "owner", "account").await?;
    drop(conn);
    let rev = touch_users(&state, std::slice::from_ref(&user.user_id), &user.user_id).await?;
    Ok(Json(json!({ "id": v.id, "revision": rev })))
}

#[derive(Deserialize)]
struct VaultMeta {
    meta: String,
}

async fn update_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<VaultMeta>,
) -> ApiResult<Json<Value>> {
    require(&state, &user.user_id, &id, Role::Admin).await?;
    check_blob(&b.meta)?;
    sqlx::query("UPDATE vaults SET meta = $1, updated_at = $2 WHERE id = $3")
        .bind(&b.meta)
        .bind(now())
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(Json(
        json!({ "revision": touch_vault(&state, &id, &user.user_id).await? }),
    ))
}

async fn delete_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require(&state, &user.user_id, &id, Role::Owner).await?;
    let vaults: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vault_members WHERE user_id = $1 AND role = 'owner'",
    )
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await?;
    if vaults <= 1 {
        return Err(ApiError::Conflict(
            "you can't delete your last vault".into(),
        ));
    }
    let members: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(&id)
            .fetch_all(&state.db)
            .await?;
    let mut tx = state.db.begin().await?;
    for stmt in [
        "DELETE FROM items WHERE vault_id = $1",
        "DELETE FROM vault_members WHERE vault_id = $1",
        "DELETE FROM vaults WHERE id = $1",
    ] {
        sqlx::query(stmt).bind(&id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({ "revision": touch_users(&state, &members, &user.user_id).await? }),
    ))
}

// ----------------------------------------------------------------- sharing

#[derive(Deserialize)]
struct LookupQuery {
    email: String,
}

/// Public key of a verified user, so a vault key can be sealed to them.
/// Clients must show the fingerprint for out-of-band confirmation.
async fn lookup_user(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<LookupQuery>,
) -> ApiResult<Json<Value>> {
    if !state
        .limiter
        .check(&format!("lookup:{}", user.user_id), 30, 600)
    {
        return Err(ApiError::TooManyRequests);
    }
    let row: Option<(String, String, String)> =
        sqlx::query_as("SELECT id, name, public_key FROM users WHERE email = $1 AND email_verified = 1 AND disabled = 0")
            .bind(normalize_email(&q.email))
            .fetch_optional(&state.db)
            .await?;
    let (id, name, public_key) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(
        json!({ "user_id": id, "name": name, "public_key": public_key }),
    ))
}

#[derive(Serialize, sqlx::FromRow)]
struct MemberRow {
    user_id: String,
    email: String,
    name: String,
    role: String,
    public_key: String,
}

async fn list_members(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require(&state, &user.user_id, &id, Role::Read).await?;
    let members: Vec<MemberRow> = sqlx::query_as(
        "SELECT m.user_id, u.email, u.name, m.role, u.public_key FROM vault_members m
         JOIN users u ON u.id = m.user_id WHERE m.vault_id = $1 ORDER BY m.created_at",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "members": members })))
}

#[derive(Deserialize)]
struct AddMember {
    user_id: String,
    role: String,
    /// Vault key sealed to the member's public key.
    sealed_key: String,
}

async fn add_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<AddMember>,
) -> ApiResult<Json<Value>> {
    let role = Role::parse(&b.role)?;
    // Ownership only comes from creating a vault. Granting it would let anyone
    // plant a vault that other people's apps pick as their default place to save.
    if role == Role::Owner {
        return Err(ApiError::Forbidden(
            "ownership of a vault can't be given to another member".into(),
        ));
    }
    check_id(&b.user_id)?;
    check_blob(&b.sealed_key)?;
    let target: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE id = $1 AND email_verified = 1 AND disabled = 0",
    )
    .bind(&b.user_id)
    .fetch_one(&state.db)
    .await?;
    if target == 0 {
        return Err(ApiError::bad("unknown user"));
    }
    let mut tx = state.db.begin().await?;
    lock_vault(&mut tx, &id).await?;
    let mine = require_in(&mut tx, &user.user_id, &id, Role::Admin).await?;
    if role > mine {
        return Err(ApiError::Forbidden(
            "cannot grant a role above your own".into(),
        ));
    }
    if let Some(current) = member_role(&mut tx, &b.user_id, &id).await?
        && (current == Role::Owner || current >= mine)
    {
        return Err(ApiError::Forbidden(
            "you can't change the access of a member at or above your own role".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO vault_members (vault_id, user_id, role, wrapped_key, key_kind, created_at) VALUES ($1, $2, $3, $4, 'sealed', $5)
         ON CONFLICT (vault_id, user_id) DO UPDATE SET role = excluded.role, wrapped_key = excluded.wrapped_key, key_kind = excluded.key_kind",
    )
    .bind(&id)
    .bind(&b.user_id)
    .bind(&b.role)
    .bind(&b.sealed_key)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "revision": touch_vault(&state, &id, &user.user_id).await? }),
    ))
}

async fn remove_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let target = role_in(&state, &member, &id).await?;
    if target == Role::Owner {
        return Err(ApiError::Forbidden("the owner cannot be removed".into()));
    }
    if member != user.user_id {
        let mine = require(&state, &user.user_id, &id, Role::Admin).await?;
        if target >= mine {
            return Err(ApiError::Forbidden(
                "you can't remove a member at or above your own role".into(),
            ));
        }
    }
    let before: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(&id)
            .fetch_all(&state.db)
            .await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&member)
        .execute(&mut *tx)
        .await?;
    // The removed member still knows the old key. Recorded on the vault, so any
    // admin's client finishes the rotation even if this one never does (a member
    // leaving can't rotate: they lose access). Prefer `.../remove`, which does both.
    sqlx::query("UPDATE vaults SET rotation_pending = 1 WHERE id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "revision": touch_users(&state, &before, &user.user_id).await?, "rotation_required": true }),
    ))
}

#[derive(Deserialize)]
struct RotateKey {
    user_id: String,
    wrapped_key: String,
    key_kind: String,
}

#[derive(Deserialize)]
struct Rotate {
    keys: Vec<RotateKey>,
    items: Vec<ItemBody>,
    /// Vault name etc. re-encrypted under the new key, stored in the same
    /// transaction (older clients send it with a separate PUT afterwards).
    #[serde(default)]
    meta: Option<String>,
}

/// Replace the vault key for every member and re-encrypted items atomically.
///
/// Everything is checked inside the transaction after locking the vault, so a
/// member or item added meanwhile makes the rotation fail instead of being
/// left on the old key.
async fn rotate_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Rotate>,
) -> ApiResult<Json<Value>> {
    check_rotation(&b, &id, &user.user_id)?;
    let mut tx = state.db.begin().await?;
    lock_vault(&mut tx, &id).await?;
    require_in(&mut tx, &user.user_id, &id, Role::Admin).await?;
    apply_rotation(&mut tx, &id, &b).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "revision": touch_vault(&state, &id, &user.user_id).await? }),
    ))
}

/// Remove a member and replace the vault key in one transaction, so a removal
/// never happens without its rotation. The body is a [`Rotate`] for the members
/// who remain.
async fn remove_member_and_rotate(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member)): Path<(String, String)>,
    Json(b): Json<Rotate>,
) -> ApiResult<Json<Value>> {
    if member == user.user_id {
        return Err(ApiError::bad(
            "to leave a vault, remove yourself; an admin replaces the key",
        ));
    }
    check_rotation(&b, &id, &user.user_id)?;
    let mut tx = state.db.begin().await?;
    lock_vault(&mut tx, &id).await?;
    let mine = require_in(&mut tx, &user.user_id, &id, Role::Admin).await?;
    let target = member_role(&mut tx, &member, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target == Role::Owner {
        return Err(ApiError::Forbidden("the owner cannot be removed".into()));
    }
    if target >= mine {
        return Err(ApiError::Forbidden(
            "you can't remove a member at or above your own role".into(),
        ));
    }
    let before: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(&id)
            .fetch_all(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&member)
        .execute(&mut *tx)
        .await?;
    apply_rotation(&mut tx, &id, &b).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "revision": touch_users(&state, &before, &user.user_id).await? }),
    ))
}

/// Shape checks of a rotation body that need no database.
fn check_rotation(b: &Rotate, id: &str, me: &str) -> ApiResult<()> {
    for k in &b.keys {
        check_blob(&k.wrapped_key)?;
        match k.key_kind.as_str() {
            // Only the member themselves can wrap a key with their account key.
            "account" if k.user_id == me => {}
            "sealed" => {}
            _ => {
                return Err(ApiError::bad(
                    "key_kind must be account (your own) or sealed",
                ));
            }
        }
    }
    let mut ids = HashSet::new();
    for i in &b.items {
        check_blob(&i.key)?;
        check_blob(&i.data)?;
        if i.vault_id != id || !ids.insert(i.id.as_str()) {
            return Err(ApiError::bad(
                "every item in the vault must be re-encrypted exactly once",
            ));
        }
    }
    if let Some(meta) = &b.meta {
        check_blob(meta)?;
    }
    Ok(())
}

/// Write a rotation inside a transaction that has locked the vault and checked
/// the caller's role: new keys for exactly the current members, every item
/// re-encrypted once, and the pending-rotation mark cleared.
async fn apply_rotation(tx: &mut sqlx::AnyConnection, id: &str, b: &Rotate) -> ApiResult<()> {
    let members: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    let mut given: Vec<&str> = b.keys.iter().map(|k| k.user_id.as_str()).collect();
    given.sort_unstable();
    let mut expected: Vec<&str> = members.iter().map(String::as_str).collect();
    expected.sort_unstable();
    if given != expected {
        return Err(ApiError::bad(
            "a new key is required for exactly the current members",
        ));
    }
    let item_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM items WHERE vault_id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if b.items.len() as i64 != item_count {
        return Err(ApiError::bad(
            "every item in the vault must be re-encrypted exactly once",
        ));
    }
    let rev = now_ms();
    for k in &b.keys {
        sqlx::query("UPDATE vault_members SET wrapped_key = $1, key_kind = $2 WHERE vault_id = $3 AND user_id = $4")
            .bind(&k.wrapped_key)
            .bind(&k.key_kind)
            .bind(id)
            .bind(&k.user_id)
            .execute(&mut *tx)
            .await?;
    }
    for i in &b.items {
        let done = match i.revision {
            Some(r) => sqlx::query("UPDATE items SET item_key = $1, data = $2, revision = $3, updated_at = $4 WHERE id = $5 AND vault_id = $6 AND revision = $7")
                .bind(&i.key)
                .bind(&i.data)
                .bind(rev)
                .bind(now())
                .bind(&i.id)
                .bind(id)
                .bind(r)
                .execute(&mut *tx)
                .await?,
            None => sqlx::query("UPDATE items SET item_key = $1, data = $2, revision = $3, updated_at = $4 WHERE id = $5 AND vault_id = $6")
                .bind(&i.key)
                .bind(&i.data)
                .bind(rev)
                .bind(now())
                .bind(&i.id)
                .bind(id)
                .execute(&mut *tx)
                .await?,
        };
        if done.rows_affected() != 1 {
            return Err(match i.revision {
                Some(_) => ApiError::Conflict(
                    "an item changed while the key was being replaced; sync and retry".into(),
                ),
                None => ApiError::bad("unknown item in rotation"),
            });
        }
    }
    if let Some(meta) = &b.meta {
        sqlx::query("UPDATE vaults SET meta = $1 WHERE id = $2")
            .bind(meta)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE vaults SET rotation_pending = 0 WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

// ------------------------------------------------------------------- items

#[derive(Deserialize)]
struct ItemBody {
    id: String,
    vault_id: String,
    key: String,
    data: String,
    /// Optimistic concurrency: reject if the stored revision differs.
    revision: Option<i64>,
}

async fn insert_item(conn: &mut sqlx::AnyConnection, i: &ItemBody, rev: i64) -> ApiResult<()> {
    check_id(&i.id)?;
    check_blob(&i.key)?;
    check_blob(&i.data)?;
    let t = now();
    sqlx::query("INSERT INTO items (id, vault_id, item_key, data, revision, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)")
        .bind(&i.id)
        .bind(&i.vault_id)
        .bind(&i.key)
        .bind(&i.data)
        .bind(rev)
        .bind(t)
        .execute(conn)
        .await
        .map_err(|e| ApiError::conflict_on_unique(e, "item id already exists"))?;
    Ok(())
}

async fn create_item(
    State(state): State<AppState>,
    user: AuthUser,
    Json(i): Json<ItemBody>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    lock_vault(&mut tx, &i.vault_id).await?;
    require_in(&mut tx, &user.user_id, &i.vault_id, Role::Write).await?;
    insert_item(&mut tx, &i, now_ms()).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "id": i.id, "revision": touch_vault(&state, &i.vault_id, &user.user_id).await? }),
    ))
}

#[derive(Deserialize)]
struct Import {
    items: Vec<ItemBody>,
}

async fn import_items(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Import>,
) -> ApiResult<Json<Value>> {
    if b.items.len() > MAX_IMPORT {
        return Err(ApiError::bad(format!(
            "import at most {MAX_IMPORT} items at a time"
        )));
    }
    let mut vaults: Vec<&str> = b.items.iter().map(|i| i.vault_id.as_str()).collect();
    vaults.sort_unstable();
    vaults.dedup();
    let rev = now_ms();
    let mut tx = state.db.begin().await?;
    for v in &vaults {
        lock_vault(&mut tx, v).await?;
        require_in(&mut tx, &user.user_id, v, Role::Write).await?;
    }
    for i in &b.items {
        insert_item(&mut tx, i, rev).await?;
    }
    tx.commit().await?;
    let mut members: Vec<String> = Vec::new();
    for v in &vaults {
        members.extend(
            sqlx::query_scalar::<_, String>(
                "SELECT user_id FROM vault_members WHERE vault_id = $1",
            )
            .bind(*v)
            .fetch_all(&state.db)
            .await?,
        );
    }
    members.sort_unstable();
    members.dedup();
    touch_users(&state, &members, &user.user_id).await?;
    Ok(Json(json!({ "imported": b.items.len() })))
}

async fn item_vault(state: &AppState, id: &str) -> ApiResult<(String, i64)> {
    sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

fn changed_elsewhere() -> ApiError {
    ApiError::Conflict("item changed on another device; sync and retry".into())
}

async fn update_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(i): Json<ItemBody>,
) -> ApiResult<Json<Value>> {
    if i.id != id {
        return Err(ApiError::bad("id mismatch"));
    }
    check_blob(&i.key)?;
    check_blob(&i.data)?;
    let (old_vault, current) = item_vault(&state, &id).await?;
    if i.revision.is_some_and(|r| r != current) {
        return Err(changed_elsewhere());
    }
    let mut tx = state.db.begin().await?;
    lock_vault(&mut tx, &old_vault).await?;
    require_in(&mut tx, &user.user_id, &old_vault, Role::Write).await?;
    if old_vault != i.vault_id {
        lock_vault(&mut tx, &i.vault_id).await?;
        require_in(&mut tx, &user.user_id, &i.vault_id, Role::Write).await?;
    }
    let rev = now_ms();
    // Conditional on the vault and revision read above: an edit or move that
    // committed in between makes this a conflict instead of a lost update.
    let done = sqlx::query("UPDATE items SET vault_id = $1, item_key = $2, data = $3, revision = $4, updated_at = $5 WHERE id = $6 AND vault_id = $7 AND revision = $8")
        .bind(&i.vault_id)
        .bind(&i.key)
        .bind(&i.data)
        .bind(rev)
        .bind(now())
        .bind(&id)
        .bind(&old_vault)
        .bind(current)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() != 1 {
        return Err(changed_elsewhere());
    }
    tx.commit().await?;
    if old_vault != i.vault_id {
        touch_vault(&state, &old_vault, &user.user_id).await?;
    }
    touch_vault(&state, &i.vault_id, &user.user_id).await?;
    Ok(Json(json!({ "id": id, "revision": rev })))
}

/// Optional optimistic-concurrency check for trash / restore / purge.
#[derive(Deserialize)]
struct RevisionQuery {
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
    require(state, &user.user_id, &vault, Role::Write).await?;
    if expected.is_some_and(|r| r != current) {
        return Err(changed_elsewhere());
    }
    let rev = now_ms();
    let done = sqlx::query("UPDATE items SET deleted_at = $1, revision = $2, updated_at = $3 WHERE id = $4 AND vault_id = $5 AND revision = $6")
        .bind(deleted_at)
        .bind(rev)
        .bind(now())
        .bind(id)
        .bind(&vault)
        .bind(current)
        .execute(&state.db)
        .await?;
    if done.rows_affected() != 1 {
        return Err(changed_elsewhere());
    }
    touch_vault(state, &vault, &user.user_id).await?;
    Ok(Json(json!({ "id": id, "revision": rev })))
}

async fn trash_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    set_deleted(&state, &user, &id, q.revision, Some(now())).await
}

async fn restore_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    set_deleted(&state, &user, &id, q.revision, None).await
}

async fn purge_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let (vault, current) = item_vault(&state, &id).await?;
    require(&state, &user.user_id, &vault, Role::Write).await?;
    if q.revision.is_some_and(|r| r != current) {
        return Err(changed_elsewhere());
    }
    let done = sqlx::query("DELETE FROM items WHERE id = $1 AND vault_id = $2")
        .bind(&id)
        .bind(&vault)
        .execute(&state.db)
        .await?;
    if done.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(
        json!({ "revision": touch_vault(&state, &vault, &user.user_id).await? }),
    ))
}
