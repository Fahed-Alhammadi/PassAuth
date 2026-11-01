//! Vaults, membership/sharing, items and sync. Everything stored here is
//! ciphertext produced by clients; the server only enforces access control.

use axum::extract::{Path, Query, State};
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

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sync", get(sync))
        .route("/sync/revision", get(revision))
        .route("/vaults", post(create_vault))
        .route("/vaults/{id}", put(update_vault).delete(delete_vault))
        .route("/vaults/{id}/members", get(list_members).post(add_member))
        .route("/vaults/{id}/members/{user_id}", delete(remove_member))
        .route("/vaults/{id}/rotate", post(rotate_vault))
        .route("/users/lookup", get(lookup_user))
        .route("/items", post(create_item))
        .route("/items/import", post(import_items))
        .route("/items/{id}", put(update_item).delete(trash_item))
        .route("/items/{id}/restore", post(restore_item))
        .route("/items/{id}/permanent", delete(purge_item))
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
        .map_err(|_| ApiError::Conflict("vault id already exists".into()))?;
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

async fn role_in(state: &AppState, user_id: &str, vault_id: &str) -> ApiResult<Role> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM vault_members WHERE vault_id = $1 AND user_id = $2")
            .bind(vault_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    Role::parse(&role.ok_or(ApiError::NotFound)?)
}

async fn require(state: &AppState, user_id: &str, vault_id: &str, min: Role) -> ApiResult<Role> {
    let role = role_in(state, user_id, vault_id).await?;
    if role < min {
        return Err(ApiError::Forbidden(
            "insufficient permission for this vault".into(),
        ));
    }
    Ok(role)
}

/// Bump the sync revision of every member of `vault_id` and notify them.
async fn touch_vault(state: &AppState, vault_id: &str) -> ApiResult<i64> {
    let members: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_all(&state.db)
            .await?;
    touch_users(state, &members).await
}

async fn touch_users(state: &AppState, users: &[String]) -> ApiResult<i64> {
    let rev = now_ms();
    for u in users {
        sqlx::query("UPDATE users SET revision = $1 WHERE id = $2")
            .bind(rev)
            .bind(u)
            .execute(&state.db)
            .await?;
    }
    state.notify_sync(users, rev);
    Ok(rev)
}

// -------------------------------------------------------------------- sync

#[derive(Serialize, sqlx::FromRow)]
struct VaultRow {
    id: String,
    meta: String,
    role: String,
    wrapped_key: String,
    key_kind: String,
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
    let (revision, name, verified, bundle): (i64, String, i64, String) =
        sqlx::query_as("SELECT revision, name, email_verified, bundle FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    let vaults: Vec<VaultRow> = sqlx::query_as(
        "SELECT v.id, v.meta, m.role, m.wrapped_key, m.key_kind FROM vaults v
         JOIN vault_members m ON m.vault_id = v.id WHERE m.user_id = $1 ORDER BY v.created_at",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let items: Vec<ItemRow> = sqlx::query_as(
        "SELECT i.id, i.vault_id, i.item_key, i.data, i.revision, i.deleted_at, i.created_at, i.updated_at FROM items i
         JOIN vault_members m ON m.vault_id = i.vault_id WHERE m.user_id = $1",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
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
    let rev = touch_users(&state, std::slice::from_ref(&user.user_id)).await?;
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
    Ok(Json(json!({ "revision": touch_vault(&state, &id).await? })))
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
        json!({ "revision": touch_users(&state, &members).await? }),
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
    _user: AuthUser,
    Query(q): Query<LookupQuery>,
) -> ApiResult<Json<Value>> {
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
    let mine = require(&state, &user.user_id, &id, Role::Admin).await?;
    let role = Role::parse(&b.role)?;
    if role > mine || role == Role::Owner && mine != Role::Owner {
        return Err(ApiError::Forbidden(
            "cannot grant a role above your own".into(),
        ));
    }
    check_blob(&b.sealed_key)?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&b.user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO vault_members (vault_id, user_id, role, wrapped_key, key_kind, created_at) VALUES ($1, $2, $3, $4, 'sealed', $5)")
        .bind(&id)
        .bind(&b.user_id)
        .bind(&b.role)
        .bind(&b.sealed_key)
        .bind(now())
        .execute(&state.db)
        .await
        .map_err(|_| ApiError::bad("unknown user"))?;
    Ok(Json(json!({ "revision": touch_vault(&state, &id).await? })))
}

async fn remove_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    if member != user.user_id {
        require(&state, &user.user_id, &id, Role::Admin).await?;
    }
    if role_in(&state, &member, &id).await? == Role::Owner {
        return Err(ApiError::Forbidden("the owner cannot be removed".into()));
    }
    let before: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(&id)
            .fetch_all(&state.db)
            .await?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&member)
        .execute(&state.db)
        .await?;
    // The removed member still knows the old key; clients must call /rotate next.
    Ok(Json(
        json!({ "revision": touch_users(&state, &before).await?, "rotation_required": true }),
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
}

/// Replace the vault key for every member and re-encrypted items atomically.
async fn rotate_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Rotate>,
) -> ApiResult<Json<Value>> {
    require(&state, &user.user_id, &id, Role::Admin).await?;
    let members: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(&id)
            .fetch_all(&state.db)
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
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    if b.items.len() as i64 != item_count || b.items.iter().any(|i| i.vault_id != id) {
        return Err(ApiError::bad(
            "every item in the vault must be re-encrypted",
        ));
    }
    let rev = now_ms();
    let mut tx = state.db.begin().await?;
    for k in &b.keys {
        check_blob(&k.wrapped_key)?;
        sqlx::query("UPDATE vault_members SET wrapped_key = $1, key_kind = $2 WHERE vault_id = $3 AND user_id = $4")
            .bind(&k.wrapped_key)
            .bind(&k.key_kind)
            .bind(&id)
            .bind(&k.user_id)
            .execute(&mut *tx)
            .await?;
    }
    for i in &b.items {
        let done = sqlx::query("UPDATE items SET item_key = $1, data = $2, revision = $3, updated_at = $4 WHERE id = $5 AND vault_id = $6")
            .bind(&i.key)
            .bind(&i.data)
            .bind(rev)
            .bind(now())
            .bind(&i.id)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() != 1 {
            return Err(ApiError::bad("unknown item in rotation"));
        }
    }
    tx.commit().await?;
    Ok(Json(json!({ "revision": touch_vault(&state, &id).await? })))
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
        .map_err(|_| ApiError::Conflict("item id already exists".into()))?;
    Ok(())
}

async fn create_item(
    State(state): State<AppState>,
    user: AuthUser,
    Json(i): Json<ItemBody>,
) -> ApiResult<Json<Value>> {
    require(&state, &user.user_id, &i.vault_id, Role::Write).await?;
    let mut conn = state.db.acquire().await?;
    insert_item(&mut conn, &i, now_ms()).await?;
    drop(conn);
    Ok(Json(
        json!({ "id": i.id, "revision": touch_vault(&state, &i.vault_id).await? }),
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
    for v in &vaults {
        require(&state, &user.user_id, v, Role::Write).await?;
    }
    let rev = now_ms();
    let mut tx = state.db.begin().await?;
    for i in &b.items {
        insert_item(&mut tx, i, rev).await?;
    }
    tx.commit().await?;
    for v in vaults {
        touch_vault(&state, v).await?;
    }
    Ok(Json(json!({ "imported": b.items.len() })))
}

async fn item_vault(state: &AppState, id: &str) -> ApiResult<(String, i64)> {
    sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
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
    let (old_vault, current) = item_vault(&state, &id).await?;
    require(&state, &user.user_id, &old_vault, Role::Write).await?;
    if old_vault != i.vault_id {
        require(&state, &user.user_id, &i.vault_id, Role::Write).await?;
    }
    if i.revision.is_some_and(|r| r != current) {
        return Err(ApiError::Conflict(
            "item changed on another device; sync and retry".into(),
        ));
    }
    check_blob(&i.key)?;
    check_blob(&i.data)?;
    let rev = now_ms();
    sqlx::query("UPDATE items SET vault_id = $1, item_key = $2, data = $3, revision = $4, updated_at = $5 WHERE id = $6")
        .bind(&i.vault_id)
        .bind(&i.key)
        .bind(&i.data)
        .bind(rev)
        .bind(now())
        .bind(&id)
        .execute(&state.db)
        .await?;
    if old_vault != i.vault_id {
        touch_vault(&state, &old_vault).await?;
    }
    touch_vault(&state, &i.vault_id).await?;
    Ok(Json(json!({ "id": id, "revision": rev })))
}

async fn set_deleted(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    deleted_at: Option<i64>,
) -> ApiResult<Json<Value>> {
    let (vault, _) = item_vault(state, id).await?;
    require(state, &user.user_id, &vault, Role::Write).await?;
    let rev = now_ms();
    sqlx::query("UPDATE items SET deleted_at = $1, revision = $2, updated_at = $3 WHERE id = $4")
        .bind(deleted_at)
        .bind(rev)
        .bind(now())
        .bind(id)
        .execute(&state.db)
        .await?;
    touch_vault(state, &vault).await?;
    Ok(Json(json!({ "id": id, "revision": rev })))
}

async fn trash_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    set_deleted(&state, &user, &id, Some(now())).await
}

async fn restore_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    set_deleted(&state, &user, &id, None).await
}

async fn purge_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (vault, _) = item_vault(&state, &id).await?;
    require(&state, &user.user_id, &vault, Role::Write).await?;
    sqlx::query("DELETE FROM items WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(Json(
        json!({ "revision": touch_vault(&state, &vault).await? }),
    ))
}
