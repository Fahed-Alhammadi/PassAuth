//! Vaults and their members: create, rename (meta), delete, share (an
//! invitation the invitee accepts or declines), remove, and vault key rotation.
//!
//! Sharing a vault with someone who isn't a member yet makes an `invited`
//! membership holding the vault key sealed to them, as before. Until they accept
//! it, they can't read or write the vault and `/sync` doesn't list it: it shows
//! the invitation instead (`invitations`, with the sealed key and the encrypted
//! name, so their app can show the name and the sharer's fingerprint). So nobody
//! can put a vault, and logins in it, into someone's apps without their consent,
//! and apps from before invitations never show a vault that wasn't accepted.

use std::collections::HashSet;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::items::ItemBody;
use super::{INVITED, Need, Role, VaultWrite, at_least, check_blob, check_id, membership, require};
use crate::auth::{AuthUser, NewVault};
use crate::db::{now, now_ms};
use crate::error::{ApiError, ApiResult, code};
use crate::events::Event;
use crate::mail::Email;
use crate::state::{AppState, Class, normalize_email};

/// Create vault `v` with `user_id` as its first member. Its id (chosen by the app)
/// is taken for good in `vault_ids` first: an id any vault ever had, also one
/// deleted since (by its owner or with their account), is a 409 `vault_exists`, so
/// whoever learned a deleted vault's id can't make a vault under it and read the
/// old vault's activity log, history or files. The unique key decides, so two
/// creates at once, or a create racing a deletion, can't both get it.
pub async fn insert_vault(
    conn: &mut AnyConnection,
    user_id: &str,
    v: &NewVault,
    role: &str,
    key_kind: &str,
) -> ApiResult<()> {
    check_id(&v.id)?;
    check_blob(&v.meta)?;
    check_blob(&v.wrapped_key)?;
    let t = now();
    let taken = |e| ApiError::conflict_on_unique(e, code::VAULT_EXISTS, "vault id already exists");
    sqlx::query("INSERT INTO vault_ids (id, created_at) VALUES ($1, $2)")
        .bind(&v.id)
        .bind(t)
        .execute(&mut *conn)
        .await
        .map_err(taken)?;
    sqlx::query("INSERT INTO vaults (id, meta, created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)")
        .bind(&v.id)
        .bind(&v.meta)
        .bind(user_id)
        .bind(t)
        .execute(&mut *conn)
        .await
        .map_err(taken)?;
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

// ------------------------------------------------------------------ vaults

pub(super) async fn create_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Json(v): Json<NewVault>,
) -> ApiResult<Json<Value>> {
    let mut w = VaultWrite::begin(&state, &user, &[]).await?;
    insert_vault(w.conn(), &user.user_id, &v, "owner", "account").await?;
    w.created(&v.id);
    w.log(Event::new("vault.created").vault(&v.id)).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(json!({ "id": v.id, "revision": revision })))
}

#[derive(Deserialize)]
pub(super) struct VaultMeta {
    meta: String,
    /// Epoch of the vault key `meta` is encrypted with.
    key_epoch: Option<i64>,
}

pub(super) async fn update_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<VaultMeta>,
) -> ApiResult<Json<Value>> {
    check_blob(&b.meta)?;
    let need = Need::new(&id, Role::Admin, b.key_epoch);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    sqlx::query("UPDATE vaults SET meta = $1 WHERE id = $2")
        .bind(&b.meta)
        .bind(&id)
        .execute(w.conn())
        .await?;
    // Invitations show the (encrypted) name.
    w.tell_invitees(&id);
    w.log(Event::new("vault.renamed").vault(&id)).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(json!({ "revision": revision })))
}

pub(super) async fn delete_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let need = Need::new(&id, Role::Owner, None);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let owned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vault_members WHERE user_id = $1 AND role = 'owner'",
    )
    .bind(&user.user_id)
    .fetch_one(w.conn())
    .await?;
    if owned <= 1 {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::LAST_VAULT,
            "you can't delete your last vault",
        ));
    }
    // Before the members go: they all re-sync and see the vault gone (and the
    // invitees their invitation).
    w.tell_invitees(&id);
    w.bump().await?;
    let files = super::attachments::detach_vault(w.conn(), &id).await?;
    crate::emergency::forget_vault_keys(w.conn(), &id).await?;
    for stmt in [
        "DELETE FROM items WHERE vault_id = $1",
        "DELETE FROM item_versions WHERE vault_id = $1",
        "DELETE FROM item_tombstones WHERE vault_id = $1",
        "DELETE FROM vault_members WHERE vault_id = $1",
        "DELETE FROM vaults WHERE id = $1",
    ] {
        sqlx::query(stmt).bind(&id).execute(w.conn()).await?;
    }
    w.log(Event::new("vault.deleted").vault(&id)).await?;
    let revision = w.commit(&state).await?;
    super::attachments::remove_files(&state, &files).await;
    Ok(Json(json!({ "revision": revision })))
}

// ----------------------------------------------------------------- sharing

#[derive(Deserialize)]
pub(super) struct LookupQuery {
    email: String,
}

/// Public key of a verified user, so a vault key can be sealed to them.
/// Clients must show the fingerprint for out-of-band confirmation.
pub(super) async fn lookup_user(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<LookupQuery>,
) -> ApiResult<Json<Value>> {
    state
        .limiter
        .limit(Class::Target, &format!("lookup:{}", user.user_id), 30, 600)?;
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
    /// `active`, or `invited` until they accept.
    status: String,
    /// Who shared the vault with them (`null` for members from before invitations).
    invited_by: Option<String>,
    invited_at: Option<i64>,
}

/// Every member, invitations included (`status`): a key replacement must seal
/// the new key to invitees too.
pub(super) async fn list_members(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require(&state, &user.user_id, &id, Role::Read).await?;
    let members: Vec<MemberRow> = sqlx::query_as(
        "SELECT m.user_id, u.email, u.name, m.role, u.public_key, m.status, m.invited_by, m.invited_at
         FROM vault_members m JOIN users u ON u.id = m.user_id
         WHERE m.vault_id = $1 ORDER BY m.created_at",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "members": members })))
}

#[derive(Deserialize)]
pub(super) struct AddMember {
    user_id: String,
    role: String,
    /// Vault key sealed to the member's public key.
    sealed_key: String,
    /// Epoch of the vault key that was sealed.
    key_epoch: Option<i64>,
}

/// New invitations one user may send per hour.
const INVITATIONS_PER_HOUR: u32 = 100;

/// Share a vault: someone who isn't a member yet gets an invitation (`invited`,
/// shown to them in `/sync` until they accept or decline it, and emailed when
/// email is set up); for an existing member or invitation this changes the role
/// and the sealed key and keeps the status. Answers `{"revision", "status"}`, with
/// `"rotation_pending": true` when the vault had emergency-access wraps: an
/// emergency contact may hold its key, so the sharing app replaces it at once.
pub(super) async fn add_member(
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
    let target: Option<String> = sqlx::query_scalar(
        "SELECT email FROM users WHERE id = $1 AND email_verified = 1 AND disabled = 0",
    )
    .bind(&b.user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(invitee_email) = target else {
        return Err(ApiError::bad("unknown user"));
    };
    let need = Need::new(&id, Role::Admin, b.key_epoch);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let mine = w.role(&id);
    if role > mine {
        return Err(ApiError::Forbidden(
            "cannot grant a role above your own".into(),
        ));
    }
    let current = membership(w.conn(), &b.user_id, &id).await?;
    if let Some((current, _)) = current
        && (current == Role::Owner || current >= mine)
    {
        return Err(ApiError::Forbidden(
            "you can't change the access of a member at or above your own role".into(),
        ));
    }
    let invited = match current {
        None => {
            state.limiter.limit(
                Class::Target,
                &format!("invite:{}", user.user_id),
                INVITATIONS_PER_HOUR,
                3600,
            )?;
            let t = now();
            sqlx::query(
                "INSERT INTO vault_members (vault_id, user_id, role, wrapped_key, key_kind, created_at, status, invited_by, invited_at)
                 VALUES ($1, $2, $3, $4, 'sealed', $5, 'invited', $6, $5)",
            )
            .bind(&id)
            .bind(&b.user_id)
            .bind(&b.role)
            .bind(&b.sealed_key)
            .bind(t)
            .bind(&user.user_id)
            .execute(w.conn())
            .await?;
            w.log(
                Event::new("member.invited")
                    .vault(&id)
                    .target(&b.user_id)
                    .data(json!({ "role": b.role })),
            )
            .await?;
            true
        }
        Some((was, invited)) => {
            sqlx::query(
                "UPDATE vault_members SET role = $1, wrapped_key = $2, key_kind = 'sealed'
                 WHERE vault_id = $3 AND user_id = $4",
            )
            .bind(&b.role)
            .bind(&b.sealed_key)
            .bind(&id)
            .bind(&b.user_id)
            .execute(w.conn())
            .await?;
            let status = if invited { "invited" } else { "active" };
            let event = if was == role {
                Event::new("member.key_updated").data(json!({ "role": b.role, "status": status }))
            } else {
                Event::new("member.role_changed")
                    .data(json!({ "role": b.role, "from": role_name(was), "status": status }))
            };
            w.log(event.vault(&id).target(&b.user_id)).await?;
            invited
        }
    };
    // Shared now (or still): no emergency contact gets this vault's key from here on.
    // A contact may already hold it (an approved access, or a compromised server
    // handing the key out early), and the other members never chose to trust them:
    // the vault is marked for a new key, which the owner's apps make.
    let rekey = crate::emergency::forget_vault_keys(w.conn(), &id).await? > 0;
    if rekey {
        sqlx::query("UPDATE vaults SET rotation_pending = 1 WHERE id = $1")
            .bind(&id)
            .execute(w.conn())
            .await?;
    }
    if invited {
        // Their invitation (new, or its role or key) is in their `/sync`.
        w.tell(&b.user_id);
    }
    let revision = w.commit(&state).await?;
    if current.is_none()
        && let Err(e) = send_invitation(&state, &user, invitee_email).await
    {
        tracing::warn!(error = %e, "emailing a vault invitation failed");
    }
    let status = if invited { "invited" } else { "active" };
    let mut answer = json!({ "revision": revision, "status": status });
    if rekey {
        // The sharing app replaces the key now, sealing the new one to everyone.
        answer["rotation_pending"] = true.into();
    }
    Ok(Json(answer))
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Read => "read",
        Role::Write => "write",
        Role::Admin => "admin",
        Role::Owner => "owner",
    }
}

/// "You've been invited to a shared vault", naming the sharer. The vault's name
/// is encrypted, so the email can't say it; the invitee sees it in PassAuth.
async fn send_invitation(state: &AppState, by: &AuthUser, to: String) -> ApiResult<()> {
    if !state.mailer.enabled() {
        return Ok(());
    }
    let name: String = sqlx::query_scalar("SELECT name FROM users WHERE id = $1")
        .bind(&by.user_id)
        .fetch_one(&state.db)
        .await?;
    state
        .mailer
        .send_later(to, invitation_email(&state.config.domain, &name, &by.email));
    Ok(())
}

/// The invitation email: names the sharer and links to the web vault's
/// "Vaults & sharing" page, where invitations are accepted or declined.
pub(crate) fn invitation_email(domain: &str, name: &str, email: &str) -> Email {
    // The name is the sharer's own text: one short line, nothing to dress up as.
    let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    let name = name.trim();
    let sharer = if name.is_empty() {
        email.to_owned()
    } else {
        format!("{name} ({email})")
    };
    Email {
        subject: "You've been invited to a shared vault".into(),
        heading: "You've been invited to a shared vault".into(),
        body: format!(
            "{sharer} invited you to a shared vault on your PassAuth server. Open PassAuth to see the invitation, then accept or decline it. Nothing from the vault appears in your apps until you accept.\nBefore accepting, check with {sharer} in person or by phone that the fingerprint PassAuth shows for them matches theirs."
        ),
        action: Some((
            "See the invitation".into(),
            format!("{domain}/settings/vaults"),
        )),
        code: None,
    }
}

/// `POST /vaults/{id}/invitation/accept`: the invitation becomes membership. The
/// vault's members (now including the caller) get a new revision, so the vault
/// arrives with the next sync. Accepting again is harmless. Answers
/// `{"revision", "vault_seq", "status": "active"}`.
pub(super) async fn accept_invitation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (mut w, invited) = VaultWrite::invitation(&state, &user, &id).await?;
    let seq = w.seq(&id);
    if !invited {
        // Already a member (an earlier try landed): nothing to write.
        drop(w);
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
        return Ok(Json(
            json!({ "revision": revision, "vault_seq": seq - 1, "status": "active" }),
        ));
    }
    sqlx::query(
        "UPDATE vault_members SET status = 'active' WHERE vault_id = $1 AND user_id = $2 AND status = $3",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(INVITED)
    .execute(w.conn())
    .await?;
    w.log(Event::new("member.accepted").vault(&id)).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(
        json!({ "revision": revision, "vault_seq": seq, "status": "active" }),
    ))
}

/// `DELETE /vaults/{id}/invitation`: decline. The invitation goes away (404 when
/// there is none, also once accepted: leave the vault instead). The vault is
/// marked for a key replacement like after someone leaves: the invitation
/// handed out the vault key (sealed to the invitee, whose app opens it to show
/// the vault's name), and a non-member who knows the key shouldn't be able to
/// read what is saved there later, should they ever get the ciphertext.
pub(super) async fn decline_invitation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (mut w, invited) = VaultWrite::invitation(&state, &user, &id).await?;
    if !invited {
        return Err(ApiError::NotFound);
    }
    w.tell(&user.user_id);
    w.bump().await?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(w.conn())
        .await?;
    sqlx::query("UPDATE vaults SET rotation_pending = 1 WHERE id = $1")
        .bind(&id)
        .execute(w.conn())
        .await?;
    w.log(Event::new("member.declined").vault(&id)).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(json!({ "revision": revision })))
}

/// Leave a vault, cancel an invitation, or (older clients) remove a member
/// without replacing the key.
pub(super) async fn remove_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let need = Need::new(&id, Role::Read, None);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let mine = w.role(&id);
    let (target, invited) = membership(w.conn(), &member, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target == Role::Owner {
        return Err(ApiError::Forbidden("the owner cannot be removed".into()));
    }
    if member != user.user_id {
        at_least(mine, Role::Admin)?;
        if target >= mine {
            return Err(ApiError::Forbidden(
                "you can't remove a member at or above your own role".into(),
            ));
        }
    }
    if invited {
        w.tell(&member);
    }
    w.bump().await?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&member)
        .execute(w.conn())
        .await?;
    // The removed member still knows the old key (an invitee's app opened it to
    // show the vault's name). Recorded on the vault, so any admin's client
    // finishes the rotation even if this one never does (a member leaving can't
    // rotate: they lose access). Prefer `.../remove`, which does both.
    sqlx::query("UPDATE vaults SET rotation_pending = 1 WHERE id = $1")
        .bind(&id)
        .execute(w.conn())
        .await?;
    let event = if member == user.user_id {
        Event::new("member.left")
    } else {
        Event::new("member.removed")
            .target(&member)
            .data(json!({ "status": if invited { "invited" } else { "active" }, "rotated": false }))
    };
    w.log(event.vault(&id)).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(
        json!({ "revision": revision, "rotation_required": true }),
    ))
}

#[derive(Deserialize)]
struct RotateKey {
    user_id: String,
    wrapped_key: String,
    key_kind: String,
}

#[derive(Deserialize)]
pub(super) struct Rotate {
    keys: Vec<RotateKey>,
    items: Vec<ItemBody>,
    /// Vault name etc. re-encrypted under the new key, stored in the same
    /// transaction (older clients send it with a separate PUT afterwards).
    #[serde(default)]
    meta: Option<String>,
    /// The epoch of the key being replaced: a rotation that raced another one
    /// gets 409 `vault_key_changed`.
    key_epoch: Option<i64>,
}

/// Replace the vault key for every member and re-encrypted items atomically.
///
/// Everything is checked inside the transaction after locking the vault, so a
/// member or item added meanwhile makes the rotation fail instead of being
/// left on the old key.
pub(super) async fn rotate_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(b): Json<Rotate>,
) -> ApiResult<Json<Value>> {
    check_rotation(&b, &id, &user.user_id)?;
    let need = Need::new(&id, Role::Admin, b.key_epoch);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    // Invitations carry the sealed key and the encrypted name: both change.
    w.tell_invitees(&id);
    let seq = w.seq(&id);
    let key_epoch = apply_rotation(&mut w, &id, &b, seq).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(
        json!({ "revision": revision, "key_epoch": key_epoch, "vault_seq": seq }),
    ))
}

/// Remove a member and replace the vault key in one transaction, so a removal
/// never happens without its rotation. The body is a [`Rotate`] for the members
/// who remain.
pub(super) async fn remove_member_and_rotate(
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
    let need = Need::new(&id, Role::Admin, b.key_epoch);
    let mut w = VaultWrite::begin(&state, &user, &[need]).await?;
    let mine = w.role(&id);
    let (target, invited) = membership(w.conn(), &member, &id)
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
    if invited {
        w.tell(&member);
    }
    // The other invitations carry the vault key and name, which both change.
    w.tell_invitees(&id);
    w.bump().await?;
    sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&member)
        .execute(w.conn())
        .await?;
    w.log(
        Event::new("member.removed")
            .vault(&id)
            .target(&member)
            .data(json!({ "status": if invited { "invited" } else { "active" }, "rotated": true })),
    )
    .await?;
    let seq = w.seq(&id);
    let key_epoch = apply_rotation(&mut w, &id, &b, seq).await?;
    let revision = w.commit(&state).await?;
    Ok(Json(
        json!({ "revision": revision, "key_epoch": key_epoch, "vault_seq": seq }),
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
        i.check_rotated()?;
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

/// Write a rotation inside a write that has locked the vault and checked the
/// caller's role: new keys for exactly the current members (invitees included:
/// they need the new key sealed to them), every item re-encrypted once (stamped
/// with the write's sequence number `seq`), the pending-rotation mark cleared and
/// the key epoch raised. Earlier item versions are deleted: they are encrypted
/// with the old key, which the new one is meant to replace; so are the vault's
/// emergency-access wraps (the owner's apps wrap the new key). Attachments stay as
/// they are: each file has its own key, kept inside its (re-encrypted) item.
/// Returns the new epoch. The caller tells the invitees (their invitation's key
/// and name change).
async fn apply_rotation(w: &mut VaultWrite, id: &str, b: &Rotate, seq: i64) -> ApiResult<i64> {
    let key_epoch = rotate_rows(w.conn(), id, b, seq).await?;
    w.log(
        Event::new("vault.key_rotated")
            .vault(id)
            .data(json!({ "key_epoch": key_epoch })),
    )
    .await?;
    Ok(key_epoch)
}

async fn rotate_rows(conn: &mut AnyConnection, id: &str, b: &Rotate, seq: i64) -> ApiResult<i64> {
    let members: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(id)
            .fetch_all(&mut *conn)
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
        .fetch_one(&mut *conn)
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
            .execute(&mut *conn)
            .await?;
    }
    for i in &b.items {
        let done = match i.revision {
            Some(r) => sqlx::query("UPDATE items SET item_key = $1, data = $2, revision = $3, updated_at = $4, seq = $5 WHERE id = $6 AND vault_id = $7 AND revision = $8")
                .bind(&i.key)
                .bind(&i.data)
                .bind(rev)
                .bind(now())
                .bind(seq)
                .bind(&i.id)
                .bind(id)
                .bind(r)
                .execute(&mut *conn)
                .await?,
            None => sqlx::query("UPDATE items SET item_key = $1, data = $2, revision = $3, updated_at = $4, seq = $5 WHERE id = $6 AND vault_id = $7")
                .bind(&i.key)
                .bind(&i.data)
                .bind(rev)
                .bind(now())
                .bind(seq)
                .bind(&i.id)
                .bind(id)
                .execute(&mut *conn)
                .await?,
        };
        if done.rows_affected() != 1 {
            return Err(match i.revision {
                Some(_) => ApiError::revision_conflict(
                    "an item changed while the key was being replaced; sync and retry",
                ),
                None => ApiError::bad("unknown item in rotation"),
            });
        }
    }
    if let Some(meta) = &b.meta {
        sqlx::query("UPDATE vaults SET meta = $1 WHERE id = $2")
            .bind(meta)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("DELETE FROM item_versions WHERE vault_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    // Emergency contacts' wraps hold the old key; the owner's apps wrap the new one.
    crate::emergency::forget_vault_keys(conn, id).await?;
    Ok(sqlx::query_scalar(
        "UPDATE vaults SET rotation_pending = 0, key_epoch = key_epoch + 1 WHERE id = $1 RETURNING key_epoch",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?)
}
