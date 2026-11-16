//! Vaults, membership/sharing, items and sync. Everything stored here is
//! ciphertext produced by clients; the server only enforces access control.
//!
//! Every write into a vault goes through [`VaultWrite`]: one transaction that
//! locks the vault rows (in id order, so two writes never wait on each other in
//! a circle) and takes each vault's next sequence number in the same statement,
//! checks the caller's role and the key epoch the client encrypted with, makes
//! the change (stamping every item row it writes with that sequence number),
//! checks the vault owners' quotas and gives every member a new sync revision
//! before it commits. The members' clients are told after the commit.
//!
//! Because the sequence number is taken under the vault's row lock, a vault's
//! writes get increasing numbers in the order they commit, and a cursor holding
//! the number a sync saw (`sync.rs`) misses nothing written later.
//!
//! Membership has a status: a vault shared with someone is `invited` until they
//! accept it (`sharing.rs`). Only `active` members can read or write a vault, see
//! it in `/sync`, or get its revisions and live-sync numbers; an invitee only
//! learns that their invitations changed. The same transaction also writes the
//! activity-log events of the change (`crate::events`) and, for edits and
//! trashing, the item's previous version (`history.rs`). Attachments
//! (`attachments.rs`) are vault writes too.

mod attachments;
mod history;
mod items;
mod sharing;
mod signed;
mod sync;

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use sqlx::{Any, AnyConnection, Transaction};

use crate::auth::AuthUser;
use crate::db::{is_postgres, now, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::events::{self, Event};
use crate::settings::Num;
use crate::state::{AppState, SyncNotice};

#[cfg(test)]
pub(crate) use attachments::PENDING_TTL as ATTACHMENT_PENDING_TTL;
pub use attachments::sweep as sweep_attachments;
pub(crate) use attachments::{detach_vault, file_response, remove_files};
pub use history::trim_versions;
pub use items::purge_trash;
#[cfg(test)]
pub(crate) use sharing::KEY_REPLACEMENTS_PER_HOUR;
pub use sharing::insert_vault;
#[cfg(test)]
pub(crate) use sharing::invitation_email;
#[cfg(test)]
pub(crate) use sync::Cursor;
pub use sync::purge_tombstones;

/// Vault names and wrapped or sealed vault keys.
const MAX_BLOB: usize = 2 * 1024 * 1024;
/// Largest encrypted item value the admin may allow (`max_item_kib`); key
/// rotation re-encrypts stored items against this, never the current setting.
const MAX_ITEM_BLOB: usize = Num::MaxItemKib.spec().max as usize * 1024;
/// Request bodies: one item (two blobs) for ordinary routes, whole vaults for
/// import and key rotation.
const ITEM_BODY_LIMIT: usize = 2 * MAX_ITEM_BLOB + 64 * 1024;
const BULK_BODY_LIMIT: usize = 64 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    let bulk = || DefaultBodyLimit::max(BULK_BODY_LIMIT);
    Router::new()
        .route("/sync", get(sync::sync).layer(sync::compression()))
        .route(
            "/sync/revision",
            get(sync::revision).layer(sync::compression()),
        )
        .route("/vaults", post(sharing::create_vault))
        .route(
            "/vaults/{id}",
            put(sharing::update_vault).delete(sharing::delete_vault),
        )
        .route(
            "/vaults/{id}/members",
            get(sharing::list_members).post(sharing::add_member),
        )
        .route(
            "/vaults/{id}/members/{user_id}",
            delete(sharing::remove_member),
        )
        .route(
            "/vaults/{id}/members/{user_id}/remove",
            post(sharing::remove_member_and_rotate).layer(bulk()),
        )
        .route(
            "/vaults/{id}/rotate",
            post(sharing::rotate_vault).layer(bulk()),
        )
        .route(
            "/vaults/{id}/invitation",
            delete(sharing::decline_invitation),
        )
        .route(
            "/vaults/{id}/invitation/accept",
            post(sharing::accept_invitation),
        )
        .route("/vaults/{id}/events", get(vault_events))
        .route("/vaults/{id}/rosters", get(signed::rosters))
        .route("/vaults/{id}/resign", post(signed::resign).layer(bulk()))
        .route("/users/lookup", get(sharing::lookup_user))
        .route("/items", post(items::create_item))
        .route("/items/import", post(items::import_items).layer(bulk()))
        .route(
            "/items/{id}",
            put(items::update_item).delete(items::trash_item),
        )
        .route("/items/{id}/restore", post(items::restore_item))
        .route("/items/{id}/permanent", delete(items::purge_item))
        .route("/items/{id}/versions", get(history::list_versions))
        .route("/items/{id}/versions/{seq}", get(history::get_version))
        .route(
            "/items/{id}/attachments",
            get(attachments::list).post(attachments::create),
        )
        // The upload streams its body itself, within the attachment's size
        // (`DefaultBodyLimit` doesn't apply to a raw `Body`).
        .route(
            "/attachments/{id}",
            get(attachments::download)
                .put(attachments::upload)
                .delete(attachments::remove),
        )
        .layer(DefaultBodyLimit::max(ITEM_BODY_LIMIT))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

fn check_id(id: &str) -> ApiResult<()> {
    uuid::Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| ApiError::bad("ids must be UUIDs"))
}

fn check_blob(s: &str) -> ApiResult<()> {
    check_size(s, MAX_BLOB)
}

fn check_size(s: &str, max: usize) -> ApiResult<()> {
    if s.is_empty() || s.len() > max {
        return Err(ApiError::bad("encrypted value missing or too large"));
    }
    Ok(())
}

/// An item's encrypted key or data, within the admin's `max_item_kib`.
fn check_item_blob(state: &AppState, s: &str) -> ApiResult<()> {
    check_size(s, state.num(Num::MaxItemKib) as usize * 1024)
}

/// Bytes an item counts for in its vault owner's storage (encrypted key + data).
fn item_bytes(key: &str, data: &str) -> i64 {
    (key.len() + data.len()) as i64
}

/// A user's role in a vault they can use: active memberships only (an
/// invitation gives no access until it is accepted).
async fn member_role(
    conn: &mut AnyConnection,
    user_id: &str,
    vault_id: &str,
) -> ApiResult<Option<Role>> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM vault_members WHERE vault_id = $1 AND user_id = $2 AND status = 'active'",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    role.as_deref().map(Role::parse).transpose()
}

/// Someone's membership whatever its status: their role, and whether it is
/// still an invitation.
async fn membership(
    conn: &mut AnyConnection,
    user_id: &str,
    vault_id: &str,
) -> ApiResult<Option<(Role, bool)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT role, status FROM vault_members WHERE vault_id = $1 AND user_id = $2",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(role, status)| Ok((Role::parse(&role)?, status == INVITED)))
        .transpose()
}

/// `vault_members.status` of a share not accepted yet (the other value is `active`).
const INVITED: &str = "invited";

fn at_least(role: Role, min: Role) -> ApiResult<Role> {
    if role < min {
        return Err(ApiError::Forbidden(
            "insufficient permission for this vault".into(),
        ));
    }
    Ok(role)
}

/// The caller's role for reads (no lock): 404 for non-members.
async fn require(state: &AppState, user_id: &str, vault_id: &str, min: Role) -> ApiResult<Role> {
    let mut conn = state.db.acquire().await?;
    let role = member_role(&mut conn, user_id, vault_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    at_least(role, min)
}

/// `GET /vaults/{id}/events`: the vault's activity log, for its owner and admins.
async fn vault_events(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<events::Page>,
) -> ApiResult<Json<events::EventPage>> {
    require(&state, &user.user_id, &id, Role::Admin).await?;
    Ok(Json(events::vault_events(&state, &user, &id, &q).await?))
}

// ------------------------------------------------------------ vault writes

/// What a write needs from one vault: the caller's role at least `min` and,
/// when the client says which key epoch it encrypted with (or wrapped), that
/// it is still the vault's current one.
struct Need<'a> {
    vault: &'a str,
    min: Role,
    epoch: Option<i64>,
}

impl<'a> Need<'a> {
    fn new(vault: &'a str, min: Role, epoch: Option<i64>) -> Self {
        Self { vault, min, epoch }
    }
}

struct Locked {
    id: String,
    /// The caller's role (`None` for the server's own writes, e.g. the trash sweeper).
    role: Option<Role>,
    key_epoch: i64,
    /// The vault's sequence number taken by this write.
    seq: i64,
}

/// One write into one or more vaults; see the module docs. Dropping it without
/// [`VaultWrite::commit`] rolls everything back.
struct VaultWrite {
    tx: Transaction<'static, Any>,
    /// The caller (`None` for the server's own writes, e.g. the trash sweeper).
    me: Option<AuthUser>,
    /// Live-sync origin of the writing session (`None` for the server's own writes).
    origin: Option<String>,
    locked: Vec<Locked>,
    /// Vaults created in this write: their members get a new revision too.
    created: Vec<String>,
    /// Vaults whose invitations change with this write (name, key, the vault
    /// itself): their invitees get a new revision too.
    invitees_of: BTreeSet<String>,
    /// Other users whose `/sync` changes with this write (someone invited, or
    /// whose invitation went away).
    also: BTreeSet<String>,
    /// What this write adds to each vault (negative: takes away), for its owners' quotas.
    charges: BTreeMap<String, Charge>,
    /// What this write adds to users directly: an attachment upload counts against
    /// whoever started it until it is ready (then against the vault's owners).
    user_charges: BTreeMap<String, Charge>,
    /// Notices for the members, made when the revisions were given out (see [`VaultWrite::bump`]).
    bumped: Option<Vec<(String, SyncNotice)>>,
    postgres: bool,
    /// The admin's `event_ip` when the write began.
    keep_ip: bool,
    /// The admin's `item_versions_kept` when the write began.
    versions_kept: i64,
}

impl VaultWrite {
    /// Begin a write by `me`: lock each vault named in `needs` (in id order, once
    /// each), then check the caller's role (404 for non-members) and the key epoch.
    async fn begin(state: &AppState, me: &AuthUser, needs: &[Need<'_>]) -> ApiResult<Self> {
        let mut w = Self::start(state, Some(me)).await?;
        let mut needs: Vec<&Need> = needs.iter().collect();
        needs.sort_by_key(|n| n.vault);
        for need in needs {
            let epoch = w.lock(need.vault).await?;
            at_least(w.role(need.vault), need.min)?;
            if need.epoch.is_some_and(|e| e != epoch) {
                return Err(ApiError::vault_key_changed());
            }
        }
        Ok(w)
    }

    /// A write by the server itself (no caller, no role check) into `vault`.
    async fn system(state: &AppState, vault: &str) -> ApiResult<Self> {
        let mut w = Self::start(state, None).await?;
        w.lock(vault).await?;
        Ok(w)
    }

    /// A write by `me` into a vault they were invited to (accept or decline):
    /// locks it like any write, and returns whether the membership is still an
    /// invitation (404 when there is none).
    async fn invitation(state: &AppState, me: &AuthUser, vault: &str) -> ApiResult<(Self, bool)> {
        let mut w = Self::start(state, Some(me)).await?;
        let (seq, epoch) = w.lock_row(vault).await?;
        let (role, invited) = membership(&mut w.tx, &me.user_id, vault)
            .await?
            .ok_or(ApiError::NotFound)?;
        w.locked.push(Locked {
            id: vault.to_owned(),
            role: Some(role),
            key_epoch: epoch,
            seq,
        });
        Ok((w, invited))
    }

    async fn start(state: &AppState, me: Option<&AuthUser>) -> ApiResult<Self> {
        Ok(Self {
            tx: state.db.begin().await?,
            me: me.cloned(),
            origin: me.map(|u| state.origin(&u.session_id)),
            locked: Vec::new(),
            created: Vec::new(),
            invitees_of: BTreeSet::new(),
            also: BTreeSet::new(),
            charges: BTreeMap::new(),
            user_charges: BTreeMap::new(),
            bumped: None,
            postgres: is_postgres(&state.config.database_url),
            keep_ip: state.numbers.event_ip(),
            versions_kept: state.num(Num::ItemVersionsKept),
        })
    }

    /// Take the vault's row lock (PostgreSQL) / the write lock (SQLite: a write
    /// first, so the transaction never has to upgrade from reading) for the rest
    /// of the transaction, and its next sequence number in the same statement.
    /// Returns the vault's key epoch.
    async fn lock(&mut self, vault: &str) -> ApiResult<i64> {
        if let Some(l) = self.locked.iter().find(|l| l.id == vault) {
            return Ok(l.key_epoch);
        }
        let (seq, epoch) = self.lock_row(vault).await?;
        let role = match &self.me {
            Some(me) => Some(
                member_role(&mut self.tx, &me.user_id, vault)
                    .await?
                    .ok_or(ApiError::NotFound)?,
            ),
            None => None,
        };
        self.locked.push(Locked {
            id: vault.to_owned(),
            role,
            key_epoch: epoch,
            seq,
        });
        Ok(epoch)
    }

    /// The row lock and the next sequence number: (seq, key epoch); 404 for no vault.
    async fn lock_row(&mut self, vault: &str) -> ApiResult<(i64, i64)> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "UPDATE vaults SET updated_at = $1, seq = seq + 1 WHERE id = $2 RETURNING seq, key_epoch",
        )
        .bind(now())
        .bind(vault)
        .fetch_optional(&mut *self.tx)
        .await?;
        row.ok_or(ApiError::NotFound)
    }

    /// Write an activity-log event in this transaction, done by the caller.
    async fn log(&mut self, event: Event) -> ApiResult<()> {
        let event = match &self.me {
            Some(me) => event.by(me),
            None => event,
        };
        event.record_with(&mut self.tx, self.keep_ip).await
    }

    /// `user`'s `/sync` changes with this write although they aren't an active
    /// member (an invitation came or went): they get a new revision too. Call it
    /// before [`Self::bump`].
    fn tell(&mut self, user: &str) {
        debug_assert!(self.bumped.is_none(), "tell() after bump()");
        self.also.insert(user.to_owned());
    }

    /// The invitations to `vault` change with this write (its name, its key, or
    /// the vault itself): its invitees get a new revision too. Call it before
    /// [`Self::bump`].
    fn tell_invitees(&mut self, vault: &str) {
        debug_assert!(self.bumped.is_none(), "tell_invitees() after bump()");
        self.invitees_of.insert(vault.to_owned());
    }

    fn locked(&self, vault: &str) -> &Locked {
        self.locked
            .iter()
            .find(|l| l.id == vault)
            .expect("a vault locked by this write")
    }

    /// The caller's role in a vault this write has locked.
    fn role(&self, vault: &str) -> Role {
        self.locked(vault)
            .role
            .expect("role of a vault locked by a caller's write")
    }

    /// The sequence number of this write in a vault it has locked: every item
    /// row it writes there carries it.
    fn seq(&self, vault: &str) -> i64 {
        self.locked(vault).seq
    }

    fn conn(&mut self) -> &mut AnyConnection {
        &mut self.tx
    }

    /// The members of `vault` (created in this write) get a new revision too.
    fn created(&mut self, vault: &str) {
        self.created.push(vault.to_owned());
    }

    /// Count `items` and `bytes` (either may be negative) against the owners of
    /// `vault`, checked at [`Self::commit`].
    fn charge(&mut self, vault: &str, items: i64, bytes: i64) {
        let c = self.charges.entry(vault.to_owned()).or_default();
        c.items += items;
        c.bytes += bytes;
    }

    /// Count `bytes` of ready attachments (may be negative) against the owners of
    /// `vault`: their storage and their attachment storage.
    fn charge_files(&mut self, vault: &str, bytes: i64) {
        let c = self.charges.entry(vault.to_owned()).or_default();
        c.bytes += bytes;
        c.files += bytes;
    }

    /// Count `bytes` of attachment uploads that haven't finished (may be negative)
    /// against `user`, who started them.
    fn charge_uploader(&mut self, user: &str, bytes: i64) {
        let c = self.user_charges.entry(user.to_owned()).or_default();
        c.bytes += bytes;
        c.files += bytes;
    }

    /// `item` left `vault` in this write (deleted for good or moved out): apps
    /// that sync changes only learn it from this tombstone.
    async fn tombstone(&mut self, vault: &str, item: &str) -> ApiResult<()> {
        let seq = self.seq(vault);
        sqlx::query(
            "INSERT INTO item_tombstones (vault_id, item_id, seq, deleted_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (vault_id, item_id) DO UPDATE SET seq = excluded.seq, deleted_at = excluded.deleted_at",
        )
        .bind(vault)
        .bind(item)
        .bind(seq)
        .bind(now())
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The items this write put into `vault` (created or moved in) are no
    /// longer deleted there.
    async fn untombstone(&mut self, vault: &str) -> ApiResult<()> {
        let seq = self.seq(vault);
        sqlx::query(
            "DELETE FROM item_tombstones WHERE vault_id = $1
             AND item_id IN (SELECT id FROM items WHERE vault_id = $1 AND seq = $2)",
        )
        .bind(vault)
        .bind(seq)
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Refuse the write when it takes someone past the admin's item, storage or
    /// attachment limit: a vault's owners for what the write adds to the vault, an
    /// uploader for the uploads they started. Only growth counts: a write that keeps
    /// or lowers someone's usage always passes, also above a limit that was lowered
    /// later. Run after [`Self::bump`], which locked every member's row.
    async fn check_quota(&mut self, state: &AppState) -> ApiResult<()> {
        let charges = std::mem::take(&mut self.charges);
        let mut owners = std::mem::take(&mut self.user_charges);
        let (max_items, max_bytes) = quota(state);
        let max_files = attachment_quota(state);
        if (charges.is_empty() && owners.is_empty())
            || (max_items == 0 && max_bytes == 0 && max_files == 0)
        {
            return Ok(());
        }
        for (vault, charge) in charges {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT user_id FROM vault_members WHERE vault_id = $1 AND role = 'owner'",
            )
            .bind(&vault)
            .fetch_all(&mut *self.tx)
            .await?;
            for id in ids {
                owners.entry(id).or_default().add(charge);
            }
        }
        let growing: Vec<(String, Charge)> = owners
            .into_iter()
            .filter(|(_, c)| {
                (c.items > 0 && max_items > 0)
                    || (c.bytes > 0 && max_bytes > 0)
                    || (c.files > 0 && max_files > 0)
            })
            .collect();
        if growing.is_empty() {
            return Ok(());
        }
        // PostgreSQL: their rows locked (in id order; `bump` already holds them), so
        // writes at once into different vaults of one owner check one after the
        // other instead of each seeing only its own new rows.
        let ids: Vec<String> = growing.iter().map(|(id, _)| id.clone()).collect();
        lock_users(&mut self.tx, self.postgres, &ids).await?;
        for (owner, c) in growing {
            let more_items = c.items > 0 && max_items > 0;
            let more_bytes = c.bytes > 0 && max_bytes > 0;
            if more_items || more_bytes {
                let (count, size) = usage(&mut self.tx, &owner).await?;
                if (more_items && count > max_items) || (more_bytes && size > max_bytes) {
                    return Err(ApiError::quota_exceeded());
                }
            }
            if c.files > 0
                && max_files > 0
                && attachment_usage(&mut self.tx, &owner).await? > max_files
            {
                return Err(ApiError::attachment_quota_exceeded());
            }
        }
        Ok(())
    }

    /// Give every active member of the written vaults a new sync revision now
    /// (with the vaults' new numbers for live sync), and the invitees and other
    /// users this write concerns one with no vault numbers. Done before removing
    /// members, so they learn that they lost the vault.
    async fn bump(&mut self) -> ApiResult<()> {
        let mut seqs: BTreeMap<String, i64> =
            self.locked.iter().map(|l| (l.id.clone(), l.seq)).collect();
        for vault in &self.created {
            seqs.entry(vault.clone()).or_insert(0);
        }
        let vaults: Vec<String> = seqs.keys().cloned().collect();
        let mut theirs: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        for (user, vault) in members_of(&mut self.tx, self.postgres, &vaults).await? {
            if let Some(seq) = seqs.get(&vault) {
                theirs.entry(user).or_default().insert(vault, *seq);
            }
        }
        let invited: Vec<String> = self.invitees_of.iter().cloned().collect();
        for (user, _) in invitees_of(&mut self.tx, self.postgres, &invited).await? {
            theirs.entry(user).or_default();
        }
        for user in &self.also {
            theirs.entry(user.clone()).or_default();
        }
        let users: Vec<String> = theirs.keys().cloned().collect();
        let revisions = bump_users(&mut self.tx, self.postgres, &users).await?;
        let notices = revisions
            .into_iter()
            .map(|(user, revision)| {
                let mut notice = SyncNotice::new(revision, self.origin.clone());
                notice.vaults = theirs.remove(&user).unwrap_or_default();
                (user, notice)
            })
            .collect();
        self.bumped = Some(notices);
        Ok(())
    }

    /// Bump the revisions (unless [`Self::bump`] did), check the quotas, commit,
    /// and tell the members' clients. Returns the caller's new revision. The bump
    /// comes first: it locks the user rows of every member (owners and uploaders
    /// among them) in id order, which the quota check then relies on.
    async fn commit(mut self, state: &AppState) -> ApiResult<i64> {
        if self.bumped.is_none() {
            self.bump().await?;
        }
        self.check_quota(state).await?;
        let Self { tx, me, bumped, .. } = self;
        tx.commit().await?;
        let notices = bumped.unwrap_or_default();
        let revision = own_revision(&notices, me.as_ref().map(|u| u.user_id.as_str()));
        state.notify_sync(notices);
        Ok(revision)
    }
}

/// What a write adds to (or, negative, takes from) someone's storage.
#[derive(Clone, Copy, Debug, Default)]
struct Charge {
    items: i64,
    /// Every byte, attachments included.
    bytes: i64,
    /// The attachments' part of `bytes`.
    files: i64,
}

impl Charge {
    fn add(&mut self, other: Charge) {
        self.items += other.items;
        self.bytes += other.bytes;
        self.files += other.files;
    }
}

/// The admin's per-user limits: (items, bytes); 0 = none.
pub(crate) fn quota(state: &AppState) -> (i64, i64) {
    (
        state.num(Num::MaxItemsPerUser),
        state.num(Num::MaxStorageMbPerUser) * 1024 * 1024,
    )
}

/// The admin's attachment storage limit per user, in bytes; 0 = none.
pub(crate) fn attachment_quota(state: &AppState) -> i64 {
    state.num(Num::MaxAttachmentStorageMbPerUser) * 1024 * 1024
}

/// Items, and bytes (encrypted key + data of items, trash included, and of
/// their earlier versions, and the encrypted size of their ready attachments), in
/// the vaults a user owns; the bytes also count the user's Sends (encrypted name,
/// data and wrapped key) and the attachment uploads they started that haven't
/// finished (whoever owns the vault).
pub(crate) async fn usage(conn: &mut AnyConnection, user_id: &str) -> ApiResult<(i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
            WHERE m.user_id = $1 AND m.role = 'owner'),
           CAST((SELECT COALESCE(SUM(octet_length(i.item_key) + octet_length(i.data)), 0)
                 FROM items i JOIN vault_members m ON m.vault_id = i.vault_id
                 WHERE m.user_id = $1 AND m.role = 'owner')
              + (SELECT COALESCE(SUM(octet_length(v.item_key) + octet_length(v.data)), 0)
                 FROM item_versions v JOIN vault_members m ON m.vault_id = v.vault_id
                 WHERE m.user_id = $1 AND m.role = 'owner')
              + (SELECT COALESCE(SUM(a.size), 0)
                 FROM attachments a JOIN vault_members m ON m.vault_id = a.vault_id
                 WHERE m.user_id = $1 AND m.role = 'owner' AND a.state = 'ready')
              + (SELECT COALESCE(SUM(a.size), 0)
                 FROM attachments a WHERE a.created_by = $1 AND a.state = 'pending')
              + (SELECT COALESCE(SUM(octet_length(s.name) + octet_length(s.data) + octet_length(s.owner_key)), 0)
                 FROM sends s WHERE s.user_id = $1) AS BIGINT)",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?)
}

/// Bytes of attachments that count against a user ([`attachment_quota`]): the
/// ready ones in the vaults they own and the uploads they started that haven't
/// finished.
pub(crate) async fn attachment_usage(conn: &mut AnyConnection, user_id: &str) -> ApiResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT CAST(
           (SELECT COALESCE(SUM(a.size), 0)
            FROM attachments a JOIN vault_members m ON m.vault_id = a.vault_id
            WHERE m.user_id = $1 AND m.role = 'owner' AND a.state = 'ready')
         + (SELECT COALESCE(SUM(a.size), 0)
            FROM attachments a WHERE a.created_by = $1 AND a.state = 'pending') AS BIGINT)",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?)
}

/// PostgreSQL: lock these users' rows (in id order, so two writes never wait on
/// each other in a circle) for the rest of the transaction, before reading their
/// usage. SQLite needs nothing: its writers take turns for the whole transaction.
pub(crate) async fn lock_users(
    conn: &mut AnyConnection,
    postgres: bool,
    users: &[String],
) -> ApiResult<()> {
    if !postgres || users.is_empty() {
        return Ok(());
    }
    let ids = serde_json::to_string(users).map_err(anyhow::Error::from)?;
    sqlx::query(
        "SELECT id FROM users WHERE id IN (SELECT json_array_elements_text($1::json))
         ORDER BY id FOR UPDATE",
    )
    .bind(&ids)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// (member, vault) for every active member of `vaults`.
async fn members_of(
    conn: &mut AnyConnection,
    postgres: bool,
    vaults: &[String],
) -> ApiResult<Vec<(String, String)>> {
    if vaults.is_empty() {
        return Ok(Vec::new());
    }
    let ids = serde_json::to_string(vaults).map_err(anyhow::Error::from)?;
    let sql = if postgres {
        "SELECT user_id, vault_id FROM vault_members
         WHERE vault_id IN (SELECT json_array_elements_text($1::json)) AND status = 'active'"
    } else {
        "SELECT user_id, vault_id FROM vault_members
         WHERE vault_id IN (SELECT value FROM json_each($1)) AND status = 'active'"
    };
    Ok(sqlx::query_as(sql).bind(ids).fetch_all(&mut *conn).await?)
}

/// (invitee, vault) for every pending invitation to `vaults`.
async fn invitees_of(
    conn: &mut AnyConnection,
    postgres: bool,
    vaults: &[String],
) -> ApiResult<Vec<(String, String)>> {
    if vaults.is_empty() {
        return Ok(Vec::new());
    }
    let ids = serde_json::to_string(vaults).map_err(anyhow::Error::from)?;
    let sql = if postgres {
        "SELECT user_id, vault_id FROM vault_members
         WHERE vault_id IN (SELECT json_array_elements_text($1::json)) AND status = 'invited'"
    } else {
        "SELECT user_id, vault_id FROM vault_members
         WHERE vault_id IN (SELECT value FROM json_each($1)) AND status = 'invited'"
    };
    Ok(sqlx::query_as(sql).bind(ids).fetch_all(&mut *conn).await?)
}

/// `me`'s revision among `notices`, else the highest (`me` left the vault).
fn own_revision(notices: &[(String, SyncNotice)], me: Option<&str>) -> i64 {
    notices
        .iter()
        .find(|(u, _)| Some(u.as_str()) == me)
        .or_else(|| notices.iter().max_by_key(|(_, n)| n.revision))
        .map_or_else(now_ms, |(_, n)| n.revision)
}

/// New sync revisions for the active members of `vaults` and the invitees of
/// `invitations_of`, inside the caller's transaction (account deletion).
pub(crate) async fn bump_members(
    conn: &mut AnyConnection,
    postgres: bool,
    vaults: &[String],
    invitations_of: &[String],
) -> ApiResult<Vec<(String, i64)>> {
    let mut users: BTreeSet<String> = members_of(conn, postgres, vaults)
        .await?
        .into_iter()
        .map(|(user, _)| user)
        .collect();
    users.extend(
        invitees_of(conn, postgres, invitations_of)
            .await?
            .into_iter()
            .map(|(user, _)| user),
    );
    bump_users(conn, postgres, &users.into_iter().collect::<Vec<_>>()).await
}

/// New sync revisions for `users`, in one statement inside the caller's
/// transaction. A revision never goes backwards, even if the clock does (NTP
/// step, VM restore), or clients would ignore every change until the clock
/// caught up. PostgreSQL first locks all the user rows in id order, so two
/// writes with users in common can't deadlock.
async fn bump_users(
    conn: &mut AnyConnection,
    postgres: bool,
    users: &[String],
) -> ApiResult<Vec<(String, i64)>> {
    if users.is_empty() {
        return Ok(Vec::new());
    }
    let ids = serde_json::to_string(users).map_err(anyhow::Error::from)?;
    let rev = now_ms();
    let revisions = if postgres {
        lock_users(conn, postgres, users).await?;
        sqlx::query_as(
            "UPDATE users SET revision = CASE WHEN revision >= $1 THEN revision + 1 ELSE $1 END
             WHERE id IN (SELECT json_array_elements_text($2::json))
             RETURNING id, revision",
        )
        .bind(rev)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query_as(
            "UPDATE users SET revision = CASE WHEN revision >= $1 THEN revision + 1 ELSE $1 END
             WHERE id IN (SELECT value FROM json_each($2))
             RETURNING id, revision",
        )
        .bind(rev)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
    };
    Ok(revisions)
}

/// A new sync revision for one user (their own data changed: profile, email
/// verification, account keys). `None` when the user doesn't exist.
pub(crate) async fn bump_user(conn: &mut AnyConnection, user_id: &str) -> ApiResult<Option<i64>> {
    Ok(sqlx::query_scalar(
        "UPDATE users SET revision = CASE WHEN revision >= $1 THEN revision + 1 ELSE $1 END
         WHERE id = $2 RETURNING revision",
    )
    .bind(now_ms())
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?)
}

/// Lock a vault the server is about to change for a reason other than a
/// vault write (account deletion), taking its next sequence number like a
/// write; false when it no longer exists.
pub(crate) async fn lock_vault(conn: &mut AnyConnection, vault_id: &str) -> ApiResult<bool> {
    let done = sqlx::query("UPDATE vaults SET updated_at = $1, seq = seq + 1 WHERE id = $2")
        .bind(now())
        .bind(vault_id)
        .execute(&mut *conn)
        .await?;
    Ok(done.rows_affected() == 1)
}
