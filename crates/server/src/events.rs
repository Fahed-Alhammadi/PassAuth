//! Activity log: who did what and when, from which app (and address, while the
//! admin's `event_ip` is on). Every event is written in the same transaction as
//! the change it describes, so a write that fails leaves no event behind.
//!
//! Events hold ids, counts, roles, and method or setting names only: never item
//! names, URLs or any other vault content (the server has none in plaintext
//! anyway) and never setting values. They are kept `event_days` (admin page);
//! the sweeper deletes older ones.
//!
//! Sends (`send.*`) name the Send in `data` (`{"send": id}`); visitors opening one
//! are counted per Send and hour (`send.accessed`) without any address or app.
//!
//! Reading: `GET /account/events` (the user's own actions and actions on their
//! account), `GET /vaults/{id}/events` (the vault's owner and admins) and
//! `GET /admin/events` (the admin page, with filters). Pages go newest first;
//! `next` is an opaque cursor for `before`. An address is shown to the admin page,
//! to the person who acted, and to the account owner for what nobody signed in did
//! to their account (failed sign-ins, a revoked stolen session); vault admins never
//! see other members' addresses, and users never see the admin page's.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Json;
use axum::extract::{Query, State};
use passauth_core::item::{b64, unb64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AnyConnection;

use crate::admin::Admin;
use crate::auth::AuthUser;
use crate::db::{Db, now};
use crate::error::{ApiError, ApiResult};
use crate::settings::Num;
use crate::state::{App, AppState};

/// One activity-log entry about to be written.
#[derive(Default)]
pub struct Event {
    kind: &'static str,
    actor: Option<String>,
    session: Option<String>,
    client: Option<String>,
    ip: Option<String>,
    vault: Option<String>,
    item: Option<String>,
    target: Option<String>,
    data: Option<Value>,
}

impl Event {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Done by a signed-in user, in the request's session, app and address.
    pub fn by(mut self, user: &AuthUser) -> Self {
        self.actor = Some(user.user_id.clone());
        self.session = Some(user.session_id.clone());
        self.client.clone_from(&user.client);
        self.ip.clone_from(&user.ip);
        self
    }

    /// Done on the admin page (no user), from the request's app and address.
    pub fn by_admin(mut self, admin: &Admin) -> Self {
        self.client.clone_from(&admin.client);
        self.ip.clone_from(&admin.ip);
        self
    }

    /// The app and address of a request without a session (sign-in).
    pub fn from(mut self, client: Option<String>, ip: Option<String>) -> Self {
        self.client = client;
        self.ip = ip;
        self
    }

    pub fn actor(mut self, user_id: &str) -> Self {
        self.actor = Some(user_id.to_owned());
        self
    }

    pub fn session(mut self, session_id: &str) -> Self {
        self.session = Some(session_id.to_owned());
        self
    }

    pub fn vault(mut self, vault_id: &str) -> Self {
        self.vault = Some(vault_id.to_owned());
        self
    }

    pub fn item(mut self, item_id: &str) -> Self {
        self.item = Some(item_id.to_owned());
        self
    }

    /// The user the action was done to (a member invited or removed, an account
    /// the admin disabled…).
    pub fn target(mut self, user_id: &str) -> Self {
        self.target = Some(user_id.to_owned());
        self
    }

    /// Counts, roles, names of methods or settings: never vault content or values.
    pub fn data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Write it inside the caller's transaction.
    pub async fn record(self, conn: &mut AnyConnection, state: &App) -> ApiResult<()> {
        self.record_with(conn, state.numbers.event_ip()).await
    }

    /// [`Self::record`] with the `event_ip` switch read by the caller.
    pub async fn record_with(self, conn: &mut AnyConnection, keep_ip: bool) -> ApiResult<()> {
        sqlx::query(
            "INSERT INTO events (id, at, type, actor_id, session_id, client, ip, vault_id, item_id, target_user_id, data)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        // Time-ordered: events of one second keep the order they happened in.
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(now())
        .bind(self.kind)
        .bind(self.actor)
        .bind(self.session)
        .bind(self.client)
        .bind(self.ip.filter(|_| keep_ip))
        .bind(self.vault)
        .bind(self.item)
        .bind(self.target)
        .bind(self.data.map(|d| d.to_string()))
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
}

/// A failed sign-in to an existing account, waiting to be counted.
struct Failure {
    user_id: String,
    reason: &'static str,
    client: Option<String>,
    /// Already dropped when the admin's `event_ip` was off at the failure.
    ip: Option<String>,
}

/// Failed sign-ins that wait for [`count_failure`]. Counting writes to the
/// database; doing that before answering would make a wrong password for an
/// existing account slower than one for an email without an account (which
/// writes nothing), so the answer goes out first and one background task counts
/// the failures in order. Best effort, like the count itself: while it is far
/// behind (a flood), further failures are left out of the log (the rate limits
/// still count them).
pub struct FailureLog {
    queue: tokio::sync::mpsc::Sender<Failure>,
    /// Failures queued and not yet counted.
    waiting: Arc<AtomicUsize>,
    counted: Arc<tokio::sync::Notify>,
}

/// Failures that may wait at once.
const FAILURE_QUEUE: usize = 1024;

impl FailureLog {
    /// Start the background task that counts failures in `db`. Needs a Tokio
    /// runtime; the task ends when the log is dropped.
    pub fn start(db: Db) -> Self {
        let (queue, mut next) = tokio::sync::mpsc::channel::<Failure>(FAILURE_QUEUE);
        let waiting = Arc::new(AtomicUsize::new(0));
        let counted = Arc::new(tokio::sync::Notify::new());
        let (left, done) = (Arc::clone(&waiting), Arc::clone(&counted));
        tokio::spawn(async move {
            use futures_util::FutureExt;
            while let Some(failure) = next.recv().await {
                // A panic loses this count, never the task.
                let counted = std::panic::AssertUnwindSafe(count_failure(&db, failure))
                    .catch_unwind()
                    .await;
                match counted {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!(error = %e, "recording a failed sign-in failed"),
                    Err(_) => tracing::error!("recording a failed sign-in panicked"),
                }
                left.fetch_sub(1, Ordering::SeqCst);
                done.notify_waiters();
            }
        });
        Self {
            queue,
            waiting,
            counted,
        }
    }

    /// Count a failed sign-in to `user_id` after the answer has gone out. `ip` is
    /// kept only while `keep_ip` (the admin's `event_ip`) is on.
    pub fn record(
        &self,
        user_id: &str,
        reason: &'static str,
        client: Option<String>,
        ip: Option<String>,
        keep_ip: bool,
    ) {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let failure = Failure {
            user_id: user_id.to_owned(),
            reason,
            client,
            ip: ip.filter(|_| keep_ip),
        };
        if self.queue.try_send(failure).is_err() {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            self.counted.notify_waiters();
            tracing::warn!(
                user = %user_id,
                reason,
                "too many failed sign-ins at once; this one is left out of the activity log"
            );
        }
    }

    /// Wait until every failure recorded so far is counted.
    #[cfg(test)]
    pub async fn flush(&self) {
        loop {
            let counted = self.counted.notified();
            tokio::pin!(counted);
            counted.as_mut().enable();
            if self.waiting.load(Ordering::SeqCst) == 0 {
                return;
            }
            counted.await;
        }
    }
}

/// Failed sign-ins to an existing account are counted, not logged one by one:
/// one `auth.signin_failed` event per account, reason and clock hour, with
/// `{"reason", "count"}`, showing the newest attempt's time, app and address. A
/// guesser held back only by the rate limits would otherwise write thousands of
/// rows a day. Reasons: `password`, `reauth` (a wrong password when confirming
/// it for a sensitive action), `two_step`, `account_disabled`, `email_not_verified`.
/// Runs in [`FailureLog`]'s task, after the answer went out.
async fn count_failure(db: &Db, f: Failure) -> ApiResult<()> {
    let Failure {
        user_id,
        reason,
        client,
        ip,
    } = f;
    let t = now();
    let hour = t - t.rem_euclid(3600);
    let mut conn = db.acquire().await?;
    // Compare-and-swap on the row's data: two failures at once never lose a count.
    for _ in 0..3 {
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, data FROM events
             WHERE target_user_id = $1 AND type = 'auth.signin_failed' AND at >= $2",
        )
        .bind(&user_id)
        .bind(hour)
        .fetch_all(&mut *conn)
        .await?;
        let found = rows.into_iter().find_map(|(id, data)| {
            let data = data?;
            let parsed: Value = serde_json::from_str(&data).ok()?;
            (parsed["reason"] == reason).then(|| (id, parsed["count"].as_i64().unwrap_or(1), data))
        });
        let Some((id, count, old)) = found else {
            break;
        };
        let done = sqlx::query(
            "UPDATE events SET at = $1, data = $2, client = $3, ip = $4 WHERE id = $5 AND data = $6",
        )
        .bind(t)
        .bind(json!({ "reason": reason, "count": count + 1 }).to_string())
        .bind(&client)
        .bind(&ip)
        .bind(&id)
        .bind(&old)
        .execute(&mut *conn)
        .await?;
        if done.rows_affected() == 1 {
            return Ok(());
        }
    }
    let keep_ip = ip.is_some();
    Event::new("auth.signin_failed")
        .target(&user_id)
        .from(client, ip)
        .data(json!({ "reason": reason, "count": 1 }))
        .record_with(&mut conn, keep_ip)
        .await
}

/// A visitor opened a Send: one `send.accessed` event per Send and clock hour
/// with `{"send", "count"}`, for its owner (`target`), inside the caller's
/// transaction. Visitors are anonymous: no address and no app are kept, so the
/// owner (and the admin page) only ever see how often.
pub async fn count_send_access(
    conn: &mut AnyConnection,
    owner: &str,
    send_id: &str,
) -> ApiResult<()> {
    let t = now();
    let hour = t - t.rem_euclid(3600);
    // The caller holds the Send's row lock, so accesses to one Send take turns;
    // the compare-and-swap still never loses a count.
    for _ in 0..3 {
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, data FROM events
             WHERE target_user_id = $1 AND type = 'send.accessed' AND at >= $2",
        )
        .bind(owner)
        .bind(hour)
        .fetch_all(&mut *conn)
        .await?;
        let found = rows.into_iter().find_map(|(id, data)| {
            let data = data?;
            let parsed: Value = serde_json::from_str(&data).ok()?;
            (parsed["send"] == send_id).then(|| (id, parsed["count"].as_i64().unwrap_or(1), data))
        });
        let Some((id, count, old)) = found else {
            break;
        };
        let done = sqlx::query("UPDATE events SET at = $1, data = $2 WHERE id = $3 AND data = $4")
            .bind(t)
            .bind(json!({ "send": send_id, "count": count + 1 }).to_string())
            .bind(&id)
            .bind(&old)
            .execute(&mut *conn)
            .await?;
        if done.rows_affected() == 1 {
            return Ok(());
        }
    }
    Event::new("send.accessed")
        .target(owner)
        .data(json!({ "send": send_id, "count": 1 }))
        .record_with(conn, false)
        .await
}

/// Delete events older than the admin's `event_days`. Returns how many.
pub async fn purge(state: &App) -> ApiResult<u64> {
    let days = state.num(Num::EventDays);
    let done = sqlx::query("DELETE FROM events WHERE at < $1")
        .bind(now() - days * 86_400)
        .execute(&state.db)
        .await?;
    if done.rows_affected() > 0 {
        tracing::info!(
            events = done.rows_affected(),
            days,
            "deleted old activity-log entries"
        );
    }
    Ok(done.rows_affected())
}

// ------------------------------------------------------------------ reading

/// `?before=<cursor>&limit=<1..200>` (default 50).
#[derive(Deserialize)]
pub struct Page {
    before: Option<String>,
    limit: Option<i64>,
}

const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 200;

/// Where a page starts: below (`at`, `id`), and how many rows to read (one more
/// than the page, to know whether another follows).
struct Start {
    at: i64,
    id: String,
    limit: i64,
}

impl Page {
    fn start(&self) -> ApiResult<Start> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
        let Some(cursor) = self.before.as_deref().filter(|c| !c.is_empty()) else {
            // Above every event: `~` sorts after every id.
            return Ok(Start {
                at: i64::MAX,
                id: "~".into(),
                limit,
            });
        };
        let bad = || ApiError::bad("invalid cursor");
        let text = String::from_utf8(unb64(cursor).map_err(|_| bad())?).map_err(|_| bad())?;
        let (at, id) = text.split_once(':').ok_or_else(bad)?;
        Ok(Start {
            at: at.parse().map_err(|_| bad())?,
            id: id.to_owned(),
            limit,
        })
    }
}

fn cursor(at: i64, id: &str) -> String {
    b64(format!("{at}:{id}").as_bytes())
}

/// Every event query reads the same columns, newest first, below a cursor.
macro_rules! events_query {
    ($filter:literal, $limit:literal) => {
        concat!(
            "SELECT e.id, e.at, e.type AS kind, e.actor_id, a.email AS actor_email, a.name AS actor_name,
                    e.client, e.ip, e.vault_id, e.item_id, e.target_user_id, t.email AS target_email, e.data
             FROM events e
             LEFT JOIN users a ON a.id = e.actor_id
             LEFT JOIN users t ON t.id = e.target_user_id
             WHERE ",
            $filter,
            " ORDER BY e.at DESC, e.id DESC LIMIT ",
            $limit
        )
    };
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    at: i64,
    kind: String,
    actor_id: Option<String>,
    actor_email: Option<String>,
    actor_name: Option<String>,
    client: Option<String>,
    ip: Option<String>,
    vault_id: Option<String>,
    item_id: Option<String>,
    target_user_id: Option<String>,
    target_email: Option<String>,
    data: Option<String>,
}

#[derive(Serialize)]
pub struct EventOut {
    id: String,
    /// Unix seconds.
    at: i64,
    #[serde(rename = "type")]
    kind: String,
    /// `null` for the server's own actions and the admin page; `email` and
    /// `name` are `null` once that account is deleted.
    actor: Option<Value>,
    /// The app that made the request (`X-PassAuth-Client`), when it said.
    client: Option<String>,
    /// Only where the address was kept and may be shown to this reader.
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    vault_id: Option<String>,
    item_id: Option<String>,
    target_user: Option<Value>,
    data: Option<Value>,
}

/// Whose addresses a page shows: everyone's (admin page), or the reader's own
/// and those of attempts on their account by nobody signed in.
#[derive(Clone, Copy)]
enum Addresses<'a> {
    All,
    Reader(&'a str),
}

#[derive(Serialize)]
pub struct EventPage {
    events: Vec<EventOut>,
    /// Send as `before` for the next (older) page; `null` on the last page.
    next: Option<String>,
}

fn page(mut rows: Vec<Row>, limit: i64, addresses: Addresses) -> EventPage {
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = more
        .then(|| rows.last().map(|r| cursor(r.at, &r.id)))
        .flatten();
    let events = rows
        .into_iter()
        .map(|r| {
            let show_ip = match addresses {
                Addresses::All => true,
                Addresses::Reader(me) => match r.actor_id.as_deref() {
                    Some(actor) => actor == me,
                    None => !r.kind.starts_with("admin."),
                },
            };
            EventOut {
                actor: r
                    .actor_id
                    .map(|id| json!({ "id": id, "email": r.actor_email, "name": r.actor_name })),
                target_user: r
                    .target_user_id
                    .map(|id| json!({ "id": id, "email": r.target_email })),
                data: r.data.and_then(|d| serde_json::from_str(&d).ok()),
                ip: r.ip.filter(|_| show_ip),
                id: r.id,
                at: r.at,
                kind: r.kind,
                client: r.client,
                vault_id: r.vault_id,
                item_id: r.item_id,
            }
        })
        .collect();
    EventPage { events, next }
}

/// `GET /account/events`: what the user did, and what was done to their account
/// (by vault admins, the admin page or the server).
pub async fn account_events(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<Page>,
) -> ApiResult<Json<EventPage>> {
    let start = q.start()?;
    let rows: Vec<Row> = sqlx::query_as(events_query!(
        "(e.actor_id = $1 OR e.target_user_id = $1) AND (e.at < $2 OR (e.at = $2 AND e.id < $3))",
        "$4"
    ))
    .bind(&user.user_id)
    .bind(start.at)
    .bind(&start.id)
    .bind(start.limit + 1)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(page(
        rows,
        start.limit,
        Addresses::Reader(&user.user_id),
    )))
}

/// `GET /vaults/{id}/events`, after the caller's role was checked (owner or admin).
pub async fn vault_events(
    state: &AppState,
    user: &AuthUser,
    vault_id: &str,
    q: &Page,
) -> ApiResult<EventPage> {
    let start = q.start()?;
    let rows: Vec<Row> = sqlx::query_as(events_query!(
        "e.vault_id = $1 AND (e.at < $2 OR (e.at = $2 AND e.id < $3))",
        "$4"
    ))
    .bind(vault_id)
    .bind(start.at)
    .bind(&start.id)
    .bind(start.limit + 1)
    .fetch_all(&state.db)
    .await?;
    Ok(page(rows, start.limit, Addresses::Reader(&user.user_id)))
}

/// `GET /admin/events` filters: `type` (an exact type such as `item.updated`, or
/// a category such as `item`), `user` (as actor or target) and `vault`.
#[derive(Deserialize)]
pub struct AdminFilter {
    #[serde(rename = "type")]
    kind: Option<String>,
    user: Option<String>,
    vault: Option<String>,
}

pub async fn admin_events(
    State(state): State<AppState>,
    _: Admin,
    Query(q): Query<Page>,
    Query(f): Query<AdminFilter>,
) -> ApiResult<Json<EventPage>> {
    let start = q.start()?;
    let kind = f.kind.unwrap_or_default();
    let (exact, prefix) = if kind.is_empty() {
        (String::new(), String::new())
    } else if kind.contains('.') {
        if !kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b"._".contains(&b))
        {
            return Err(ApiError::bad("unknown event type"));
        }
        (kind, String::new())
    } else {
        // A category: letters only, so it holds no LIKE wildcard.
        if !kind.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(ApiError::bad("unknown event type"));
        }
        (String::new(), format!("{kind}.%"))
    };
    let rows: Vec<Row> = sqlx::query_as(events_query!(
        "($1 = '' OR e.type = $1) AND ($2 = '' OR e.type LIKE $2)
         AND ($3 = '' OR e.actor_id = $3 OR e.target_user_id = $3)
         AND ($4 = '' OR e.vault_id = $4)
         AND (e.at < $5 OR (e.at = $5 AND e.id < $6))",
        "$7"
    ))
    .bind(exact)
    .bind(prefix)
    .bind(f.user.unwrap_or_default())
    .bind(f.vault.unwrap_or_default())
    .bind(start.at)
    .bind(&start.id)
    .bind(start.limit + 1)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(page(rows, start.limit, Addresses::All)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_cursors_round_trip_and_bad_ones_are_refused() {
        let id = uuid::Uuid::now_v7().to_string();
        let q = Page {
            before: Some(cursor(1_700_000_000, &id)),
            limit: Some(500),
        };
        let s = q.start().unwrap();
        assert_eq!(
            (s.at, s.id.as_str(), s.limit),
            (1_700_000_000, id.as_str(), 200)
        );
        let first = Page {
            before: None,
            limit: Some(0),
        }
        .start()
        .unwrap();
        assert_eq!((first.at, first.limit), (i64::MAX, 1));
        assert!(
            id.as_str() < first.id.as_str(),
            "the first page starts above every id"
        );
        for bad in ["***", "bm9jb2xvbg", &b64(b"x:y")] {
            let q = Page {
                before: Some(bad.into()),
                limit: None,
            };
            assert!(q.start().is_err(), "{bad}");
        }
    }

    #[test]
    fn event_ids_sort_by_time() {
        let a = uuid::Uuid::now_v7().to_string();
        let b = uuid::Uuid::now_v7().to_string();
        assert!(a < b);
    }
}
