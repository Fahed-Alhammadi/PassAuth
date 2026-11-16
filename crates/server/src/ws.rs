//! Live sync notifications. Clients connect to `/api/ws?access_token=…`, get
//! `{"type":"hello","origin":"<id>"}` first and then
//! `{"type":"sync","revision":N,"vaults":{"<vault>":seq},"origin":"<id>"}` or
//! `{"type":"logout"}` messages, and `{"type":"auth_request","id"}` /
//! `{"type":"auth_request_answered","id"}` when a device asks to sign in to the
//! account or such a request was answered (`auth_requests.rs`; the app lists the
//! requests with `GET /account/auth-requests`). `origin` names the session that wrote (left
//! out for the server's own changes and when writes from several sessions were
//! collapsed into one message); a client skips a sync whose origin is the one
//! its hello gave it. Sync notices for one account within ~300 ms arrive as one
//! message (`state::SYNC_COLLAPSE`).
//!
//! A socket lives only as long as its session: when the session is signed out
//! or revoked it gets `{"type":"logout"}` and is closed at once (the periodic
//! check, every `websocket_ping_seconds`, also catches sessions ended
//! elsewhere, a disabled account, or a client that stops answering pings). The
//! same check applies the admin's `require_two_step` policy to sockets opened
//! before it was turned on: an account without a two-step method gets
//! `{"type":"two_step_required"}` and a close frame 1008 (policy) with the reason
//! `two_step_required`, like the 403 a new connection would get.
//! Clients only listen, so incoming messages are limited to a few KiB.

use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{FromRequestParts, State};
use axum::http::Method;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;

use crate::auth::{AuthUser, authenticate, bearer};
use crate::error::{ApiError, ApiResult, code};
use crate::settings::Num;
use crate::state::{AppState, Notice, SyncNotice};

/// Largest message or frame a client may send; anything bigger closes the socket.
pub const MAX_INCOMING: usize = 4 * 1024;

/// Time between connection checks (`websocket_ping_seconds`, admin page).
fn ping_every(state: &AppState) -> Duration {
    Duration::from_secs(state.num(Num::WebsocketPingSeconds).max(1) as u64)
}

/// No frame at all (pong, message) for this long means the peer is gone:
/// three missed checks and a little slack (95 s at the default 30 s).
fn idle_timeout(ping: Duration) -> Duration {
    ping * 3 + Duration::from_secs(5)
}

/// The text of a `{"type":"sync"}` message.
pub fn sync_message(n: &SyncNotice) -> String {
    let mut msg = json!({ "type": "sync", "revision": n.revision, "vaults": n.vaults });
    if let Some(origin) = &n.origin {
        msg["origin"] = origin.clone().into();
    }
    msg.to_string()
}

/// The text of a `{"type":"auth_request"}` or `{"type":"auth_request_answered"}` message.
fn auth_request_message(kind: &str, id: &str) -> String {
    json!({ "type": kind, "id": id }).to_string()
}

/// Like [`AuthUser`], but also accepts `?access_token=` because browser
/// WebSockets can't send headers. Only this route takes tokens in the URL,
/// so they don't end up in proxy logs for ordinary API calls.
pub struct WsUser(AuthUser);

impl FromRequestParts<AppState> for WsUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = bearer(&parts.headers)
            .or_else(|| {
                parts
                    .uri
                    .query()?
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("access_token="))
                    .map(percent_decode)
            })
            .ok_or(ApiError::Unauthorized)?;
        let user = authenticate(state, &token).await?;
        crate::policies::two_step_gate(
            state,
            &user.user_id,
            &parts.method,
            crate::policies::request_path(parts),
        )
        .await?;
        Ok(Self(user))
    }
}

/// Tokens are base64url, but clients percent-encode them anyway.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            )
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn handler(
    State(state): State<AppState>,
    WsUser(user): WsUser,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(rx) = state.subscribe(&user.user_id) else {
        return ApiError::TooManyRequests(60).into_response();
    };
    ws.max_message_size(MAX_INCOMING)
        .max_frame_size(MAX_INCOMING)
        .on_upgrade(move |socket| run(state, user, socket, rx))
}

async fn session_alive(state: &AppState, session_id: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id = $1 AND u.disabled = 0",
    )
    .bind(session_id)
    .fetch_one(&state.db)
    .await
    // A database hiccup is not a reason to drop every client.
    .map_or(true, |n| n > 0)
}

async fn run(
    state: AppState,
    user: AuthUser,
    socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<Notice>,
) {
    let session_id = user.session_id;
    let (mut tx, mut incoming) = socket.split();
    let hello = json!({ "type": "hello", "origin": state.origin(&session_id) });
    if tx
        .send(Message::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    let mut next_check = Instant::now() + ping_every(&state);
    let mut last_seen = Instant::now();
    let mut signed_out = false;
    let mut two_step_required = false;
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(Notice::Sync(notice)) => {
                    if tx.send(Message::Text(sync_message(&notice).into())).await.is_err() { break }
                }
                Ok(Notice::Logout(sessions)) => if sessions.includes(&session_id) {
                    signed_out = true;
                    break;
                },
                Ok(Notice::AuthRequest(id)) => {
                    if tx.send(Message::Text(auth_request_message("auth_request", &id).into())).await.is_err() { break }
                }
                Ok(Notice::AuthRequestAnswered(id)) => {
                    if tx.send(Message::Text(auth_request_message("auth_request_answered", &id).into())).await.is_err() { break }
                }
                // Missed notices may include this session's logout, and changes:
                // a sync without an origin makes the client look.
                Err(RecvError::Lagged(_)) => {
                    if !session_alive(&state, &session_id).await {
                        signed_out = true;
                        break;
                    }
                    let Ok(revision) = sqlx::query_scalar::<_, i64>("SELECT revision FROM users WHERE id = $1")
                        .bind(&user.user_id)
                        .fetch_one(&state.db)
                        .await
                    else { continue };
                    let text = sync_message(&SyncNotice::new(revision, None));
                    if tx.send(Message::Text(text.into())).await.is_err() { break }
                }
                Err(RecvError::Closed) => break,
            },
            frame = incoming.next() => match frame {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => last_seen = Instant::now(),
            },
            _ = tokio::time::sleep_until(next_check) => {
                // Read each time: a change on the admin page applies to open sockets too.
                let every = ping_every(&state);
                if last_seen.elapsed() > idle_timeout(every) {
                    break;
                }
                // Ended elsewhere (expired, signed out on another server, account disabled).
                if !session_alive(&state, &session_id).await {
                    signed_out = true;
                    break;
                }
                // The admin may have required two-step login since this socket opened.
                if two_step_refused(&state, &user.user_id).await {
                    two_step_required = true;
                    break;
                }
                if tx.send(Message::Ping(Vec::new().into())).await.is_err() { break }
                next_check = Instant::now() + every;
            }
        }
    }
    if signed_out {
        let _ = tx.send(Message::Text(r#"{"type":"logout"}"#.into())).await;
    }
    if two_step_required {
        let _ = tx
            .send(Message::Text(r#"{"type":"two_step_required"}"#.into()))
            .await;
        let _ = tx
            .send(Message::Close(Some(CloseFrame {
                code: close_code::POLICY,
                reason: code::TWO_STEP_REQUIRED.into(),
            })))
            .await;
        return;
    }
    let _ = tx.send(Message::Close(None)).await;
}

/// Whether the admin's two-step policy refuses the account now (it has no method
/// while one is required). A database hiccup keeps the socket open.
async fn two_step_refused(state: &AppState, user_id: &str) -> bool {
    matches!(
        crate::policies::two_step_gate(state, user_id, &Method::GET, "/api/ws").await,
        Err(e) if e.code() == code::TWO_STEP_REQUIRED
    )
}

#[cfg(test)]
mod tests {
    use crate::state::SyncNotice;

    #[test]
    fn sync_messages_name_the_writer_and_the_vaults() {
        let mut n = SyncNotice::new(7, Some("abc".into()));
        n.vaults.insert("v1".into(), 3);
        let v: serde_json::Value = serde_json::from_str(&super::sync_message(&n)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "type": "sync", "revision": 7, "vaults": { "v1": 3 }, "origin": "abc" })
        );
        let v: serde_json::Value =
            serde_json::from_str(&super::sync_message(&SyncNotice::new(8, None))).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "type": "sync", "revision": 8, "vaults": {} })
        );
        assert_eq!(
            super::idle_timeout(std::time::Duration::from_secs(30)).as_secs(),
            95
        );
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(super::percent_decode("a%2Bb%2Fc%3D"), "a+b/c=");
        assert_eq!(super::percent_decode("plain-_"), "plain-_");
        assert_eq!(super::percent_decode("bad%zz%"), "bad%zz%");
    }
}
