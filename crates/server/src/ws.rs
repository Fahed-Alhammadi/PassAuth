//! Live sync notifications. Clients connect to `/api/ws?access_token=…` and
//! receive `{"type":"sync","revision":N}` or `{"type":"logout"}` messages.
//!
//! A socket lives only as long as its session: it is closed when the session
//! is signed out or revoked, when the account is disabled, or when the client
//! stops answering pings.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;

use crate::auth::{AuthUser, authenticate, bearer};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const PING_EVERY: Duration = Duration::from_secs(30);
/// No frame at all (pong, message) for this long means the peer is gone.
const IDLE_TIMEOUT: Duration = Duration::from_secs(95);

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
        Ok(Self(authenticate(state, &token).await?))
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
        return ApiError::TooManyRequests.into_response();
    };
    ws.on_upgrade(move |socket| run(state, user.session_id, socket, rx))
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
    session_id: String,
    socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<String>,
) {
    let (mut tx, mut incoming) = socket.split();
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut last_seen = Instant::now();
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(text) => if tx.send(Message::Text(text.into())).await.is_err() { break },
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            },
            frame = incoming.next() => match frame {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => last_seen = Instant::now(),
            },
            _ = ping.tick() => {
                if last_seen.elapsed() > IDLE_TIMEOUT || !session_alive(&state, &session_id).await {
                    break;
                }
                if tx.send(Message::Ping(Vec::new().into())).await.is_err() { break }
            }
        }
    }
    let _ = tx.send(Message::Close(None)).await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_decoding() {
        assert_eq!(super::percent_decode("a%2Bb%2Fc%3D"), "a+b/c=");
        assert_eq!(super::percent_decode("plain-_"), "plain-_");
        assert_eq!(super::percent_decode("bad%zz%"), "bad%zz%");
    }
}
