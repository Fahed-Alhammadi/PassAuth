//! Live sync notifications. Clients connect to `/api/ws?access_token=…` and
//! receive `{"type":"sync","revision":N}` or `{"type":"logout"}` messages.

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthUser;
use crate::state::AppState;

pub async fn handler(
    State(state): State<AppState>,
    user: AuthUser,
    ws: WebSocketUpgrade,
) -> Response {
    let rx = state.subscribe(&user.user_id);
    ws.on_upgrade(move |socket| run(socket, rx))
}

async fn run(socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<String>) {
    let (mut tx, mut incoming) = socket.split();
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(text) => if tx.send(Message::Text(text.into())).await.is_err() { break },
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            },
            frame = incoming.next() => match frame {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            _ = ping.tick() => if tx.send(Message::Ping(Vec::new().into())).await.is_err() { break },
        }
    }
}
