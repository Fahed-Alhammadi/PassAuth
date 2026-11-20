//! Push notifications for sign-in requests (feature `push` while the admin switch
//! `push_enabled` is on, the default).
//!
//! A signed-in phone app registers the push token its platform gave it for its
//! session (`PUT /account/push`; `DELETE /account/push` forgets it). When a new
//! device asks to sign in to the account and the request really reaches the
//! account's apps (exactly where they hear about it on the live-sync socket,
//! `auth_requests::create`), the server asks the push relay (admin setting
//! `push_relay_url`) to wake each registered phone, once per token, in a task of
//! its own after the request is stored: the answer to the new device never waits
//! for it, and takes the same time with or without an account behind the email.
//!
//! The relay holds the platform's signing key (APNs) and shows a fixed notice ("Sign-in
//! request"); it gets the device token, the APNs environment and the kind
//! (`auth_request`), never the request, the account, its email or this server's address. The phone opens the
//! app, which lists the request over the usual authenticated API; the approval works
//! as before. A token the relay reports gone (410) is deleted. Rows go away with
//! their session (sign-out, revoking, a new master password, the admin revoking or
//! disabling, deleting the account, expiry: [`drop_orphans`] and the sweeper), and
//! all of them while the admin switch is off.

use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::json;
use sqlx::AnyConnection;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::Url;

use crate::auth::AuthUser;
use crate::db::now;
use crate::error::{ApiError, ApiResult, code};
use crate::state::{App, AppState};

/// The relay the publisher runs (a Cloudflare Worker), used until the admin names
/// another one.
pub const DEFAULT_RELAY_URL: &str = "https://passauth-push.uaealhammadi.com";
/// `server_settings` row of the on/off switch (`1` / `0`).
pub const ENABLED_SETTING: &str = "push_enabled";
/// `server_settings` row of the relay's address.
pub const RELAY_SETTING: &str = "push_relay_url";

/// Whole budget of one notification (connect, TLS, request, answer).
const TIMEOUT: Duration = Duration::from_secs(10);
/// Device tokens: hex, this many characters (APNs tokens are 32 bytes today).
const TOKEN_HEX: std::ops::RangeInclusive<usize> = 64..=200;
/// Tokens notified per request (the most recently registered first).
const MAX_TOKENS: i64 = 20;
/// Longest relay address accepted.
const MAX_URL: usize = 512;
/// Largest relay answer read (only its status matters).
const MAX_ANSWER: usize = 4096;
const USER_AGENT: &str = concat!("PassAuth-Server/", env!("CARGO_PKG_VERSION"));

/// The admin's switch and relay address, changed on the admin page without a restart.
pub struct PushService {
    enabled: AtomicBool,
    relay_url: RwLock<String>,
    tls: tokio_rustls::TlsConnector,
}

impl PushService {
    pub fn new(enabled: bool, relay_url: String) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            relay_url: RwLock::new(relay_url),
            tls: crate::icons::tls_connector(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn relay_url(&self) -> String {
        self.relay_url.read().expect("push relay lock").clone()
    }

    pub fn set_relay_url(&self, url: String) {
        *self.relay_url.write().expect("push relay lock") = url;
    }
}

/// A relay address the server may use: `https://` with a host name, or `http://` to
/// this machine only (`localhost`, `127.0.0.1`, `[::1]`: a relay in a test or on the
/// same host); no user name, password, query or fragment. Returned without spaces
/// around it or a trailing `/`.
pub fn check_relay_url(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('/');
    let bad = || {
        "the push relay address must be an https:// address, such as https://push.example.com"
            .to_owned()
    };
    if s.is_empty() || s.len() > MAX_URL {
        return Err(bad());
    }
    let url = Url::parse(s).map_err(|_| bad())?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let scheme_ok = match url.scheme() {
        "https" => url.host_str().is_some_and(|h| !h.is_empty()),
        "http" => local,
        _ => false,
    };
    if !scheme_ok
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(bad());
    }
    Ok(s.to_owned())
}

/// The switch at start: the saved one, else `PASSAUTH_PUSH`. The relay: the saved
/// address (if still a valid one), else `PASSAUTH_PUSH_RELAY_URL`, else
/// [`DEFAULT_RELAY_URL`].
pub fn starting(
    config_on: bool,
    config_url: Option<&str>,
    saved_on: Option<&str>,
    saved_url: Option<&str>,
) -> (bool, String) {
    let on = saved_on.map_or(config_on, |v| v == "1");
    let url = saved_url
        .and_then(|u| match check_relay_url(u) {
            Ok(u) => Some(u),
            Err(_) => {
                tracing::warn!("the saved push relay address is not valid; using the default");
                None
            }
        })
        .or_else(|| config_url.map(str::to_owned))
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned());
    (on, url)
}

// ------------------------------------------------------------ registering

#[derive(Deserialize)]
pub struct Registration {
    platform: String,
    token: String,
    environment: String,
}

/// `PUT /account/push` `{platform: "apns", token, environment: "production" |
/// "sandbox"}` → 204. Keeps this session's token (one per session; replaces the one
/// it had) and takes the token away from any other session that had it (the phone
/// signed in again, or to another account). 409 `push_disabled` while the admin
/// switch is off.
pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    Json(b): Json<Registration>,
) -> ApiResult<StatusCode> {
    if !state.push.enabled() {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            code::PUSH_DISABLED,
            "push notifications are turned off on this server",
        ));
    }
    if b.platform != "apns" {
        return Err(ApiError::bad("platform must be \"apns\""));
    }
    if !TOKEN_HEX.contains(&b.token.len()) || !b.token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::bad(
            "token must be the device token in hex (64 to 200 characters)",
        ));
    }
    if !matches!(b.environment.as_str(), "production" | "sandbox") {
        return Err(ApiError::bad(
            "environment must be \"production\" or \"sandbox\"",
        ));
    }
    let token = b.token.to_ascii_lowercase();
    let t = now();
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM push_tokens WHERE token = $1 AND session_id <> $2")
        .bind(&token)
        .bind(&user.session_id)
        .execute(&mut *tx)
        .await?;
    // Only while the session still exists: one signed out at this moment keeps no row.
    sqlx::query(
        "INSERT INTO push_tokens (session_id, user_id, platform, token, environment, created_at,
             updated_at)
         SELECT id, user_id, $2, $3, $4, $5, $5 FROM sessions WHERE id = $1 AND user_id = $6
         ON CONFLICT (session_id) DO UPDATE SET platform = excluded.platform,
             token = excluded.token, environment = excluded.environment,
             updated_at = excluded.updated_at",
    )
    .bind(&user.session_id)
    .bind(&b.platform)
    .bind(&token)
    .bind(&b.environment)
    .bind(t)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /account/push` → 204: this session's token is forgotten (also while the
/// admin switch is off).
pub async fn unregister(State(state): State<AppState>, user: AuthUser) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM push_tokens WHERE session_id = $1")
        .bind(&user.session_id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the tokens of `user_id`'s sessions that no longer exist; called in the
/// transaction that ends sessions, after it deleted them.
pub async fn drop_orphans(conn: &mut AnyConnection, user_id: &str) -> sqlx::Result<()> {
    sqlx::query(
        "DELETE FROM push_tokens WHERE user_id = $1
         AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = push_tokens.session_id)",
    )
    .bind(user_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Sweeper: the tokens of every session that is gone (expired sessions above all),
/// and every token while the admin switch is off.
pub async fn sweep(state: &App) -> sqlx::Result<()> {
    let sql = if state.push.enabled() {
        "DELETE FROM push_tokens
         WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = push_tokens.session_id)"
    } else {
        "DELETE FROM push_tokens"
    };
    sqlx::query(sql).execute(&state.db).await?;
    Ok(())
}

// ------------------------------------------------------------ sending

/// A new sign-in request reached `user_id`'s apps: wake their phones, in a task of
/// its own (nothing here waits for the database or the relay).
pub fn notify_auth_request(state: &AppState, user_id: &str) {
    if !state.push.enabled() {
        return;
    }
    let state = state.clone();
    let user_id = user_id.to_owned();
    tokio::spawn(async move {
        if let Err(e) = send_all(&state, &user_id).await {
            tracing::warn!(error = %e, "sending sign-in request notifications failed");
        }
    });
}

async fn send_all(state: &AppState, user_id: &str) -> anyhow::Result<()> {
    let tokens: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT p.session_id, p.token, p.environment FROM push_tokens p
         JOIN sessions s ON s.id = p.session_id
         WHERE p.user_id = $1 AND p.platform = 'apns' AND s.refresh_expires > $2
         ORDER BY p.updated_at DESC LIMIT $3",
    )
    .bind(user_id)
    .bind(now())
    .bind(MAX_TOKENS)
    .fetch_all(&state.db)
    .await?;
    if tokens.is_empty() {
        return Ok(());
    }
    let relay = state.push.relay_url();
    let sends = tokens.into_iter().map(|(session, token, environment)| {
        let relay = relay.clone();
        async move {
            let body = json!({
                "platform": "apns",
                "token": token,
                "environment": environment,
                "kind": "auth_request",
            });
            let outcome = tokio::time::timeout(TIMEOUT, post(state, &relay, body.to_string()))
                .await
                .unwrap_or(Err(SendError::Timeout));
            (session, token, outcome)
        }
    });
    for (session, token, outcome) in futures_util::future::join_all(sends).await {
        match outcome {
            Ok(status) if status.is_success() => {
                tracing::debug!(user = %user_id, "sign-in request notification sent");
            }
            Ok(StatusCode::GONE) => {
                tracing::debug!(user = %user_id, "push token no longer valid; forgotten");
                sqlx::query("DELETE FROM push_tokens WHERE session_id = $1 AND token = $2")
                    .bind(&session)
                    .bind(&token)
                    .execute(&state.db)
                    .await?;
            }
            Ok(StatusCode::TOO_MANY_REQUESTS) => {
                tracing::debug!(user = %user_id, "the push relay is rate limiting; not sent");
            }
            Ok(status) => {
                tracing::warn!(status = status.as_u16(), relay = %relay, "the push relay refused a sign-in request notification");
            }
            Err(e) => {
                tracing::warn!(error = e.as_str(), relay = %relay, "the push relay could not be reached");
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
enum SendError {
    Address,
    Connect,
    Http,
    Timeout,
}

impl SendError {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Address => "the relay address is not usable",
            Self::Connect => "connecting failed",
            Self::Http => "the request failed",
            Self::Timeout => "no answer in time",
        }
    }
}

impl From<hyper::Error> for SendError {
    fn from(_: hyper::Error) -> Self {
        Self::Http
    }
}

/// `POST <relay>/v1/notify` with `body`; the relay's status.
async fn post(state: &App, relay: &str, body: String) -> Result<StatusCode, SendError> {
    let url = Url::parse(&format!("{relay}/v1/notify")).map_err(|_| SendError::Address)?;
    let host = url.host_str().ok_or(SendError::Address)?.to_owned();
    let port = url.port_or_known_default().ok_or(SendError::Address)?;
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let req = Request::post(&url[url::Position::BeforePath..url::Position::AfterQuery])
        .header(header::HOST, authority)
        .header(header::USER_AGENT, USER_AGENT)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| SendError::Http)?;
    // `[::1]` → `::1` for connecting.
    let connect_host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let tcp = TcpStream::connect((connect_host.as_str(), port))
        .await
        .map_err(|_| SendError::Connect)?;
    if url.scheme() == "https" {
        let name = rustls::pki_types::ServerName::try_from(connect_host)
            .map_err(|_| SendError::Address)?;
        let tls = state
            .push
            .tls
            .connect(name, tcp)
            .await
            .map_err(|_| SendError::Connect)?;
        send(tls, req).await
    } else {
        send(tcp, req).await
    }
}

async fn send<S>(io: S, req: Request<Full<Bytes>>) -> Result<StatusCode, SendError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let result = async {
        let resp = sender.send_request(req).await?;
        let status = resp.status();
        // Read (a little of) the answer so the connection ends cleanly.
        let mut body = resp.into_body();
        let mut read = 0;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                read += data.len();
                if read > MAX_ANSWER {
                    break;
                }
            }
        }
        Ok(status)
    }
    .await;
    conn.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_addresses() {
        assert_eq!(
            check_relay_url(" https://push.example.com/ "),
            Ok("https://push.example.com".into())
        );
        assert_eq!(
            check_relay_url("https://push.example.com/relay"),
            Ok("https://push.example.com/relay".into())
        );
        assert!(check_relay_url("http://127.0.0.1:8787").is_ok());
        assert!(check_relay_url("http://localhost:8787").is_ok());
        assert!(check_relay_url("http://[::1]:8787").is_ok());
        for bad in [
            "",
            "push.example.com",
            "http://push.example.com",
            "ftp://push.example.com",
            "https://user:pw@push.example.com",
            "https://push.example.com/?a=b",
            "https://push.example.com/#x",
            "http://10.0.0.1",
        ] {
            assert!(check_relay_url(bad).is_err(), "{bad}");
        }
        assert_eq!(
            starting(true, None, None, None),
            (true, DEFAULT_RELAY_URL.to_owned())
        );
        assert_eq!(
            starting(false, Some("https://a.example"), Some("1"), Some("nope")),
            (true, "https://a.example".to_owned())
        );
        assert_eq!(
            starting(
                true,
                Some("https://a.example"),
                Some("0"),
                Some("https://b.example")
            ),
            (false, "https://b.example".to_owned())
        );
    }
}
