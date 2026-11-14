mod account;
mod admin;
mod auth;
mod config;
mod db;
mod error;
mod icons;
mod logging;
mod mail;
mod passkeys;
mod privileges;
mod state;
mod twofactor;
mod vault;
mod ws;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::{App, AppState};

/// Synchronous on purpose: switching from root to PUID:PGID happens before the
/// async runtime starts any thread.
fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("serve") => {
            privileges::drop_root(true)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve())
        }
        Some("hash-admin-token") => {
            privileges::drop_root(false)?;
            hash_admin_token()
        }
        Some("healthcheck") => {
            privileges::drop_root(false)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(healthcheck())
        }
        Some("--version" | "version") => {
            println!("passauth-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(other) => anyhow::bail!(
            "unknown command {other:?} (expected serve, hash-admin-token, healthcheck)"
        ),
    }
}

async fn serve() -> Result<()> {
    let config = Config::from_env()?;
    logging::init(config.log_json);
    if config.admin_password.is_none()
        && config
            .admin_token
            .as_deref()
            .is_some_and(|t| !t.starts_with("$argon2"))
    {
        tracing::warn!(
            "ADMIN_TOKEN is plain text; generate a hash with `passauth-server hash-admin-token`"
        );
    }
    if config.ip_header.is_some() && config.trusted_proxies.is_none() {
        tracing::info!(
            "IP_HEADER is believed only from loopback and private-network proxies; set TRUSTED_PROXIES if your proxy connects from elsewhere"
        );
    }
    let bind = config.bind;
    let state = App::new(config).await?;
    if !state.mailer.enabled() {
        tracing::warn!(
            "email is not set up (admin page → Email delivery): email verification, invites and email 2FA are disabled"
        );
    }

    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            sweeper.sweep();
            sweeper.icons.sweep().await;
            let cutoff = db::now();
            let _ = sqlx::query("DELETE FROM sessions WHERE refresh_expires < $1")
                .bind(cutoff)
                .execute(&sweeper.db)
                .await;
            let _ = sqlx::query("DELETE FROM email_tokens WHERE expires_at < $1")
                .bind(cutoff)
                .execute(&sweeper.db)
                .await;
        }
    });

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, version = env!("CARGO_PKG_VERSION"), "PassAuth server listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    tracing::info!("PassAuth server stopped");
    Ok(())
}

/// Ctrl-C or SIGTERM. As PID 1 in a container the server gets SIGTERM from
/// `docker stop`, and the kernel ignores it unless a handler is installed.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutting down");
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/config", get(public_config))
        .route("/ws", get(ws::handler))
        .nest("/auth", auth::routes())
        .nest("/account", account::routes())
        .nest("/admin", admin::routes())
        .merge(vault::routes())
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        // Added after the no-store layer: icons set their own caching headers.
        .merge(icons::routes());
    // Unknown /api paths are API 404s, not the web vault's index.html.
    let api = api
        .fallback(|| async { error::ApiError::NotFound })
        .layer(middleware::from_fn(json_errors));

    let mut app = Router::new().nest("/api", api);
    if let Some(dir) = &state.config.web_vault_dir {
        let index = format!("{dir}/index.html");
        // Serves `x.br` / `x.gz` next to `x` when the browser accepts them
        // (the image build writes them), else the plain file.
        app = app.fallback_service(
            ServeDir::new(dir)
                .precompressed_br()
                .precompressed_gzip()
                .fallback(
                    ServeFile::new(index)
                        .precompressed_br()
                        .precompressed_gzip(),
                ),
        );
    }
    let h = |name: &'static str, value: &'static str| {
        SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        )
    };
    // Small by default; item and bulk routes raise it (see `vault::routes`).
    app.layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(static_cache))
        .layer(h("x-content-type-options", "nosniff"))
        .layer(h("x-frame-options", "DENY"))
        .layer(h("referrer-policy", "same-origin"))
        .layer(h("permissions-policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"))
        .layer(h(
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(peer_ip))
        .with_state(state)
}

/// Records the TCP peer address for rate limiting when no `IP_HEADER` is set.
/// Any client-sent value is dropped first, so it can't be spoofed.
async fn peer_ip(mut req: Request, next: Next) -> Response {
    req.headers_mut().remove(auth::PEER_IP_HEADER);
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    if let Some(v) = peer.and_then(|ip| HeaderValue::from_str(&ip.to_string()).ok()) {
        req.headers_mut().insert(auth::PEER_IP_HEADER, v);
    }
    next.run(req).await
}

/// Liveness plus a database round trip, so a lost database shows as unhealthy.
async fn health(State(state): State<AppState>) -> Response {
    let db = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar::<_, i64>("SELECT CAST(1 AS BIGINT)").fetch_one(&state.db),
    )
    .await;
    match db {
        Ok(Ok(_)) => Json(json!({ "status": "ok" })).into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error", "database": "unreachable" })),
        )
            .into_response(),
    }
}

/// Long-lived caching for the hashed build assets; the HTML shell is always
/// revalidated so a new release is picked up on the next load.
async fn static_cache(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;
    if path.starts_with("/api/") || !resp.status().is_success() {
        return resp;
    }
    let value = if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    resp.headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static(value));
    resp
}

/// Every API error is JSON (`{"error","message"}`), including axum's own
/// rejections (bad JSON, body too large…), so clients can always parse it.
async fn json_errors(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let status = resp.status();
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    let is_ws = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
    if !(status.is_client_error() || status.is_server_error()) || is_json || is_ws {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let text = axum::body::to_bytes(body, 4096)
        .await
        .map(|b| String::from_utf8_lossy(&b).trim().to_owned())
        .unwrap_or_default();
    let code = match status {
        StatusCode::PAYLOAD_TOO_LARGE => "too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE | StatusCode::UNPROCESSABLE_ENTITY => "bad_request",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        s if s.is_server_error() => "internal",
        _ => "bad_request",
    };
    let message = if text.is_empty() {
        status.canonical_reason().unwrap_or("error").to_owned()
    } else {
        text
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let body = json!({ "error": code, "message": message }).to_string();
    Response::from_parts(parts, axum::body::Body::from(body))
}

async fn public_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "name": "PassAuth",
        "version": env!("CARGO_PKG_VERSION"),
        "signups_allowed": state.signups.read().expect("signup policy lock").allowed,
        "email_enabled": state.mailer.enabled(),
    }))
}

fn hash_admin_token() -> Result<()> {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    let mut token = String::new();
    eprint!("Admin token: ");
    std::io::stdin().read_line(&mut token)?;
    let token = token.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(token.len() >= 16, "use at least 16 characters");
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2::Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{hash}");
    Ok(())
}

/// Used by the container HEALTHCHECK (no curl/wget in the image).
async fn healthcheck() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = healthcheck_target(std::env::var("BIND").ok().as_deref());
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(target),
    )
    .await??;
    stream
        .write_all(b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await??;
    anyhow::ensure!(
        buf.starts_with(b"HTTP/1.0 200") || buf.starts_with(b"HTTP/1.1 200"),
        "unhealthy"
    );
    Ok(())
}

/// Where the health check connects: the bound address, or loopback of the
/// same family when bound to all interfaces.
fn healthcheck_target(bind: Option<&str>) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let addr: SocketAddr = bind
        .and_then(|b| b.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)));
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}
