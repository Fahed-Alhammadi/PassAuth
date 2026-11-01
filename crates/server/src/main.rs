mod account;
mod admin;
mod auth;
mod config;
mod db;
mod error;
mod icons;
mod mail;
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
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::{App, AppState};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("serve") => serve().await,
        Some("hash-admin-token") => hash_admin_token(),
        Some("healthcheck") => healthcheck().await,
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
    init_tracing(config.log_json);
    if config
        .admin_token
        .as_deref()
        .is_some_and(|t| !t.starts_with("$argon2"))
    {
        tracing::warn!(
            "ADMIN_TOKEN is plain text; generate a hash with `passauth-server hash-admin-token`"
        );
    }
    if config.smtp.is_none() {
        tracing::warn!(
            "SMTP is not configured: email verification, invites and email 2FA are disabled"
        );
    }
    let bind = config.bind;
    let state = App::new(config).await?;

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
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
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

    let mut app = Router::new().nest("/api", api);
    if let Some(dir) = &state.config.web_vault_dir {
        let index = format!("{dir}/index.html");
        app = app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
    }
    let h = |name: &'static str, value: &'static str| {
        SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        )
    };
    app.layer(DefaultBodyLimit::max(64 * 1024 * 1024))
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

async fn public_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "name": "PassAuth",
        "version": env!("CARGO_PKG_VERSION"),
        "signups_allowed": state.config.signups_allowed,
        "email_enabled": state.mailer.enabled(),
    }))
}

fn init_tracing(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tower_http=warn,sqlx=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init()
    } else {
        builder.init()
    }
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
    let port = std::env::var("BIND")
        .ok()
        .and_then(|b| b.rsplit(':').next().map(str::to_owned))
        .unwrap_or_else(|| "8080".into());
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")),
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
