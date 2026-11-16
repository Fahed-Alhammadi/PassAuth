mod account;
mod admin;
mod admin_security;
mod auth;
mod auth_requests;
mod config;
mod db;
mod disk;
mod emergency;
mod error;
mod events;
mod files;
mod icons;
mod logging;
mod mail;
mod passkeys;
mod policies;
mod privileges;
mod sends;
mod settings;
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
use tower_http::catch_panic::CatchPanicLayer;
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
        Some("reset-sync") => {
            privileges::drop_root(false)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(reset_sync())
        }
        Some("reset-admin-2fa") => {
            privileges::drop_root(false)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(reset_admin_2fa())
        }
        Some("backup") => {
            let Some(target) = args.next() else {
                anyhow::bail!(
                    "usage: passauth-server backup <file>, e.g. /data/passauth-backup.db"
                );
            };
            privileges::drop_root(false)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(backup(target))
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
            "unknown command {other:?} (expected serve, backup, reset-sync, reset-admin-2fa, hash-admin-token, healthcheck)"
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

    tokio::spawn(sweeper(state.clone()));

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

/// Housekeeping every minute: expired in-memory state, icon cache, sessions and
/// email codes, emergency access requests whose waiting period ended, and sign-in
/// requests (expired, deleted a day later); every ten
/// minutes the trash (admin setting `trash_days`), old tombstones
/// (`tombstone_days`), old activity-log entries (`event_days`), Sends past their
/// deletion date, attachment uploads left pending, expired "remember this device"
/// tokens and devices without a session that haven't been seen for
/// [`FORGET_DEVICES_DAYS`]; every hour attachment files without an attachment.
/// Each step runs on its own ([`sweep_step`]): one that fails or panics doesn't
/// keep the others from running.
async fn sweeper(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    let mut round = 0u64;
    loop {
        tick.tick().await;
        round = round.wrapping_add(1);
        sweep_step("dropping expired sign-ins and rate limits", async {
            state.sweep();
            Ok::<_, std::convert::Infallible>(())
        })
        .await;
        sweep_step("cleaning the icon cache", async {
            state.icons.sweep().await;
            Ok::<_, std::convert::Infallible>(())
        })
        .await;
        let cutoff = db::now();
        for (what, sql) in [
            (
                "removing expired sessions",
                "DELETE FROM sessions WHERE refresh_expires < $1",
            ),
            (
                "removing expired email codes",
                "DELETE FROM email_tokens WHERE expires_at < $1",
            ),
        ] {
            sweep_step(what, sqlx::query(sql).bind(cutoff).execute(&state.db)).await;
        }
        sweep_step(
            "approving waited emergency access requests",
            emergency::approve_waited(&state),
        )
        .await;
        sweep_step("expiring sign-in requests", auth_requests::sweep(&state)).await;
        if round % 10 == 1 {
            sweep_step("emptying the trash", vault::purge_trash(&state)).await;
            sweep_step("forgetting old deletions", vault::purge_tombstones(&state)).await;
            sweep_step("deleting old activity-log entries", events::purge(&state)).await;
            sweep_step("deleting old Sends", sends::purge(&state)).await;
            sweep_step(
                "deleting abandoned attachments",
                vault::sweep_attachments(&state, round % 60 == 1),
            )
            .await;
            sweep_step("forgetting old devices", forget_old_devices(&state.db)).await;
        }
    }
}

/// Run one housekeeping step: an error is logged, and so is a panic, which ends
/// only this step (until the next round), never the sweeper.
async fn sweep_step<T, E: std::fmt::Display>(
    what: &str,
    work: impl std::future::Future<Output = Result<T, E>>,
) {
    use futures_util::FutureExt;
    match std::panic::AssertUnwindSafe(work).catch_unwind().await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "{what} failed"),
        Err(panic) => {
            let why = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            tracing::error!(
                panic = why,
                "{what} panicked; the other housekeeping goes on"
            );
        }
    }
}

/// Devices without a session that haven't signed in or refreshed a session for
/// this long are forgotten (their next sign-in counts as a new device).
const FORGET_DEVICES_DAYS: i64 = 90;

/// Clear expired "remember this device" tokens and forget devices that have had
/// no session for [`FORGET_DEVICES_DAYS`].
async fn forget_old_devices(db: &db::Db) -> Result<()> {
    let t = db::now();
    sqlx::query(
        "UPDATE devices SET remember_hash = NULL, remember_expires = NULL
         WHERE remember_expires IS NOT NULL AND remember_expires < $1",
    )
    .bind(t)
    .execute(db)
    .await?;
    let gone = sqlx::query(
        "DELETE FROM devices WHERE last_seen < $1 AND NOT EXISTS
           (SELECT 1 FROM sessions s WHERE s.user_id = devices.user_id AND s.device_id = devices.id)",
    )
    .bind(t - FORGET_DEVICES_DAYS * 86_400)
    .execute(db)
    .await?;
    if gone.rows_affected() > 0 {
        tracing::info!(
            devices = gone.rows_affected(),
            "forgot devices unused for {FORGET_DEVICES_DAYS} days"
        );
    }
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
        .nest("/emergency-access", emergency::routes())
        .nest("/public", sends::public_routes())
        .merge(vault::routes())
        .merge(sends::routes())
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
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(middleware::from_fn(static_cache))
        // Inside the default `referrer-policy` below, which keeps what this sets.
        .layer(middleware::from_fn(send_page))
        .layer(h("x-content-type-options", "nosniff"))
        .layer(h("x-frame-options", "DENY"))
        .layer(h("referrer-policy", "same-origin"))
        .layer(h(
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            content_security_policy,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(middleware::from_fn(request_id))
        .layer(middleware::from_fn(peer_ip))
        .with_state(state)
}

/// The Content-Security-Policy of every response that doesn't set its own (the
/// web vault's pages above all). With the admin's `breach_check` on, the web
/// vault may also connect to Have I Been Pwned's range API, which it asks with
/// the first five characters of a password's SHA-1 (k-anonymity; the server
/// never sees any of it).
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";
const CSP_BREACH_CHECK: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

/// [`CSP`] or [`CSP_BREACH_CHECK`], from the live setting (no restart needed).
async fn content_security_policy(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let mut resp = next.run(req).await;
    let policy = if state.breach_check() {
        CSP_BREACH_CHECK
    } else {
        CSP
    };
    resp.headers_mut()
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(policy));
    resp
}

/// The web vault's public Send page (`/send/<id>#<key>`): its key is in the
/// fragment, which browsers never send. `no-referrer` keeps even the Send's id
/// out of every request the page makes, and search engines are asked to stay away.
async fn send_page(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let send = path == "/send" || path.starts_with("/send/");
    let mut resp = next.run(req).await;
    if send {
        let headers = resp.headers_mut();
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        headers.insert(
            HeaderName::from_static("x-robots-tag"),
            HeaderValue::from_static("noindex, nofollow"),
        );
    }
    resp
}

const REQUEST_ID: &str = "x-request-id";

/// Request ids: a well-formed `x-request-id` from a proxy is kept, anything
/// else replaced by a new one. It goes back in the response header, into the
/// request's log span and into JSON error bodies (`request_id`).
async fn request_id(mut req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        })
        .map(str::to_owned);
    let id = given.unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let value = HeaderValue::from_str(&id).expect("request ids are visible ASCII");
    req.headers_mut().insert(REQUEST_ID, value.clone());
    let mut resp = error::REQUEST_ID.scope(id, next.run(req)).await;
    resp.headers_mut().insert(REQUEST_ID, value);
    resp
}

/// The request's log span (debug level): method, path, request id and client
/// app. Never the query string: `/api/ws?access_token=…` and
/// `/verify-email?token=…` carry secrets there.
fn request_span(req: &Request) -> tracing::Span {
    let id = req
        .headers()
        .get(REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let client = auth::client_app(req.headers());
    tracing::debug_span!(
        "request",
        method = %req.method(),
        path = %req.uri().path(),
        request_id = %id,
        client = client.as_deref().unwrap_or("-"),
    )
}

/// A handler panicked: log it and answer 500 like any internal error; the
/// server keeps running.
fn panic_response(panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let what = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("unknown panic");
    tracing::error!(
        panic = what,
        request_id = error::request_id().unwrap_or_default(),
        "request handler panicked"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(error::body("internal", "internal error")),
    )
        .into_response()
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

/// Every API error is JSON (`{"error","message","request_id"}`), including
/// axum's own rejections (bad JSON, body too large…), so clients can always
/// parse it, and every 429 says when to retry (`Retry-After`, seconds).
async fn json_errors(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let status = resp.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        resp.headers_mut()
            .entry(header::RETRY_AFTER)
            .or_insert(HeaderValue::from_static("60"));
    }
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
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::NOT_FOUND => "not_found",
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
    let body = error::body(code, &message).to_string();
    Response::from_parts(parts, axum::body::Body::from(body))
}

/// API version of this server: clients feature-detect from [`FEATURES`], never
/// from version numbers.
const API_VERSION: u32 = 2;

/// What this server supports beyond API 1 (see docs/ARCHITECTURE.md), plus
/// `breach_check` while the admin allows it, `item_history` while the admin
/// keeps item versions (`item_versions_kept` above 0), `sends` while Send is on,
/// `attachments` while attachments are on and have a folder, `emergency_access`
/// and `login_with_device` while they are on, and `icons` while the website-icon
/// service is on (`/api/icons/{host}` answers 404 otherwise, so apps don't ask).
const FEATURES: &[&str] = &[
    "key_epoch",
    "idempotent_create",
    "error_codes",
    "revoke_others",
    "trash_retention",
    "delta_sync",
    "vault_invitations",
    "activity_log",
    "policies",
    "forget_device",
];

async fn public_config(State(state): State<AppState>) -> Json<Value> {
    let mut features = FEATURES.to_vec();
    if state.breach_check() {
        features.push("breach_check");
    }
    if state.num(settings::Num::ItemVersionsKept) > 0 {
        features.push("item_history");
    }
    if state.flag(settings::Flag::Sends) {
        features.push("sends");
    }
    if state.flag(settings::Flag::Attachments) && state.files.is_some() {
        features.push("attachments");
    }
    if state.flag(settings::Flag::EmergencyAccess) {
        features.push("emergency_access");
    }
    if state.flag(settings::Flag::LoginWithDevice) {
        features.push("login_with_device");
    }
    if state.icons.enabled() {
        features.push("icons");
    }
    Json(json!({
        "name": "PassAuth",
        "version": env!("CARGO_PKG_VERSION"),
        "api": API_VERSION,
        "features": features,
        "signups_allowed": state.signups.read().expect("signup policy lock").allowed,
        "email_enabled": state.mailer.enabled(),
        "trash_days": state.trash_days(),
        // What clients split their requests by.
        "limits": {
            "max_import_items": state.num(settings::Num::MaxImportItems),
            "max_item_kib": state.num(settings::Num::MaxItemKib),
            "item_versions_kept": state.num(settings::Num::ItemVersionsKept),
            "send_max_days": state.num(settings::Num::SendMaxDays),
            "send_max_bytes": sends::MAX_DATA,
            "max_attachment_mb": state.num(settings::Num::MaxAttachmentMb),
        },
        // Account policies (`policies.rs`), for apps to apply before sign-in too.
        "policies": policies::config_json(&state),
    }))
}

/// `docker compose run --rm passauth reset-sync`, after restoring a database
/// backup made some other way than `backup` (pg_dump, a file copy):
/// every app's sync cursor names a newer database, so make them all fetch their
/// vaults in full once. The server picks the new generation up when it starts.
async fn reset_sync() -> Result<()> {
    let config = Config::from_env()?;
    let db = db::connect(&config.database_url, 1).await?;
    db::delete_secret(&db, state::SYNC_GENERATION).await?;
    println!(
        "Done. When the server starts, every app fetches its vaults in full at its next sync."
    );
    Ok(())
}

/// `docker compose exec passauth passauth-server reset-admin-2fa`: turn off two-step
/// login for the admin page when its authenticator and recovery codes are lost. Works
/// on a running server (the setting is read on every sign-in).
async fn reset_admin_2fa() -> Result<()> {
    let config = Config::from_env()?;
    let db = db::connect(&config.database_url, 1).await?;
    if db::delete_setting(&db, admin_security::SETTING).await? {
        println!(
            "Two-step login for the admin page is off. Sign in at /admin with the user name and password, then set it up again."
        );
    } else {
        println!("Two-step login for the admin page was not on.");
    }
    Ok(())
}

/// `docker compose exec passauth passauth-server backup /data/passauth-backup.db`:
/// a consistent copy of the SQLite database, made while the server runs, and the
/// files of its attachments in `<file>.attachments`.
async fn backup(target: String) -> Result<()> {
    let config = Config::from_env()?;
    let done = db::backup(
        &config.database_url,
        config.attachments_dir.as_deref().map(std::path::Path::new),
        std::path::Path::new(&target),
    )
    .await?;
    println!("Backup written to {target} ({} bytes).", done.size);
    if let Some(files) = &done.attachments {
        println!(
            "Attachment files: {} in {} (restore it as the attachments folder together with the database).",
            files.files,
            files.dir.display()
        );
        if files.missing > 0 {
            println!(
                "{} attachments were deleted while the backup was made and are left out of it.",
                files.missing
            );
        }
    }
    println!(
        "Keep it as safe as the server: it holds the server's sign-in key and every account's encrypted vault."
    );
    Ok(())
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
