//! Logging with a level the admin page can change while the server runs.
//! `LOG_LEVEL` (any `tracing` filter) sets the starting level; a level saved on
//! the admin page replaces it.

use std::sync::OnceLock;

use anyhow::Result;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry, fmt, reload};

/// Levels offered on the admin page, quietest first.
pub const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

static FILTER: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// Filter for one of [`LEVELS`]; noisy libraries stay a step quieter.
fn directives(level: &str) -> String {
    match level {
        "info" => "info,tower_http=warn,sqlx=warn".into(),
        "debug" => "debug,hyper=info,hyper_util=info,h2=info,rustls=info,sqlx=warn".into(),
        other => other.into(),
    }
}

pub fn init(json: bool) {
    let filter =
        EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new(directives("info")));
    let (filter, handle) = reload::Layer::new(filter);
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer()).init();
    }
    let _ = FILTER.set(handle);
}

/// The level from `LOG_LEVEL`: one of [`LEVELS`], `custom` for any other filter, or `info`.
pub fn env_level() -> String {
    match std::env::var("LOG_LEVEL") {
        Ok(v) if v.trim().is_empty() => "info".into(),
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            if LEVELS.contains(&v.as_str()) {
                v
            } else {
                "custom".into()
            }
        }
        Err(_) => "info".into(),
    }
}

/// Switch to one of [`LEVELS`] now. Does nothing before [`init`] (tests).
pub fn set_level(level: &str) -> Result<()> {
    anyhow::ensure!(LEVELS.contains(&level), "unknown log level {level:?}");
    if let Some(handle) = FILTER.get() {
        handle.reload(EnvFilter::new(directives(level)))?;
    }
    Ok(())
}
