//! Database pool and schema. One portable schema serves SQLite and
//! PostgreSQL through sqlx's `Any` driver, so it only uses TEXT, BIGINT and
//! BIGINT columns (flags are 0/1, binary values are base64url text).

use anyhow::{Context, Result};
use sqlx::any::{AnyPoolOptions, install_default_drivers};

pub type Db = sqlx::AnyPool;

const SCHEMA_V1: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS server_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        email_verified BIGINT NOT NULL,
        disabled BIGINT NOT NULL,
        opaque_record TEXT NOT NULL,
        bundle TEXT NOT NULL,
        public_key TEXT NOT NULL,
        revision BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS two_factor (
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        data TEXT NOT NULL,
        enabled BIGINT NOT NULL,
        last_used BIGINT NOT NULL,
        PRIMARY KEY (user_id, provider))",
    "CREATE TABLE IF NOT EXISTS devices (
        user_id TEXT NOT NULL,
        id TEXT NOT NULL,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        remember_hash TEXT,
        remember_expires BIGINT,
        created_at BIGINT NOT NULL,
        last_seen BIGINT NOT NULL,
        PRIMARY KEY (user_id, id))",
    "CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        access_hash TEXT NOT NULL UNIQUE,
        access_expires BIGINT NOT NULL,
        refresh_hash TEXT NOT NULL UNIQUE,
        prev_refresh_hash TEXT,
        refresh_expires BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        last_used BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id)",
    "CREATE TABLE IF NOT EXISTS vaults (
        id TEXT PRIMARY KEY,
        meta TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS vault_members (
        vault_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        wrapped_key TEXT NOT NULL,
        key_kind TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (vault_id, user_id))",
    "CREATE INDEX IF NOT EXISTS vault_members_user ON vault_members (user_id)",
    "CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        item_key TEXT NOT NULL,
        data TEXT NOT NULL,
        revision BIGINT NOT NULL,
        deleted_at BIGINT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS items_vault ON items (vault_id)",
    "CREATE TABLE IF NOT EXISTS email_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        attempts BIGINT NOT NULL,
        expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS invites (
        email TEXT PRIMARY KEY,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL)",
];

pub async fn connect(url: &str) -> Result<Db> {
    install_default_drivers();
    if let Some(dir) = url
        .strip_prefix("sqlite://")
        .and_then(|p| p.split('?').next())
        .and_then(|p| std::path::Path::new(p).parent())
    {
        std::fs::create_dir_all(dir).ok();
        let probe = dir.join(".passauth-write-test");
        std::fs::write(&probe, b"").with_context(|| {
            format!(
                "data directory {} is not writable by this process; make the host folder owned by PUID:PGID (default 1000:1000), e.g. `sudo chown -R 1000:1000 ./data`",
                dir.display()
            )
        })?;
        std::fs::remove_file(probe).ok();
    }
    let max = if url.starts_with("sqlite::memory:") {
        1
    } else {
        10
    };
    let pool = AnyPoolOptions::new()
        .max_connections(max)
        .connect(url)
        .await
        .context("connecting to database")?;
    if url.starts_with("sqlite") {
        for pragma in [
            "PRAGMA journal_mode = WAL",
            "PRAGMA foreign_keys = ON",
            "PRAGMA busy_timeout = 5000",
        ] {
            sqlx::query(pragma).execute(&pool).await.ok();
        }
    }
    migrate(&pool).await?;
    Ok(pool)
}

/// Schema changes in order; each runs once, in one transaction, when the stored version is lower.
const MIGRATIONS: &[(i64, &[&str])] = &[(1, SCHEMA_V1), (2, SCHEMA_V2)];

/// Server-wide settings the admin can change at runtime (override the env defaults).
const SCHEMA_V2: &[&str] =
    &["CREATE TABLE IF NOT EXISTS server_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"];

async fn migrate(db: &Db) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS schema_version (version BIGINT NOT NULL)")
        .execute(db)
        .await?;
    let current: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(db)
        .await?;
    for (version, stmts) in MIGRATIONS {
        if current.unwrap_or(0) >= *version {
            continue;
        }
        let mut tx = db.begin().await?;
        for stmt in *stmts {
            sqlx::query(*stmt)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("migration {version}: {stmt}"))?;
        }
        sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
            .bind(*version)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!(version, "database schema migrated");
    }
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

/// Millisecond timestamp used for sync revisions.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as i64
}

/// Read a server secret, creating it with `init` on first use.
pub async fn server_secret(db: &Db, name: &str, init: impl FnOnce() -> String) -> Result<String> {
    if let Some(v) =
        sqlx::query_scalar::<_, String>("SELECT value FROM server_secrets WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await?
    {
        return Ok(v);
    }
    let value = init();
    sqlx::query("INSERT INTO server_secrets (name, value) VALUES ($1, $2)")
        .bind(name)
        .bind(&value)
        .execute(db)
        .await?;
    Ok(value)
}

/// Read an admin-changed server setting (None = use the env default).
pub async fn setting(db: &Db, name: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT value FROM server_settings WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn set_setting(db: &Db, name: &str, value: &str) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM server_settings WHERE name = $1")
        .bind(name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO server_settings (name, value) VALUES ($1, $2)")
        .bind(name)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
