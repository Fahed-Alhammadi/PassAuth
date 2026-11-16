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

/// Connections a pool opens when `DATABASE_MAX_CONNECTIONS` is not set.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// Open the database with up to `max_connections` (`DATABASE_MAX_CONNECTIONS`)
/// and bring its schema up to date.
pub async fn connect(url: &str, max_connections: u32) -> Result<Db> {
    let pool = open(url, max_connections).await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Open the database without touching its schema (`backup`).
pub async fn open(url: &str, max_connections: u32) -> Result<Db> {
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
        max_connections.max(1)
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
    Ok(pool)
}

/// Schema changes in order; each runs once, in one transaction, when the stored version is lower.
const MIGRATIONS: &[(i64, &[&str])] = &[
    (1, SCHEMA_V1),
    (2, SCHEMA_V2),
    (3, SCHEMA_V3),
    (4, SCHEMA_V4),
    (5, SCHEMA_V5),
    (6, SCHEMA_V6),
    (7, SCHEMA_V7),
    (8, SCHEMA_V8),
    (9, SCHEMA_V9),
    (10, SCHEMA_V10),
    (11, SCHEMA_V11),
    (12, SCHEMA_V12),
    (13, SCHEMA_V13),
    (14, SCHEMA_V14),
];

/// Server-wide settings the admin can change at runtime (override the env defaults).
const SCHEMA_V2: &[&str] =
    &["CREATE TABLE IF NOT EXISTS server_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"];

/// Indexes for hot lookups and the sweeper, plus per-account two-factor failure counting.
const SCHEMA_V3: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS sessions_prev_refresh ON sessions (prev_refresh_hash)",
    "CREATE INDEX IF NOT EXISTS sessions_refresh_expires ON sessions (refresh_expires)",
    "CREATE INDEX IF NOT EXISTS email_tokens_user ON email_tokens (user_id, purpose)",
    "CREATE INDEX IF NOT EXISTS email_tokens_expires ON email_tokens (expires_at)",
    "CREATE TABLE IF NOT EXISTS two_factor_failures (
        user_id TEXT PRIMARY KEY,
        failures BIGINT NOT NULL,
        window_start BIGINT NOT NULL,
        locked_until BIGINT NOT NULL)",
];

/// Security keys / passkeys for two-step login (`credential` = webauthn-rs `SecurityKey` JSON).
const SCHEMA_V4: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS passkey_credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        credential TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        last_used_at BIGINT)",
    "CREATE INDEX IF NOT EXISTS passkey_credentials_user ON passkey_credentials (user_id)",
];

/// A vault whose key must be replaced because someone who knew it left or was
/// removed without a rotation; any admin's client finishes it (`/rotate`).
const SCHEMA_V5: &[&str] =
    &["ALTER TABLE vaults ADD COLUMN rotation_pending BIGINT NOT NULL DEFAULT 0"];

/// Vault key epochs (writes made with a replaced vault key are refused), the
/// client app of each session (`X-PassAuth-Client`), and indexes for email links
/// and the trash sweeper.
const SCHEMA_V6: &[&str] = &[
    "ALTER TABLE vaults ADD COLUMN key_epoch BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE sessions ADD COLUMN client TEXT",
    "CREATE INDEX IF NOT EXISTS email_tokens_hash ON email_tokens (token_hash)",
    "CREATE INDEX IF NOT EXISTS items_deleted ON items (deleted_at) WHERE deleted_at IS NOT NULL",
];

/// Delta sync. Every write into a vault takes the vault's next `seq` and stamps
/// the item rows it writes with it; items purged or moved out leave a tombstone
/// with that `seq`, kept `tombstone_days` (admin page). A cursor older than a
/// vault's `horizon` (its newest forgotten tombstone) gets the whole vault again.
const SCHEMA_V7: &[&str] = &[
    "ALTER TABLE vaults ADD COLUMN seq BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE vaults ADD COLUMN horizon BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE items ADD COLUMN seq BIGINT NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS items_vault_seq ON items (vault_id, seq)",
    "CREATE TABLE IF NOT EXISTS item_tombstones (
        vault_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        seq BIGINT NOT NULL,
        deleted_at BIGINT NOT NULL,
        PRIMARY KEY (vault_id, item_id))",
    "CREATE INDEX IF NOT EXISTS item_tombstones_seq ON item_tombstones (vault_id, seq)",
    "CREATE INDEX IF NOT EXISTS item_tombstones_deleted ON item_tombstones (deleted_at)",
];

/// Vault invitations: a share is `invited` (no access, nothing synced) until the
/// invitee accepts it; rows from before are `active`. The activity log (`events`,
/// ids only, kept `event_days`). Item version history: the previous row of every
/// edit and trash (`item_versions`, newest `item_versions_kept` per item), with who
/// saved each item row (`items.updated_by`).
const SCHEMA_V8: &[&str] = &[
    "ALTER TABLE vault_members ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
    "ALTER TABLE vault_members ADD COLUMN invited_by TEXT",
    "ALTER TABLE vault_members ADD COLUMN invited_at BIGINT",
    "ALTER TABLE items ADD COLUMN updated_by TEXT",
    "CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        at BIGINT NOT NULL,
        type TEXT NOT NULL,
        actor_id TEXT,
        session_id TEXT,
        client TEXT,
        ip TEXT,
        vault_id TEXT,
        item_id TEXT,
        target_user_id TEXT,
        data TEXT)",
    "CREATE INDEX IF NOT EXISTS events_actor ON events (actor_id, at)",
    "CREATE INDEX IF NOT EXISTS events_vault ON events (vault_id, at)",
    "CREATE INDEX IF NOT EXISTS events_target ON events (target_user_id, at)",
    "CREATE INDEX IF NOT EXISTS events_at ON events (at)",
    "CREATE TABLE IF NOT EXISTS item_versions (
        item_id TEXT NOT NULL,
        vault_id TEXT NOT NULL,
        seq BIGINT NOT NULL,
        item_key TEXT NOT NULL,
        data TEXT NOT NULL,
        saved_at BIGINT NOT NULL,
        saved_by TEXT,
        PRIMARY KEY (item_id, seq))",
    "CREATE INDEX IF NOT EXISTS item_versions_vault ON item_versions (vault_id)",
];

/// Send: text shared through a link whose key only the link holds (`sends.rs`).
/// `name` and `data` are encrypted with that key, `owner_key` is it wrapped by the
/// owner's account key, `access_verifier` the SHA-256 of an optional password's
/// verifier. `kind` is `text`; a `file` kind can add its columns later. Plus the
/// sessions of one device, for signing a device out (`/account/devices/{id}/forget`)
/// and the sweeper's forgotten devices.
const SCHEMA_V9: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS sends (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        data TEXT NOT NULL,
        owner_key TEXT NOT NULL,
        access_salt TEXT,
        access_verifier TEXT,
        max_views BIGINT,
        views BIGINT NOT NULL DEFAULT 0,
        expires_at BIGINT,
        delete_at BIGINT NOT NULL,
        disabled BIGINT NOT NULL DEFAULT 0,
        hide_email BIGINT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS sends_user ON sends (user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS sends_delete_at ON sends (delete_at)",
    "CREATE INDEX IF NOT EXISTS sessions_device ON sessions (user_id, device_id)",
];

/// Attachments (`vault/attachments.rs`): one row per encrypted file of an item,
/// which lives in the attachments folder under its id (`files.rs`). `state` is
/// `pending` until the upload of exactly `size` bytes finishes, then `ready`; the
/// file's name, key and real size are only inside the encrypted item. Emergency
/// access (`emergency.rs`): a trusted contact (`grantee`) who may ask to view the
/// `grantor`'s own vaults after `wait_days`; `sealed_key` is the grantor's account
/// key sealed by their app to the grantee's public key, handed out only once access
/// is approved.
const SCHEMA_V10: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS attachments (
        id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL,
        vault_id TEXT NOT NULL,
        size BIGINT NOT NULL,
        state TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        created_by TEXT NOT NULL,
        updated_at BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS attachments_item ON attachments (item_id)",
    "CREATE INDEX IF NOT EXISTS attachments_vault ON attachments (vault_id)",
    "CREATE INDEX IF NOT EXISTS attachments_state ON attachments (state, updated_at)",
    "CREATE TABLE IF NOT EXISTS emergency_access (
        id TEXT PRIMARY KEY,
        grantor_id TEXT NOT NULL,
        grantee_id TEXT NOT NULL,
        status TEXT NOT NULL,
        wait_days BIGINT NOT NULL,
        sealed_key TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        requested_at BIGINT,
        approved_at BIGINT)",
    "CREATE UNIQUE INDEX IF NOT EXISTS emergency_access_pair ON emergency_access (grantor_id, grantee_id)",
    "CREATE INDEX IF NOT EXISTS emergency_access_grantee ON emergency_access (grantee_id)",
    "CREATE INDEX IF NOT EXISTS emergency_access_requested ON emergency_access (status, requested_at)",
];

/// Sign-in requests a signed-in device approves (`auth_requests.rs`). `user_id` is
/// set when the email belongs to an account that may sign in, else NULL (nobody sees
/// the request; it expires). `email_hash` is a keyed hash of the email (per-email
/// limit), `access_code_hash` and `remember_hash` SHA-256 of the new device's poll
/// code and "remember this device" token; `sealed_key` is the account key sealed by
/// the approving app to `requester_public_key`, kept only until the new device takes
/// it. Status: `pending` → `approved` | `denied` | `expired`; `approved` → `used`
/// (exchanged once) | `expired`. Rows go a day after they expire.
const SCHEMA_V11: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS auth_requests (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        email_hash TEXT NOT NULL,
        requester_public_key TEXT NOT NULL,
        device_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        device_kind TEXT NOT NULL,
        client TEXT,
        ip TEXT,
        access_code_hash TEXT NOT NULL,
        remember_hash TEXT,
        status TEXT NOT NULL,
        sealed_key TEXT,
        approved_by_session TEXT,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        answered_at BIGINT)",
    "CREATE INDEX IF NOT EXISTS auth_requests_user ON auth_requests (user_id, status)",
    "CREATE INDEX IF NOT EXISTS auth_requests_email ON auth_requests (email_hash, created_at)",
    "CREATE INDEX IF NOT EXISTS auth_requests_expires ON auth_requests (expires_at)",
];

/// Security fixes. `vault_ids`: every vault id this server has ever used, never
/// deleted, so a deleted vault's id can't be created again (409 `vault_exists`)
/// and nobody who knows it inherits its activity log; filled with the vaults that
/// exist and the ids that still appear anywhere (vaults deleted before). The Send
/// wrong-password count moves into the Send's row (`wrong_passwords` since
/// `wrong_since`), so neither a restart nor a flood of other requests resets it.
/// Unfinished attachment uploads count against whoever started them (index for
/// that).
const SCHEMA_V12: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS vault_ids (id TEXT PRIMARY KEY, created_at BIGINT NOT NULL)",
    "INSERT INTO vault_ids (id, created_at) SELECT id, created_at FROM vaults",
    RETIRE_KNOWN_VAULT_IDS,
    "ALTER TABLE sends ADD COLUMN wrong_passwords BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE sends ADD COLUMN wrong_since BIGINT NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS attachments_creator ON attachments (created_by, state)",
];

/// Emergency access v2 (`emergency.rs`): a contact gets a key of their own (an
/// emergency key per access) that opens only the grantor's personal vaults, instead
/// of the grantor's account key. `sealed_key` is now that key sealed to the contact,
/// `grantor_key` the same key wrapped by the grantor's account key (for their apps
/// to wrap more vault keys later), `key_version` the scheme (2), and
/// `emergency_vault_keys` each personal vault key wrapped by an access's key. The
/// grantor's apps keep the list of contacts they trust in `users.emergency_roster`,
/// sealed with the account key (opaque here), changed only by compare-and-swap on
/// `emergency_roster_seq`. Every access that held a sealed account key goes back to
/// `accepted` with `reconfirm` and `v1_exposed` set, without it (the data step in
/// [`migrate`], which on SQLite also overwrites the freed space): the grantor
/// confirms the contact again with the new scheme.
const SCHEMA_V13: &[&str] = &[
    "ALTER TABLE emergency_access ADD COLUMN key_version BIGINT NOT NULL DEFAULT 2",
    "ALTER TABLE emergency_access ADD COLUMN grantor_key TEXT",
    "ALTER TABLE emergency_access ADD COLUMN reconfirm BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE emergency_access ADD COLUMN v1_exposed BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN emergency_roster TEXT",
    "ALTER TABLE users ADD COLUMN emergency_roster_seq BIGINT NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS emergency_vault_keys (
        access_id TEXT NOT NULL,
        vault_id TEXT NOT NULL,
        wrapped_key TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (access_id, vault_id))",
    "CREATE INDEX IF NOT EXISTS emergency_vault_keys_vault ON emergency_vault_keys (vault_id)",
];

/// Signed sharing (`signing.rs`, `vault/signed.rs`): each account's signing identity
/// (`users.signing_key`, `identity_signature`, the X25519 key's XEdDSA cross-signature
/// `x25519_signature`, the private key `wrapped_signing_key` by the account key; set
/// once, `identity_at`), its key pins (`users.key_pins`,
/// sealed by its apps, changed by compare-and-swap on `key_pins_seq`), each
/// membership's share signature, who made it and their identity then
/// (`vault_members.share_signature`, `share_signer`, `share_signer_identity`: JSON,
/// so the share still verifies once the signer's account is gone; NULL = not
/// signed), and each vault's signed member roster: the
/// latest in `vaults.member_roster` (version `member_roster_seq`, 0 = none) and every
/// version in `vault_rosters`, so apps can check the chain of who changed it.
const SCHEMA_V14: &[&str] = &[
    "ALTER TABLE users ADD COLUMN signing_key TEXT",
    "ALTER TABLE users ADD COLUMN identity_signature TEXT",
    "ALTER TABLE users ADD COLUMN x25519_signature TEXT",
    "ALTER TABLE users ADD COLUMN wrapped_signing_key TEXT",
    "ALTER TABLE users ADD COLUMN identity_at BIGINT",
    "ALTER TABLE users ADD COLUMN key_pins TEXT",
    "ALTER TABLE users ADD COLUMN key_pins_seq BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE vault_members ADD COLUMN share_signature TEXT",
    "ALTER TABLE vault_members ADD COLUMN share_signer TEXT",
    "ALTER TABLE vault_members ADD COLUMN share_signer_identity TEXT",
    "ALTER TABLE vaults ADD COLUMN member_roster TEXT",
    "ALTER TABLE vaults ADD COLUMN member_roster_seq BIGINT NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS vault_rosters (
        vault_id TEXT NOT NULL,
        version BIGINT NOT NULL,
        roster TEXT NOT NULL,
        signer_id TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (vault_id, version))",
];

/// Migration 12: the ids of vaults deleted before it, as far as the database still
/// names them (their activity log above all), go into `vault_ids` too.
pub(crate) const RETIRE_KNOWN_VAULT_IDS: &str = "INSERT INTO vault_ids (id, created_at)
     SELECT DISTINCT x.vault_id, 0 FROM (
         SELECT vault_id FROM events WHERE vault_id IS NOT NULL
         UNION SELECT vault_id FROM vault_members
         UNION SELECT vault_id FROM items
         UNION SELECT vault_id FROM item_versions
         UNION SELECT vault_id FROM item_tombstones
         UNION SELECT vault_id FROM attachments
     ) x
     WHERE NOT EXISTS (SELECT 1 FROM vault_ids v WHERE v.id = x.vault_id)";

async fn migrate(db: &Db) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS schema_version (version BIGINT NOT NULL)")
        .execute(db)
        .await?;
    let current: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(db)
        .await?;
    let latest = MIGRATIONS.last().map_or(0, |(v, _)| *v);
    if let Some(current) = current
        && current > latest
    {
        anyhow::bail!(
            "this database was last used by a newer PassAuth server (schema version {current}; \
             version {} knows up to {latest}). Start that newer version again, or restore the \
             backup you made before upgrading",
            env!("CARGO_PKG_VERSION")
        );
    }
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
        let sqlite = tx.backend_name() == "SQLite";
        data_step(*version, &mut tx, sqlite)
            .await
            .with_context(|| format!("migration {version}: data"))?;
        sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
            .bind(*version)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!(version, "database schema migrated");
    }
    Ok(())
}

/// `server_settings` key, set by migration 13 on SQLite: the database files may still
/// hold the secrets it cleared (account keys sealed to emergency contacts), so
/// [`scrub_if_pending`] rebuilds them, at each start until that succeeds.
pub const SCRUB_PENDING: &str = "scrub_pending";

/// The database file of a SQLite `url` on disk.
fn sqlite_file(url: &str) -> Option<std::path::PathBuf> {
    let path = url.strip_prefix("sqlite:")?;
    let path = path.strip_prefix("//").unwrap_or(path);
    let path = path.split('?').next().unwrap_or_default();
    (!path.is_empty() && !path.contains(":memory:")).then(|| path.into())
}

/// The pending scrub ([`SCRUB_PENDING`]), at start-up. It never fails the start: when
/// the disk lacks room for twice the database (its size, write-ahead log included:
/// `VACUUM` builds a temporary copy and writes the new file through the log) plus
/// the admin's reserve (`min_free_disk_mb`), or the scrub fails, it warns and stays
/// pending for the next start.
pub async fn scrub_if_pending(state: &crate::state::App) {
    match setting(&state.db, SCRUB_PENDING).await {
        Ok(Some(_)) => {}
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read whether the database still needs its one-time cleanup");
            return;
        }
    }
    let size = sqlite_file(&state.config.database_url).map_or(0, |file| {
        let len = |p: &std::path::Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let mut wal = file.clone().into_os_string();
        wal.push("-wal");
        (len(&file) + len(std::path::Path::new(&wal))).saturating_mul(2)
    });
    let reserve = state.num(crate::settings::Num::MinFreeDiskMb).max(0) as u64 * 1024 * 1024;
    if let Some(free) = state.disk.free().await
        && free < size.saturating_add(reserve)
    {
        tracing::warn!(
            free_mb = free / (1024 * 1024),
            needed_mb = size.saturating_add(reserve) / (1024 * 1024),
            "the one-time cleanup of the database (erasing old emergency access keys) needs more free disk space; it runs at the next start"
        );
        return;
    }
    match scrub_sqlite(&state.db).await {
        Ok(()) => match delete_setting(&state.db, SCRUB_PENDING).await {
            Ok(_) => tracing::info!(
                "database cleaned up: old emergency access keys erased from its files"
            ),
            Err(e) => {
                tracing::warn!(error = %e, "database cleaned up, but couldn't note it; it runs again at the next start")
            }
        },
        Err(e) => tracing::warn!(
            error = %e,
            "the one-time cleanup of the database (erasing old emergency access keys) failed; it runs again at the next start"
        ),
    }
}

/// Leave no copy of cleared secrets in the SQLite files: `VACUUM` rebuilds the
/// database without free pages (also those an earlier deletion left, before
/// `secure_delete`), on its own connection and outside any transaction; then the
/// write-ahead log is checkpointed and emptied (`TRUNCATE`), tried again for a moment
/// while a reader holds it, else left with a warning (it empties itself at a later
/// checkpoint).
async fn scrub_sqlite(db: &Db) -> Result<()> {
    #[cfg(test)]
    if setting(db, "test_fail_vacuum").await?.is_some() {
        anyhow::bail!("VACUUM failed (a test's fault)");
    }
    let mut conn = db.acquire().await?;
    sqlx::query("VACUUM")
        .execute(&mut *conn)
        .await
        .context("rebuilding the database file (VACUUM)")?;
    for attempt in 1..=CHECKPOINT_TRIES {
        let (busy, _log, _done): (i64, i64, i64) =
            sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(&mut *conn)
                .await
                .context("checkpointing the write-ahead log")?;
        if busy == 0 {
            return Ok(());
        }
        if attempt < CHECKPOINT_TRIES {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    tracing::warn!(
        "the write-ahead log is busy and couldn't be emptied now; old values in it go at a later checkpoint"
    );
    Ok(())
}

/// Tries of the migration's write-ahead log checkpoint while a reader holds it.
const CHECKPOINT_TRIES: u32 = 10;

/// Data a migration changes after its statements, in the same transaction (what
/// needs the clock, new ids or the activity log).
async fn data_step(version: i64, conn: &mut sqlx::AnyConnection, sqlite: bool) -> Result<()> {
    if version != 13 {
        return Ok(());
    }
    // Migration 13 clears the account keys sealed to emergency contacts (v1): SQLite
    // overwrites what it frees on this connection meanwhile, so they don't stay in
    // free pages of the file. PostgreSQL's old row versions go with its vacuum.
    let secure_delete: Option<i64> = if sqlite {
        let was = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(&mut *conn)
            .await?;
        sqlx::query("PRAGMA secure_delete = ON")
            .execute(&mut *conn)
            .await?;
        Some(was)
    } else {
        None
    };
    let reset = crate::emergency::reconfirm_v1_accesses(conn).await;
    if let Some(was) = secure_delete {
        sqlx::query(if was == 0 {
            "PRAGMA secure_delete = OFF"
        } else {
            "PRAGMA secure_delete = ON"
        })
        .execute(&mut *conn)
        .await?;
    }
    let reset = reset?;
    if reset > 0 {
        tracing::info!(
            accesses = reset,
            "emergency contacts must be confirmed again (new emergency access keys)"
        );
    }
    // Always, once: a v1 key may also linger in space freed by an access removed before.
    if sqlite {
        set_setting(&mut *conn, SCRUB_PENDING, "1").await?;
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
    // Two instances starting at once: the first insert wins and both read it back.
    sqlx::query(
        "INSERT INTO server_secrets (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(init())
    .execute(db)
    .await?;
    Ok(
        sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = $1")
            .bind(name)
            .fetch_one(db)
            .await?,
    )
}

/// Remove a server secret (it is made again on first use).
pub async fn delete_secret(db: &Db, name: &str) -> Result<()> {
    sqlx::query("DELETE FROM server_secrets WHERE name = $1")
        .bind(name)
        .execute(db)
        .await?;
    Ok(())
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

/// Save a setting (on the pool, or inside a caller's transaction).
pub async fn set_setting<'e, E>(db: E, name: &str, value: &str) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    sqlx::query(
        "INSERT INTO server_settings (name, value) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value",
    )
    .bind(name)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

/// Remove a setting; true when it existed.
pub async fn delete_setting<'e, E>(db: E, name: &str) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let done = sqlx::query("DELETE FROM server_settings WHERE name = $1")
        .bind(name)
        .execute(db)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Replace a setting only if it still holds `old` (two requests can't both use one code).
pub async fn swap_setting<'e, E>(db: E, name: &str, old: &str, new: &str) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let done = sqlx::query("UPDATE server_settings SET value = $1 WHERE name = $2 AND value = $3")
        .bind(new)
        .bind(name)
        .bind(old)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// Whether the database is PostgreSQL (else SQLite).
pub fn is_postgres(url: &str) -> bool {
    url.starts_with("postgres")
}

/// What [`backup`] wrote.
#[derive(Debug)]
pub struct Backup {
    /// Bytes of the database copy.
    pub size: u64,
    /// The attachment files, when the copy has any.
    pub attachments: Option<AttachmentsCopy>,
}

/// The folder of attachment files written beside a backup copy.
#[derive(Debug)]
pub struct AttachmentsCopy {
    /// `<backup file>.attachments`, laid out like the attachments folder.
    pub dir: std::path::PathBuf,
    /// Files in it (one per attachment in the copy).
    pub files: u64,
    /// Attachments whose file was deleted after the copy was taken: left out of
    /// the copy, rows included.
    pub missing: u64,
}

/// The folder beside backup file `target` that holds its attachment files.
pub fn attachments_backup_dir(target: &std::path::Path) -> std::path::PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".attachments");
    name.into()
}

/// Write a consistent copy of the SQLite database to `target` (a new file, mode
/// 0600: it holds the server's OPAQUE key) while the server keeps running, and
/// the files of the attachments that are ready in that copy to the new folder
/// `<target>.attachments` (see [`copy_attachments`]). PostgreSQL is backed up with
/// `pg_dump` instead.
pub async fn backup(
    url: &str,
    attachments: Option<&std::path::Path>,
    target: &std::path::Path,
) -> Result<Backup> {
    if is_postgres(url) {
        anyhow::bail!(
            "the database is PostgreSQL: back it up with pg_dump (for example `pg_dump -Fc -f passauth.dump <database>`)"
        );
    }
    if url.contains(":memory:") {
        anyhow::bail!("the database is in memory; there is nothing to back up");
    }
    // Never create an empty database (`mode=rwc`) just to copy it.
    let source = url.strip_prefix("sqlite:").unwrap_or(url);
    let source = source.strip_prefix("//").unwrap_or(source);
    let source = source.split('?').next().unwrap_or_default();
    if !std::path::Path::new(source).is_file() {
        anyhow::bail!("there is no database at {source:?} (check DATABASE_URL)");
    }
    // `VACUUM INTO` needs a missing or empty file; creating it first (never
    // following an existing file or link) sets its permissions.
    let mut file = std::fs::OpenOptions::new();
    file.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut file, 0o600);
    file.open(target)
        .with_context(|| format!("creating {} (it must not exist yet)", target.display()))?;
    let path = target
        .to_str()
        .context("the backup path must be valid UTF-8")?
        .to_owned();
    let db = open(url, 1).await?;
    let done = sqlx::query("VACUUM INTO $1")
        .bind(&path)
        .execute(&db)
        .await
        .map_err(|e| anyhow::Error::from(e).context("copying the database"));
    db.close().await;
    let done = match done {
        Ok(_) => forget_sync_generation(&path).await,
        Err(e) => Err(e),
    };
    let copied = match done {
        Ok(()) => copy_attachments(&path, attachments, target).await,
        Err(e) => Err(e),
    };
    match copied {
        Ok(attachments) => Ok(Backup {
            size: std::fs::metadata(target)?.len(),
            attachments,
        }),
        Err(e) => {
            std::fs::remove_file(target).ok();
            Err(e)
        }
    }
}

/// Put the attachment files of the backup copy at `copy` beside it, so the copy
/// and its files match: the files of the rows that are `ready` in the copy go to
/// the new folder `<target>.attachments` (hard links where the file system allows,
/// as files never change in place). Pending uploads have no file yet and a file
/// deleted after the copy was taken can't be copied: their rows are left out of the
/// copy. `None` when the copy has no attachments (no folder is made).
async fn copy_attachments(
    copy: &str,
    from: Option<&std::path::Path>,
    target: &std::path::Path,
) -> Result<Option<AttachmentsCopy>> {
    use sqlx::{ConnectOptions, Connection};
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(copy)
        .connect()
        .await
        .context("opening the backup copy")?;
    // A database the server hasn't migrated yet has no attachments.
    let table: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'attachments'",
    )
    .fetch_one(&mut conn)
    .await?;
    if table == 0 {
        conn.close().await?;
        return Ok(None);
    }
    sqlx::query("DELETE FROM attachments WHERE state <> 'ready'")
        .execute(&mut conn)
        .await
        .context("updating the backup copy")?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM attachments ORDER BY id")
        .fetch_all(&mut conn)
        .await?;
    if ids.is_empty() {
        conn.close().await?;
        return Ok(None);
    }
    let Some(from) = from else {
        anyhow::bail!(
            "the database has attachments but no attachments folder is set (ATTACHMENTS_DIR)"
        );
    };
    let dir = attachments_backup_dir(target);
    crate::files::new_folder(&dir).with_context(|| {
        format!(
            "creating {} for the attachment files (it must not exist yet)",
            dir.display()
        )
    })?;
    let copied = async {
        let missing = tokio::task::spawn_blocking({
            let (from, dir, ids) = (from.to_owned(), dir.clone(), ids.clone());
            move || crate::files::copy_into(&from, &ids, &dir)
        })
        .await?
        .context("copying the attachment files")?;
        if !missing.is_empty() {
            sqlx::query("DELETE FROM attachments WHERE id IN (SELECT value FROM json_each($1))")
                .bind(serde_json::to_string(&missing)?)
                .execute(&mut conn)
                .await
                .context("updating the backup copy")?;
        }
        conn.close().await?;
        anyhow::Ok(missing.len() as u64)
    }
    .await;
    match copied {
        Ok(missing) => Ok(Some(AttachmentsCopy {
            dir,
            files: ids.len() as u64 - missing,
            missing,
        })),
        Err(e) => {
            std::fs::remove_dir_all(&dir).ok();
            Err(e)
        }
    }
}

/// Leave the sync generation out of a backup copy: a server started from it
/// makes a new one, so apps that synced after the backup was made fetch their
/// vaults in full once instead of trusting cursors from a newer database.
async fn forget_sync_generation(copy: &str) -> Result<()> {
    use sqlx::{ConnectOptions, Connection};
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(copy)
        .connect()
        .await
        .context("opening the backup copy")?;
    sqlx::query("DELETE FROM server_secrets WHERE name = $1")
        .bind(crate::state::SYNC_GENERATION)
        .execute(&mut conn)
        .await
        .context("updating the backup copy")?;
    conn.close().await?;
    Ok(())
}
