use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use passauth_core::crypto::random_bytes;
use passauth_core::item::{b64, unb64};
use passauth_core::opaque::{Suite, opaque_ke::ServerSetup};
use rand_core06::OsRng;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::config::{
    ADMIN_PASSWORD_EXAMPLE, ADMIN_PASSWORD_MIN_CHARS, Config, SignupPolicy, SmtpConfig,
};
use crate::db::{self, Db, now};
use crate::error::{ApiError, ApiResult};
use crate::icons::IconService;
use crate::mail::Mailer;
use crate::settings::{Flag, Num, Numbers};

pub type AppState = Arc<App>;

/// Live-sync sockets one account may hold open at once.
pub const MAX_SOCKETS_PER_USER: usize = 20;

/// Sync notices for one account within this time reach its sockets as one message.
pub const SYNC_COLLAPSE: Duration = Duration::from_millis(300);

pub struct App {
    pub config: Config,
    pub db: Db,
    pub opaque: ServerSetup<Suite>,
    /// Keys deterministic fake prelogin answers for unknown emails.
    pub prelogin_secret: [u8; 32],
    pub mailer: Arc<Mailer>,
    pub registrations: Expiring<PendingRegistration>,
    pub logins: Expiring<PendingLogin>,
    pub two_factor: Expiring<PendingTwoFactor>,
    pub reauth: Expiring<String>,
    /// Security-key registrations in progress (`passkeys.rs`).
    pub passkey_registrations: Expiring<PendingPasskeyRegistration>,
    /// WebAuthn relying party from `DOMAIN`; `None` when it isn't a usable URL.
    pub webauthn: Option<webauthn_rs::Webauthn>,
    pub limiter: RateLimiter,
    /// Failed sign-ins waiting to be counted in the activity log (`events.rs`).
    pub failures: crate::events::FailureLog,
    /// Free space on the disks holding the data (`disk.rs`).
    pub disk: crate::disk::Disk,
    /// Live-sync channel of each account with open sockets (`ws.rs`).
    pub notify: DashMap<String, broadcast::Sender<Notice>>,
    /// Sync notices waiting for their account's collapse window ([`SYNC_COLLAPSE`]).
    pub pending_sync: DashMap<String, SyncNotice>,
    /// Changes when the database is restored from a `backup` copy (which leaves
    /// it out): every sync cursor from before is then unreadable, so apps fetch
    /// their vaults in full once.
    pub sync_generation: String,
    pub icons: IconService,
    /// Attachment files (`files.rs`); `None` when the server has no folder it can
    /// write them to (attachments are then unavailable).
    pub files: Option<crate::files::FileStore>,
    /// Limits and lifetimes from the admin page (`settings.rs`), e.g. `trash_days`.
    pub numbers: Numbers,
    /// Effective sign-up policy (env defaults, overridden from the admin page).
    pub signups: std::sync::RwLock<SignupPolicy>,
    /// New accounts must confirm their email before the first sign-in
    /// (`SIGNUPS_VERIFY`, overridden from the admin page).
    pub signups_verify: std::sync::atomic::AtomicBool,
    /// Log level shown on the admin page: one of `logging::LEVELS` or `custom`.
    pub log_level: std::sync::RwLock<String>,
    /// How the admin page signs in.
    pub admin: AdminLogin,
    /// Admin page sessions by SHA-256 of their token: (idle expiry, absolute expiry).
    pub admin_sessions: DashMap<String, (i64, i64)>,
    /// Admin sign-ins waiting for their two-step code (value = wrong codes so far).
    pub admin_pending: Expiring<u32>,
    /// Admin two-step setup in progress: (secret, expiry).
    pub admin_2fa_setup: std::sync::Mutex<Option<(String, i64)>>,
    /// Bounds concurrent Argon2 checks of admin sign-ins (each takes ~19 MiB).
    pub admin_verify: tokio::sync::Semaphore,
    /// SHA-256 of the last `ADMIN_TOKEN` sent directly as a bearer token that passed
    /// the Argon2 check, with its expiry (scripts that skip `/admin/login`).
    pub admin_verified: std::sync::Mutex<Option<(String, i64)>>,
}

/// How the admin page signs in.
pub enum AdminLogin {
    /// No admin credentials, or a password the server refuses (`weak` = true).
    Off { weak: bool },
    /// `PASSAUTH_ADMIN_USERNAME` + `PASSAUTH_ADMIN_PASSWORD` (kept as an Argon2 hash).
    Password { username: String, hash: String },
    /// Old `ADMIN_TOKEN` (Argon2 PHC string or plain text).
    Token(String),
}

impl AdminLogin {
    fn from_config(config: &Config) -> Result<Self> {
        let Some(password) = &config.admin_password else {
            return Ok(match &config.admin_token {
                Some(token) => Self::Token(token.clone()),
                None => Self::Off { weak: false },
            });
        };
        if password == ADMIN_PASSWORD_EXAMPLE || password.chars().count() < ADMIN_PASSWORD_MIN_CHARS
        {
            tracing::warn!(
                "the admin page is off: PASSAUTH_ADMIN_PASSWORD is still the example value or shorter than {ADMIN_PASSWORD_MIN_CHARS} characters; set a long password in .env and run `docker compose up -d`"
            );
            return Ok(Self::Off { weak: true });
        }
        if config.admin_username.is_empty() {
            anyhow::bail!("PASSAUTH_ADMIN_USERNAME is empty");
        }
        if config.admin_token.is_some() {
            tracing::info!(
                "ADMIN_TOKEN is ignored because PASSAUTH_ADMIN_PASSWORD is set; you can remove it from .env"
            );
        }
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hashing the admin password: {e}"))?
            .to_string();
        Ok(Self::Password {
            username: config.admin_username.clone(),
            hash,
        })
    }

    pub fn mode(&self) -> &'static str {
        match self {
            Self::Off { .. } => "off",
            Self::Password { .. } => "password",
            Self::Token(_) => "token",
        }
    }
}

pub struct PendingRegistration {
    pub email: String,
    pub account_id: String,
}

pub struct PendingLogin {
    /// `None` for unknown emails: the protocol runs against a fake record.
    pub user_id: Option<String>,
    pub state: Vec<u8>,
}

#[derive(Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub kind: String,
}

pub struct PendingTwoFactor {
    pub user_id: String,
    pub device: DeviceInfo,
    pub attempts: u32,
    /// Security-key challenge issued by `/auth/2fa/passkey/start`, if any.
    pub passkey: Option<webauthn_rs::prelude::SecurityKeyAuthentication>,
    /// Set when the sign-in is a request another device approved (`auth_requests.rs`)
    /// rather than the master password: the sealed account key waits here for the
    /// session.
    pub device_login: Option<DeviceLogin>,
}

/// A sign-in request another device approved, being exchanged for a session.
#[derive(Clone)]
pub struct DeviceLogin {
    pub request_id: String,
    /// The account key sealed by the approving app to the new device's public key
    /// (opaque to the server). It goes out only together with the session.
    pub sealed_key: String,
}

pub struct PendingPasskeyRegistration {
    pub user_id: String,
    pub state: webauthn_rs::prelude::SecurityKeyRegistration,
}

/// A message for the live-sync sockets of one account.
#[derive(Clone, Debug)]
pub enum Notice {
    /// The account's data changed: its clients re-sync up to this revision.
    Sync(SyncNotice),
    /// These sessions ended: their sockets get `{"type":"logout"}` and close.
    Logout(Sessions),
    /// A device asks to sign in to the account (`auth_requests.rs`):
    /// `{"type":"auth_request","id"}` on every socket.
    AuthRequest(String),
    /// A sign-in request was approved or denied on one of the account's devices:
    /// `{"type":"auth_request_answered","id"}` on every socket.
    AuthRequestAnswered(String),
}

/// What changed for one account (`{"type":"sync"}` on its sockets).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncNotice {
    /// The account's new sync revision.
    pub revision: i64,
    /// New sequence numbers of the account's vaults that were written.
    pub vaults: BTreeMap<String, i64>,
    /// Live-sync origin of the session that wrote ([`App::origin`]); `None` for
    /// the server's own changes, or when writes from several sessions were collapsed.
    pub origin: Option<String>,
}

impl SyncNotice {
    pub fn new(revision: i64, origin: Option<String>) -> Self {
        Self {
            revision,
            vaults: BTreeMap::new(),
            origin,
        }
    }

    /// Fold a later notice into this one: the newest revision and sequence
    /// numbers win, and an origin stays only while every write came from it.
    pub fn merge(&mut self, later: SyncNotice) {
        self.revision = self.revision.max(later.revision);
        for (vault, seq) in later.vaults {
            let s = self.vaults.entry(vault).or_insert(seq);
            *s = (*s).max(seq);
        }
        if self.origin != later.origin {
            self.origin = None;
        }
    }
}

/// Which of an account's sessions a [`Notice::Logout`] is for.
#[derive(Clone, Debug)]
pub enum Sessions {
    All,
    Only(String),
    AllExcept(String),
}

impl Sessions {
    pub fn includes(&self, session_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(id) => id == session_id,
            Self::AllExcept(id) => id != session_id,
        }
    }
}

impl App {
    pub async fn new(config: Config) -> Result<AppState> {
        let db = db::connect(&config.database_url, config.database_max_connections).await?;
        let opaque_bytes = db::server_secret(&db, "opaque_server_setup", || {
            b64(&ServerSetup::<Suite>::new(&mut OsRng).serialize())
        })
        .await?;
        let opaque = ServerSetup::<Suite>::deserialize(&unb64(&opaque_bytes)?)
            .map_err(|e| anyhow::anyhow!("invalid stored OPAQUE setup: {e:?}"))?;
        let prelogin = db::server_secret(&db, "prelogin_secret", || {
            b64(&random_bytes::<32>().unwrap())
        })
        .await?;
        let prelogin_secret = unb64(&prelogin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid prelogin secret"))?;
        let mut signups = config.signup_policy();
        if let Some(v) = db::setting(&db, "signups_allowed").await? {
            signups.allowed = v == "1";
        }
        if let Some(v) = db::setting(&db, "signups_domains").await? {
            signups.domains = v
                .split(',')
                .filter(|d| !d.is_empty())
                .map(str::to_owned)
                .collect();
        }
        let flag = |v: Option<String>, default: bool| v.map_or(default, |v| v == "1");
        let signups_verify = flag(
            db::setting(&db, "signups_verify").await?,
            config.signups_verify,
        );
        let icons_on = flag(db::setting(&db, "icon_service").await?, config.icon_service);
        let numbers = Numbers::load(&db).await?;
        let sync_generation =
            db::server_secret(&db, SYNC_GENERATION, || b64(&random_bytes::<9>().unwrap())).await?;
        let log_level = match db::setting(&db, "log_level").await? {
            Some(level) if crate::logging::set_level(&level).is_ok() => level,
            _ => crate::logging::env_level(),
        };
        let smtp: Option<SmtpConfig> = match db::setting(&db, "smtp").await?.as_deref() {
            Some("off") => None,
            Some(json) => match serde_json::from_str(json) {
                Ok(smtp) => Some(smtp),
                Err(e) => {
                    tracing::warn!(error = %e, "saved email settings are unreadable; using SMTP_* from .env");
                    config.smtp.clone()
                }
            },
            None => config.smtp.clone(),
        };
        let mailer = match Mailer::new(&config.domain, smtp.as_ref()) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "email settings are invalid, email is off until they are fixed on the admin page");
                Mailer::new(&config.domain, None)?
            }
        };
        let icons = IconService::new(&config);
        icons.set_enabled(icons_on);
        let files = match config.attachments_dir.as_deref() {
            Some(dir) => match crate::files::FileStore::open(dir) {
                Ok(store) => Some(store),
                Err(e) => {
                    tracing::warn!(dir, error = %e, "attachments are unavailable: the server can't write to their folder (ATTACHMENTS_DIR)");
                    None
                }
            },
            None => {
                if db::is_postgres(&config.database_url) {
                    tracing::warn!(
                        "attachments are unavailable: with PostgreSQL, mount the /data volume or set ATTACHMENTS_DIR to a folder for them"
                    );
                }
                None
            }
        };
        let disk = crate::disk::Disk::new(
            &config.database_url,
            files.as_ref().map(crate::files::FileStore::dir),
        );
        let failures = crate::events::FailureLog::start(db.clone());
        let admin = AdminLogin::from_config(&config)?;
        let webauthn = match crate::passkeys::build(&config.domain) {
            Ok(w) => Some(w),
            Err(e) => {
                tracing::warn!(error = %e, "security keys for two-step login are unavailable until DOMAIN is the server's full public address");
                None
            }
        };
        Ok(Arc::new(Self {
            webauthn,
            passkey_registrations: Expiring::default(),
            signups: std::sync::RwLock::new(signups),
            signups_verify: std::sync::atomic::AtomicBool::new(signups_verify),
            log_level: std::sync::RwLock::new(log_level),
            admin,
            admin_sessions: DashMap::new(),
            admin_pending: Expiring::default(),
            admin_2fa_setup: std::sync::Mutex::new(None),
            mailer: Arc::new(mailer),
            icons,
            files,
            config,
            db,
            opaque,
            prelogin_secret,
            registrations: Expiring::default(),
            logins: Expiring::default(),
            two_factor: Expiring::default(),
            reauth: Expiring::default(),
            limiter: RateLimiter::default(),
            failures,
            disk,
            notify: DashMap::new(),
            pending_sync: DashMap::new(),
            sync_generation,
            numbers,
            admin_verify: tokio::sync::Semaphore::new(2),
            admin_verified: std::sync::Mutex::new(None),
        }))
    }

    pub fn signups_verify(&self) -> bool {
        self.signups_verify
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The current value of an admin setting.
    pub fn num(&self, n: Num) -> i64 {
        self.numbers.get(n)
    }

    /// The current value of an admin switch.
    pub fn flag(&self, f: Flag) -> bool {
        self.numbers.flag(f)
    }

    pub fn trash_days(&self) -> i64 {
        self.num(Num::TrashDays)
    }

    /// Whether the web vault may check passwords against Have I Been Pwned.
    pub fn breach_check(&self) -> bool {
        self.numbers.breach_check()
    }

    /// Short opaque id of a session for live sync: the server names the writer in
    /// each `{"type":"sync"}` message, and every socket learns its own in
    /// `{"type":"hello"}`, so clients skip what they wrote themselves. Keyed with a
    /// server secret, so it says nothing about the session id.
    pub fn origin(&self, session_id: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.prelogin_secret);
        h.update(b"passauth/live-sync-origin/v1");
        h.update(session_id.as_bytes());
        b64(&h.finalize()[..9])
    }

    /// Tell the connected clients of these users to re-sync. Notices for one
    /// account within [`SYNC_COLLAPSE`] reach its sockets as one message (see
    /// [`SyncNotice::merge`]); accounts without sockets are skipped.
    pub fn notify_sync(self: &Arc<Self>, notices: Vec<(String, SyncNotice)>) {
        use dashmap::mapref::entry::Entry;
        for (user, notice) in notices {
            if !self.notify.contains_key(&user) {
                continue;
            }
            match self.pending_sync.entry(user.clone()) {
                Entry::Occupied(mut pending) => pending.get_mut().merge(notice),
                Entry::Vacant(slot) => {
                    slot.insert(notice);
                    match tokio::runtime::Handle::try_current() {
                        Ok(rt) => {
                            let app = Arc::clone(self);
                            rt.spawn(async move {
                                tokio::time::sleep(SYNC_COLLAPSE).await;
                                app.flush_sync(&user);
                            });
                        }
                        Err(_) => self.flush_sync(&user),
                    }
                }
            }
        }
    }

    /// Send an account's collected sync notice to its sockets.
    fn flush_sync(&self, user: &str) {
        if let Some((_, notice)) = self.pending_sync.remove(user)
            && let Some(tx) = self.notify.get(user)
        {
            let _ = tx.send(Notice::Sync(notice));
        }
    }

    /// Sign these sessions' sockets out at once (the rows are already gone).
    pub fn notify_logout(&self, user_id: &str, sessions: Sessions) {
        if let Some(tx) = self.notify.get(user_id) {
            let _ = tx.send(Notice::Logout(sessions));
        }
    }

    /// Drop the account's sign-ins waiting for their two-step login: their token
    /// stops working, and the sealed key of an approved device sign-in goes with it.
    /// For a new master password, a disabled or deleted account, and signing
    /// everyone else out.
    pub fn forget_pending_sign_ins(&self, user_id: &str) {
        self.two_factor.retain(|p| p.user_id != user_id);
    }

    /// Send `notice` to every socket of the account at once (sign-in requests).
    pub fn notify_user(&self, user_id: &str, notice: Notice) {
        if let Some(tx) = self.notify.get(user_id) {
            let _ = tx.send(notice);
        }
    }

    /// Live-sync subscription for `user_id`, or `None` when the user already
    /// has [`MAX_SOCKETS_PER_USER`] open sockets.
    pub fn subscribe(&self, user_id: &str) -> Option<broadcast::Receiver<Notice>> {
        let tx = self
            .notify
            .entry(user_id.to_owned())
            .or_insert_with(|| broadcast::channel(32).0);
        (tx.receiver_count() < MAX_SOCKETS_PER_USER).then(|| tx.subscribe())
    }

    /// Drop expired entries. Called periodically from main.
    pub fn sweep(&self) {
        self.registrations.sweep();
        self.logins.sweep();
        self.two_factor.sweep();
        self.reauth.sweep();
        self.passkey_registrations.sweep();
        self.admin_pending.sweep();
        self.limiter.sweep();
        let t = now();
        self.admin_sessions
            .retain(|_, (idle, absolute)| *idle > t && *absolute > t);
        self.notify.retain(|_, tx| tx.receiver_count() > 0);
    }
}

/// In-memory map whose entries expire. Entries are single-use (`take`).
pub struct Expiring<T>(DashMap<String, (i64, T)>);

impl<T> Default for Expiring<T> {
    fn default() -> Self {
        Self(DashMap::new())
    }
}

impl<T> Expiring<T> {
    pub fn insert(&self, value: T, ttl_secs: i64) -> String {
        let id = random_token();
        self.0.insert(id.clone(), (now() + ttl_secs, value));
        id
    }

    pub fn put_back(&self, id: String, value: T, expires: i64) {
        self.0.insert(id, (expires, value));
    }

    pub fn take(&self, id: &str) -> Option<(i64, T)> {
        let (_, (exp, v)) = self.0.remove(id)?;
        (exp > now()).then_some((exp, v))
    }

    /// Look at an unexpired entry without taking it.
    pub fn peek<R>(&self, id: &str, look: impl FnOnce(&T) -> R) -> Option<R> {
        let entry = self.0.get(id)?;
        (entry.0 > now()).then(|| look(&entry.1))
    }

    /// Keep only the entries `keep` says yes to.
    pub fn retain(&self, mut keep: impl FnMut(&T) -> bool) {
        self.0.retain(|_, (_, v)| keep(v));
    }

    fn sweep(&self) {
        let t = now();
        self.0.retain(|_, (exp, _)| *exp > t);
    }
}

/// Most keys the rate limiter keeps for addresses ([`Class::Address`]). They come
/// from addresses and what visitors send along, so a flood from many addresses
/// could otherwise grow the map without bound.
pub const LIMITER_MAX_KEYS: usize = 100_000;

/// Which of the rate limiter's maps a key lives in. The two never share room, so
/// flooding one can't drop the counters of the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Keyed by the visitor's address, alone or with something the visitor
    /// chose (`"login-ip:<ip>"`, `"login-email:<email>:<ip>"`). Anyone with many
    /// addresses can make many such keys, so this map is bounded: when it is full,
    /// ended windows go first, then the oldest tenth. That only resets counters of
    /// addresses, and an attacker who can make that many keys has that many
    /// addresses anyway.
    Address,
    /// Keyed by something the request has proven exists: the signed-in user, a
    /// sign-in waiting for its two-step code, an emergency access, the whole
    /// server. Their number follows the accounts and accesses in the database, not
    /// the traffic, so they are never dropped to make room (only once their window
    /// has ended). Never key this class by anything a visitor can make up.
    Target,
}

/// Fixed-window counters, keyed e.g. `"login-ip:<ip>"`, in the two maps of
/// [`Class`], plus [`SlotCounter`]s for the per-email ceilings, whose keys anyone
/// can make up.
pub struct RateLimiter {
    addresses: DashMap<String, Window>,
    /// Most keys in `addresses` ([`LIMITER_MAX_KEYS`]; tests lower it).
    capacity: AtomicUsize,
    targets: DashMap<String, Window>,
    /// Sign-in attempts per email from every address together (`auth.rs`).
    pub login_email: SlotCounter,
    /// Sign-in requests per email that reach the account's devices (`auth_requests.rs`).
    pub auth_request_shown: SlotCounter,
}

struct Window {
    start: i64,
    secs: i64,
    count: u32,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            addresses: DashMap::new(),
            capacity: AtomicUsize::new(LIMITER_MAX_KEYS),
            targets: DashMap::new(),
            login_email: SlotCounter::new(
                1 << 18,
                crate::auth::LOGIN_PER_EMAIL,
                crate::auth::LOGIN_PER_EMAIL_WINDOW,
            ),
            auth_request_shown: SlotCounter::new(
                1 << 14,
                crate::auth_requests::SHOWN_PER_EMAIL as u32,
                crate::auth_requests::TTL,
            ),
        }
    }
}

impl RateLimiter {
    /// Count one request for `key` in `class`: `Err(seconds)` until its window
    /// ends once more than `limit` were made within `window_secs`.
    pub fn hit(&self, class: Class, key: &str, limit: u32, window_secs: i64) -> Result<(), u64> {
        let t = now();
        let map = match class {
            Class::Address => {
                if !self.addresses.contains_key(key)
                    && self.addresses.len() >= self.capacity.load(Ordering::Relaxed)
                {
                    self.make_room(t);
                }
                &self.addresses
            }
            Class::Target => &self.targets,
        };
        let mut w = map.entry(key.to_owned()).or_insert(Window {
            start: t,
            secs: window_secs,
            count: 0,
        });
        if t - w.start >= window_secs || t < w.start {
            *w = Window {
                start: t,
                secs: window_secs,
                count: 0,
            };
        }
        w.count = w.count.saturating_add(1);
        if w.count <= limit {
            Ok(())
        } else {
            Err((w.start + window_secs - t).max(1) as u64)
        }
    }

    /// [`Self::hit`] as a 429 error.
    pub fn limit(&self, class: Class, key: &str, limit: u32, window_secs: i64) -> ApiResult<()> {
        self.hit(class, key, limit, window_secs)
            .map_err(ApiError::TooManyRequests)
    }

    /// Drop windows that have ended.
    fn sweep(&self) {
        let t = now();
        self.addresses.retain(|_, w| t - w.start < w.secs);
        self.targets.retain(|_, w| t - w.start < w.secs);
    }

    /// The address map is full: drop ended windows, and if that isn't enough (a
    /// flood of new keys) the oldest tenth. Those keys start counting again from
    /// zero, which beats refusing everyone or running out of memory. Only address
    /// keys go: [`Class::Target`] counters and the [`SlotCounter`]s stay.
    fn make_room(&self, t: i64) {
        let map = &self.addresses;
        map.retain(|_, w| t - w.start < w.secs);
        if map.len() < self.capacity.load(Ordering::Relaxed) {
            return;
        }
        let mut starts: Vec<i64> = map.iter().map(|e| e.start).collect();
        starts.sort_unstable();
        let cutoff = starts[starts.len() / 10];
        map.retain(|_, w| w.start > cutoff);
        tracing::warn!(
            kept = map.len(),
            "rate limiter full; dropped the oldest address entries"
        );
    }

    /// Keys held in `class`.
    #[cfg(test)]
    pub fn key_count(&self, class: Class) -> usize {
        match class {
            Class::Address => self.addresses.len(),
            Class::Target => self.targets.len(),
        }
    }

    /// Room for this many address keys (tests flood a small map).
    #[cfg(test)]
    pub fn set_capacity(&self, keys: usize) {
        self.capacity.store(keys, Ordering::Relaxed);
    }

    /// Forget every count.
    #[cfg(test)]
    pub fn clear(&self) {
        self.addresses.clear();
        self.targets.clear();
        self.login_email.clear();
        self.auth_request_shown.clear();
    }
}

/// Fixed-window counters for keys anyone can make up, such as every email address
/// whether or not it has an account: a fixed table of slots, each key counted in
/// the slot a keyed hash of it picks. Memory never grows and nothing is ever
/// dropped to make room, so no flood resets a key's count; and an email without an
/// account is counted exactly like one with an account, so the limit tells nobody
/// which exist. Keys that land in one slot share its count, which can only make
/// the limit stricter for them. The hash key is random per process, so nobody can
/// aim at a given key's slot: raising every slot over the limit takes `limit` ×
/// the number of slots requests within one window.
pub struct SlotCounter {
    /// Window start (Unix seconds) in the high 32 bits, the count in the low 32.
    slots: Box<[AtomicU64]>,
    secret: [u8; 32],
    limit: u32,
    window: i64,
}

impl SlotCounter {
    /// `slots` counters (a power of two) of at most `limit` per `window` seconds.
    pub fn new(slots: usize, limit: u32, window: i64) -> Self {
        debug_assert!(slots.is_power_of_two());
        Self {
            slots: (0..slots).map(|_| AtomicU64::new(0)).collect(),
            secret: random_bytes::<32>().expect("OS RNG available"),
            limit,
            window,
        }
    }

    fn slot(&self, key: &str) -> &AtomicU64 {
        let digest = Sha256::new()
            .chain_update(self.secret)
            .chain_update(key.as_bytes())
            .finalize();
        let mut index = [0u8; 8];
        index.copy_from_slice(&digest[..8]);
        let i = u64::from_le_bytes(index) as usize & (self.slots.len() - 1);
        &self.slots[i]
    }

    /// Count one request for `key`: `Err(seconds)` until its slot's window ends
    /// once more than the limit were counted in it.
    pub fn hit(&self, key: &str) -> Result<(), u64> {
        let t = now();
        let slot = self.slot(key);
        let mut seen = slot.load(Ordering::Relaxed);
        loop {
            let (start, count) = ((seen >> 32) as i64, seen as u32);
            let (start, count) = if t - start >= self.window || t < start {
                (t, 0)
            } else {
                (start, count)
            };
            let count = count.saturating_add(1);
            let next =
                (u64::from(u32::try_from(start).unwrap_or(u32::MAX)) << 32) | u64::from(count);
            match slot.compare_exchange_weak(seen, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) if count <= self.limit => return Ok(()),
                Ok(_) => return Err((start + self.window - t).max(1) as u64),
                Err(now_there) => seen = now_there,
            }
        }
    }

    /// [`Self::hit`] as a 429 error.
    pub fn limit(&self, key: &str) -> ApiResult<()> {
        self.hit(key).map_err(ApiError::TooManyRequests)
    }

    #[cfg(test)]
    fn clear(&self) {
        for slot in self.slots.iter() {
            slot.store(0, Ordering::Relaxed);
        }
    }
}

/// `server_secrets` row naming this database's sync generation (see [`App::sync_generation`]).
pub const SYNC_GENERATION: &str = "sync_generation";

pub fn random_token() -> String {
    b64(&random_bytes::<32>().expect("OS RNG available"))
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time string comparison.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
