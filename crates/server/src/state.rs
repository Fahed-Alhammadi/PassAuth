use std::sync::Arc;

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
use crate::icons::IconService;
use crate::mail::Mailer;

pub type AppState = Arc<App>;

/// Live-sync sockets one account may hold open at once.
pub const MAX_SOCKETS_PER_USER: usize = 20;

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
    pub notify: DashMap<String, broadcast::Sender<String>>,
    pub icons: IconService,
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
}

pub struct PendingPasskeyRegistration {
    pub user_id: String,
    pub state: webauthn_rs::prelude::SecurityKeyRegistration,
}

impl App {
    pub async fn new(config: Config) -> Result<AppState> {
        let db = db::connect(&config.database_url).await?;
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
            config,
            db,
            opaque,
            prelogin_secret,
            registrations: Expiring::default(),
            logins: Expiring::default(),
            two_factor: Expiring::default(),
            reauth: Expiring::default(),
            limiter: RateLimiter::default(),
            notify: DashMap::new(),
            admin_verify: tokio::sync::Semaphore::new(2),
            admin_verified: std::sync::Mutex::new(None),
        }))
    }

    pub fn signups_verify(&self) -> bool {
        self.signups_verify
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Tell every connected client of these users to re-sync to their new revision.
    pub fn notify_sync(&self, revisions: &[(String, i64)]) {
        for (id, revision) in revisions {
            if let Some(tx) = self.notify.get(id) {
                let _ = tx.send(format!(r#"{{"type":"sync","revision":{revision}}}"#));
            }
        }
    }

    pub fn notify_logout(&self, user_id: &str) {
        if let Some(tx) = self.notify.get(user_id) {
            let _ = tx.send(r#"{"type":"logout"}"#.into());
        }
    }

    /// Live-sync subscription for `user_id`, or `None` when the user already
    /// has [`MAX_SOCKETS_PER_USER`] open sockets.
    pub fn subscribe(&self, user_id: &str) -> Option<broadcast::Receiver<String>> {
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

    fn sweep(&self) {
        let t = now();
        self.0.retain(|_, (exp, _)| *exp > t);
    }
}

/// Fixed-window counter keyed by e.g. `"login:<ip>"`.
#[derive(Default)]
pub struct RateLimiter(DashMap<String, (i64, u32)>);

impl RateLimiter {
    pub fn check(&self, key: &str, limit: u32, window_secs: i64) -> bool {
        let t = now();
        let mut entry = self.0.entry(key.to_owned()).or_insert((t, 0));
        if t - entry.0 >= window_secs {
            *entry = (t, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }

    fn sweep(&self) {
        let t = now();
        self.0.retain(|_, (start, _)| t - *start < 3600);
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.0.clear();
    }
}

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
