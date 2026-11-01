use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use passauth_core::crypto::random_bytes;
use passauth_core::item::{b64, unb64};
use passauth_core::opaque::{Suite, opaque_ke::ServerSetup};
use rand_core06::OsRng;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::config::{Config, SignupPolicy};
use crate::db::{self, Db, now};
use crate::icons::IconService;
use crate::mail::Mailer;

pub type AppState = Arc<App>;

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
    pub limiter: RateLimiter,
    pub notify: DashMap<String, broadcast::Sender<String>>,
    pub icons: IconService,
    /// Effective sign-up policy (env defaults, overridden from the admin page).
    pub signups: std::sync::RwLock<SignupPolicy>,
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
        Ok(Arc::new(Self {
            signups: std::sync::RwLock::new(signups),
            mailer: Arc::new(Mailer::new(&config)?),
            icons: IconService::new(&config),
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
        }))
    }

    /// Tell every connected client of these users to re-sync.
    pub fn notify_sync(&self, user_ids: &[String], revision: i64) {
        let msg = format!(r#"{{"type":"sync","revision":{revision}}}"#);
        for id in user_ids {
            if let Some(tx) = self.notify.get(id) {
                let _ = tx.send(msg.clone());
            }
        }
    }

    pub fn notify_logout(&self, user_id: &str) {
        if let Some(tx) = self.notify.get(user_id) {
            let _ = tx.send(r#"{"type":"logout"}"#.into());
        }
    }

    pub fn subscribe(&self, user_id: &str) -> broadcast::Receiver<String> {
        self.notify
            .entry(user_id.to_owned())
            .or_insert_with(|| broadcast::channel(32).0)
            .subscribe()
    }

    /// Drop expired entries. Called periodically from main.
    pub fn sweep(&self) {
        self.registrations.sweep();
        self.logins.sweep();
        self.two_factor.sweep();
        self.reauth.sweep();
        self.limiter.sweep();
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
