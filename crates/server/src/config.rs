//! Configuration from environment variables. Any variable can also be read
//! from a file by setting `<NAME>_FILE` (Docker secrets).

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    Starttls,
    ForceTls,
    Off,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub from_name: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Public base URL, e.g. `https://vault.example.com` (used in emails).
    pub domain: String,
    pub bind: SocketAddr,
    pub database_url: String,
    pub signups_allowed: bool,
    pub signups_domains: Vec<String>,
    pub signups_verify: bool,
    /// Argon2 PHC string (preferred) or plain token. `None` disables /api/admin.
    pub admin_token: Option<String>,
    pub smtp: Option<SmtpConfig>,
    pub web_vault_dir: Option<String>,
    /// Header holding the client IP when behind a reverse proxy.
    pub ip_header: Option<String>,
    pub log_json: bool,
    /// `ICON_SERVICE=internal` (default) serves `/api/icons/{host}`; `off` disables it.
    pub icon_service: bool,
    /// Disk cache for fetched icons. Defaults to `icons/` next to the SQLite
    /// file; `None` (e.g. PostgreSQL without `ICON_CACHE_DIR`) caches in memory.
    pub icon_cache_dir: Option<String>,
}

fn var(name: &str) -> Result<Option<String>> {
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        let v = std::fs::read_to_string(&path).with_context(|| format!("reading {name}_FILE"))?;
        return Ok(Some(v.trim().to_owned()));
    }
    Ok(std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
}

fn flag(name: &str, default: bool) -> Result<bool> {
    match var(name)?
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(v) => bail!("{name}: expected true/false, got {v:?}"),
    }
}

/// Directory holding the SQLite database file, if `url` names one on disk.
pub(crate) fn sqlite_dir(url: &str) -> Option<String> {
    let path = url.strip_prefix("sqlite:")?;
    let path = path.strip_prefix("//").unwrap_or(path);
    let path = path.split('?').next().unwrap_or_default();
    if path.is_empty() || path.contains(":memory:") {
        return None;
    }
    let dir = std::path::Path::new(path).parent()?.to_str()?;
    Some(if dir.is_empty() {
        ".".into()
    } else {
        dir.into()
    })
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let smtp = match var("SMTP_HOST")? {
            None => None,
            Some(host) => {
                let security = match var("SMTP_SECURITY")?.as_deref().unwrap_or("starttls") {
                    "starttls" => SmtpSecurity::Starttls,
                    "force_tls" => SmtpSecurity::ForceTls,
                    "off" => SmtpSecurity::Off,
                    v => bail!("SMTP_SECURITY: expected starttls, force_tls or off, got {v:?}"),
                };
                let default_port = match security {
                    SmtpSecurity::Starttls => 587,
                    SmtpSecurity::ForceTls => 465,
                    SmtpSecurity::Off => 25,
                };
                Some(SmtpConfig {
                    host,
                    port: var("SMTP_PORT")?
                        .map(|p| p.parse())
                        .transpose()?
                        .unwrap_or(default_port),
                    security,
                    username: var("SMTP_USERNAME")?,
                    password: var("SMTP_PASSWORD")?,
                    from: var("SMTP_FROM")?
                        .context("SMTP_FROM is required when SMTP_HOST is set")?,
                    from_name: var("SMTP_FROM_NAME")?.unwrap_or_else(|| "PassAuth".into()),
                })
            }
        };
        let icon_service = match var("ICON_SERVICE")?
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("internal") => true,
            Some("off") => false,
            Some(v) => bail!("ICON_SERVICE: expected internal or off, got {v:?}"),
        };
        let database_url =
            var("DATABASE_URL")?.unwrap_or_else(|| "sqlite:///data/passauth.db?mode=rwc".into());
        let icon_cache_dir = match var("ICON_CACHE_DIR")? {
            Some(dir) => Some(dir),
            None => sqlite_dir(&database_url).map(|d| format!("{d}/icons")),
        };
        let domain = var("DOMAIN")?
            .unwrap_or_else(|| "http://localhost:8080".into())
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            bind: var("BIND")?
                .unwrap_or_else(|| "0.0.0.0:8080".into())
                .parse()
                .context("BIND")?,
            database_url,
            signups_allowed: flag("SIGNUPS_ALLOWED", true)?,
            signups_domains: var("SIGNUPS_DOMAINS_WHITELIST")?
                .map(|v| {
                    v.split(',')
                        .map(|d| d.trim().to_ascii_lowercase())
                        .filter(|d| !d.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            signups_verify: flag("SIGNUPS_VERIFY", smtp.is_some())?,
            admin_token: var("ADMIN_TOKEN")?,
            web_vault_dir: if flag("WEB_VAULT_ENABLED", true)? {
                Some(var("WEB_VAULT_DIR")?.unwrap_or_else(|| "/web-vault".into()))
            } else {
                None
            },
            ip_header: var("IP_HEADER")?,
            log_json: var("LOG_FORMAT")?.as_deref() == Some("json"),
            icon_service,
            icon_cache_dir,
            smtp,
            domain,
        })
    }

    /// Sign-up policy from the environment, before any admin changes.
    pub fn signup_policy(&self) -> SignupPolicy {
        SignupPolicy {
            allowed: self.signups_allowed,
            domains: self.signups_domains.clone(),
        }
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            domain: "http://localhost".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: "sqlite::memory:".into(),
            signups_allowed: true,
            signups_domains: vec![],
            signups_verify: false,
            admin_token: Some("test-admin".into()),
            smtp: None,
            web_vault_dir: None,
            ip_header: None,
            log_json: false,
            icon_service: true,
            icon_cache_dir: None,
        }
    }
}

/// Who may self-register. Starts from `SIGNUPS_ALLOWED` / `SIGNUPS_DOMAINS_WHITELIST`;
/// the admin page can change it at runtime (stored in `server_settings`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignupPolicy {
    pub allowed: bool,
    /// Email domains allowed to sign up; empty = any.
    pub domains: Vec<String>,
}

impl SignupPolicy {
    /// Whether `email` may self-register (invites bypass this).
    pub fn permits(&self, email: &str) -> bool {
        self.allowed
            && (self.domains.is_empty()
                || email
                    .rsplit_once('@')
                    .is_some_and(|(_, d)| self.domains.iter().any(|w| w == d)))
    }
}
