//! Configuration from environment variables. Any variable can also be read
//! from a file by setting `<NAME>_FILE` (Docker secrets).

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    Starttls,
    ForceTls,
    Off,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
    /// `DATABASE_MAX_CONNECTIONS`: size of the database connection pool (default 10).
    pub database_max_connections: u32,
    pub signups_allowed: bool,
    pub signups_domains: Vec<String>,
    pub signups_verify: bool,
    /// Old admin sign-in: Argon2 PHC string (preferred) or plain token. Used only
    /// when `PASSAUTH_ADMIN_PASSWORD` is not set.
    pub admin_token: Option<String>,
    /// `PASSAUTH_ADMIN_USERNAME` (default `admin`).
    pub admin_username: String,
    /// `PASSAUTH_ADMIN_PASSWORD`, plain text; hashed in memory at startup.
    /// `None` (and no `admin_token`) turns the admin page off.
    pub admin_password: Option<String>,
    /// `PASSAUTH_ADMIN_ALLOWED_NETWORKS`: the admin API answers only visitors from
    /// these networks (IPs or CIDRs). `None` = from anywhere.
    pub admin_networks: Option<Vec<IpNet>>,
    pub smtp: Option<SmtpConfig>,
    pub web_vault_dir: Option<String>,
    /// Header holding the client IP when behind a reverse proxy.
    pub ip_header: Option<String>,
    /// Proxies whose `ip_header` is believed (`TRUSTED_PROXIES`, IPs or CIDRs).
    /// `None` = loopback and private-network peers, the usual reverse-proxy setups.
    pub trusted_proxies: Option<Vec<IpNet>>,
    pub log_json: bool,
    /// `ICON_SERVICE=internal` (default) serves `/api/icons/{host}`; `off` disables it.
    pub icon_service: bool,
    /// Disk cache for fetched icons. Defaults to `icons/` next to the SQLite
    /// file; `None` (e.g. PostgreSQL without `ICON_CACHE_DIR`) caches in memory.
    pub icon_cache_dir: Option<String>,
    /// Folder for attachment files (`ATTACHMENTS_DIR`, see [`attachments_dir_for`]);
    /// `None`: attachments are unavailable.
    pub attachments_dir: Option<String>,
    /// `PASSAUTH_PUSH` (default on): the starting value of the admin page's
    /// `push_enabled` (sign-in request push notifications, `push.rs`).
    pub push: bool,
    /// `PASSAUTH_PUSH_RELAY_URL` (optional): the starting value of the admin page's
    /// `push_relay_url`; `None` = [`crate::push::DEFAULT_RELAY_URL`].
    pub push_relay_url: Option<String>,
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

/// A comma-separated list of IPs or CIDRs from `name`.
fn networks(name: &str) -> Result<Option<Vec<IpNet>>> {
    var(name)?
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| IpNet::parse(p).with_context(|| format!("{name}: {p:?}")))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()
}

/// Database used when `DATABASE_URL` is not set.
pub const DEFAULT_DATABASE_URL: &str = "sqlite:///data/passauth.db?mode=rwc";

/// The image's data folder (a volume): attachments go there with PostgreSQL.
const DATA_DIR: &str = "/data";

/// Where attachment files live: `ATTACHMENTS_DIR` when set; else `attachments/`
/// beside the SQLite file (like the icon cache); else, with PostgreSQL, `/data/attachments`
/// when the image's `/data` folder exists (the compose file mounts it). Otherwise
/// `None`: attachments are unavailable (the server says so at startup) rather than
/// stored somewhere a container restart would lose them.
pub fn attachments_dir_for(
    database_url: &str,
    env: Option<String>,
    data_dir_exists: bool,
) -> Option<String> {
    if let Some(dir) = env {
        return Some(dir);
    }
    if let Some(dir) = sqlite_dir(database_url) {
        return Some(format!("{dir}/attachments"));
    }
    (crate::db::is_postgres(database_url) && data_dir_exists)
        .then(|| format!("{DATA_DIR}/attachments"))
}

fn attachments_dir_from_env(database_url: &str) -> Result<Option<String>> {
    Ok(attachments_dir_for(
        database_url,
        var("ATTACHMENTS_DIR")?,
        std::path::Path::new(DATA_DIR).is_dir(),
    ))
}

/// The admin password `.env.example` ships with; the admin page stays off until it is changed.
pub const ADMIN_PASSWORD_EXAMPLE: &str = "change-me-to-a-long-password";
pub const ADMIN_PASSWORD_MIN_CHARS: usize = 12;

/// Folders PassAuth itself writes (the SQLite database folder, the icon cache and
/// the attachments), for the startup ownership fix. Only absolute paths below `/`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn data_dirs() -> Result<Vec<String>> {
    let db = var("DATABASE_URL")?.unwrap_or_else(|| DEFAULT_DATABASE_URL.into());
    let attachments = attachments_dir_from_env(&db)?;
    Ok(data_dirs_for(&db, var("ICON_CACHE_DIR")?, attachments))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn data_dirs_for(
    database_url: &str,
    icon_cache_dir: Option<String>,
    attachments_dir: Option<String>,
) -> Vec<String> {
    let safe = |d: &String| {
        let path = std::path::Path::new(d);
        path.is_absolute() && path.components().count() > 1
    };
    let db_dir = sqlite_dir(database_url).filter(safe);
    let icons = match icon_cache_dir {
        Some(dir) => Some(dir).filter(safe),
        None => db_dir.as_ref().map(|d| format!("{d}/icons")),
    };
    let attachments = attachments_dir.filter(safe);
    let mut dirs: Vec<String> = db_dir.into_iter().chain(icons).chain(attachments).collect();
    dirs.dedup();
    dirs
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
        let database_url = var("DATABASE_URL")?.unwrap_or_else(|| DEFAULT_DATABASE_URL.into());
        let icon_cache_dir = match var("ICON_CACHE_DIR")? {
            Some(dir) => Some(dir),
            None => sqlite_dir(&database_url).map(|d| format!("{d}/icons")),
        };
        let attachments_dir = attachments_dir_from_env(&database_url)?;
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
            database_max_connections: match var("DATABASE_MAX_CONNECTIONS")? {
                None => crate::db::DEFAULT_MAX_CONNECTIONS,
                Some(v) => v
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (1..=1000).contains(n))
                    .context("DATABASE_MAX_CONNECTIONS: expected a number from 1 to 1000")?,
            },
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
            admin_username: var("PASSAUTH_ADMIN_USERNAME")?
                .map(|u| u.trim().to_owned())
                .unwrap_or_else(|| "admin".into()),
            admin_password: var("PASSAUTH_ADMIN_PASSWORD")?,
            web_vault_dir: if flag("WEB_VAULT_ENABLED", true)? {
                Some(var("WEB_VAULT_DIR")?.unwrap_or_else(|| "/web-vault".into()))
            } else {
                None
            },
            ip_header: var("IP_HEADER")?,
            trusted_proxies: networks("TRUSTED_PROXIES")?,
            admin_networks: networks("PASSAUTH_ADMIN_ALLOWED_NETWORKS")?,
            log_json: var("LOG_FORMAT")?.as_deref() == Some("json"),
            icon_service,
            icon_cache_dir,
            attachments_dir,
            push: flag("PASSAUTH_PUSH", true)?,
            push_relay_url: var("PASSAUTH_PUSH_RELAY_URL")?
                .map(|u| {
                    crate::push::check_relay_url(&u)
                        .map_err(|e| anyhow::anyhow!("PASSAUTH_PUSH_RELAY_URL: {e}"))
                })
                .transpose()?,
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
            database_max_connections: crate::db::DEFAULT_MAX_CONNECTIONS,
            signups_allowed: true,
            signups_domains: vec![],
            signups_verify: false,
            admin_token: Some("test-admin".into()),
            admin_username: "admin".into(),
            admin_password: None,
            admin_networks: None,
            smtp: None,
            web_vault_dir: None,
            ip_header: None,
            trusted_proxies: None,
            log_json: false,
            icon_service: true,
            icon_cache_dir: None,
            attachments_dir: None,
            push: true,
            push_relay_url: None,
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

/// An IP network (`10.0.0.0/8`, `fd00::/8`) or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn parse(s: &str) -> Result<Self> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p.parse::<u8>().context("prefix length")?)),
            None => (s, None),
        };
        let addr: IpAddr = ip.parse().context("IP address")?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            bail!("prefix /{prefix} is too long");
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) as plain IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let (full, rest) = ((prefix / 8) as usize, prefix % 8);
    if a[..full] != b[..full] {
        return false;
    }
    rest == 0 || (a[full] ^ b[full]) >> (8 - rest) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_networks() {
        let net = IpNet::parse("10.1.0.0/16").unwrap();
        assert!(net.contains("10.1.200.3".parse().unwrap()));
        assert!(net.contains("::ffff:10.1.0.9".parse().unwrap()));
        assert!(!net.contains("10.2.0.1".parse().unwrap()));
        let one = IpNet::parse("2001:db8::1").unwrap();
        assert!(one.contains("2001:db8::1".parse().unwrap()));
        assert!(!one.contains("2001:db8::2".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(
            IpNet::parse("172.16.0.0/12")
                .unwrap()
                .contains("172.31.255.1".parse().unwrap())
        );
    }

    #[test]
    fn data_dirs_follow_the_database_and_skip_unsafe_paths() {
        let attachments = |db: &str| attachments_dir_for(db, None, true);
        assert_eq!(
            data_dirs_for(
                DEFAULT_DATABASE_URL,
                None,
                attachments(DEFAULT_DATABASE_URL)
            ),
            ["/data", "/data/icons", "/data/attachments"]
        );
        // Never the root folder or a relative path (that would be the working directory).
        assert!(data_dirs_for("sqlite:///passauth.db", None, None).is_empty());
        assert!(
            data_dirs_for(
                "sqlite:passauth.db",
                Some("cache".into()),
                attachments("sqlite:passauth.db")
            )
            .is_empty()
        );
        assert_eq!(
            data_dirs_for(
                "postgres://db/passauth",
                Some("/cache/icons".into()),
                Some("/files".into())
            ),
            ["/cache/icons", "/files"]
        );
        assert!(data_dirs_for("postgres://db/passauth", None, None).is_empty());
    }

    #[test]
    fn attachments_live_beside_the_database_or_in_the_data_volume() {
        assert_eq!(
            attachments_dir_for(DEFAULT_DATABASE_URL, None, false).as_deref(),
            Some("/data/attachments")
        );
        assert_eq!(
            attachments_dir_for("sqlite://db/p.db", None, true).as_deref(),
            Some("db/attachments")
        );
        assert_eq!(
            attachments_dir_for("postgres://db/passauth", Some("/files".into()), false).as_deref(),
            Some("/files")
        );
        // PostgreSQL: the image's /data volume, else nowhere (never a folder a
        // container restart would lose).
        assert_eq!(
            attachments_dir_for("postgres://db/passauth", None, true).as_deref(),
            Some("/data/attachments")
        );
        assert_eq!(
            attachments_dir_for("postgres://db/passauth", None, false),
            None
        );
        assert_eq!(attachments_dir_for("sqlite::memory:", None, true), None);
    }
}
