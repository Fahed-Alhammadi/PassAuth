//! Website icons: `GET /api/icons/{host}`.
//!
//! Loaded by clients as `<img src>`, so the route cannot be authenticated.
//! That makes it an SSRF surface, hence:
//! - hosts must be plain public DNS names (no IP literals, no local suffixes);
//! - we resolve DNS ourselves, refuse the target if any address is
//!   non-public, and connect only to an address we checked (no rebinding);
//! - redirects are followed by hand (max 3), each hop re-validated;
//! - only http/https on ports 80/443, small body caps, a 5 s budget;
//! - only raster images (sniffed by magic bytes) are served, never SVG/HTML.
//!
//! Results (hits and misses) are cached on disk, or in a bounded map.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use dashmap::DashMap;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

use crate::auth::client_ip;
use crate::config::Config;
use crate::db::now;
use crate::state::AppState;

const USER_AGENT: &str = "PassAuth-Icons/1.0";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Per TCP connect and per TLS handshake, so the http fallback still fits.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTML_LIMIT: usize = 256 * 1024;
const ICON_LIMIT: usize = 100 * 1024;
const MAX_REDIRECTS: usize = 3;
/// `<link>` icons tried before falling back to `/favicon.ico`.
const MAX_CANDIDATES: usize = 3;
const HIT_TTL: i64 = 7 * 86400;
const MISS_TTL: i64 = 86400;
const MAX_CONCURRENT: usize = 8;
/// Uncached fetches per client IP per minute.
const RATE_LIMIT: u32 = 60;
const MEM_ENTRIES: usize = 1000;
const DISK_ENTRIES: usize = 20_000;

const HIT_CACHE: &str = "public, max-age=604800";
const MISS_CACHE: &str = "public, max-age=86400";

pub fn routes() -> Router<AppState> {
    Router::new().route("/icons/{host}", get(icon))
}

async fn icon(
    State(state): State<AppState>,
    Path(host): Path<String>,
    headers: HeaderMap,
) -> Response {
    let icons = &state.icons;
    if !icons.enabled {
        return reply(StatusCode::NOT_FOUND, "no-store", None);
    }
    let Some(host) = normalize_host(&host) else {
        return reply(StatusCode::NOT_FOUND, MISS_CACHE, None);
    };
    let lookup = match icons.cached(&host).await {
        Some(hit) => hit,
        None => {
            let key = format!("icons:{}", client_ip(&state, &headers));
            if !state.limiter.check(&key, RATE_LIMIT, 60) {
                return reply(StatusCode::TOO_MANY_REQUESTS, "no-store", None);
            }
            icons.fetch_coalesced(&host).await
        }
    };
    match lookup {
        Lookup::Hit(icon) => reply(StatusCode::OK, HIT_CACHE, Some(icon)),
        Lookup::Miss => reply(StatusCode::NOT_FOUND, MISS_CACHE, None),
        Lookup::Busy => reply(StatusCode::SERVICE_UNAVAILABLE, "no-store", None),
    }
}

fn reply(status: StatusCode, cache: &'static str, icon: Option<Icon>) -> Response {
    let (content_type, body) = match icon {
        Some(icon) => (icon.kind.content_type(), Body::from(icon.bytes)),
        None => ("text/plain; charset=utf-8", Body::empty()),
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    h.insert(header::CACHE_CONTROL, cache.parse().unwrap());
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'".parse().unwrap(),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    resp
}

// ------------------------------------------------------------------ service

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Ico,
    Gif,
    Jpeg,
    Webp,
}

impl ImageKind {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Ico => "image/x-icon",
            Self::Gif => "image/gif",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

#[derive(Clone)]
pub struct Icon {
    pub bytes: Bytes,
    pub kind: ImageKind,
}

#[derive(Clone)]
enum Lookup {
    Hit(Icon),
    Miss,
    /// Too many fetches in flight; not cached.
    Busy,
}

pub struct IconService {
    enabled: bool,
    disk: Option<PathBuf>,
    mem: DashMap<String, (i64, Option<Icon>)>,
    inflight: DashMap<String, Arc<OnceCell<Lookup>>>,
    permits: Semaphore,
    tls: tokio_rustls::TlsConnector,
    last_disk_sweep: AtomicI64,
}

impl IconService {
    pub fn new(config: &Config) -> Self {
        let disk = config
            .icon_cache_dir
            .as_deref()
            .filter(|_| config.icon_service)
            .and_then(|dir| match std::fs::create_dir_all(dir) {
                Ok(()) => Some(PathBuf::from(dir)),
                Err(e) => {
                    tracing::warn!(dir, error = %e, "icon cache dir unavailable, caching in memory");
                    None
                }
            });
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            enabled: config.icon_service,
            disk,
            mem: DashMap::new(),
            inflight: DashMap::new(),
            permits: Semaphore::new(MAX_CONCURRENT),
            tls: tokio_rustls::TlsConnector::from(Arc::new(tls)),
            last_disk_sweep: AtomicI64::new(0),
        }
    }

    async fn cached(&self, host: &str) -> Option<Lookup> {
        let Some(dir) = &self.disk else {
            let entry = self.mem.get(host)?;
            let (expires, icon) = &*entry;
            return (*expires > now()).then(|| icon.clone().map_or(Lookup::Miss, Lookup::Hit));
        };
        let path = dir.join(host);
        let meta = tokio::fs::metadata(&path).await.ok()?;
        let age = meta
            .modified()
            .ok()?
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        if meta.len() == 0 {
            return (age < MISS_TTL as u64).then_some(Lookup::Miss);
        }
        if age >= HIT_TTL as u64 {
            return None;
        }
        let bytes = tokio::fs::read(&path).await.ok()?;
        let kind = sniff(&bytes)?;
        Some(Lookup::Hit(Icon {
            bytes: bytes.into(),
            kind,
        }))
    }

    /// Stores a hit (`Some`) or a miss (`None`). On disk a miss is an empty file.
    pub async fn store(&self, host: &str, icon: Option<&Icon>) {
        if let Some(dir) = &self.disk {
            let tmp = dir.join(format!(".{host}.{}.tmp", uuid::Uuid::new_v4().simple()));
            let data: &[u8] = icon.map(|i| i.bytes.as_ref()).unwrap_or_default();
            let written = match tokio::fs::write(&tmp, data).await {
                Ok(()) => tokio::fs::rename(&tmp, dir.join(host)).await,
                Err(e) => Err(e),
            };
            if let Err(e) = written {
                let _ = tokio::fs::remove_file(&tmp).await;
                tracing::warn!(error = %e, "writing icon cache failed");
            }
            return;
        }
        if self.mem.len() >= MEM_ENTRIES {
            let t = now();
            self.mem.retain(|_, (expires, _)| *expires > t);
            if self.mem.len() >= MEM_ENTRIES {
                self.mem.clear();
            }
        }
        let ttl = if icon.is_some() { HIT_TTL } else { MISS_TTL };
        self.mem
            .insert(host.to_owned(), (now() + ttl, icon.cloned()));
    }

    /// Concurrent requests for the same host share one fetch.
    async fn fetch_coalesced(&self, host: &str) -> Lookup {
        let cell = Arc::clone(&self.inflight.entry(host.to_owned()).or_default());
        let lookup = cell
            .get_or_init(|| self.fetch_and_store(host))
            .await
            .clone();
        self.inflight.remove_if(host, |_, c| Arc::ptr_eq(c, &cell));
        lookup
    }

    async fn fetch_and_store(&self, host: &str) -> Lookup {
        let Ok(Ok(_permit)) = tokio::time::timeout(FETCH_TIMEOUT, self.permits.acquire()).await
        else {
            return Lookup::Busy;
        };
        let icon = tokio::time::timeout(FETCH_TIMEOUT, self.fetch(host))
            .await
            .ok()
            .flatten();
        self.store(host, icon.as_ref()).await;
        icon.map_or(Lookup::Miss, Lookup::Hit)
    }

    /// Expires memory entries; prunes the disk cache at most hourly.
    pub async fn sweep(&self) {
        let t = now();
        self.mem.retain(|_, (expires, _)| *expires > t);
        self.inflight.retain(|_, cell| Arc::strong_count(cell) > 1);
        let Some(dir) = self.disk.clone() else { return };
        if t - self.last_disk_sweep.load(Ordering::Relaxed) < 3600 {
            return;
        }
        self.last_disk_sweep.store(t, Ordering::Relaxed);
        if let Ok(Err(e)) = tokio::task::spawn_blocking(move || sweep_dir(&dir)).await {
            tracing::warn!(error = %e, "pruning icon cache failed");
        }
    }

    async fn fetch(&self, host: &str) -> Option<Icon> {
        let home = Url::parse(&format!("https://{host}/")).ok()?;
        let page = match self.get(home.clone(), HTML_LIMIT, true).await {
            Err(FetchError::Connect) => {
                let http = Url::parse(&format!("http://{host}/")).ok()?;
                self.get(http, HTML_LIMIT, true).await.ok()
            }
            other => other.ok(),
        };
        let mut candidates = Vec::new();
        let mut base = home;
        if let Some(page) = page {
            if page.status.is_success() && page.is_html() {
                let html = String::from_utf8_lossy(&page.body);
                candidates.extend(
                    parse_icon_links(&html)
                        .iter()
                        .filter_map(|href| page.url.join(href).ok())
                        .filter(|u| matches!(u.scheme(), "http" | "https"))
                        .take(MAX_CANDIDATES),
                );
            }
            base = page.url;
        }
        if let Ok(fallback) = base.join("/favicon.ico")
            && !candidates.contains(&fallback)
        {
            candidates.push(fallback);
        }
        for url in candidates {
            if let Ok(resp) = self.get(url, ICON_LIMIT, false).await
                && resp.status.is_success()
                && let Some(kind) = sniff(&resp.body)
            {
                return Some(Icon {
                    bytes: resp.body,
                    kind,
                });
            }
        }
        None
    }

    /// GET with manual redirects. `html` selects the Accept header and
    /// truncates the body at `limit`; otherwise a larger body is an error.
    async fn get(&self, mut url: Url, limit: usize, html: bool) -> Result<Fetched, FetchError> {
        for _ in 0..=MAX_REDIRECTS {
            let (host, port) = check_url(&url).ok_or(FetchError::Refused)?;
            let addrs = resolve_public(&host, port).await?;
            let resp = self.request(&url, &host, &addrs, limit, html).await?;
            if resp.status.is_redirection()
                && let Some(location) = &resp.location
            {
                url = url.join(location).map_err(|_| FetchError::Http)?;
                continue;
            }
            return Ok(resp);
        }
        Err(FetchError::Http)
    }

    async fn request(
        &self,
        url: &Url,
        host: &str,
        addrs: &[SocketAddr],
        limit: usize,
        html: bool,
    ) -> Result<Fetched, FetchError> {
        let mut tcp = None;
        for addr in addrs.iter().take(2) {
            if let Ok(Ok(stream)) =
                tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await
            {
                tcp = Some(stream);
                break;
            }
        }
        let tcp = tcp.ok_or(FetchError::Connect)?;
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let accept = if html {
            "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"
        } else {
            "image/png,image/x-icon,image/*;q=0.9,*/*;q=0.5"
        };
        let req = Request::get(&url[url::Position::BeforePath..url::Position::AfterQuery])
            .header(header::HOST, authority)
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::ACCEPT, accept)
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| FetchError::Http)?;
        let read = ReadOpts {
            limit,
            truncate: html,
        };
        if url.scheme() == "https" {
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| FetchError::Refused)?;
            let tls = tokio::time::timeout(CONNECT_TIMEOUT, self.tls.connect(name, tcp))
                .await
                .ok()
                .and_then(Result::ok)
                .ok_or(FetchError::Connect)?;
            send(tls, req, read, url.clone()).await
        } else {
            send(tcp, req, read, url.clone()).await
        }
    }
}

#[derive(Debug)]
enum FetchError {
    /// TCP/TLS connect failed (the homepage then falls back to http).
    Connect,
    /// Target not allowed (bad host, scheme, port or address).
    Refused,
    Http,
}

impl From<hyper::Error> for FetchError {
    fn from(_: hyper::Error) -> Self {
        Self::Http
    }
}

struct Fetched {
    url: Url,
    status: StatusCode,
    content_type: Option<String>,
    location: Option<String>,
    body: Bytes,
}

impl Fetched {
    fn is_html(&self) -> bool {
        self.content_type
            .as_deref()
            .is_none_or(|t| t.to_ascii_lowercase().contains("html"))
    }
}

#[derive(Clone, Copy)]
struct ReadOpts {
    limit: usize,
    truncate: bool,
}

/// Aborts the spawned hyper connection task when the request is done or dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn send<S>(
    io: S,
    req: Request<Empty<Bytes>>,
    read: ReadOpts,
    url: Url,
) -> Result<Fetched, FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    let _conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let text = |name: header::HeaderName| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = text(header::CONTENT_TYPE);
    let location = text(header::LOCATION);
    let body = if status.is_redirection() {
        Bytes::new()
    } else {
        read_body(resp.into_body(), read).await?
    };
    Ok(Fetched {
        url,
        status,
        content_type,
        location,
        body,
    })
}

async fn read_body(mut body: Incoming, read: ReadOpts) -> Result<Bytes, FetchError> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(data) = frame?.into_data() else {
            continue;
        };
        if buf.len() + data.len() > read.limit {
            if !read.truncate {
                return Err(FetchError::Http);
            }
            buf.extend_from_slice(&data[..read.limit - buf.len()]);
            break;
        }
        buf.extend_from_slice(&data);
    }
    Ok(buf.into())
}

/// The validated host and port of a URL we may fetch.
fn check_url(url: &Url) -> Option<(String, u16)> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let url::Host::Domain(domain) = url.host()? else {
        return None;
    };
    let host = normalize_host(domain)?;
    let port = url.port_or_known_default()?;
    matches!(port, 80 | 443).then_some((host, port))
}

/// Resolves `host`; refuses it if any address is non-public, so a name
/// that mixes public and private records can't be used to reach inside.
async fn resolve_public(host: &str, port: u16) -> Result<Vec<SocketAddr>, FetchError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FetchError::Refused)?
        .collect();
    if addrs.is_empty() || !addrs.iter().all(|a| is_public_ip(a.ip())) {
        return Err(FetchError::Refused);
    }
    Ok(addrs)
}

fn sweep_dir(dir: &FsPath) -> std::io::Result<()> {
    let mut live = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified()?;
        let age = modified.elapsed().unwrap_or_default().as_secs();
        let ttl = if entry.file_name().to_string_lossy().starts_with('.') {
            3600 // abandoned temp file
        } else if meta.len() == 0 {
            MISS_TTL
        } else {
            HIT_TTL
        };
        if age >= ttl as u64 {
            let _ = std::fs::remove_file(entry.path());
        } else {
            live.push((modified, entry.path()));
        }
    }
    if live.len() > DISK_ENTRIES {
        live.sort();
        for (_, path) in &live[..live.len() - DISK_ENTRIES] {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}

// --------------------------------------------------------------- validation

/// Suffixes that only make sense on private networks.
const LOCAL_SUFFIXES: [&str; 12] = [
    "localhost",
    "local",
    "internal",
    "lan",
    "localdomain",
    "home.arpa",
    "home",
    "corp",
    "intranet",
    "test",
    "invalid",
    "onion",
];

/// Lowercases and validates a public DNS hostname; `None` if not acceptable.
pub fn normalize_host(raw: &str) -> Option<String> {
    let host = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    if host.len() > 253 || !host.contains('.') || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let valid_label = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !host.split('.').all(valid_label) {
        return None;
    }
    // TLDs start with a letter. This also rules out numeric forms such as
    // `127.1` or `1.0x7f` that some resolvers treat as IPv4 addresses.
    let tld = host.rsplit('.').next()?;
    if !tld.starts_with(|c: char| c.is_ascii_lowercase()) {
        return None;
    }
    if LOCAL_SUFFIXES
        .iter()
        .any(|s| host == *s || host.strip_suffix(s).is_some_and(|h| h.ends_with('.')))
    {
        return None;
    }
    Some(host)
}

/// Whether `ip` is a globally routable unicast address we may connect to.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let special = a == 0 // "this network", unspecified
        || a == 10
        || a == 127
        || a >= 224 // multicast, reserved, broadcast
        || (a == 100 && (64..128).contains(&b)) // CGNAT
        || (a == 169 && b == 254) // link-local, cloud metadata
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2)) // IETF assignments, TEST-NET-1
        || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // TEST-NET-2
        || (a == 203 && b == 0 && c == 113); // TEST-NET-3
    !special
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let o = ip.octets();
    let last_v4 = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    // Forms embedding an IPv4 address are judged by that address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    if s[..6] == [0; 6] {
        // IPv4-compatible; also covers :: and ::1 (0.0.0.0/8).
        return is_public_v4(last_v4);
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(last_v4); // NAT64
    }
    if s[0] == 0x2002 {
        return is_public_v4(Ipv4Addr::new(o[2], o[3], o[4], o[5])); // 6to4
    }
    // Otherwise only global unicast (2000::/3) qualifies. This excludes ULA
    // fc00::/7, link-local fe80::/10, multicast ff00::/8, 64:ff9b:1::/48,
    // discard 100::/64 and the deprecated site-local fec0::/10.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23 (Teredo, ORCHID, ...)
        && !(s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        && !(s[0] == 0x3fff && s[1] < 0x1000) // documentation 3fff::/20
}

/// Detects a raster image by magic bytes. SVG, HTML and anything else is `None`.
pub fn sniff(b: &[u8]) -> Option<ImageKind> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ImageKind::Png)
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some(ImageKind::Gif)
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(ImageKind::Jpeg)
    } else if b.len() >= 12 && b.starts_with(b"RIFF") && &b[8..12] == b"WEBP" {
        Some(ImageKind::Webp)
    } else if b.len() >= 6 && b.starts_with(&[0, 0, 1, 0]) && (b[4] | b[5]) != 0 {
        Some(ImageKind::Ico)
    } else {
        None
    }
}

// ------------------------------------------------------------- HTML parsing

/// Icon hrefs from `<link rel=icon|shortcut icon|apple-touch-icon>` tags,
/// best first: sizes near 32–64 px, then PNG before other formats. SVG and
/// `data:` hrefs are skipped. Tolerant of malformed markup.
pub fn parse_icon_links(html: &str) -> Vec<String> {
    // ASCII lowercasing keeps byte offsets identical to `html`.
    let lower = html.to_ascii_lowercase();
    let mut found: Vec<(u32, u8, String)> = Vec::new();
    let mut pos = 0;
    while let Some(i) = lower[pos..].find("<link") {
        let start = pos + i + "<link".len();
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        pos = end;
        if !lower[start..].starts_with(|c: char| c.is_ascii_whitespace() || c == '/') {
            continue;
        }
        let attrs = parse_attrs(&html[start..end]);
        let attr = |name: &str| {
            attrs
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
                .unwrap_or_default()
        };
        let rel = attr("rel").to_ascii_lowercase();
        let apple = rel
            .split_ascii_whitespace()
            .any(|t| t == "apple-touch-icon" || t == "apple-touch-icon-precomposed");
        if !apple && !rel.split_ascii_whitespace().any(|t| t == "icon") {
            continue;
        }
        let href = attr("href").trim();
        let href_lower = href.to_ascii_lowercase();
        let path = href_lower.split(['?', '#']).next().unwrap_or_default();
        let kind = attr("type").to_ascii_lowercase();
        if href.is_empty()
            || href_lower.starts_with("data:")
            || href_lower.starts_with("javascript:")
            || kind.contains("svg")
            || path.ends_with(".svg")
        {
            continue;
        }
        let penalty = |px: u32| match px {
            32..=64 => 0,
            65.. => px - 64,
            _ => (32 - px) * 2,
        };
        let size = attr("sizes")
            .split_ascii_whitespace()
            .filter_map(|s| s.split(['x', 'X']).next()?.parse::<u32>().ok())
            .map(penalty)
            .min()
            .unwrap_or(if apple { penalty(180) } else { 30 });
        let png = kind == "image/png" || path.ends_with(".png");
        if !found.iter().any(|(_, _, h)| h == href) {
            found.push((size, u8::from(!png), href.to_owned()));
        }
    }
    // Stable sort keeps document order among equals.
    found.sort_by_key(|(size, fmt, _)| (*size, *fmt));
    found.into_iter().map(|(_, _, href)| href).collect()
}

/// `name=value` pairs inside a tag (names lowercased, values entity-decoded).
fn parse_attrs(s: &str) -> Vec<(String, String)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() || b[i] == b'/' {
            i += 1;
            continue;
        }
        let name_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'/') {
            i += 1;
        }
        let name = s[name_start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = "";
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && matches!(b[i], b'"' | b'\'') {
                let quote = b[i];
                i += 1;
                let start = i;
                while i < b.len() && b[i] != quote {
                    i += 1;
                }
                value = &s[start..i];
                i += 1;
            } else {
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = &s[start..i];
            }
        }
        if !name.is_empty() {
            out.push((name, decode_entities(value)));
        }
    }
    out
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    s.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#x2f;", "/")
        .replace("&#x2F;", "/")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_validation() {
        for (raw, want) in [
            ("github.com", "github.com"),
            ("GitHub.COM", "github.com"),
            ("www.example.co.uk", "www.example.co.uk"),
            ("example.com.", "example.com"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("a-b.c0.io", "a-b.c0.io"),
        ] {
            assert_eq!(normalize_host(raw).as_deref(), Some(want), "{raw}");
        }
        let long = format!("{}.com", vec!["a".repeat(63); 4].join("."));
        for bad in [
            "",
            "com",
            "localhost",
            "foo.localhost",
            "printer.local",
            "db.internal",
            "nas.lan",
            "router.home.arpa",
            "127.0.0.1",
            "127.1",
            "1.0x7f",
            "0x7f000001",
            "[::1]",
            "::1",
            "10.0.0.1.",
            "exa mple.com",
            "exa_mple.com",
            "example..com",
            ".example.com",
            "-a.example.com",
            "a-.example.com",
            "example.com:8080",
            "user@example.com",
            "example.com/x",
            "bücher.de",
            "example.123",
            &long,
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert_eq!(normalize_host(bad), None, "{bad:?}");
        }
        // Suffix match is by label, not by substring.
        assert!(normalize_host("mylan.com").is_some());
        assert!(normalize_host("lan.example.com").is_some());
    }

    #[test]
    fn ip_classification() {
        let public = [
            "8.8.8.8",
            "1.1.1.1",
            "140.82.112.3",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "2a00:1450:4001:80b::200e",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ];
        for ip in public {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} should be public");
        }
        let private = [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.169.254",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "198.18.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "fd00::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "2002:c0a8:101::1",
            "2001:db8::1",
            "2001::1",
            "3fff::1",
            "100::1",
        ];
        for ip in private {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
        assert!(is_public_ip("2002:808:808::1".parse().unwrap()));
    }

    #[test]
    fn magic_bytes() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        assert_eq!(sniff(png), Some(ImageKind::Png));
        assert_eq!(sniff(b"GIF89a\x01\0\x01\0"), Some(ImageKind::Gif));
        assert_eq!(sniff(b"GIF87a\x01\0\x01\0"), Some(ImageKind::Gif));
        assert_eq!(
            sniff(&[0xff, 0xd8, 0xff, 0xe0, 0, 0x10]),
            Some(ImageKind::Jpeg)
        );
        assert_eq!(sniff(b"RIFF\x24\0\0\0WEBPVP8 "), Some(ImageKind::Webp));
        assert_eq!(sniff(&[0, 0, 1, 0, 1, 0, 16, 16]), Some(ImageKind::Ico));
        for bad in [
            &b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"[..],
            b"<?xml version=\"1.0\"?><svg/>",
            b"<!DOCTYPE html><html></html>",
            b"<html><script>alert(1)</script>",
            b"\xef\xbb\xbf<svg/>",
            b"RIFF\x24\0\0\0WAVEfmt ",
            &[0, 0, 1, 0, 0, 0],
            &[0, 0, 2, 0, 1, 0],
            b"",
            b"\x89PN",
        ] {
            assert_eq!(sniff(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        assert_eq!(ImageKind::Ico.content_type(), "image/x-icon");
    }

    #[test]
    fn icon_link_parser() {
        let html = r##"<!doctype html><html><head>
            <LINK REL="shortcut icon" href="/favicon.ico">
            <link rel=icon type="image/png" sizes="16x16" href="/f16.png">
            <link rel="icon" sizes="32x32" href='/f32.png?v=1&amp;x=2'>
            <link rel="apple-touch-icon" href="/apple.png">
            <link rel="icon" type="image/svg+xml" href="/logo.svg">
            <link rel="mask-icon" href="/mask.svg" color="#000">
            <link rel="stylesheet" href="/site.css">
            <link rel="icon" href="data:image/png;base64,AAAA">
            <link rel="icon" sizes="any" href="/any.svg?x">
            <linker rel="icon" href="/nope.png">
            <link rel="icon" sizes="48x48" href="/f48.ico"/>
            <link rel="icon" href="/f32.png?v=1&x=2">
        </head>"##;
        assert_eq!(
            parse_icon_links(html),
            vec![
                "/f32.png?v=1&x=2",
                "/f48.ico",
                "/favicon.ico",
                "/f16.png",
                "/apple.png",
            ]
        );
        assert!(parse_icon_links("").is_empty());
        assert!(parse_icon_links("<link").is_empty());
        assert!(parse_icon_links("<link rel=\"icon\" href=\"/x.png").len() == 1);
        assert_eq!(
            parse_icon_links("<link rel=icon href=https://cdn.example.com/i.png>"),
            vec!["https://cdn.example.com/i.png"]
        );
        // Non-ASCII content around tags must not break slicing.
        assert_eq!(
            parse_icon_links("<title>ünï</title><link rel='icon' href='/é.png'>"),
            vec!["/é.png"]
        );
    }

    #[test]
    fn url_checks() {
        let ok = |u: &str| check_url(&Url::parse(u).unwrap());
        assert_eq!(ok("https://github.com/x"), Some(("github.com".into(), 443)));
        assert_eq!(ok("http://github.com:80/"), Some(("github.com".into(), 80)));
        assert_eq!(
            ok("https://github.com:80/"),
            Some(("github.com".into(), 80))
        );
        for bad in [
            "https://github.com:8443/",
            "ftp://github.com/",
            "file:///etc/passwd",
            "https://127.0.0.1/",
            "http://0x7f.1/",
            "http://[::1]/",
            "https://user:pw@github.com/",
            "https://localhost/",
            "https://metadata.google.internal/",
        ] {
            assert_eq!(ok(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn local_names_are_refused_before_connecting() {
        assert!(matches!(
            resolve_public("localhost", 443).await,
            Err(FetchError::Refused)
        ));
    }

    #[test]
    fn default_cache_dir_follows_sqlite_file() {
        use crate::config::sqlite_dir;
        assert_eq!(
            sqlite_dir("sqlite:///data/passauth.db?mode=rwc").as_deref(),
            Some("/data")
        );
        assert_eq!(sqlite_dir("sqlite://passauth.db").as_deref(), Some("."));
        assert_eq!(sqlite_dir("sqlite:./db/p.db").as_deref(), Some("./db"));
        assert_eq!(sqlite_dir("sqlite::memory:"), None);
        assert_eq!(sqlite_dir("postgres://u:p@db/passauth"), None);
    }
}
