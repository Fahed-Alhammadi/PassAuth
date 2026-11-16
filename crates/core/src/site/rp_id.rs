//! WebAuthn relying party IDs: which RP ID a page may use (PassAuth as the authenticator).

use url::{Host, Url};

use super::{is_js_space, psl, utf16_len};

/// Why a request's origin or RP ID is refused. Every case is a WebAuthn `SecurityError`;
/// [`RpIdError::message`] is the DOMException message pages see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpIdError {
    /// Not a serialised origin ("https://example.com", no path, lower case, no default port).
    InvalidOrigin,
    /// Neither https nor http on localhost / *.localhost.
    InsecureOrigin,
    /// The origin's host is an IP address.
    OriginNotDomain,
    /// The requested RP ID is not a valid domain (empty, too long, IP address, port, wildcard,
    /// white space, trailing dot …).
    InvalidRpId,
    /// The RP ID is another site, or a public suffix ("com", "co.uk", "myfritz.net").
    NotRegistrableSuffix,
}

impl RpIdError {
    /// Short code: "invalid_origin", "insecure_origin", "origin_not_domain", "invalid_rp_id",
    /// "not_registrable_suffix".
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidOrigin => "invalid_origin",
            Self::InsecureOrigin => "insecure_origin",
            Self::OriginNotDomain => "origin_not_domain",
            Self::InvalidRpId => "invalid_rp_id",
            Self::NotRegistrableSuffix => "not_registrable_suffix",
        }
    }

    /// The message of the `SecurityError` the page gets.
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidOrigin => "Invalid origin.",
            Self::InsecureOrigin => "WebAuthn requires a secure (https) origin.",
            Self::OriginNotDomain => "The origin's host is not a valid domain.",
            Self::InvalidRpId => "Invalid RP ID.",
            Self::NotRegistrableSuffix => {
                "The RP ID is not a registrable domain suffix of the origin."
            }
        }
    }
}

impl std::fmt::Display for RpIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RpIdError {}

/// The host of a request's origin, if PassAuth may answer WebAuthn requests from it.
fn origin_host(origin: &str) -> Result<String, RpIdError> {
    let url = Url::parse(origin).map_err(|_| RpIdError::InvalidOrigin)?;
    if url.origin().ascii_serialization() != origin {
        return Err(RpIdError::InvalidOrigin);
    }
    let host = url.host_str().unwrap_or("");
    let localhost = host == "localhost" || host.ends_with(".localhost");
    if !(url.scheme() == "https" || (url.scheme() == "http" && localhost)) {
        return Err(RpIdError::InsecureOrigin);
    }
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return Err(RpIdError::OriginNotDomain);
    }
    Ok(host.to_owned())
}

/// A requested RP ID in canonical form (lower case, punycode), or `None` if it isn't a domain.
fn canonical_domain(s: &str) -> Option<String> {
    if s.is_empty()
        || utf16_len(s) > 253
        || s.chars()
            .any(|c| is_js_space(c) || "/\\?#@:[]%*".contains(c))
    {
        return None;
    }
    let url = Url::parse(&format!("https://{s}/")).ok()?;
    let Some(Host::Domain(host)) = url.host() else {
        return None;
    };
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return None;
    }
    Some(host.to_owned())
}

/// The RP ID to use for a request from `origin`: `requested` if it equals the origin's host or
/// is a registrable-domain suffix of it (a parent domain that is not a public suffix by the full
/// list; "localhost" counts as a domain), else an error. No RP ID requested → the origin's host.
/// Only https origins (plus http://localhost and http://*.localhost) with a domain host qualify.
pub fn effective_rp_id(requested: Option<&str>, origin: &str) -> Result<String, RpIdError> {
    let host = origin_host(origin)?;
    let Some(requested) = requested else {
        return Ok(host);
    };
    let rp_id = canonical_domain(requested).ok_or(RpIdError::InvalidRpId)?;
    if rp_id == host {
        return Ok(rp_id);
    }
    let public = rp_id != "localhost" && psl::is_public_suffix(&rp_id);
    if !host.ends_with(&format!(".{rp_id}")) || public {
        return Err(RpIdError::NotRegistrableSuffix);
    }
    Ok(rp_id)
}

#[cfg(test)]
mod tests {
    use super::RpIdError::*;
    use super::*;

    #[test]
    fn rp_ids() {
        let ok = [
            ("https://login.example.com", None, "login.example.com"),
            (
                "https://login.example.com",
                Some("example.com"),
                "example.com",
            ),
            (
                "https://login.example.com:8443",
                Some("EXAMPLE.com"),
                "example.com",
            ),
            (
                "https://a.example.co.uk",
                Some("example.co.uk"),
                "example.co.uk",
            ),
            (
                "https://a.nas.myfritz.net",
                Some("nas.myfritz.net"),
                "nas.myfritz.net",
            ),
            ("http://localhost:8080", None, "localhost"),
            ("http://app.localhost", Some("localhost"), "localhost"),
            (
                "https://xn--bcher-kva.de",
                Some("bücher.de"),
                "xn--bcher-kva.de",
            ),
            (
                "https://xn--strae-oqa.de",
                Some("straße.de"),
                "xn--strae-oqa.de",
            ),
            ("https://a.b.internal", Some("b.internal"), "b.internal"),
        ];
        for (origin, requested, want) in ok {
            assert_eq!(
                effective_rp_id(requested, origin).as_deref(),
                Ok(want),
                "{origin} {requested:?}"
            );
        }
        let refused = [
            ("https://login.example.com/", None, InvalidOrigin),
            ("https://Login.example.com", None, InvalidOrigin),
            ("http://example.com", None, InsecureOrigin),
            ("http://192.168.1.10", None, InsecureOrigin),
            ("https://192.168.1.10", None, OriginNotDomain),
            ("https://[::1]", None, OriginNotDomain),
            ("https://login.example.com", Some(""), InvalidRpId),
            (
                "https://login.example.com",
                Some("example.com."),
                InvalidRpId,
            ),
            (
                "https://login.example.com",
                Some("exa mple.com"),
                InvalidRpId,
            ),
            (
                "https://login.example.com",
                Some("example.com:443"),
                InvalidRpId,
            ),
            (
                "https://login.example.com",
                Some("*.example.com"),
                InvalidRpId,
            ),
            ("https://login.example.com", Some("1.2.3.4"), InvalidRpId),
            ("https://login.example.com", Some("0x7f.1"), InvalidRpId),
            (
                "https://login.example.com",
                Some("other.com"),
                NotRegistrableSuffix,
            ),
            (
                "https://evil-example.com",
                Some("example.com"),
                NotRegistrableSuffix,
            ),
            (
                "https://login.example.com",
                Some("com"),
                NotRegistrableSuffix,
            ),
            (
                "https://a.example.co.uk",
                Some("co.uk"),
                NotRegistrableSuffix,
            ),
            (
                "https://home.duckdns.org",
                Some("duckdns.org"),
                NotRegistrableSuffix,
            ),
            // Review finding S3: private suffixes and wildcard rules from the full list.
            (
                "https://nas.myfritz.net",
                Some("myfritz.net"),
                NotRegistrableSuffix,
            ),
            ("https://a.myds.me", Some("myds.me"), NotRegistrableSuffix),
            ("https://x.foo.ck", Some("foo.ck"), NotRegistrableSuffix),
            (
                "https://ec2-1-2-3-4.us-east-2.compute.amazonaws.com",
                Some("us-east-2.compute.amazonaws.com"),
                NotRegistrableSuffix,
            ),
        ];
        for (origin, requested, want) in refused {
            assert_eq!(
                effective_rp_id(requested, origin),
                Err(want),
                "{origin} {requested:?}"
            );
        }
        assert_eq!(NotRegistrableSuffix.code(), "not_registrable_suffix");
        assert_eq!(InvalidRpId.to_string(), "Invalid RP ID.");
    }
}
