//! Host names the way browsers read them (WHATWG URL host parser).

use url::Host;

/// A host after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedHost {
    /// ASCII (UTS #46 nontransitional, so "straße.de" stays "xn--strae-oqa.de"), lowercase,
    /// without the one trailing dot of a fully qualified name; may still hold empty labels
    /// ("a..b"), which the URL parser accepts.
    Domain(String),
    /// An IP address in its canonical form: "192.168.1.10", "[2001:db8::1]".
    Ip(String),
}

/// Parse a host as the URL parser does for http(s) addresses: percent-decoding, IDNA to ASCII,
/// lowercase, IPv4 in any of its forms ("0x7f.1" is 127.0.0.1), IPv6 in brackets.
pub(crate) fn parse_host(host: &str) -> Option<ParsedHost> {
    match Host::parse(host).ok()? {
        Host::Domain(domain) => {
            let domain = match domain.strip_suffix('.') {
                Some(stripped) => stripped.to_owned(),
                None => domain,
            };
            (!domain.is_empty()).then_some(ParsedHost::Domain(domain))
        }
        // url's own serialisation (WHATWG), not std's: they differ for IPv4-mapped IPv6.
        ip => Some(ParsedHost::Ip(ip.to_string())),
    }
}

/// The canonical form of a host name: what a browser's address parser makes of it (IDNA to
/// ASCII, lowercase, IPv4 and IPv6 normalised, IPv6 in brackets), without a trailing dot.
/// `None` when it isn't a valid host ("a b.com", "::1" without brackets, "").
pub fn normalize_host(host: &str) -> Option<String> {
    parse_host(host).map(|h| match h {
        ParsedHost::Domain(d) | ParsedHost::Ip(d) => d,
    })
}

/// The host as the browser sees it, or else the input in lower case without a trailing dot.
pub(crate) fn host_or_lowercase(host: &str) -> String {
    normalize_host(host).unwrap_or_else(|| {
        let lower = host.to_lowercase();
        match lower.strip_suffix('.') {
            Some(stripped) => stripped.to_owned(),
            None => lower,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_like_the_url_parser() {
        let cases = [
            ("www.example.com", Some("www.example.com")),
            ("EXAMPLE.COM.", Some("example.com")),
            ("BÜCHER.de", Some("xn--bcher-kva.de")),
            ("straße.de", Some("xn--strae-oqa.de")),
            ("xn--bcher-kva.de", Some("xn--bcher-kva.de")),
            ("ａｂｃ.com", Some("abc.com")),
            ("exa%41mple.com", Some("exaample.com")),
            ("0x7f.1", Some("127.0.0.1")),
            ("1.2.3", Some("1.2.0.3")),
            ("192.168.1.10", Some("192.168.1.10")),
            ("[::1]", Some("[::1]")),
            ("[2001:DB8:0:0:0:0:0:1]", Some("[2001:db8::1]")),
            ("[::ffff:1.2.3.4]", Some("[::ffff:102:304]")),
            ("a..b", Some("a..b")),
            ("example.com..", Some("example.com.")),
            ("::1", None),
            ("a b.com", None),
            ("192.168.1.256", None),
            ("xn--abc", None),
            ("", None),
            (".", None),
        ];
        for (input, want) in cases {
            assert_eq!(normalize_host(input).as_deref(), want, "{input:?}");
        }
    }

    #[test]
    fn falls_back_to_lower_case() {
        assert_eq!(host_or_lowercase("::1"), "::1");
        assert_eq!(host_or_lowercase("A B.COM."), "a b.com");
        assert_eq!(host_or_lowercase("Login.Example.COM."), "login.example.com");
    }
}
