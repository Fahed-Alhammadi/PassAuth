//! Public suffixes and registrable domains ("sites") from the full Public Suffix List.
//!
//! The list is the upstream `public_suffix_list.dat` (github.com/publicsuffix/list, MPL-2.0),
//! kept byte for byte next to this file; `build.rs` embeds its rules without the comments. Both
//! sections count (ICANN and private), so a name under a dynamic-DNS or hosting suffix is a site
//! of its own: x.myfritz.net, x.myds.me, x.dedyn.io, x.cloudapp.net, x.eu-west-1.compute.amazonaws.com.
//! Wildcard (`*.ck`) and exception (`!www.ck`) rules follow the list's algorithm, and a name under
//! a top-level domain the list doesn't know (`a.b.internal`) falls under its implicit `*` rule.
//!
//! Updating (any time; take a commit at least two weeks old, like the dependency rule):
//! 1. `curl -fsSL -o crates/core/src/site/public_suffix_list.dat
//!    https://raw.githubusercontent.com/publicsuffix/list/<commit>/public_suffix_list.dat`
//! 2. Set [`PUBLIC_SUFFIX_LIST_COMMIT`], [`PUBLIC_SUFFIX_LIST_DATE`] and `LIST_SHA256` below
//!    (`shasum -a 256 crates/core/src/site/public_suffix_list.dat`).
//! 3. `cargo test -p passauth-core`, and regenerate the golden vectors.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use super::host::{ParsedHost, parse_host};

/// Upstream commit of the embedded list (github.com/publicsuffix/list).
pub const PUBLIC_SUFFIX_LIST_COMMIT: &str = "73f8cc701c084fe07d888ec552b2f0b53281a674";
/// Date of that commit.
pub const PUBLIC_SUFFIX_LIST_DATE: &str = "2026-10-31";
/// SHA-256 of `public_suffix_list.dat`, checked by a test so the file can't change unnoticed.
#[cfg_attr(not(test), allow(dead_code))]
const LIST_SHA256: &str = "2f43816a521cab39333ba60714665fe045b8089159816791371e77c5ebb3d4e8";

/// The list's rules, one per line, without comments (see build.rs).
const RULES: &str = include_str!(concat!(env!("OUT_DIR"), "/public_suffix_rules.txt"));

/// "Date commit" of the embedded list, e.g. for an About page or a bug report.
pub fn public_suffix_list_version() -> String {
    format!(
        "{PUBLIC_SUFFIX_LIST_DATE} {}",
        &PUBLIC_SUFFIX_LIST_COMMIT[..12]
    )
}

struct Rules {
    /// `example.com`: the name is a public suffix.
    exact: HashSet<Cow<'static, str>>,
    /// `*.ck` stored as `ck`: every name one label below it is a public suffix.
    wildcard: HashSet<Cow<'static, str>>,
    /// `!www.ck` stored as `www.ck`: not a public suffix after all (its parent is).
    exception: HashSet<Cow<'static, str>>,
}

fn rules() -> &'static Rules {
    static PARSED: OnceLock<Rules> = OnceLock::new();
    PARSED.get_or_init(|| parse_rules(RULES))
}

fn parse_rules(text: &'static str) -> Rules {
    let mut rules = Rules {
        exact: HashSet::with_capacity(10_500),
        wildcard: HashSet::with_capacity(400),
        exception: HashSet::with_capacity(16),
    };
    for line in text.lines() {
        let (set, name) = if let Some(name) = line.strip_prefix('!') {
            (&mut rules.exception, name)
        } else if let Some(name) = line.strip_prefix("*.") {
            (&mut rules.wildcard, name)
        } else {
            (&mut rules.exact, line)
        };
        // Internationalised rules are written in Unicode ("公司.cn"); hosts are compared in ASCII.
        let name: Cow<'static, str> = if name.is_ascii() {
            Cow::Borrowed(name)
        } else {
            match idna::domain_to_ascii(name) {
                Ok(ascii) => Cow::Owned(ascii),
                Err(_) => continue,
            }
        };
        set.insert(name);
    }
    rules
}

/// Byte offsets at which each label of `domain` starts.
fn label_starts(domain: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(domain.match_indices('.').map(|(i, _)| i + 1))
        .collect()
}

/// The label index at which the public suffix of `domain` starts (lowercase ASCII, no empty
/// labels), by the list's algorithm: an exception rule prevails and stands for its parent;
/// otherwise the matching rule with the most labels; otherwise the implicit `*` (the last label).
fn suffix_start(domain: &str, starts: &[usize]) -> usize {
    let r = rules();
    let labels = starts.len();
    if let Some(i) = (0..labels).find(|&i| r.exception.contains(&domain[starts[i]..])) {
        return i + 1;
    }
    (0..labels)
        .find(|&i| {
            r.exact.contains(&domain[starts[i]..])
                || (i + 1 < labels && r.wildcard.contains(&domain[starts[i + 1]..]))
        })
        .unwrap_or(labels - 1)
}

/// A domain from `host`, ready for the list: `None` for IP addresses, invalid hosts and names
/// with an empty label ("example.com..", ".example.com").
fn domain_of(host: &str) -> Option<String> {
    match parse_host(host)? {
        ParsedHost::Domain(d) if !d.split('.').any(str::is_empty) => Some(d),
        _ => None,
    }
}

/// The public suffix of `host` in ASCII: "co.uk" for "login.example.co.uk", "com" for
/// "example.com", "myfritz.net" for "nas.myfritz.net", "c" for "a.b.c" (implicit `*` rule).
/// Empty for IP addresses and invalid hosts.
pub fn public_suffix(host: &str) -> String {
    domain_of(host)
        .map(|d| {
            let starts = label_starts(&d);
            d[starts[suffix_start(&d, &starts)]..].to_owned()
        })
        .unwrap_or_default()
}

/// The registrable domain of `host` (its public suffix and one more label), in ASCII:
/// "example.co.uk" for "login.example.co.uk", "nas.myfritz.net" for "a.nas.myfritz.net".
/// `None` for a public suffix itself ("co.uk", "myfritz.net", "localhost"), IP addresses and
/// invalid hosts.
pub fn registrable_domain(host: &str) -> Option<String> {
    let d = domain_of(host)?;
    registrable_of(&d).map(str::to_owned)
}

fn registrable_of(domain: &str) -> Option<&str> {
    let starts = label_starts(domain);
    let suffix = suffix_start(domain, &starts);
    (suffix > 0).then(|| &domain[starts[suffix - 1]..])
}

/// Is `host` itself a public suffix ("com", "co.uk", "github.io", "c.kobe.jp", an unknown
/// single label such as "localhost")? False for IP addresses and invalid hosts.
pub fn is_public_suffix(host: &str) -> bool {
    domain_of(host).is_some_and(|d| registrable_of(&d).is_none())
}

/// The site a host belongs to, as "domain" matching compares it: its registrable domain;
/// a public suffix, IP address or a name with an empty label stands for itself (canonical
/// form, no trailing dot); an invalid host is returned in lower case without a trailing dot.
pub fn base_domain(host: &str) -> String {
    match parse_host(host) {
        Some(ParsedHost::Domain(d)) => {
            if d.split('.').any(str::is_empty) {
                return d;
            }
            match registrable_of(&d) {
                Some(site) => site.to_owned(),
                None => d,
            }
        }
        Some(ParsedHost::Ip(ip)) => ip,
        None => super::host::host_or_lowercase(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_list_is_the_recorded_upstream_file() {
        use sha2::{Digest, Sha256};
        let file = include_bytes!("public_suffix_list.dat");
        let digest: String = Sha256::digest(file)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest, LIST_SHA256,
            "public_suffix_list.dat changed: update LIST_SHA256, the commit and the date"
        );
        let text = std::str::from_utf8(file).unwrap();
        assert!(text.contains("===BEGIN PRIVATE DOMAINS==="));
    }

    #[test]
    fn rules_are_complete_and_well_formed() {
        let r = rules();
        assert!(r.exact.len() > 9_000, "{} rules", r.exact.len());
        assert!(r.wildcard.len() > 100);
        assert!(r.exception.contains("www.ck"));
        // The lookup handles wildcards only as the leftmost label (as in the whole list).
        for name in r.exact.iter().chain(&r.wildcard).chain(&r.exception) {
            assert!(!name.contains('*') && !name.contains('!'), "{name}");
            assert!(name.is_ascii() && *name == name.to_lowercase(), "{name}");
            assert!(!name.split('.').any(str::is_empty), "{name}");
        }
        // Internationalised rules are kept in ASCII.
        assert!(r.exact.contains("xn--55qx5d.cn"));
        assert_eq!(
            RULES.lines().count(),
            r.exact.len() + r.wildcard.len() + r.exception.len()
        );
    }

    /// The list's own test cases (tests/test_psl.txt, public domain): registrable domain or null.
    #[test]
    fn upstream_test_cases() {
        let cases: &[(&str, Option<&str>)] = &[
            ("COM", None),
            ("example.COM", Some("example.com")),
            ("WwW.example.COM", Some("example.com")),
            (".com", None),
            (".example", None),
            (".example.com", None),
            (".example.example", None),
            ("example", None),
            ("example.example", Some("example.example")),
            ("b.example.example", Some("example.example")),
            ("a.b.example.example", Some("example.example")),
            ("biz", None),
            ("domain.biz", Some("domain.biz")),
            ("b.domain.biz", Some("domain.biz")),
            ("a.b.domain.biz", Some("domain.biz")),
            ("com", None),
            ("example.com", Some("example.com")),
            ("b.example.com", Some("example.com")),
            ("a.b.example.com", Some("example.com")),
            ("uk.com", None),
            ("example.uk.com", Some("example.uk.com")),
            ("b.example.uk.com", Some("example.uk.com")),
            ("a.b.example.uk.com", Some("example.uk.com")),
            ("test.ac", Some("test.ac")),
            ("mm", None),
            ("c.mm", None),
            ("b.c.mm", Some("b.c.mm")),
            ("a.b.c.mm", Some("b.c.mm")),
            ("jp", None),
            ("test.jp", Some("test.jp")),
            ("www.test.jp", Some("test.jp")),
            ("ac.jp", None),
            ("test.ac.jp", Some("test.ac.jp")),
            ("www.test.ac.jp", Some("test.ac.jp")),
            ("kyoto.jp", None),
            ("test.kyoto.jp", Some("test.kyoto.jp")),
            ("ide.kyoto.jp", None),
            ("b.ide.kyoto.jp", Some("b.ide.kyoto.jp")),
            ("a.b.ide.kyoto.jp", Some("b.ide.kyoto.jp")),
            ("c.kobe.jp", None),
            ("b.c.kobe.jp", Some("b.c.kobe.jp")),
            ("a.b.c.kobe.jp", Some("b.c.kobe.jp")),
            ("city.kobe.jp", Some("city.kobe.jp")),
            ("www.city.kobe.jp", Some("city.kobe.jp")),
            ("ck", None),
            ("test.ck", None),
            ("b.test.ck", Some("b.test.ck")),
            ("a.b.test.ck", Some("b.test.ck")),
            ("www.ck", Some("www.ck")),
            ("www.www.ck", Some("www.ck")),
            ("us", None),
            ("test.us", Some("test.us")),
            ("www.test.us", Some("test.us")),
            ("ak.us", None),
            ("test.ak.us", Some("test.ak.us")),
            ("www.test.ak.us", Some("test.ak.us")),
            ("k12.ak.us", None),
            ("test.k12.ak.us", Some("test.k12.ak.us")),
            ("www.test.k12.ak.us", Some("test.k12.ak.us")),
            ("食狮.com.cn", Some("食狮.com.cn")),
            ("食狮.公司.cn", Some("食狮.公司.cn")),
            ("www.食狮.公司.cn", Some("食狮.公司.cn")),
            ("shishi.公司.cn", Some("shishi.公司.cn")),
            ("公司.cn", None),
            ("食狮.中国", Some("食狮.中国")),
            ("www.食狮.中国", Some("食狮.中国")),
            ("shishi.中国", Some("shishi.中国")),
            ("中国", None),
            ("xn--85x722f.com.cn", Some("xn--85x722f.com.cn")),
            (
                "xn--85x722f.xn--55qx5d.cn",
                Some("xn--85x722f.xn--55qx5d.cn"),
            ),
            (
                "www.xn--85x722f.xn--55qx5d.cn",
                Some("xn--85x722f.xn--55qx5d.cn"),
            ),
            ("shishi.xn--55qx5d.cn", Some("shishi.xn--55qx5d.cn")),
            ("xn--55qx5d.cn", None),
            ("xn--85x722f.xn--fiqs8s", Some("xn--85x722f.xn--fiqs8s")),
            ("www.xn--85x722f.xn--fiqs8s", Some("xn--85x722f.xn--fiqs8s")),
            ("shishi.xn--fiqs8s", Some("shishi.xn--fiqs8s")),
            ("xn--fiqs8s", None),
        ];
        for &(host, want) in cases {
            // Expected values are compared in ASCII, as this module answers.
            let want = want.map(|w| crate::site::normalize_host(w).unwrap());
            assert_eq!(registrable_domain(host), want, "{host}");
        }
    }

    /// Review finding S3: names under dynamic-DNS and hosting suffixes are separate sites.
    #[test]
    fn private_suffixes_separate_sites() {
        let separate = [
            ("nas.myfritz.net", "attacker.myfritz.net"),
            ("home.myds.me", "evil.myds.me"),
            ("mine.dedyn.io", "theirs.dedyn.io"),
            ("app.cloudapp.net", "other.cloudapp.net"),
            (
                "ec2-1-2-3-4.eu-west-1.compute.amazonaws.com",
                "ec2-5-6-7-8.eu-west-1.compute.amazonaws.com",
            ),
            ("svc.up.railway.app", "other.up.railway.app"),
            ("pvt.k12.ma.us", "other.k12.ma.us"),
        ];
        for (mine, theirs) in separate {
            assert_ne!(base_domain(mine), base_domain(theirs), "{mine} / {theirs}");
        }
        assert_eq!(base_domain("a.nas.myfritz.net"), "nas.myfritz.net");
        assert_eq!(public_suffix("nas.myfritz.net"), "myfritz.net");
        assert_eq!(
            public_suffix("x.eu-west-1.compute.amazonaws.com"),
            "eu-west-1.compute.amazonaws.com"
        );
        assert!(is_public_suffix("myfritz.net"));
        assert!(is_public_suffix("eu-west-1.compute.amazonaws.com"));
        assert!(!is_public_suffix("nas.myfritz.net"));
    }

    #[test]
    fn base_domain_cases() {
        let cases = [
            ("www.example.com", "example.com"),
            ("EXAMPLE.COM.", "example.com"),
            ("a.b.c", "b.c"),
            ("login.example.co.uk", "example.co.uk"),
            ("co.uk", "co.uk"),
            ("up.railway.app", "up.railway.app"),
            ("localhost", "localhost"),
            ("app.localhost", "app.localhost"),
            ("192.168.1.10", "192.168.1.10"),
            ("[::1]", "[::1]"),
            ("::1", "::1"),
            ("shop.xn--bcher-kva.de", "xn--bcher-kva.de"),
            ("shop.BÜCHER.de", "xn--bcher-kva.de"),
            ("example.com..", "example.com."),
            ("", ""),
        ];
        for (host, want) in cases {
            assert_eq!(base_domain(host), want, "{host}");
        }
        assert_eq!(public_suffix("192.168.1.10"), "");
        assert_eq!(public_suffix("example.com.."), "");
        assert_eq!(public_suffix("a.b.c"), "c");
        assert_eq!(public_suffix("localhost"), "localhost");
        assert!(!is_public_suffix("192.168.1.10"));
        assert!(public_suffix_list_version().starts_with(PUBLIC_SUFFIX_LIST_DATE));
    }
}
