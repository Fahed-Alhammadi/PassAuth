//! Does a page match a saved website? Every match type, the https→http downgrade rule and
//! regular expressions on one engine.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use regex_lite::{Regex, RegexBuilder};
use url::Url;

use super::psl::base_domain;
use super::utf16_len;
use crate::item::UrlMatch;

/// Longest regular expression PassAuth evaluates, in UTF-16 code units (JavaScript's `length`).
pub const MAX_REGEX_LENGTH: usize = 300;
/// Longest part of a page address a pattern is tested against (origin and path); a page with
/// a longer one matches no pattern.
pub const MAX_REGEX_INPUT: usize = 2048;
/// Largest compiled pattern (bytes of the engine's program). The engine runs in time linear
/// in pattern size × input length, so this and [`MAX_REGEX_INPUT`] bound every match.
const REGEX_SIZE_LIMIT: usize = 64 * 1024;
/// Compiled patterns kept (the badge matches on every tab switch).
const REGEX_CACHE: usize = 200;

/// Parse a saved address like the clients always have:
/// `new URL(s.includes("://") ? s : "https://" + s)` (WHATWG URL parsing, so hosts are
/// IDNA-mapped, default ports and dot segments dropped).
pub(crate) fn parse(url: &str) -> Option<Url> {
    if url.contains("://") {
        Url::parse(url).ok()
    } else {
        Url::parse(&format!("https://{url}")).ok()
    }
}

/// Parse a page address: only an absolute http(s) URL is a page. No default scheme here
/// (review L4: with one, "data:,@bank.com/" read as https://bank.com/).
fn parse_page(page: &str) -> Option<Url> {
    Url::parse(page).ok().filter(is_web)
}

pub(crate) fn is_web(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

/// A saved entry that is an absolute address written the way it serializes (one trailing "/"
/// aside): an http(s) address, like every address saved from a page, or an app's
/// (`androidapp://…`). Never meant as a pattern.
fn is_plain_address(s: &str) -> bool {
    Url::parse(s).is_ok_and(|url| {
        (is_web(&url) || s.contains("://")) && one_slash_less(url.as_str()) == one_slash_less(s)
    })
}

fn one_slash_less(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

/// JavaScript's `URL.host`: the host name and the port when it isn't the scheme's default.
fn host_and_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// A match type as items store it ("default", "domain", "host", "starts_with", "exact",
/// "regex", "never"); `None` for anything else.
pub fn parse_url_match(s: &str) -> Option<UrlMatch> {
    Some(match s {
        "default" => UrlMatch::Default,
        "domain" => UrlMatch::Domain,
        "host" => UrlMatch::Host,
        "starts_with" => UrlMatch::StartsWith,
        "exact" => UrlMatch::Exact,
        "regex" => UrlMatch::Regex,
        "never" => UrlMatch::Never,
        _ => return None,
    })
}

/// A page address, parsed once to be matched against many saved websites.
#[derive(Debug, Clone)]
pub struct Page {
    url: Url,
    /// Its base domain, for "domain" matching.
    site: String,
}

impl Page {
    /// `None` unless it is an absolute http(s) address (`https://…` or `http://…`, the
    /// scheme included): nothing matches any other page, nor a page string without a scheme.
    pub fn parse(page: &str) -> Option<Self> {
        let url = parse_page(page)?;
        let site = base_domain(url.host_str().unwrap_or(""));
        Some(Self { url, site })
    }

    /// Does the saved website `url` with `match_type` match this page? `default_match` (the
    /// user's setting) resolves "default"; "default" there means "domain". `allow_regex`: only
    /// the user's own logins may use regular expressions; a pattern in a vault somebody shared
    /// was written by somebody else and runs on every page, so it never matches (also when
    /// "default" resolves to "regex").
    ///
    /// - domain: same registrable domain (full Public Suffix List; ports and scheme ignored).
    /// - host: same host name and port.
    /// - starts_with / exact: the normalised address (`href`) starts with / equals the saved one.
    /// - regex: case-insensitive, ASCII, searched (not anchored) in the page's origin and path
    ///   (never the query or fragment). The path is whatever the page's owner chooses, so only
    ///   a pattern that pins the origin is safe: `bank\.com` also matches
    ///   `https://evil.example/bank.com`, `^https://bank\.com/` doesn't ([`regex_warning`]).
    ///   A page whose origin and path are longer than [`MAX_REGEX_INPUT`] bytes matches no
    ///   pattern.
    /// - never: nothing.
    ///
    /// "default" resolved to "regex" (the user's setting) treats an entry that is a plain
    /// absolute http(s) address, written as it serializes (one trailing "/" aside), as
    /// "domain": a saved page address is never a pattern, nor is an app's address (which
    /// matches no page). Other entries are patterns ([`resolve_match`]).
    ///
    /// Saved addresses without a scheme are https; one with any scheme other than http(s)
    /// (`androidapp://…`) is not a website and matches no page.
    pub fn matches(
        &self,
        url: &str,
        match_type: UrlMatch,
        default_match: UrlMatch,
        allow_regex: bool,
    ) -> bool {
        let resolved = resolve_match(url, match_type, default_match);
        match resolved {
            UrlMatch::Never => false,
            UrlMatch::Regex => allow_regex && regex_matches(url, &self.url),
            _ => {
                let Some(saved) = parse(url) else {
                    return false;
                };
                if !is_web(&saved) {
                    return false;
                }
                match resolved {
                    UrlMatch::Exact => self.url.as_str() == saved.as_str(),
                    UrlMatch::StartsWith => self.url.as_str().starts_with(saved.as_str()),
                    UrlMatch::Host => host_and_port(&self.url) == host_and_port(&saved),
                    _ => self.site == base_domain(saved.host_str().unwrap_or("")),
                }
            }
        }
    }
}

/// What the saved website `url` with `match_type` is matched as, `default_match` being the
/// user's setting: never [`UrlMatch::Default`]. "default" resolves to the setting ("domain"
/// when that is "default" too), except that with "regex" a plain absolute http(s) address,
/// written as it serializes (one trailing "/" aside), stays "domain": a saved page address is
/// never a pattern. So does an app's address (`androidapp://…`), which matches no page. For
/// editors: an entry runs as a pattern exactly when this is [`UrlMatch::Regex`] (then show
/// [`regex_error`] and [`regex_warning`]).
pub fn resolve_match(url: &str, match_type: UrlMatch, default_match: UrlMatch) -> UrlMatch {
    match (match_type, default_match) {
        (UrlMatch::Default, UrlMatch::Default) => UrlMatch::Domain,
        // Review M2: as a pattern, "https://bank.com" matched
        // "https://evil.example/https://bank.com". Fail closed to its site.
        (UrlMatch::Default, UrlMatch::Regex) if is_plain_address(url) => UrlMatch::Domain,
        (UrlMatch::Default, fallback) => fallback,
        (m, _) => m,
    }
}

/// [`Page::matches`] for a single page address (false unless the page is an absolute http(s)
/// address).
pub fn matches_url(
    page: &str,
    url: &str,
    match_type: UrlMatch,
    default_match: UrlMatch,
    allow_regex: bool,
) -> bool {
    Page::parse(page).is_some_and(|p| p.matches(url, match_type, default_match, allow_regex))
}

/// Refuse to send a secret saved for an https site to an http page (localhost excepted). For a
/// regular expression, "saved for https" means the pattern starts with `https:` or `^https:`.
pub fn downgrade(page: &str, url: &str, match_type: UrlMatch) -> bool {
    if match_type == UrlMatch::Regex {
        let page_lower = page.to_ascii_lowercase();
        let local = ["http://localhost", "https://localhost"].iter().any(|p| {
            page_lower
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with([':', '/']))
        });
        let pattern = url.strip_prefix('^').unwrap_or(url);
        return page_lower.starts_with("http:")
            && !local
            && pattern
                .get(..6)
                .is_some_and(|s| s.eq_ignore_ascii_case("https:"));
    }
    match (parse_page(page), parse(url)) {
        (Some(p), Some(u)) => {
            u.scheme() == "https" && p.scheme() == "http" && p.host_str() != Some("localhost")
        }
        _ => false,
    }
}

/// Why the engine refuses `pattern` as a website pattern (too long, too large, or syntax it
/// doesn't have, such as look-around or back-references), or `None` when it is evaluated.
///
/// Patterns use the syntax of the `regex` crate without Unicode classes (`regex-lite`), always
/// case-insensitive, ASCII-only for `\w`, `\d`, `\s`, `\b` and case folding (addresses are
/// ASCII anyway, as in JavaScript without the `u` flag). The engine runs in time linear in
/// pattern × input, so no pattern can backtrack catastrophically: there is no unsafe-pattern scan.
pub fn regex_error(pattern: &str) -> Option<String> {
    compile(pattern).err()
}

fn compile(pattern: &str) -> Result<Regex, String> {
    if utf16_len(pattern) > MAX_REGEX_LENGTH {
        return Err(format!(
            "The pattern is longer than {MAX_REGEX_LENGTH} characters."
        ));
    }
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| {
            // The engine's message is a phrase ("look-around is not supported"): make it a sentence.
            let text = e.to_string();
            let mut chars = text.trim().trim_end_matches('.').chars();
            match chars.next() {
                Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
                None => "The pattern is not valid.".to_owned(),
            }
        })
}

/// Compiled patterns, shared (an `Arc`: a cloned `Regex` would start with an empty search cache).
fn compiled(pattern: &str) -> Option<Arc<Regex>> {
    static CACHE: LazyLock<Mutex<HashMap<String, Option<Arc<Regex>>>>> =
        LazyLock::new(Default::default);
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(re) = cache.get(pattern) {
        return re.clone();
    }
    let re = compile(pattern).ok().map(Arc::new);
    if cache.len() >= REGEX_CACHE {
        cache.clear();
    }
    cache.insert(pattern.to_owned(), re.clone());
    re
}

fn regex_matches(pattern: &str, page: &Url) -> bool {
    // ASCII: the origin is serialised with the punycode host, the path is percent-encoded.
    let mut haystack = page.origin().ascii_serialization();
    haystack.push_str(page.path());
    // Too long to test whole: no match (review I3: a cut-off address let `^…/a+$` match
    // a path that went on with "/evil").
    if haystack.len() > MAX_REGEX_INPUT {
        return false;
    }
    compiled(pattern).is_some_and(|re| re.is_match(&haystack))
}

const NOT_ANCHORED: &str = "The pattern isn't tied to the start of the address, so any website whose address contains matching text matches it. Start it with ^https:// and the website's host, for example ^https://example\\.com/";
const HOST_NOT_PINNED: &str = "The pattern doesn't pin the website's host, so other websites can match it. Write the host with \\. for each dot and end it with /, : or $, for example ^https://example\\.com/";

/// Why an explicit website pattern can also match other websites, for the item editors to
/// show as a warning (never a refusal: patterns that work keep working), or `None` when it
/// pins its website. Pinned means every alternative starts with `^https://` (or `^http://`,
/// `^https?://`) and the host, every dot escaped, followed by `/`, `:` (a port) or `$`.
/// Before the website's own name there may be a part for subdomains that can't match `/`,
/// when the name after it is a registrable domain, such as
/// `^https://([a-z0-9-]+\.)*example\.com/` or `^https://[^/]+\.example\.com:8443/`.
///
/// A heuristic over the pattern's text that errs towards warning. `None` also for a pattern
/// [`regex_error`] refuses (it never runs; show that error instead).
pub fn regex_warning(pattern: &str) -> Option<String> {
    if regex_error(pattern).is_some() {
        return None;
    }
    let tree = tokens(pattern).and_then(|t| {
        let mut i = 0;
        let alts = alternatives(&t, &mut i, false)?;
        (i == t.len()).then_some(alts)
    });
    let Some(alts) = tree else {
        return Some(HOST_NOT_PINNED.to_owned());
    };
    alts.iter()
        .find_map(|alt| pins_its_site(alt).err())
        .map(str::to_owned)
}

/// A token of a website pattern, as far as [`regex_warning`] follows the syntax.
#[derive(Debug, Clone, Copy)]
enum Tok<'a> {
    Start,
    End,
    Lit(char),
    /// `.`, a class or a class escape: its source text.
    Set(&'a str),
    /// What the lint doesn't follow: assertions, flag groups, other escapes.
    Other,
    Open,
    Close,
    Alt,
    /// A repetition; `true` when it allows none.
    Repeat(bool),
}

fn tokens(p: &str) -> Option<Vec<Tok<'_>>> {
    let cs: Vec<(usize, char)> = p.char_indices().collect();
    let at = |i: usize| cs.get(i).map(|&(_, c)| c);
    let offset = |i: usize| cs.get(i).map_or(p.len(), |&(o, _)| o);
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        let start = i;
        let c = cs[i].1;
        i += 1;
        let tok = match c {
            '^' => Tok::Start,
            '$' => Tok::End,
            '.' => Tok::Set(&p[offset(start)..offset(i)]),
            '|' => Tok::Alt,
            ')' => Tok::Close,
            '(' if at(i) == Some('?') => {
                i += 1;
                match at(i)? {
                    ':' => {
                        i += 1;
                        Tok::Open
                    }
                    'P' | '<' => {
                        while at(i)? != '>' {
                            i += 1;
                        }
                        i += 1;
                        Tok::Open
                    }
                    _ => {
                        while at(i).is_some_and(|c| c.is_ascii_alphabetic() || c == '-') {
                            i += 1;
                        }
                        match at(i)? {
                            // Flags for a group: followed like any group.
                            ':' => {
                                i += 1;
                                Tok::Open
                            }
                            ')' => {
                                i += 1;
                                Tok::Other
                            }
                            _ => return None,
                        }
                    }
                }
            }
            '(' => Tok::Open,
            '*' | '?' | '+' => {
                if at(i) == Some('?') {
                    i += 1;
                }
                Tok::Repeat(c != '+')
            }
            '{' => {
                let digits = i;
                while at(i)?.is_ascii_digit() {
                    i += 1;
                }
                let zero = p[offset(digits)..offset(i)].parse::<u32>().ok()? == 0;
                while at(i)? != '}' {
                    i += 1;
                }
                i += 1;
                if at(i) == Some('?') {
                    i += 1;
                }
                Tok::Repeat(zero)
            }
            '[' => {
                i = class_end(&cs, i)?;
                Tok::Set(&p[offset(start)..offset(i)])
            }
            '\\' => {
                let e = at(i)?;
                i += 1;
                match e {
                    'd' | 'D' | 'w' | 'W' | 's' | 'S' => Tok::Set(&p[offset(start)..offset(i)]),
                    'A' => Tok::Start,
                    'z' => Tok::End,
                    e if e.is_ascii_punctuation() || e == ' ' => Tok::Lit(e),
                    _ => Tok::Other,
                }
            }
            c => Tok::Lit(c),
        };
        out.push(tok);
    }
    Some(out)
}

/// Index after the `]` that closes the class opened just before `i`.
fn class_end(cs: &[(usize, char)], mut i: usize) -> Option<usize> {
    let at = |i: usize| cs.get(i).map(|&(_, c)| c);
    let mut depth = 1;
    loop {
        // A `]` right after the opening (and its `^`) is a literal.
        if at(i)? == '^' {
            i += 1;
        }
        if at(i)? == ']' {
            i += 1;
        }
        loop {
            match at(i)? {
                '\\' => i += 2,
                '[' => {
                    depth += 1;
                    i += 1;
                    break;
                }
                ']' => {
                    depth -= 1;
                    i += 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => i += 1,
            }
        }
    }
}

#[derive(Debug)]
enum Node<'a> {
    Start,
    End,
    Lit(char),
    Set(&'a str),
    Other,
    Group(Vec<Vec<Piece<'a>>>),
}

#[derive(Debug)]
struct Piece<'a> {
    node: Node<'a>,
    /// `Some(true)`: may occur no time at all; `Some(false)`: repeated, at least once.
    repeat: Option<bool>,
}

/// The alternatives up to the `)` that closes a group (`in_group`) or the end.
fn alternatives<'a>(t: &[Tok<'a>], i: &mut usize, in_group: bool) -> Option<Vec<Vec<Piece<'a>>>> {
    let mut alts: Vec<Vec<Piece<'a>>> = vec![Vec::new()];
    while let Some(&tok) = t.get(*i) {
        *i += 1;
        let node = match tok {
            Tok::Close => return in_group.then_some(alts),
            Tok::Alt => {
                alts.push(Vec::new());
                continue;
            }
            Tok::Repeat(zero) => {
                let last = alts.last_mut()?.last_mut()?;
                last.repeat = Some(zero || last.repeat == Some(true));
                continue;
            }
            Tok::Open => Node::Group(alternatives(t, i, true)?),
            Tok::Start => Node::Start,
            Tok::End => Node::End,
            Tok::Lit(c) => Node::Lit(c),
            Tok::Set(s) => Node::Set(s),
            Tok::Other => Node::Other,
        };
        alts.last_mut()?.push(Piece { node, repeat: None });
    }
    (!in_group).then_some(alts)
}

fn is_lit(p: &Piece, c: char) -> bool {
    p.repeat.is_none() && matches!(p.node, Node::Lit(l) if l.eq_ignore_ascii_case(&c))
}

/// Does one alternative pin its website? The error is the warning to show.
fn pins_its_site(alt: &[Piece]) -> Result<(), &'static str> {
    let rest = match alt {
        [first, rest @ ..] if first.repeat.is_none() && matches!(first.node, Node::Start) => rest,
        _ => return Err(NOT_ANCHORED),
    };
    let mut rest = scheme(rest).ok_or(NOT_ANCHORED)?;
    for c in [':', '/', '/'] {
        match rest.split_first() {
            Some((p, tail)) if is_lit(p, c) => rest = tail,
            _ => return Err(NOT_ANCHORED),
        }
    }
    let end = (0..rest.len())
        .find(|&k| ends_host(&rest[k..]))
        .ok_or(HOST_NOT_PINNED)?;
    let host = &rest[..end];
    if host.is_empty() || !host.iter().all(host_safe) {
        return Err(HOST_NOT_PINNED);
    }
    if exact(host) {
        return Ok(());
    }
    // A part that varies, then the website's own name, which must start at a label: after
    // an escaped dot, or after a group whose every alternative ends with one.
    let run = host
        .iter()
        .rposition(|p| !(p.repeat.is_none() && matches!(p.node, Node::Lit(_))))
        .map_or(0, |k| k + 1);
    let name: String = host[run..]
        .iter()
        .map(|p| match p.node {
            Node::Lit(c) => c,
            _ => unreachable!("only literals in the run"),
        })
        .collect();
    let name = match name.strip_prefix('.') {
        Some(name) => name,
        None => match host[..run].last() {
            Some(Piece {
                node: Node::Group(alts),
                ..
            }) if alts.iter().all(|a| a.last().is_none_or(|p| is_lit(p, '.'))) => name.as_str(),
            _ => return Err(HOST_NOT_PINNED),
        },
    };
    if name.starts_with('.') || super::registrable_domain(name).is_none() {
        return Err(HOST_NOT_PINNED);
    }
    Ok(())
}

/// `http` and an optional `s` (`s`, `s?`, `(s)?`, `(?:s)?`); what follows it.
fn scheme<'p, 'a>(mut rest: &'p [Piece<'a>]) -> Option<&'p [Piece<'a>]> {
    for c in ['h', 't', 't', 'p'] {
        let (p, tail) = rest.split_first()?;
        if !is_lit(p, c) {
            return None;
        }
        rest = tail;
    }
    if let Some((p, tail)) = rest.split_first() {
        let s = match &p.node {
            Node::Lit(c) => c.eq_ignore_ascii_case(&'s'),
            Node::Group(alts) => {
                matches!(alts.as_slice(), [only] if matches!(only.as_slice(), [p] if is_lit(p, 's')))
            }
            _ => false,
        };
        if s && p.repeat != Some(false) {
            rest = tail;
        }
    }
    Some(rest)
}

/// Does the host end where `rest` starts: `/`, `:` or `$`, or a group whose every
/// alternative starts so (when it may be skipped, what follows it must end the host too)?
fn ends_host(rest: &[Piece]) -> bool {
    let Some((first, tail)) = rest.split_first() else {
        return false;
    };
    let ends = match &first.node {
        Node::Lit('/' | ':') | Node::End => true,
        Node::Group(alts) => alts.iter().all(|a| ends_host(a)),
        _ => false,
    };
    ends && (first.repeat != Some(true) || ends_host(tail))
}

/// Can this part of a host match only host characters (never `/`)?
fn host_safe(p: &Piece) -> bool {
    match &p.node {
        Node::Lit(c) => c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'),
        Node::Set(src) => !matches_slash(src),
        Node::Group(alts) => alts.iter().all(|a| a.iter().all(host_safe)),
        _ => false,
    }
}

/// One host (or a fixed choice of hosts) spelled out.
fn exact(pieces: &[Piece]) -> bool {
    pieces.iter().all(|p| {
        p.repeat.is_none()
            && match &p.node {
                Node::Lit(_) => true,
                Node::Group(alts) => alts.iter().all(|a| !a.is_empty() && exact(a)),
                _ => false,
            }
    })
}

/// Can this class (or `.`, or a class escape) match `/`, as the engine runs it?
fn matches_slash(set: &str) -> bool {
    RegexBuilder::new(&format!("^(?:{set})$"))
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .ok()
        .is_none_or(|re| re.is_match("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use UrlMatch::*;

    fn m(page: &str, url: &str, match_type: UrlMatch) -> bool {
        matches_url(page, url, match_type, Domain, true)
    }

    #[test]
    fn domain_uses_the_full_suffix_list() {
        assert!(m(
            "https://www.example.com/login",
            "https://example.com",
            Domain
        ));
        assert!(m(
            "https://login.example.co.uk/",
            "www.example.co.uk",
            Domain
        ));
        assert!(!m(
            "https://evil.duckdns.org/",
            "https://home.duckdns.org/",
            Domain
        ));
        // Review finding S3: these used to fall back to "the last two labels".
        assert!(!m(
            "https://attacker.myfritz.net/",
            "https://nas.myfritz.net",
            Domain
        ));
        assert!(!m("https://evil.myds.me/", "https://home.myds.me", Domain));
        assert!(!m("https://b.dedyn.io/", "https://a.dedyn.io", Domain));
        assert!(!m(
            "https://b.cloudapp.net/",
            "https://a.cloudapp.net",
            Domain
        ));
        assert!(!m(
            "https://ec2-5-6-7-8.us-east-2.compute.amazonaws.com/",
            "https://ec2-1-2-3-4.us-east-2.compute.amazonaws.com",
            Domain
        ));
        assert!(m(
            "https://x.nas.myfritz.net/",
            "https://nas.myfritz.net",
            Domain
        ));
        assert!(m(
            "https://192.168.1.10:8443/",
            "https://192.168.1.10",
            Domain
        ));
        assert!(!m("https://192.168.1.11/", "https://192.168.1.10", Domain));
        assert!(m("https://bücher.de/", "https://xn--bcher-kva.de", Domain));
        assert!(m("https://EXAMPLE.com./", "https://example.com", Domain));
        assert!(!m("ftp://example.com/", "https://example.com", Domain));
    }

    #[test]
    fn other_schemes_are_not_websites() {
        // An Android app login is not a login for the website with the same labels.
        assert!(!m(
            "https://example.app/",
            "androidapp://com.example.app",
            Domain
        ));
        assert!(!m(
            "https://com.example.app/",
            "androidapp://com.example.app",
            Host
        ));
        assert!(m("http://example.com/", "example.com", Domain));
    }

    #[test]
    fn host_starts_with_exact_never_and_default() {
        assert!(m("https://example.com:443/", "https://example.com", Host));
        assert!(!m("https://example.com:8443/", "https://example.com", Host));
        assert!(!m("https://example.com./", "https://example.com", Host));
        assert!(m("http://example.com/", "https://example.com", Host));
        assert!(m(
            "https://example.com/login/2",
            "https://example.com/login",
            StartsWith
        ));
        assert!(!m(
            "https://example.com.evil.com/",
            "https://example.com",
            StartsWith
        ));
        assert!(m(
            "https://example.com/a/../login",
            "https://example.com/login",
            Exact
        ));
        assert!(m(
            "https://example.com/caf%C3%A9",
            "https://example.com/café",
            Exact
        ));
        assert!(!m(
            "https://example.com/login#top",
            "https://example.com/login",
            Exact
        ));
        assert!(!m("https://example.com/", "https://example.com", Never));
        let d = |default| {
            matches_url(
                "https://login.example.com/",
                "https://www.example.com",
                Default,
                default,
                true,
            )
        };
        assert!(d(Domain) && d(Default) && !d(Host) && !d(Never));
    }

    #[test]
    fn regular_expressions() {
        assert!(m(
            "https://example.com/login",
            r"^https://example\.com/",
            Regex
        ));
        assert!(m("https://EXAMPLE.com/", r"^HTTPS://example\.com", Regex));
        assert!(!m(
            "https://evil.com/?https://example.com/",
            r"example\.com",
            Regex
        ));
        assert!(!m("https://evil.com/#example.org", r"example\.org", Regex));
        assert!(m(
            "https://example.com:8443/app",
            r"^https://example\.com:8443/app$",
            Regex
        ));
        assert!(!m("https://example.com/", "[", Regex));
        // Only the user's own logins may use them, also through "default".
        assert!(!matches_url(
            "https://example.com/",
            ".*",
            Regex,
            Domain,
            false
        ));
        assert!(!matches_url(
            "https://example.com/",
            ".*",
            Default,
            Regex,
            false
        ));
        assert!(matches_url(
            "https://example.com/",
            ".*",
            Default,
            Regex,
            true
        ));
        // ASCII classes and case folding: the Kelvin sign is not "k" (as in JavaScript).
        assert!(m("https://example.com/a1", r"/\w\d$", Regex));
        assert!(!m("https://k.example/", "\u{212a}", Regex));
    }

    #[test]
    fn default_regex_keeps_plain_addresses_to_their_site() {
        // Review M2: with "regular expression" as the default, a saved page address used to be
        // run as a pattern, so phishing pages that contain it matched.
        let d = |page: &str, url: &str, allow| matches_url(page, url, Default, Regex, allow);
        for url in [
            "https://bank.com",
            "https://bank.com/",
            "http://bank.com/login",
        ] {
            assert!(
                !d("https://evil.example/https://bank.com", url, true),
                "{url}"
            );
            assert!(
                !d("https://evil.example/bank.com/login", url, true),
                "{url}"
            );
            assert!(!d("https://bankxcom.example/", url, true), "{url}");
            // As "domain": the site itself and its subdomains, also in a shared vault.
            assert!(d("https://www.bank.com/login", url, true), "{url}");
            assert!(d("https://www.bank.com/login", url, false), "{url}");
        }
        assert!(d("https://bank.com/x", "https://bank.com/login/", true));
        assert!(d("https://bank.com/", "https://bank.com/a?b=1#c", true));
        // Anything else is still a pattern (existing patterns keep working).
        assert!(d("https://bank.com/login", r"^https://bank\.com/", true));
        assert!(d("https://example.com/", ".*", true));
        assert!(!d("https://example.com/", ".*", false));
        // Not written as it serializes: a pattern (upper case, default port, no scheme).
        assert!(d("https://bank.com/", "https://BANK.com", true));
        assert!(!d("https://bank.com/", "https://bank.com:443/", true));
        assert!(d("https://bankxcom.example/", "bank.com", true));
        // Explicit "regex" and other defaults are unchanged.
        assert!(m(
            "https://evil.example/https://bank.com",
            "https://bank.com",
            Regex
        ));
        assert!(!matches_url(
            "https://evil.example/https://bank.com",
            "https://bank.com",
            Default,
            Domain,
            true
        ));
        // An app's address is never a pattern either: it matches no page.
        assert!(!d(
            "https://evil.example/androidapp://com.bank",
            "androidapp://com.bank",
            true
        ));
        assert!(!d("https://com.bank/", "androidapp://com.bank", true));
        assert!(is_plain_address("androidapp://com.bank"));
        assert!(!is_plain_address("a:b"));
        assert!(is_plain_address("https://bank.com"));
        assert!(is_plain_address("https://bank.com//"));
        assert!(!is_plain_address("https://bank.com/./"));
        assert!(!is_plain_address("https://bank.com:443"));
        assert!(!is_plain_address("bank.com"));
        // Another scheme's address is an address too (and no website).
        assert!(is_plain_address("ftp://bank.com/"));
        assert!(!d("https://bank.com/", "ftp://bank.com/", true));
        assert!(!is_plain_address(" https://bank.com/"));
        assert!(!is_plain_address("https://bank.com/a b"));
    }

    #[test]
    fn pages_need_an_absolute_http_address() {
        // Review L4: page strings got the saved addresses' default scheme.
        for page in [
            "data:,@bank.com/",
            "mailto:x@bank.com",
            "javascript:alert(1)//@bank.com/",
            "bank.com",
            "//bank.com/",
            "bank.com/login",
            "",
        ] {
            for t in [Domain, Host, StartsWith, Exact, Regex, Default] {
                assert!(!m(page, "https://bank.com", t), "{page} {t:?}");
                assert!(!m(page, "bank.com", t), "{page} {t:?}");
            }
            assert!(Page::parse(page).is_none(), "{page}");
            assert!(!downgrade(page, "https://bank.com", Domain), "{page}");
        }
        assert!(Page::parse("HTTPS://BANK.com").is_some());
        assert!(m("https://bank.com", "bank.com", Domain));
        // Saved addresses keep the default scheme.
        assert!(m("https://www.bank.com/", "bank.com/login", Domain));
        assert!(downgrade("http://bank.com/", "bank.com", Domain));
    }

    #[test]
    fn long_pages_match_no_pattern() {
        // Review I3: the address was cut at MAX_REGEX_INPUT bytes and the rest ignored.
        let page = |len: usize| {
            let base = "https://bank.com/";
            format!("{base}{}", "a".repeat(len - base.len()))
        };
        let at_limit = page(MAX_REGEX_INPUT);
        assert_eq!(at_limit.len(), MAX_REGEX_INPUT);
        assert!(m(&at_limit, r"^https://bank\.com/a+$", Regex));
        assert!(!m(
            &page(MAX_REGEX_INPUT + 1),
            r"^https://bank\.com/a+$",
            Regex
        ));
        assert!(!m(
            &page(MAX_REGEX_INPUT + 1),
            r"^https://bank\.com/",
            Regex
        ));
        let evil = format!("https://bank.com/{}/evil", "a".repeat(2100));
        assert!(!m(&evil, r"^https://bank\.com/a+$", Regex));
        // Only patterns: other match types don't care about the length.
        assert!(m(&evil, "https://bank.com", Domain));
        // The query and fragment don't count towards it (they aren't tested).
        let query = format!("https://bank.com/?{}", "q".repeat(5000));
        assert!(m(&query, r"^https://bank\.com/$", Regex));
    }

    #[test]
    fn regex_warnings() {
        for pinned in [
            r"^https://example\.com/",
            r"^http://example\.com/",
            r"^https?://example\.com/",
            r"^http(s)?://example\.com/",
            r"^http(?:s)?://example\.com/login$",
            r"^HTTPS://EXAMPLE\.com/",
            r"^https:\/\/example\.com\/",
            r"\Ahttps://example\.com/",
            r"^https://example\.com$",
            r"^https://example\.com:8443/",
            r"^https://example\.com(/.*)?$",
            r"^https://example\.com(?::\d+)?/",
            r"^https://example\.com(?:/|$)",
            r"^https://(www\.)?example\.com/",
            r"^https://(?:www\.|)example\.com/",
            r"^https://([a-z0-9-]+\.)*example\.com/",
            r"^https://[a-z0-9-]+\.example\.com/",
            r"^https://[^/]+\.example\.co\.uk/",
            r"^https://(www|login)\.example\.com/",
            r"^https://(example|example-cdn)\.com/",
            r"^https://login\.example\.com/|^https://example\.org/",
            r"^https://192\.168\.1\.10:8443/",
            r"^https://nas\.myfritz\.net/",
            r"^https://co\.uk/",
        ] {
            assert_eq!(regex_warning(pinned), None, "{pinned}");
        }
        for loose in [
            r"example\.com",
            r"https://example\.com/",
            "",
            ".*",
            r"(?i)^https://example\.com/",
            r"^ftp://example\.com/",
            r"^.*://example\.com/",
            r"^https://example\.com/|example\.org",
        ] {
            assert_eq!(
                regex_warning(loose).as_deref(),
                Some(NOT_ANCHORED),
                "{loose}"
            );
        }
        for loose in [
            // Unescaped dots: "https://myxexample.com/".
            r"^https://my.example\.com/",
            r"^https://example.com/",
            // No end to the host: "https://example.com.evil.net/".
            r"^https://example\.com",
            r"^https://example\.com\b",
            r"^https://example\.com/?",
            r"^https://example\.com(/.*)?",
            // A part that can span "/" or labels: "https://evil.net/x.example.com/".
            r"^https://.*\.example\.com/",
            r"^https://(.*\.)?example\.com/",
            r"^https://[^.]+\.example\.com/",
            r"^https://\S+\.example\.com/",
            // The name doesn't start at a label: "https://notexample.com/".
            r"^https://[a-z]+example\.com/",
            r"^https://\w*example\.com/",
            // Every site under a public suffix.
            r"^https://([a-z]+\.)*com/",
            r"^https://[^/]+\.co\.uk/",
            r"^https://[a-z]+/",
            r"^https://[0-9.]+/",
        ] {
            assert_eq!(
                regex_warning(loose).as_deref(),
                Some(HOST_NOT_PINNED),
                "{loose}"
            );
        }
        // Refused patterns get their error instead.
        assert_eq!(regex_warning("("), None);
        assert_eq!(regex_warning(r"(?<=a)b"), None);
    }

    #[test]
    fn regex_warning_reads_any_pattern() {
        // Every short pattern of metacharacters, alone and after a pinned start: no panic, and
        // never "pinned" unless the engine accepts it.
        let alphabet: Vec<char> = r"^$.()[]{}|?*+\/:-a1,".chars().collect();
        let mut patterns = vec![String::new()];
        for _ in 0..3 {
            let longer: Vec<String> = patterns
                .iter()
                .flat_map(|p| alphabet.iter().map(move |c| format!("{p}{c}")))
                .collect();
            patterns.extend(longer);
        }
        for p in &patterns {
            for pattern in [
                p.clone(),
                format!(r"^https://a\.com{p}"),
                format!(r"^https://{p}a\.com/"),
            ] {
                if regex_warning(&pattern).is_none() {
                    assert!(
                        regex_error(&pattern).is_some() || pattern.starts_with("^https://"),
                        "{pattern}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_catastrophic_backtracking() {
        // Just under MAX_REGEX_INPUT, so the final "!" is still part of what is tested.
        let page = format!("https://example.com/{}!", "a".repeat(2000));
        let start = std::time::Instant::now();
        for pattern in [
            "(a+)+$",
            "(.*a){10}$",
            "(a|aa)+$",
            "(a+a+)+b",
            "(a?){30}a{30}b",
        ] {
            assert!(regex_error(pattern).is_none(), "{pattern}");
            assert!(!m(&page, pattern, Regex), "{pattern}");
        }
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    }

    #[test]
    fn refused_patterns() {
        assert!(regex_error(r"^https://(www\.)?example\.com/").is_none());
        assert!(regex_error(&"x".repeat(MAX_REGEX_LENGTH)).is_none());
        assert!(
            regex_error(&"x".repeat(MAX_REGEX_LENGTH + 1))
                .unwrap()
                .contains("longer than 300")
        );
        assert_eq!(
            regex_error("(?<=a)b").as_deref(),
            Some("Look-around is not supported.")
        );
        assert_eq!(
            regex_error(r"(a)\1").as_deref(),
            Some("Backreferences are not supported.")
        );
        assert!(regex_error("[").is_some());
        assert!(regex_error("a{1000}{1000}").unwrap().contains("size limit"));
        // Character classes may hold non-ASCII characters (they match none of an address).
        assert!(regex_error("[^à-ü]+$").is_none());
        assert!(regex_error(r"\p{L}").is_some());
    }

    #[test]
    fn downgrade_rule() {
        assert!(downgrade(
            "http://example.com/",
            "https://example.com",
            Domain
        ));
        assert!(downgrade("HTTP://EXAMPLE.com/", "example.com", Domain));
        assert!(!downgrade(
            "https://example.com/",
            "http://example.com",
            Domain
        ));
        assert!(!downgrade(
            "http://localhost:8080/",
            "https://localhost:8080",
            Domain
        ));
        assert!(downgrade(
            "http://192.168.1.10/",
            "https://192.168.1.10",
            Host
        ));
        assert!(downgrade(
            "http://example.com/",
            r"^https://example\.com",
            Regex
        ));
        assert!(!downgrade("http://example.com/", r"example\.com", Regex));
        assert!(!downgrade(
            "http://localhost/x",
            "^https://localhost",
            Regex
        ));
        assert!(downgrade("http://localhostx/", "^https://", Regex));
        assert!(downgrade(
            "HTTP://example.com/",
            r"^HTTPS://example\.com",
            Regex
        ));
    }

    #[test]
    fn match_types_parse() {
        assert_eq!(parse_url_match("starts_with"), Some(StartsWith));
        assert_eq!(parse_url_match("Domain"), None);
        assert_eq!(parse_url_match(""), None);
        for m in [Default, Domain, Host, StartsWith, Exact, Regex, Never] {
            assert_eq!(parse_url_match(m.as_str()), Some(m));
        }
    }

    #[test]
    fn resolved_match_types() {
        let r = resolve_match;
        assert_eq!(r("https://bank.com", Default, Regex), Domain);
        assert_eq!(r("https://bank.com/login/", Default, Regex), Domain);
        assert_eq!(r("bank.com", Default, Regex), Regex);
        assert_eq!(r(r"^https://bank\.com/", Default, Regex), Regex);
        assert_eq!(r("https://bank.com", Regex, Domain), Regex);
        assert_eq!(r("https://bank.com", Default, Default), Domain);
        assert_eq!(r("https://bank.com", Default, Host), Host);
        assert_eq!(r("https://bank.com", Exact, Regex), Exact);
        assert_eq!(r("https://bank.com", Never, Regex), Never);
        assert_eq!(r("androidapp://com.bank", Default, Regex), Domain);
    }
}
