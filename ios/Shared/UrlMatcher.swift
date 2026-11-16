import Foundation
import PassAuthCore

/// Website matching for autofill: thin wrappers over the Rust core's site logic
/// (`crates/core/src/site`, the one implementation every PassAuth client calls): base domains
/// from the full Public Suffix List, every match type, the https→http downgrade rule and
/// regular expressions on one linear-time engine. This file only adapts the app's types (the
/// item's match type, the user's default match setting, the shared-vault regex rule) and keeps
/// `parse`, the app's own URL reading for display, the server address and the identity store.
public enum UrlMatcher {
    static let defaultPorts: [String: Int] = ["http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21]

    /// The parts of a URL the app shows or keys on, read like the browser's `URL` (host in
    /// ASCII). Matching never uses it: the core parses addresses itself.
    public struct Parsed: Equatable, Sendable {
        public let scheme: String
        /// Lowercase host name without port.
        public let hostname: String
        /// Host name plus a non-default port.
        public let host: String
        public let href: String
        /// Path as written ("" when none).
        public let path: String
        public var origin: String { "\(scheme)://\(host)" }
    }

    /// Characters a URI may not contain unescaped (java.net.URI rejects them too).
    private static let invalid = CharacterSet(charactersIn: " \"<>\\^`{|}").union(.controlCharacters).union(.whitespacesAndNewlines)

    /// Parse like `new URL(url.includes("://") ? url : "https://" + url)`; nil if invalid.
    public static func parse(_ url: String) -> Parsed? {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let text = trimmed.contains("://") ? trimmed : "https://" + trimmed
        if text.unicodeScalars.contains(where: { invalid.contains($0) }) { return nil }
        guard let sep = text.range(of: "://") else { return nil }
        let scheme = String(text[..<sep.lowerBound]).lowercased()
        guard let first = scheme.unicodeScalars.first, CharacterSet.letters.contains(first),
              scheme.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || "+.-".unicodeScalars.contains($0) })
        else { return nil }
        let rest = text[sep.upperBound...]
        let authEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? rest.endIndex
        let authority = String(rest[..<authEnd])
        var tail = String(rest[authEnd...])

        var fragment: String?
        if let h = tail.firstIndex(of: "#") {
            fragment = String(tail[tail.index(after: h)...])
            tail = String(tail[..<h])
        }
        var query: String?
        if let q = tail.firstIndex(of: "?") {
            query = String(tail[tail.index(after: q)...])
            tail = String(tail[..<q])
        }
        let path = tail

        var userInfo: String?
        var hostPort = authority
        if let at = authority.lastIndex(of: "@") {
            userInfo = String(authority[..<at])
            hostPort = String(authority[authority.index(after: at)...])
        }
        var hostname: String
        var portText: String?
        if hostPort.hasPrefix("[") {
            guard let close = hostPort.firstIndex(of: "]") else { return nil }
            hostname = String(hostPort[...close])
            let after = hostPort[hostPort.index(after: close)...]
            if after.hasPrefix(":") { portText = String(after.dropFirst()) } else if !after.isEmpty { return nil }
        } else if let colon = hostPort.lastIndex(of: ":") {
            hostname = String(hostPort[..<colon])
            portText = String(hostPort[hostPort.index(after: colon)...])
        } else {
            hostname = hostPort
        }
        hostname = hostname.lowercased()
        if hostname.isEmpty && (scheme == "http" || scheme == "https") { return nil }
        // Internationalised names in their ASCII (punycode) form, as the browser's URL has them
        // ("bücher.de" is "xn--bcher-kva.de"): the core's host parser (UTS #46 nontransitional).
        if !hostname.hasPrefix("["), !hostname.allSatisfy(\.isASCII) {
            guard let ascii = idnaHost(hostname) else { return nil }
            hostname = ascii
        }
        var port: Int?
        if let p = portText, !p.isEmpty {
            guard let n = Int(p), p.allSatisfy(\.isASCII), n >= 0, n <= 65535 else { return nil }
            port = n == defaultPorts[scheme] ? nil : n
        }
        let host = port.map { "\(hostname):\($0)" } ?? hostname
        var href = "\(scheme)://"
        if let u = userInfo { href += u + "@" }
        href += host
        href += path.isEmpty ? "/" : path
        if let q = query { href += "?" + q }
        if let f = fragment { href += "#" + f }
        return Parsed(scheme: scheme, hostname: hostname, host: host, href: href, path: path)
    }

    /// The ASCII form of an internationalised host name, as the browser's URL parser makes it
    /// (the core's `normalizeHost`: UTS #46 nontransitional, lower case); nil if it isn't a
    /// valid name. "straße.de" is "xn--strae-oqa.de".
    static func idnaHost(_ host: String) -> String? {
        guard let ascii = normalizeHost(host: host), !ascii.isEmpty, !ascii.hasPrefix("[") else { return nil }
        return ascii
    }

    /// The site "domain" matching compares (the core's `baseDomain`): the registrable domain by
    /// the full Public Suffix List ("home.duckdns.org", "nas.myfritz.net"); a public suffix, an IP
    /// address or an invalid name stands for itself.
    public static func baseDomain(_ host: String) -> String {
        PassAuthCore.baseDomain(host: host)
    }

    /// Does the page URL match a saved website (the core's `matchesUrl`)? `fallback` resolves
    /// "default" (the user's setting). `allowRegex`: regular expressions count only for the
    /// user's own items; a pattern from a vault somebody shared was written by somebody else (and
    /// would run on every page the user visits), so it never matches, also when "default"
    /// resolves to it. An `androidapp://` address is never a website.
    public static func matches(_ page: String, _ item: LoginUrl, fallback: UrlMatch = .domain, allowRegex: Bool = true) -> Bool {
        matchesUrl(page: page, url: item.url, matchType: item.match.rawValue, defaultMatch: fallback.rawValue, allowRegex: allowRegex)
    }

    /// Any of the login's websites matches the page (`allowRegex`: see `matches`): one call to the
    /// core, which reads the page address once.
    public static func matchesAny(_ page: String, _ login: Login, fallback: UrlMatch = .domain, allowRegex: Bool = true) -> Bool {
        guard !login.urls.isEmpty else { return false }
        let urls = login.urls.map { SavedUrl(url: $0.url, matchType: $0.match.rawValue, allowRegex: allowRegex) }
        return matchUrls(page: page, defaultMatch: fallback.rawValue, urls: urls).contains(true)
    }

    /// Refuse to send a secret saved for an https site to an http page (localhost excepted).
    public static func downgrade(_ page: String, _ item: LoginUrl) -> Bool {
        PassAuthCore.downgrade(page: page, url: item.url, matchType: item.match.rawValue)
    }

    /// Why the core refuses a website pattern (longer than 300 characters, too large, or syntax
    /// it doesn't have, such as look-around); nil when it is used. Patterns run on a linear-time
    /// engine, so none is refused for being slow.
    public static func regexError(_ pattern: String) -> String? {
        PassAuthCore.regexError(pattern: pattern)
    }

    /// What an item editor says under a website that runs as a regular expression.
    public enum PatternNote: Equatable, Sendable {
        /// The core refuses the pattern (its reason): it never matches.
        case error(String)
        /// The pattern isn't tied to one website (`patternWarning`); saving is still allowed.
        case warning
    }

    /// Under a website set to "Regular expression" (core review M2).
    public static let patternWarning = "This pattern isn't tied to one website, so it could match other sites. Start it with ^https://example\\.com/ (your site's address)."

    /// The note for one website in the editor: only when the entry runs as a pattern (the core's
    /// `resolveMatch` is "regex": "Regular expression", or "Default" while the default setting
    /// is "Regular expression" and the entry isn't a plain address), then the core's refusal
    /// (`regexError`) or its warning that the pattern can match other sites (`regexWarning`).
    /// Nil for a blank entry and for every other match type.
    public static func patternNote(url: String, match: UrlMatch, defaultMatch: UrlMatch) -> PatternNote? {
        let pattern = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !pattern.isEmpty, resolveMatch(url: pattern, matchType: match.rawValue, defaultMatch: defaultMatch.rawValue) == UrlMatch.regex.rawValue else { return nil }
        if let refused = regexError(pattern) { return .error(refused) }
        return regexWarning(pattern: pattern) == nil ? nil : .warning
    }
}
