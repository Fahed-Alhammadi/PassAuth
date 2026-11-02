import Foundation

/// Website matching for autofill: a port of the extension's `background/urls.ts` (and the
/// Android app's `UrlMatcher`), with the same semantics, including WHATWG-style URL
/// normalisation for "exact" and "starts with".
public enum UrlMatcher {
    // Common multi-label public suffixes. Not the full Public Suffix List: for hosts under
    // other multi-label suffixes "domain" matching falls back to the last two labels, which
    // can over-match. Use "host" matching on such items.
    static let multi: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp",
        "com.br", "com.cn", "com.hk", "com.sg", "com.tr", "com.mx", "com.ar", "co.in", "co.za", "co.kr",
        "com.sa", "net.sa", "gov.sa", "co.ae", "gov.ae", "com.eg", "com.qa", "com.kw", "com.bh", "com.om",
        "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "herokuapp.com", "azurewebsites.net",
        "cloudfront.net", "appspot.com", "web.app", "firebaseapp.com",
    ]

    static let defaultPorts: [String: Int] = ["http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21]

    /// The parts of a URL the matcher needs, normalised like the browser's `URL`.
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

    public static func baseDomain(_ host: String) -> String {
        var h = host.lowercased()
        if h.hasSuffix(".") { h.removeLast() }
        if h.allSatisfy({ $0.isNumber || $0 == "." }) || h.contains(":") || !h.contains(".") { return h }
        let labels = h.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let last2 = labels.suffix(2).joined(separator: ".")
        if multi.contains(last2) && labels.count >= 3 { return labels.suffix(3).joined(separator: ".") }
        return last2
    }

    /// Does the page URL match a saved website? `fallback` resolves "default" (the user's setting).
    public static func matches(_ page: String, _ item: LoginUrl, fallback: UrlMatch = .domain) -> Bool {
        guard let p = parse(page), p.scheme == "http" || p.scheme == "https" else { return false }
        let match = item.match == .default ? fallback : item.match
        if match == .never || match == .default { return false }
        if match == .regex {
            guard let re = try? NSRegularExpression(pattern: item.url, options: [.caseInsensitive]) else { return false }
            return re.firstMatch(in: page, range: NSRange(page.startIndex..., in: page)) != nil
        }
        guard let u = parse(item.url) else { return false }
        switch match {
        case .exact: return p.href == u.href
        case .startsWith: return p.href.hasPrefix(u.href)
        case .host: return p.host == u.host
        default: return baseDomain(p.hostname) == baseDomain(u.hostname)
        }
    }

    /// Any of the login's websites matches the page.
    public static func matchesAny(_ page: String, _ login: Login, fallback: UrlMatch = .domain) -> Bool {
        login.urls.contains { matches(page, $0, fallback: fallback) }
    }

    /// Refuse to send a secret saved for an https site to an http page.
    public static func downgrade(_ page: String, _ item: LoginUrl) -> Bool {
        if item.match == .regex {
            func has(_ pattern: String, _ s: String) -> Bool {
                s.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
            }
            return has("^http:", page) && !has("^https?://localhost[:/]", page) && has("^\\^?https:", item.url)
        }
        guard let p = parse(page), let u = parse(item.url) else { return false }
        return u.scheme == "https" && p.scheme == "http" && p.hostname != "localhost"
    }
}
