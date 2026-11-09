import AuthenticationServices
import Foundation

/// Which logins AutoFill may offer for what iOS asks about. iOS hands the credential provider
/// service identifiers: a page URL (Safari, `.URL`, full address) or a domain (apps with
/// associated domains, `.domain`). Same rules as the extension and the Android app's
/// `AutofillMatcher` for web content: `UrlMatcher` with the default-match setting, a domain
/// without scheme is taken as `https://<domain>/` (so "exact" / "starts with" see that), app
/// websites (`androidapp://…`) never match and an https login is never offered on an http page.
/// The PassAuth server's own web vault is an ordinary website: a login saved for the server's
/// address is offered on its sign-in page.
public enum AutofillMatcher {
    public static let androidAppScheme = "androidapp://"

    /// The page address used for matching, or nil for identifiers that can't be matched.
    public static func page(_ identifier: String, isURL: Bool) -> String? {
        let raw = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return nil }
        if isURL {
            let text = raw.contains("://") ? raw : "https://" + raw
            guard let p = UrlMatcher.parse(text), p.scheme == "http" || p.scheme == "https", !p.hostname.isEmpty else { return nil }
            return text
        }
        var domain = raw.lowercased()
        while domain.hasSuffix(".") { domain.removeLast() }
        guard !domain.isEmpty, !domain.contains("/"), !domain.contains("://") else { return nil }
        let text = "https://\(domain)/"
        return UrlMatcher.parse(text) == nil ? nil : text
    }

    public static func page(_ id: ASCredentialServiceIdentifier) -> String? {
        switch id.type {
        case .URL: page(id.identifier, isURL: true)
        case .domain: page(id.identifier, isURL: false)
        default: nil // App IDs (iOS 26.2) aren't websites.
        }
    }

    /// The pages for the identifiers, most specific (lowest index) first, without duplicates.
    public static func pages(_ ids: [ASCredentialServiceIdentifier]) -> [String] {
        var seen = Set<String>()
        return ids.compactMap(page).filter { seen.insert($0).inserted }
    }

    /// Host shown in the list ("Suggestions for …").
    public static func displayHost(_ page: String) -> String {
        UrlMatcher.parse(page)?.host ?? page
    }

    public static func isAppUrl(_ u: LoginUrl) -> Bool {
        u.url.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix(androidAppScheme)
    }

    /// May `login` be offered on `page`?
    public static func matches(_ page: String, _ login: Login, defaultMatch: UrlMatch) -> Bool {
        login.urls.contains { !isAppUrl($0) && UrlMatcher.matches(page, $0, fallback: defaultMatch) }
            && !login.urls.contains { UrlMatcher.downgrade(page, $0) }
    }

    /// Matching logins for the pages (first page's matches first), no duplicates.
    public static func candidates(_ pages: [String], _ entries: [Entry], defaultMatch: UrlMatch) -> [Entry] {
        var out: [Entry] = []
        var seen = Set<String>()
        for page in pages {
            for e in entries {
                guard let l = e.item.login, !seen.contains(e.id), matches(page, l, defaultMatch: defaultMatch) else { continue }
                seen.insert(e.id)
                out.append(e)
            }
        }
        return out
    }

    /// Search over all logins (name, username, websites).
    public static func search(_ query: String, _ entries: [Entry]) -> [Entry] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let logins = entries.filter { $0.item.login != nil }
        guard !q.isEmpty else { return logins }
        return logins.filter { e in
            e.item.name.lowercased().contains(q)
                || (e.item.login?.username.lowercased().contains(q) ?? false)
                || (e.item.login?.urls.contains { $0.url.lowercased().contains(q) } ?? false)
        }
    }
}
