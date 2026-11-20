import AuthenticationServices
import Foundation

/// Which logins AutoFill may offer for what iOS asks about. iOS hands the credential provider
/// service identifiers: a page URL (Safari, `.URL`, full address) or a domain (apps with
/// associated domains, `.domain`). The same rules as every PassAuth client for web content (the
/// Rust core's site logic through `UrlMatcher`, with the default-match setting): a domain without
/// scheme is taken as `https://<domain>/` (so "exact" / "starts with" see that), app websites
/// (`androidapp://…`) never match and an https login is never offered on an http page.
/// The PassAuth server's own web vault is an ordinary website: a login saved for the server's
/// address is offered on its sign-in page. A website that is a regular expression counts only for
/// logins in the user's own vaults: one in a vault somebody shared was written by somebody else,
/// who could make it slow or match every site (the extension's `allowRegex` rule).
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

    /// May `login` be offered on `page`? `allowRegex`: the login is in one of the user's own
    /// vaults (`VaultData.isPersonal`), the only place its regular expressions count. The core
    /// matches all its websites in one call (app addresses never match a page).
    public static func matches(_ page: String, _ login: Login, defaultMatch: UrlMatch, allowRegex: Bool) -> Bool {
        UrlMatcher.matchesAny(page, login, fallback: defaultMatch, allowRegex: allowRegex)
            && !login.urls.contains { UrlMatcher.downgrade(page, $0) }
    }

    /// The vault's logins matching the pages (first page's matches first), no duplicates.
    public static func candidates(_ pages: [String], in vault: VaultData, defaultMatch: UrlMatch) -> [Entry] {
        var out: [Entry] = []
        var seen = Set<String>()
        for page in pages {
            for e in vault.entries {
                guard let l = e.item.login, !seen.contains(e.id),
                      matches(page, l, defaultMatch: defaultMatch, allowRegex: vault.isPersonal(e)) else { continue }
                seen.insert(e.id)
                out.append(e)
            }
        }
        return out
    }

    /// Search over all logins: the apps' one item search (`ItemSearch`), every website included.
    public static func search(_ query: String, _ entries: [Entry]) -> [Entry] {
        ItemSearch.search(entries.filter { $0.item.login != nil }, query)
    }
}
