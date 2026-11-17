import Foundation

/// "Add this site to a login": one account that signs in on several sites (a mail login also
/// used on another domain of the same company). The page's address is added as one more website
/// of a login the user picks, so that login is suggested and filled there from now on instead of
/// a second copy being saved. The same rules as the browser extension:
///
/// - Only web pages (http/https with a host); app-only identifiers never get it.
/// - Only logins the user can edit, and only those none of whose websites already match the
///   page (with the user's default match; regular expressions only for the user's own vaults).
/// - The address added is the page's origin (`https://host`) with match "Default", the same as
///   a login saved from the page. Nothing else changes (user name, password, history).
/// - The save sheet offers it only when nothing for the site can be updated (`SaveLogic.targets`
///   is empty), and only for logins in the user's OWN vault with exactly the typed user name
///   (trimmed, case-insensitive) and password: the same account, used on one more site. Never
///   preselected ("New login" stays selected); at most `maxSameAccount` rows.
public enum AddSite {
    public static let maxSameAccount = 3

    public enum Outcome: Equatable, Sendable {
        /// The page's origin was added to the login.
        case added
        /// One of the login's websites already matched the page: nothing changed.
        case alreadyMatched
    }

    /// The page's origin (`https://host[:port]`) when it is an http(s) page, else nil.
    public static func origin(_ page: String) -> String? {
        guard let p = UrlMatcher.parse(page), p.scheme == "http" || p.scheme == "https", !p.hostname.isEmpty else { return nil }
        return p.origin
    }

    /// Does one of the login's websites already match the page?
    public static func alreadyMatches(_ login: Login, page: String, defaultMatch: UrlMatch, allowRegex: Bool) -> Bool {
        UrlMatcher.matchesAny(page, login, fallback: defaultMatch, allowRegex: allowRegex)
    }

    /// The item with `origin` added to its login's websites (match "Default").
    public static func withSite(_ item: Item, origin: String) -> Item {
        var next = item
        next.login?.urls.append(LoginUrl(url: origin, match: .default))
        return next
    }

    /// What adding the page to `entry` changes: nil when it already matches the page, else the
    /// updated item. Nil too for a page that isn't a website or an entry without a login.
    public static func updated(_ e: Entry, page: String, vault: VaultData, defaultMatch: UrlMatch) -> Item? {
        guard let origin = origin(page), let login = e.item.login,
              !alreadyMatches(login, page: page, defaultMatch: defaultMatch, allowRegex: vault.isPersonal(e)) else { return nil }
        return withSite(e.item, origin: origin)
    }

    /// The logins the page can be added to: editable, with a login, none of their websites
    /// matching the page yet. The user's own vaults first, otherwise in vault order.
    public static func targets(page: String, vault: VaultData, defaultMatch: UrlMatch) -> [Entry] {
        guard origin(page) != nil else { return [] }
        let eligible = vault.entries.filter { e in
            guard let login = e.item.login, vault.canWrite(e) else { return false }
            return !alreadyMatches(login, page: page, defaultMatch: defaultMatch, allowRegex: vault.isPersonal(e))
        }
        return eligible.filter { vault.isPersonal($0) } + eligible.filter { !vault.isPersonal($0) }
    }

    /// The save sheet's extra rows: the user's OWN logins (personal vault, editable) for other
    /// sites saved with exactly the typed user name and password. Both must be typed: a password
    /// alone says nothing about the account. Only when the save has no login to update for the
    /// site (`saveTargets` empty); at most `maxSameAccount`.
    public static func sameAccountElsewhere(page: String, username: String, password: String, saveTargets: [Entry], vault: VaultData,
                                            defaultMatch: UrlMatch) -> [Entry] {
        let user = norm(username)
        guard saveTargets.isEmpty, !user.isEmpty, !password.isEmpty, origin(page) != nil else { return [] }
        var out: [Entry] = []
        for e in vault.entries where out.count < maxSameAccount {
            guard let login = e.item.login, vault.isOwn(e), login.password == password, norm(login.username) == user,
                  !alreadyMatches(login, page: page, defaultMatch: defaultMatch, allowRegex: true) else { continue }
            out.append(e)
        }
        return out
    }

    /// Is `e` (still) a login the typed credentials may be added to from the save sheet?
    public static func isSameAccount(_ e: Entry, username: String, password: String, vault: VaultData) -> Bool {
        guard let login = e.item.login, vault.isOwn(e) else { return false }
        return !password.isEmpty && login.password == password && norm(login.username) == norm(username) && !norm(username).isEmpty
    }

    /// The login's own site ("gmail.com"): the host of its first website that is one (without
    /// "www."); "" when it has none.
    public static func site(_ e: Entry) -> String {
        for u in e.item.login?.urls ?? [] where !AutofillMatcher.isAppUrl(u) {
            guard let p = UrlMatcher.parse(u.url), p.scheme == "http" || p.scheme == "https", !p.hostname.isEmpty else { continue }
            return p.hostname.hasPrefix("www.") ? String(p.hostname.dropFirst(4)) : p.hostname
        }
        return ""
    }

    /// The name shown for the login (its name, else its site).
    public static func name(_ e: Entry) -> String {
        if !e.item.name.isEmpty { return e.item.name }
        let s = site(e)
        return s.isEmpty ? "Login" : s
    }

    // MARK: Words (the same as the extension)

    /// The save sheet's note while such a login is selected.
    public static func describe(_ e: Entry, host: String) -> String {
        "Adds \(host) to \(name(e)). Its user name and password stay the same, and it is suggested here from now on."
    }

    /// The save sheet's warning while such a login is selected.
    public static func warning(_ e: Entry, host: String) -> String {
        let s = site(e)
        return s.isEmpty ? "Only add it if this site uses the same account." : "Only add it if \(host) uses the same account as \(s)."
    }

    /// The picker's confirmation text.
    public static func confirmText(_ e: Entry, host: String) -> String {
        let s = site(e)
        return "\(name(e)) will be suggested and filled on \(host). Its user name and password stay the same. Add a site only when it uses the same account\(s.isEmpty ? "" : " as \(s)")."
    }

    /// The picker's warning for a login in a shared vault: its members see the new website.
    public static func sharedWarning(_ e: Entry, in vault: VaultData) -> String? {
        vault.sharedVaultName(e).map { "This login is in \($0): everyone in that vault sees the new website." }
    }

    private static func norm(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
