import Foundation

/// Saving logins from AutoFill (`ASSavePasswordRequest`, iOS 26.2): whether to offer it and
/// what it changes. The same rule in every PassAuth client: a login already saved for the site
/// is updated instead of saving a second one (same user name → its password; a login of your
/// own with only a password → its user name too; no user name typed and one login of your own
/// for the site → its password), otherwise a new login; never when "Ask to save" is off or the
/// site is on the never-save list (base domain). The server's own web vault counts as any other
/// site.
///
/// Shared vaults: anyone on the server can share a vault with this account and put a login
/// for a site in it. Such a login is only ever updated when it has the exact user name that
/// was typed (rule 1). The looser rules 2 and 3 use logins in the account's own vault only, so
/// a planted login can't become the place a typed user name and password are written to.
public enum SaveLogic {
    public enum Blocked: Equatable, Sendable {
        case askToSaveOff, neverSave, notWebsite, noPassword
    }

    /// Which rule made an update the default.
    public enum Reason: Equatable, Sendable {
        /// Rule 1: the login has the typed user name.
        case same
        /// Rule 2: a login of your own that was saved with only a password.
        case blank
        /// Rule 3: no user name was typed and it is your only login for the site. Never applied
        /// without the sheet (the user sees which login changes).
        case only
        /// No rule: the user chose this login in "Save in".
        case picked
    }

    public enum Plan: Sendable {
        /// A new login for the site.
        case create
        /// A login for the site gets the typed password (and the typed user name, if one was typed).
        case update(Entry, Reason)
        /// Already saved with this password.
        case unchanged(Entry)
        /// Same site and user name, but in a vault the user can only view.
        case readOnly(Entry)
        /// Nothing to save: no password.
        case noPassword

        public var isChange: Bool {
            switch self {
            case .create, .update: true
            case .unchanged, .readOnly, .noPassword: false
            }
        }
    }

    /// "Save in" choice meaning a new login (never an item id: those are UUIDs).
    public static let newLogin = "new"

    /// The never-save key of a page: its base domain.
    public static func neverSaveKey(_ page: String) -> String? {
        guard let p = UrlMatcher.parse(page), !p.hostname.isEmpty else { return nil }
        return UrlMatcher.baseDomain(p.hostname)
    }

    /// Why not to offer saving (nil: offer it). `page` is from `AutofillMatcher.page`.
    public static func blocked(page: String?, password: String, settings: Settings) -> Blocked? {
        guard settings.askToSave else { return .askToSaveOff }
        guard let page, let key = neverSaveKey(page) else { return .notWebsite }
        if settings.neverSave.contains(key) { return .neverSave }
        if password.isEmpty { return .noPassword }
        return nil
    }

    private static func norm(_ s: String?) -> String {
        (s ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// The logins that match the page, in the matcher's order.
    private static func matching(_ page: String, _ vault: VaultData, _ defaultMatch: UrlMatch) -> [Entry] {
        AutofillMatcher.candidates([page], vault.entries, defaultMatch: defaultMatch)
    }

    /// What saving `username` / `password` on `page` does to the vault by default.
    ///
    /// 0. No password → nothing to save.
    /// 1. Logins for the page with the typed user name (`same`; with no user name typed these
    ///    are the logins saved with only a password): one already has the password → unchanged;
    ///    else one the user can edit → update it; else (view-only) → nothing to save. With no
    ///    user name typed only logins in the user's OWN vault are updated this way: "the same
    ///    user name" proves nothing when both are empty, and a login without a user name is
    ///    exactly what somebody could plant in a shared vault.
    /// 2. None, and a user name was typed: a login in the user's OWN vault that has no user name
    ///    (only a password was saved) → update it, preferring the one with the typed password,
    ///    else the first; none → a new login.
    /// 3. None, and no user name was typed: the password is already saved for the page →
    ///    unchanged; exactly one login in the user's OWN vault → update it; otherwise → a new login.
    public static func plan(page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch) -> Plan {
        guard !password.isEmpty else { return .noPassword }
        let user = norm(username)
        let all = matching(page, vault, defaultMatch)
        let same = all.filter { norm($0.item.login?.username) == user }
        if let e = same.first(where: { $0.item.login?.password == password }) { return .unchanged(e) }
        let trusted = user.isEmpty ? same.filter(vault.isOwn) : same
        if let e = trusted.first(where: vault.canWrite) { return .update(e, .same) }
        if let e = trusted.first { return .readOnly(e) }
        let own = all.filter(vault.isOwn)
        if !user.isEmpty {
            let bare = own.filter { norm($0.item.login?.username).isEmpty }
            if let e = bare.first(where: { $0.item.login?.password == password }) ?? bare.first { return .update(e, .blank) }
            return .create
        }
        if let e = all.first(where: { $0.item.login?.password == password }) { return .unchanged(e) }
        return own.count == 1 ? .update(own[0], .only) : .create
    }

    /// "Save in": the logins for the page in the user's own vault, plus the login rule 1
    /// preselects when that one is in a shared vault (so the sheet can show it as the selection,
    /// with its vault's name). In the matcher's order; the sheet lists them above "New login".
    public static func targets(page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch) -> [Entry] {
        var shared: String?
        if case .update(let e, .same) = plan(page: page, username: username, password: password, vault: vault, defaultMatch: defaultMatch), !vault.isOwn(e) {
            shared = e.id
        }
        return matching(page, vault, defaultMatch).filter { vault.isOwn($0) || $0.id == shared }
    }

    /// The preselected "Save in" choice of a plan: the login it updates, else a new login.
    public static func defaultTarget(_ plan: Plan) -> String {
        if case .update(let e, _) = plan { return e.id }
        return newLogin
    }

    /// What saving does with the "Save in" choice (an entry id or `newLogin`); nil when that id
    /// is not one of `targets` (any more). A chosen login that already has the typed user name
    /// (or none was typed) and password is unchanged.
    public static func plan(target: String, page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch) -> Plan? {
        guard !password.isEmpty else { return .noPassword }
        if target == newLogin { return .create }
        let offered = targets(page: page, username: username, password: password, vault: vault, defaultMatch: defaultMatch)
        guard let e = offered.first(where: { $0.id == target }) else { return nil }
        let user = norm(username)
        let sameUser = norm(e.item.login?.username) == user
        if (sameUser || user.isEmpty) && e.item.login?.password == password { return .unchanged(e) }
        return .update(e, sameUser ? .same : norm(e.item.login?.username).isEmpty ? .blank : .picked)
    }

    /// The new login: named after the host (without "www."), website = the page's origin
    /// (`https://<domain>` for an app's associated domain), URL match "Default".
    public static func newItem(page: String, username: String, password: String) -> Item {
        let p = UrlMatcher.parse(page)
        var host = p?.hostname ?? page
        if host.hasPrefix("www.") { host.removeFirst(4) }
        let login = Login(username: username.trimmingCharacters(in: .whitespacesAndNewlines), password: password,
                          urls: [LoginUrl(url: p?.origin ?? page, match: .default)])
        return Item(name: host, login: login)
    }

    /// The login with the typed password, and the typed user name unless none was typed (as in
    /// every PassAuth client). Everything else is untouched; `VaultRepository.updateItem` adds
    /// the old password to the history.
    public static func updatedItem(_ e: Entry, username: String, password: String) -> Item {
        var item = e.item
        item.login?.password = password
        let typed = username.trimmingCharacters(in: .whitespacesAndNewlines)
        if !typed.isEmpty { item.login?.username = typed }
        return item
    }
}
