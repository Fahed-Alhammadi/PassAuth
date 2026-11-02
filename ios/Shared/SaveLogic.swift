import Foundation

/// Saving logins from AutoFill (`ASSavePasswordRequest`, iOS 26.2): whether to offer it and
/// what it changes. The same rules as the extension's `onSubmitted` and Android's
/// `onSaveRequest`: same site + user name → update that login's password (the old one goes to
/// the password history), otherwise a new login; never when "Ask to save" is off, the site is
/// on the never-save list (base domain), or on the PassAuth server's own web vault.
public enum SaveLogic {
    public enum Blocked: Equatable, Sendable {
        case askToSaveOff, neverSave, vaultPage, notWebsite, noPassword
    }

    public enum Plan: Sendable {
        /// A new login for the site.
        case create
        /// Same site and user name, different password.
        case update(Entry)
        /// Already saved with this password.
        case unchanged(Entry)
        /// Same site and user name, but in a vault the user can only view.
        case readOnly(Entry)

        public var isChange: Bool {
            switch self {
            case .create, .update: true
            case .unchanged, .readOnly: false
            }
        }
    }

    /// The never-save key of a page: its base domain.
    public static func neverSaveKey(_ page: String) -> String? {
        guard let p = UrlMatcher.parse(page), !p.hostname.isEmpty else { return nil }
        return UrlMatcher.baseDomain(p.hostname)
    }

    /// Why not to offer saving (nil: offer it). `page` is from `AutofillMatcher.page`.
    public static func blocked(page: String?, password: String, settings: Settings, server: String) -> Blocked? {
        guard settings.askToSave else { return .askToSaveOff }
        guard let page, let key = neverSaveKey(page) else { return .notWebsite }
        if AutofillMatcher.isVaultPage(page, server: server) { return .vaultPage }
        if settings.neverSave.contains(key) { return .neverSave }
        if password.isEmpty { return .noPassword }
        return nil
    }

    /// What saving `username` / `password` on `page` does to the vault.
    public static func plan(page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch, server: String) -> Plan {
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let same = AutofillMatcher.candidates([page], vault.entries, defaultMatch: defaultMatch, server: server)
            .filter { ($0.item.login?.username ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == user }
        if let e = same.first(where: { $0.item.login?.password == password }) { return .unchanged(e) }
        if let e = same.first(where: vault.canWrite) { return .update(e) }
        if let e = same.first { return .readOnly(e) }
        return .create
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

    /// The login with the new password (`VaultRepository.updateItem` adds the old one to the history).
    public static func updatedItem(_ e: Entry, password: String) -> Item {
        var item = e.item
        item.login?.password = password
        return item
    }
}
