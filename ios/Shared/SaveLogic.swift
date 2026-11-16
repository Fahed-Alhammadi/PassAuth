import Foundation
import PassAuthCore

/// Saving logins from AutoFill (`ASSavePasswordRequest`, iOS 26.2): whether to offer it and
/// what it changes. The rule itself is the Rust core's (`planSave` / `chosenSaveTarget`, the
/// same in every PassAuth client); this file feeds it the logins that match the page and keeps
/// what is the app's own (when to offer saving, the sheet's wording, the items written). A
/// login already saved for the site is updated instead of saving a second one (same user name
/// → its password; a login of your own with only a password → its user name too; no user name
/// typed and one login of your own for the site → its password), otherwise a new login; never
/// when "Ask to save" is off or the site is on the never-save list (base domain). The server's
/// own web vault counts as any other site.
///
/// Shared vaults: anyone on the server can share a vault with this account (no consent needed)
/// and put a login for a site in it, even one with the user's own email as its user name. So a
/// login in a shared vault is never chosen by a rule: rule 1 only lists one with the typed user
/// name as an extra, unselected "Save in" choice (labelled with its vault, with a warning when
/// picked), and it is written to only when the user picks it there. The default place is always
/// the account's own vault: one of its logins, or a new login.
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
        case unchanged
        /// Nothing to save: no password.
        case noPassword

        public var isChange: Bool {
            switch self {
            case .create, .update: true
            case .unchanged, .noPassword: false
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

    /// The logins that match the page, in the matcher's order (regular expressions only from the
    /// user's own vaults, so a shared vault can't make its logins candidates for every site), and
    /// the core's plan for them: the rule (docs/ARCHITECTURE.md "Save rule") with "Save in"
    /// (`targets`: the user's own logins, then shared ones with the typed user name).
    private static func corePlan(page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch) -> (SavePlan, [String: Entry]) {
        let matching = AutofillMatcher.candidates([page], in: vault, defaultMatch: defaultMatch)
        let candidates = matching.map { e in
            SaveCandidate(id: e.id, name: e.item.name, username: e.item.login?.username ?? "", password: e.item.login?.password ?? "",
                          writable: vault.canWrite(e), personal: vault.isPersonal(e), vault: vault.sharedVaultName(e))
        }
        let byId = Dictionary(matching.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return (planSave(candidates: candidates, typedUser: username, password: password), byId)
    }

    private static func targetsOf(_ plan: SavePlan) -> [SaveTarget] {
        switch plan {
        case .none: []
        case .create(let targets), .update(_, _, let targets): targets
        }
    }

    /// What saving `username` / `password` on `page` does to the vault by default (the core's
    /// `planSave` over the logins that match the page):
    ///
    /// 0. No password → nothing to save.
    /// 1. Logins for the page with the typed user name (with no user name typed: the user's OWN
    ///    logins saved with only a password; "the same user name" proves nothing when both are
    ///    empty): one already has the password (in any vault) → unchanged; else the first in the
    ///    user's OWN vault → update it; none there (only shared or view-only ones) → a new login.
    ///    Shared ones the user can edit are only offered in "Save in" (`targets`).
    /// 2. None, and a user name was typed: a login in the user's OWN vault that has no user name
    ///    (only a password was saved) → update it, preferring the one with the typed password,
    ///    else the first; none → a new login.
    /// 3. None, and no user name was typed: the password is already saved for the page →
    ///    unchanged; exactly one login in the user's OWN vault → update it; otherwise → a new login.
    public static func plan(page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch) -> Plan {
        guard !password.isEmpty else { return .noPassword }
        let (plan, byId) = corePlan(page: page, username: username, password: password, vault: vault, defaultMatch: defaultMatch)
        switch plan {
        case .none:
            return .unchanged
        case .create:
            return .create
        case .update(let reason, let target, _):
            // Always one of the matching logins; anything else would be a new login.
            guard let e = byId[target] else { return .create }
            let why: Reason = switch reason {
            case .same: .same
            case .blank: .blank
            case .only: .only
            }
            return .update(e, why)
        }
    }

    /// "Save in": the logins for the page in the user's own vault, then the ones in shared vaults
    /// the user can edit that have the typed user name (rule 1's extra choices, never preselected;
    /// never for an empty user name). In the matcher's order; the sheet lists them above "New login".
    /// Empty when there is nothing to save.
    public static func targets(page: String, username: String, password: String, vault: VaultData, defaultMatch: UrlMatch) -> [Entry] {
        let (plan, byId) = corePlan(page: page, username: username, password: password, vault: vault, defaultMatch: defaultMatch)
        return targetsOf(plan).compactMap { byId[$0.id] }
    }

    /// The sheet's warning for a "Save in" choice in a shared vault (nil for the user's own vault
    /// or a new login).
    public static func sharedWarning(_ e: Entry?, in vault: VaultData) -> String? {
        guard let e, let name = vault.sharedVaultName(e) else { return nil }
        return "Saving here shares this password with everyone in \(name)."
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
        // Only a login this save offers (the core's `chosenSaveTarget`): never one worked out again.
        let (plan, byId) = corePlan(page: page, username: username, password: password, vault: vault, defaultMatch: defaultMatch)
        guard let id = chosenSaveTarget(targets: targetsOf(plan), answer: target), let e = byId[id] else { return nil }
        let user = norm(username)
        let sameUser = norm(e.item.login?.username) == user
        if (sameUser || user.isEmpty) && e.item.login?.password == password { return .unchanged }
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
