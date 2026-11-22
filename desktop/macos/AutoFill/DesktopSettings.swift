import Foundation
import PassAuthKit

/// AutoFill settings shared with the desktop app on this Mac (its Settings → This app → "AutoFill on this
/// Mac"; `autofill_settings_*` in desktop/src-tauri/src/autofill_settings.rs). One Keychain item in this
/// extension's access group holds `{"defaultMatch":"host","changedAt":<unix ms>,"fillSingleMatch":true,
/// "suggestAllLogins":false}` (the two switches since 0.15.10; older items lack them); both sides write all of it
/// when the user changes any of these there, and the newer change wins (`defaultMatchChangedAt` is its time). On every request the extension
/// reconciles: it takes a newer desktop change, and writes its own value back when the item is missing,
/// unreadable or older, so the desktop always shows what AutoFill uses.
enum DesktopSettings {
    struct Adoption: Equatable {
        let match: UrlMatch
        let changedAt: Int64
        /// Absent in items written before 0.15.10: the extension keeps its own value.
        var fillSingleMatch: Bool? = nil
        var suggestAllLogins: Bool? = nil
    }

    private struct Shared: Codable {
        let defaultMatch: String
        let changedAt: Int64
        var fillSingleMatch: Bool?
        var suggestAllLogins: Bool?
    }

    /// The values the "Default URI match detection" picker offers (never `.default`).
    static let matches: [UrlMatch] = [.domain, .host, .startsWith, .regex, .exact, .never]

    /// The desktop's setting to adopt: only well-formed data naming a known match, changed after this
    /// extension's own last change.
    static func adoption(_ data: Data?, ownChangedAt: Int64) -> Adoption? {
        guard let data, let s = try? JSONDecoder().decode(Shared.self, from: data),
              let match = UrlMatch(rawValue: s.defaultMatch), matches.contains(match),
              s.changedAt > ownChangedAt
        else { return nil }
        return Adoption(match: match, changedAt: s.changedAt, fillSingleMatch: s.fillSingleMatch, suggestAllLogins: s.suggestAllLogins)
    }

    enum Action: Equatable {
        case adopt(Adoption)
        case publish(UrlMatch, changedAt: Int64)
        case none
    }

    /// What to do with the shared item, given this extension's own setting and when it last changed.
    static func reconcile(_ data: Data?, own: UrlMatch, ownChangedAt: Int64, fillSingleMatch: Bool = true, suggestAllLogins: Bool = false) -> Action {
        if let a = adoption(data, ownChangedAt: ownChangedAt) { return .adopt(a) }
        if let data, let s = try? JSONDecoder().decode(Shared.self, from: data), s.changedAt == ownChangedAt,
           UrlMatch(rawValue: s.defaultMatch) == own, s.fillSingleMatch == fillSingleMatch, s.suggestAllLogins == suggestAllLogins {
            return .none
        }
        // Missing, unreadable, older (also after the clock went back) or without the switches: this extension's values.
        return .publish(own, changedAt: max(ownChangedAt, 1))
    }

    static func encode(_ match: UrlMatch, changedAt: Int64, fillSingleMatch: Bool = true, suggestAllLogins: Bool = false) -> Data {
        (try? JSONEncoder().encode(Shared(defaultMatch: match.rawValue, changedAt: changedAt, fillSingleMatch: fillSingleMatch, suggestAllLogins: suggestAllLogins))) ?? Data()
    }

    static func encode(_ s: Settings, changedAt: Int64) -> Data {
        encode(s.defaultMatch, changedAt: changedAt, fillSingleMatch: s.fillSingleMatch, suggestAllLogins: s.suggestAllLogins)
    }

    static func now() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded()) }

    /// On each request, after the state is loaded: take a newer change made in the desktop app (through
    /// `updateSettings`, which re-registers the AutoFill identities when the match changes), or tell the
    /// desktop app this extension's own value.
    @MainActor
    static func adopt(_ repo: VaultRepository) async {
        guard repo.store.loaded else { return }
        let settings = repo.state.settings
        switch reconcile(Keychain.readDesktopSettings(), own: settings.defaultMatch, ownChangedAt: settings.defaultMatchChangedAt,
                         fillSingleMatch: settings.fillSingleMatch, suggestAllLogins: settings.suggestAllLogins) {
        case .adopt(let a):
            await repo.updateSettings {
                $0.defaultMatch = a.match
                $0.defaultMatchChangedAt = a.changedAt
                if let v = a.fillSingleMatch { $0.fillSingleMatch = v }
                if let v = a.suggestAllLogins, v != $0.suggestAllLogins { $0.suggestAllLogins = v; $0.suggestAllLoginsChosen = true }
            }
            // An item without the switches: complete it with this extension's values.
            if a.fillSingleMatch == nil || a.suggestAllLogins == nil {
                Keychain.writeDesktopSettings(encode(repo.state.settings, changedAt: a.changedAt))
            }
        case .publish(_, let at):
            Keychain.writeDesktopSettings(encode(settings, changedAt: at))
        case .none:
            break
        }
    }

    /// The user picked a match in this extension's settings: keep it, and tell the desktop app (always,
    /// also when it's the value shown, so a stale desktop item is corrected).
    @MainActor
    static func set(_ match: UrlMatch, _ repo: VaultRepository) async {
        await set(repo) { $0.defaultMatch = match }
    }

    /// The user changed a shared setting (match or one of the two switches) in this extension's settings.
    @MainActor
    static func set(_ repo: VaultRepository, _ change: @escaping (inout Settings) -> Void) async {
        let at = now()
        await repo.updateSettings {
            change(&$0)
            $0.defaultMatchChangedAt = at
        }
        Keychain.writeDesktopSettings(encode(repo.state.settings, changedAt: at))
    }
}
