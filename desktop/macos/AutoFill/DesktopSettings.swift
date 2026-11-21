import Foundation
import PassAuthKit

/// AutoFill settings shared with the desktop app on this Mac (its Settings → This app → "AutoFill on this
/// Mac"; `autofill_settings_*` in desktop/src-tauri/src/autofill_settings.rs). One Keychain item in this
/// extension's access group holds `{"defaultMatch":"host","changedAt":<unix ms>}`; both sides write it when
/// the user changes the setting there, and the newer change wins. On every request the extension
/// reconciles: it takes a newer desktop change, and writes its own value back when the item is missing,
/// unreadable or older, so the desktop always shows what AutoFill uses.
enum DesktopSettings {
    struct Adoption: Equatable {
        let match: UrlMatch
        let changedAt: Int64
    }

    private struct Shared: Codable {
        let defaultMatch: String
        let changedAt: Int64
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
        return Adoption(match: match, changedAt: s.changedAt)
    }

    enum Action: Equatable {
        case adopt(Adoption)
        case publish(UrlMatch, changedAt: Int64)
        case none
    }

    /// What to do with the shared item, given this extension's own setting and when it last changed.
    static func reconcile(_ data: Data?, own: UrlMatch, ownChangedAt: Int64) -> Action {
        if let a = adoption(data, ownChangedAt: ownChangedAt) { return .adopt(a) }
        if let data, let s = try? JSONDecoder().decode(Shared.self, from: data), s.changedAt == ownChangedAt,
           UrlMatch(rawValue: s.defaultMatch) == own {
            return .none
        }
        // Missing, unreadable or older (also after the clock went back): this extension's value.
        return .publish(own, changedAt: max(ownChangedAt, 1))
    }

    static func encode(_ match: UrlMatch, changedAt: Int64) -> Data {
        (try? JSONEncoder().encode(Shared(defaultMatch: match.rawValue, changedAt: changedAt))) ?? Data()
    }

    static func now() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded()) }

    /// On each request, after the state is loaded: take a newer change made in the desktop app (through
    /// `updateSettings`, which re-registers the AutoFill identities when the match changes), or tell the
    /// desktop app this extension's own value.
    @MainActor
    static func adopt(_ repo: VaultRepository) async {
        guard repo.store.loaded else { return }
        let settings = repo.state.settings
        switch reconcile(Keychain.readDesktopSettings(), own: settings.defaultMatch, ownChangedAt: settings.defaultMatchChangedAt) {
        case .adopt(let a):
            await repo.updateSettings {
                $0.defaultMatch = a.match
                $0.defaultMatchChangedAt = a.changedAt
            }
        case .publish(let match, let at):
            Keychain.writeDesktopSettings(encode(match, changedAt: at))
        case .none:
            break
        }
    }

    /// The user picked a match in this extension's settings: keep it, and tell the desktop app (always,
    /// also when it's the value shown, so a stale desktop item is corrected).
    @MainActor
    static func set(_ match: UrlMatch, _ repo: VaultRepository) async {
        let at = now()
        await repo.updateSettings {
            $0.defaultMatch = match
            $0.defaultMatchChangedAt = at
        }
        Keychain.writeDesktopSettings(encode(match, changedAt: at))
    }
}
