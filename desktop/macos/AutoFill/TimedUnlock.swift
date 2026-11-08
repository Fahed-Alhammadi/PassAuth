import Foundation
import PassAuthKit

/// Keeps the unlocked keys in the extension's Keychain (this device only, its own access group)
/// until the vault timeout passes, so the next AutoFill request within it doesn't ask again.
/// The deadline is a separate item without secrets, so expired keys are found and deleted
/// without reading them: at the end of every request, when the configuration screen opens, on
/// restore, lock and sign out.
@MainActor
enum TimedUnlock {
    private static let item = "timedUnlock"
    private static let deadlineItem = "timedUnlockUntil"

    private static var now: Int64 { Int64(Date().timeIntervalSince1970) }

    /// After an unlock (and each use): keep the keys until the timeout passes from now.
    static func keep(_ repo: VaultRepository) {
        let s = repo.state
        guard TimedUnlockPolicy.keepSeconds(s.settings.vaultTimeout) != nil, var bytes = repo.activeSessionBytes() else {
            return forget()
        }
        let keys = bytes.base64EncodedString()
        bytes.resetBytes(in: 0..<bytes.count)
        guard let r = TimedUnlockPolicy.record(account: s.activeId, keys: keys, timeout: s.settings.vaultTimeout, now: now),
              let data = try? JSONEncoder().encode(r) else { return forget() }
        // Deadline first: keys never exist without a readable deadline.
        guard Keychain.write(deadlineItem, Data(String(r.until).utf8)), Keychain.write(item, data) else { return forget() }
    }

    /// Reopen the active account from kept keys that are still within the timeout.
    static func restore(_ repo: VaultRepository) async -> Bool {
        purgeExpired(repo)
        guard let data = Keychain.read(item), let r = try? JSONDecoder().decode(TimedUnlockPolicy.Record.self, from: data) else { return false }
        let s = repo.state
        guard s.status == .locked, TimedUnlockPolicy.usable(r, account: s.activeId, timeout: s.settings.vaultTimeout, now: now),
              var bytes = Data(base64Encoded: r.keys) else {
            forget()
            return false
        }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard await repo.openActive(sessionBytes: bytes) else {
            forget()
            return false
        }
        keep(repo) // Used now: the timeout counts from here.
        return true
    }

    /// Delete the kept keys if their deadline passed (or can't be read), from the deadline alone.
    static func purgeExpired(_ repo: VaultRepository) {
        let until = Keychain.read(deadlineItem).flatMap { Int64(String(decoding: $0, as: UTF8.self)) }
        if TimedUnlockPolicy.stale(until: until, timeout: repo.state.settings.vaultTimeout, now: now) { forget() }
    }

    static func forget() {
        Keychain.delete(item)
        Keychain.delete(deadlineItem)
    }
}
