import Foundation
import PassAuthKit

/// When the macOS AutoFill extension may reopen the vault from kept keys (pure logic, tested
/// in `desktop/macos/Tests`). macOS starts the extension anew for most requests, so the vault
/// timeout can't be a timer in memory: the unlocked keys stay in the extension's Keychain with
/// a deadline that moves forward each time they are used.
enum TimedUnlockPolicy {
    /// The kept keys of one account.
    struct Record: Codable, Equatable {
        /// The local account id the keys belong to.
        var account: String
        /// Unix seconds after which the keys are not used any more.
        var until: Int64
        /// Session bytes (base64), as the timeout "Never" keeps them.
        var keys: String
    }

    /// Timeouts offered on macOS: "On app restart" has no meaning for an extension.
    static let choices: [VaultTimeout] = VaultTimeout.allCases.filter { $0 != .restart }

    /// Seconds of inactivity the keys are kept for; nil when nothing is kept this way
    /// ("Immediately" asks every time, "Never" is kept by the repository itself).
    static func keepSeconds(_ timeout: VaultTimeout) -> Int64? {
        guard let m = timeout.minutes, m > 0 else { return nil }
        return Int64(m) * 60
    }

    static func record(account: String, keys: String, timeout: VaultTimeout, now: Int64) -> Record? {
        guard let s = keepSeconds(timeout), !account.isEmpty, !keys.isEmpty else { return nil }
        return Record(account: account, until: now + s, keys: keys)
    }

    /// The kept keys must be deleted now: no readable deadline, the deadline passed, the
    /// timeout keeps nothing, or the deadline is further away than the current timeout allows.
    /// Checked from the deadline alone (stored apart from the keys) at the end of every request
    /// and when the configuration screen opens.
    static func stale(until: Int64?, timeout: VaultTimeout, now: Int64) -> Bool {
        guard let until, let s = keepSeconds(timeout) else { return true }
        return now >= until || until - now > s
    }

    /// The record still opens the vault: same account, deadline not passed, and not further
    /// away than the current timeout allows (the user may have shortened it meanwhile).
    static func usable(_ r: Record, account: String, timeout: VaultTimeout, now: Int64) -> Bool {
        guard r.account == account, !r.keys.isEmpty else { return false }
        return !stale(until: r.until, timeout: timeout, now: now)
    }
}
