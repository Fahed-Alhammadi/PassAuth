import Foundation

// Account policies set by the server's admin (servers with the `policies` feature: `GET
// /api/config` `policies`, and `GET /account` `policy_violations` for what an account still has
// to change; server side `crates/server/src/policies.rs`), and what the app does with them, as
// the web vault's `policies.ts` (pure, unit-tested in `PolicyTests`).
//
// Enforced by the server: two-step login (403 `two_step_required` on everything but setting a
// method up, reading the account and signing out), a Secret Key and the key-derivation minimums
// for new account keys (400 `secret_key_required` / `kdf_too_weak`). Applied by the app: the
// master password length, the longest vault timeout and export. Servers without the feature send
// no policies: every value then has its default, which changes nothing.

/// The `/api/config` feature of servers with account policies.
public let policiesFeature = "policies"

public struct Policies: Codable, Equatable, Sendable {
    /// Every account must use two-step login.
    public var requireTwoStep = false
    /// New account keys (registration, master password or Secret Key change) must use a Secret Key.
    public var requireSecretKey = false
    /// Least Argon2id memory (MiB) and passes for new account keys.
    public var minKdfMemoryMib = 64
    public var minKdfIterations = 3
    /// Shortest new master password the apps accept; never below the apps' own 10.
    public var masterPasswordMinLength = PolicyRules.minMasterPassword
    /// Longest vault timeout the apps offer, in minutes; 0 = no limit.
    public var maxVaultTimeoutMinutes = 0
    /// The apps don't offer exporting the vault.
    public var disableExport = false

    public init() {}

    /// The server's policies (`/api/config` `policies`), with the defaults for a value it didn't
    /// send or that isn't a whole number in range (clamped like the web vault's `readPolicies`).
    public init(json: JSON?) {
        let d = Policies()
        guard let j = json, case .object = j else { self = d; return }
        func whole(_ key: String, _ min: Int, _ max: Int, _ fallback: Int) -> Int {
            let n: Int64?
            switch j[key] {
            case .int(let i)?: n = i
            case .double(let x)? where x.isFinite && x == x.rounded() && abs(x) < 1e15: n = Int64(x)
            default: n = nil
            }
            guard let n else { return fallback }
            return Int(Swift.min(Int64(max), Swift.max(Int64(min), n)))
        }
        requireTwoStep = j["require_two_step"] == .bool(true)
        requireSecretKey = j["require_secret_key"] == .bool(true)
        minKdfMemoryMib = whole("min_kdf_memory_mib", d.minKdfMemoryMib, 1024, d.minKdfMemoryMib)
        minKdfIterations = whole("min_kdf_iterations", d.minKdfIterations, 20, d.minKdfIterations)
        masterPasswordMinLength = whole("master_password_min_length", PolicyRules.minMasterPassword, 128, PolicyRules.minMasterPassword)
        maxVaultTimeoutMinutes = whole("max_vault_timeout_minutes", 0, PolicyRules.maxTimeoutMinutes, 0)
        disableExport = j["disable_export"] == .bool(true)
    }

    /// Stored files may be older or newer than this app: unknown or missing values are defaults.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Policies()
        requireTwoStep = c.lenient(.requireTwoStep, d.requireTwoStep)
        requireSecretKey = c.lenient(.requireSecretKey, d.requireSecretKey)
        minKdfMemoryMib = c.lenient(.minKdfMemoryMib, d.minKdfMemoryMib)
        minKdfIterations = c.lenient(.minKdfIterations, d.minKdfIterations)
        masterPasswordMinLength = c.lenient(.masterPasswordMinLength, d.masterPasswordMinLength)
        maxVaultTimeoutMinutes = c.lenient(.maxVaultTimeoutMinutes, d.maxVaultTimeoutMinutes)
        disableExport = c.lenient(.disableExport, d.disableExport)
    }
}

/// What an account still has to change for the server's policies (`GET /account` `policy_violations`).
public enum PolicyViolation: String, Codable, CaseIterable, Sendable {
    case twoStep = "two_step"
    case secretKey = "secret_key"
    case kdf
}

/// Where a policy notice sends the user (Settings → Account security).
public enum PolicyAction: String, Equatable, Sendable, Identifiable {
    case setUpTwoStep, turnOnSecretKey, changePassword

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .setUpTwoStep: "Set up two-step login"
        case .turnOnSecretKey: "Turn on a Secret Key"
        case .changePassword: "Change master password"
        }
    }
}

public struct PolicyNotice: Equatable, Sendable, Identifiable {
    public var id: String { violation.rawValue }
    public let violation: PolicyViolation
    public let text: String
    /// Where the user fixes it, when this app can.
    public let action: PolicyAction?
}

/// Least Argon2id memory (MiB) and passes for new account keys, as the core takes them
/// (`createAccountWithKdf` / `Account.rewrapWithKdf`); nil = the core's own default.
public struct KdfMinimums: Equatable, Sendable {
    public var memoryMib: UInt32?
    public var iterations: UInt32?

    public init(memoryMib: UInt32? = nil, iterations: UInt32? = nil) {
        self.memoryMib = memoryMib
        self.iterations = iterations
    }

    /// The policy's minimums (already within the core's range: 64–1024 MiB, 3–20 passes).
    public init(_ p: Policies) {
        self.init(memoryMib: UInt32(clamping: p.minKdfMemoryMib), iterations: UInt32(clamping: p.minKdfIterations))
    }
}

public enum PolicyRules {
    /// The apps' own minimum master password length; a policy can only raise it.
    public static let minMasterPassword = 10
    /// The server's ceiling for `max_vault_timeout_minutes` (30 days).
    public static let maxTimeoutMinutes = 43_200

    /// Characters a new master password needs: the server's minimum, never below the apps' own.
    public static func minPasswordLength(_ p: Policies) -> Int { max(minMasterPassword, p.masterPasswordMinLength) }

    /// Whether the app offers exporting the vault.
    public static func exportAllowed(_ p: Policies) -> Bool { !p.disableExport }

    /// The key-derivation minimums for new account keys (registration, every keys change):
    /// the server's policy, read again from `/api/config` right before, else the policies kept
    /// with the account; none (the core's defaults, 128 MiB and 3 passes) for a server without
    /// the `policies` feature. The core makes keys with max(128 MiB, minimum) memory and
    /// max(3, minimum) passes (`createAccountWithKdf` / `rewrapWithKdf`).
    public static func kdfMinimums(_ config: PublicConfig?, stored: Policies? = nil) -> KdfMinimums {
        if let config { return config.features.contains(policiesFeature) ? KdfMinimums(config.policies) : KdfMinimums() }
        return stored.map { KdfMinimums($0) } ?? KdfMinimums()
    }

    /// The `kdf` notice: a keys change with the server's minimums fixes it, with the same password too.
    public static let kdfNotice = "Your server asks you to update your account's encryption settings. Change your master password to update them. You can keep the same password."
    /// On Change master password while the account has a `kdf` violation.
    public static let kdfSamePasswordNote = "Your server asks for new encryption settings. Changing your master password applies them: you can enter your current password again as the new one."

    // MARK: Vault timeout

    /// Whether `t` locks the vault within `max` minutes of inactivity (0 = no limit: every
    /// choice does). "On app restart" and "Never" have no time limit: above every limit.
    public static func timeoutWithin(_ t: VaultTimeout, max: Int) -> Bool {
        if max <= 0 || t == .immediately { return true }
        guard let m = t.minutes else { return false }
        return m <= max
    }

    /// The choices to offer under the server's limit, short to long.
    public static func timeoutOptions(max: Int) -> [VaultTimeout] {
        VaultTimeout.allCases.filter { timeoutWithin($0, max: max) }
    }

    /// The timeout that applies: the saved choice, or the longest choice within the limit.
    public static func clampTimeout(_ t: VaultTimeout, max: Int) -> VaultTimeout {
        if timeoutWithin(t, max: max) { return t }
        return timeoutOptions(max: max).max { ($0.minutes ?? 0) < ($1.minutes ?? 0) } ?? .immediately
    }

    /// The strictest limit of several servers (accounts on different servers); 0 = none.
    public static func strictestLimit(_ limits: [Int]) -> Int {
        limits.filter { $0 > 0 }.min() ?? 0
    }

    /// "45 minutes", "1 hour", "4 hours", "30 days": a limit in words.
    public static func minutesLabel(_ minutes: Int) -> String {
        func plural(_ n: Int, _ unit: String) -> String { "\(n) \(unit)\(n == 1 ? "" : "s")" }
        if minutes >= 1440 && minutes % 1440 == 0 { return plural(minutes / 1440, "day") }
        if minutes >= 60 && minutes % 60 == 0 { return plural(minutes / 60, "hour") }
        return plural(minutes, "minute")
    }

    public static func timeoutLimitNote(_ max: Int) -> String {
        "Your server allows at most \(minutesLabel(max)) before the vault locks."
    }

    public static func timeoutLoweredNote(_ t: VaultTimeout) -> String {
        "Your previous choice was longer, so it was lowered to \(t.label.lowercased())."
    }

    // MARK: Export and Secret Key

    public static let exportDisabledFooter = "Exporting is turned off by your server's admin."
    public static let exportDisabledMessage = "Your server's admin turned off exporting the vault."
    public static let secretKeyRequiredNote = "Your server requires a Secret Key."

    // MARK: Violations

    /// The known violations in a fixed order; unknown or repeated entries (and servers without
    /// the list) give none.
    public static func readViolations(_ value: JSON?) -> [PolicyViolation] {
        let names = Set((value?.array ?? []).compactMap(\.string))
        return PolicyViolation.allCases.filter { names.contains($0.rawValue) }
    }

    /// The notice lines for an account's violations, each with the place that fixes it.
    public static func notices(_ violations: [PolicyViolation], _ p: Policies) -> [PolicyNotice] {
        violations.map { v in
            switch v {
            case .twoStep:
                PolicyNotice(violation: v, text: "Your server requires two-step login.", action: .setUpTwoStep)
            case .secretKey:
                PolicyNotice(violation: v, text: "Your server asks you to turn on a Secret Key.", action: .turnOnSecretKey)
            case .kdf:
                PolicyNotice(violation: v, text: kdfNotice, action: .changePassword)
            }
        }
    }

    /// Identifies a set of violations, so a dismissed notice comes back when the set changes.
    public static func violationsKey(_ v: [PolicyViolation]) -> String {
        v.map(\.rawValue).joined(separator: ",")
    }
}

/// The server requires two-step login (policy) and the account has no method: it refuses
/// everything but reading the account, setting a method up and signing out, so the app shows a
/// screen that offers only those (as the web vault's `TwoStepRequired` page).
public enum TwoStepGate {
    public static let code = "two_step_required"

    /// Whether an answer is the server's "set up two-step login first".
    public static func isRequired(status: Int, code: String) -> Bool { status == 403 && code == Self.code }

    public enum Next: Equatable, Sendable {
        /// The account keys are in memory: sync, and the vault opens.
        case sync
        /// They aren't (the screen came up while locked): the unlock screen.
        case unlock
    }

    /// What follows once a method is on and the user continues.
    public static func afterSetup(keysInMemory: Bool) -> Next { keysInMemory ? .sync : .unlock }

    public static let title = "Your server requires two-step login"
    public static let message = "Your server requires two-step login. Set it up to continue."
    public static let hint = "You get recovery codes with your first method. Keep them somewhere safe: they let you sign in if you lose it."
    public static let securityKeys = "Security keys and passkeys can be added in the web vault."
    public static let onTitle = "Two-step login is on"
    public static let onText = "Your vault can open now."

    public static func intro(email: String) -> String {
        (email.isEmpty ? "Set up a second step to open your vault. " : "Set up a second step for \(email) to open your vault. ")
            + "It's asked for after your master password when you sign in on a new device, so a stolen password isn't enough."
    }
}

/// `/api/config` as the app uses it (no account needed).
public struct PublicConfig: Equatable, Sendable {
    public var signupsAllowed: Bool?
    public var features: [String]
    /// The defaults on servers without the `policies` feature.
    public var policies: Policies
    /// The server's API version (`api`, a whole number; API 2 servers and later); nil from older
    /// servers, which send none.
    public var api: Int?

    public init(signupsAllowed: Bool? = nil, features: [String] = [], policies: Policies = Policies(), api: Int? = nil) {
        self.signupsAllowed = signupsAllowed
        self.features = features
        self.policies = policies
        self.api = api
    }

    /// nil for an answer that isn't PassAuth's config.
    public init?(json j: JSON) {
        guard case .object = j else { return nil }
        features = (j["features"]?.array ?? []).compactMap(\.string)
        if case .bool(let b)? = j["signups_allowed"] { signupsAllowed = b } else { signupsAllowed = nil }
        policies = features.contains(policiesFeature) ? Policies(json: j["policies"]) : Policies()
        switch j["api"] {
        case .int(let n)? where n >= 0 && n < 1_000_000: api = Int(n)
        case .double(let x)? where x.isFinite && x == x.rounded() && x >= 0 && x < 1_000_000: api = Int(x)
        default: api = nil
        }
    }
}

/// Website icons (`/api/icons/<host>`): shown when the user wants them and the server offers
/// them, as the web vault's `siteIconsShown`. API 2 servers list the icon service as the feature
/// `icons` only while it is on; older servers (no `api`, or below 2) always had it; until the
/// account's config is known the user's setting alone decides (a failed icon just falls back to
/// the letter tile).
public enum SiteIcons {
    public static let feature = "icons"

    /// `api` / `features`: the server's `/api/config` as kept with the account (`features` nil:
    /// not asked yet).
    public static func shown(wanted: Bool, api: Int?, features: [String]?) -> Bool {
        guard wanted else { return false }
        guard let features, let api, api >= 2 else { return true }
        return features.contains(feature)
    }
}
