import Foundation

public let maxAccounts = 5

/// Vault timeout, like the extension's (minutes of inactivity, or a special trigger).
public enum VaultTimeout: String, Codable, CaseIterable, Sendable {
    case immediately, min1 = "1", min5 = "5", min15 = "15", min30 = "30", hour1 = "60", hour4 = "240", restart, never

    public var label: String {
        switch self {
        case .immediately: "Immediately"
        case .min1: "1 minute"
        case .min5: "5 minutes"
        case .min15: "15 minutes"
        case .min30: "30 minutes"
        case .hour1: "1 hour"
        case .hour4: "4 hours"
        case .restart: "On app restart"
        case .never: "Never"
        }
    }

    /// Minutes of inactivity; nil for the special triggers (0 = immediately).
    public var minutes: Int? {
        switch self {
        case .immediately: 0
        case .restart, .never: nil
        default: Int(rawValue)
        }
    }
}

public enum TimeoutAction: String, Codable, CaseIterable, Sendable {
    case lock, logout
}

public enum ThemeMode: String, Codable, CaseIterable, Sendable {
    case system, light, dark
}

/// App settings (shared by all accounts), mirroring the extension's and Android's `Settings`.
public struct Settings: Codable, Equatable, Sendable {
    public var vaultTimeout: VaultTimeout = .min15
    public var timeoutAction: TimeoutAction = .lock
    public var autoCopyTotp = true
    /// Seconds; 0 = never.
    public var clearClipboard = 30
    public var showIcons = true
    /// Resolves a website's "default" match; never `.default` itself.
    public var defaultMatch: UrlMatch = .domain
    public var theme: ThemeMode = .system
    /// Offer to save new logins and update changed passwords (AutoFill).
    public var askToSave = true
    /// Never offer to save on these sites (base domains, as the extension and Android).
    public var neverSave: [String] = []
    /// The generator's options (Generator tab, and AutoFill's password generation).
    public var generator = GeneratorSettings()
    /// The permissions screen: shown once, and what iOS doesn't report itself.
    public var permissions = PermissionMemory()

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Settings()
        vaultTimeout = c.lenient(.vaultTimeout, d.vaultTimeout)
        timeoutAction = c.lenient(.timeoutAction, d.timeoutAction)
        autoCopyTotp = c.lenient(.autoCopyTotp, d.autoCopyTotp)
        clearClipboard = c.lenient(.clearClipboard, d.clearClipboard)
        showIcons = c.lenient(.showIcons, d.showIcons)
        defaultMatch = c.lenient(.defaultMatch, d.defaultMatch)
        if defaultMatch == .default { defaultMatch = .domain }
        theme = c.lenient(.theme, d.theme)
        askToSave = c.lenient(.askToSave, d.askToSave)
        neverSave = c.lenient(.neverSave, d.neverSave)
        generator = c.lenient(.generator, d.generator)
        permissions = c.lenient(.permissions, d.permissions)
    }
}

/// Password / passphrase generator options, shared by the app and the AutoFill extension.
/// Defaults as the core's `PasswordOptions` / `PassphraseOptions`.
public struct GeneratorSettings: Codable, Equatable, Sendable {
    public var passphrase = false
    public var length = 20
    public var uppercase = true
    public var lowercase = true
    public var digits = true
    public var symbols = true
    public var avoidAmbiguous = false
    public var words = 5
    public var separator = "-"
    public var capitalize = true
    public var includeNumber = true

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = GeneratorSettings()
        passphrase = c.lenient(.passphrase, d.passphrase)
        length = min(max(c.lenient(.length, d.length), 8), 128)
        uppercase = c.lenient(.uppercase, d.uppercase)
        lowercase = c.lenient(.lowercase, d.lowercase)
        digits = c.lenient(.digits, d.digits)
        symbols = c.lenient(.symbols, d.symbols)
        avoidAmbiguous = c.lenient(.avoidAmbiguous, d.avoidAmbiguous)
        words = min(max(c.lenient(.words, d.words), 3), 20)
        separator = String(c.lenient(.separator, d.separator).prefix(3))
        capitalize = c.lenient(.capitalize, d.capitalize)
        includeNumber = c.lenient(.includeNumber, d.includeNumber)
    }
}

/// Access and refresh token of a signed-in account (kept in the Keychain).
public struct Tokens: Codable, Equatable, Sendable {
    public var access: String
    public var refresh: String

    public init(access: String, refresh: String) {
        self.access = access
        self.refresh = refresh
    }
}

/// One account on this device. Secrets (tokens, unlocked keys) live in the Keychain
/// ([Secrets]); this part is stored in an encrypted file in the App Group container.
public struct AccountData: Codable, Equatable, Sendable {
    public var server = ""
    public var email = ""
    /// Profile name, for the account initials.
    public var name = ""
    public var lastSync: Double = 0
    /// The account bundle (encrypted keys) from the server, as JSON.
    public var bundle: String?
    /// Face ID / Touch ID unlock is set up (session bytes in a biometry-bound Keychain item).
    public var biometric = false

    public init(server: String = "", email: String = "") {
        self.server = server
        self.email = email
    }

    var isListed: Bool { !server.isEmpty && !email.isEmpty }
}

/// Non-secret state: accounts, settings, device id.
public struct StoredFile: Codable, Equatable, Sendable {
    public var deviceId = ""
    public var activeId = ""
    public var accounts: [String: AccountData] = [:]
    public var settings = Settings()
    /// Account order (oldest first), for stable lists.
    public var order: [String] = []
}

/// Secrets kept in the Keychain (this device only, never backed up).
public struct Secrets: Codable, Equatable, Sendable {
    public var tokens: [String: Tokens] = [:]
    /// Two-step "remember this device" tokens, keyed `server|email`.
    public var rememberTokens: [String: String] = [:]
    /// Secret Keys typed at sign-in, keyed by lower-case email.
    public var secretKeys: [String: String] = [:]
    /// Unlocked keys (base64 session bytes), only while the vault timeout is "never".
    public var persistedKeys: [String: String] = [:]
}

/// Everything the app keeps, as one value (split between file and Keychain on disk).
public struct Stored: Equatable, Sendable {
    public var file = StoredFile()
    public var secrets = Secrets()

    public var activeId: String { file.activeId }
    public var active: AccountData? { file.accounts[file.activeId] }
    public var settings: Settings { file.settings }

    public func tokens(_ id: String) -> Tokens? { secrets.tokens[id] }
}
