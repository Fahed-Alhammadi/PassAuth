import Foundation
import LocalAuthentication
import Security

/// Where the app and its AutoFill extension share data: the App Group container for files and
/// a shared Keychain access group for secrets.
public enum SharedConfig {
    public static let appGroup = "group.io.passauth.app"
    #if os(macOS)
    /// macOS (the desktop app's AutoFill extension): no App Group; the extension keeps its own
    /// Keychain group `JEXQBK3SQ5.io.passauth.desktop.autofill` and its own sandbox container.
    static let keychainGroupSuffix = "io.passauth.desktop.autofill"
    #else
    static let keychainGroupSuffix = "io.passauth.shared"
    #endif

    /// File protection "complete" where the platform has it (iOS); plain atomic writes on macOS,
    /// where the sandbox container and FileVault protect the files.
    static var writeOptions: Data.WritingOptions {
        #if os(iOS)
        [.atomic, .completeFileProtection]
        #else
        [.atomic]
        #endif
    }

    static var directoryAttributes: [FileAttributeKey: Any] {
        #if os(iOS)
        [.protectionKey: FileProtectionType.complete]
        #else
        [:]
        #endif
    }

    /// The shared Keychain access group, exactly as listed in both targets' entitlements
    /// (`$(AppIdentifierPrefix)io.passauth.shared`): `JEXQBK3SQ5.io.passauth.shared` in builds
    /// signed with the team, `io.passauth.shared` in unsigned simulator builds (no prefix; the
    /// simulator honours the group from the embedded entitlements). Nil only if the Info.plist
    /// key is missing (the default group is then used, not shared).
    public static var keychainGroup: String? {
        let g = (Bundle.main.object(forInfoDictionaryKey: "PAKeychainGroup") as? String) ?? ""
        return g.hasSuffix(keychainGroupSuffix) ? g : nil
    }

    /// The directory for PassAuth's files: the App Group container when the entitlement is
    /// present, else Application Support. Excluded from backups.
    public static func dataDirectory() -> URL {
        let fm = FileManager.default
        #if os(macOS)
        // Asking for a group container that isn't in the entitlements makes macOS warn the user.
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        #else
        let base = fm.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        #endif
        var dir = base.appendingPathComponent("PassAuth", isDirectory: true)
        if !fm.fileExists(atPath: dir.path) {
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: directoryAttributes)
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }
}

/// Generic-password Keychain items of this app (this device only, never in backups or iCloud).
public enum Keychain {
    static let service = "io.passauth.app"
    static let biometricService = "io.passauth.app.biometric"

    private static func base(_ service: String, _ account: String?) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: false,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        if let group = SharedConfig.keychainGroup { q[kSecAttrAccessGroup as String] = group }
        #if os(macOS)
        // The iOS-style Keychain (access groups, access control, this-device-only items).
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }

    /// The outcome of a Keychain read: "not there" and "couldn't read it now" are different
    /// things (a failed read must never be treated as an empty item and written back).
    public enum ReadResult: Sendable, Equatable {
        case found(Data)
        case notFound
        /// The Keychain refused the read (e.g. errSecInteractionNotAllowed while the device is locked).
        case failed(OSStatus)
    }

    public static func lookup(_ account: String) -> ReadResult {
        var q = base(service, account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard let d = out as? Data else { return .failed(errSecDecode) }
            return .found(d)
        case errSecItemNotFound: return .notFound
        default: return .failed(status)
        }
    }

    /// The item's data, or nil if it's missing or can't be read (use [lookup] to tell them apart).
    public static func read(_ account: String) -> Data? {
        if case .found(let d) = lookup(account) { return d }
        return nil
    }

    @discardableResult
    public static func write(_ account: String, _ data: Data) -> Bool {
        let q = base(service, account)
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        var status = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(q.merging(attrs) { _, b in b } as CFDictionary, nil)
        }
        return status == errSecSuccess
    }

    public static func delete(_ account: String) {
        SecItemDelete(base(service, account) as CFDictionary)
    }

    /// Remove every item of this app (fresh install: Keychain items outlive the app).
    public static func deleteAll() {
        SecItemDelete(base(service, nil) as CFDictionary)
        SecItemDelete(base(biometricService, nil) as CFDictionary)
    }

    // MARK: Biometric unlock

    public enum BiometricResult: Sendable {
        case ok(Data)
        case cancelled
        /// The item is gone: biometrics changed (enrolment), or it was never stored.
        case invalidated
        case failed(String)
    }

    /// Store session bytes so that only the currently enrolled Face ID / Touch ID can read them.
    public static func storeBiometric(_ account: String, _ data: Data) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error) else {
            throw UserError("Face ID unlock isn't available on this device.")
        }
        let q = base(biometricService, account)
        SecItemDelete(q as CFDictionary)
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw UserError("Couldn't turn on biometric unlock (error \(status)).")
        }
    }

    /// Read the session bytes: shows the Face ID / Touch ID prompt. Blocks; call off the main thread.
    public static func readBiometric(_ account: String, reason: String) -> BiometricResult {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedCancelTitle = "Use master password"
        var q = base(biometricService, account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = context
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard let d = out as? Data else { return .failed("Biometric unlock failed.") }
            return .ok(d)
        // The prompt can't be shown right now (the app isn't on screen): nothing to report, try again later.
        case errSecUserCanceled, errSecInteractionNotAllowed: return .cancelled
        case errSecItemNotFound: return .invalidated
        case errSecAuthFailed: return .failed("Biometric unlock failed. Unlock with your master password.")
        default: return .failed("Biometric unlock failed (error \(status)).")
        }
    }

    public static func deleteBiometric(_ account: String) {
        SecItemDelete(base(biometricService, account) as CFDictionary)
    }
}

/// What the device offers for biometric unlock.
public enum BiometryKind: Sendable {
    case none, faceID, touchID, opticID

    public static var current: BiometryKind {
        let c = LAContext()
        var error: NSError?
        guard c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return .none }
        switch c.biometryType {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        default: return .none
        }
    }

    public var name: String {
        switch self {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        case .none: "biometrics"
        }
    }

    public var symbol: String {
        switch self {
        case .faceID: "faceid"
        case .touchID: "touchid"
        case .opticID: "opticid"
        case .none: "lock"
        }
    }

    public var available: Bool { self != .none }

    /// Ask for Face ID / Touch ID (turning biometric unlock on). False when cancelled or failed.
    public static func confirm(reason: String) async -> Bool {
        let c = LAContext()
        c.localizedCancelTitle = "Cancel"
        return (try? await c.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)) ?? false
    }
}
