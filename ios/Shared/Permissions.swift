import Foundation

/// What PassAuth knows about one permission or system feature.
public enum PermissionStatus: String, Codable, Equatable, Sendable {
    case allowed, denied, notAsked, unavailable, unknown
}

/// What the app remembers about permissions (device-wide, in the shared settings): iOS has
/// no API for the local network permission and none for "was Face ID asked".
public struct PermissionMemory: Codable, Equatable, Sendable {
    /// The first-launch "Set up PassAuth" screen was shown (continued or skipped).
    public var introShown = false
    /// Last result of the local network check (nil: never checked).
    public var localNetwork: PermissionStatus?
    /// Face ID / Touch ID worked once from the permissions list.
    public var biometricsAllowed = false
    /// The "Turn on Face ID unlock?" offer after the first sign-in was made.
    public var biometricOffered = false

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = PermissionMemory()
        introShown = c.lenient(.introShown, d.introShown)
        localNetwork = c.lenient(.localNetwork, d.localNetwork)
        biometricsAllowed = c.lenient(.biometricsAllowed, d.biometricsAllowed)
        biometricOffered = c.lenient(.biometricOffered, d.biometricOffered)
    }
}

/// Pure rules behind the permissions screen (unit-tested).
public enum PermissionRules {
    /// Show the first-launch screen once, before the first account is set up. Devices that
    /// already have accounts (updated from a version without the screen) don't get it.
    public static func showIntro(_ memory: PermissionMemory, hasAccounts: Bool, skip: Bool = false) -> Bool {
        !skip && !memory.introShown && !hasAccounts
    }

    /// Offer biometric unlock once after a sign-in or unlock, if the user allowed it on the
    /// permissions screen and the account doesn't use it yet.
    public static func offerBiometricUnlock(_ memory: PermissionMemory, available: Bool, enabled: Bool) -> Bool {
        memory.biometricsAllowed && !memory.biometricOffered && available && !enabled
    }

    /// `AVAuthorizationStatus` raw value: 0 not determined, 1 restricted, 2 denied, 3 authorized.
    public static func camera(_ raw: Int) -> PermissionStatus {
        switch raw {
        case 0: .notAsked
        case 1: .unavailable
        case 2: .denied
        case 3: .allowed
        default: .unknown
        }
    }

    /// Face ID / Touch ID from `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`:
    /// its result, the `LAError` code when it failed, whether the device has the hardware
    /// (`biometryType` is set even when the check fails), and whether it worked from the list.
    public static func biometrics(canEvaluate: Bool, errorCode: Int?, hasHardware: Bool, allowedBefore: Bool) -> PermissionStatus {
        if canEvaluate { return allowedBefore ? .allowed : .notAsked }
        guard hasHardware else { return .unavailable }
        switch errorCode {
        // biometryNotAvailable with the hardware present: the user said no to Face ID for PassAuth.
        case -6: return .denied
        // biometryLockout: too many failed attempts; the permission itself is unchanged.
        case -8: return allowedBefore ? .allowed : .notAsked
        // biometryNotEnrolled, passcodeNotSet and anything else: nothing to allow yet.
        default: return .unavailable
        }
    }

    /// AutoFill from `ASCredentialIdentityStore` state (nil: no answer).
    public static func autofill(_ enabled: Bool?) -> PermissionStatus {
        switch enabled {
        case true?: .allowed
        case false?: .notAsked
        case nil: .unknown
        }
    }

    /// What the local network browse showed.
    public enum ProbeEvent: Equatable, Sendable {
        case ready, policyDenied, waiting, failed
    }

    /// `kDNSServiceErr_PolicyDenied`: the local network permission is off for the app.
    public static let policyDeniedCode: Int32 = -65570

    /// A waiting or failed browser state, from its DNS-SD error code (nil: not a DNS error).
    public static func probeEvent(dnsError: Int32?, failed: Bool) -> ProbeEvent {
        if dnsError == policyDeniedCode { return .policyDenied }
        return failed ? .failed : .waiting
    }

    /// Local network from the browse's states. iOS reports a denial as the browser waiting
    /// with `kDNSServiceErr_PolicyDenied`; "ready" alone is trusted only once the prompt (if
    /// any) was answered. Anything else stays unknown.
    public static func localNetwork(_ events: [ProbeEvent], promptSettled: Bool) -> PermissionStatus {
        if events.contains(.policyDenied) { return .denied }
        if promptSettled && events.contains(.ready) && !events.contains(.failed) { return .allowed }
        return .unknown
    }

    /// The status shown for the local network: the last check, or "not asked" before any.
    public static func localNetworkShown(_ memory: PermissionMemory) -> PermissionStatus {
        memory.localNetwork ?? .notAsked
    }
}
