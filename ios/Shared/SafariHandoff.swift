import Foundation

/// What the PassAuth app leaves for "PassAuth for Safari" (safari/), so its sign-in needs only the
/// master password: the unlocked active account's server, email and Secret Key, as JSON in a
/// Keychain item of the shared group. Never tokens or keys: the Safari extension signs in itself and
/// gets its own session (the same rule as the desktop app's hand-off on macOS).
public struct SafariHandoff: Codable, Equatable, Sendable {
    public var server: String
    public var email: String
    public var secretKey: String?

    public init(server: String, email: String, secretKey: String?) {
        self.server = server
        self.email = email
        self.secretKey = secretKey
    }

    /// The hand-off for the active account, only while it is unlocked (nil otherwise).
    public static func make(status: Status, server: String, email: String, secretKey: String?) -> SafariHandoff? {
        guard status == .unlocked, !server.isEmpty, !email.isEmpty else { return nil }
        return SafariHandoff(server: server, email: email, secretKey: secretKey?.isEmpty == false ? secretKey : nil)
    }

    public func json() throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        return try enc.encode(self)
    }

    /// Writes `handoff`, or clears the item when nil (signed out). The Safari extension reads it
    /// (safari/Extension/Handoff.swift, service `io.passauth.safari.handoff`).
    public static func store(_ handoff: SafariHandoff?) {
        Keychain.writeSafariHandoff(handoff.flatMap { try? $0.json() })
    }
}
