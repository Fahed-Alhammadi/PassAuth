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

    /// Whether the stored hand-off must go: signed out, or it is another account's than the active one
    /// (one of several accounts logged out and the next one, locked, became active).
    public static func shouldClear(status: Status, server: String, email: String, stored: SafariHandoff?) -> Bool {
        if status == .setup || status == .loggedOut { return true }
        guard let stored else { return false }
        return stored.server != server || stored.email.lowercased() != email.lowercased()
    }

    /// What the app watches to write the hand-off again: account, state, server, email and (as a hash, never the
    /// value) the Secret Key, so a changed Secret Key reaches Safari at once.
    public static func changeKey(activeId: String, status: Status, server: String, email: String, secretKey: String?) -> String {
        var h = Hasher()
        h.combine(secretKey)
        return "\(activeId)|\(status)|\(server)|\(email)|\(h.finalize())"
    }

    /// The hand-off stored now, if any.
    public static func stored() -> SafariHandoff? {
        Keychain.readSafariHandoff().flatMap { try? JSONDecoder().decode(SafariHandoff.self, from: $0) }
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
