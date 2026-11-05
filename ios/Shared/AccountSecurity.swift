import Foundation
import PassAuthCore

// Account security in the app: change the master password / Secret Key setting and manage
// two-step login, like the web vault's Settings → Security and Two-step login.

/// Two-step login as `GET /api/account` reports it.
public struct TwoFactorStatus: Equatable, Sendable {
    public var providers: [String] = []
    public var recoveryCodesLeft = 0
    /// The server can send email (email codes can be turned on).
    public var emailAvailable = false
    public var email = ""

    public init(providers: [String] = [], recoveryCodesLeft: Int = 0, emailAvailable: Bool = false, email: String = "") {
        self.providers = providers
        self.recoveryCodesLeft = recoveryCodesLeft
        self.emailAvailable = emailAvailable
        self.email = email
    }

    public init(json j: JSON) {
        providers = (j["two_factor"]?.array ?? []).compactMap(\.string)
        recoveryCodesLeft = Int(j["recovery_codes_left"]?.int ?? 0)
        emailAvailable = j["email_enabled"]?.bool ?? false
        email = j.str("email")
    }

    public var totpOn: Bool { providers.contains(TwoFactorProvider.totp.rawValue) }
    public var emailOn: Bool { providers.contains(TwoFactorProvider.email.rawValue) }
    public var anyOn: Bool { totpOn || emailOn }
    /// Turning this one off leaves no method (the server then deletes the recovery codes too).
    public func isLast(_ p: TwoFactorProvider) -> Bool { providers.filter { $0 != p.rawValue && $0 != "recovery" }.isEmpty }
}

public enum TwoFactorProvider: String, Sendable, CaseIterable {
    case totp, email
}

/// What `POST /account/2fa/totp/setup` returns: the new secret (base32) and its `otpauth://` URI.
public struct TotpSetup: Equatable, Sendable {
    public let secret: String
    public let uri: String
    public init(secret: String, uri: String) {
        self.secret = secret
        self.uri = uri
    }
}

/// The Secret Key part of a master password change.
public enum SecretKeyChange: Sendable, Equatable {
    /// Keep the current setting (and the current Secret Key, if there is one).
    case keep
    /// Create a Secret Key (shown once).
    case turnOn
    /// Master password alone from now on.
    case turnOff

    public static func from(wasOn: Bool, wantOn: Bool) -> SecretKeyChange {
        wasOn == wantOn ? .keep : wantOn ? .turnOn : .turnOff
    }
}

/// Rules and wording shared by the change-password and two-step screens (pure, unit-tested).
public enum AccountSecurityLogic {
    public static let minPasswordLength = 10
    /// Below this, a new master password is "easy to guess" (the web vault's `WEAK_BITS`).
    public static let weakBits = 50.0

    public enum PasswordProblem: Equatable, Sendable {
        case noCurrent, nothingToChange, tooShort, mismatch, sameAsCurrent
        /// Weak: shown once; submitting again uses it anyway.
        case weak

        public var message: String {
            switch self {
            case .noCurrent: "Enter your current master password."
            case .nothingToChange: "Enter a new master password, or change the Secret Key setting."
            case .tooShort: "Use at least \(AccountSecurityLogic.minPasswordLength) characters for your new master password."
            case .mismatch: "The new passwords don't match. Type the same password in both fields."
            case .sameAsCurrent: "The new master password is the same as the current one."
            case .weak: "This password is easy to guess. Choose a longer one, or select Change master password again to use it anyway."
            }
        }
    }

    /// Checks before a master password change (as the web vault's Security tab and Register).
    /// An empty new password keeps the current one, allowed only when the Secret Key setting changes.
    public static func passwordProblem(current: String, new: String, confirm: String, secretKeyChange: SecretKeyChange,
                                       weakAccepted: Bool, bits: (String) -> Double) -> PasswordProblem? {
        if current.isEmpty { return .noCurrent }
        if new.isEmpty && confirm.isEmpty { return secretKeyChange == .keep ? .nothingToChange : nil }
        if new.count < minPasswordLength { return .tooShort }
        if new != confirm { return .mismatch }
        if new == current && secretKeyChange == .keep { return .sameAsCurrent }
        if bits(new) < weakBits && !weakAccepted { return .weak }
        return nil
    }

    /// Only digits (spaces and dashes typed or pasted with the code are dropped).
    public static func cleanCode(_ code: String) -> String {
        String(code.filter { $0.isASCII && $0.isNumber })
    }

    /// Authenticator codes are 6 digits.
    public static func isTotpCode(_ code: String) -> Bool { cleanCode(code).count == 6 }

    /// Email codes: whatever the server sent (digits), at least 6.
    public static func isEmailCode(_ code: String) -> Bool { (6...10).contains(cleanCode(code).count) }

    /// The setup key in groups of four, easier to type into another app.
    public static func groupedSecret(_ secret: String) -> String {
        var out = ""
        for (i, c) in secret.enumerated() {
            if i > 0 && i % 4 == 0 { out.append(" ") }
            out.append(c)
        }
        return out
    }

    /// The recovery codes as one text (Copy all / Share), as the web vault's download.
    public static func recoveryCodesText(_ codes: [String], server: String) -> String {
        "PassAuth recovery codes\n\(server)\n\nEach code works once.\n\n" + codes.joined(separator: "\n") + "\n"
    }

    /// The `otpauth://` link from the server, opened only if it really is one.
    public static func authenticatorURL(_ uri: String) -> URL? {
        guard let u = URL(string: uri), u.scheme?.lowercased() == "otpauth", u.host?.lowercased() == "totp" else { return nil }
        return u
    }
}

/// Screens that show something only once (recovery codes, a new Secret Key): they close only
/// after the user confirmed saving it.
public struct ShownOnce: Equatable, Sendable {
    public private(set) var value: [String]
    public var saved = false

    public init(_ value: [String]) { self.value = value }

    public var canClose: Bool { saved && !value.isEmpty }

    /// Close: forget the secret. Returns false (nothing changes) while not confirmed.
    public mutating func close() -> Bool {
        guard canClose else { return false }
        value = []
        saved = false
        return true
    }
}

/// Error text for the two-step and password screens: wrong code, rate limit, network.
public func securityErrorMessage(_ error: Error) -> String {
    if let e = error as? ApiError {
        if e.status == 429 || e.code == "rate_limited" { return "Too many attempts, try again later." }
        switch e.message.lowercased() {
        case "invalid code": return "That code isn't right. Check it and try again."
        case "start setup first": return "Setup has expired. Start again."
        case "email is not configured on this server": return "This server can't send email, so email codes aren't available."
        case "reauth_required": return "Please confirm your master password again."
        default: break
        }
        if e.status == 409 { return "This method is already on. Turn it off first to set it up again." }
    }
    return errorMessage(error)
}

extension VaultRepository {
    private func requireOnline() throws {
        if vault?.offline == true { throw UserError("You're offline. This needs your PassAuth server.") }
    }

    // MARK: Master password / Secret Key

    /// Change the master password and/or the Secret Key setting (the web vault's `changeKeys`):
    /// re-authenticate with the current password → `Account.rewrap` (same account key and key
    /// pair, wrapped with the new password) → `/account/keys/start` → OPAQUE registration with
    /// the new password → `/account/keys/finish` with the reauth token. The server signs every
    /// other session out. `newPassword` nil keeps the current one (Secret Key change only).
    /// Returns the new Secret Key when one was created (show it once).
    public func changeMasterPassword(current: String, typedSecretKey: String?, newPassword: String?, secretKeyChange: SecretKeyChange) async throws -> String? {
        try await lock.run {
            try requireOnline()
            let id = activeId
            guard sessions[id] != nil else { throw UserError("Unlock your vault first.") }
            let token = try await reauthToken(id, password: current, secretKey: typedSecretKey)
            return try await changeKeysLocked(id, reauthToken: token, newPassword: newPassword ?? current, typedSecretKey: typedSecretKey, change: secretKeyChange)
        }
    }

    /// The part after re-authentication (`reauthToken` from the server); see `changeMasterPassword`.
    public func changeKeys(reauthToken: String, newPassword: String, secretKeyChange: SecretKeyChange, typedSecretKey: String? = nil) async throws -> String? {
        try await lock.run {
            try requireOnline()
            return try await changeKeysLocked(activeId, reauthToken: reauthToken, newPassword: newPassword, typedSecretKey: typedSecretKey, change: secretKeyChange)
        }
    }

    private func changeKeysLocked(_ id: String, reauthToken: String, newPassword: String, typedSecretKey: String?, change: SecretKeyChange) async throws -> String? {
        let s = store.get()
        guard let a = s.file.accounts[id], let session = sessions[id] else { throw UserError("Unlock your vault first.") }
        guard let bundle = a.bundle else { throw UserError("Sync your vault first.") }
        let enabled = (try JSON.parse(bundle))["secret_key_enabled"]?.bool ?? false
        let email = a.email.lowercased()
        let typed = typedSecretKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        let current = enabled ? ((typed?.isEmpty == false ? typed : nil) ?? s.secrets.secretKeys[email]) : nil
        let withKey: Bool = switch change {
        case .keep: enabled
        case .turnOn: true
        case .turnOff: false
        }
        // Keeping the Secret Key needs it (it is part of the new wrapping key).
        if withKey && enabled && current == nil { throw UserError(secretKeyRequiredMessage) }
        let account = session.account
        let keep = withKey ? current : nil
        let next = try await core { try account.rewrap(bundleJson: bundle, newPassword: newPassword, withSecretKey: withKey, existingSecretKey: keep) }
        let master = next.master
        let start = try await core { try opaqueRegisterStart(master: master) }
        let resp = try await api.call(id, "/account/keys/start", body: ["message": .string(start.message)])
        let message = resp.str("message")
        let upload = try await core { try opaqueRegisterFinish(state: start.state, master: master, response: message) }
        let newBundle = try JSON.parse(next.bundleJson)
        do {
            _ = try await api.call(id, "/account/keys/finish", body: ["upload": .string(upload), "bundle": newBundle], headers: ["x-reauth-token": reauthToken])
        } catch let e as ApiError {
            throw e
        } catch {
            // No answer: the change may still have reached the server. If the server has the
            // new bundle, finish here (otherwise a new Secret Key would be lost).
            guard await serverHas(id, bundle: newBundle) else { throw error }
        }
        // Everything on this device that depends on the password: the bundle (unlock in the
        // app and in AutoFill derive from it), the Secret Key, and the two-step "remember this
        // device" token (the server forgot them all). The account key and key pair don't
        // change (only their wrapping), so the Face ID item and the "never" session bytes stay
        // valid: the session bytes are rewritten from the new session, the Face ID item is
        // left alone (replacing it deletes it first, and a failed add would lose it).
        let sameEmailElsewhere = s.file.accounts.contains { $0.key != id && $0.value.email.lowercased() == email }
        let server = a.server
        store.update { st in
            st.file.accounts[id]?.bundle = next.bundleJson
            if let sk = next.secretKey {
                st.secrets.secretKeys[email] = sk
            } else if withKey, let current {
                st.secrets.secretKeys[email] = current
            } else if !withKey, !sameEmailElsewhere {
                st.secrets.secretKeys[email] = nil
            }
            st.secrets.rememberTokens["\(server)|\(email)"] = nil
        }
        openSession(id, Session(accountId: session.accountId, account: next.account))
        // Fresh `/sync`: the offline copy (also read by AutoFill) gets the new bundle.
        await syncAfterWrite()
        return next.secretKey
    }

    /// Whether the server already has this bundle (after a lost `/account/keys/finish` answer).
    private func serverHas(_ id: String, bundle: JSON) async -> Bool {
        guard let j = try? await api.call(id, "/sync"), let b = j["bundle"] else { return false }
        return b["wrapped_account_key"]?.string == bundle["wrapped_account_key"]?.string && b["kdf"] == bundle["kdf"]
    }

    // MARK: Two-step login

    public func twoFactorStatus() async throws -> TwoFactorStatus {
        TwoFactorStatus(json: try await api.call(activeId, "/account"))
    }

    /// Start authenticator setup: a new secret, enabled only after `enableTotp` with a code.
    public func startTotpSetup() async throws -> TotpSetup {
        try requireOnline()
        let r = try await api.call(activeId, "/account/2fa/totp/setup", method: "POST")
        let secret = r.str("secret"), uri = r.str("uri")
        guard !secret.isEmpty, !uri.isEmpty else { throw UserError("Your server didn't start the setup. Try again.") }
        return TotpSetup(secret: secret, uri: uri)
    }

    /// Turn on the authenticator app. Returns the recovery codes when this is the first method.
    public func enableTotp(code: String) async throws -> [String]? {
        let r = try await api.call(activeId, "/account/2fa/totp/enable", body: ["code": .string(AccountSecurityLogic.cleanCode(code))])
        return Self.recoveryCodes(r)
    }

    /// Email a setup code to the account's address.
    public func sendEmailSetupCode() async throws {
        try requireOnline()
        _ = try await api.call(activeId, "/account/2fa/email/setup", method: "POST")
    }

    /// Turn on email codes. Returns the recovery codes when this is the first method.
    public func enableEmailCodes(code: String) async throws -> [String]? {
        let r = try await api.call(activeId, "/account/2fa/email/enable", body: ["code": .string(AccountSecurityLogic.cleanCode(code))])
        return Self.recoveryCodes(r)
    }

    /// New recovery codes (the old ones stop working), after the master password.
    public func regenerateRecoveryCodes(password: String, typedSecretKey: String?) async throws -> [String] {
        try await lock.run {
            try requireOnline()
            let token = try await reauthToken(activeId, password: password, secretKey: typedSecretKey)
            return try await regenerateLocked(token)
        }
    }

    public func regenerateRecoveryCodes(reauthToken: String) async throws -> [String] {
        try await lock.run { try await regenerateLocked(reauthToken) }
    }

    private func regenerateLocked(_ token: String) async throws -> [String] {
        let r = try await api.call(activeId, "/account/2fa/recovery", method: "POST", headers: ["x-reauth-token": token])
        guard let codes = Self.recoveryCodes(r), !codes.isEmpty else { throw UserError("Your server didn't send new recovery codes. Try again.") }
        return codes
    }

    /// Turn a method off, after the master password.
    public func disableTwoFactor(_ provider: TwoFactorProvider, password: String, typedSecretKey: String?) async throws {
        try await lock.run {
            try requireOnline()
            let token = try await reauthToken(activeId, password: password, secretKey: typedSecretKey)
            try await disableLocked(provider, token)
        }
    }

    public func disableTwoFactor(_ provider: TwoFactorProvider, reauthToken: String) async throws {
        try await lock.run { try await disableLocked(provider, reauthToken) }
    }

    private func disableLocked(_ provider: TwoFactorProvider, _ token: String) async throws {
        _ = try await api.call(activeId, "/account/2fa/\(provider.rawValue)", method: "DELETE", headers: ["x-reauth-token": token])
    }

    nonisolated private static func recoveryCodes(_ r: JSON) -> [String]? {
        guard let v = r["recovery_codes"], v != .null else { return nil }
        let codes = v.array.compactMap(\.string)
        return codes.isEmpty ? nil : codes
    }
}
