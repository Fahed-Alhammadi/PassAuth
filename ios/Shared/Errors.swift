import Foundation
import PassAuthCore

/// An error response from the server (`{ "error": code, "message": …, "request_id": … }`).
/// `message` is the server's own text: it is never shown as it is (see `errorMessage`).
public struct ApiError: Error, LocalizedError, Sendable {
    public let status: Int
    public let code: String
    public let message: String
    /// Seconds to wait before trying again: a 429's `Retry-After` (nil when it didn't say).
    public let retryAfter: Int?
    /// The server's id for the request (the body's `request_id`, else `x-request-id`), when it
    /// looks like one (`ApiError.requestIdPattern`): names the request in the server's log.
    public let requestId: String?
    /// The answer's other fields (`members_changed`: `unknown`, `identity_changed`, …); nil when none.
    public let fields: JSON?
    /// The app's wording, also wherever an error is shown through `localizedDescription`.
    public var errorDescription: String? { errorMessage(self) }

    public init(status: Int, code: String, message: String, retryAfter: Int? = nil, requestId: String? = nil, fields: JSON? = nil) {
        self.status = status
        self.code = code
        self.message = message
        self.retryAfter = retryAfter
        self.requestId = requestId.flatMap(Self.validRequestId)
        self.fields = fields
    }

    /// A request id worth showing: what servers make (letters, digits, `-_.:`, at most 64),
    /// never other text from the answer.
    public static func validRequestId(_ id: String?) -> String? {
        guard let id, (1...64).contains(id.count),
              id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "-_.:".contains($0)) }) else { return nil }
        return id
    }

    /// The server (or a proxy in front of it) refused because of too many requests.
    public var isRateLimited: Bool { status == 429 || code == "rate_limited" }

    /// Is this the server's `reason` (the answer's `error` code)?
    public func hasCode(_ reason: String) -> Bool { code == reason }
}

/// A user-facing error from the app itself (shown as is).
public struct UserError: Error, LocalizedError, Sendable, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Text that came from the server or from another device, as the app shows it (a device's name,
/// a server's message): control and format characters (Unicode Cc and Cf: bidi overrides and
/// isolates, zero-width marks, the byte order mark) dropped, every run of white space (line
/// breaks too) one space, trimmed, and at most `limit` characters (Unicode code points, so
/// stacked combining marks count too); a cut ends with "…".
public enum ShownText {
    public static func clean(_ text: String, limit: Int) -> String {
        var out = String.UnicodeScalarView()
        var count = 0
        var space = false
        var cut = false
        for s in text.unicodeScalars {
            if s.properties.isWhitespace {
                space = !out.isEmpty
                continue
            }
            switch s.properties.generalCategory {
            case .control, .format: continue
            default: break
            }
            if count + (space ? 2 : 1) > limit {
                cut = true
                break
            }
            if space {
                out.append(" ")
                count += 1
                space = false
            }
            out.append(s)
            count += 1
        }
        return String(out) + (cut ? "…" : "")
    }
}

/// Saving an item failed because it changed on the server since editing started (HTTP 409).
public struct ConflictError: Error, LocalizedError, Sendable {
    public let itemId: String
    public var errorDescription: String? { "This item was changed on another device." }
}

public let secretKeyRequiredMessage = "secret_key_required"

/// A request got no answer from the server (no network, DNS, refused or reset connection, TLS,
/// timeout): the offline change list (`OfflineQueue.waits`) keeps a save for later on this text.
public let cantReachServerMessage = "Can't reach your PassAuth server. Check the server address and your connection."

/// 403 `quota_exceeded`: the save would take the vault's owner past the server's item or storage
/// limit (only growth is refused; editing, trashing and deleting always work).
public let quotaExceededMessage = "You've reached this server's storage limit. Delete items or ask the server's admin."

/// 400 `secret_key_required` (policy): new account keys need a Secret Key.
public let secretKeyPolicyMessage = "Your server requires a Secret Key. Turn on \"Use a Secret Key\" and try again."

/// 400 `kdf_too_weak` (policy): the keys were made for minimums the server no longer has (the
/// app reads them right before; the policy changed meanwhile).
public let kdfTooWeakMessage = "Your server's encryption settings have changed. Try again."

/// 507 `insufficient_storage`: the server's disk is down to the admin's reserve, so it keeps
/// what it has and refuses anything new (reading, syncing and deleting still work).
public let outOfStorageMessage = "Your server is running out of storage space, so this wasn't saved. Ask the server's admin."

/// 403 `quota_exceeded` for the admin's attachment storage limit per account.
public let attachmentQuotaMessage = "You've reached your attachment storage limit."

/// 403 `reauth_required`: the step needs the master password confirmed (again).
public let reauthRequiredMessage = "Please confirm your master password again."

/// Server error codes with the app's own wording: the server's `message` is never shown for these.
let apiCodeText: [String: String] = [
    "invalid_credentials": "Wrong email, master password or Secret Key.",
    "email_not_verified": "Confirm your email address first, then sign in.",
    "account_disabled": "This account is disabled. Ask your server's admin.",
    "vault_key_changed": "This vault's key was just replaced. Try again.",
    "revision_conflict": "This was changed on another device just now, so nothing was saved. Try again.",
    "quota_exceeded": quotaExceededMessage,
    "insufficient_storage": outOfStorageMessage,
    "secret_key_required": secretKeyPolicyMessage,
    "kdf_too_weak": kdfTooWeakMessage,
    TwoStepGate.code: TwoStepGate.message,
    "reauth_required": reauthRequiredMessage,
    "expired": "This took too long and expired. Start again.",
    "invalid_code": "That code isn't right. Check it and try again.",
    "unauthorized": "Your session ended. Sign in again.",
    "session_expired": "Your session ended. Sign in again.",
    "signups_closed": "Sign-ups are closed on this server. Ask the server's admin.",
    "account_exists": "An account with this email address already exists. Sign in instead.",
    "not_found": "Your PassAuth server couldn't find this. It may have been deleted on another device.",
    "item_exists": "An item with the same id already exists. Try again.",
    "vault_exists": "A vault with the same id already exists. Try again.",
    "last_vault": "You can't delete your last vault.",
    "already_enabled": "This method is already on. Turn it off first to set it up again.",
    "too_large": "This is larger than your server allows.",
    "login_with_device_disabled": "Your server doesn't allow signing in with another device.",
    "attachments_disabled": "Files are turned off on this server.",
    "sends_disabled": "Send is turned off on this server.",
    "emergency_access_disabled": "Emergency access is turned off on this server.",
    // Signed sharing.
    "update_required": "This vault's members are signed. Update PassAuth to change them.",
    "members_changed": "The vault's members changed meanwhile, so the key wasn't changed. Check them and try again.",
    "member_roster_changed": "The vault's members changed meanwhile, so the key wasn't changed. Check them and try again.",
    "signing_identity_required": SharingText.needsIdentity,
    "bad_signature": "Your server didn't accept the signature, so nothing was changed.",
    "identity_exists": "This account already has a signing key.",
    "key_pins_changed": "Your list of known keys changed on another device. Try again.",
    // Made by the app itself (`ApiClient`): an answer that isn't a PassAuth server's.
    "not_passauth": "That address doesn't look like a PassAuth server.",
]

/// Messages the app knows, compared without case, where the code alone doesn't say enough: a
/// generic code (`bad_request`), or a code shared by two reasons (`expired`, `quota_exceeded`).
let apiMessageText: [String: String] = [
    "start setup first": "Setup has expired. Start again.",
    "attachment storage limit reached": attachmentQuotaMessage,
    "email is not configured on this server": "This server can't send email, so email codes aren't available.",
    "invalid email address": "Enter a valid email address.",
]

/// The longest piece of a server's own message that is shown, as a labelled detail.
public let serverMessageLimit = 200

/// What the app says about an error answer (client review F11): its own wording for every code
/// (and message) it knows; otherwise a sentence of its own with the request's reference,
/// and the server's message only as a labelled detail ("Server message: …"), cleaned
/// (`ShownText`) and at most 200 characters. A compromised server can't put instructions of its
/// own into the app's words this way.
public func apiErrorText(_ e: ApiError) -> String {
    if e.isRateLimited { return tooManyAttemptsMessage(e) ?? "Too many attempts. Wait a moment and try again." }
    // A known message first (it says more than its code), then the code.
    let reason = e.message.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if let known = apiMessageText[reason] ?? apiCodeText[e.code] { return known }
    if e.status == 507 { return outOfStorageMessage }
    let reference = e.requestId
    // A failure inside the server: its log has the details under the request's id.
    if e.status >= 500 && e.code == "internal" {
        return "Something went wrong on your PassAuth server. Try again; if it keeps happening, tell the server's admin"
            + (reference.map { " and give them this reference: \($0)" } ?? "") + "."
    }
    var parts = [e.status >= 500 ? "Something went wrong on your PassAuth server." : "Your PassAuth server refused this request."]
    if let reference { parts.append("Reference: \(reference).") }
    let detail = ShownText.clean(e.message, limit: serverMessageLimit)
    if !detail.isEmpty { parts.append("Server message: \(detail)") }
    return parts.joined(separator: " ")
}

/// "Too many attempts. Try again in 30 seconds." for a rate-limited request that said when to
/// retry (`Retry-After`), worded as the extension does; nil otherwise (callers keep their own
/// text for a limit without a time).
public func tooManyAttemptsMessage(_ e: ApiError) -> String? {
    guard e.isRateLimited, let s = e.retryAfter, s > 0 else { return nil }
    return "Too many attempts. Try again in \(waitText(s))."
}

/// A wait in plain words, never shorter than the real one: "a moment" (a second), "45 seconds"
/// (under a minute and a half), else whole minutes rounded up ("2 minutes", "60 minutes").
public func waitText(_ seconds: Int) -> String {
    if seconds <= 1 { return "a moment" }
    if seconds < 90 { return "\(seconds) seconds" }
    return "\((seconds + 59) / 60) minutes"
}

/// Seconds from a `Retry-After` header: a number of seconds, or an HTTP date (RFC 9110); nil if
/// absent or unreadable.
public func retryAfterSeconds(_ value: String?, now: Date = Date()) -> Int? {
    guard let v = value?.trimmingCharacters(in: .whitespaces), !v.isEmpty else { return nil }
    if v.allSatisfy({ $0.isASCII && $0.isNumber }) { return Int(v) }
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    guard let at = f.date(from: v) else { return nil }
    return max(0, Int(at.timeIntervalSince(now).rounded(.up)))
}

/// The message to show for any error (mirrors the Android app's `errorMessage`).
public func errorMessage(_ error: Error) -> String {
    if let e = error as? UserError {
        if e.message == secretKeyRequiredMessage { return "This account uses a Secret Key. Enter it from your Emergency Kit." }
        if e.message == "email_not_verified" { return "Confirm your email address first, then sign in." }
        return e.message
    }
    if let e = error as? ApiError { return apiErrorText(e) }
    if let e = error as? DeviceLoginStopped { return e.message }
    if let e = error as? CoreError {
        switch e {
        case .DecryptFailed: return "Wrong master password or Secret Key."
        // The server's key-derivation settings are outside what the core accepts (a server
        // asking for a cheap key, or one too costly for this device): nothing was derived.
        case .WeakKdf: return "Your server's encryption settings are weaker than PassAuth allows, so your master password wasn't used. Ask the server's admin."
        case .KdfTooStrong: return "Your server's encryption settings are stronger than this device can use. Ask the server's admin."
        case .PhraseMismatch: return DeviceApprovals.mismatch
        case .WrongCode: return "That code doesn't match."
        case .TooManyWrongCodes: return DeviceLogin.tooManyCodes
        case .NotConfirmed: return DeviceLogin.codePrompt
        // Signed sharing: something didn't verify (the views say what it was about).
        case .BadSignature, .IdentityMismatch, .Rollback, .RosterForked, .RosterUnauthorized:
            return "PassAuth couldn't verify the keys your server sent, so nothing was changed."
        case .TooLarge: return "The list of known keys is too large to save."
        case .ReviewMismatch: return "The vault's members changed after you checked them. Check them again."
        case .PasswordRequired(let m), .Invalid(let m): return "Something went wrong: \(m)"
        }
    }
    if let e = error as? ConflictError { return e.errorDescription ?? "Conflict." }
    let m = error.localizedDescription
    return m.isEmpty ? "Something went wrong." : m
}
