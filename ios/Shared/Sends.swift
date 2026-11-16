import Foundation
import PassAuthCore

/// Send (servers with the `sends` feature): text shared through a link,
/// `<server>/send/<id>#<key>`. The app encrypts the name and the text with a random send key that
/// exists only in the link's fragment and keeps the key wrapped by the account key
/// (`owner_key`), so the owner can copy the link and edit the Send later. The server stores
/// ciphertext only; an optional password is checked by the server with a verifier derived from it
/// (`access_salt`), not used for encryption.
///
/// The rules are the web vault's `web/src/lib/sends.ts` (pure, `SendsTests`); the requests are
/// `VaultRepository`'s below (`send-client.ts`).
public let sendsFeature = "sends"

public enum SendRules {
    /// The link to share: the server's address, the Send's id and, after `#`, its key.
    public static func link(origin: String, id: String, key: String) -> String {
        var o = origin
        while o.hasSuffix("/") { o.removeLast() }
        let path = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-_.~"))) ?? id
        return "\(o)/send/\(path)#\(key)"
    }

    /// The link with its key (everything after `#`) hidden, for showing it on screen.
    public static func masked(_ link: String) -> String {
        guard let at = link.firstIndex(of: "#") else { return link }
        return String(link[...at]) + String(repeating: "\u{2022}", count: 12)
    }

    // MARK: Sizes

    /// Bytes the core adds when it encrypts a field: a version byte, the 24-byte nonce, the 16-byte tag.
    static let overhead = 1 + 24 + 16

    public static func utf8Length(_ text: String) -> Int { text.utf8.count }

    /// Characters of the encrypted field (unpadded base64url) for `plainBytes` bytes of text.
    public static func encryptedFieldLength(_ plainBytes: Int) -> Int { ((plainBytes + overhead) * 4 + 2) / 3 }

    /// The most text (UTF-8 bytes) that fits the server's limit on the encrypted text.
    public static func maxTextBytes(_ maxEncrypted: Int) -> Int { max(0, (maxEncrypted * 3) / 4 - overhead) }

    public static let defaultMaxBytes = 1024 * 1024
    public static let defaultMaxDays = 30
    /// Longest name accepted in the form.
    public static let nameMax = 200
    /// Most views a Send may allow (the server's limit).
    public static let maxViews = 1_000_000

    /// `send_max_days` and `send_max_bytes` from `/api/config` `limits`, with the server's defaults.
    public static func limits(_ limits: JSON?) -> (maxDays: Int, maxBytes: Int) {
        func whole(_ v: JSON?, _ min: Double, _ fallback: Int, max: Int64) -> Int {
            switch v {
            case .int(let n)? where Double(n) >= min: return Int(Swift.min(n, max))
            case .double(let d)? where d.isFinite && d >= min: return Int(Swift.min(d, Double(max)).rounded(.down))
            default: return fallback
            }
        }
        // Upper bounds keep day and byte arithmetic (days × 86400, bytes × 3) from overflowing.
        return (whole(limits?["send_max_days"], 1, defaultMaxDays, max: 36_500), whole(limits?["send_max_bytes"], 1024, defaultMaxBytes, max: 1 << 40))
    }

    // MARK: Durations

    static let hour = 3600
    static let day = 24 * hour

    static let presets: [(Int, String)] = [
        (hour, "1 hour"), (day, "1 day"), (2 * day, "2 days"), (3 * day, "3 days"), (7 * day, "7 days"),
        (14 * day, "14 days"), (30 * day, "30 days"), (90 * day, "90 days"), (180 * day, "180 days"), (365 * day, "365 days"),
    ]

    static func dayLabel(_ days: Int) -> String { "\(days) \(days == 1 ? "day" : "days")" }

    /// The durations within `maxDays`, and the limit itself when it isn't one of them.
    public static func durationChoices(_ maxDays: Int) -> [(seconds: Int, label: String)] {
        let maxSeconds = max(1, maxDays) * day
        let within = presets.filter { $0.0 <= maxSeconds }
        let out = within.map { (seconds: $0.0, label: $0.1) }
        return within.contains { $0.0 == maxSeconds } ? out : out + [(seconds: maxSeconds, label: dayLabel(maxSeconds / day))]
    }

    /// The deletion offered first: 7 days, or the server's limit when that is shorter.
    public static func defaultDeletion(_ maxDays: Int) -> Int { min(7 * day, max(1, maxDays) * day) }
}

/// A Send as its owner's list shows it (`GET /sends`); `name` and `ownerKey` are encrypted.
public struct OwnedSend: Identifiable, Equatable, Sendable {
    public let id: String
    public var name: String
    public var ownerKey: String
    public var hasPassword: Bool
    public var accessSalt: String?
    public var maxViews: Int64?
    public var views: Int64
    public var expiresAt: Int64?
    public var deleteAt: Int64
    public var disabled: Bool
    public var hideEmail: Bool
    /// Whether a visitor can open it right now (the server's answer).
    public var available: Bool
    public var createdAt: Int64
    public var updatedAt: Int64
    /// Encrypted text: only in `GET /sends/{id}`.
    public var data: String?

    static func number(_ v: JSON?) -> Int64? { v?.number }

    static func text(_ v: JSON?) -> String? {
        if case .string(let s)? = v, !s.isEmpty { return s }
        return nil
    }

    /// One Send from the owner's API, or nil when malformed.
    public init?(json s: JSON) {
        guard case .object = s, let id = Self.text(s["id"]), let name = Self.text(s["name"]), let ownerKey = Self.text(s["owner_key"]),
              let deleteAt = Self.number(s["delete_at"]) else { return nil }
        self.id = id
        self.name = name
        self.ownerKey = ownerKey
        self.deleteAt = deleteAt
        hasPassword = s["has_password"] == .bool(true)
        accessSalt = Self.text(s["access_salt"])
        maxViews = Self.number(s["max_views"])
        views = Self.number(s["views"]) ?? 0
        expiresAt = Self.number(s["expires_at"])
        disabled = s["disabled"] == .bool(true)
        hideEmail = s["hide_email"] == .bool(true)
        if case .bool(let b)? = s["available"] { available = b } else { available = true }
        createdAt = Self.number(s["created_at"]) ?? 0
        updatedAt = Self.number(s["updated_at"]) ?? 0
        data = Self.text(s["data"])
    }

    /// `GET /sends`: the owner's Sends as the server sends them; malformed entries left out.
    public static func list(_ j: JSON?) -> [OwnedSend] {
        (j?["sends"]?.array ?? []).compactMap { OwnedSend(json: $0) }
    }
}

public enum SendState: String, Sendable {
    case available, disabled, usedUp = "used-up", expired, deleted, unavailable

    public var label: String {
        switch self {
        case .available: "Active"
        case .disabled: "Turned off"
        case .usedUp: "Used up"
        case .expired: "Expired"
        case .deleted: "Deleted"
        case .unavailable: "Unavailable"
        }
    }
}

extension OwnedSend {
    /// Why a Send can or can't be opened right now (its own settings first, then the server's say).
    public func state(now: Int64) -> SendState {
        if deleteAt <= now { return .deleted }
        if disabled { return .disabled }
        if let e = expiresAt, e <= now { return .expired }
        if let m = maxViews, views >= m { return .usedUp }
        return available ? .available : .unavailable
    }

    /// "Not opened yet", "Opened 3 times", "Opened 2 of 5 times".
    public static func viewsText(views: Int64, maxViews: Int64?) -> String {
        if let m = maxViews { return "Opened \(views) of \(m) \(m == 1 ? "time" : "times")" }
        if views == 0 { return "Not opened yet" }
        return "Opened \(views) \(views == 1 ? "time" : "times")"
    }

    public var viewsText: String { Self.viewsText(views: views, maxViews: maxViews) }
}

/// What a change of a Send sends (`PUT /sends/{id}` takes only what changed).
public struct SendChanges: Equatable, Sendable {
    public enum Password: Equatable, Sendable {
        case remove
        case set(salt: String, verifier: String)
    }

    public enum Value<T: Equatable & Sendable>: Equatable, Sendable {
        case keep
        case set(T)
    }

    public var name: String?
    public var data: String?
    /// nil keeps the current password.
    public var password: Password?
    public var maxViews: Value<Int64?> = .keep
    public var expiresAt: Value<Int64?> = .keep
    public var deleteAt: Int64?
    public var disabled: Bool?
    public var hideEmail: Bool?

    public init() {}

    /// The `PUT /sends/{id}` body (null clears `max_views` / `expires_at`; `access_verifier: null`
    /// removes the password).
    public var body: JSON {
        var o: [String: JSON] = [:]
        if let name { o["name"] = .string(name) }
        if let data { o["data"] = .string(data) }
        switch password {
        case .remove?: o["access_verifier"] = .null
        case .set(let salt, let verifier)?:
            o["access_salt"] = .string(salt)
            o["access_verifier"] = .string(verifier)
        case nil: break
        }
        if case .set(let v) = maxViews { o["max_views"] = v.map(JSON.int) ?? .null }
        if case .set(let v) = expiresAt { o["expires_at"] = v.map(JSON.int) ?? .null }
        if let deleteAt { o["delete_at"] = .int(deleteAt) }
        if let disabled { o["disabled"] = .bool(disabled) }
        if let hideEmail { o["hide_email"] = .bool(hideEmail) }
        return .object(o)
    }
}

/// A new Send as the editor made it (plaintext; the repository encrypts it).
public struct NewSend: Sendable {
    public var name: String
    public var text: String
    public var password: String?
    public var maxViews: Int64?
    public var expiresAt: Int64?
    public var deleteAt: Int64
    public var hideEmail: Bool

    public init(name: String, text: String, password: String?, maxViews: Int64?, expiresAt: Int64?, deleteAt: Int64, hideEmail: Bool) {
        self.name = name
        self.text = text
        self.password = password
        self.maxViews = maxViews
        self.expiresAt = expiresAt
        self.deleteAt = deleteAt
        self.hideEmail = hideEmail
    }
}

/// What the owner changed (plaintext name and text, a new password, settings); nil keeps.
public struct SendEdit: Sendable {
    public var name: String?
    public var text: String?
    /// `.some(nil)` removes the password; `.some(p)` sets `p`.
    public var password: String??
    public var maxViews: SendChanges.Value<Int64?> = .keep
    public var expiresAt: SendChanges.Value<Int64?> = .keep
    public var deleteAt: Int64?
    public var disabled: Bool?
    public var hideEmail: Bool?

    public init() {}
}

// MARK: Requests (the owner's side, `send-client.ts`)

extension VaultRepository {
    private static let sendUnexpected = "The server sent an unexpected response. Try again."

    /// The active account's unlocked keys (Sends need them for everything but deleting).
    private func sendAccount() throws -> Account {
        guard let s = sessions[activeId] else { throw UserError("The vault is locked. Unlock it and try again.") }
        return s.account
    }

    /// The active account's server's `/api/config`, asked now: whether Send is on and its limits.
    public func sendConfig() async -> (enabled: Bool, maxDays: Int, maxBytes: Int)? {
        guard let config = await fetchConfig(activeId) else { return nil }
        let l = SendRules.limits(config.limits)
        return (config.features.contains(sendsFeature), l.maxDays, l.maxBytes)
    }

    /// The Send's key (for its link and its text), from its `owner_key`.
    public func sendKey(_ s: OwnedSend) throws -> String {
        try sendAccount().unwrapSendKey(wrapped: s.ownerKey)
    }

    /// The link to share.
    public func sendLink(_ s: OwnedSend) throws -> String {
        SendRules.link(origin: state.server, id: s.id, key: try sendKey(s))
    }

    /// The Send's name, or nil when it can't be decrypted (made by a key this account no longer has).
    public func sendName(_ s: OwnedSend) -> String? {
        guard let key = try? sendKey(s) else { return nil }
        return try? sendDecrypt(key: key, field: "name", ciphertext: s.name)
    }

    /// The Send's text (`data`, from `GET /sends/{id}`).
    public func sendText(_ s: OwnedSend) throws -> String {
        guard let data = s.data else { throw UserError(Self.sendUnexpected) }
        return try sendDecrypt(key: try sendKey(s), field: "data", ciphertext: data)
    }

    public func listSends() async throws -> [OwnedSend] {
        OwnedSend.list(try await api.call(activeId, "/sends"))
    }

    /// One Send with its text.
    public func getSend(_ id: String) async throws -> OwnedSend {
        guard let s = OwnedSend(json: try await api.call(activeId, "/sends/\(Self.pathPart(id))")) else { throw UserError(Self.sendUnexpected) }
        return s
    }

    /// A new password's salt and verifier (Argon2id, about a second, off the main thread).
    private func sendPasswordFields(_ password: String) async throws -> (salt: String, verifier: String) {
        try await core {
            let salt = try sendPasswordSalt()
            return (salt, try sendPasswordVerifier(password: password, salt: salt))
        }
    }

    /// Encrypt and save a new Send; returns it and its link (the only place its key is shown).
    public func createSend(_ d: NewSend) async throws -> (send: OwnedSend, link: String) {
        let account = try sendAccount()
        let id = activeId
        let server = state.server
        let key = try sendNewKey()
        var body: [String: JSON] = [
            "kind": "text",
            "name": .string(try sendEncrypt(key: key, field: "name", plaintext: d.name)),
            "data": .string(try sendEncrypt(key: key, field: "data", plaintext: d.text)),
            "owner_key": .string(try account.wrapSendKey(key: key)),
            "max_views": d.maxViews.map(JSON.int) ?? .null,
            "expires_at": d.expiresAt.map(JSON.int) ?? .null,
            "delete_at": .int(d.deleteAt),
            "hide_email": .bool(d.hideEmail),
            "disabled": false,
        ]
        if let p = d.password, !p.isEmpty {
            let f = try await sendPasswordFields(p)
            body["access_salt"] = .string(f.salt)
            body["access_verifier"] = .string(f.verifier)
        }
        guard let send = OwnedSend(json: try await api.call(id, "/sends", body: .object(body))) else { throw UserError(Self.sendUnexpected) }
        return (send, SendRules.link(origin: server, id: send.id, key: key))
    }

    /// Save changes to a Send: only what changed is sent; name and text are encrypted again with
    /// the same key (the link has it).
    @discardableResult
    public func updateSend(_ s: OwnedSend, _ edit: SendEdit) async throws -> OwnedSend {
        var changes = SendChanges()
        changes.maxViews = edit.maxViews
        changes.expiresAt = edit.expiresAt
        changes.deleteAt = edit.deleteAt
        changes.disabled = edit.disabled
        changes.hideEmail = edit.hideEmail
        if edit.name != nil || edit.text != nil {
            let key = try sendKey(s)
            if let n = edit.name { changes.name = try sendEncrypt(key: key, field: "name", plaintext: n) }
            if let t = edit.text { changes.data = try sendEncrypt(key: key, field: "data", plaintext: t) }
        }
        switch edit.password {
        case .some(.none): changes.password = .remove
        case .some(.some(let p)) where !p.isEmpty:
            let f = try await sendPasswordFields(p)
            changes.password = .set(salt: f.salt, verifier: f.verifier)
        default: break
        }
        guard let send = OwnedSend(json: try await api.call(activeId, "/sends/\(Self.pathPart(s.id))", body: changes.body, method: "PUT")) else {
            throw UserError(Self.sendUnexpected)
        }
        return send
    }

    public func deleteSend(_ id: String) async throws {
        _ = try await api.call(activeId, "/sends/\(Self.pathPart(id))", method: "DELETE")
    }

    /// A server-chosen id as one path segment.
    nonisolated static func pathPart(_ id: String) -> String {
        id.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-_.~"))) ?? id
    }
}
