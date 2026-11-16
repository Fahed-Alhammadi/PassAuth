import Foundation

// Settings → Account security → Signed-in devices (the web vault's Settings → Sessions): the
// account's sessions (`GET /api/account/sessions`), signing one out (`DELETE
// /api/account/sessions/{id}`) and every other one at once (`POST
// /api/account/sessions/revoke-others`, offered only when `GET /api/config` lists the
// `revoke_others` feature), and forgetting a device (`POST
// /api/account/devices/{device_id}/forget`, with the `forget_device` feature): every session of
// that device ends and its next sign-in counts as a new device (two-step login again).

/// One signed-in session of the account.
public struct SessionInfo: Equatable, Sendable, Identifiable {
    public var id: String
    /// The device the session belongs to (several sessions can share one: the app and its
    /// AutoFill extension, or sign-ins after sign-outs).
    public var deviceId: String
    public var deviceName: String
    /// The device's kind as it signed in: `web`, `extension`, `desktop`, `mobile`, `cli`.
    public var deviceKind: String
    /// The app that signed in (`X-PassAuth-Client`, e.g. `ios/0.6.0`); nil from older servers
    /// and sessions.
    public var client: String?
    /// Unix seconds.
    public var createdAt: Int64
    public var lastUsed: Int64
    /// This app's own session (signing it out is "Log out").
    public var current: Bool

    public init(id: String, deviceId: String = "", deviceName: String = "", deviceKind: String = "", client: String? = nil, createdAt: Int64 = 0, lastUsed: Int64 = 0, current: Bool = false) {
        self.id = id
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.deviceKind = deviceKind
        self.client = client
        self.createdAt = createdAt
        self.lastUsed = lastUsed
        self.current = current
    }
}

/// The account's sessions as the server lists them (most recently used first), and whether it
/// can sign out all the others in one request.
public struct SessionList: Equatable, Sendable {
    public var sessions: [SessionInfo]
    /// `features` of `/api/config` has `revoke_others`.
    public var canRevokeOthers: Bool
    /// `features` of `/api/config` has `forget_device`.
    public var canForget: Bool

    public init(sessions: [SessionInfo], canRevokeOthers: Bool, canForget: Bool = false) {
        self.sessions = sessions
        self.canRevokeOthers = canRevokeOthers
        self.canForget = canForget
    }

    /// `{"current": id, "sessions": [{id, device_id, device_name, device_kind, client, created_at, last_used}]}`.
    public init(json j: JSON, canRevokeOthers: Bool, canForget: Bool = false) {
        let current = j.str("current")
        sessions = (j["sessions"]?.array ?? []).compactMap { s in
            let id = s.str("id")
            guard !id.isEmpty else { return nil }
            let client = s["client"]?.string?.trimmingCharacters(in: .whitespaces)
            return SessionInfo(id: id, deviceId: s.str("device_id"), deviceName: s.str("device_name"), deviceKind: s.str("device_kind"),
                               client: client?.isEmpty == false ? client : nil,
                               createdAt: s["created_at"]?.int ?? 0, lastUsed: s["last_used"]?.int ?? 0, current: id == current)
        }
        self.canRevokeOthers = canRevokeOthers
        self.canForget = canForget
    }

    /// The sessions other than this app's.
    public var others: [SessionInfo] { sessions.filter { !$0.current } }

    /// Whether "Forget…" is offered for a session (the server has the feature and named its device).
    public func canForget(_ s: SessionInfo) -> Bool { canForget && !s.deviceId.isEmpty }

    /// How many listed sessions belong to a device.
    public func sessionCount(device deviceId: String) -> Int { sessions.filter { $0.deviceId == deviceId }.count }

    /// Whether a device is the one this app runs on (it holds this app's session).
    public func isThisDevice(_ deviceId: String) -> Bool { sessions.contains { $0.current && $0.deviceId == deviceId } }
}

/// Session wording, as the web vault's Sessions tab (pure, unit-tested).
public enum SessionText {
    /// Apps by the name they send in `X-PassAuth-Client` (`<name>/<version>`); `version` false
    /// leaves the version out.
    private static let clients: [String: (label: String, version: Bool)] = [
        "web": ("Web", false),
        "desktop": ("Desktop app", true),
        "extension": ("Chrome extension", true),
        "chrome": ("Chrome extension", true),
        "chrome-extension": ("Chrome extension", true),
        "ios": ("iPhone app", true),
        "iphone": ("iPhone app", true),
        "ipad": ("iPad app", true),
        "ios-autofill": ("iPhone AutoFill", true),
        "android": ("Android app", true),
        "macos-autofill": ("Mac AutoFill", true),
        "mac-autofill": ("Mac AutoFill", true),
        "cli": ("Command line", true),
    ]

    /// The app in plain words: "desktop/0.7.0" → "Desktop app 0.7.0", "web/0.9.0" → "Web",
    /// "ios/0.6.0" → "iPhone app 0.6.0"; an unknown name as sent (first letter capitalised) with
    /// its version; nil when the session has no client (older servers).
    public static func client(_ raw: String?) -> String? {
        guard let raw = raw?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        let parts = raw.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let name = parts[0].lowercased().replacingOccurrences(of: "[\\s_]+", with: "-", options: .regularExpression)
        let version = parts.count > 1 ? parts[1].trimmingCharacters(in: .whitespaces) : ""
        let shown = version.range(of: "^[0-9][A-Za-z0-9_.+-]{0,31}$", options: .regularExpression) != nil ? version : ""
        guard let known = clients[name] else {
            let label = String(name.prefix(40))
            guard let first = label.first else { return nil }
            return first.uppercased() + label.dropFirst() + (shown.isEmpty ? "" : " \(shown)")
        }
        return known.version && !shown.isEmpty ? "\(known.label) \(shown)" : known.label
    }

    /// The device kind, for sessions without a client.
    public static func kind(_ kind: String) -> String {
        switch kind {
        case "web": "Web vault"
        case "extension": "Browser extension"
        case "cli": "Command line"
        case "desktop": "Desktop app"
        case "mobile": "Mobile app"
        case "": "Unknown app"
        default: kind.prefix(1).uppercased() + kind.dropFirst()
        }
    }

    /// The app of a session: its client, else its device kind.
    public static func app(_ s: SessionInfo) -> String {
        client(s.client) ?? kind(s.deviceKind)
    }

    /// "Just now", "5 min ago", "3 hours ago", "2 days ago", else the date.
    public static func ago(_ ts: Int64, now: Date = Date()) -> String {
        let s = max(0, Int64(now.timeIntervalSince1970) - ts)
        if s < 60 { return "Just now" }
        if s < 3600 { return "\(s / 60) min ago" }
        if s < 86_400 {
            let h = s / 3600
            return "\(h) hour\(h == 1 ? "" : "s") ago"
        }
        if s < 30 * 86_400 {
            let d = s / 86_400
            return "\(d) day\(d == 1 ? "" : "s") ago"
        }
        return Date(timeIntervalSince1970: TimeInterval(ts)).formatted(date: .abbreviated, time: .omitted)
    }

    /// The line under a session's app: "Signed in 12 Nov 2026 · last used 5 min ago" ("in use
    /// now" for this app's own session).
    public static func detail(_ s: SessionInfo, now: Date = Date()) -> String {
        let signedIn = "Signed in " + Date(timeIntervalSince1970: TimeInterval(s.createdAt)).formatted(date: .abbreviated, time: .omitted)
        if s.current { return signedIn + " · in use now" }
        let used = ago(s.lastUsed, now: now)
        return signedIn + " · last used " + (used == "Just now" ? "just now" : used)
    }

    /// The notice after signing the others out ("2 other sessions signed out").
    public static func revokedOthers(_ n: Int?) -> String {
        guard let n else { return "Other sessions signed out." }
        return "\(n) other \(n == 1 ? "session" : "sessions") signed out."
    }

    /// The page's intro, with a line about forgetting where the server offers it.
    public static func intro(canForget: Bool) -> String {
        "Signing a device out ends its session there. It needs your master password to sign in again."
            + (canForget ? " Forgetting a device also ends its other sessions and makes its next sign-in count as a new device, so a remembered device has to use two-step login again." : "")
    }

    public static let forgetTitle = "Forget this device?"

    /// What forgetting a device does: `sessions` = its listed sessions, `here` = this device.
    public static func forgetBody(sessions: Int, here: Bool) -> String {
        (sessions > 1 ? "Its \(sessions) sessions are signed out at once." : "Its session is signed out at once.")
            + " The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it."
            + (here ? " This is the device you're using, so you're signed out here too." : "")
    }

    public static func forgetAction(here: Bool) -> String { here ? "Forget and sign out" : "Forget device" }

    /// The notice afterwards.
    public static func forgotten(_ deviceName: String, here: Bool) -> String {
        here ? "This device was forgotten and signed out." : "\(deviceName.isEmpty ? "Device" : deviceName) forgotten."
    }
}

extension VaultRepository {
    /// The active account's sessions, and whether its server signs out all others in one request.
    public func accountSessions() async throws -> SessionList {
        let id = activeId
        let j = try await api.call(id, "/account/sessions")
        // Feature check (API v2); an older server or a failed check just hides the bulk action.
        let config = try? await api.call(id, "/config", auth: false)
        let features = (config?["features"]?.array ?? []).compactMap(\.string)
        return SessionList(json: j, canRevokeOthers: features.contains("revoke_others"), canForget: features.contains("forget_device"))
    }

    /// Forget one of the account's devices: every session it holds ends at once and its next
    /// sign-in counts as a new device (two-step login again, new-device email). Forgetting this
    /// device signs the account out here too, without asking the server again (it already ended
    /// the session), and drops the "remember this device" token the server forgot. Returns
    /// whether it was this device.
    public func forgetDevice(_ deviceId: String) async throws -> Bool {
        let id = activeId
        let r = try await api.call(id, "/account/devices/\(Self.pathSegment(deviceId))/forget", method: "POST")
        guard r["current"]?.bool == true else { return false }
        if activeId == id { await signOut(remote: false, forgetRememberToken: true) }
        return true
    }

    /// Sign out one of the account's other sessions (this app's own is "Log out").
    public func revokeSession(_ sessionId: String) async throws {
        let path = sessionId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? sessionId
        _ = try await api.call(activeId, "/account/sessions/\(path)", method: "DELETE")
    }

    /// Sign out every other session of the account at once; this one stays. Returns how many,
    /// when the server says.
    public func revokeOtherSessions() async throws -> Int? {
        let r = try await api.call(activeId, "/account/sessions/revoke-others", method: "POST")
        return r["revoked"].map { Int($0.int) }
    }
}
