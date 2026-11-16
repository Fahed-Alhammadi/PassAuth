import Foundation

/// A message from the server's live sync socket (`GET /api/ws`, see the server's `ws.rs`).
public enum LiveMessage: Equatable, Sendable {
    /// The first message on a socket: the live-sync origin of this session (`origin` of the
    /// sync messages its own writes cause).
    case hello(origin: String)
    /// The account's data changed: the new sync revision, the new number of each vault written
    /// (nil from older servers; empty for profile or account changes) and the session that wrote
    /// (nil for the server's own changes and for notices from several sessions merged into one).
    case sync(revision: Int64, vaults: [String: Int64]? = nil, origin: String? = nil)
    /// Sessions of this account were ended on the server (password change, admin, deletion).
    case logout
    /// A new device asks to sign in to this account (sign in with another device).
    case authRequest(id: String)
    /// A sign-in request was answered (on any device) or is gone.
    case authRequestAnswered(id: String)
    /// The server now requires two-step login and the account has no method yet: it closes the
    /// socket next (code 1008, reason `two_step_required`) and answers other requests with 403
    /// `two_step_required` until a method is on.
    case twoStepRequired
}

/// What the app does about a `LiveMessage`.
public enum LiveAction: Equatable, Sendable {
    case ignore, sync, checkSession
    /// List the account's sign-in requests again (the app; AutoFill has no socket).
    case listAuthRequests
    /// Close that request's sheet, if it is shown.
    case authRequestAnswered(String)
    /// Stop live sync and show the two-step setup screen (as for a 403 `two_step_required`).
    case twoStepRequired
}

/// The pure parts of live sync (unit-tested), like the Android app's `LiveSyncProtocol`.
public enum LiveSyncProtocol {
    public static func parse(_ text: String) -> LiveMessage? {
        guard let j = try? JSON.parse(Data(text.utf8)) else { return nil }
        switch j.str("type") {
        case "hello":
            guard let origin = j["origin"]?.string else { return nil }
            return .hello(origin: origin)
        case "sync":
            let revision: Int64
            switch j["revision"] {
            case .int(let n)?: revision = n
            case .double(let d)?: revision = Int64(d)
            default: return nil
            }
            return .sync(revision: revision, vaults: DeltaSync.vaultNumbers(j["vaults"]), origin: j["origin"]?.string)
        case "logout": return .logout
        case "auth_request":
            guard let id = j["id"]?.string, !id.isEmpty else { return nil }
            return .authRequest(id: id)
        case "auth_request_answered":
            guard let id = j["id"]?.string, !id.isEmpty else { return nil }
            return .authRequestAnswered(id: id)
        case TwoStepGate.code: return .twoStepRequired
        default: return nil
        }
    }

    /// A sync message refreshes the copy only when it has something the copy lacks
    /// (`SyncDecision.onLiveSync`: a vault number newer than the copy's, or no vault numbers
    /// at all for a profile or account change; older servers: a newer revision), whichever
    /// session wrote it: this device's own saves are already in the copy. `have`: the open
    /// copy's position, nil while locked. A logout message makes the app check its session: an
    /// ended one signs the account out through the refresh-token path; a live one (another
    /// device's sessions were ended) is left alone.
    public static func action(_ msg: LiveMessage?, have: SyncPosition?) -> LiveAction {
        switch msg {
        case nil, .hello: .ignore
        case .sync(let r, let vaults, _): SyncDecision.onLiveSync(revision: r, vaults: vaults, have: have) ? .sync : .ignore
        case .logout: .checkSession
        case .authRequest: .listAuthRequests
        case .authRequestAnswered(let id): .authRequestAnswered(id)
        case .twoStepRequired: .twoStepRequired
        }
    }

    /// The close code and reason a server ends a socket with when it requires two-step login
    /// first (1008 "policy violation", reason `two_step_required`): the app stops reconnecting.
    public static func closedForTwoStep(code: Int, reason: Data?) -> Bool {
        code == 1008 && reason.map { String(decoding: $0, as: UTF8.self) } == TwoStepGate.code
    }

    /// `ws(s)://server/api/ws?access_token=…` (sockets can't always send headers; the server accepts the query).
    public static func socketURL(server: String, accessToken: String) -> URL? {
        let base: String
        if server.hasPrefix("https://") {
            base = "wss://" + server.dropFirst("https://".count)
        } else if server.hasPrefix("http://") {
            base = "ws://" + server.dropFirst("http://".count)
        } else {
            return nil
        }
        guard var c = URLComponents(string: base + "/api/ws") else { return nil }
        c.queryItems = [URLQueryItem(name: "access_token", value: accessToken)]
        // URLComponents leaves "+" alone in queries; the server would read it as a space.
        let query = c.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        c.percentEncodedQuery = query
        return c.url
    }

    /// Reconnect delay in milliseconds: 1 s, 2 s, 4 s … up to a minute, plus up to 20% jitter (0…1).
    public static func backoffMillis(attempt: Int, jitter: Double = 0) -> Int64 {
        let base = min(Int64(1_000) << Int64(min(max(attempt, 0), 6)), 60_000)
        return base + Int64(Double(base) * min(max(jitter, 0), 1) * 0.2)
    }
}
