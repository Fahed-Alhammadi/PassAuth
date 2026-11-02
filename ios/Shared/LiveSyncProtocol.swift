import Foundation

/// A message from the server's live sync socket (`GET /api/ws`, see the server's `ws.rs`).
public enum LiveMessage: Equatable, Sendable {
    /// The account's data changed; the new sync revision.
    case sync(revision: Int64)
    /// Sessions of this account were ended on the server (password change, admin, deletion).
    case logout
}

/// What the app does about a `LiveMessage`.
public enum LiveAction: Equatable, Sendable { case ignore, sync, checkSession }

/// The pure parts of live sync (unit-tested), like the Android app's `LiveSyncProtocol`.
public enum LiveSyncProtocol {
    public static func parse(_ text: String) -> LiveMessage? {
        guard let j = try? JSON.parse(Data(text.utf8)) else { return nil }
        switch j.str("type") {
        case "sync":
            switch j["revision"] {
            case .int(let n)?: return .sync(revision: n)
            case .double(let d)?: return .sync(revision: Int64(d))
            default: return nil
            }
        case "logout": return .logout
        default: return nil
        }
    }

    /// A sync message refreshes the vault only when its revision is newer than the one on
    /// screen (our own saves also send one, after we already re-synced). A logout message makes
    /// the app check its session: an ended one signs the account out through the refresh-token
    /// path; a live one (another device's sessions were ended) is left alone.
    public static func action(_ msg: LiveMessage?, currentRevision: Int64?) -> LiveAction {
        switch msg {
        case nil: .ignore
        case .sync(let r): (currentRevision.map { r > $0 } ?? false) ? .sync : .ignore
        case .logout: .checkSession
        }
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
