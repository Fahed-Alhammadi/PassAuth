import Foundation

/// Refuses redirects: a PassAuth server never redirects API calls, and following one could
/// send tokens elsewhere.
private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// HTTP client for PassAuth servers: bearer auth, refresh-token rotation on 401 and
/// per-account pinning (a request always uses the server and tokens of the account it was
/// started for, even if the user switches accounts meanwhile).
///
/// Refresh tokens rotate and the server revokes the session when one is used twice, so the app
/// and its AutoFill extension must never refresh with the same token: a refresh runs under a
/// cross-process file lock per account, re-reads the tokens from the Keychain first, and only
/// calls the server when the stored access token is still the one that was rejected (else the
/// other process already rotated them and the new ones are used).
@MainActor
public final class ApiClient {
    public let session: URLSession
    private let store: SecureStore
    private var refreshing: [String: Task<RefreshResult, Never>] = [:]

    /// Called when an account's session can't be refreshed (it is signed out).
    public var onSessionLost: (@MainActor (String) -> Void)?

    /// The app wraps a token refresh in a background task (it holds a shared-container lock,
    /// and iOS terminates apps suspended while holding one). Returns the function ending it.
    public var beginBackgroundWork: (@MainActor () -> (@MainActor () -> Void))?

    enum RefreshResult: Sendable { case refreshed, rejected, unavailable }

    /// `configure` adjusts the session (tests register a URLProtocol).
    public init(store: SecureStore, configure: ((URLSessionConfiguration) -> Void)? = nil) {
        self.store = store
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.waitsForConnectivity = false
        configure?(config)
        session = URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
    }

    /// An API call (`path` below `/api`) as JSON.
    public func call(_ accountId: String, _ path: String, body: JSON? = nil, method: String? = nil, auth: Bool = true, headers: [String: String] = [:]) async throws -> JSON {
        let data = try await callData(accountId, path, body: body, method: method, auth: auth, headers: headers)
        if data.isEmpty { return .null }
        guard let j = try? JSON.parse(data) else {
            throw ApiError(status: 200, code: "not_passauth", message: "That address doesn't look like a PassAuth server.")
        }
        return j
    }

    /// An API call returning the raw response body (`/sync` is cached as received).
    public func callData(_ accountId: String, _ path: String, body: JSON? = nil, method: String? = nil, auth: Bool = true, headers: [String: String] = [:]) async throws -> Data {
        let m = method ?? (body == nil ? "GET" : "POST")
        var usedAccess = ""
        func send() async throws -> (Data, HTTPURLResponse) {
            let s = store.get()
            guard let a = s.file.accounts[accountId], !a.server.isEmpty, let url = URL(string: a.server + "/api" + path) else {
                throw UserError("Set your PassAuth server address first.")
            }
            var req = URLRequest(url: url)
            req.httpMethod = m
            if let body {
                req.httpBody = body.data
                req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
            if auth, let t = s.tokens(accountId) {
                usedAccess = t.access
                req.setValue("Bearer \(t.access)", forHTTPHeaderField: "Authorization")
            }
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
            return try await execute(req)
        }
        var (data, res) = try await send()
        if res.statusCode == 401 && auth {
            switch await refresh(accountId, rejected: usedAccess) {
            case .refreshed:
                (data, res) = try await send()
            case .unavailable:
                throw UserError("Can't reach your PassAuth server. Check the server address and your connection.")
            case .rejected:
                store.update { $0.secrets.tokens[accountId] = nil }
                onSessionLost?(accountId)
                throw ApiError(status: 401, code: "unauthorized", message: "Your session ended. Sign in again.")
            }
        }
        return try check(data, res)
    }

    /// A request to a server URL directly (server setup check).
    public func get(_ url: URL) async throws -> (Data, HTTPURLResponse) {
        try await execute(URLRequest(url: url))
    }

    /// Rotate the tokens after `rejected` (the access token sent) got a 401.
    func refresh(_ accountId: String, rejected: String) async -> RefreshResult {
        if let running = refreshing[accountId] { return await running.value }
        let task = Task<RefreshResult, Never> { @MainActor in
            let endWork = beginBackgroundWork?()
            defer { endWork?() }
            let lockURL = FileLock.url("refresh-\(accountId.filter { $0.isLetter || $0.isNumber || $0 == "-" })", directory: store.directory)
            // The other process may be refreshing right now (one request, at most 20 s).
            guard let lock = await FileLock.acquire(lockURL, timeout: 25) else { return .unavailable }
            defer { lock.release() }
            store.reload()
            let s = store.get()
            guard let a = s.file.accounts[accountId], let tokens = s.tokens(accountId), let url = URL(string: a.server + "/api/auth/refresh") else { return .rejected }
            // Already rotated by the other process (or an earlier refresh here): use the new tokens.
            if !rejected.isEmpty && tokens.access != rejected { return .refreshed }
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.timeoutInterval = 20
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = (["refresh_token": .string(tokens.refresh)] as JSON).data
            guard let (data, res) = try? await execute(req) else { return .unavailable }
            guard res.statusCode == 200, let j = try? JSON.parse(data) else {
                return res.statusCode == 401 || res.statusCode == 400 || res.statusCode == 403 ? .rejected : .unavailable
            }
            let access = j.str("access_token")
            let refresh = j.str("refresh_token")
            guard !access.isEmpty, !refresh.isEmpty else { return .rejected }
            store.update { $0.secrets.tokens[accountId] = Tokens(access: access, refresh: refresh) }
            return .refreshed
        }
        refreshing[accountId] = task
        let result = await task.value
        refreshing[accountId] = nil
        return result
    }

    /// Best-effort sign-out with an account's own server and token.
    public func logoutRemote(server: String, tokens: Tokens?) async {
        guard let tokens, !server.isEmpty, let url = URL(string: server + "/api/auth/logout") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 10
        req.setValue("Bearer \(tokens.access)", forHTTPHeaderField: "Authorization")
        _ = try? await execute(req)
    }

    private func execute(_ req: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, res) = try await session.data(for: req)
            guard let http = res as? HTTPURLResponse else { throw URLError(.badServerResponse) }
            return (data, http)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw UserError("Can't reach your PassAuth server. Check the server address and your connection.")
        }
    }

    /// Success bodies are returned as received: [call] parses them once, and `/sync` (often
    /// megabytes) is decoded off the main thread by the repository instead of being parsed here too.
    private func check(_ data: Data, _ res: HTTPURLResponse) throws -> Data {
        if (200..<300).contains(res.statusCode) {
            return data
        }
        let j = try? JSON.parse(data)
        if j == nil && !data.isEmpty && res.statusCode != 401 {
            throw ApiError(status: res.statusCode, code: "not_passauth", message: "That address doesn't look like a PassAuth server.")
        }
        throw ApiError(
            status: res.statusCode,
            code: j?["error"]?.string ?? "error",
            message: j?["message"]?.string ?? "Request failed (\(res.statusCode))"
        )
    }
}
