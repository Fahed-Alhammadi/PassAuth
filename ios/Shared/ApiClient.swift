import Foundation

/// Refuses redirects: a PassAuth server never redirects API calls, and following one could
/// send tokens elsewhere.
private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// Upload progress of one transfer (and no redirects, as for every request).
private final class TransferProgress: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    let report: @Sendable (Double) -> Void
    init(_ report: @escaping @Sendable (Double) -> Void) { self.report = report }

    func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64, totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        if totalBytesExpectedToSend > 0 { report(Double(totalBytesSent) / Double(totalBytesExpectedToSend)) }
    }

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

    /// Called when the server refused a signed-in request with 403 `two_step_required` (its
    /// policy requires two-step login and the account has no method yet).
    public var onTwoStepRequired: (@MainActor (String) -> Void)?

    /// The app wraps a token refresh in a background task (it holds a shared-container lock,
    /// and iOS terminates apps suspended while holding one). Returns the function ending it.
    public var beginBackgroundWork: (@MainActor () -> (@MainActor () -> Void))?

    enum RefreshResult: Sendable { case refreshed, rejected, unavailable }

    /// Sent with every request to a PassAuth server (API v2): which app and version is asking.
    public nonisolated static let clientHeaderName = "X-PassAuth-Client"

    /// `ios/<version>` for the iOS app and its AutoFill extension, `macos-autofill/<version>` for
    /// the desktop app's AutoFill extension (Info.plist version).
    public nonisolated static var clientHeader: String {
        #if os(macOS)
        let app = "macos-autofill"
        #else
        let app = "ios"
        #endif
        let version = AppVersion.current.name
        return "\(app)/\(version.isEmpty ? "0" : version)"
    }

    /// `configure` adjusts the session (tests register a URLProtocol).
    public init(store: SecureStore, configure: ((URLSessionConfiguration) -> Void)? = nil) {
        self.store = store
        let config = URLSessionConfiguration.ephemeral
        // Also on requests that don't go through `execute` (website icons).
        config.httpAdditionalHeaders = [Self.clientHeaderName: Self.clientHeader]
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
        do {
            return try check(data, res)
        } catch let e as ApiError where auth && TwoStepGate.isRequired(status: e.status, code: e.code) {
            onTwoStepRequired?(accountId)
            throw e
        }
    }

    // MARK: File transfers (attachments)

    /// Attachment uploads and downloads: an idle limit like other requests, but no 60-second cap
    /// on the whole transfer (the server allows 60 s plus the size at 32 KiB/s).
    private lazy var transferSession: URLSession = {
        let config = session.configuration
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 6 * 3600
        return URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
    }()

    /// A signed-in request through `perform`, renewing the session once after a 401 (as `callData`).
    private func authorized<T>(_ accountId: String, _ path: String, method: String, headers: [String: String] = [:],
                               perform: (URLRequest) async throws -> (T, HTTPURLResponse)) async throws -> (T, HTTPURLResponse) {
        var usedAccess = ""
        func request() throws -> URLRequest {
            let s = store.get()
            guard let a = s.file.accounts[accountId], !a.server.isEmpty, let url = URL(string: a.server + "/api" + path) else {
                throw UserError("Set your PassAuth server address first.")
            }
            var req = URLRequest(url: url)
            req.httpMethod = method
            req.setValue(Self.clientHeader, forHTTPHeaderField: Self.clientHeaderName)
            if let t = s.tokens(accountId) {
                usedAccess = t.access
                req.setValue("Bearer \(t.access)", forHTTPHeaderField: "Authorization")
            }
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
            return req
        }
        func send() async throws -> (T, HTTPURLResponse) {
            do {
                return try await perform(try request())
            } catch let e as UserError {
                throw e
            } catch is CancellationError {
                throw CancellationError()
            } catch let e as URLError where e.code == .cancelled {
                throw CancellationError()
            } catch {
                throw UserError("Can't reach your PassAuth server. Check the server address and your connection.")
            }
        }
        var (value, res) = try await send()
        if res.statusCode == 401 {
            switch await refresh(accountId, rejected: usedAccess) {
            case .refreshed:
                (value, res) = try await send()
            case .unavailable:
                throw UserError("Can't reach your PassAuth server. Check the server address and your connection.")
            case .rejected:
                store.update { $0.secrets.tokens[accountId] = nil }
                onSessionLost?(accountId)
                throw ApiError(status: 401, code: "unauthorized", message: "Your session ended. Sign in again.")
            }
        }
        return (value, res)
    }

    /// `PUT` the file at `file` (streamed from disk) to `path`; `progress` hears the fraction sent.
    /// A 409 `already_uploaded` (an earlier try landed) counts as done.
    public func uploadFile(_ accountId: String, _ path: String, file: URL, progress: @escaping @Sendable (Double) -> Void) async throws {
        let session = transferSession
        let (data, res) = try await authorized(accountId, path, method: "PUT") { req in
            var r = req
            r.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            let (data, res) = try await session.upload(for: r, fromFile: file, delegate: TransferProgress(progress))
            guard let http = res as? HTTPURLResponse else { throw URLError(.badServerResponse) }
            return (data, http)
        }
        if res.statusCode == 409, (try? JSON.parse(data))?["error"]?.string == "already_uploaded" { return }
        _ = try check(data, res)
    }

    /// `GET` `path` into a new file inside `directory`: the file for a success, else the status
    /// (404: gone) or the server's error.
    public func downloadFile(_ accountId: String, _ path: String, into directory: URL) async throws -> (file: URL?, status: Int) {
        let session = transferSession
        let (url, res) = try await authorized(accountId, path, method: "GET") { req in
            let (url, res) = try await session.download(for: req, delegate: TransferProgress { _ in })
            guard let http = res as? HTTPURLResponse else {
                try? FileManager.default.removeItem(at: url)
                throw URLError(.badServerResponse)
            }
            return (url, http)
        }
        if (200..<300).contains(res.statusCode) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let target = directory.appendingPathComponent(UUID().uuidString.lowercased())
            try FileManager.default.moveItem(at: url, to: target)
            return (target, res.statusCode)
        }
        let body = (try? Data(contentsOf: url)) ?? Data()
        try? FileManager.default.removeItem(at: url)
        if res.statusCode == 404 { return (nil, 404) }
        _ = try check(body.count > 64 * 1024 ? Data() : body, res)
        return (nil, res.statusCode)
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

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var req = request
        req.setValue(Self.clientHeader, forHTTPHeaderField: Self.clientHeaderName)
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
        // Every 429 says when to retry (`Retry-After`), also one from a proxy with its own body.
        let retryAfter = res.statusCode == 429 ? retryAfterSeconds(res.value(forHTTPHeaderField: "Retry-After")) : nil
        if j == nil && res.statusCode == 429 {
            throw ApiError(status: 429, code: "rate_limited", message: "Too many requests", retryAfter: retryAfter)
        }
        if j == nil && !data.isEmpty && res.statusCode != 401 {
            throw ApiError(status: res.statusCode, code: "not_passauth", message: "That address doesn't look like a PassAuth server.")
        }
        // The request's id names it in the server's log (shown as a reference for unknown errors).
        let requestId = ApiError.validRequestId(j?["request_id"]?.string) ?? ApiError.validRequestId(res.value(forHTTPHeaderField: "x-request-id"))
        throw ApiError(
            status: res.statusCode,
            code: j?["error"]?.string ?? "error",
            message: j?["message"]?.string ?? "",
            retryAfter: retryAfter,
            requestId: requestId,
            fields: j
        )
    }
}
