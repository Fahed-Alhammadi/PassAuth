import Foundation
import PassAuthKit
import XCTest

/// A fake PassAuth server: refresh tokens rotate and a reused one is rejected (like the real
/// server, which then revokes the session).
final class FakeServer: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var refreshToken = "R1"
    nonisolated(unsafe) private static var accessToken = "A1"
    nonisolated(unsafe) private static var generation = 1
    nonisolated(unsafe) private(set) static var refreshCalls = 0
    nonisolated(unsafe) private(set) static var reuseDetected = false

    static func reset() {
        lock.lock()
        defer { lock.unlock() }
        refreshToken = "R1"
        accessToken = "A1"
        generation = 1
        refreshCalls = 0
        reuseDetected = false
    }

    /// The server's access token changes (the old one is expired).
    static func expireAccess() {
        lock.lock()
        defer { lock.unlock() }
        accessToken = "expired-\(generation)"
    }

    static var calls: Int { lock.lock(); defer { lock.unlock() }; return refreshCalls }
    static var reused: Bool { lock.lock(); defer { lock.unlock() }; return reuseDetected }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        var status = 404
        var body: [String: Any] = ["error": "not_found"]
        Self.lock.lock()
        if path == "/api/auth/refresh" {
            Self.refreshCalls += 1
            let sent = (Self.bodyJSON(request)?["refresh_token"] as? String) ?? ""
            if sent == Self.refreshToken {
                Self.generation += 1
                Self.refreshToken = "R\(Self.generation)"
                Self.accessToken = "A\(Self.generation)"
                status = 200
                body = ["access_token": Self.accessToken, "refresh_token": Self.refreshToken]
            } else {
                Self.reuseDetected = true
                status = 401
                body = ["error": "unauthorized"]
            }
        } else if path == "/api/sync/revision" {
            if request.value(forHTTPHeaderField: "Authorization") == "Bearer \(Self.accessToken)" {
                status = 200
                body = ["revision": 7]
            } else {
                status = 401
                body = ["error": "unauthorized"]
            }
        }
        Self.lock.unlock()
        // A little latency, so concurrent requests overlap.
        Thread.sleep(forTimeInterval: 0.05)
        let res = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: res, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: try! JSONSerialization.data(withJSONObject: body))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func bodyJSON(_ r: URLRequest) -> [String: Any]? {
        var data = r.httpBody
        if data == nil, let s = r.httpBodyStream {
            s.open()
            var d = Data()
            var buf = [UInt8](repeating: 0, count: 4096)
            while s.hasBytesAvailable {
                let n = s.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                d.append(buf, count: n)
            }
            s.close()
            data = d
        }
        return data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    }
}

/// The app and the AutoFill extension (separate processes, modelled as two stores and clients
/// on the same files and Keychain item) never refresh with the same refresh token.
@MainActor
final class TokenRefreshTests: XCTestCase {
    private var dir: URL!
    private let accountId = "acc-1"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-refresh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        FakeServer.reset()
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        SecureStore.wipeAll(directory: dir)
    }

    private func client(_ store: SecureStore) -> ApiClient {
        ApiClient(store: store) { $0.protocolClasses = [FakeServer.self] }
    }

    /// App store with one signed-in account, plus an extension store reading the same state.
    private func stores() -> (SecureStore, SecureStore) {
        let app = SecureStore(directory: dir, role: .app)
        app.load()
        app.update { s in
            s.file.accounts[accountId] = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            s.file.activeId = accountId
            s.secrets.tokens[accountId] = Tokens(access: "A1", refresh: "R1")
        }
        let ext = SecureStore(directory: dir, role: .appExtension)
        ext.load()
        XCTAssertEqual(ext.get().tokens(accountId)?.refresh, "R1")
        return (app, ext)
    }

    func testSequentialRefreshUsesTheOtherProcessTokens() async throws {
        let (appStore, extStore) = stores()
        let app = client(appStore)
        let ext = client(extStore)
        FakeServer.expireAccess()
        // The extension refreshes first (R1 → R2) …
        let r1 = try await ext.call(accountId, "/sync/revision")
        XCTAssertEqual(r1["revision"]?.int, 7)
        XCTAssertEqual(FakeServer.calls, 1)
        // … the app still holds A1/R1 in memory: its 401 must not refresh with R1 again.
        XCTAssertEqual(appStore.get().tokens(accountId)?.refresh, "R1")
        let r2 = try await app.call(accountId, "/sync/revision")
        XCTAssertEqual(r2["revision"]?.int, 7)
        XCTAssertEqual(FakeServer.calls, 1, "the app picked up the extension's rotated tokens")
        XCTAssertFalse(FakeServer.reused)
        XCTAssertEqual(appStore.get().tokens(accountId), Tokens(access: "A2", refresh: "R2"))
    }

    func testConcurrentRefreshRotatesOnce() async throws {
        let (appStore, extStore) = stores()
        let app = client(appStore)
        let ext = client(extStore)
        FakeServer.expireAccess()
        let id = accountId
        let a = Task { @MainActor in try await app.call(id, "/sync/revision") }
        let b = Task { @MainActor in try await ext.call(id, "/sync/revision") }
        let ra = try await a.value
        let rb = try await b.value
        XCTAssertEqual(ra["revision"]?.int, 7)
        XCTAssertEqual(rb["revision"]?.int, 7)
        XCTAssertEqual(FakeServer.calls, 1)
        XCTAssertFalse(FakeServer.reused)
        appStore.reload()
        extStore.reload()
        XCTAssertEqual(appStore.get().tokens(accountId), extStore.get().tokens(accountId))
    }

    func testWritesDoNotOverwriteTheOtherProcess() {
        let (appStore, extStore) = stores()
        // The extension rotates tokens; the app then changes a setting from its stale copy.
        extStore.update { $0.secrets.tokens[accountId] = Tokens(access: "A9", refresh: "R9") }
        appStore.update { $0.file.settings.clearClipboard = 60 }
        XCTAssertEqual(appStore.get().tokens(accountId)?.refresh, "R9")
        extStore.reload()
        XCTAssertEqual(extStore.get().settings.clearClipboard, 60)
    }

    func testExtensionNeverCreatesState() {
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent("pa-ext-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: empty) }
        let ext = SecureStore(directory: empty, role: .appExtension)
        ext.load()
        ext.update { $0.file.activeId = "x" }
        XCTAssertFalse(ext.exists)
        XCTAssertFalse(FileManager.default.fileExists(atPath: empty.appendingPathComponent("state.bin").path))
    }
}
