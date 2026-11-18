import Foundation
import PassAuthCore
import PassAuthKit
import XCTest

/// A fake PassAuth server for the API v2 client rules: answers queued per "METHOD path" (else
/// 200), `/api/sync` bodies in turn (the last one stays; an answer queued for "GET /api/sync"
/// goes first), every request recorded with its headers.
final class ScriptedServer: URLProtocol, @unchecked Sendable {
    struct Request {
        let method: String
        let path: String
        /// The query string ("since=…&trash=summary"), "" without one.
        let query: String
        let body: [String: Any]
        let headers: [String: String]
    }

    nonisolated(unsafe) static var syncBodies: [Data] = []
    nonisolated(unsafe) static var answers: [String: [(status: Int, body: String, headers: [String: String])]] = [:]
    nonisolated(unsafe) static var requests: [Request] = []
    private static let lock = NSLock()

    static func reset() {
        lock.lock()
        syncBodies = []
        answers = [:]
        requests = []
        lock.unlock()
    }

    static func answer(_ key: String, _ status: Int, _ body: String, headers: [String: String] = [:]) {
        lock.lock()
        answers[key, default: []].append((status, body, headers))
        lock.unlock()
    }

    static func recorded() -> [Request] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let method = request.httpMethod ?? "GET"
        var status = 200
        var body = Data("{}".utf8)
        var headers = ["Content-Type": "application/json"]
        Self.lock.lock()
        Self.requests.append(Request(method: method, path: path, query: request.url?.query ?? "", body: Self.bodyJSON(request), headers: request.allHTTPHeaderFields ?? [:]))
        if path == "/api/sync" && (Self.answers["\(method) \(path)"] ?? []).isEmpty {
            body = Self.syncBodies.count > 1 ? Self.syncBodies.removeFirst() : (Self.syncBodies.first ?? body)
        } else if var queue = Self.answers["\(method) \(path)"], !queue.isEmpty {
            let a = queue.removeFirst()
            Self.answers["\(method) \(path)"] = queue
            status = a.status
            body = Data(a.body.utf8)
            headers.merge(a.headers) { _, new in new }
        } else if path.hasPrefix("/api/items") {
            body = Data(#"{"revision":7}"#.utf8)
        }
        Self.lock.unlock()
        let res = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: res, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func bodyJSON(_ r: URLRequest) -> [String: Any] {
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
        return data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
    }
}

/// The client side of API contract v2 (2026-11-15): `X-PassAuth-Client` on every request,
/// error codes before message texts, the vault key epoch on item writes with one re-encrypted
/// retry after `vault_key_changed`, and a create keeping its item id across retries.
@MainActor
final class ContractTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    /// An account with one vault (`vaultId`), its key, and one login in it.
    private struct Fixture {
        let created: NewAccount
        let vaultId: String
        let key: VaultKey
        let wrapped: String
        let itemId: String
        let item: Item
        /// The account id: also its user id on the server ("me").
        var accountId: String { (try? JSON.parse(created.account.legacyIdentityJson()))?.str("user_id") ?? "" }
    }

    private func fixture() throws -> Fixture {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let a = try newId()
        let k = try created.account.newVaultKey(vaultId: a)
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Shop"
        item.login?.username = "alice"
        item.login?.password = "pw-1"
        item.login?.urls = [LoginUrl(url: "https://shop.example.com", match: .default)]
        return Fixture(created: created, vaultId: a, key: k.key, wrapped: k.wrapped, itemId: try newId(), item: item)
    }

    /// A `/sync` body: the vault with `key` (and its epoch, when given) and the login at `revision`.
    private func syncBody(_ f: Fixture, key: VaultKey, wrapped: String, epoch: Int64?, item: Item? = nil, revision: Int64 = 3) throws -> Data {
        let enc = try key.encryptItem(itemJson: ItemCodec.encode(item ?? f.item), id: f.itemId, vaultId: f.vaultId)
        var vault: [String: Any] = ["id": f.vaultId, "wrapped_key": wrapped, "key_kind": "account",
                                    "meta": try key.encryptMeta(vaultId: f.vaultId, metaJson: #"{"name":"Personal"}"#), "role": "owner"]
        if let epoch { vault["key_epoch"] = epoch }
        return try JSONSerialization.data(withJSONObject: [
            "vaults": [vault],
            "items": [["id": f.itemId, "vault_id": f.vaultId, "item_key": enc.key, "data": enc.data, "revision": revision, "deleted_at": NSNull()]],
            "revision": 5,
        ] as [String: Any])
    }

    private func repo(_ f: Fixture) async throws -> VaultRepository {
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = f.created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] })
        try await repo.unlock(password: password, secretKey: nil)
        return repo
    }

    private func writes() -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.path.hasPrefix("/api/items") }
    }

    func testClientHeaderOnEveryRequest() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        try await repo.createItem(Item(name: "Note"), vaultId: nil)
        let all = ScriptedServer.recorded()
        XCTAssertFalse(all.isEmpty)
        let version = AppVersion.current.name
        for r in all {
            XCTAssertEqual(r.headers["X-PassAuth-Client"], "ios/\(version.isEmpty ? "0" : version)", "\(r.method) \(r.path)")
        }
        XCTAssertTrue(ApiClient.clientHeader.hasPrefix("ios/"))
    }

    func testErrorCodesBeforeMessages() {
        // API v2 code, and the message text older servers put the reason in.
        XCTAssertTrue(ApiError(status: 403, code: "reauth_required", message: "anything").hasCode("reauth_required"))
        XCTAssertTrue(ApiError(status: 403, code: "forbidden", message: "reauth_required").hasCode("reauth_required"))
        XCTAssertFalse(ApiError(status: 403, code: "forbidden", message: "nope").hasCode("reauth_required"))
        XCTAssertTrue(ApiError(status: 400, code: "bad_request", message: "Invalid code").hasCode("invalid_code", orMessage: "invalid code"))
        XCTAssertEqual(errorMessage(ApiError(status: 403, code: "email_not_verified", message: "x")), "Confirm your email address first, then sign in.")
        XCTAssertEqual(errorMessage(ApiError(status: 403, code: "forbidden", message: "email_not_verified")), "Confirm your email address first, then sign in.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 403, code: "reauth_required", message: "reauth_required")), "Please confirm your master password again.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 400, code: "invalid_code", message: "wrong")), "That code isn't right. Check it and try again.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 400, code: "bad_request", message: "invalid code")), "That code isn't right. Check it and try again.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 429, code: "rate_limited", message: "too many requests")), "Too many attempts, try again later.")
    }

    /// Client review F11: the request id from the error body (else `x-request-id`) becomes the
    /// reference of an unknown error; the server's own text is only a labelled detail; 507 is
    /// said in the app's words wherever a save fails.
    func testServerErrorTextWithReference() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        ScriptedServer.answer("GET /api/account", 400, #"{"error":"odd_reason","message":"Visit evil.example‮ now","request_id":"req-77"}"#)
        do {
            _ = try await repo.twoFactorStatus()
            XCTFail("expected the error")
        } catch let e as ApiError {
            XCTAssertEqual(e.requestId, "req-77")
            XCTAssertEqual(errorMessage(e), "Your PassAuth server refused this request. Reference: req-77. Server message: Visit evil.example now")
        }
        ScriptedServer.answer("GET /api/account", 503, #"{"error":"odd_reason"}"#, headers: ["x-request-id": "hdr-9"])
        do {
            _ = try await repo.twoFactorStatus()
            XCTFail("expected the error")
        } catch let e as ApiError {
            XCTAssertEqual(e.requestId, "hdr-9", "the header when the body has none")
            XCTAssertEqual(errorMessage(e), "Something went wrong on your PassAuth server. Reference: hdr-9.")
        }
        ScriptedServer.answer("POST /api/items", 507, #"{"error":"insufficient_storage","message":"disk full","request_id":"r-1"}"#)
        do {
            try await repo.createItem(Item(name: "Note"), vaultId: nil)
            XCTFail("expected the error")
        } catch {
            XCTAssertEqual(errorMessage(error), "Your server is running out of storage space, so this wasn't saved. Ask the server's admin.")
        }
    }

    /// A 429 says when to retry (`Retry-After`); sign-in, unlock and two-step steps show it.
    func testRateLimitsSayWhenToTryAgain() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        ScriptedServer.answer("GET /api/account", 429, #"{"error":"rate_limited","message":"too many requests"}"#, headers: ["Retry-After": "120"])
        do {
            _ = try await repo.twoFactorStatus()
            XCTFail("expected the rate limit")
        } catch let e as ApiError {
            XCTAssertTrue(e.isRateLimited)
            XCTAssertEqual(e.retryAfter, 120)
            XCTAssertEqual(errorMessage(e), "Too many attempts. Try again in 2 minutes.")
            XCTAssertEqual(securityErrorMessage(e), "Too many attempts. Try again in 2 minutes.")
        }
        // A proxy's own 429 page is still a rate limit, not "not a PassAuth server".
        ScriptedServer.answer("GET /api/account", 429, "<html>Too Many Requests</html>", headers: ["Content-Type": "text/html", "Retry-After": "30"])
        do {
            _ = try await repo.twoFactorStatus()
            XCTFail("expected the rate limit")
        } catch let e as ApiError {
            XCTAssertEqual(e.code, "rate_limited")
            XCTAssertEqual(errorMessage(e), "Too many attempts. Try again in 30 seconds.")
        }
        // Without Retry-After: the general wording; other statuses don't carry one.
        XCTAssertEqual(errorMessage(ApiError(status: 429, code: "rate_limited", message: "x")), "Too many attempts. Wait a moment and try again.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 429, code: "rate_limited", message: "x")), "Too many attempts, try again later.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 429, code: "rate_limited", message: "x", retryAfter: 3600)), "Too many attempts. Try again in 60 minutes.")
        ScriptedServer.answer("GET /api/account", 503, #"{"error":"internal","message":"down"}"#, headers: ["Retry-After": "10"])
        do {
            _ = try await repo.twoFactorStatus()
            XCTFail("expected the error")
        } catch let e as ApiError {
            XCTAssertNil(e.retryAfter)
        }
    }

    func testRetryAfterAndWaitWords() throws {
        XCTAssertEqual(retryAfterSeconds("120"), 120)
        XCTAssertEqual(retryAfterSeconds(" 7 "), 7)
        XCTAssertNil(retryAfterSeconds(nil))
        XCTAssertNil(retryAfterSeconds(""))
        XCTAssertNil(retryAfterSeconds("soon"))
        // An HTTP date: the seconds until then (rounded up), never negative.
        let at = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-11-15T10:00:00Z"))
        XCTAssertEqual(retryAfterSeconds("Sun, 15 Nov 2026 10:01:30 GMT", now: at), 90)
        XCTAssertEqual(retryAfterSeconds("Sun, 15 Nov 2026 10:00:01 GMT", now: at.addingTimeInterval(0.5)), 1)
        XCTAssertEqual(retryAfterSeconds("Sun, 15 Nov 2026 09:59:00 GMT", now: at), 0)
        XCTAssertEqual(waitText(1), "a moment")
        XCTAssertEqual(waitText(45), "45 seconds")
        XCTAssertEqual(waitText(89), "89 seconds")
        XCTAssertEqual(waitText(90), "2 minutes")
        XCTAssertEqual(waitText(120), "2 minutes")
        XCTAssertEqual(waitText(121), "3 minutes")
        XCTAssertEqual(waitText(3600), "60 minutes")
    }

    func testKeyEpochSentWithWrites() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 3)]
        let repo = try await repo(f)
        try await repo.createItem(Item(name: "Note"), vaultId: nil)
        var e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var changed = e.item
        changed.login?.password = "pw-2"
        try await repo.updateItem(e, changed)
        let w = writes()
        XCTAssertEqual(w.map(\.method), ["POST", "PUT"])
        XCTAssertEqual((w[0].body["key_epoch"] as? NSNumber)?.int64Value, 3)
        XCTAssertEqual((w[1].body["key_epoch"] as? NSNumber)?.int64Value, 3)
        XCTAssertEqual((w[1].body["revision"] as? NSNumber)?.int64Value, 3)

        // An older server sends no epoch: none is sent back.
        ScriptedServer.reset()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: nil)]
        try await repo.sync()
        e = try XCTUnwrap(repo.vault?.get(f.itemId))
        try await repo.updateItem(e, changed)
        let put = try XCTUnwrap(writes().first)
        XCTAssertNil(put.body["key_epoch"])
    }

    /// 409 `vault_key_changed` on a create: sync (the new key arrives), encrypt again under the
    /// same id with the new key and its epoch, send once more.
    func testCreateRetriesOnceWithTheNewKey() async throws {
        let f = try fixture()
        let rotated = try f.created.account.newVaultKey(vaultId: f.vaultId)
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        ScriptedServer.syncBodies = [try syncBody(f, key: rotated.key, wrapped: rotated.wrapped, epoch: 2, revision: 4)]
        ScriptedServer.answer("POST /api/items", 409, #"{"error":"vault_key_changed","message":"the vault's key was replaced; sync and try again"}"#)
        let id = try await repo.createItem(Item(name: "Note"), vaultId: nil)

        let posts = writes().filter { $0.method == "POST" }
        XCTAssertEqual(posts.count, 2)
        XCTAssertEqual(posts.map { $0.body["id"] as? String }, [id, id], "the same item id")
        XCTAssertEqual(posts.map { ($0.body["key_epoch"] as? NSNumber)?.int64Value }, [1, 2])
        // The retry is encrypted with the new key; the old one can't open it.
        let retry = EncryptedItem(id: id, vaultId: f.vaultId, key: posts[1].body["key"] as! String, data: posts[1].body["data"] as! String)
        XCTAssertEqual(try ItemCodec.decode(try rotated.key.decryptItem(encrypted: retry)).name, "Note")
        XCTAssertThrowsError(try f.key.decryptItem(encrypted: retry))
    }

    /// Only one retry: a second `vault_key_changed` is reported.
    func testCreateGivesUpAfterOneRetry() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        for _ in 0..<2 { ScriptedServer.answer("POST /api/items", 409, #"{"error":"vault_key_changed","message":"changed"}"#) }
        do {
            try await repo.createItem(Item(name: "Note"), vaultId: nil)
            XCTFail("expected the error")
        } catch let e as ApiError {
            XCTAssertEqual(e.code, "vault_key_changed")
            XCTAssertEqual(errorMessage(e), "This vault's key was just replaced. Try again.")
        }
        XCTAssertEqual(writes().filter { $0.method == "POST" }.count, 2)
    }

    /// 409 `vault_key_changed` on an update: synced, and saved again with the new key and the
    /// item's new revision when its content is still the one the change was made to.
    func testUpdateRetriesWithTheNewKeyAndRevision() async throws {
        let f = try fixture()
        let rotated = try f.created.account.newVaultKey(vaultId: f.vaultId)
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        // The rotation re-encrypted the (unchanged) item under the new key: revision 4.
        ScriptedServer.syncBodies = [try syncBody(f, key: rotated.key, wrapped: rotated.wrapped, epoch: 2, revision: 4)]
        ScriptedServer.answer("PUT /api/items/\(f.itemId)", 409, #"{"error":"vault_key_changed","message":"changed"}"#)
        var changed = e.item
        changed.login?.password = "pw-2"
        try await repo.updateItem(e, changed)

        let puts = writes().filter { $0.method == "PUT" }
        XCTAssertEqual(puts.count, 2)
        XCTAssertEqual(puts.map { ($0.body["revision"] as? NSNumber)?.int64Value }, [3, 4])
        XCTAssertEqual(puts.map { ($0.body["key_epoch"] as? NSNumber)?.int64Value }, [1, 2])
        let saved = try ItemCodec.decode(try rotated.key.decryptItem(encrypted: EncryptedItem(id: f.itemId, vaultId: f.vaultId,
                                                                                               key: puts[1].body["key"] as! String, data: puts[1].body["data"] as! String)))
        XCTAssertEqual(saved.login?.password, "pw-2")
        XCTAssertEqual(saved.passwordHistory.map(\.password), ["pw-1"])
    }

    /// … but when the item itself changed meanwhile, it is the usual conflict for the user.
    func testUpdateAfterKeyChangeWithAChangedItemIsAConflict() async throws {
        let f = try fixture()
        let rotated = try f.created.account.newVaultKey(vaultId: f.vaultId)
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var elsewhere = f.item
        elsewhere.login?.password = "changed-elsewhere"
        ScriptedServer.syncBodies = [try syncBody(f, key: rotated.key, wrapped: rotated.wrapped, epoch: 2, item: elsewhere, revision: 4)]
        ScriptedServer.answer("PUT /api/items/\(f.itemId)", 409, #"{"error":"vault_key_changed","message":"changed"}"#)
        var mine = e.item
        mine.login?.password = "pw-2"
        do {
            try await repo.updateItem(e, mine)
            XCTFail("expected a conflict")
        } catch is ConflictError {}
        XCTAssertEqual(writes().filter { $0.method == "PUT" }.count, 1, "nothing sent on top of the other change")
    }

    /// A create whose earlier attempt got through (409 `item_exists`, or the older servers'
    /// "item id already exists"): the item already there is updated, not saved a second time.
    func testCreateWithAnIdThatGotThroughUpdatesIt() async throws {
        for answer in [#"{"error":"item_exists","message":"item id already exists"}"#, #"{"error":"conflict","message":"item id already exists"}"#] {
            // A fresh device each time (no offline copy of the previous account).
            SecureStore.wipeAll(directory: dir)
            ScriptedServer.reset()
            let f = try fixture()
            ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
            let repo = try await repo(f)
            ScriptedServer.answer("POST /api/items", 409, answer)
            var again = f.item
            again.login?.password = "pw-2"
            let id = try await repo.createItem(again, vaultId: nil, id: f.itemId)
            XCTAssertEqual(id, f.itemId)
            let w = writes()
            XCTAssertEqual(w.map(\.method), ["POST", "PUT"], answer)
            XCTAssertEqual(w[0].body["id"] as? String, f.itemId)
            XCTAssertEqual(w[1].path, "/api/items/\(f.itemId)")
            XCTAssertEqual((w[1].body["revision"] as? NSNumber)?.int64Value, 3)
        }
    }

    /// Any other 409 on a create is an error (the item id isn't in the vault).
    func testCreateConflictWithoutTheItemIsAnError() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        ScriptedServer.answer("POST /api/items", 409, #"{"error":"item_exists","message":"item id already exists"}"#)
        do {
            try await repo.createItem(Item(name: "Note"), vaultId: nil, id: try newId())
            XCTFail("expected the error")
        } catch let e as ApiError {
            XCTAssertEqual(e.code, "item_exists")
        }
        XCTAssertEqual(writes().map(\.method), ["POST"])
    }
    // MARK: Delta sync (`delta_sync`) and quotas

    private func deltaServer() {
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync"]}"#)
    }

    /// The vault row with the server's numbers.
    private func vaultRow(_ f: Fixture, key: VaultKey? = nil, wrapped: String? = nil, epoch: Int64 = 0, seq: Int64) throws -> [String: Any] {
        ["id": f.vaultId, "wrapped_key": wrapped ?? f.wrapped, "key_kind": "account", "role": "owner", "rotation_pending": 0,
         "meta": try (key ?? f.key).encryptMeta(vaultId: f.vaultId, metaJson: #"{"name":"Personal"}"#), "key_epoch": epoch, "seq": seq]
    }

    private func itemRow(_ f: Fixture, key: VaultKey? = nil, id: String, item: Item, revision: Int64) throws -> [String: Any] {
        let enc = try (key ?? f.key).encryptItem(itemJson: ItemCodec.encode(item), id: id, vaultId: f.vaultId)
        return ["id": id, "vault_id": f.vaultId, "item_key": enc.key, "data": enc.data, "revision": revision, "deleted_at": NSNull(),
                "created_at": 1_700_000_000, "updated_at": 1_700_000_000]
    }

    /// A `/sync` answer of a server with delta sync (bundle and user included).
    private func answer(_ f: Fixture, _ o: [String: Any]) throws -> Data {
        var o = o
        o["bundle"] = try JSONSerialization.jsonObject(with: Data(f.created.bundleJson.utf8))
        o["user"] = ["id": f.accountId, "email": "a@example.com", "name": "Alex", "email_verified": true]
        return try JSONSerialization.data(withJSONObject: o)
    }

    // MARK: Vault key replacement

    /// Two vaults this account owns: `f.vaultId` (personal: members = this account) and a shared
    /// one (another member too), each with one item.
    private func twoVaults(_ f: Fixture) throws -> (sharedId: String, body: Data) {
        let sharedId = try newId()
        let sk = try f.created.account.newVaultKey(vaultId: sharedId)
        let sharedItem = try sk.key.encryptItem(itemJson: ItemCodec.encode(named("Shared note")), id: try newId(), vaultId: sharedId)
        let body = try answer(f, [
            "revision": 5,
            "vaults": [try vaultRow(f, epoch: 1, seq: 3),
                       ["id": sharedId, "wrapped_key": sk.wrapped, "key_kind": "account", "role": "owner", "rotation_pending": 1, "key_epoch": 1, "seq": 2,
                        "meta": try sk.key.encryptMeta(vaultId: sharedId, metaJson: #"{"name":"Family"}"#)]],
            "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3),
                      ["id": sharedItem.id, "vault_id": sharedId, "item_key": sharedItem.key, "data": sharedItem.data, "revision": 4, "deleted_at": NSNull(),
                       "created_at": 1_700_000_000, "updated_at": 1_700_000_000]],
        ])
        return (sharedId, body)
    }

    private func members(_ ids: [String]) -> String {
        let rows = ids.map { #"{"user_id":"\#($0)","email":"\#($0)@example.com","name":"\#($0)","role":"owner","public_key":"pk-\#($0)"}"# }
        return #"{"members":[\#(rows.joined(separator: ","))]}"#
    }

    private func rotations() -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.method == "POST" && $0.path.hasSuffix("/rotate") }
    }

    /// A shared vault in the list is left for the web vault or the desktop app, and the personal
    /// vault after it still gets its new key; the result says which is which.
    func testKeyReplacementSkipsASharedVaultAndGoesOn() async throws {
        let f = try fixture()
        let two = try twoVaults(f)
        ScriptedServer.syncBodies = [two.body]
        let repo = try await repo(f)
        ScriptedServer.answer("GET /api/vaults/\(two.sharedId)/members", 200, members([f.accountId, "u2"]))
        ScriptedServer.answer("GET /api/vaults/\(f.vaultId)/members", 200, members([f.accountId]))
        let done = try await repo.rotateVaultKeys([two.sharedId, f.vaultId])
        XCTAssertEqual(done.rotated, [f.vaultId])
        XCTAssertEqual(done.shared, [KeyReplacement.Shared(id: two.sharedId, name: "Family")])
        XCTAssertEqual(done.sharedText, "Family is shared, so replace its key in the web vault or the desktop app.")
        XCTAssertEqual(rotations().map(\.path), ["/api/vaults/\(f.vaultId)/rotate"])
    }

    /// Each re-encrypted item carries the revision it was read at; an item saved meanwhile (409
    /// `revision_conflict`) means sync and build it again, a bounded number of times.
    func testKeyReplacementSendsRevisionsAndRetriesAfterAConflict() async throws {
        let f = try fixture()
        let two = try twoVaults(f)
        ScriptedServer.syncBodies = [two.body]
        let repo = try await repo(f)
        let conflict = #"{"error":"revision_conflict","message":"item changed"}"#
        ScriptedServer.answer("GET /api/vaults/\(f.vaultId)/members", 200, members([f.accountId]))
        ScriptedServer.answer("GET /api/vaults/\(f.vaultId)/members", 200, members([f.accountId]))
        ScriptedServer.answer("POST /api/vaults/\(f.vaultId)/rotate", 409, conflict)
        let done = try await repo.rotateVaultKeys([f.vaultId])
        XCTAssertEqual(done.rotated, [f.vaultId])
        let sent = rotations()
        XCTAssertEqual(sent.count, 2)
        for r in sent {
            let items = try XCTUnwrap(r.body["items"] as? [[String: Any]])
            XCTAssertEqual(items.map { ($0["revision"] as? NSNumber)?.int64Value }, [3])
        }

        // Conflicts every time: given up after `rotationAttempts`, the error thrown.
        ScriptedServer.reset()
        ScriptedServer.syncBodies = [two.body]
        for _ in 0..<5 {
            ScriptedServer.answer("GET /api/vaults/\(f.vaultId)/members", 200, members([f.accountId]))
            ScriptedServer.answer("POST /api/vaults/\(f.vaultId)/rotate", 409, conflict)
        }
        do {
            try await repo.rotateVaultKeys([f.vaultId])
            XCTFail("expected the conflict")
        } catch let e as ApiError {
            XCTAssertTrue(e.hasCode("revision_conflict"))
        }
        XCTAssertEqual(rotations().count, 3)
    }

    private func syncRequests() -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.path == "/api/sync" }
    }

    private func named(_ name: String) -> Item {
        var i = Item.empty(.note, now: 1_700_000_000)
        i.name = name
        return i
    }

    /// The first sync fetches everything; later ones only what changed since the cursor of the
    /// copy, which is stored with the items it describes.
    func testDeltaSyncAsksOnlyForChanges() async throws {
        let f = try fixture()
        deltaServer()
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "cursor": "c1", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)]])]
        let repo = try await repo(f)
        XCTAssertEqual(syncRequests().map(\.query), [""], "first sync: everything")

        // Another device added a note…
        let noteId = try newId()
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 6, "cursor": "c2", "vaults": [try vaultRow(f, seq: 4)],
                                                    "items": [try itemRow(f, id: noteId, item: named("Note"), revision: 4)], "deleted": [], "reset": []])]
        try await repo.sync()
        XCTAssertEqual(syncRequests().last?.query, "since=c1")
        XCTAssertEqual(Set(repo.vault?.entries.map(\.id) ?? []), [f.itemId, noteId])
        XCTAssertEqual(repo.vault?.get(f.itemId)?.item.name, "Shop", "kept from the copy")

        // … and deleted the login for good.
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 7, "cursor": "c3", "vaults": [try vaultRow(f, seq: 5)],
                                                    "items": [], "deleted": [["id": f.itemId, "vault_id": f.vaultId]], "reset": []])]
        try await repo.sync()
        XCTAssertEqual(syncRequests().last?.query, "since=c2")
        XCTAssertEqual(repo.vault?.entries.map(\.id), [noteId])
        XCTAssertEqual(repo.vault?.revision, 7)

        // The copy on the device carries the cursor and numbers with its items.
        let disk = SecureStore(directory: dir, role: .app)
        disk.load()
        let copy = try XCTUnwrap(disk.readCache("acc").flatMap(SyncSnapshot.decode))
        XCTAssertEqual(copy.cursor, "c3")
        XCTAssertEqual(copy.items.map(\.id), [noteId])
        XCTAssertEqual(copy.vaults.first?.seq, 5)
    }

    /// This device's own write that is the vault's next number is applied to the copy without a
    /// sync; when someone else wrote in between, the write is followed by a delta sync.
    func testOwnWriteAppliedWithoutAnotherSync() async throws {
        let f = try fixture()
        deltaServer()
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "cursor": "c1", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)]])]
        let repo = try await repo(f)
        let synced = syncRequests().count
        let noteId = try newId()
        ScriptedServer.answer("POST /api/items", 200, #"{"id":"\#(noteId)","revision":9,"vault_seq":4}"#)
        try await repo.createItem(named("Note"), vaultId: nil, id: noteId)
        XCTAssertEqual(syncRequests().count, synced, "the next number: applied to the copy, no sync")
        let note = try XCTUnwrap(repo.vault?.get(noteId))
        XCTAssertEqual(note.item.name, "Note")
        XCTAssertEqual(note.revision, 9)
        XCTAssertEqual(repo.syncPosition?.vaults, [f.vaultId: 4])
        // The live message of that write names a number the copy has: nothing to do.
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 6, vaults: [f.vaultId: 4], origin: "o"), have: repo.syncPosition), .ignore)
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 7, vaults: [f.vaultId: 5], origin: "o"), have: repo.syncPosition), .sync)

        // Someone else wrote 5; this edit is 6: a delta from the copy's (unchanged) cursor.
        var renamed = note.item
        renamed.name = "Note 2"
        ScriptedServer.answer("PUT /api/items/\(noteId)", 200, #"{"id":"\#(noteId)","revision":10,"vault_seq":6}"#)
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 8, "cursor": "c2", "vaults": [try vaultRow(f, seq: 6)],
                                                    "items": [try itemRow(f, id: noteId, item: renamed, revision: 10)], "deleted": [], "reset": []])]
        try await repo.updateItem(note, renamed)
        XCTAssertEqual(syncRequests().count, synced + 1)
        XCTAssertEqual(syncRequests().last?.query, "since=c1", "a local change keeps the cursor")
        XCTAssertEqual(repo.vault?.get(noteId)?.item.name, "Note 2")
        XCTAssertEqual(repo.vault?.get(noteId)?.revision, 10)

        // Polls: everything known → no sync; a newer vault number → a delta.
        ScriptedServer.answer("GET /api/sync/revision", 200, #"{"revision":8,"vaults":{"\#(f.vaultId)":6}}"#)
        await repo.refreshIfStale()
        XCTAssertEqual(syncRequests().count, synced + 1)
        ScriptedServer.answer("GET /api/sync/revision", 200, #"{"revision":9,"vaults":{"\#(f.vaultId)":7}}"#)
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 9, "cursor": "c3", "vaults": [try vaultRow(f, seq: 7)],
                                                    "items": [], "deleted": [], "reset": []])]
        await repo.refreshIfStale()
        XCTAssertEqual(syncRequests().count, synced + 2)
        XCTAssertEqual(syncRequests().last?.query, "since=c2")

        // Trash and delete for good: applied the same way.
        ScriptedServer.answer("DELETE /api/items/\(noteId)", 200, #"{"id":"\#(noteId)","revision":11,"vault_seq":8}"#)
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(noteId)))
        XCTAssertEqual(repo.vault?.trash.map(\.id), [noteId])
        ScriptedServer.answer("DELETE /api/items/\(noteId)/permanent", 200, #"{"revision":12,"vault_seq":9}"#)
        try await repo.purgeItem(try XCTUnwrap(repo.vault?.get(noteId)))
        XCTAssertNil(repo.vault?.get(noteId))
        XCTAssertEqual(syncRequests().count, synced + 2)
    }

    /// Servers without the feature: everything on every sync, a sync after every write, as before.
    func testWithoutDeltaSyncEverythingAsBefore() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "cursor": "c1", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)]])]
        let repo = try await repo(f)
        try await repo.sync()
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":9}"#)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(syncRequests().map(\.query), ["", "", ""])
    }

    /// An answer that isn't a vault leaves the copy and its cursor as they were.
    func testUnreadableAnswerKeepsTheCopyAndCursor() async throws {
        let f = try fixture()
        deltaServer()
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "cursor": "c1", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)]])]
        let repo = try await repo(f)
        ScriptedServer.syncBodies = [Data(#"{"error":"nope"}"#.utf8)]
        do {
            try await repo.sync()
            XCTFail("expected an error")
        } catch let e as UserError {
            XCTAssertEqual(e.message, "The server's answer couldn't be read.")
        }
        XCTAssertEqual(repo.vault?.entries.map(\.id), [f.itemId])
        XCTAssertEqual(repo.vault?.offline, false)
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 6, "cursor": "c2", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [], "deleted": [], "reset": []])]
        try await repo.sync()
        XCTAssertEqual(syncRequests().last?.query, "since=c1")
        // A delta without its copy can't be applied: the next sync asks for everything again.
    }

    /// A replaced vault key comes as a reset vault with a new header: the key is opened again,
    /// the items decrypt with it and new writes carry the new epoch. A vault the account lost
    /// goes with its items.
    func testKeyChangeAndLostVault() async throws {
        let f = try fixture()
        deltaServer()
        let rotated = try f.created.account.newVaultKey(vaultId: f.vaultId)
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "cursor": "c1", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)]])]
        let repo = try await repo(f)
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 6, "cursor": "c2",
                                                    "vaults": [try vaultRow(f, key: rotated.key, wrapped: rotated.wrapped, epoch: 1, seq: 9)],
                                                    "items": [try itemRow(f, key: rotated.key, id: f.itemId, item: f.item, revision: 9)],
                                                    "deleted": [], "reset": [f.vaultId]])]
        try await repo.sync()
        let e = try XCTUnwrap(repo.vault?.get(f.itemId), "decrypted with the vault's new key")
        XCTAssertEqual(e.item.name, "Shop")
        XCTAssertEqual(e.revision, 9)
        XCTAssertEqual(repo.vault?.vaults.first?.keyEpoch, 1)
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":10,"vault_seq":10}"#)
        try await repo.createItem(named("Note"), vaultId: nil)
        let post = try XCTUnwrap(writes().last)
        XCTAssertEqual((post.body["key_epoch"] as? NSNumber)?.int64Value, 1)
        let sent = EncryptedItem(id: post.body["id"] as! String, vaultId: f.vaultId, key: post.body["key"] as! String, data: post.body["data"] as! String)
        XCTAssertEqual(try ItemCodec.decode(try rotated.key.decryptItem(encrypted: sent)).name, "Note")

        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 7, "cursor": "c3", "vaults": [], "items": [], "deleted": [], "reset": []])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.entries.count, 0)
        XCTAssertEqual(repo.vault?.vaults.count, 0)
    }

    /// Apps that never show the trash ask for it as a summary (the macOS AutoFill extension).
    func testTrashSummaryWhereTheTrashIsNeverShown() async throws {
        let f = try fixture()
        deltaServer()
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "cursor": "c1", "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)]])]
        let repo = try await repo(f)
        repo.trashSummary = true
        ScriptedServer.syncBodies = [try answer(f, ["delta": true, "revision": 6, "cursor": "c2", "vaults": [try vaultRow(f, seq: 4)],
                                                    "items": [["id": f.itemId, "vault_id": f.vaultId, "revision": 4, "deleted_at": 1_700_000_000]],
                                                    "deleted": [], "reset": []])]
        try await repo.sync()
        XCTAssertEqual(syncRequests().last?.query, "since=c1&trash=summary")
        XCTAssertNil(repo.vault?.get(f.itemId), "a trashed item without data isn't shown")
    }

    /// 403 `quota_exceeded`: in plain words wherever a save fails (the app, AutoFill saves).
    func testQuotaExceededInPlainWords() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        ScriptedServer.answer("POST /api/items", 403, #"{"error":"quota_exceeded","message":"storage limit reached"}"#)
        do {
            try await repo.createItem(named("Note"), vaultId: nil)
            XCTFail("expected the error")
        } catch {
            XCTAssertEqual(errorMessage(error), "You've reached this server's storage limit. Delete items or ask the server's admin.")
        }
        ScriptedServer.answer("PUT /api/items/\(f.itemId)", 403, #"{"error":"quota_exceeded","message":"storage limit reached"}"#)
        do {
            _ = try await repo.saveLogin(page: "https://shop.example.com/login", username: "alice", password: "pw-new")
            XCTFail("expected the error")
        } catch {
            XCTAssertEqual(errorMessage(error), quotaExceededMessage)
        }
        ScriptedServer.answer("GET /api/account", 200, #"{"usage":{"item_count":500,"storage_bytes":1048576},"limits":{"max_items":500,"max_storage_bytes":0}}"#)
        let usage = try await repo.accountUsage()
        XCTAssertTrue(usage.full)
        XCTAssertEqual(usage.itemsLine, "500 of 500 items")
    }

    // MARK: Invitations (`vault_invitations`), policies (`policies`), the two-step gate

    private let gate = #"{"error":"two_step_required","message":"this server requires two-step login: turn it on in Settings → Two-step login"}"#

    /// Requests other than the feature check, as "METHOD path".
    private func calls() -> [String] {
        ScriptedServer.recorded().filter { $0.path != "/api/config" }.map { "\($0.method) \($0.path)" }
    }

    /// Invitations come with every answer and stay with the copy; only the app opens them (the
    /// AutoFill extension ignores them). A sealed key this account can't open has no name.
    func testInvitationsKeptWithTheCopyAndOpenedByTheApp() async throws {
        let f = try fixture()
        let sharerKey = f.created.account.publicKey()
        // Not sealed to this account (wrapped with its own key instead): it can't be opened.
        let inv: [String: Any] = ["vault_id": "V9", "role": "write", "wrapped_key": f.wrapped, "meta": "bm90LXJlYWw",
                                  "invited_by": ["id": "u2", "email": "alex@example.com", "name": "Alex", "public_key": sharerKey],
                                  "invited_at": 1_762_000_000]
        ScriptedServer.syncBodies = [try answer(f, ["revision": 5, "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)], "invitations": [inv]])]
        let repo = try await repo(f)
        XCTAssertEqual(repo.vault?.invitations, [], "not the app: nothing opened")
        let disk = SecureStore(directory: dir, role: .app)
        disk.load()
        XCTAssertEqual(disk.readCache("acc").flatMap(SyncSnapshot.decode)?.invitations.map(\.vaultId), ["V9"], "kept with the copy")

        repo.isApp = true
        try await repo.sync()
        let shown = try XCTUnwrap(repo.vault?.invitations.first)
        XCTAssertEqual(shown.vaultId, "V9")
        XCTAssertNil(shown.name, "can't be opened: only Decline is offered")
        XCTAssertEqual(shown.role, "write")
        XCTAssertEqual(shown.invitedBy?.publicKey, sharerKey)
        XCTAssertEqual(repo.vault?.entries.map(\.id), [f.itemId], "the invitation's vault isn't in the vault")
        // The fingerprint shown is the core's, the same the sharer sees for their own key.
        XCTAssertEqual(try fingerprint(publicKey: sharerKey), f.created.account.fingerprint())
        XCTAssertThrowsError(try fingerprint(publicKey: "not a key"))

        // Answered elsewhere: the next answer lists none.
        ScriptedServer.syncBodies = [try answer(f, ["revision": 6, "vaults": [try vaultRow(f, seq: 3)],
                                                    "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)], "invitations": []])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.invitations, [])
    }

    /// Accept → POST then a sync (the vault arrives whole); decline → DELETE then a sync. A
    /// declined invitation that is already gone is fine; an accepted one is reported.
    func testAcceptAndDeclineThenSync() async throws {
        let f = try fixture()
        // An invitation this account can open (accepting passes on the entry as shown).
        let vid = try newId()
        let k = try f.created.account.newVaultKey(vaultId: vid).key
        let inv: [String: Any] = ["vault_id": vid, "role": "write",
                                  "wrapped_key": try k.shareTo(vaultId: vid, recipientPublicKey: f.created.account.publicKey()),
                                  "meta": try k.encryptMeta(vaultId: vid, metaJson: #"{"name":"Team"}"#),
                                  "invited_by": ["id": "u2", "email": "alex@example.com", "name": "Alex", "public_key": f.created.account.publicKey()],
                                  "invited_at": 1_762_000_000]
        let body = try answer(f, ["revision": 5, "vaults": [try vaultRow(f, seq: 3)],
                                  "items": [try itemRow(f, id: f.itemId, item: f.item, revision: 3)], "invitations": [inv]])
        ScriptedServer.syncBodies = [body]
        let repo = try await repo(f)
        repo.isApp = true
        try await repo.sync()
        let shown = try XCTUnwrap(repo.vault?.invitations.first { $0.vaultId == vid })
        XCTAssertTrue(shown.canAccept)

        ScriptedServer.reset()
        ScriptedServer.syncBodies = [body]
        ScriptedServer.answer("POST /api/vaults/\(vid)/invitation/accept", 200, #"{"revision":6,"vault_seq":2,"status":"active"}"#)
        try await repo.acceptInvitation(shown)
        XCTAssertEqual(calls(), ["POST /api/vaults/\(vid)/invitation/accept", "GET /api/sync"])

        ScriptedServer.reset()
        ScriptedServer.syncBodies = [body]
        ScriptedServer.answer("POST /api/vaults/\(vid)/invitation/accept", 404, #"{"error":"not_found","message":"not found"}"#)
        do {
            try await repo.acceptInvitation(shown)
            XCTFail("expected the error")
        } catch {
            XCTAssertEqual(errorMessage(error), "This invitation is no longer open. The person who shared the vault may have cancelled it.")
        }
        XCTAssertEqual(calls(), ["POST /api/vaults/\(vid)/invitation/accept", "GET /api/sync"], "the list is refreshed")

        for status in [200, 404] {
            ScriptedServer.reset()
            ScriptedServer.syncBodies = [body]
            ScriptedServer.answer("DELETE /api/vaults/\(vid)/invitation", status, status == 200 ? #"{"revision":7}"# : #"{"error":"not_found","message":"not found"}"#)
            try await repo.declineInvitation(vid)
            XCTAssertEqual(calls(), ["DELETE /api/vaults/\(vid)/invitation", "GET /api/sync"], "\(status)")
        }
    }

    /// 403 `two_step_required` (the server's policy): the account shows the setup screen, keeps
    /// its keys, and opens once a sync goes through.
    func testTwoStepRequiredGatesUntilASyncGoesThrough() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        XCTAssertFalse(repo.state.twoStepRequired)

        ScriptedServer.answer("GET /api/sync", 403, gate)
        do {
            try await repo.sync()
            XCTFail("expected the error")
        } catch {
            XCTAssertEqual(errorMessage(error), "Your server requires two-step login. Set it up to continue.")
        }
        XCTAssertTrue(repo.state.twoStepRequired)
        XCTAssertEqual(repo.state.status, .unlocked, "the keys stay for after the setup")

        // Still none: "Continue" keeps the screen.
        ScriptedServer.answer("GET /api/sync", 403, gate)
        do {
            try await repo.continueAfterTwoStep()
            XCTFail("expected the error")
        } catch {}
        XCTAssertTrue(repo.state.twoStepRequired)
        // A method is on now: the sync goes through and the vault opens.
        try await repo.continueAfterTwoStep()
        XCTAssertFalse(repo.state.twoStepRequired)
        XCTAssertNotNil(repo.vault?.get(f.itemId))

        // The revision poll is refused the same way.
        ScriptedServer.answer("GET /api/sync/revision", 403, gate)
        await repo.refreshIfStale()
        XCTAssertTrue(repo.state.twoStepRequired)
        ScriptedServer.answer("GET /api/sync/revision", 200, #"{"revision":5}"#)
        await repo.refreshIfStale()
        XCTAssertFalse(repo.state.twoStepRequired)
    }

    /// Unlocking into the gate isn't an error; locked, "Continue" leads to the unlock screen.
    func testUnlockIntoTheGate() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        ScriptedServer.answer("GET /api/sync", 403, gate)
        let repo = try await repo(f)
        XCTAssertTrue(repo.state.twoStepRequired)
        XCTAssertEqual(repo.state.status, .unlocked)
        XCTAssertNil(repo.vault, "no copy yet")
        // Setting a method up works meanwhile (the copy isn't "offline").
        ScriptedServer.answer("POST /api/account/2fa/totp/setup", 200, #"{"secret":"JBSWY3DPEHPK3PXP","uri":"otpauth://totp/PassAuth:a?secret=JBSWY3DPEHPK3PXP&issuer=PassAuth"}"#)
        let setup = try await repo.startTotpSetup()
        XCTAssertEqual(setup.secret, "JBSWY3DPEHPK3PXP")

        await repo.lockActive()
        XCTAssertEqual(repo.state.status, .locked)
        XCTAssertTrue(repo.state.twoStepRequired, "the screen stays while locked")
        try await repo.continueAfterTwoStep()
        XCTAssertFalse(repo.state.twoStepRequired)
        XCTAssertEqual(repo.state.status, .locked, "then unlock as usual")

        // Signing out forgets it.
        ScriptedServer.answer("GET /api/sync/revision", 403, gate)
        try await repo.unlock(password: password, secretKey: nil)
        await repo.refreshIfStale()
        XCTAssertTrue(repo.state.twoStepRequired)
        await repo.logout()
        XCTAssertFalse(repo.state.twoStepRequired)
    }

    /// The server's policies after unlock: the vault timeout lowered to its limit ("Never" keys
    /// dropped), export off, the account's violations; a server without them changes nothing.
    func testPoliciesAppliedAfterUnlock() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        await repo.updateSettings { $0.vaultTimeout = .never }
        XCTAssertNotNil(repo.store.get().secrets.persistedKeys["acc"])

        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["policies"],"policies":{"max_vault_timeout_minutes":45,"disable_export":true,"master_password_min_length":14,"require_secret_key":true}}"#)
        ScriptedServer.answer("GET /api/account", 200, #"{"policy_violations":["secret_key","later"]}"#)
        await repo.refreshPolicies()
        let s = repo.state
        XCTAssertFalse(PolicyRules.exportAllowed(s.policies))
        XCTAssertTrue(s.policies.requireSecretKey)
        XCTAssertEqual(PolicyRules.minPasswordLength(s.policies), 14)
        XCTAssertEqual(s.timeoutLimit, 45)
        XCTAssertEqual(s.settings.vaultTimeout, .min30, "lowered to the longest choice within the limit")
        XCTAssertTrue(s.settings.vaultTimeoutLowered)
        XCTAssertNil(repo.store.get().secrets.persistedKeys["acc"], "the keys kept for Never are gone")
        XCTAssertEqual(s.policyViolations, [.secretKey])

        // Without the feature (an older server): the defaults, and nothing more is asked.
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["delta_sync"]}"#)
        let asked = ScriptedServer.recorded().filter { $0.path == "/api/account" }.count
        await repo.refreshPolicies()
        XCTAssertEqual(repo.state.policies, Policies())
        XCTAssertEqual(repo.state.policyViolations, [])
        XCTAssertEqual(repo.state.timeoutLimit, 0)
        XCTAssertEqual(ScriptedServer.recorded().filter { $0.path == "/api/account" }.count, asked)
        XCTAssertEqual(repo.state.settings.vaultTimeout, .min30, "a lowered choice isn't raised again")
    }
}

// MARK: Security round 7/8/9 (epoch-bound own wraps, Send v2, item rollback)

extension ContractTests {
    /// `body` (a `/sync` answer) with `fields` added to its `user`.
    private func withUser(_ body: Data, _ fields: [String: Any]) throws -> Data {
        var o = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        var user = o["user"] as? [String: Any] ?? [:]
        user.merge(fields) { _, new in new }
        o["user"] = user
        return try JSONSerialization.data(withJSONObject: o)
    }

    private func ownWrapAfterRotation(hint: Any?) async throws -> (wrapped: String, f: Fixture) {
        let f = try fixture()
        let two = try twoVaults(f)
        ScriptedServer.syncBodies = [hint.map { try? withUser(two.body, ["account_wraps_v2": $0]) } ?? two.body].compactMap { $0 }
        let repo = try await repo(f)
        ScriptedServer.answer("GET /api/vaults/\(f.vaultId)/members", 200, members([f.accountId]))
        let done = try await repo.rotateVaultKeys([f.vaultId])
        XCTAssertEqual(done.rotated, [f.vaultId])
        let keys = try XCTUnwrap(rotations().first?.body["keys"] as? [[String: Any]])
        return (try XCTUnwrap(keys.first?["wrapped_key"] as? String), f)
    }

    /// Every app of the account reads v2 (`user.account_wraps_v2`): the own wrap is bound to the
    /// epoch the vault has after the replacement (1 → 2).
    func testOwnKeyReplacementIsEpochBoundWhenEveryAppReadsIt() async throws {
        let (wrapped, f) = try await ownWrapAfterRotation(hint: true)
        XCTAssertTrue(accountWrapIsBound(wrapped: wrapped))
        XCTAssertNoThrow(try f.created.account.openVaultKey(vaultId: f.vaultId, wrapped: wrapped, kind: "account", keyEpoch: 2, legacyAllowed: false))
    }

    /// Without the hint (an older server, or an app that can't read v2), or a hint that isn't
    /// `true`: v1 as before.
    func testOwnKeyReplacementStaysV1WithoutTheHint() async throws {
        let (wrapped, _) = try await ownWrapAfterRotation(hint: nil)
        XCTAssertFalse(accountWrapIsBound(wrapped: wrapped))
    }

    func testOwnKeyReplacementStaysV1WhenTheHintIsntTrue() async throws {
        let (wrapped, _) = try await ownWrapAfterRotation(hint: "true")
        XCTAssertFalse(accountWrapIsBound(wrapped: wrapped))
    }

    /// The server sends an older version of an item: the newer copy stays shown and in the
    /// offline copy, the item is marked, and the counter remembered survives a new unlock.
    func testAnOlderItemFromTheServerKeepsTheNewerCopy() async throws {
        let f = try fixture()
        let old = try f.key.encryptItem(itemJson: ItemCodec.encode(f.item), id: f.itemId, vaultId: f.vaultId)
        var changed = try ItemCodec.decode(try f.key.decryptItem(encrypted: old))
        changed.login?.password = "pw-2"
        let newer = try f.key.updateItem(encrypted: old, itemJson: ItemCodec.encode(changed))
        func body(_ e: EncryptedItem, _ revision: Int64) throws -> Data {
            try answer(f, ["revision": revision, "vaults": [try vaultRow(f, seq: revision)],
                           "items": [["id": f.itemId, "vault_id": f.vaultId, "item_key": e.key, "data": e.data, "revision": revision, "deleted_at": NSNull()]]])
        }
        ScriptedServer.syncBodies = [try body(newer, 5)]
        let repo = try await repo(f)
        XCTAssertEqual(repo.vault?.get(f.itemId)?.item.login?.password, "pw-2")
        XCTAssertNil(repo.vault?.rollback)
        ScriptedServer.syncBodies = [try body(old, 6)]
        try await repo.sync()
        let shown = try XCTUnwrap(repo.vault?.get(f.itemId))
        XCTAssertTrue(shown.rolledBack)
        XCTAssertEqual(shown.item.login?.password, "pw-2")
        XCTAssertEqual(repo.vault?.rollback?.kept, [f.itemId])
        // Kept in the offline copy too, and the remembered counter is on the device.
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        XCTAssertEqual(store.readItemRevs("acc"), [f.itemId: 2])
        let cached = try XCTUnwrap(store.readCache("acc").flatMap(SyncSnapshot.decode))
        XCTAssertEqual(cached.items.first?.data, newer.data)
        // An edit of the kept copy counts on from it (rev 3) at the server's revision.
        var edit = shown.item
        edit.notes = "edited"
        try await repo.updateItem(shown, edit)
        let put = try XCTUnwrap(writes().last { $0.method == "PUT" })
        XCTAssertEqual((put.body["revision"] as? NSNumber)?.int64Value, 6)
        let sent = EncryptedItem(id: f.itemId, vaultId: f.vaultId, key: put.body["key"] as? String ?? "", data: put.body["data"] as? String ?? "")
        XCTAssertEqual(try ItemCodec.decode(try f.key.decryptItem(encrypted: sent)).rev, 3)
    }

    /// Send v2 (server with `send_v2`): a Send with a password is encrypted with the
    /// password-derived content key, which the owner keeps wrapped; without the feature, v1.
    func testSendWithAPasswordIsEncryptedWithIt() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f, key: f.key, wrapped: f.wrapped, epoch: 1)]
        let repo = try await repo(f)
        let reply = #"{"id":"s1","name":"n","owner_key":"k","delete_at":9999999999}"#
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["sends","send_v2"]}"#)
        _ = await repo.sendConfig()
        ScriptedServer.answer("POST /api/sends", 200, reply)
        _ = try await repo.createSend(NewSend(name: "Door", text: "1234", password: "open sesame", maxViews: nil, expiresAt: nil,
                                              deleteAt: 9_999_999_999, hideEmail: false))
        let body = try XCTUnwrap(ScriptedServer.recorded().last { $0.path == "/api/sends" }?.body)
        let account = f.created.account
        let key = try account.unwrapSendKey(wrapped: try XCTUnwrap(body["owner_key"] as? String))
        let ck = try account.unwrapSendContentKey(wrapped: try XCTUnwrap(body["owner_content_key"] as? String))
        let name = try XCTUnwrap(body["name"] as? String)
        XCTAssertEqual(try sendFieldVersion(ciphertext: name), 2)
        XCTAssertEqual(try sendOpen(key: key, contentKey: ck, field: "name", ciphertext: name), "Door")
        XCTAssertThrowsError(try sendOpen(key: key, contentKey: nil, field: "data", ciphertext: body["data"] as? String ?? ""))
        let keys = try sendPasswordKeys(password: "open sesame", salt: try XCTUnwrap(body["access_salt"] as? String), key: key)
        XCTAssertEqual(body["access_verifier"] as? String, keys.verifier)
        XCTAssertEqual(keys.contentKey, ck)

        // The owner opens it with the wrapped content key; removing the password goes back to v1.
        let owned = try XCTUnwrap(OwnedSend(json: ["id": "s1", "name": .string(name), "owner_key": .string(body["owner_key"] as? String ?? ""),
                                                   "owner_content_key": .string(body["owner_content_key"] as? String ?? ""),
                                                   "data": .string(body["data"] as? String ?? ""), "delete_at": 9_999_999_999, "has_password": true]))
        XCTAssertEqual(repo.sendName(owned), "Door")
        XCTAssertEqual(try repo.sendText(owned), "1234")
        ScriptedServer.answer("PUT /api/sends/s1", 200, reply)
        var edit = SendEdit()
        edit.password = .some(nil)
        try await repo.updateSend(owned, edit)
        let put = try XCTUnwrap(ScriptedServer.recorded().last { $0.method == "PUT" }?.body)
        XCTAssertTrue(put["owner_content_key"] is NSNull)
        XCTAssertTrue(put["access_verifier"] is NSNull)
        XCTAssertEqual(try sendFieldVersion(ciphertext: put["data"] as? String ?? ""), 1)
        XCTAssertEqual(try sendOpen(key: key, contentKey: nil, field: "data", ciphertext: put["data"] as? String ?? ""), "1234")

        // A server without `send_v2`: v1 with a server-checked password, as before.
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["sends"]}"#)
        _ = await repo.sendConfig()
        ScriptedServer.answer("POST /api/sends", 200, reply)
        _ = try await repo.createSend(NewSend(name: "Door", text: "1234", password: "open sesame", maxViews: nil, expiresAt: nil,
                                              deleteAt: 9_999_999_999, hideEmail: false))
        let v1 = try XCTUnwrap(ScriptedServer.recorded().last { $0.path == "/api/sends" }?.body)
        XCTAssertNil(v1["owner_content_key"])
        XCTAssertEqual(try sendFieldVersion(ciphertext: v1["name"] as? String ?? ""), 1)
        XCTAssertNotNil(v1["access_verifier"] as? String)
    }
}
