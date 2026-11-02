import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation
import PassAuthCore
import PassAuthKit
import XCTest

/// Live sync messages, reconnect backoff and the socket address.
final class LiveSyncTests: XCTestCase {
    func testParse() {
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"sync","revision":42}"#), .sync(revision: 42))
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"logout"}"#), .logout)
        XCTAssertNil(LiveSyncProtocol.parse(#"{"type":"sync"}"#))
        XCTAssertNil(LiveSyncProtocol.parse(#"{"type":"sync","revision":null}"#))
        XCTAssertNil(LiveSyncProtocol.parse(#"{"type":"hello"}"#))
        XCTAssertNil(LiveSyncProtocol.parse("not json"))
    }

    func testActions() {
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 8), currentRevision: 7), .sync)
        // Our own save already re-synced to this revision.
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 7), currentRevision: 7), .ignore)
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 6), currentRevision: 7), .ignore)
        // Locked meanwhile: nothing shown, nothing to refresh.
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 8), currentRevision: nil), .ignore)
        XCTAssertEqual(LiveSyncProtocol.action(.logout, currentRevision: 7), .checkSession)
        XCTAssertEqual(LiveSyncProtocol.action(nil, currentRevision: 7), .ignore)
    }

    func testBackoff() {
        XCTAssertEqual((0...8).map { LiveSyncProtocol.backoffMillis(attempt: $0) }, [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000])
        XCTAssertEqual(LiveSyncProtocol.backoffMillis(attempt: -1), 1_000)
        XCTAssertEqual(LiveSyncProtocol.backoffMillis(attempt: 0, jitter: 1), 1_200)
        XCTAssertEqual(LiveSyncProtocol.backoffMillis(attempt: 10, jitter: 0.5), 66_000)
        XCTAssertEqual(LiveSyncProtocol.backoffMillis(attempt: 1, jitter: 7), 2_400, "jitter is capped at 20%")
    }

    func testSocketURL() {
        XCTAssertEqual(LiveSyncProtocol.socketURL(server: "https://vault.example.com", accessToken: "abc")?.absoluteString, "wss://vault.example.com/api/ws?access_token=abc")
        XCTAssertEqual(LiveSyncProtocol.socketURL(server: "http://127.0.0.1:8091/pa", accessToken: "a+b/c=")?.absoluteString, "ws://127.0.0.1:8091/pa/api/ws?access_token=a%2Bb/c%3D")
        XCTAssertNil(LiveSyncProtocol.socketURL(server: "ftp://x", accessToken: "a"))
    }
}

/// Export file names, password checks, formats from the core, password history listing.
final class ExportTests: XCTestCase {
    func testFileNames() {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let date = Date(timeIntervalSince1970: 1_799_000_000) // 2027-01-03 UTC
        XCTAssertEqual(VaultExport.fileName(.encrypted, date: date, calendar: cal), "passauth-export-2027-01-03-protected.json")
        XCTAssertEqual(VaultExport.fileName(.json, date: date, calendar: cal), "passauth-export-2027-01-03.json")
        XCTAssertEqual(VaultExport.fileName(.csv, date: date, calendar: cal), "passauth-export-2027-01-03.csv")
    }

    func testPasswordProblems() {
        XCTAssertNotNil(VaultExport.passwordProblem("short", "short"))
        XCTAssertNotNil(VaultExport.passwordProblem("long enough 1", "long enough 2"))
        XCTAssertNil(VaultExport.passwordProblem("long enough", "long enough"))
        XCTAssertNil(VaultExport.passwordProblem("0123456789", "0123456789"))
    }

    func testFormatsFromTheCore() throws {
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Example"
        item.login?.username = "alice"
        item.login?.password = "s3cret-pw"
        var card = Item.empty(.card, now: 1_700_000_000)
        card.name = "Card"
        let items = "[" + [item, card].map { ItemCodec.encode($0) }.joined(separator: ",") + "]"
        let json = try VaultExport.build(.json, itemsJson: items, password: nil)
        XCTAssertTrue(json.contains("s3cret-pw"))
        let csv = try VaultExport.build(.csv, itemsJson: items, password: nil)
        XCTAssertTrue(csv.contains("alice"))
        XCTAssertFalse(csv.contains("Card"), "CSV holds logins and notes only")
        let protected = try VaultExport.build(.encrypted, itemsJson: items, password: "export-password-1")
        XCTAssertFalse(protected.contains("s3cret-pw"))
        // The encrypted file imports again with its password (the core's importer).
        let back = try importFile(data: Data(protected.utf8), password: "export-password-1")
        XCTAssertTrue(back.contains("s3cret-pw"))
        XCTAssertThrowsError(try VaultExport.build(.encrypted, itemsJson: items, password: "short"))
    }

    func testPasswordHistoryOrder() {
        let h = [PasswordChange(password: "old", changedAt: 10), PasswordChange(password: "", changedAt: 30), PasswordChange(password: "newer", changedAt: 20)]
        XCTAssertEqual(PasswordHistory.entries(h).map(\.password), ["newer", "old"])
        XCTAssertEqual(PasswordHistory.summary(0), "No previous passwords")
        XCTAssertEqual(PasswordHistory.summary(1), "1 previous password")
        XCTAssertEqual(PasswordHistory.summary(3), "3 previous passwords")
    }
}

/// QR codes from images (Photos): generated codes decode, also light-on-dark ones.
final class QrDecoderTests: XCTestCase {
    private func qr(_ text: String, inverted: Bool = false) -> Data {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        var img = f.outputImage!.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        if inverted { img = img.applyingFilter("CIColorInvert") }
        // A quiet zone around the code, like a screenshot.
        let bg = CIImage(color: inverted ? .black : .white).cropped(to: img.extent.insetBy(dx: -64, dy: -64))
        let composed = img.composited(over: bg)
        let ctx = CIContext()
        return ctx.pngRepresentation(of: composed, format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())!
    }

    func testDecodesOtpauthQr() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        let codes = QrDecoder.decode(data: qr(uri))
        XCTAssertEqual(codes, [uri])
        XCTAssertEqual(OtpAuth.parse(codes[0]).key?.label, "Example (alice@example.com)")
    }

    func testDecodesInvertedQr() {
        XCTAssertEqual(QrDecoder.decode(data: qr("JBSWY3DPEHPK3PXP", inverted: true)), ["JBSWY3DPEHPK3PXP"])
    }

    func testNoQr() {
        let blank = CIContext().pngRepresentation(of: CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: 200, height: 200)), format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())!
        XCTAssertEqual(QrDecoder.decode(data: blank), [])
        XCTAssertEqual(QrDecoder.decode(data: Data("nope".utf8)), [])
    }

    /// Scanned codes go through the same checks as typed ones (HOTP and migration exports refused).
    func testScannedKindsRefused() {
        XCTAssertEqual(OtpAuth.parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").problem, "This is a counter-based (HOTP) key. PassAuth supports time-based (TOTP) keys only.")
        XCTAssertEqual(OtpAuth.parse("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8").problem,
                       "This is an authenticator app's export of several accounts. Scan the QR code a website shows when you set up two-step login.")
        XCTAssertEqual(OtpAuth.parse("otpauth://totp/x?issuer=Nope").problem, "This QR code has no secret key in it.")
    }
}

/// A fake server for the repository: `/sync` from fixed data, records the item writes.
final class RecordingServer: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var syncBody = Data()
    nonisolated(unsafe) static var requests: [(method: String, path: String, body: [String: Any])] = []
    private static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let method = request.httpMethod ?? "GET"
        var body = Data("{}".utf8)
        Self.lock.lock()
        if path == "/api/sync" {
            body = Self.syncBody
        } else {
            Self.requests.append((method, path, Self.bodyJSON(request)))
            if path.hasPrefix("/api/items/") { body = Data(#"{"revision":6}"#.utf8) }
        }
        Self.lock.unlock()
        let res = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
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

/// Moving an item: re-encrypted with the target vault's key under the same id, sent as
/// `PUT /api/items/{id}` with the new `vault_id` and the old revision (like the web vault).
@MainActor
final class MoveItemTests: XCTestCase {
    private var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-move-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        RecordingServer.requests = []
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
    }

    func testMoveRequestShape() async throws {
        let password = "correct horse battery staple"
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let account = created.account
        let a = try newId(), b = try newId()
        let ka = try account.newVaultKey(vaultId: a), kb = try account.newVaultKey(vaultId: b)
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Shop"
        item.login?.password = "pw-1"
        let itemId = try newId()
        let enc = try ka.key.encryptItem(itemJson: ItemCodec.encode(item), id: itemId, vaultId: a)
        let sync: [String: Any] = [
            "vaults": [
                ["id": a, "wrapped_key": ka.wrapped, "key_kind": "account", "meta": try ka.key.encryptMeta(vaultId: a, metaJson: #"{"name":"Personal"}"#), "role": "owner"],
                ["id": b, "wrapped_key": kb.wrapped, "key_kind": "account", "meta": try kb.key.encryptMeta(vaultId: b, metaJson: #"{"name":"Team"}"#), "role": "write"],
            ],
            "items": [["id": itemId, "vault_id": a, "item_key": enc.key, "data": enc.data, "revision": 3, "deleted_at": NSNull()]],
            "revision": 5,
        ]
        RecordingServer.syncBody = try JSONSerialization.data(withJSONObject: sync)

        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        let api = ApiClient(store: store) { $0.protocolClasses = [RecordingServer.self] }
        let repo = VaultRepository(store: store, api: api)
        try await repo.unlock(password: password, secretKey: nil)
        let entry = try XCTUnwrap(repo.vault?.get(itemId))
        XCTAssertEqual(repo.moveTargets(entry).map(\.name), ["Team"])

        try await repo.moveItem(entry, to: b)
        let put = try XCTUnwrap(RecordingServer.requests.first { $0.method == "PUT" })
        XCTAssertEqual(put.path, "/api/items/\(itemId)")
        XCTAssertEqual(put.body["id"] as? String, itemId)
        XCTAssertEqual(put.body["vault_id"] as? String, b)
        XCTAssertEqual((put.body["revision"] as? NSNumber)?.int64Value, 3, "the revision the item had")
        // Encrypted for the target vault: its key opens it, the old vault's doesn't.
        let moved = EncryptedItem(id: itemId, vaultId: b, key: put.body["key"] as! String, data: put.body["data"] as! String)
        XCTAssertEqual(try ItemCodec.decode(try kb.key.decryptItem(encrypted: moved)).name, "Shop")
        XCTAssertThrowsError(try ka.key.decryptItem(encrypted: EncryptedItem(id: itemId, vaultId: a, key: moved.key, data: moved.data)))

        // Same vault: nothing is sent.
        RecordingServer.requests = []
        try await repo.moveItem(entry, to: a)
        XCTAssertTrue(RecordingServer.requests.isEmpty)
    }

    /// Changing a login's password keeps the old one in the history (newest first).
    func testPasswordChangeAppendsHistory() async throws {
        let password = "correct horse battery staple"
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let a = try newId()
        let ka = try created.account.newVaultKey(vaultId: a)
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Shop"
        item.login?.password = "pw-1"
        item.passwordHistory = [PasswordChange(password: "pw-0", changedAt: 1_600_000_000)]
        let itemId = try newId()
        let enc = try ka.key.encryptItem(itemJson: ItemCodec.encode(item), id: itemId, vaultId: a)
        RecordingServer.syncBody = try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": a, "wrapped_key": ka.wrapped, "key_kind": "account", "meta": try ka.key.encryptMeta(vaultId: a, metaJson: #"{"name":"Personal"}"#), "role": "owner"]],
            "items": [["id": itemId, "vault_id": a, "item_key": enc.key, "data": enc.data, "revision": 1]],
            "revision": 1,
        ] as [String: Any])
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [RecordingServer.self] })
        try await repo.unlock(password: password, secretKey: nil)
        let entry = try XCTUnwrap(repo.vault?.get(itemId))
        var next = entry.item
        next.login?.password = "pw-2"
        try await repo.updateItem(entry, next)
        let put = try XCTUnwrap(RecordingServer.requests.first { $0.method == "PUT" })
        let saved = try ItemCodec.decode(try ka.key.decryptItem(encrypted: EncryptedItem(id: itemId, vaultId: a, key: put.body["key"] as! String, data: put.body["data"] as! String)))
        XCTAssertEqual(saved.login?.password, "pw-2")
        XCTAssertEqual(saved.passwordHistory.map(\.password), ["pw-1", "pw-0"])
    }
}
