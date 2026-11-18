import CoreGraphics
import Foundation
import ImageIO
import PassAuthCore
@testable import PassAuth
import PassAuthKit
import UniformTypeIdentifiers
import XCTest

/// Profile pictures: the picture made on the device (square 256×256 JPEG ≤ 256 KiB, no
/// metadata), the sync rule (fetch only when `user.avatar_seq` changes), set/remove, the cache
/// dropped at log out, and the globe tile when website icons are off.
@MainActor
final class AvatarTests: XCTestCase {
    private var dir: URL!
    private var avatarDir: URL!
    private let password = "correct horse battery staple"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-avatar-\(UUID().uuidString)")
        avatarDir = dir.appendingPathComponent("avatars", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    // MARK: Picture made on the device

    /// A noisy RGBA image (worst case for JPEG size) of `w`×`h`, as PNG with GPS metadata.
    private func noisyPNG(_ w: Int, _ h: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: w * h * 4)
        var seed: UInt32 = 12345
        for i in 0..<bytes.count {
            seed = seed &* 1_664_525 &+ 1_013_904_223
            bytes[i] = UInt8(truncatingIfNeeded: seed >> 24)
        }
        let space = CGColorSpace(name: CGColorSpace.sRGB)!
        let ctx = try XCTUnwrap(CGContext(data: &bytes, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: space,
                                          bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        let image = try XCTUnwrap(ctx.makeImage())
        let out = NSMutableData()
        let dest = try XCTUnwrap(CGImageDestinationCreateWithData(out, UTType.png.identifier as CFString, 1, nil))
        let gps: [CFString: Any] = [kCGImagePropertyGPSLatitude: 52.37, kCGImagePropertyGPSLongitude: 4.89]
        CGImageDestinationAddImage(dest, image, [kCGImagePropertyGPSDictionary: gps] as CFDictionary)
        XCTAssertTrue(CGImageDestinationFinalize(dest))
        return out as Data
    }

    func testPreparedPictureIsSquareSmallJpegWithoutLocation() throws {
        for (w, h) in [(3000, 2000), (400, 1200), (64, 64)] {
            let jpeg = try XCTUnwrap(AvatarImage.prepare(try noisyPNG(w, h)), "\(w)×\(h)")
            XCTAssertLessThanOrEqual(jpeg.count, AvatarImage.maxBytes)
            let src = try XCTUnwrap(CGImageSourceCreateWithData(jpeg as CFData, nil))
            XCTAssertEqual(CGImageSourceGetType(src) as String?, UTType.jpeg.identifier)
            let props = try XCTUnwrap(CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any])
            XCTAssertEqual(props[kCGImagePropertyPixelWidth] as? Int, 256)
            XCTAssertEqual(props[kCGImagePropertyPixelHeight] as? Int, 256)
            XCTAssertNil(props[kCGImagePropertyGPSDictionary])
        }
    }

    func testNotAnImageIsRefused() {
        XCTAssertNil(AvatarImage.prepare(Data("not a picture".utf8)))
        XCTAssertNil(AvatarImage.prepare(Data()))
    }

    // MARK: Sync rule

    func testSyncActionFetchesOnlyWhenTheVersionChanges() {
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: nil, cachedSeq: 3, hasFile: true), .none, "older server")
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 0, cachedSeq: nil, hasFile: false), .none)
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 0, cachedSeq: 0, hasFile: false), .none)
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 0, cachedSeq: 2, hasFile: true), .clear)
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 2, cachedSeq: nil, hasFile: false), .fetch)
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 2, cachedSeq: 2, hasFile: true), .none)
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 3, cachedSeq: 2, hasFile: true), .fetch)
        XCTAssertEqual(AvatarSyncAction.decide(serverSeq: 2, cachedSeq: 2, hasFile: false), .none, "fetched once (didn't open): not asked again")
    }

    // MARK: Repository

    private struct Fixture {
        let created: NewAccount
        let vaultId: String
        let key: VaultKey
        let wrapped: String
        var accountId: String { (try? JSON.parse(created.account.legacyIdentityJson()))?.str("user_id") ?? "" }
    }

    private func fixture() throws -> Fixture {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let v = try newId()
        let k = try created.account.newVaultKey(vaultId: v)
        return Fixture(created: created, vaultId: v, key: k.key, wrapped: k.wrapped)
    }

    private func syncBody(_ f: Fixture, avatarSeq: Int64?) throws -> Data {
        var user: [String: Any] = ["id": f.accountId, "name": "Alex Morgan"]
        if let avatarSeq { user["avatar_seq"] = avatarSeq }
        return try JSONSerialization.data(withJSONObject: [
            "user": user,
            "vaults": [["id": f.vaultId, "wrapped_key": f.wrapped, "key_kind": "account",
                        "meta": try f.key.encryptMeta(vaultId: f.vaultId, metaJson: #"{"name":"Personal"}"#), "role": "owner"]],
            "items": [],
            "revision": 5,
        ] as [String: Any])
    }

    private func repo(_ f: Fixture, avatarSeq: Int64?) async throws -> VaultRepository {
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
        repo.isApp = true
        repo.avatarCache = AvatarCache(directory: avatarDir)
        ScriptedServer.syncBodies = [try syncBody(f, avatarSeq: avatarSeq)]
        try await repo.unlock(password: password, secretKey: nil)
        await repo.avatarFetch?.value
        return repo
    }

    private func avatarGets() -> Int {
        ScriptedServer.recorded().filter { $0.method == "GET" && $0.path == "/api/account/avatar" }.count
    }

    func testSyncFetchesThePictureOnlyWhenItsVersionChanges() async throws {
        let f = try fixture()
        let jpeg = try XCTUnwrap(AvatarImage.prepare(try noisyPNG(300, 300)))
        let sealed = try f.created.account.sealAvatar(image: jpeg)
        ScriptedServer.answer("GET /api/account/avatar", 200, #"{"avatar":"\#(sealed)","avatar_seq":1}"#)
        let repo = try await repo(f, avatarSeq: 1)
        XCTAssertEqual(avatarGets(), 1)
        XCTAssertEqual(repo.avatars["acc"], jpeg)
        XCTAssertEqual(repo.activeAvatar, jpeg)
        XCTAssertEqual(AvatarCache(directory: avatarDir).read("acc"), jpeg)
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.avatarSeq, 1)

        // Same version: nothing asked.
        try await repo.sync()
        await repo.avatarFetch?.value
        XCTAssertEqual(avatarGets(), 1)

        // Another device removed it: the next sync drops the picture without asking.
        ScriptedServer.syncBodies = [try syncBody(f, avatarSeq: 2)]
        ScriptedServer.answer("GET /api/account/avatar", 200, #"{"avatar":null,"avatar_seq":2}"#)
        try await repo.sync()
        await repo.avatarFetch?.value
        XCTAssertEqual(avatarGets(), 2)
        XCTAssertNil(repo.avatars["acc"])
        XCTAssertNil(AvatarCache(directory: avatarDir).read("acc"))
    }

    func testPictureThatDoesNotOpenShowsInitialsAndIsNotAskedAgain() async throws {
        let f = try fixture()
        let other = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let sealed = try other.account.sealAvatar(image: Data([0xFF, 0xD8, 0xFF, 0xD9]))
        ScriptedServer.answer("GET /api/account/avatar", 200, #"{"avatar":"\#(sealed)","avatar_seq":4}"#)
        let repo = try await repo(f, avatarSeq: 4)
        XCTAssertNil(repo.avatars["acc"])
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.avatarSeq, 4)
        try await repo.sync()
        await repo.avatarFetch?.value
        XCTAssertEqual(avatarGets(), 1)
    }

    func testOlderServerWithoutPicturesAsksNothing() async throws {
        let f = try fixture()
        let repo = try await repo(f, avatarSeq: nil)
        XCTAssertEqual(avatarGets(), 0)
        XCTAssertFalse(repo.avatarsSupported)
    }

    func testSetAndRemoveSealTheJpegAndKeepTheCache() async throws {
        let f = try fixture()
        let repo = try await repo(f, avatarSeq: 0)
        XCTAssertEqual(avatarGets(), 0)
        let jpeg = try XCTUnwrap(AvatarImage.prepare(try noisyPNG(500, 300)))
        ScriptedServer.answer("PUT /api/account/avatar", 200, #"{"ok":true,"avatar_seq":7}"#)
        try await repo.setAvatar(jpeg)
        let put = try XCTUnwrap(ScriptedServer.recorded().last { $0.method == "PUT" && $0.path == "/api/account/avatar" })
        let sent = try XCTUnwrap(put.body["avatar"] as? String)
        XCTAssertEqual(try f.created.account.openAvatar(sealed: sent), jpeg)
        XCTAssertEqual(repo.avatars["acc"], jpeg)
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.avatarSeq, 7)

        // The sync after its own change doesn't download it again.
        ScriptedServer.syncBodies = [try syncBody(f, avatarSeq: 7)]
        try await repo.sync()
        await repo.avatarFetch?.value
        XCTAssertEqual(avatarGets(), 0)

        ScriptedServer.answer("DELETE /api/account/avatar", 200, #"{"ok":true,"avatar_seq":8}"#)
        try await repo.removeAvatar()
        XCTAssertNil(repo.avatars["acc"])
        XCTAssertNil(AvatarCache(directory: avatarDir).read("acc"))
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.avatarSeq, 8)
    }

    func testTooLargeAnswerIsExplained() async throws {
        let f = try fixture()
        let repo = try await repo(f, avatarSeq: 0)
        ScriptedServer.answer("PUT /api/account/avatar", 413, #"{"error":"too large","code":"payload_too_large"}"#)
        do {
            try await repo.setAvatar(Data([0xFF, 0xD8, 0xFF, 0xD9]))
            XCTFail("expected an error")
        } catch let e as UserError {
            XCTAssertTrue(e.message.contains("too large"))
        }
        XCTAssertNil(repo.avatars["acc"])
    }

    func testLogOutDeletesTheCachedPicture() async throws {
        let f = try fixture()
        let jpeg = try XCTUnwrap(AvatarImage.prepare(try noisyPNG(256, 256)))
        let sealed = try f.created.account.sealAvatar(image: jpeg)
        ScriptedServer.answer("GET /api/account/avatar", 200, #"{"avatar":"\#(sealed)","avatar_seq":1}"#)
        let repo = try await repo(f, avatarSeq: 1)
        XCTAssertNotNil(AvatarCache(directory: avatarDir).read("acc"))
        await repo.logout()
        XCTAssertNil(repo.avatars["acc"])
        XCTAssertNil(AvatarCache(directory: avatarDir).read("acc"))
        XCTAssertNil(repo.store.get().file.accounts["acc"]?.avatarSeq)
        // A new cache over the same folder finds nothing.
        XCTAssertTrue(AvatarCache(directory: avatarDir).all().isEmpty)
    }

    // MARK: Website icons off

    func testLoginsShowTheGlobeWhenIconsAreOff() {
        XCTAssertEqual(SiteIconGlyph.symbol(iconsOn: false, kind: .login), "globe")
        XCTAssertNil(SiteIconGlyph.symbol(iconsOn: true, kind: .login), "icons on: the letter fallback stays")
        XCTAssertNil(SiteIconGlyph.symbol(iconsOn: false, kind: .card), "other kinds keep their own glyph")
    }
}
