import Foundation
import PassAuthKit
import XCTest

/// Settings → Account security → Signed-in devices: the sessions list with each one's app
/// (`client`), signing one out, and "Sign out other sessions" only where the server has it.
@MainActor
final class SessionsTests: XCTestCase {
    private var dir: URL!

    private let sessionsJSON = #"{"current":"s1","sessions":["#
        + #"{"id":"s1","device_id":"d1","device_name":"PassAuth for iOS (iPhone)","device_kind":"mobile","client":"ios/0.6.0","created_at":1762000000,"last_used":1762100000},"#
        + #"{"id":"s 2","device_id":"d2","device_name":"Chrome on macOS","device_kind":"extension","client":"extension/0.6.0","created_at":1762000000,"last_used":1762000500},"#
        + #"{"id":"s3","device_id":"d3","device_name":"","device_kind":"web","client":null,"created_at":1762000000,"last_used":1762000600}]}"#

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-sessions-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    /// A signed-in account (nothing to unlock: these requests only need its session).
    private func repo() -> VaultRepository {
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            s.file.accounts["acc"] = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        return VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] }).allowingOlderServers()
    }

    func testSessionsListedWithTheirAppAndSignedOut() async throws {
        ScriptedServer.answer("GET /api/account/sessions", 200, sessionsJSON)
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["key_epoch","revoke_others"]}"#)
        let repo = repo()
        let list = try await repo.accountSessions()
        XCTAssertEqual(list.sessions.map(\.id), ["s1", "s 2", "s3"])
        XCTAssertEqual(list.sessions.map(\.current), [true, false, false])
        XCTAssertEqual(list.others.map(\.id), ["s 2", "s3"])
        XCTAssertTrue(list.canRevokeOthers)
        XCTAssertEqual(list.sessions.map(SessionText.app), ["iPhone app 0.6.0", "Chrome extension 0.6.0", "Web vault"])
        XCTAssertNil(list.sessions[2].client)
        // The feature check is sent without the session.
        let config = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/config" })
        XCTAssertNil(config.headers["Authorization"])

        ScriptedServer.reset()
        try await repo.revokeSession("s 2")
        ScriptedServer.answer("POST /api/account/sessions/revoke-others", 200, #"{"ok":true,"revoked":2}"#)
        let revoked = try await repo.revokeOtherSessions()
        XCTAssertEqual(revoked, 2)
        let calls = ScriptedServer.recorded()
        XCTAssertEqual(calls.map { "\($0.method) \($0.path)" }, ["DELETE /api/account/sessions/s 2", "POST /api/account/sessions/revoke-others"])
        XCTAssertTrue(calls.allSatisfy { $0.headers["Authorization"] == "Bearer A" })
    }

    func testSignOutOthersOnlyWhereTheServerHasIt() async throws {
        let repo = repo()
        // An older server: no `revoke_others` in its features, or no features at all.
        for config in [#"{"name":"PassAuth","features":["key_epoch"]}"#, #"{"name":"PassAuth"}"#] {
            ScriptedServer.answer("GET /api/account/sessions", 200, sessionsJSON)
            ScriptedServer.answer("GET /api/config", 200, config)
            let list = try await repo.accountSessions()
            XCTAssertFalse(list.canRevokeOthers, config)
        }
        // The check failing doesn't fail the list.
        ScriptedServer.answer("GET /api/account/sessions", 200, sessionsJSON)
        ScriptedServer.answer("GET /api/config", 502, "<html>Bad gateway</html>", headers: ["Content-Type": "text/html"])
        let list = try await repo.accountSessions()
        XCTAssertEqual(list.sessions.count, 3)
        XCTAssertFalse(list.canRevokeOthers)
    }

    func testSessionWordingLikeTheWebVault() {
        XCTAssertEqual(SessionText.client("extension/0.6.0"), "Chrome extension 0.6.0")
        XCTAssertEqual(SessionText.client("desktop/0.7.0"), "Desktop app 0.7.0")
        XCTAssertEqual(SessionText.client("web/0.9.0"), "Web")
        XCTAssertEqual(SessionText.client("ios/0.6.0"), "iPhone app 0.6.0")
        XCTAssertEqual(SessionText.client("android/0.6.1"), "Android app 0.6.1")
        XCTAssertEqual(SessionText.client("macos-autofill/0.7.0"), "Mac AutoFill 0.7.0")
        XCTAssertEqual(SessionText.client("cli/unknown"), "Command line")
        XCTAssertEqual(SessionText.client("desktop"), "Desktop app")
        // Unknown names as sent (first letter capitalised), with a version that looks like one.
        XCTAssertEqual(SessionText.client("MyTool/1.2"), "Mytool 1.2")
        XCTAssertEqual(SessionText.client("password_sync/2.0-beta"), "Password-sync 2.0-beta")
        XCTAssertNil(SessionText.client(nil))
        XCTAssertNil(SessionText.client("  "))
        XCTAssertEqual(SessionText.kind("mobile"), "Mobile app")
        XCTAssertEqual(SessionText.kind("extension"), "Browser extension")
        XCTAssertEqual(SessionText.kind("tv"), "Tv")
        let s = SessionInfo(id: "x", deviceName: "Laptop", deviceKind: "desktop", createdAt: 1_000, lastUsed: 1_000)
        XCTAssertEqual(SessionText.app(s), "Desktop app")
        let now = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertEqual(SessionText.ago(1_000_000 - 30, now: now), "Just now")
        XCTAssertEqual(SessionText.ago(1_000_000 - 300, now: now), "5 min ago")
        XCTAssertEqual(SessionText.ago(1_000_000 - 3_700, now: now), "1 hour ago")
        XCTAssertEqual(SessionText.ago(1_000_000 - 3 * 3_600, now: now), "3 hours ago")
        XCTAssertEqual(SessionText.ago(1_000_000 - 2 * 86_400, now: now), "2 days ago")
        var mine = s
        mine.current = true
        XCTAssertTrue(SessionText.detail(mine).hasSuffix(" · in use now"))
        var other = s
        other.lastUsed = 1_000_000 - 300
        XCTAssertTrue(SessionText.detail(other, now: now).hasSuffix(" · last used 5 min ago"))
        other.lastUsed = 1_000_000
        XCTAssertTrue(SessionText.detail(other, now: now).hasSuffix(" · last used just now"))
        XCTAssertEqual(SessionText.revokedOthers(2), "2 other sessions signed out.")
        XCTAssertEqual(SessionText.revokedOthers(1), "1 other session signed out.")
        XCTAssertEqual(SessionText.revokedOthers(nil), "Other sessions signed out.")
    }

    // MARK: Forget a device (`forget_device`)

    /// Sessions carry their device; "Forget…" is offered only where the server has the feature.
    func testDevicesCanBeForgottenWhereTheServerHasIt() async throws {
        let repo = repo()
        ScriptedServer.answer("GET /api/account/sessions", 200, sessionsJSON)
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","features":["revoke_others","forget_device"]}"#)
        let list = try await repo.accountSessions()
        XCTAssertEqual(list.sessions.map(\.deviceId), ["d1", "d2", "d3"])
        XCTAssertTrue(list.canForget)
        XCTAssertTrue(list.canForget(list.sessions[1]))
        XCTAssertTrue(list.isThisDevice("d1"))
        XCTAssertFalse(list.isThisDevice("d2"))
        XCTAssertEqual(list.sessionCount(device: "d2"), 1)

        ScriptedServer.answer("GET /api/account/sessions", 200, sessionsJSON)
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","features":["revoke_others"]}"#)
        let older = try await repo.accountSessions()
        XCTAssertFalse(older.canForget(older.sessions[1]))
        // A session without its device (older server) can't be forgotten.
        let noDevice = SessionList(json: try JSON.parse(#"{"current":"s1","sessions":[{"id":"s1"},{"id":"s2","device_id":"d2"}]}"#), canRevokeOthers: true, canForget: true)
        XCTAssertFalse(noDevice.canForget(noDevice.sessions[0]))
        XCTAssertTrue(noDevice.canForget(noDevice.sessions[1]))
    }

    /// Forgetting another device: one request, this device stays signed in.
    func testForgetAnotherDevice() async throws {
        let repo = repo()
        ScriptedServer.answer("POST /api/account/devices/d 2/forget", 200, #"{"ok":true,"signed_out":2,"current":false}"#)
        let here = try await repo.forgetDevice("d 2")
        XCTAssertFalse(here)
        XCTAssertNotNil(repo.store.get().tokens("acc"))
        let calls = ScriptedServer.recorded()
        XCTAssertEqual(calls.map { "\($0.method) \($0.path)" }, ["POST /api/account/devices/d 2/forget"])
        XCTAssertEqual(calls.first?.headers["Authorization"], "Bearer A")
    }

    /// Forgetting this device signs the account out here without another request (the server
    /// already ended the session) and drops the two-step "remember this device" token.
    func testForgetThisDeviceSignsOutHere() async throws {
        let repo = repo()
        let remember = "https://fake.passauth.test|a@example.com"
        repo.store.update { $0.secrets.rememberTokens[remember] = "remembered" }
        ScriptedServer.answer("POST /api/account/devices/d1/forget", 200, #"{"ok":true,"signed_out":1,"current":true}"#)
        let here = try await repo.forgetDevice("d1")
        XCTAssertTrue(here)
        XCTAssertNil(repo.store.get().tokens("acc"))
        XCTAssertNil(repo.store.get().secrets.rememberTokens[remember])
        XCTAssertEqual(repo.state.status, .loggedOut)
        XCTAssertEqual(repo.state.email, "a@example.com", "the sign-in screen still knows the account")
        XCTAssertFalse(ScriptedServer.recorded().contains { $0.path == "/api/auth/logout" }, "no logout request")
    }

    func testForgetWording() {
        XCTAssertEqual(SessionText.intro(canForget: false), "Signing a device out ends its session there. It needs your master password to sign in again.")
        XCTAssertTrue(SessionText.intro(canForget: true).hasSuffix(" Forgetting a device also ends its other sessions and makes its next sign-in count as a new device, so a remembered device has to use two-step login again."))
        XCTAssertEqual(SessionText.forgetBody(sessions: 1, here: false),
                       "Its session is signed out at once. The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it.")
        XCTAssertEqual(SessionText.forgetBody(sessions: 3, here: true),
                       "Its 3 sessions are signed out at once. The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it. This is the device you're using, so you're signed out here too.")
        XCTAssertEqual(SessionText.forgetAction(here: false), "Forget device")
        XCTAssertEqual(SessionText.forgetAction(here: true), "Forget and sign out")
        XCTAssertEqual(SessionText.forgotten("Chrome on macOS", here: false), "Chrome on macOS forgotten.")
        XCTAssertEqual(SessionText.forgotten("", here: false), "Device forgotten.")
        XCTAssertEqual(SessionText.forgotten("x", here: true), "This device was forgotten and signed out.")
    }
}
