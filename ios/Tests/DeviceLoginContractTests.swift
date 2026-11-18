import Foundation
import PassAuthCore
import PassAuthKit
import XCTest

/// Sign in with another device against the scripted server (`ScriptedServer` in
/// ContractTests.swift): the new device's requests (no session, the access code only in a header)
/// and its sign-in with the sealed key, also through two-step login; the approving app's list and
/// answers (signed in, with the account's keys).
@MainActor
final class DeviceLoginContractTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"
    private let server = "https://fake.passauth.test"
    private let requestId = "3f6c1a7e-9b2d-4c1a-8f00-000000000001"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-device-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    private var now: Int { Int(Date().timeIntervalSince1970) }

    /// A `/sync` body with the account's own vault (no items).
    private func syncBody(_ created: NewAccount) throws -> Data {
        let vaultId = try newId()
        let k = try created.account.newVaultKey(vaultId: vaultId)
        return try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": vaultId, "wrapped_key": k.wrapped, "key_kind": "account", "role": "owner",
                        "meta": try k.key.encryptMeta(vaultId: vaultId, metaJson: #"{"name":"Personal"}"#)]],
            "items": [],
            "revision": 5,
        ] as [String: Any])
    }

    private func repo(remember: String? = nil, configure: (inout Stored) -> Void = { _ in }) -> VaultRepository {
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            s.file.accounts["acc"] = AccountData(server: server)
            s.file.activeId = "acc"
            if let remember { s.secrets.rememberTokens["\(server)|a@example.com"] = remember }
            configure(&s)
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] }).allowingOlderServers()
        repo.isApp = true
        repo.deviceLoginSleep = { _ in }
        return repo
    }

    /// The session answer of an approved request (as a password sign-in's, plus `sealed_key`).
    private func session(_ created: NewAccount, sealed: String, remember: String? = nil, status: Bool = true) throws -> String {
        let accountId = try JSON.parse(created.bundleJson).str("account_id")
        return #"{"#
            + (status ? #""status":"approved","# : "")
            + #""sealed_key":"\#(sealed)","access_token":"A2","refresh_token":"R2","expires_in":900,"#
            + #""remember_token":\#(remember.map { "\"\($0)\"" } ?? "null"),"user_id":"\#(accountId)","email":"a@example.com","bundle":\#(created.bundleJson)}"#
    }

    private func started() -> String {
        #"{"id":"\#(requestId)","fingerprint_phrase":"words from the server","expires_at":\#(now + 900)}"#
    }

    /// The other device's approval of the request made with `pub`: the user picked its words.
    private func approve(_ created: NewAccount, _ pub: String, requestId: String? = nil, secretKey: String?) throws -> LoginApproval {
        try created.account.approveLoginRequest(requesterPublicKey: pub, requestId: requestId ?? self.requestId, chosenPhrase: try loginPhrase(publicKey: pub), secretKey: secretKey)
    }

    /// A code other than `code`.
    private func wrong(_ code: String) -> String { code == "000000" ? "111111" : "000000" }

    /// Waits until the (background, best-effort) sign-out of the discarded session was sent.
    private func logoutSent(token: String) async -> Bool {
        for _ in 0..<50 {
            if ScriptedServer.recorded().contains(where: { $0.method == "POST" && $0.path == "/api/auth/logout" && $0.headers["Authorization"] == "Bearer \(token)" }) { return true }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return false
    }

    func testNewDeviceSignsInWithTheOtherDevicesApproval() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        // A Secret Key the approving app keeps for this account, passed along sealed.
        let sk = try XCTUnwrap(try createAccount(accountId: try newId(), password: password, withSecretKey: true).secretKey)
        ScriptedServer.syncBodies = [try syncBody(created)]
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        let repo = repo(remember: "REM")

        let shown = try await repo.beginDeviceLogin(email: " A@example.com ")
        let post = try XCTUnwrap(ScriptedServer.recorded().first { $0.method == "POST" && $0.path == "/api/auth/requests" })
        XCTAssertNil(post.headers["Authorization"], "no session yet")
        XCTAssertEqual(post.body["email"] as? String, "A@example.com")
        let pub = try XCTUnwrap(post.body["public_key"] as? String)
        let code = try XCTUnwrap(post.body["access_code"] as? String)
        XCTAssertEqual(code.count, 43)
        XCTAssertEqual(post.body["device_kind"] as? String, "mobile")
        XCTAssertEqual(post.body["remember_token"] as? String, "REM", "this device's remember token for the account")
        XCTAssertEqual(shown.phrase, try loginPhrase(publicKey: pub), "the words of this device's own key")
        XCTAssertNotEqual(shown.phrase, "words from the server")
        XCTAssertEqual(shown.id, requestId)

        // The other device approves: the account key sealed to this request's key, and a code.
        let approval = try approve(created, pub, secretKey: sk)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, #"{"status":"pending"}"#)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, try session(created, sealed: approval.sealed, remember: "REM2"))
        let step = try await repo.awaitDeviceLogin()
        XCTAssertEqual(step, .enterCode)
        // Nothing is kept before the code: no tokens, no Secret Key, still signed out.
        XCTAssertTrue(repo.deviceCodePending)
        XCTAssertEqual(repo.state.status, .loggedOut)
        XCTAssertNil(repo.store.get().tokens("acc"))
        XCTAssertNil(repo.store.get().secrets.secretKeys["a@example.com"])
        do {
            try await repo.confirmDeviceLogin(code: wrong(approval.code))
            XCTFail("wrong code")
        } catch let e as UserError {
            XCTAssertEqual(e.message, "That code doesn't match. 2 tries left.")
        }
        do {
            try await repo.confirmDeviceLogin(code: "12 34")
            XCTFail("not 6 digits")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.codePrompt, "not counted")
        }
        XCTAssertEqual(repo.state.status, .loggedOut)
        try await repo.confirmDeviceLogin(code: "\(approval.code.prefix(3))-\(approval.code.suffix(3))")
        XCTAssertFalse(repo.deviceCodePending)

        let polls = ScriptedServer.recorded().filter { $0.path == "/api/auth/requests/\(requestId)" }
        XCTAssertEqual(polls.count, 2)
        for p in polls {
            XCTAssertEqual(p.method, "GET")
            XCTAssertEqual(p.headers["X-PassAuth-Access-Code"], code)
            XCTAssertNil(p.headers["Authorization"])
            XCTAssertEqual(p.query, "", "the code never goes into the URL")
        }
        let s = repo.store.get()
        XCTAssertEqual(repo.state.status, .unlocked)
        XCTAssertEqual(repo.state.email, "a@example.com")
        XCTAssertEqual(s.tokens("acc"), Tokens(access: "A2", refresh: "R2"))
        XCTAssertEqual(s.secrets.secretKeys["a@example.com"], sk, "kept for unlocking with the master password later")
        XCTAssertEqual(s.secrets.rememberTokens["\(server)|a@example.com"], "REM2")
        XCTAssertNotNil(repo.vault, "synced and opened like a password sign-in")

        // Locked later, the master password unlocks it (the bundle is the account's own).
        await repo.lockActive()
        try await repo.unlock(password: password, secretKey: nil)
        XCTAssertEqual(repo.state.status, .unlocked)
    }

    func testTwoStepLoginAfterTheApproval() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        ScriptedServer.syncBodies = [try syncBody(created)]
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        let repo = repo()
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        let pub = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/auth/requests" }?.body["public_key"] as? String)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200,
                              #"{"status":"approved","two_factor_required":true,"two_factor_token":"TT","providers":["totp","recovery"]}"#)
        guard case .twoFactor(let token, let providers) = try await repo.awaitDeviceLogin() else { return XCTFail("two-step login first") }
        XCTAssertEqual(token, "TT")
        XCTAssertEqual(providers, ["totp", "recovery"])
        XCTAssertEqual(repo.state.status, .loggedOut)

        // The session (and the sealed key) come with the second step; then the code.
        let approval = try approve(created, pub, secretKey: nil)
        ScriptedServer.answer("POST /api/auth/2fa/verify", 200, try session(created, sealed: approval.sealed, remember: "REM", status: false))
        let next = try await repo.verifyTwoFactor(token: "TT", provider: "totp", code: "123 456", remember: true)
        XCTAssertEqual(next, .enterDeviceCode)
        let verify = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/auth/2fa/verify" })
        XCTAssertEqual(verify.body["two_factor_token"] as? String, "TT")
        XCTAssertEqual(verify.body["code"] as? String, "123456")
        XCTAssertEqual(repo.state.status, .loggedOut, "not before the code")
        try await repo.confirmDeviceLogin(code: approval.code)
        XCTAssertEqual(repo.state.status, .unlocked)
        XCTAssertEqual(repo.store.get().secrets.rememberTokens["\(server)|a@example.com"], "REM")
        XCTAssertNil(repo.store.get().secrets.secretKeys["a@example.com"], "no Secret Key came along")
    }

    func testDeniedForgedAndCancelledRequestsSignNobodyIn() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let repo = repo()
        // Denied on the other device.
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, #"{"status":"denied"}"#)
        do {
            _ = try await repo.awaitDeviceLogin()
            XCTFail("denied")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.denied)
        }
        do {
            _ = try await repo.awaitDeviceLogin()
            XCTFail("nothing left to wait for")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.gone)
        }

        // An approval sealed for another request (a server that swapped things): nothing is kept.
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        let pub = try XCTUnwrap(ScriptedServer.recorded().last { $0.path == "/api/auth/requests" }?.body["public_key"] as? String)
        let other = try approve(created, pub, requestId: "another-request", secretKey: nil)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, try session(created, sealed: other.sealed))
        do {
            _ = try await repo.awaitDeviceLogin()
            XCTFail("forged")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.unverified)
        }
        XCTAssertEqual(repo.state.status, .loggedOut)
        XCTAssertNil(repo.store.get().tokens("acc"))
        let discarded = await logoutSent(token: "A2")
        XCTAssertTrue(discarded, "the session the server made for it is signed out")

        // Turned off on the server.
        ScriptedServer.answer("POST /api/auth/requests", 403, #"{"error":"login_with_device_disabled","message":"off"}"#)
        do {
            _ = try await repo.beginDeviceLogin(email: "a@example.com")
            XCTFail("disabled")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.disabled)
        }

        // Cancelled: the key is dropped.
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        repo.cancelDeviceLogin()
        do {
            _ = try await repo.awaitDeviceLogin()
            XCTFail("cancelled")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.gone)
        }
    }

    /// Three wrong codes stop the sign-in: the session is signed out, the keys dropped, nothing
    /// stored; the right code no longer helps.
    func testThreeWrongCodesStopTheSignIn() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let sk = try XCTUnwrap(try createAccount(accountId: try newId(), password: password, withSecretKey: true).secretKey)
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        let repo = repo()
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        let pub = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/auth/requests" }?.body["public_key"] as? String)
        let approval = try approve(created, pub, secretKey: sk)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, try session(created, sealed: approval.sealed, remember: "REM2"))
        _ = try await repo.awaitDeviceLogin()
        for left in ["2 tries", "1 try"] {
            do {
                try await repo.confirmDeviceLogin(code: wrong(approval.code))
                XCTFail("wrong code")
            } catch let e as UserError {
                XCTAssertEqual(e.message, "That code doesn't match. \(left) left.")
            }
        }
        do {
            try await repo.confirmDeviceLogin(code: wrong(approval.code))
            XCTFail("third wrong code")
        } catch let e as DeviceLoginStopped {
            XCTAssertEqual(e.message, DeviceLogin.tooManyCodes)
        }
        XCTAssertFalse(repo.deviceCodePending)
        let signedOut = await logoutSent(token: "A2")
        XCTAssertTrue(signedOut, "the new session is signed out")
        do {
            try await repo.confirmDeviceLogin(code: approval.code)
            XCTFail("over")
        } catch is DeviceLoginStopped {}
        let s = repo.store.get()
        XCTAssertEqual(repo.state.status, .loggedOut)
        XCTAssertNil(s.tokens("acc"))
        XCTAssertNil(s.secrets.secretKeys["a@example.com"])
        XCTAssertNil(s.secrets.rememberTokens["\(server)|a@example.com"])
    }

    /// Client review F7: a received Secret Key is kept only for the email typed here, and never
    /// replaces another one kept for it.
    func testReceivedSecretKeyNeverReplacesAnotherOne() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let sk = try XCTUnwrap(try createAccount(accountId: try newId(), password: password, withSecretKey: true).secretKey)
        ScriptedServer.syncBodies = [try syncBody(created)]
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        let repo = repo { $0.secrets.secretKeys["a@example.com"] = "PA1-KEPT" }
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        let pub = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/auth/requests" }?.body["public_key"] as? String)
        let approval = try approve(created, pub, secretKey: sk)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, try session(created, sealed: approval.sealed))
        _ = try await repo.awaitDeviceLogin()
        try await repo.confirmDeviceLogin(code: approval.code)
        XCTAssertEqual(repo.state.status, .unlocked)
        XCTAssertEqual(repo.store.get().secrets.secretKeys["a@example.com"], "PA1-KEPT", "the one kept stays")
    }

    /// An answer naming another account than the email typed: its Secret Key isn't kept for either.
    func testReceivedSecretKeyOnlyForTheTypedEmail() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let sk = try XCTUnwrap(try createAccount(accountId: try newId(), password: password, withSecretKey: true).secretKey)
        ScriptedServer.syncBodies = [try syncBody(created)]
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        let repo = repo()
        _ = try await repo.beginDeviceLogin(email: "typed@example.com")
        let pub = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/auth/requests" }?.body["public_key"] as? String)
        let approval = try approve(created, pub, secretKey: sk)
        // `session` answers for a@example.com.
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, try session(created, sealed: approval.sealed))
        _ = try await repo.awaitDeviceLogin()
        try await repo.confirmDeviceLogin(code: approval.code)
        let keys = repo.store.get().secrets.secretKeys
        XCTAssertNil(keys["typed@example.com"])
        XCTAssertNil(keys["a@example.com"])
    }

    /// Cancelling at the code step drops the approval and signs its session out.
    func testCancellingAtTheCodeStep() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        ScriptedServer.answer("POST /api/auth/requests", 200, started())
        let repo = repo()
        _ = try await repo.beginDeviceLogin(email: "a@example.com")
        let pub = try XCTUnwrap(ScriptedServer.recorded().first { $0.path == "/api/auth/requests" }?.body["public_key"] as? String)
        let approval = try approve(created, pub, secretKey: nil)
        ScriptedServer.answer("GET /api/auth/requests/\(requestId)", 200, try session(created, sealed: approval.sealed))
        _ = try await repo.awaitDeviceLogin()
        repo.cancelDeviceLogin()
        XCTAssertFalse(repo.deviceCodePending)
        let signedOut = await logoutSent(token: "A2")
        XCTAssertTrue(signedOut)
        do {
            try await repo.confirmDeviceLogin(code: approval.code)
            XCTFail("cancelled")
        } catch is DeviceLoginStopped {}
        XCTAssertEqual(repo.state.status, .loggedOut)
    }

    func testFeatureOfferedByTheServer() async throws {
        let repo = repo()
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["login_with_device"]}"#)
        let offered = await repo.deviceLoginAvailable()
        XCTAssertTrue(offered)
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["delta_sync"]}"#)
        let older = await repo.deviceLoginAvailable()
        XCTAssertFalse(older)
    }

    /// The approving app: signed in, listed with the session, answered with the account's keys.
    func testApprovingAppListsAndAnswers() async throws {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        ScriptedServer.syncBodies = [try syncBody(created)]
        let repo = repo { s in
            s.file.accounts["acc"]?.email = "a@example.com"
            s.file.accounts["acc"]?.bundle = created.bundleJson
            s.file.accounts["acc"]?.features = ["login_with_device"]
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        // Locked: nothing is asked.
        var list = try await repo.listAuthRequests()
        XCTAssertNil(list)
        // The server's config as the app asks for it after unlocking (policies).
        for _ in 0..<2 { ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["login_with_device"]}"#) }
        try await repo.unlock(password: password, secretKey: nil)

        let key = try LoginRequestKey.generate()
        ScriptedServer.answer("GET /api/account/auth-requests", 200, #"""
        {"requests":[{"id":"\#(requestId)","public_key":"\#(key.publicKey())","fingerprint_phrase":"spoofed words","challenge":"not-a-real-challenge","device_name":"Pixel 9","device_kind":"mobile","client":"android/0.6.0","ip":"203.0.113.7","created_at":\#(now),"expires_at":\#(now + 900)}]}
        """#)
        list = try await repo.listAuthRequests()
        let r = try XCTUnwrap(list?.first)
        XCTAssertEqual(r.id, requestId)
        XCTAssertTrue(DeviceApprovals.choices(r).contains(key.phrase()), "the words of the key, not the server's")
        XCTAssertFalse(DeviceApprovals.choices(r).contains("spoofed words"))
        let get = try XCTUnwrap(ScriptedServer.recorded().last { $0.path == "/api/account/auth-requests" })
        XCTAssertEqual(get.headers["Authorization"], "Bearer A")

        // Words that aren't the key's: nothing is sealed or sent.
        do {
            _ = try await repo.approveAuthRequest(r, phrase: "apple banana cherry delta echo")
            XCTFail("not the key's words")
        } catch {
            XCTAssertTrue(DeviceApprovals.isPhraseMismatch(error))
        }
        // A challenge the account's keys don't open: nothing is sent (a stolen session can't approve either).
        do {
            _ = try await repo.approveAuthRequest(r, phrase: key.phrase())
            XCTFail("the challenge must open")
        } catch {}
        XCTAssertTrue(ScriptedServer.recorded().filter { $0.path == "/api/account/auth-requests/\(requestId)" }.isEmpty)

        // Deny: just the answer.
        ScriptedServer.answer("POST /api/account/auth-requests/\(requestId)", 200, #"{"id":"\#(requestId)","status":"denied"}"#)
        try await repo.denyAuthRequest(r)
        let answer = try XCTUnwrap(ScriptedServer.recorded().last { $0.path == "/api/account/auth-requests/\(requestId)" })
        XCTAssertEqual(answer.method, "POST")
        XCTAssertEqual(answer.body as NSDictionary, ["approve": false] as NSDictionary)

        // A server without the feature isn't asked.
        repo.store.update { $0.file.accounts["acc"]?.features = ["delta_sync"] }
        let asked = ScriptedServer.recorded().filter { $0.path == "/api/account/auth-requests" }.count
        list = try await repo.listAuthRequests()
        XCTAssertNil(list)
        XCTAssertEqual(ScriptedServer.recorded().filter { $0.path == "/api/account/auth-requests" }.count, asked)
    }
}
