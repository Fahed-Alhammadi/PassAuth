import PassAuthCore
import PassAuthKit
import XCTest

/// A fake server for account security: `/sync` from fixed data, the OPAQUE registration
/// answer for `/account/keys/start` (any valid Ristretto255 points the client doesn't
/// reflect back: another registration's blinded element, then the client's own as the
/// server key; the client can't verify either at registration), authenticator setup / enable with a known secret, and every request recorded.
final class SecurityServer: URLProtocol, @unchecked Sendable {
    struct Request {
        let method: String
        let path: String
        let body: [String: Any]
        let headers: [String: String]
    }

    nonisolated(unsafe) static var syncBody = Data()
    /// A valid group element other than the client's blinded one.
    nonisolated(unsafe) static var otherPoint = Data()
    nonisolated(unsafe) static var requests: [Request] = []
    nonisolated(unsafe) static var totpSecret = "JBSWY3DPEHPK3PXP"
    nonisolated(unsafe) static var recovery: [String]? = ["aaaa-bbbb", "cccc-dddd"]
    /// Paths answered with HTTP 429.
    nonisolated(unsafe) static var rateLimited: Set<String> = []
    private static let lock = NSLock()

    static func reset() {
        lock.lock()
        requests = []
        rateLimited = []
        recovery = ["aaaa-bbbb", "cccc-dddd"]
        lock.unlock()
    }

    static var recorded: [Request] {
        lock.lock()
        defer { lock.unlock() }
        return requests.filter { $0.path != "/api/sync" }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    static func b64url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    private static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let method = request.httpMethod ?? "GET"
        let json = Self.bodyJSON(request)
        var status = 200
        var out: Any = ["ok": true]
        Self.lock.lock()
        Self.requests.append(Request(method: method, path: path, body: json, headers: request.allHTTPHeaderFields ?? [:]))
        if Self.rateLimited.contains(path) {
            status = 429
            out = ["error": "rate_limited", "message": "too many requests"]
        } else {
            switch (method, path) {
            case (_, "/api/sync"):
                out = (try? JSONSerialization.jsonObject(with: Self.syncBody)) ?? [:]
            case ("POST", "/api/account/keys/start"):
                let req = Self.b64url(json["message"] as? String ?? "") ?? Data()
                out = ["message": Self.b64url(Self.otherPoint + req)]
            case ("GET", "/api/account"):
                out = ["email": "a@example.com", "two_factor": ["totp"], "recovery_codes_left": 2, "email_enabled": false]
            case ("POST", "/api/account/2fa/totp/setup"):
                out = ["secret": Self.totpSecret, "uri": "otpauth://totp/PassAuth:a%40example.com?secret=\(Self.totpSecret)&issuer=PassAuth"]
            case ("POST", "/api/account/2fa/totp/enable"):
                let now = UInt64(Date().timeIntervalSince1970)
                let ok = (try? totpCode(secret: Self.totpSecret, unixSeconds: now).code) == json["code"] as? String
                if ok {
                    out = ["recovery_codes": Self.recovery.map { $0 as Any } ?? NSNull()]
                } else {
                    status = 400
                    out = ["error": "bad_request", "message": "invalid code"]
                }
            case ("POST", "/api/account/2fa/recovery"):
                out = ["recovery_codes": ["new1-new1", "new2-new2"]]
            default:
                break
            }
        }
        Self.lock.unlock()
        let body = (try? JSONSerialization.data(withJSONObject: out)) ?? Data("{}".utf8)
        let res = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
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

/// Changing the master password / Secret Key and two-step login against the fake server.
@MainActor
final class AccountSecurityRepoTests: XCTestCase {
    private var dir: URL!
    private let server = "https://fake.passauth.test"
    private let email = "a@example.com"
    private let oldPassword = "correct horse battery staple"
    private let newPassword = "violet-lantern-orbit-cascade"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-sec-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        SecurityServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
    }

    /// An unlocked account (no Secret Key) with one vault, vault timeout "never" (session bytes kept).
    private func unlockedRepo() async throws -> (VaultRepository, SecureStore, NewAccount) {
        let created = try createAccount(accountId: try newId(), password: oldPassword, withSecretKey: false)
        SecurityServer.otherPoint = SecurityServer.b64url(try opaqueRegisterStart(master: created.master).message) ?? Data()
        let v = try newId()
        let nv = try created.account.newVaultKey(vaultId: v)
        SecurityServer.syncBody = try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": v, "wrapped_key": nv.wrapped, "key_kind": "account", "meta": try nv.key.encryptMeta(vaultId: v, metaJson: #"{"name":"Personal"}"#), "role": "owner"]],
            "items": [],
            "revision": 1,
        ] as [String: Any])
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: self.server, email: self.email)
            acc.bundle = created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.file.settings.vaultTimeout = .never
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
            s.secrets.rememberTokens["\(self.server)|\(self.email)"] = "remember-me"
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [SecurityServer.self] })
        try await repo.unlock(password: oldPassword, secretKey: nil)
        return (repo, store, created)
    }

    func testChangePasswordSequenceAndLocalState() async throws {
        let (repo, store, created) = try await unlockedRepo()
        let keptBefore = try XCTUnwrap(store.get().secrets.persistedKeys["acc"])
        SecurityServer.reset()

        // New password + turn the Secret Key on.
        let sk = try await repo.changeKeys(reauthToken: "reauth-1", newPassword: newPassword, secretKeyChange: .turnOn)
        let secretKey = try XCTUnwrap(sk, "a new Secret Key is returned to show once")
        let calls = SecurityServer.recorded
        XCTAssertEqual(calls.map(\.path), ["/api/account/keys/start", "/api/account/keys/finish"])
        XCTAssertNil(calls[0].headers["x-reauth-token"])
        let finish = calls[1]
        XCTAssertEqual(finish.method, "POST")
        XCTAssertEqual(finish.headers["x-reauth-token"], "reauth-1")
        XCTAssertFalse((finish.body["upload"] as? String ?? "").isEmpty)
        let bundle = try XCTUnwrap(finish.body["bundle"] as? [String: Any])
        XCTAssertEqual(bundle["secret_key_enabled"] as? Bool, true)
        let old = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(created.bundleJson.utf8)) as? [String: Any])
        XCTAssertEqual(bundle["public_key"] as? String, old["public_key"] as? String, "only the password wrapping changes")
        XCTAssertNotEqual(bundle["wrapped_account_key"] as? String, old["wrapped_account_key"] as? String)

        // On this device: the sent bundle, the new Secret Key, no stale remember token; the
        // kept session bytes (vault timeout "never", same as the Face ID item) are unchanged.
        let st = store.get()
        let stored = try XCTUnwrap(st.file.accounts["acc"]?.bundle)
        XCTAssertEqual(try JSON.parse(stored), try JSON.parse(String(decoding: try JSONSerialization.data(withJSONObject: bundle), as: UTF8.self)))
        XCTAssertEqual(st.secrets.secretKeys[email], secretKey)
        XCTAssertNil(st.secrets.rememberTokens["\(server)|\(email)"])
        XCTAssertEqual(st.secrets.persistedKeys["acc"], keptBefore)
        XCTAssertTrue(repo.state.secretKeyRequired)
        XCTAssertTrue(repo.state.secretKeyStored)

        // The next unlock (app or AutoFill: same store) takes the new password, not the old one.
        await repo.lockActive()
        do {
            try await repo.unlock(password: oldPassword, secretKey: nil)
            XCTFail("the old password no longer unlocks")
        } catch {}
        try await repo.unlock(password: newPassword, secretKey: nil)
        XCTAssertTrue(repo.isUnlocked)

        // Secret Key off, same password: forgotten on the device.
        SecurityServer.reset()
        let none = try await repo.changeKeys(reauthToken: "reauth-2", newPassword: newPassword, secretKeyChange: .turnOff)
        XCTAssertNil(none)
        XCTAssertEqual(SecurityServer.recorded.last?.headers["x-reauth-token"], "reauth-2")
        XCTAssertNil(store.get().secrets.secretKeys[email])
        XCTAssertFalse(repo.state.secretKeyRequired)
        await repo.lockActive()
        try await repo.unlock(password: newPassword, secretKey: nil)
    }

    func testChangePasswordNeedsTheServerFirst() async throws {
        let (repo, store, _) = try await unlockedRepo()
        let before = store.get().file.accounts["acc"]?.bundle
        SecurityServer.reset()
        SecurityServer.rateLimited = ["/api/account/keys/finish"]
        do {
            _ = try await repo.changeKeys(reauthToken: "t", newPassword: newPassword, secretKeyChange: .keep)
            XCTFail("rate limited")
        } catch {
            XCTAssertEqual(securityErrorMessage(error), "Too many attempts, try again later.")
        }
        XCTAssertEqual(store.get().file.accounts["acc"]?.bundle, before, "nothing changes locally when the server refused")
        XCTAssertEqual(store.get().secrets.rememberTokens["\(server)|\(email)"], "remember-me")
    }

    func testTotpSetupAndEnable() async throws {
        let (repo, _, _) = try await unlockedRepo()
        SecurityServer.reset()
        let setup = try await repo.startTotpSetup()
        XCTAssertEqual(setup.secret, SecurityServer.totpSecret)
        XCTAssertNotNil(AccountSecurityLogic.authenticatorURL(setup.uri))

        do {
            _ = try await repo.enableTotp(code: "000 000")
            XCTFail("wrong code")
        } catch {
            XCTAssertEqual(securityErrorMessage(error), "That code isn't right. Check it and try again.")
        }
        XCTAssertEqual(SecurityServer.recorded.last?.body["code"] as? String, "000000", "spaces dropped")

        var c = try totpCode(secret: setup.secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        if c.remaining < 3 {
            try await Task.sleep(nanoseconds: UInt64(c.remaining + 1) * 1_000_000_000)
            c = try totpCode(secret: setup.secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        }
        let codes = try await repo.enableTotp(code: String(c.code.prefix(3)) + " " + String(c.code.dropFirst(3)))
        XCTAssertEqual(codes, ["aaaa-bbbb", "cccc-dddd"], "first method: recovery codes to show once")
        XCTAssertEqual(SecurityServer.recorded.map(\.path), ["/api/account/2fa/totp/setup", "/api/account/2fa/totp/enable", "/api/account/2fa/totp/enable"])

        // A second method gets no codes (null).
        SecurityServer.recovery = nil
        let again = try await repo.enableTotp(code: try totpCode(secret: setup.secret, unixSeconds: UInt64(Date().timeIntervalSince1970)).code)
        XCTAssertNil(again)

        let status = try await repo.twoFactorStatus()
        XCTAssertEqual(status, TwoFactorStatus(providers: ["totp"], recoveryCodesLeft: 2, emailAvailable: false, email: email))
        XCTAssertTrue(status.isLast(.totp))

        SecurityServer.rateLimited = ["/api/account/2fa/totp/enable"]
        do {
            _ = try await repo.enableTotp(code: "123456")
            XCTFail("rate limited")
        } catch {
            XCTAssertEqual(securityErrorMessage(error), "Too many attempts, try again later.")
        }
    }

    func testDisableAndRegenerateNeedReauth() async throws {
        let (repo, _, _) = try await unlockedRepo()
        SecurityServer.reset()
        // The fake server can't prove the password (no OPAQUE): reauth fails, nothing is turned off.
        do {
            try await repo.disableTwoFactor(.totp, password: oldPassword, typedSecretKey: nil)
            XCTFail("reauth can't succeed against the fake server")
        } catch {}
        XCTAssertFalse(SecurityServer.recorded.contains { $0.method == "DELETE" }, "never sent without a reauth token")
        XCTAssertEqual(SecurityServer.recorded.first?.path, "/api/auth/prelogin", "reauth starts with prelogin")

        SecurityServer.reset()
        try await repo.disableTwoFactor(.totp, reauthToken: "reauth-9")
        let del = try XCTUnwrap(SecurityServer.recorded.first)
        XCTAssertEqual(del.method, "DELETE")
        XCTAssertEqual(del.path, "/api/account/2fa/totp")
        XCTAssertEqual(del.headers["x-reauth-token"], "reauth-9")

        SecurityServer.reset()
        let codes = try await repo.regenerateRecoveryCodes(reauthToken: "reauth-10")
        XCTAssertEqual(codes, ["new1-new1", "new2-new2"])
        let post = try XCTUnwrap(SecurityServer.recorded.first)
        XCTAssertEqual(post.method, "POST")
        XCTAssertEqual(post.path, "/api/account/2fa/recovery")
        XCTAssertEqual(post.headers["x-reauth-token"], "reauth-10")
    }
}

/// Pure rules of the account security screens.
final class AccountSecurityLogicTests: XCTestCase {
    func testRecoveryCodesGuard() {
        var once = ShownOnce(["a", "b"])
        XCTAssertFalse(once.canClose, "not before the user confirmed saving them")
        XCTAssertFalse(once.close())
        XCTAssertEqual(once.value, ["a", "b"], "still shown")
        once.saved = true
        XCTAssertTrue(once.canClose)
        XCTAssertTrue(once.close())
        XCTAssertEqual(once.value, [], "forgotten once closed")
        XCTAssertFalse(once.canClose)
        var empty = ShownOnce([])
        empty.saved = true
        XCTAssertFalse(empty.canClose)
    }

    func testPasswordProblems() {
        let bits: (String) -> Double = { $0.count >= 20 ? 90 : 30 }
        func p(_ cur: String, _ new: String, _ conf: String, _ sk: SecretKeyChange = .keep, weak: Bool = false) -> AccountSecurityLogic.PasswordProblem? {
            AccountSecurityLogic.passwordProblem(current: cur, new: new, confirm: conf, secretKeyChange: sk, weakAccepted: weak, bits: bits)
        }
        XCTAssertEqual(p("", "x", "x"), .noCurrent)
        XCTAssertEqual(p("cur", "", ""), .nothingToChange)
        XCTAssertNil(p("cur", "", "", .turnOn), "Secret Key change only keeps the password")
        XCTAssertEqual(p("cur", "short", "short"), .tooShort)
        XCTAssertEqual(p("cur", "long enough pass", "long enough pasS"), .mismatch)
        XCTAssertEqual(p("same password 123", "same password 123", "same password 123"), .sameAsCurrent)
        XCTAssertEqual(p("cur", "weakweakweak", "weakweakweak"), .weak)
        XCTAssertNil(p("cur", "weakweakweak", "weakweakweak", weak: true), "accepted on the second try")
        XCTAssertNil(p("cur", "a much longer passphrase here", "a much longer passphrase here"))
        XCTAssertEqual(SecretKeyChange.from(wasOn: true, wantOn: true), .keep)
        XCTAssertEqual(SecretKeyChange.from(wasOn: false, wantOn: true), .turnOn)
        XCTAssertEqual(SecretKeyChange.from(wasOn: true, wantOn: false), .turnOff)
        // The web vault's weak threshold.
        XCTAssertEqual(AccountSecurityLogic.weakBits, 50)
    }

    func testCodesAndSecrets() {
        XCTAssertEqual(AccountSecurityLogic.cleanCode(" 123 456 "), "123456")
        XCTAssertEqual(AccountSecurityLogic.cleanCode("12-34-56"), "123456")
        XCTAssertTrue(AccountSecurityLogic.isTotpCode("123 456"))
        XCTAssertFalse(AccountSecurityLogic.isTotpCode("12345"))
        XCTAssertFalse(AccountSecurityLogic.isTotpCode("１２３４５６"), "ASCII digits only")
        XCTAssertEqual(AccountSecurityLogic.groupedSecret("JBSWY3DPEHPK3PXP"), "JBSW Y3DP EHPK 3PXP")
        XCTAssertEqual(AccountSecurityLogic.groupedSecret("ABCDE"), "ABCD E")
        XCTAssertEqual(AccountSecurityLogic.recoveryCodesText(["a1", "b2"], server: "https://pass.example.org"),
                       "PassAuth recovery codes\nhttps://pass.example.org\n\nEach code works once.\n\na1\nb2\n")
        XCTAssertNotNil(AccountSecurityLogic.authenticatorURL("otpauth://totp/PassAuth:a%40b.c?secret=X&issuer=PassAuth"))
        XCTAssertNil(AccountSecurityLogic.authenticatorURL("https://evil.example/otpauth"))
        XCTAssertNil(AccountSecurityLogic.authenticatorURL("otpauth://hotp/x?secret=X"))
    }

    func testStatusFromServer() throws {
        let j = try JSON.parse(#"{"email":"a@b.c","two_factor":["totp","email"],"recovery_codes_left":7,"email_enabled":true}"#)
        let s = TwoFactorStatus(json: j)
        XCTAssertTrue(s.totpOn && s.emailOn && s.anyOn && s.emailAvailable)
        XCTAssertEqual(s.recoveryCodesLeft, 7)
        XCTAssertFalse(s.isLast(.totp))
        XCTAssertTrue(TwoFactorStatus(providers: ["email"]).isLast(.email))
        XCTAssertFalse(TwoFactorStatus().anyOn)
    }

    func testSecurityKeysFromServer() throws {
        let j = try JSON.parse(#"{"two_factor":["passkey","recovery"],"recovery_codes_left":10,"passkeys":[{"id":"k1","name":"YubiKey","created_at":1762000000,"last_used_at":null},{"id":"k2","name":"Laptop","created_at":1762000100,"last_used_at":1762100000}]}"#)
        let s = TwoFactorStatus(json: j)
        XCTAssertEqual(s.securityKeys.map(\.id), ["k1", "k2"])
        XCTAssertNil(s.securityKeys[0].lastUsedAt)
        XCTAssertEqual(s.securityKeys[1].lastUsedAt, 1762100000)
        XCTAssertTrue(s.keysOn && s.anyOn)
        XCTAssertFalse(s.isLastKey(), "two keys left")
        XCTAssertTrue(TwoFactorStatus(providers: ["passkey"], securityKeys: [SecurityKeyInfo(id: "k1", name: "Key")]).isLastKey())
        XCTAssertFalse(TwoFactorStatus(providers: ["passkey", "totp"], securityKeys: [SecurityKeyInfo(id: "k1", name: "Key")]).isLastKey())
        XCTAssertTrue(TwoFactorStatus(json: try JSON.parse(#"{"two_factor":[]}"#)).securityKeys.isEmpty)
    }

    func testErrorMessages() {
        XCTAssertEqual(securityErrorMessage(ApiError(status: 429, code: "rate_limited", message: "too many requests")), "Too many attempts, try again later.")
        XCTAssertEqual(securityErrorMessage(ApiError(status: 400, code: "bad_request", message: "invalid code")), "That code isn't right. Check it and try again.")
        XCTAssertEqual(securityErrorMessage(UserError("Can't reach your PassAuth server. Check the server address and your connection.")),
                       "Can't reach your PassAuth server. Check the server address and your connection.")
    }
}

