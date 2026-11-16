import Foundation
import PassAuthCore
import PassAuthKit
import XCTest

/// A fake server for the new device's requests: answers in turn (pending when none is left),
/// every request recorded.
private actor FakeLoginServer: DeviceLoginTransport {
    enum Answer {
        case json(JSON)
        case error(Error)
    }

    private(set) var created: [JSON] = []
    private(set) var polls: [(id: String, code: String)] = []
    private var createAnswer: Answer = .json(["id": "3f6c1a7e-9b2d-4c1a-8f00-000000000001", "fingerprint_phrase": "server words", "expires_at": 1_000_900])
    private var pollAnswers: [Answer] = []

    func onCreate(_ a: Answer) { createAnswer = a }
    func queue(_ a: [Answer]) { pollAnswers += a }

    func create(_ body: JSON) async throws -> JSON {
        created.append(body)
        switch createAnswer {
        case .json(let j): return j
        case .error(let e): throw e
        }
    }

    func poll(id: String, accessCode: String) async throws -> JSON {
        polls.append((id, accessCode))
        guard !pollAnswers.isEmpty else { return ["status": "pending"] }
        switch pollAnswers.removeFirst() {
        case .json(let j): return j
        case .error(let e): throw e
        }
    }
}

/// A clock that only moves when the flow sleeps.
private final class FakeClock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Double
    private var slept: [Double] = []

    init(_ t: Double) { self.t = t }

    var now: Double { lock.withLock { t } }
    var sleeps: [Double] { lock.withLock { slept } }

    func sleep(_ s: Double) {
        lock.withLock {
            slept.append(s)
            t += s
        }
    }
}

/// An approving app's keys that just say what they were asked: the key's words are "words of
/// <key>", anything else is the core's `PhraseMismatch`.
private struct FakeApprovalCrypto: ApprovalCrypto {
    func approve(publicKey: String, requestId: String, phrase: String, secretKey: String?) throws -> LoginApproval {
        guard phrase == "words of \(publicKey)" else { throw CoreError.PhraseMismatch(message: "phrase_mismatch") }
        return LoginApproval(sealed: "sealed(\(publicKey),\(requestId),\(secretKey ?? "-"))", code: "123456")
    }
    func proof(challenge: String, requestId: String) throws -> String { "opened(\(challenge),\(requestId))" }
}

/// The words choices of a fake request: its own ("words of <key>") and two decoys.
private func fakeChoices(_ r: AuthRequest) -> [String] {
    ["decoy one of \(r.publicKey)", "words of \(r.publicKey)", "decoy two of \(r.publicKey)"]
}

@MainActor
private final class FakeSource: AuthRequestSource {
    var list: Result<[AuthRequest]?, Error> = .success([])
    /// The listing takes this long (to lock the app meanwhile).
    var delay: UInt64 = 0
    /// (request id, approved, the key it was sealed to, the words picked).
    var approvals: [(id: String, key: String, phrase: String)] = []
    var denials: [String] = []
    var answerError: Error?
    var denyError: Error?

    func listAuthRequests() async throws -> [AuthRequest]? {
        let answer = list
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        return try answer.get()
    }

    func approveAuthRequest(_ r: AuthRequest, phrase: String) async throws -> String {
        approvals.append((r.id, r.publicKey, phrase))
        if let answerError { throw answerError }
        return try FakeApprovalCrypto().approve(publicKey: r.publicKey, requestId: r.id, phrase: phrase, secretKey: nil).code
    }

    func denyAuthRequest(_ r: AuthRequest) async throws {
        denials.append(r.id)
        if let denyError { throw denyError }
    }
}

/// Sign in with another device: the new device's request and wait (`DeviceLoginFlow`), the
/// approving app's list, answer, queue and inbox, the wording, and the keys through the real core.
@MainActor
final class DeviceLoginTests: XCTestCase {
    private let requestId = "3f6c1a7e-9b2d-4c1a-8f00-000000000001"
    private let device: JSON = ["id": "dev-1", "name": "PassAuth for iOS (iPhone)", "kind": "mobile"]

    private func flow(_ server: FakeLoginServer, _ clock: FakeClock) -> DeviceLoginFlow {
        DeviceLoginFlow(transport: server, now: { clock.now }, sleep: { clock.sleep($0) })
    }

    private func request(_ id: String, created: Int64 = 1_000_000, expires: Int64 = 1_000_900, key: String = "PUB", ip: String? = "203.0.113.7", client: String? = "android/0.6.0") -> AuthRequest {
        AuthRequest(id: id, publicKey: key, challenge: "CH-\(id)", deviceName: "Pixel 9", deviceKind: "mobile", client: client, ip: ip, createdAt: created, expiresAt: expires)
    }

    // MARK: New device

    func testAccessCodeDelaysAndCountdown() throws {
        let a = try DeviceLogin.accessCode(), b = try DeviceLogin.accessCode()
        XCTAssertEqual(a.count, 43, "32 bytes in base64url without padding")
        XCTAssertTrue(a.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        XCTAssertNotEqual(a, b)
        XCTAssertEqual((0..<12).map { DeviceLogin.pollDelay(attempt: $0) }, [2, 2, 2, 3, 3, 4, 5, 6, 8, 10, 10, 10])
        XCTAssertEqual(DeviceLogin.countdown(expiresAt: 1_000_900, now: 1_000_001), "14:59")
        XCTAssertEqual(DeviceLogin.countdown(expiresAt: 1_000_900, now: 1_000_894.5), "0:06")
        XCTAssertEqual(DeviceLogin.countdown(expiresAt: 1_000_900, now: 1_001_000), "0:00")
        XCTAssertEqual(DeviceLogin.expiresIn(expiresAt: 1_000_900, now: 1_000_000), "Expires in 15:00")
        XCTAssertTrue(DeviceLogin.isRequestId(requestId))
        XCTAssertFalse(DeviceLogin.isRequestId("../account"))
        XCTAssertFalse(DeviceLogin.isRequestId(""))
        XCTAssertEqual(DeviceLogin.waitText(email: "a@example.com"),
                       "On a device where you're signed in as a@example.com, open PassAuth. When it asks which words this device shows, pick these:")
    }

    func testPollAnswers() {
        XCTAssertEqual(DeviceLogin.parsePoll(["status": "pending"]), .pending)
        XCTAssertEqual(DeviceLogin.parsePoll(["status": "who knows"]), .pending, "unknown: keep waiting until it expires")
        XCTAssertEqual(DeviceLogin.parsePoll(["status": "denied"]), .ended(message: DeviceLogin.denied))
        XCTAssertEqual(DeviceLogin.parsePoll(["status": "expired"]), .ended(message: DeviceLogin.expired))
        XCTAssertEqual(DeviceLogin.parsePoll(["status": "used"]), .ended(message: DeviceLogin.used))
        let session: JSON = ["status": "approved", "sealed_key": "S", "access_token": "A", "refresh_token": "R", "user_id": "u", "email": "a@example.com", "bundle": [:]]
        XCTAssertEqual(DeviceLogin.parsePoll(session), .approved(session: session))
        XCTAssertEqual(DeviceLogin.parsePoll(["status": "approved", "two_factor_required": true, "two_factor_token": "T", "providers": ["totp", "recovery"]]),
                       .twoFactor(token: "T", providers: ["totp", "recovery"]))
    }

    func testStartSendsTheRequestAndNeverTheServersWords() async throws {
        let server = FakeLoginServer(), clock = FakeClock(1_000_000)
        let started = try await flow(server, clock).start(email: "  a@example.com ", publicKey: "PUB", accessCode: "CODE", device: device, rememberToken: "REM")
        XCTAssertEqual(started, DeviceLoginFlow.Started(id: requestId, expiresAt: 1_000_900))
        let sent = await server.created
        XCTAssertEqual(sent, [["email": "a@example.com", "public_key": "PUB", "access_code": "CODE", "device_id": "dev-1",
                               "device_name": "PassAuth for iOS (iPhone)", "device_kind": "mobile", "remember_token": "REM"]])
        // No remember token: not sent at all.
        _ = try await flow(server, clock).start(email: "a@example.com", publicKey: "PUB", accessCode: "CODE", device: device, rememberToken: nil)
        let second = await server.created[1]
        XCTAssertNil(second["remember_token"])

        await server.onCreate(.error(ApiError(status: 403, code: "login_with_device_disabled", message: "off")))
        do {
            _ = try await flow(server, clock).start(email: "a@example.com", publicKey: "PUB", accessCode: "CODE", device: device, rememberToken: nil)
            XCTFail("disabled")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.disabled)
        }
        await server.onCreate(.json(["id": "../../account", "expires_at": 1]))
        do {
            _ = try await flow(server, clock).start(email: "a@example.com", publicKey: "PUB", accessCode: "CODE", device: device, rememberToken: nil)
            XCTFail("a malformed id never goes into a path")
        } catch let e as UserError {
            XCTAssertEqual(e.message, DeviceLogin.gone)
        }
    }

    func testWaitsWithGrowingDelaysUntilApproved() async throws {
        let server = FakeLoginServer(), clock = FakeClock(1_000_000)
        let session: JSON = ["status": "approved", "sealed_key": "S", "user_id": "u"]
        await server.queue([.json(["status": "pending"]), .json(["status": "pending"]), .json(["status": "pending"]), .json(["status": "pending"]), .json(session)])
        let end = try await flow(server, clock).wait(id: requestId, accessCode: "CODE", expiresAt: 1_000_900)
        XCTAssertEqual(end, .approved(session: session))
        XCTAssertEqual(clock.sleeps, [2, 2, 2, 3, 3])
        let polls = await server.polls
        XCTAssertEqual(polls.count, 5)
        XCTAssertTrue(polls.allSatisfy { $0.id == requestId && $0.code == "CODE" })
    }

    func testTwoStepAndTheWaysAWaitEnds() async throws {
        let cases: [(FakeLoginServer.Answer, DeviceLoginPoll)] = [
            (.json(["status": "approved", "two_factor_required": true, "two_factor_token": "T", "providers": ["email"]]), .twoFactor(token: "T", providers: ["email"])),
            (.json(["status": "denied"]), .ended(message: DeviceLogin.denied)),
            (.json(["status": "expired"]), .ended(message: DeviceLogin.expired)),
            (.json(["status": "used"]), .ended(message: DeviceLogin.used)),
            (.error(ApiError(status: 404, code: "not_found", message: "not found")), .ended(message: DeviceLogin.gone)),
            (.error(ApiError(status: 403, code: "login_with_device_disabled", message: "off")), .ended(message: DeviceLogin.disabled)),
        ]
        for (answer, want) in cases {
            let server = FakeLoginServer(), clock = FakeClock(1_000_000)
            await server.queue([answer])
            let end = try await flow(server, clock).wait(id: requestId, accessCode: "CODE", expiresAt: 1_000_900)
            XCTAssertEqual(end, want)
        }
    }

    func testRateLimitsServerErrorsAndOfflineKeepWaiting() async throws {
        let server = FakeLoginServer(), clock = FakeClock(1_000_000)
        await server.queue([
            .error(ApiError(status: 429, code: "rate_limited", message: "slow down", retryAfter: 7)),
            .error(ApiError(status: 429, code: "rate_limited", message: "slow down")),
            .error(ApiError(status: 502, code: "error", message: "bad gateway")),
            .error(UserError("Can't reach your PassAuth server. Check the server address and your connection.")),
            .json(["status": "denied"]),
        ])
        let end = try await flow(server, clock).wait(id: requestId, accessCode: "CODE", expiresAt: 1_000_900)
        XCTAssertEqual(end, .ended(message: DeviceLogin.denied))
        XCTAssertEqual(clock.sleeps, [2, 7, 2, 10, 2, 3, 3], "Retry-After, else 10 s; then the next delay")
        // Anything else (a disabled account, …) ends the wait as the error it is.
        let other = FakeLoginServer()
        await other.queue([.error(ApiError(status: 403, code: "account_disabled", message: "disabled"))])
        do {
            _ = try await flow(other, FakeClock(1_000_000)).wait(id: requestId, accessCode: "CODE", expiresAt: 1_000_900)
            XCTFail("account_disabled")
        } catch let e as ApiError {
            XCTAssertEqual(e.code, "account_disabled")
        }
    }

    func testGivesUpPastTheExpiryByTheClock() async throws {
        let server = FakeLoginServer(), clock = FakeClock(1_000_000)
        let end = try await flow(server, clock).wait(id: requestId, accessCode: "CODE", expiresAt: 1_000_003)
        XCTAssertEqual(end, .ended(message: DeviceLogin.expired))
        let polls = await server.polls.count
        XCTAssertEqual(polls, 11, "polled at +2 … +55; at +65 it is past expires_at + a minute")
    }

    /// Client review F7: the server's `expires_at` never keeps the new device waiting longer than
    /// the 15 minutes a request lives (plus a minute's grace), from when it was made.
    func testDeadlineIsCappedAtFifteenMinutes() async throws {
        XCTAssertEqual(DeviceLogin.deadline(serverExpiresAt: 1_000_600, requestedAt: 1_000_000), 1_000_600, "within 15 minutes: the server's")
        XCTAssertEqual(DeviceLogin.deadline(serverExpiresAt: 1_000_900, requestedAt: 1_000_000.7), 1_000_900)
        XCTAssertEqual(DeviceLogin.deadline(serverExpiresAt: 1_000_000 + 10 * 365 * 86_400, requestedAt: 1_000_000), 1_000_900, "years ahead: 15 minutes")
        XCTAssertEqual(DeviceLogin.deadline(serverExpiresAt: 999_000, requestedAt: 1_000_000), 1_000_900, "already past (clock skew): 15 minutes")
        XCTAssertEqual(DeviceLogin.deadline(serverExpiresAt: nil, requestedAt: 1_000_000), 1_000_900, "not given: 15 minutes")

        // `start` keeps the capped deadline (the countdown shows it).
        let server = FakeLoginServer(), clock = FakeClock(1_000_000)
        await server.onCreate(.json(["id": .string(requestId), "expires_at": .int(1_000_000 + 10 * 365 * 86_400)]))
        let started = try await flow(server, clock).start(email: "a@example.com", publicKey: "PUB", accessCode: "CODE", device: device, rememberToken: nil)
        XCTAssertEqual(started.expiresAt, 1_000_900)

        // `wait` gives up by its own clock too, whatever it is handed: 15 minutes + 1 from now.
        let forever = try await flow(server, clock).wait(id: requestId, accessCode: "CODE", expiresAt: Int64.max / 2)
        XCTAssertEqual(forever, .ended(message: DeviceLogin.expired))
        XCTAssertLessThanOrEqual(clock.now, 1_000_000 + 16 * 60 + 10, "stopped within one poll after 16 minutes")
        XCTAssertGreaterThan(clock.now, 1_000_000 + 16 * 60)
    }

    func testCancellingStopsTheWait() async throws {
        let server = FakeLoginServer()
        let f = DeviceLoginFlow(transport: server, sleep: { _ in try await Task.sleep(nanoseconds: 20_000_000) })
        let task = Task { try await f.wait(id: requestId, accessCode: "CODE", expiresAt: Int64(Date().timeIntervalSince1970) + 900) }
        try await Task.sleep(nanoseconds: 70_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("cancelled")
        } catch is CancellationError {}
    }

    // MARK: Keys (the real core)

    /// Number matching and the code (core M1, client review F1/F6): the approving app offers
    /// three sets of words, one the key's own; only that one approves, and the approval gives a
    /// code without which the new device can't unlock or read the Secret Key.
    func testApprovalKeysThroughTheCore() throws {
        let created = try createAccount(accountId: try newId(), password: "correct horse battery staple", withSecretKey: true)
        let accountId = try JSON.parse(created.bundleJson).str("account_id")
        let key = try LoginRequestKey.generate()
        XCTAssertEqual(try loginPhrase(publicKey: key.publicKey()), key.phrase())
        XCTAssertEqual(key.phrase().split(separator: " ").count, 5)
        let r = request(requestId, key: key.publicKey())

        // Three different phrases of five words, exactly one the key's own, the decoys sharing
        // no word with it at the same place.
        let choices = DeviceApprovals.choices(r)
        XCTAssertEqual(choices.count, 3)
        XCTAssertEqual(Set(choices).count, 3)
        XCTAssertEqual(choices.filter { $0 == key.phrase() }.count, 1, "worked out from the key, never taken from the server")
        for decoy in choices where decoy != key.phrase() {
            XCTAssertEqual(decoy.split(separator: " ").count, 5)
            XCTAssertTrue(zip(decoy.split(separator: " "), key.phrase().split(separator: " ")).allSatisfy { $0 != $1 })
        }
        XCTAssertEqual(DeviceApprovals.choices(request(requestId, key: "not a key")), [], "a malformed key can't be checked")
        XCTAssertEqual(DeviceApprovals.choices(r) { _, _ in ["a", "a", "b"] }, [], "anything but three different phrases: can't be checked")
        XCTAssertEqual(DeviceApprovals.choices(r) { _, _ in ["a", "b"] }, [])

        let crypto = AccountApprovalCrypto(account: created.account)
        // A decoy: refused before anything is sealed.
        let decoy = try XCTUnwrap(choices.first { $0 != key.phrase() })
        XCTAssertThrowsError(try crypto.approve(publicKey: key.publicKey(), requestId: requestId, phrase: decoy, secretKey: created.secretKey)) { e in
            XCTAssertTrue(DeviceApprovals.isPhraseMismatch(e))
            XCTAssertEqual(errorMessage(e), DeviceApprovals.mismatch)
        }
        // A challenge the account's keys can't open (not sealed to it by the server): no approval.
        XCTAssertThrowsError(try DeviceApprovals.approval(r, phrase: key.phrase(), crypto: crypto, secretKey: created.secretKey))

        let approval = try crypto.approve(publicKey: key.publicKey(), requestId: requestId, phrase: key.phrase(), secretKey: created.secretKey)
        XCTAssertFalse(approval.sealed.isEmpty)
        XCTAssertEqual(approval.code.count, 6)
        XCTAssertTrue(approval.code.allSatisfy { $0.isASCII && $0.isNumber })

        // The new device: nothing usable before the code.
        let approved = try key.open(sealed: approval.sealed, accountId: accountId, requestId: requestId)
        XCTAssertEqual(approved.accountId(), accountId)
        XCTAssertFalse(approved.isConfirmed())
        XCTAssertThrowsError(try approved.secretKey()) { e in
            guard case .NotConfirmed? = e as? CoreError else { return XCTFail("\(e)") }
        }
        XCTAssertThrowsError(try approved.unlock(bundleJson: created.bundleJson)) { e in
            guard case .NotConfirmed? = e as? CoreError else { return XCTFail("\(e)") }
        }
        let wrong = approval.code == "000000" ? "111111" : "000000"
        XCTAssertThrowsError(try approved.confirm(code: wrong)) { e in
            guard case .WrongCode? = e as? CoreError else { return XCTFail("\(e)") }
        }
        XCTAssertEqual(approved.attemptsLeft(), 2)
        XCTAssertThrowsError(try approved.confirm(code: "12")) { e in
            guard case .Invalid? = e as? CoreError else { return XCTFail("\(e)") }
        }
        XCTAssertEqual(approved.attemptsLeft(), 2, "not 6 digits: not counted")
        try approved.confirm(code: "\(approval.code.prefix(3)) \(approval.code.suffix(3))")
        XCTAssertTrue(approved.isConfirmed())
        XCTAssertEqual(try approved.secretKey(), created.secretKey)
        XCTAssertEqual(try approved.unlock(bundleJson: created.bundleJson).publicKey(), created.account.publicKey())

        XCTAssertThrowsError(try key.open(sealed: approval.sealed, accountId: accountId, requestId: "another-request"))
        XCTAssertThrowsError(try key.open(sealed: approval.sealed, accountId: try newId(), requestId: requestId))
        XCTAssertThrowsError(try LoginRequestKey.generate().open(sealed: approval.sealed, accountId: accountId, requestId: requestId))

        // Three wrong codes: refused for good, the right one too.
        let again = try key.open(sealed: approval.sealed, accountId: accountId, requestId: requestId)
        for left in [2, 1] {
            XCTAssertThrowsError(try again.confirm(code: wrong))
            XCTAssertEqual(Int(again.attemptsLeft()), left)
        }
        XCTAssertThrowsError(try again.confirm(code: wrong)) { e in
            guard case .TooManyWrongCodes? = e as? CoreError else { return XCTFail("\(e)") }
        }
        XCTAssertThrowsError(try again.confirm(code: approval.code))
        XCTAssertThrowsError(try again.secretKey())

        // Without a Secret Key kept on the approving device, none comes along.
        let plain = try crypto.approve(publicKey: key.publicKey(), requestId: requestId, phrase: key.phrase(), secretKey: nil)
        let opened = try key.open(sealed: plain.sealed, accountId: accountId, requestId: requestId)
        try opened.confirm(code: plain.code)
        XCTAssertNil(try opened.secretKey())
    }

    // MARK: New device: what is kept

    /// Client review F7: a Secret Key that came with an approval is kept only for the email
    /// typed on this device, and never replaces another one kept for it.
    func testSecretKeyIsKeptOnlyForTheTypedEmail() {
        XCTAssertTrue(DeviceLogin.keepsSecretKey(typedEmail: " A@Example.com ", sessionEmail: "a@example.com", stored: nil))
        XCTAssertTrue(DeviceLogin.keepsSecretKey(typedEmail: "a@example.com", sessionEmail: "", stored: nil), "the answer doesn't name the account")
        XCTAssertFalse(DeviceLogin.keepsSecretKey(typedEmail: "a@example.com", sessionEmail: "b@example.com", stored: nil), "another account than the one typed")
        XCTAssertFalse(DeviceLogin.keepsSecretKey(typedEmail: "a@example.com", sessionEmail: "a@example.com", stored: "PA1-KEPT"), "the one kept stays")
        XCTAssertFalse(DeviceLogin.keepsSecretKey(typedEmail: "  ", sessionEmail: "a@example.com", stored: nil))
        XCTAssertEqual(DeviceLogin.wrongCode(left: 2), "That code doesn't match. 2 tries left.")
        XCTAssertEqual(DeviceLogin.wrongCode(left: 1), "That code doesn't match. 1 try left.")
        XCTAssertEqual(DeviceLogin.codePrompt, "Enter the 6-digit code shown on your other device.")
        XCTAssertEqual(DeviceLogin.tooManyCodes,
                       "Too many wrong codes, so this sign-in was stopped. If you didn't approve it on your other device, change your master password.")
        XCTAssertEqual(errorMessage(DeviceLoginStopped(DeviceLogin.tooManyCodes)), DeviceLogin.tooManyCodes)
    }

    // MARK: Approving app

    func testListReadLenientlyNewestFirst() throws {
        let j = try JSON.parse(#"""
        {"requests":[
          {"id":"a1","public_key":"K1","challenge":"C1","device_name":"Pixel 9","device_kind":"mobile","client":"android/0.6.0","ip":"203.0.113.7","created_at":1000000,"expires_at":1000900,"fingerprint_phrase":"never shown"},
          {"id":"b2","public_key":"K2","challenge":"C2","device_name":"","device_kind":"web","client":null,"ip":null,"created_at":1000100,"expires_at":1001000},
          {"id":"old","public_key":"K3","challenge":"C3","created_at":999000,"expires_at":999900},
          {"id":"../x","public_key":"K4","challenge":"C4","expires_at":1001000},
          {"id":"nokey","challenge":"C5","expires_at":1001000},
          {"id":"nochallenge","public_key":"K6","expires_at":1001000},
          "junk"
        ]}
        """#)
        let list = DeviceApprovals.parse(j, now: 1_000_200)
        XCTAssertEqual(list.map(\.id), ["b2", "a1"], "newest first; expired, malformed and incomplete ones left out")
        XCTAssertEqual(list[1], AuthRequest(id: "a1", publicKey: "K1", challenge: "C1", deviceName: "Pixel 9", deviceKind: "mobile",
                                            client: "android/0.6.0", ip: "203.0.113.7", createdAt: 1_000_000, expiresAt: 1_000_900))
        XCTAssertNil(list[0].client)
        XCTAssertNil(list[0].ip)
        XCTAssertEqual(DeviceApprovals.parse(nil, now: 0), [])
        XCTAssertEqual(DeviceApprovals.parse(["requests": "nope"], now: 0), [])
    }

    func testSheetWording() {
        let r = request("a1")
        XCTAssertEqual(DeviceApprovals.body(email: "alex@example.com"), "A new device wants to sign in to alex@example.com.")
        XCTAssertEqual(DeviceApprovals.deviceLabel, "Device (as it calls itself)")
        XCTAssertEqual(DeviceApprovals.deviceName(r), "Pixel 9")
        XCTAssertEqual(DeviceApprovals.deviceName(AuthRequest(id: "a", publicKey: "k", challenge: "c", deviceName: " \u{202E} ", deviceKind: "web", client: nil, ip: nil, createdAt: 0, expiresAt: 1)),
                       "Not given")
        XCTAssertEqual(DeviceApprovals.app(r), "Android app 0.6.0")
        XCTAssertEqual(DeviceApprovals.app(request("a2", client: nil)), "Mobile app", "the device kind when the app is unknown")
        XCTAssertEqual(DeviceApprovals.ip(r), "203.0.113.7")
        XCTAssertNil(DeviceApprovals.ip(request("a3", ip: nil)))
        XCTAssertEqual(DeviceApprovals.question, "Which words does the new device show?")
        XCTAssertEqual(DeviceApprovals.noneOfThese, "None of these")
        XCTAssertEqual(DeviceApprovals.notNow, "Not now")
        XCTAssertEqual(DeviceApprovals.codeHeading, "Enter this code on the new device")
        XCTAssertEqual(DeviceApprovals.groupedCode("123456"), "123 456")
        XCTAssertEqual(DeviceApprovals.groupedCode("12345"), "12345")
        XCTAssertEqual(DeviceApprovals.mismatch, "Those aren't the words for this request, so it was denied.")
        XCTAssertEqual(DeviceApprovals.changed, "This request changed, so it was closed. If you're signing in on a new device, start again there.")
        XCTAssertEqual(DeviceApprovals.choiceCount, 3)
        XCTAssertEqual(DeviceApprovals.armDelay, 1)
        XCTAssertEqual(DeviceApprovals.requested(createdAt: 1_000_000, now: 1_000_030), "Just now")
        XCTAssertEqual(DeviceApprovals.requested(createdAt: 1_000_000, now: 1_000_065), "1 minute ago")
        XCTAssertEqual(DeviceApprovals.requested(createdAt: 1_000_000, now: 1_000_190), "3 minutes ago")
        XCTAssertEqual(DeviceApprovals.requested(createdAt: 1_000_000, now: 1_007_300), "2 hours ago")
        XCTAssertEqual(DeviceApprovals.errorMessage(ApiError(status: 409, code: "conflict", message: "answered")), "This request was already answered on another device.")
        XCTAssertEqual(DeviceApprovals.errorMessage(ApiError(status: 400, code: "expired", message: "expired")), "This request expired.")
        XCTAssertEqual(DeviceApprovals.errorMessage(ApiError(status: 404, code: "not_found", message: "gone")), "This request is no longer there.")
        XCTAssertNil(DeviceApprovals.errorMessage(ApiError(status: 400, code: "bad_request", message: "bad")))
        XCTAssertNil(DeviceApprovals.errorMessage(UserError("offline")))
    }

    /// Client review F6: what a device claims about itself is shown without control or format
    /// characters (bidi overrides and isolates, zero-width marks, BOM) and capped at 64.
    func testClaimedTextIsCleaned() {
        let spoof = "Your \u{202E}kooBcaM\u{202C} \u{2066}PassAuth\u{2069}\u{200B}\u{FEFF} check\u{200E}\u{200F}"
        XCTAssertEqual(ShownText.clean(spoof, limit: 64), "Your kooBcaM PassAuth check")
        XCTAssertEqual(ShownText.clean("Alex's\n\n\tiPhone\u{0}\u{7}\u{1B}[31m", limit: 64), "Alex's iPhone[31m")
        XCTAssertEqual(ShownText.clean("  \u{2028} x \u{2029}  ", limit: 64), "x")
        let long = String(repeating: "A", count: 100)
        XCTAssertEqual(ShownText.clean(long, limit: 64), String(repeating: "A", count: 64) + "…")
        XCTAssertEqual(ShownText.clean(String(repeating: "A", count: 64), limit: 64), String(repeating: "A", count: 64), "exactly 64: no cut")
        let stacked = "e" + String(repeating: "\u{0301}", count: 200)
        XCTAssertEqual(ShownText.clean(stacked, limit: 64).unicodeScalars.count, 65, "combining marks count, so a stack can't grow without end")
        XCTAssertEqual(ShownText.clean("Bücher café 日本", limit: 64), "Bücher café 日本")

        let r = AuthRequest(id: "a", publicKey: "k", challenge: "c", deviceName: spoof + String(repeating: "x", count: 80),
                            deviceKind: "mobile", client: "evil\u{202E}app/1.0", ip: "203.0.113.7\u{202E}", createdAt: 0, expiresAt: 1)
        XCTAssertEqual(DeviceApprovals.deviceName(r).unicodeScalars.count, 65)
        XCTAssertFalse(DeviceApprovals.deviceName(r).unicodeScalars.contains { $0.properties.generalCategory == .format })
        XCTAssertFalse(DeviceApprovals.app(r).unicodeScalars.contains { $0.properties.generalCategory == .format })
        XCTAssertEqual(DeviceApprovals.ip(r), "203.0.113.7")
    }

    func testApprovalBodies() throws {
        let r = request("a1", key: "PUB")
        let answer = try DeviceApprovals.approval(r, phrase: "words of PUB", crypto: FakeApprovalCrypto(), secretKey: "PA1-SK")
        XCTAssertEqual(answer.body, ["approve": true, "sealed_key": "sealed(PUB,a1,PA1-SK)", "proof": "opened(CH-a1,a1)"])
        XCTAssertEqual(answer.code, "123456")
        XCTAssertEqual(try DeviceApprovals.approval(r, phrase: "words of PUB", crypto: FakeApprovalCrypto(), secretKey: nil).body,
                       ["approve": true, "sealed_key": "sealed(PUB,a1,-)", "proof": "opened(CH-a1,a1)"])
        XCTAssertThrowsError(try DeviceApprovals.approval(r, phrase: "decoy one of PUB", crypto: FakeApprovalCrypto(), secretKey: nil)) { e in
            XCTAssertTrue(DeviceApprovals.isPhraseMismatch(e), "picked words that aren't the key's: nothing to send")
        }
        XCTAssertEqual(DeviceApprovals.denyBody, ["approve": false], "denying needs no keys")
    }

    /// Client review F1: the shown request is frozen; a listing that changes its key or
    /// challenge, or drops it, closes it while the user is choosing; newer requests wait.
    func testQueueFreezesQueuesAndClosesOnChange() {
        var q = ApprovalQueue()
        let now = 1_000_200.0
        q.listed([request("b", created: 1_000_100, key: "K-B"), request("a", key: "K-A")], now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.request.id, "b", "the newest first")
        XCTAssertEqual(q.shown?.choices, fakeChoices(request("b", key: "K-B")))
        XCTAssertEqual(q.shown?.phase, .choosing)
        XCTAssertEqual(q.waiting.map(\.id), ["a"])

        // A newer request never takes the shown one's place.
        q.listed([request("c", created: 1_000_150, key: "K-C"), request("b", created: 1_000_100, key: "K-B"), request("a", key: "K-A")], now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.request.id, "b")
        XCTAssertEqual(q.waiting.map(\.id), ["c", "a"])

        // The same request with another name or app: the frozen copy is kept as it was.
        var renamed = request("b", created: 1_000_100, key: "K-B")
        renamed = AuthRequest(id: "b", publicKey: "K-B", challenge: renamed.challenge, deviceName: "Your MacBook", deviceKind: "desktop", client: nil, ip: nil, createdAt: 1_000_100, expiresAt: 1_000_900)
        q.listed([renamed, request("a", key: "K-A")], now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.request.deviceName, "Pixel 9")
        XCTAssertEqual(q.shown?.phase, .choosing)

        // Its key swapped in place: closed, never answered from here.
        q.listed([request("b", created: 1_000_100, key: "K-SERVER"), request("a", key: "K-A")], now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.phase, .closed(DeviceApprovals.changed))
        XCTAssertEqual(q.shown?.request.publicKey, "K-B")
        XCTAssertNil(q.send("b"), "a closed request can't be answered")
        q.close("b", now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.request.id, "a", "the next one only after the current one is handled")
        q.listed([request("b", created: 1_000_100, key: "K-SERVER"), request("a", key: "K-A")], now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.request.id, "a")
        XCTAssertEqual(q.waiting.map(\.id), [], "a closed request isn't shown again in this run")

        // Its challenge changed: closed too.
        let other = AuthRequest(id: "a", publicKey: "K-A", challenge: "another", deviceName: "Pixel 9", deviceKind: "mobile", client: nil, ip: nil, createdAt: 1_000_000, expiresAt: 1_000_900)
        q.listed([other], now: now, choices: fakeChoices)
        XCTAssertEqual(q.shown?.phase, .closed(DeviceApprovals.changed))

        // Dropped from the listing: closed (said as expired once past its time).
        var gone = ApprovalQueue()
        gone.listed([request("x", key: "K-X")], now: now, choices: fakeChoices)
        gone.listed([], now: now, choices: fakeChoices)
        XCTAssertEqual(gone.shown?.phase, .closed(DeviceApprovals.changed))
        var expired = ApprovalQueue()
        expired.listed([request("y", expires: 1_000_300, key: "K-Y")], now: now, choices: fakeChoices)
        expired.listed([], now: 1_000_400, choices: fakeChoices)
        XCTAssertEqual(expired.shown?.phase, .closed(DeviceApprovals.expiredHere))

        // Once the answer is sent, listings don't touch it (an approved request isn't listed any more).
        var sent = ApprovalQueue()
        sent.listed([request("z", key: "K-Z")], now: now, choices: fakeChoices)
        XCTAssertNil(sent.send("other"), "only the shown request")
        XCTAssertEqual(sent.send("z")?.publicKey, "K-Z")
        sent.listed([], now: now, choices: fakeChoices)
        XCTAssertEqual(sent.shown?.phase, .sending)
        sent.close("z", now: now, choices: fakeChoices)
        XCTAssertEqual(sent.shown?.id, "z", "not closed while the answer is on its way")
        sent.answered("z", .code("123456"))
        sent.listed([request("n", key: "K-N")], now: now, choices: fakeChoices)
        XCTAssertEqual(sent.shown?.phase, .code("123456"), "the code stays until Done")
        sent.answeredElsewhere("z", now: now, choices: fakeChoices)
        XCTAssertEqual(sent.shown?.phase, .code("123456"), "the server tells this device about its own answer too")
        sent.close("z", now: now, choices: fakeChoices)
        XCTAssertEqual(sent.shown?.id, "n")

        // Answered on another device while being decided: closed; a waiting one is dropped.
        var elsewhere = ApprovalQueue()
        elsewhere.listed([request("p", created: 1_000_100, key: "K-P"), request("q", key: "K-Q"), request("r", created: 999_000, key: "K-R")], now: now, choices: fakeChoices)
        elsewhere.answeredElsewhere("q", now: now, choices: fakeChoices)
        XCTAssertEqual(elsewhere.waiting.map(\.id), ["r"])
        elsewhere.answeredElsewhere("p", now: now, choices: fakeChoices)
        XCTAssertEqual(elsewhere.shown?.id, "r")

        // Expired while waiting: never shown.
        var stale = ApprovalQueue()
        stale.listed([request("s", expires: 1_000_250, key: "K-S")], now: 1_000_300, choices: fakeChoices)
        XCTAssertNil(stale.shown)
        q.clear()
        XCTAssertNil(q.shown)
        XCTAssertTrue(q.waiting.isEmpty)
    }

    /// The server seals a request's challenge anew for every listing: another ciphertext with
    /// the same value inside is the same request; another value (or key) closes it.
    func testResealedChallengeIsTheSameRequest() {
        func listed(_ challenge: String, proof: String?, key: String = "K") -> AuthRequest {
            AuthRequest(id: "r", publicKey: key, challenge: challenge, deviceName: "Pixel 9", deviceKind: "mobile", client: nil, ip: nil,
                        createdAt: 1_000_000, expiresAt: 1_000_900, challengeProof: proof)
        }
        XCTAssertTrue(DeviceApprovals.sameRequest(listed("sealed-1", proof: "P"), listed("sealed-2", proof: "P")))
        XCTAssertFalse(DeviceApprovals.sameRequest(listed("sealed-1", proof: "P"), listed("sealed-2", proof: "Q")))
        XCTAssertFalse(DeviceApprovals.sameRequest(listed("sealed-1", proof: "P"), listed("sealed-2", proof: nil)), "no longer opens")
        XCTAssertFalse(DeviceApprovals.sameRequest(listed("sealed-1", proof: "P"), listed("sealed-1", proof: "P", key: "K2")), "another key")
        XCTAssertTrue(DeviceApprovals.sameRequest(listed("c", proof: nil), listed("c", proof: nil)), "unopened: compared as listed")
        XCTAssertFalse(DeviceApprovals.sameRequest(listed("c", proof: nil), listed("d", proof: nil)))
        XCTAssertEqual(listed("c", proof: nil).withChallengeProof("P").challengeProof, "P")

        var q = ApprovalQueue()
        q.listed([listed("sealed-1", proof: "P")], now: 1_000_200, choices: fakeChoices)
        q.listed([listed("sealed-2", proof: "P")], now: 1_000_200, choices: fakeChoices)
        XCTAssertEqual(q.shown?.phase, .choosing, "resealed: still open")
        XCTAssertEqual(q.shown?.request.challenge, "sealed-1", "the frozen copy is kept")
        q.listed([listed("sealed-3", proof: "OTHER")], now: 1_000_200, choices: fakeChoices)
        XCTAssertEqual(q.shown?.phase, .closed(DeviceApprovals.changed))
    }

    func testInboxAnswersTheFrozenRequest() async {
        let source = FakeSource()
        let inbox = AuthRequestInbox(source: source, now: { 1_000_200 }, choices: fakeChoices)
        source.list = .success([request("b", created: 1_000_100, key: "K1"), request("a", key: "K-A")])
        await inbox.refresh()
        XCTAssertEqual(inbox.shown?.id, "b")
        // A failed listing keeps what is shown.
        source.list = .failure(ApiError(status: 502, code: "error", message: "bad gateway"))
        await inbox.refresh()
        XCTAssertEqual(inbox.shown?.id, "b")

        // Picked the right words: sealed to the frozen key, the code on the sheet until Done.
        await inbox.choose("words of K1", for: "b")
        XCTAssertEqual(source.approvals.map(\.key), ["K1"])
        XCTAssertEqual(inbox.shown?.phase, .code("123456"))
        source.list = .success([request("a", key: "K-A")])
        await inbox.refresh()
        XCTAssertEqual(inbox.shown?.id, "b", "the code stays")
        inbox.close("b")
        XCTAssertEqual(inbox.shown?.id, "a")

        // Words that aren't the request's: denied on the server, and the sheet says so.
        await inbox.choose("decoy one of K-A", for: "a")
        XCTAssertEqual(source.denials, ["a"])
        XCTAssertEqual(inbox.shown?.phase, .closed(DeviceApprovals.mismatch))
        inbox.close("a")
        XCTAssertNil(inbox.shown)

        // "None of these": denied, the sheet closes, the user is told.
        source.list = .success([request("c", key: "K-C")])
        await inbox.refresh()
        let notice = await inbox.deny("c")
        XCTAssertEqual(notice, DeviceApprovals.denied)
        XCTAssertEqual(source.denials, ["a", "c"])
        XCTAssertNil(inbox.shown)

        // A server that refuses the answer: the sheet says why.
        source.list = .success([request("d", key: "K-D")])
        await inbox.refresh()
        source.answerError = ApiError(status: 409, code: "conflict", message: "answered")
        await inbox.choose("words of K-D", for: "d")
        XCTAssertEqual(inbox.shown?.phase, .closed("This request was already answered on another device."))
        inbox.close("d")

        // The frozen challenge doesn't open with the account's key: not approved, the sheet says so.
        source.list = .success([request("u", key: "K-U")])
        await inbox.refresh()
        source.answerError = CoreError.DecryptFailed(message: "decrypt_failed")
        await inbox.choose("words of K-U", for: "u")
        XCTAssertEqual(inbox.shown?.phase, .closed(DeviceApprovals.unverifiable))
        XCTAssertEqual(source.denials, ["a", "c"], "not denied: it may be the server's doing")
        inbox.close("u")

        // Actions for another request than the shown one do nothing.
        source.answerError = nil
        source.list = .success([request("e", key: "K-E")])
        await inbox.refresh()
        await inbox.choose("words of K-E", for: "d")
        inbox.close("d")
        XCTAssertEqual(inbox.shown?.id, "e")
        XCTAssertEqual(inbox.shown?.phase, .choosing)

        // Nothing to ask (locked, no feature) empties it.
        source.list = .success(nil)
        await inbox.refresh()
        XCTAssertNil(inbox.shown)
        // Locked meanwhile: a listing that started before is dropped.
        source.list = .success([request("z", key: "K-Z")])
        source.delay = 100_000_000
        let late = Task { await inbox.refresh() }
        try? await Task.sleep(nanoseconds: 20_000_000)
        inbox.clear()
        await late.value
        XCTAssertNil(inbox.shown, "the listing from before the lock isn't shown")
        source.delay = 0
        await inbox.refresh()
        XCTAssertEqual(inbox.shown?.id, "z")
    }

    // MARK: Live sync

    func testLiveSyncMessagesForSignInRequests() {
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"auth_request","id":"r1"}"#), .authRequest(id: "r1"))
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"auth_request_answered","id":"r1"}"#), .authRequestAnswered(id: "r1"))
        XCTAssertNil(LiveSyncProtocol.parse(#"{"type":"auth_request"}"#))
        XCTAssertNil(LiveSyncProtocol.parse(#"{"type":"auth_request_answered","id":7}"#))
        XCTAssertEqual(LiveSyncProtocol.action(.authRequest(id: "r1"), have: nil), .listAuthRequests)
        XCTAssertEqual(LiveSyncProtocol.action(.authRequestAnswered(id: "r1"), have: nil), .authRequestAnswered("r1"))
        // The server now requires two-step login first: live sync stops (no reconnect loop).
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"two_step_required"}"#), .twoStepRequired)
        XCTAssertEqual(LiveSyncProtocol.action(.twoStepRequired, have: nil), .twoStepRequired)
        XCTAssertTrue(LiveSyncProtocol.closedForTwoStep(code: 1008, reason: Data("two_step_required".utf8)))
        XCTAssertFalse(LiveSyncProtocol.closedForTwoStep(code: 1008, reason: Data("other".utf8)))
        XCTAssertFalse(LiveSyncProtocol.closedForTwoStep(code: 1000, reason: Data("two_step_required".utf8)))
        XCTAssertFalse(LiveSyncProtocol.closedForTwoStep(code: 1008, reason: nil))
    }
}
