import Foundation
@testable import PassAuth
import PassAuthCore
import PassAuthKit
import XCTest

/// Password health (Shared/PasswordHealth.swift), the same cases as the web vault's
/// `health.test.ts`: the weak threshold, reuse groups, what's left out, range answers, the breach
/// check's requests, limits and failures, and the session dropping everything when the vault closes.
@MainActor
final class PasswordHealthTests: XCTestCase {
    // MARK: Helpers

    private var nextId = 0

    private func login(_ password: String, name: String? = nil, deleted: Int64? = nil) -> Entry {
        nextId += 1
        let id = "item-\(nextId)"
        return Entry(id: id, item: Item(name: name ?? "Login \(nextId)", login: Login(password: password)), vaultId: "v1", revision: 1,
                     enc: EncryptedItem(id: id, vaultId: "v1", key: "", data: ""), deletedAt: deleted)
    }

    /// Strength estimate stub: bits per password, 100 for anything not listed.
    private func bits(_ table: [String: Double]) -> (String) -> Double { { table[$0] ?? 100 } }

    /// A 40-character uppercase hex hash from a 5-character prefix and a suffix seed.
    nonisolated private static func hash(_ prefix: String, _ seed: String) -> String {
        String((prefix + String(repeating: seed, count: 35)).prefix(40)).uppercased()
    }

    /// Digest stub: fixed hashes per password, so tests choose which passwords share a prefix.
    nonisolated private static func digest(_ table: [String: String]) -> @Sendable (String) -> String {
        { table[$0] ?? "0000000000000000000000000000000000000000" }
    }

    /// `count` padding lines (count 0), as Have I Been Pwned adds them.
    nonisolated private static func padding(_ count: Int, seed: Int = 0) -> [String] {
        (0..<count).map { i in
            let hex = String(seed * 1000 + i, radix: 16, uppercase: true)
            return String(repeating: "F", count: 35 - hex.count) + hex + ":0"
        }
    }

    private func ids(_ entries: [Entry]) -> [String] { entries.map(\.id) }

    // MARK: Weak

    func testOneThresholdOf50Bits() {
        XCTAssertEqual(PasswordHealth.weakBits, 50)
        XCTAssertEqual(PasswordHealth.weakBits, AccountSecurityLogic.weakBits)
        XCTAssertTrue(PasswordHealth.isWeak("short") { _ in 49.99 })
        XCTAssertFalse(PasswordHealth.isWeak("longer") { _ in 50 })
        XCTAssertFalse(PasswordHealth.isWeak("longest") { _ in 80 })
    }

    func testEmptyPasswordIsNeverWeak() {
        var asked = false
        XCTAssertFalse(PasswordHealth.isWeak("") { _ in asked = true; return 0 })
        XCTAssertFalse(asked)
    }

    func testCoreEstimate() {
        let core = { (p: String) in estimateBits(password: p) }
        XCTAssertTrue(PasswordHealth.isWeak("password", bits: core))
        XCTAssertTrue(PasswordHealth.isWeak("abc123", bits: core))
        XCTAssertFalse(PasswordHealth.isWeak("cT7#qLm2!vXr9$Wz4@Hs", bits: core))
    }

    func testReportsLoginsBelowTheThreshold() {
        let weak = login("abc"), edge = login("edge"), strong = login("strong")
        let report = HealthReport(entries: [weak, edge, strong], bits: bits(["abc": 15, "edge": PasswordHealth.weakBits, "strong": 90]))
        XCTAssertEqual(ids(report.weak), [weak.id])
        XCTAssertEqual(ids(report.logins), [weak.id, edge.id, strong.id])
    }

    // MARK: Reuse

    func testGroupsIdenticalPasswordsLargestFirst() {
        let a1 = login("same-a"), b1 = login("same-b"), a2 = login("same-a"), b2 = login("same-b"), a3 = login("same-a"), alone = login("only-once")
        let report = HealthReport(entries: [a1, b1, a2, b2, a3, alone], bits: bits([:]))
        XCTAssertEqual(report.reused.map(ids), [[a1.id, a2.id, a3.id], [b1.id, b2.id]])
        XCTAssertEqual(report.reuseCount[a1.id], 2)
        XCTAssertEqual(report.reuseCount[b2.id], 1)
        XCTAssertNil(report.reuseCount[alone.id])
    }

    func testGroupsOfTheSameSizeKeepVaultOrder() {
        let c1 = login("c"), d1 = login("d"), c2 = login("c"), d2 = login("d")
        XCTAssertEqual(HealthReport(entries: [c1, d1, c2, d2], bits: bits([:])).reused.map(ids), [[c1.id, c2.id], [d1.id, d2.id]])
    }

    func testComparesPasswordsExactly() {
        let report = HealthReport(entries: [login("Secret"), login("secret"), login("secret "), login(" secret")], bits: bits([:]))
        XCTAssertTrue(report.reused.isEmpty)
        // Two spellings of "café" (composed é and e + combining accent): equal for Swift's ==,
        // different passwords for a website (and the web vault).
        let composed = login("caf\u{E9}"), decomposed = login("cafe\u{301}")
        XCTAssertEqual(composed.item.login?.password, decomposed.item.login?.password)
        XCTAssertTrue(HealthReport(entries: [composed, decomposed], bits: bits([:])).reused.isEmpty)
    }

    func testSkipsEmptyPasswordsTrashAndOtherItems() {
        let empty1 = login(""), empty2 = login("")
        let kept = login("shared-password")
        let trashed = login("shared-password", deleted: 1_700_000_000)
        let note = Entry(id: "note", item: Item(name: "Note", notes: "shared-password"), vaultId: "v1", revision: 1,
                         enc: EncryptedItem(id: "note", vaultId: "v1", key: "", data: ""), deletedAt: nil)
        let report = HealthReport(entries: [empty1, empty2, kept, trashed, note], bits: bits(["": 0]))
        XCTAssertTrue(report.reused.isEmpty)
        XCTAssertEqual(ids(report.logins), [kept.id])
        XCTAssertTrue(report.weak.isEmpty)
        XCTAssertTrue(HealthReport(entries: [login("abc", deleted: 1)], bits: bits(["abc": 10])).weak.isEmpty)
    }

    // MARK: Range answers

    func testReadsSuffixCountLinesAndLeavesPaddingOut() throws {
        let body = (["0018A45C4D1DEF81644B54AB7F969B88D65:1", "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"] + Self.padding(3)).joined(separator: "\r\n")
        XCTAssertEqual(try XCTUnwrap(PwnedPasswords.parseRange(body)), ["0018A45C4D1DEF81644B54AB7F969B88D65": 1, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC": 2])
    }

    func testAcceptsLowercaseHexPlainNewlinesAndBlankLines() throws {
        let range = try XCTUnwrap(PwnedPasswords.parseRange("\n0018a45c4d1def81644b54ab7f969b88d65:12\n\n"))
        XCTAssertEqual(range["0018A45C4D1DEF81644B54AB7F969B88D65"], 12)
        // A byte order mark and spaces around a line, as JavaScript's trim() removes them.
        XCTAssertEqual(PwnedPasswords.parseRange("\u{FEFF}0018A45C4D1DEF81644B54AB7F969B88D65:3 \r\n")?["0018A45C4D1DEF81644B54AB7F969B88D65"], 3)
    }

    func testIgnoresLinesOfTheWrongShape() throws {
        let range = try XCTUnwrap(PwnedPasswords.parseRange([
            "SHORT:1",
            "0018A45C4D1DEF81644B54AB7F969B88D65",
            "ZZ18A45C4D1DEF81644B54AB7F969B88D65:3",
            "0018A45C4D1DEF81644B54AB7F969B88D65:",
            "0018A45C4D1DEF81644B54AB7F969B88D65:1:2",
            "0018A45C4D1DEF81644B54AB7F969B88D65 :5",
            "0018A45C4D1DEF81644B54AB7F969B88D65:-5",
            "0018A45C4D1DEF81644B54AB7F969B88D65A:5",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:4",
        ].joined(separator: "\n")))
        XCTAssertEqual(Array(range.keys), ["00D4F6E8FA6EECAD2A3AA415EEC418D38EC"])
    }

    func testKeepsTheLargestCountAndHugeCounts() {
        let range = PwnedPasswords.parseRange([
            "0018A45C4D1DEF81644B54AB7F969B88D65:2", "0018a45c4d1def81644b54ab7f969b88d65:9", "0018A45C4D1DEF81644B54AB7F969B88D65:0",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:99999999999999999999999999",
        ].joined(separator: "\r\n"))
        XCTAssertEqual(range?["0018A45C4D1DEF81644B54AB7F969B88D65"], 9)
        XCTAssertEqual(range?["00D4F6E8FA6EECAD2A3AA415EEC418D38EC"], Int.max)
    }

    func testAnswerWithoutARangeLineIsNoAnswer() {
        XCTAssertNil(PwnedPasswords.parseRange("<!doctype html><title>Sign in to this network</title>"))
        XCTAssertNil(PwnedPasswords.parseRange(""))
        XCTAssertNil(PwnedPasswords.parseRange("{\"error\":\"rate limited\"}"))
        // Only padding is still a real answer: nothing found.
        XCTAssertEqual(PwnedPasswords.parseRange(Self.padding(2).joined(separator: "\r\n"))?.count, 0)
    }

    // MARK: Breach check

    func testHashesWithSha1() {
        XCTAssertEqual(PwnedPasswords.sha1Hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        XCTAssertEqual(PwnedPasswords.sha1Hex(""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
        let utf8 = PwnedPasswords.sha1Hex("pässwörd")
        XCTAssertEqual(utf8.count, 40)
        XCTAssertTrue(utf8.allSatisfy { "0123456789ABCDEF".contains($0) })
        XCTAssertNotEqual(PwnedPasswords.sha1Hex("caf\u{E9}"), PwnedPasswords.sha1Hex("cafe\u{301}"))
    }

    func testSendsOnlyTheFirst5CharactersAndMatchesTheSuffix() async throws {
        let suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        let net = StubNet { _ in .ok((Self.padding(5) + ["\(suffix):3861"] + Self.padding(5, seed: 1)).joined(separator: "\r\n")) }
        let result = try await BreachChecker(fetch: net.fetch).check(["password"])
        XCTAssertEqual(result.timesSeen("password"), 3861)
        let requests = net.requests
        XCTAssertEqual(requests.count, 1)
        let r = try XCTUnwrap(requests.first)
        XCTAssertEqual(r.url?.absoluteString, "\(PwnedPasswords.rangeURL)5BAA6")
        XCTAssertFalse(r.url?.absoluteString.contains(suffix) ?? true)
        XCTAssertEqual(r.httpMethod, "GET")
        XCTAssertNil(r.httpBody)
        XCTAssertEqual(r.value(forHTTPHeaderField: "Add-Padding"), "true")
        XCTAssertFalse(r.httpShouldHandleCookies)
        XCTAssertEqual(r.cachePolicy, .reloadIgnoringLocalAndRemoteCacheData)
        XCTAssertNil(r.value(forHTTPHeaderField: "Authorization"))
        XCTAssertNil(r.value(forHTTPHeaderField: ApiClient.clientHeaderName))
    }

    func testReports0ForMissingAndPaddedPasswords() async throws {
        let digest = Self.digest(["listed": Self.hash("ABCDE", "1"), "padded": Self.hash("ABCDE", "2"), "missing": Self.hash("ABCDE", "3")])
        let net = StubNet { _ in .ok((["\(String(repeating: "1", count: 35)):7", "\(String(repeating: "2", count: 35)):0"] + Self.padding(3)).joined(separator: "\r\n")) }
        let result = try await BreachChecker(digest: digest, fetch: net.fetch).check(["listed", "padded", "missing"])
        XCTAssertEqual(result.timesSeen("listed"), 7)
        XCTAssertEqual(result.timesSeen("padded"), 0)
        XCTAssertEqual(result.timesSeen("missing"), 0)
        XCTAssertNil(result.timesSeen("not part of the check"))
    }

    func testRequestsEachPrefixOnceAndKeepsAnswersUntilCleared() async throws {
        let digest = Self.digest(["one": Self.hash("AAAAA", "1"), "two": Self.hash("AAAAA", "2"), "three": Self.hash("BBBBB", "3")])
        let net = StubNet { prefix in prefix == "AAAAA" ? .ok("\(String(repeating: "2", count: 35)):5") : .ok(Self.padding(4).joined(separator: "\r\n")) }
        let checker = BreachChecker(digest: digest, fetch: net.fetch)

        let first = try await checker.check(["one", "two", "", "three", "one", "two"])
        XCTAssertEqual(net.prefixes.sorted(), ["AAAAA", "BBBBB"])
        XCTAssertEqual([first.timesSeen("one"), first.timesSeen("two"), first.timesSeen("three")], [0, 5, 0])
        XCTAssertEqual(first.count, 3)

        let again = try await checker.check(["two", "three"])
        XCTAssertEqual(net.requests.count, 2)
        XCTAssertEqual([again.timesSeen("two"), again.timesSeen("three")], [5, 0])

        checker.clear()
        _ = try await checker.check(["three"])
        XCTAssertEqual(net.requests.count, 3)
        XCTAssertEqual(net.prefixes.last, "BBBBB")
    }

    func testChecksNothingWithoutPasswords() async throws {
        let net = StubNet { _ in .ok("") }
        let progress = ProgressLog()
        let result = try await BreachChecker(fetch: net.fetch).check(["", ""]) { progress.add($0, $1) }
        XCTAssertEqual(result.count, 0)
        XCTAssertTrue(net.requests.isEmpty)
        XCTAssertEqual(progress.steps.map { [$0.0, $0.1] }, [[0, 0]])
    }

    func testRunsAtMost6RequestsAtATime() async throws {
        var table: [String: String] = [:]
        for i in 0..<40 { table["p\(i)"] = Self.hash(String(format: "%05X", i), "C") }
        let net = StubNet(delay: { .milliseconds(Int.random(in: 1...6)) }) { _ in .ok(Self.padding(3).joined(separator: "\r\n")) }
        let checker = BreachChecker(digest: Self.digest(table), fetch: net.fetch)
        let names = (0..<40).map { "p\($0)" }
        // Two overlapping checks share the same limit.
        async let a = checker.check(Array(names[..<25]))
        async let b = checker.check(Array(names[25...]))
        _ = try await (a, b)
        XCTAssertEqual(PwnedPasswords.parallel, 6)
        XCTAssertEqual(net.most, PwnedPasswords.parallel)
        XCTAssertEqual(Set(net.prefixes).count, 40)
        XCTAssertEqual(net.prefixes.count, 40)
    }

    func testHonoursALowerLimit() async throws {
        let table = Dictionary(uniqueKeysWithValues: (0..<8).map { ("p\($0)", Self.hash("0000\($0)", "D")) })
        let net = StubNet(delay: { .milliseconds(2) }) { _ in .ok(Self.padding(1).joined(separator: "\n")) }
        _ = try await BreachChecker(parallel: 2, digest: Self.digest(table), fetch: net.fetch).check(Array(table.keys))
        XCTAssertEqual(net.most, 2)
        XCTAssertEqual(net.requests.count, 8)
    }

    func testReportsProgressInDistinctPasswords() async throws {
        let digest = Self.digest(["a": Self.hash("11111", "1"), "b": Self.hash("11111", "2"), "c": Self.hash("22222", "3")])
        let net = StubNet { _ in .ok(Self.padding(2).joined(separator: "\r\n")) }
        let progress = ProgressLog()
        _ = try await BreachChecker(digest: digest, fetch: net.fetch).check(["a", "b", "c", "a"]) { progress.add($0, $1) }
        let steps = progress.steps
        XCTAssertEqual(steps.first.map { [$0.0, $0.1] }, [0, 3])
        XCTAssertEqual(steps.last.map { [$0.0, $0.1] }, [3, 3])
        XCTAssertEqual(steps.map(\.0), steps.map(\.0).sorted())
    }

    func testFailsWithTheHttpStatusAndDoesntKeepTheFailedPrefix() async throws {
        let net = StubNet { _ in .ok("") }
        net.answer = { _ in .status(503, "busy") }
        let checker = BreachChecker(fetch: net.fetch)
        await assertFails(checker, ["password"], with: .http(503))
        net.answer = { _ in .ok(Self.padding(2).joined(separator: "\r\n")) }
        let result = try await checker.check(["password"])
        XCTAssertEqual(result.timesSeen("password"), 0)
        XCTAssertEqual(net.requests.count, 2)
    }

    func testNoAnswerIsANetworkFailure() async {
        await assertFails(BreachChecker(fetch: StubNet { _ in .fail(URLError(.cannotConnectToHost)) }.fetch), ["password"], with: .network)
        await assertFails(BreachChecker(fetch: StubNet { _ in .fail(CocoaError(.fileNoSuchFile)) }.fetch), ["password"], with: .network)
        await assertFails(BreachChecker(fetch: StubNet { _ in .fail(URLError(.notConnectedToInternet)) }.fetch), ["password"], with: .offline)
        await assertFails(BreachChecker(fetch: StubNet { _ in .fail(URLError(.timedOut)) }.fetch), ["password"], with: .timeout)
    }

    func testAnAnswerThatIsntARangeListIsInvalid() async {
        await assertFails(BreachChecker(fetch: StubNet { _ in .ok("<html>Sign in to continue</html>") }.fetch), ["password"], with: .invalid)
    }

    func testGivesUpOnARequestAfterTheTimeout() async {
        let net = StubNet(delay: { .seconds(30) }) { _ in .ok("") }
        let started = ContinuousClock.now
        await assertFails(BreachChecker(timeout: .milliseconds(20), fetch: net.fetch), ["password"], with: .timeout)
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(5))
    }

    func testSkipsTheRemainingRequestsAfterTheFirstFailure() async throws {
        let table = Dictionary(uniqueKeysWithValues: (0..<6).map { ("p\($0)", Self.hash("9999\($0)", "E")) })
        let net = StubNet(delay: { .milliseconds(1) }) { _ in .status(429, "") }
        await assertFails(BreachChecker(parallel: 1, digest: Self.digest(table), fetch: net.fetch), Array(table.keys), with: .http(429))
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(net.requests.count, 1)
    }

    func testClearStopsARunningCheck() async throws {
        let table = Dictionary(uniqueKeysWithValues: (0..<12).map { ("p\($0)", Self.hash(String(format: "7%04X", $0), "F")) })
        let net = StubNet(delay: { .milliseconds(200) }) { _ in .ok(Self.padding(1).joined(separator: "\n")) }
        let checker = BreachChecker(digest: Self.digest(table), fetch: net.fetch)
        let running = Task { try await checker.check(Array(table.keys)) }
        try await Task.sleep(for: .milliseconds(30))
        checker.clear()
        do {
            _ = try await running.value
            XCTFail("The check should have stopped")
        } catch {
            XCTAssertEqual(error as? BreachCheckError, .stopped)
        }
        try await Task.sleep(for: .milliseconds(250))
        // Only the first slots were ever sent; the queued prefixes never went out.
        XCTAssertEqual(net.requests.count, PwnedPasswords.parallel)
    }

    /// The real fetcher: its own session (no cookies, cache or PassAuth headers) and the request as sent.
    func testUrlSessionFetcherSendsAPlainPaddedRequest() async throws {
        ScriptedServer.reset()
        defer { ScriptedServer.reset() }
        let session = PwnedPasswords.makeSession { $0.protocolClasses = [ScriptedServer.self] }
        XCTAssertNil(session.configuration.httpCookieStorage)
        XCTAssertNil(session.configuration.urlCache)
        XCTAssertNil(session.configuration.urlCredentialStorage)
        XCTAssertFalse(session.configuration.httpShouldSetCookies)
        XCTAssertEqual(session.configuration.httpCookieAcceptPolicy, .never)
        XCTAssertNil(session.configuration.httpAdditionalHeaders?[ApiClient.clientHeaderName])
        XCTAssertEqual(session.configuration.timeoutIntervalForResource, 15)
        ScriptedServer.answer("GET /range/5BAA6", 200, (Self.padding(3) + ["1E4C9B93F3F0682250B6CF8331B7EE68FD8:42"]).joined(separator: "\r\n"))
        let result = try await BreachChecker(fetch: PwnedPasswords.fetcher(session: session)).check(["password"])
        XCTAssertEqual(result.timesSeen("password"), 42)
        let sent = ScriptedServer.recorded()
        XCTAssertEqual(sent.map(\.path), ["/range/5BAA6"])
        let headers = Dictionary(uniqueKeysWithValues: (sent.first?.headers ?? [:]).map { ($0.key.lowercased(), $0.value) })
        XCTAssertEqual(headers["add-padding"], "true")
        XCTAssertNil(headers["cookie"])
        XCTAssertNil(headers["authorization"])
        XCTAssertNil(headers[ApiClient.clientHeaderName.lowercased()])
    }

    // MARK: Wording

    func testFailureMessages() {
        XCTAssertEqual(HealthText.explain(BreachCheckError.http(429)), "Have I Been Pwned is busy. Wait a minute, then try again.")
        XCTAssertEqual(HealthText.explain(BreachCheckError.http(503)), "Have I Been Pwned couldn't answer (error 503). Try again later.")
        XCTAssertEqual(HealthText.explain(BreachCheckError.offline), HealthText.offline)
        XCTAssertEqual(HealthText.explain(BreachCheckError.network), HealthText.unreachable)
        XCTAssertEqual(HealthText.explain(BreachCheckError.timeout), HealthText.timeout)
        XCTAssertEqual(HealthText.explain(BreachCheckError.invalid), HealthText.invalid)
        XCTAssertEqual(HealthText.explain(BreachCheckError.stopped), "The check stopped. Try again.")
        XCTAssertEqual(HealthText.explain(CancellationError()), "The check stopped. Try again.")
        XCTAssertEqual(HealthText.notAllowed, "This server doesn't allow checking passwords against Have I Been Pwned.")
    }

    func testNotesAndAnnouncements() {
        XCTAssertEqual(HealthText.usedIn(1), "Used in 1 other login")
        XCTAssertEqual(HealthText.usedIn(2), "Used in 2 other logins")
        XCTAssertEqual(HealthText.timesSeen(1), "Seen 1 time")
        XCTAssertEqual(HealthText.timesSeen(12), "Seen 12 times")
        XCTAssertEqual(HealthText.progress(done: 0, total: 0), "Starting the check.")
        XCTAssertEqual(HealthText.progress(done: 0, total: 10), "Checking 10 passwords, 0% done.")
        XCTAssertEqual(HealthText.progress(done: 3, total: 10), "Checking 10 passwords, 25% done.")
        XCTAssertEqual(HealthText.progress(done: 7, total: 10), "Checking 10 passwords, 50% done.")
        XCTAssertEqual(HealthText.progress(done: 10, total: 10), "Checking 10 passwords, 100% done.")
        XCTAssertEqual(HealthText.progress(done: 1, total: 1), "Checking 1 password, 100% done.")
        XCTAssertEqual(HealthText.finished(exposed: 0), "Check finished. No exposed passwords found.")
        XCTAssertEqual(HealthText.finished(exposed: 1), "Check finished. 1 login uses a password found in data breaches.")
        XCTAssertEqual(HealthText.finished(exposed: 3), "Check finished. 3 logins use passwords found in data breaches.")
    }

    private func assertFails(_ checker: BreachChecker, _ passwords: [String], with expected: BreachCheckError, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await checker.check(passwords)
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? BreachCheckError, expected, file: file, line: line)
        }
    }
}

/// Progress callbacks in order.
@MainActor
private final class ProgressLog {
    private(set) var steps: [(Int, Int)] = []
    func add(_ done: Int, _ total: Int) { steps.append((done, total)) }
}

/// A stubbed range API: answers each prefix with `answer(prefix)` after `delay`, records every
/// request and the most requests in flight at once. Waiting is cancellable, like URLSession.
private final class StubNet: @unchecked Sendable {
    enum Reply {
        case ok(String)
        case status(Int, String)
        case fail(Error)
    }

    private let lock = NSLock()
    private var sent: [URLRequest] = []
    private var inFlight = 0
    private var peak = 0
    private let delay: (@Sendable () -> Duration)?
    private var _answer: @Sendable (String) -> Reply

    init(delay: (@Sendable () -> Duration)? = nil, _ answer: @escaping @Sendable (String) -> Reply) {
        self.delay = delay
        _answer = answer
    }

    var answer: @Sendable (String) -> Reply {
        get { lock.withLock { _answer } }
        set { lock.withLock { _answer = newValue } }
    }

    var requests: [URLRequest] { lock.withLock { sent } }
    var prefixes: [String] { requests.map { $0.url?.lastPathComponent ?? "" } }
    var most: Int { lock.withLock { peak } }

    var fetch: BreachChecker.Fetch {
        { [self] request in
            let reply: Reply = lock.withLock {
                sent.append(request)
                inFlight += 1
                peak = max(peak, inFlight)
                return _answer(request.url?.lastPathComponent ?? "")
            }
            defer { lock.withLock { inFlight -= 1 } }
            if let delay { try await Task.sleep(for: delay()) }
            switch reply {
            case .ok(let body): return RangeAnswer(status: 200, body: Data(body.utf8))
            case .status(let status, let body): return RangeAnswer(status: status, body: Data(body.utf8))
            case .fail(let error): throw error
            }
        }
    }
}

/// The session behind Settings → Password health: a check against a stubbed range API, and
/// everything dropped when the vault closes (lock, log out, another account).
@MainActor
final class HealthSessionTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-health-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    /// An unlocked account whose vault holds two logins with the password "password" and one strong one.
    private func unlocked() async throws -> VaultRepository {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let vaultId = try newId()
        let k = try created.account.newVaultKey(vaultId: vaultId)
        var items: [[String: Any]] = []
        for (name, pw) in [("Shop", "password"), ("Mail", "password"), ("Bank", "cT7#qLm2!vXr9$Wz4@Hs")] {
            var item = Item.empty(.login, now: 1_700_000_000)
            item.name = name
            item.login?.password = pw
            let id = try newId()
            let enc = try k.key.encryptItem(itemJson: ItemCodec.encode(item), id: id, vaultId: vaultId)
            items.append(["id": id, "vault_id": vaultId, "item_key": enc.key, "data": enc.data, "revision": 1, "deleted_at": NSNull()])
        }
        ScriptedServer.syncBodies = [try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": vaultId, "wrapped_key": k.wrapped, "key_kind": "account", "role": "owner",
                        "meta": try k.key.encryptMeta(vaultId: vaultId, metaJson: #"{"name":"Personal"}"#)]],
            "items": items,
            "revision": 5,
        ] as [String: Any])]
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] }).allowingOlderServers()
        try await repo.unlock(password: password, secretKey: nil)
        return repo
    }

    private func waitWhileChecking(_ health: HealthSession) async throws {
        for _ in 0..<500 where health.status == .checking { try await Task.sleep(for: .milliseconds(10)) }
    }

    func testCheckFindsBreachedPasswordsAndLockDropsEverything() async throws {
        let repo = try await unlocked()
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["breach_check"]}"#)
        let net = StubNet { prefix in .ok(prefix == "5BAA6" ? "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861" : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0") }
        let health = HealthSession(repo: repo, checker: BreachChecker(fetch: net.fetch))
        let v = try XCTUnwrap(repo.vault)
        let report = health.report(v)
        XCTAssertEqual(report.logins.count, 3)
        XCTAssertEqual(report.reused.map(\.count), [2])
        XCTAssertEqual(report.weak.count, 2)

        health.check()
        try await waitWhileChecking(health)
        XCTAssertEqual(health.status, .done, health.error ?? "")
        XCTAssertEqual(health.availability, .on)
        XCTAssertEqual(health.results?.timesSeen("password"), 3861)
        XCTAssertEqual(health.results?.timesSeen("cT7#qLm2!vXr9$Wz4@Hs"), 0)
        XCTAssertEqual(net.requests.count, 2)
        XCTAssertNotNil(health.checkedAt)
        // The server's settings are asked without the session.
        XCTAssertNil(ScriptedServer.recorded().first { $0.path == "/api/config" }?.headers["Authorization"])

        await repo.lockActive()
        XCTAssertNil(health.results)
        XCTAssertNil(health.checkedAt)
        XCTAssertEqual(health.status, .idle)
        XCTAssertEqual(health.availability, .loading)
    }

    func testServerWithoutTheFeatureSendsNothing() async throws {
        let repo = try await unlocked()
        ScriptedServer.answer("GET /api/config", 200, #"{"name":"PassAuth","api":2,"features":["delta_sync"]}"#)
        let net = StubNet { _ in .ok("") }
        let health = HealthSession(repo: repo, checker: BreachChecker(fetch: net.fetch))
        await health.loadAvailability()
        XCTAssertEqual(health.availability, .off)
        // Asked again at the check: the admin may have switched it off since the page opened.
        ScriptedServer.answer("GET /api/config", 200, #"{"features":[]}"#)
        health.check()
        try await waitWhileChecking(health)
        XCTAssertEqual(health.status, .idle)
        XCTAssertEqual(health.availability, .off)
        XCTAssertNil(health.error)
        XCTAssertNil(health.results)
        XCTAssertTrue(net.requests.isEmpty)
    }

    func testUnreadableSettingsSayWhy() async throws {
        let repo = try await unlocked()
        ScriptedServer.answer("GET /api/config", 502, "<html>Bad gateway</html>")
        ScriptedServer.answer("GET /api/config", 502, "<html>Bad gateway</html>")
        let net = StubNet { _ in .ok("") }
        let health = HealthSession(repo: repo, checker: BreachChecker(fetch: net.fetch))
        await health.loadAvailability()
        XCTAssertEqual(health.availability, .unknown)
        health.check()
        try await waitWhileChecking(health)
        XCTAssertEqual(health.error, HealthText.noConfig)
        XCTAssertTrue(net.requests.isEmpty)
    }

    func testLockDuringACheckStopsIt() async throws {
        let repo = try await unlocked()
        ScriptedServer.answer("GET /api/config", 200, #"{"features":["breach_check"]}"#)
        let net = StubNet(delay: { .seconds(5) }) { _ in .ok("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0") }
        let health = HealthSession(repo: repo, checker: BreachChecker(fetch: net.fetch))
        health.check()
        for _ in 0..<300 where net.requests.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(health.status, .checking)
        await repo.lockActive()
        XCTAssertEqual(health.status, .idle)
        try await Task.sleep(for: .milliseconds(100))
        // The stopped check doesn't come back as a failure or a result.
        XCTAssertEqual(health.status, .idle)
        XCTAssertNil(health.results)
        XCTAssertNil(health.error)
    }
}
