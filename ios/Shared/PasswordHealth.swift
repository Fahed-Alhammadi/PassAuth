import CryptoKit
import Foundation

// Password health (the iOS app's Settings → Password health and the notes on an item's page):
// weak, reused and exposed passwords among the logins the user can read. The web vault's
// `web/src/lib/health.ts`, with the same rules, threshold, limits and wording. Pure: callers pass
// the strength estimate (the core's `estimateBits`) and the network (`PwnedPasswords.fetcher`).
// Decrypted passwords stay in memory: reuse is found by comparing them in place, and the breach
// check sends only the first 5 hex characters of each password's SHA-1 hash to Have I Been
// Pwned's range API (k-anonymity, padded answers), never a full hash or a password.

// MARK: Strength

public enum PasswordHealth {
    /// Bits, as estimated by the core's `estimateBits`, below which a password is weak ("easy to
    /// guess"): the one threshold of the strength meter, the master password checks, the
    /// generator and password health, as in the web vault (`WEAK_BITS`), the extension and Android.
    public static let weakBits: Double = AccountSecurityLogic.weakBits

    /// Weak: set, and estimated below `weakBits`.
    public static func isWeak(_ password: String, bits: (String) -> Double) -> Bool {
        !password.isEmpty && bits(password) < weakBits
    }
}

/// The `/api/config` feature of servers whose admin allows the breach check.
public let breachCheckFeature = "breach_check"

// MARK: Report

/// Weak and reused passwords among the logins of every vault the user can read.
public struct HealthReport: Sendable {
    /// Logins with a password that aren't in the trash: everything the report covers, in vault order.
    public private(set) var logins: [Entry] = []
    /// Logins whose password is weak.
    public private(set) var weak: [Entry] = []
    /// Logins that share one password, in groups of 2 or more, the largest group first.
    public private(set) var reused: [[Entry]] = []
    /// For each login in `reused`: how many other logins use the same password.
    public private(set) var reuseCount: [String: Int] = [:]

    public init() {}

    /// Items in the trash, items that aren't logins and logins without a password are left out.
    /// Passwords are compared exactly as they are (their UTF-8 bytes: unlike Swift's `==`, two
    /// spellings of "é" are different passwords, as on the web).
    public init(entries: [Entry], bits: (String) -> Double) {
        var groups: [[Entry]] = []
        var groupOf: [Data: Int] = [:]
        for e in entries {
            guard e.deletedAt == nil, let password = e.item.login?.password, !password.isEmpty else { continue }
            logins.append(e)
            if PasswordHealth.isWeak(password, bits: bits) { weak.append(e) }
            let key = Data(password.utf8)
            if let n = groupOf[key] {
                groups[n].append(e)
            } else {
                groupOf[key] = groups.count
                groups.append([e])
            }
        }
        // Largest first; groups of the same size stay in vault order.
        reused = groups.enumerated().filter { $0.element.count > 1 }
            .sorted { $0.element.count != $1.element.count ? $0.element.count > $1.element.count : $0.offset < $1.offset }
            .map(\.element)
        for group in reused { for e in group { reuseCount[e.id] = group.count - 1 } }
    }
}

// MARK: Breaches

/// Have I Been Pwned's Pwned Passwords range API.
public enum PwnedPasswords {
    public static let origin = "https://api.pwnedpasswords.com"
    /// GET this + the first 5 hex characters (uppercase) of a password's SHA-1 hash.
    public static let rangeURL = origin + "/range/"
    /// Range requests running at the same time, at most.
    public static let parallel = 6
    /// Per request, from when it is sent until its answer has been read.
    public static let timeout: Duration = .seconds(15)

    /// One range request: padded answers (800 to 1,000 lines, so their size says nothing about
    /// the prefix), no cookies and no cached copy. Nil for a prefix that isn't URL-safe.
    public static func request(prefix: String) -> URLRequest? {
        guard let url = URL(string: rangeURL + prefix) else { return nil }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        r.httpMethod = "GET"
        r.httpShouldHandleCookies = false
        r.setValue("true", forHTTPHeaderField: "Add-Padding")
        return r
    }

    /// The breach check's own session: ephemeral, no cookies, cache or credentials, and never the
    /// PassAuth server's headers (`ApiClient`'s session sends `X-PassAuth-Client` and tokens).
    /// `configure` adjusts it (tests register a URLProtocol).
    public static func makeSession(configure: ((URLSessionConfiguration) -> Void)? = nil) -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.httpCookieAcceptPolicy = .never
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.urlCredentialStorage = nil
        c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        c.timeoutIntervalForRequest = 15
        c.timeoutIntervalForResource = 15
        c.httpMaximumConnectionsPerHost = parallel
        c.waitsForConnectivity = false
        configure?(c)
        return URLSession(configuration: c)
    }

    /// Sends range requests with `session`.
    public static func fetcher(session: URLSession = makeSession()) -> BreachChecker.Fetch {
        { request in
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw BreachCheckError.network }
            return RangeAnswer(status: http.statusCode, body: data)
        }
    }

    /// Uppercase hex SHA-1 of the text's UTF-8 bytes.
    public static func sha1Hex(_ text: String) -> String {
        let digits = Array("0123456789ABCDEF".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(40)
        for byte in Insecure.SHA1.hash(data: Data(text.utf8)) {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// A range answer (`SUFFIX:COUNT` lines): hash suffix → times seen. Padding lines (count 0)
    /// are left out. Nil when no line has that shape, so a page that isn't a range answer (a
    /// network's sign-in page) never reads as "not found".
    public static func parseRange(_ body: String) -> [String: Int]? {
        var seen: [String: Int] = [:]
        var lines = 0
        // Split on "\n" by scalar: as a Character, "\r\n" is one grapheme and never equals "\n".
        for raw in body.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let (suffix, count) = rangeLine(String(String.UnicodeScalarView(raw)).trimmingCharacters(in: trimmed)) else { continue }
            lines += 1
            if count > 0 { seen[suffix] = max(count, seen[suffix] ?? 0) }
        }
        return lines > 0 ? seen : nil
    }

    /// What JavaScript's `trim()` removes: white space, line breaks and the byte order mark.
    private static let trimmed = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\u{FEFF}"))

    /// `^[0-9A-F]{35}:\d+$` (case-insensitive hex), as (suffix, count).
    private static func rangeLine(_ line: String) -> (String, Int)? {
        let upper = line.uppercased()
        guard let colon = upper.firstIndex(of: ":") else { return nil }
        let hex = upper[..<colon].utf8
        let number = upper[upper.index(after: colon)...].utf8
        guard hex.count == 35, hex.allSatisfy({ (0x30...0x39).contains($0) || (0x41...0x46).contains($0) }),
              !number.isEmpty, number.allSatisfy({ (0x30...0x39).contains($0) })
        else { return nil }
        // Only digits: a count too large for Int is still "seen".
        return (String(upper[..<colon]), Int(upper[upper.index(after: colon)...]) ?? Int.max)
    }
}

/// An answer from the range API (or a stub in tests).
public struct RangeAnswer: Sendable {
    public let status: Int
    public let body: Data

    public init(status: Int, body: Data) {
        self.status = status
        self.body = body
    }
}

/// Why a breach check stopped.
public enum BreachCheckError: Error, Equatable, Sendable {
    /// No answer at all (DNS, TLS, connection, a blocking VPN).
    case network
    /// This device has no internet connection.
    case offline
    /// No answer within `PwnedPasswords.timeout`.
    case timeout
    /// An answer with this HTTP status (429: rate limited).
    case http(Int)
    /// An answer that isn't a range list (e.g. a network's sign-in page).
    case invalid
    /// `clear()` (the vault locked or signed out) or the caller's task was cancelled.
    case stopped
}

/// How often each password of one check appears in known data breaches (0: not found). Keyed by
/// the passwords' exact bytes, in memory only.
public struct BreachResults: Sendable, Equatable {
    private var counts: [Data: Int] = [:]

    public init() {}

    init(counts: [Data: Int]) { self.counts = counts }

    /// Times seen in data breaches (0: not found); nil when the password wasn't part of the check
    /// (added or changed since).
    public func timesSeen(_ password: String) -> Int? { counts[Data(password.utf8)] }

    /// Distinct passwords checked.
    public var count: Int { counts.count }
}

/// Checks passwords against Have I Been Pwned through `fetch` (`PwnedPasswords.fetcher`, or a stub
/// in tests). Answers per prefix are kept (in memory) for later checks until `clear`.
@MainActor
public final class BreachChecker {
    public typealias Fetch = @Sendable (URLRequest) async throws -> RangeAnswer

    private let fetch: Fetch
    private let parallel: Int
    private let timeout: Duration
    private let digest: @Sendable (String) -> String

    /// Answers per prefix: hash suffix → times seen.
    private var ranges: [String: [String: Int]] = [:]
    /// Bumped by `clear`: work started before it is dropped.
    private var generation = 0
    private var active = 0
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private var checks: [Int: Task<BreachResults, Error>] = [:]
    private var nextCheck = 0

    /// `parallel`: requests at the same time, at most, across checks. `timeout`: per request.
    /// `digest`: uppercase hex SHA-1.
    public init(
        parallel: Int = PwnedPasswords.parallel,
        timeout: Duration = PwnedPasswords.timeout,
        digest: @escaping @Sendable (String) -> String = PwnedPasswords.sha1Hex,
        fetch: @escaping Fetch = PwnedPasswords.fetcher()
    ) {
        self.parallel = max(1, parallel)
        self.timeout = timeout
        self.digest = digest
        self.fetch = fetch
    }

    /// How often each distinct, non-empty password appears in known data breaches (0: not
    /// found). Passwords that share a prefix share one request, kept answers are reused, and at
    /// most `parallel` requests run at a time. `onProgress` counts distinct passwords. The first
    /// failed request fails the check with its `BreachCheckError`; the check's requests that
    /// haven't started yet are then skipped. `clear` stops it with `.stopped`.
    public func check(_ passwords: [String], onProgress: (@MainActor @Sendable (Int, Int) -> Void)? = nil) async throws -> BreachResults {
        let id = nextCheck
        nextCheck += 1
        let gen = generation
        let task = Task { @MainActor in try await self.run(passwords, gen: gen, onProgress: onProgress) }
        checks[id] = task
        defer { checks[id] = nil }
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }

    /// Stop every check in progress (each fails with `.stopped`) and forget the kept answers.
    public func clear() {
        generation += 1
        ranges = [:]
        for task in checks.values { task.cancel() }
    }

    private func stopped(_ gen: Int) -> Bool { gen != generation || Task.isCancelled }

    private func run(_ passwords: [String], gen: Int, onProgress: (@MainActor @Sendable (Int, Int) -> Void)?) async throws -> BreachResults {
        var unique: [String] = []
        var keys = Set<Data>()
        for p in passwords where !p.isEmpty {
            if keys.insert(Data(p.utf8)).inserted { unique.append(p) }
        }
        let distinct = unique
        let hashes = await Self.hashAll(distinct, digest)
        if stopped(gen) { throw BreachCheckError.stopped }
        var prefixes: [String] = []
        var members: [String: [Int]] = [:]
        for (i, hash) in hashes.enumerated() {
            let prefix = String(hash.prefix(5))
            if members[prefix] == nil { prefixes.append(prefix) }
            members[prefix, default: []].append(i)
        }
        let state = CheckState(distinct: distinct, hashes: hashes, onProgress: onProgress)
        onProgress?(0, distinct.count)
        try await withThrowingTaskGroup(of: Void.self) { group in
            for prefix in prefixes {
                let indices = members[prefix] ?? []
                group.addTask { try await self.lookUp(prefix, indices, gen: gen, state: state) }
            }
            try await group.waitForAll()
        }
        return BreachResults(counts: state.seen)
    }

    /// The passwords `indices` (of `state.distinct`) that share `prefix`.
    private func lookUp(_ prefix: String, _ indices: [Int], gen: Int, state: CheckState) async throws {
        let found = try await range(prefix, gen: gen, state: state)
        for i in indices { state.seen[Data(state.distinct[i].utf8)] = found[String(state.hashes[i].dropFirst(5))] ?? 0 }
        state.done += indices.count
        if !state.failed { state.onProgress?(state.done, state.distinct.count) }
    }

    /// The answer for `prefix`: kept, or asked for once a slot is free. Not sent when the
    /// checker was cleared or the check (`state`) has already failed.
    private func range(_ prefix: String, gen: Int, state: CheckState) async throws -> [String: Int] {
        if gen == generation, let kept = ranges[prefix] { return kept }
        await acquire()
        // Runs after the catch below: the check is marked failed before the slot is handed on,
        // so its next request already sees it.
        defer { release() }
        do {
            if stopped(gen) || state.failed { throw BreachCheckError.stopped }
            guard let request = PwnedPasswords.request(prefix: prefix) else { throw BreachCheckError.invalid }
            let found = try await Self.send(request, fetch: fetch, timeout: timeout)
            if stopped(gen) { throw BreachCheckError.stopped }
            ranges[prefix] = found
            return found
        } catch {
            state.failed = true
            if stopped(gen) { throw BreachCheckError.stopped }
            throw error
        }
    }

    private func acquire() async {
        if active < parallel {
            active += 1
            return
        }
        await withCheckedContinuation { waiting.append($0) }
    }

    /// A finished request hands its slot straight to the next one, so never more than `parallel` run.
    private func release() {
        if waiting.isEmpty { active -= 1 } else { waiting.removeFirst().resume() }
    }

    /// Hashing and parsing run off the main actor.
    nonisolated private static func hashAll(_ passwords: [String], _ digest: @Sendable (String) -> String) async -> [String] {
        passwords.map { digest($0).uppercased() }
    }

    nonisolated private static func send(_ request: URLRequest, fetch: @escaping Fetch, timeout: Duration) async throws -> [String: Int] {
        let answer: RangeAnswer
        do {
            answer = try await withThrowingTaskGroup(of: RangeAnswer.self) { group in
                group.addTask { try await fetch(request) }
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw BreachCheckError.timeout
                }
                defer { group.cancelAll() }
                guard let first = try await group.next() else { throw BreachCheckError.network }
                return first
            }
        } catch let e as BreachCheckError {
            throw e
        } catch let e as URLError {
            switch e.code {
            case .timedOut: throw BreachCheckError.timeout
            case .notConnectedToInternet, .dataNotAllowed, .internationalRoamingOff: throw BreachCheckError.offline
            default: throw BreachCheckError.network
            }
        } catch {
            throw BreachCheckError.network
        }
        guard (200..<300).contains(answer.status) else { throw BreachCheckError.http(answer.status) }
        guard let range = PwnedPasswords.parseRange(String(decoding: answer.body, as: UTF8.self)) else { throw BreachCheckError.invalid }
        return range
    }
}

/// One check: its distinct passwords and their hashes, progress and results.
@MainActor
private final class CheckState {
    let distinct: [String]
    let hashes: [String]
    let onProgress: (@MainActor @Sendable (Int, Int) -> Void)?
    var failed = false
    var done = 0
    var seen: [Data: Int] = [:]

    init(distinct: [String], hashes: [String], onProgress: (@MainActor @Sendable (Int, Int) -> Void)?) {
        self.distinct = distinct
        self.hashes = hashes
        self.onProgress = onProgress
    }
}

// MARK: Wording

/// The web vault's wording for password health.
public enum HealthText {
    public static let notAllowed = "This server doesn't allow checking passwords against Have I Been Pwned."
    public static let noConfig = "Couldn't load your server's settings. Check your connection, then try again."
    public static let unavailable = "Couldn't load your server's settings, so the breach check isn't available right now. Check your connection, then try again."
    public static let offline = "You're offline. Connect to the internet, then try again."
    public static let unreachable = "Couldn't reach Have I Been Pwned. Check your connection or VPN, then try again."
    public static let timeout = "Have I Been Pwned didn't answer in time. Try again in a moment."
    public static let busy = "Have I Been Pwned is busy. Wait a minute, then try again."
    public static let invalid = "The answer didn't come from Have I Been Pwned. If this network shows a sign-in page, sign in there first, then try again."
    public static let stopped = "The check stopped. Try again."
    /// What the check sends, next to its button.
    public static let privacy = "The first 5 characters of each password's SHA-1 hash go to Have I Been Pwned; your passwords never leave this device."

    /// Why a check stopped, in plain words.
    public static func explain(_ error: Error) -> String {
        guard let e = error as? BreachCheckError else { return stopped }
        switch e {
        case .network: return unreachable
        case .offline: return offline
        case .timeout: return timeout
        case .http(429): return busy
        case .http(let status): return "Have I Been Pwned couldn't answer (error \(status)). Try again later."
        case .invalid: return invalid
        case .stopped: return stopped
        }
    }

    /// "1 login", "2,048 logins".
    public static func count(_ n: Int, _ one: String, _ many: String) -> String {
        "\(n.formatted()) \(n == 1 ? one : many)"
    }

    /// "Seen 3,861 times".
    public static func timesSeen(_ n: Int) -> String { "Seen \(count(n, "time", "times"))" }

    /// "Used in 2 other logins".
    public static func usedIn(_ others: Int) -> String { "Used in \(others) other \(others == 1 ? "login" : "logins")" }

    /// Screen reader progress in steps of a quarter, not after every request.
    public static func progress(done: Int, total: Int) -> String {
        guard total > 0 else { return "Starting the check." }
        return "Checking \(count(total, "password", "passwords")), \(min(done * 4 / total, 4) * 25)% done."
    }

    /// Read out when a check finishes.
    public static func finished(exposed: Int) -> String {
        exposed > 0
            ? "Check finished. \(count(exposed, "login uses a password", "logins use passwords")) found in data breaches."
            : "Check finished. No exposed passwords found."
    }
}
