import Foundation
import PassAuthCore

// Sign in with another device's approval (servers with the `login_with_device` feature; server
// side crates/server/src/auth_requests.rs, keys in crates/core/src/device_login.rs). The pure
// parts, unit-tested in DeviceLoginTests (iOS and the macOS AutoFill tests): the new device's
// request and its wait for an answer (`DeviceLoginFlow` over a `DeviceLoginTransport`), the
// code it must be given before it uses the approval, and the approving app's list, frozen sheet,
// word choices and answer (`DeviceApprovals`, `ApprovalQueue`). VaultRepository supplies the real
// transport and keys; the app's sign-in screen and `AuthRequestInbox` use them. Same rules and
// words as the other apps (the security review's client spec, section 1).
//
// Why the code: the approval's sealed box is anonymous, so a new device can't tell on its own who
// sealed it (a malicious server could seal a key of its own). The approving app shows a 6-digit
// code only the real account key gives (`approveLoginRequest`); the core refuses to unlock or
// hand out the Secret Key until the new device was given that code (`ApprovedLogin.confirm`).
// Why the word choices: the user picks, among 3, the words the new device shows, instead of
// tapping Approve under words a server could swap.

/// What polling a sign-in request ended with (never `.pending` from `DeviceLoginFlow.wait`).
public enum DeviceLoginPoll: Equatable, Sendable {
    case pending
    /// Approved: the password sign-in's session answer plus `sealed_key`.
    case approved(session: JSON)
    /// Approved, but the account has two-step login and this device isn't remembered.
    case twoFactor(token: String, providers: [String])
    /// Denied, expired, already used or gone: `message` says so.
    case ended(message: String)
}

/// The new device's sign-in stopped for good (three wrong codes, or an approval that can't be
/// used): everything of it is dropped and the start screen shows `message`.
public struct DeviceLoginStopped: Error, LocalizedError, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// The new device's side, as plain data and wording.
public enum DeviceLogin {
    /// The `/api/config` feature.
    public static let feature = "login_with_device"
    /// The poll's header for the access code (never in the URL: proxies log query strings).
    public static let accessCodeHeader = "X-PassAuth-Access-Code"

    /// Seconds before each poll, then `maxDelay` after them.
    static let delays: [Double] = [2, 2, 2, 3, 3, 4, 5, 6, 8]
    public static let maxDelay: Double = 10
    /// Seconds to wait after a 429 that didn't say how long.
    public static let rateLimitWait: Double = 10
    /// How long a request lives on the server: the countdown and the wait never go past it from
    /// when the request was made, whatever the server's `expires_at` says.
    public static let requestLifetime: Double = 15 * 60
    /// The wait gives up this long after the request expired (the clocks may differ a little).
    public static let expiryGrace: Double = 60

    public static let link = "Sign in with another device"
    public static let title = "Sign in with another device"
    public static let intro = "Approve the sign-in on a device where you're already signed in to PassAuth. You don't need your master password here."
    public static let send = "Send request"
    public static let waitTitle = "Approve on your other device"
    public static let waiting = "Waiting for approval…"

    public static let denied = "The sign-in was denied on your other device."
    public static let expired = "The request expired. Start again to get new words."
    public static let used = "This request was already used. Start again."
    public static let gone = "This request is no longer valid. Start again."
    public static let disabled = "Your server doesn't allow signing in with another device."
    public static let unverified = "This approval couldn't be verified on this device. Start again."

    // The code step, after the approval arrived (and two-step login, when the account has it).
    public static let codeTitle = "Confirm the sign-in"
    public static let codePrompt = "Enter the 6-digit code shown on your other device."
    public static let codeLabel = "6-digit code"
    public static let codeConfirm = "Sign in"
    public static let tooManyCodes = "Too many wrong codes, so this sign-in was stopped. If you didn't approve it on your other device, change your master password."

    /// "That code doesn't match. 2 tries left."
    public static func wrongCode(left: Int) -> String {
        "That code doesn't match. \(left) \(left == 1 ? "try" : "tries") left."
    }

    /// The waiting screen's instruction.
    public static func waitText(email: String) -> String {
        "On a device where you're signed in as \(email), open PassAuth. When it asks which words this device shows, pick these:"
    }

    /// 32 random bytes in base64url without padding (43 characters): the code only this device knows.
    public static func accessCode() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw UserError("Couldn't make a random code on this device.")
        }
        return PasskeyLogic.b64url(Data(bytes))
    }

    /// Seconds to wait before poll number `attempt` (0-based).
    public static func pollDelay(attempt: Int) -> Double {
        attempt >= 0 && attempt < delays.count ? delays[attempt] : maxDelay
    }

    /// When a request made at `requestedAt` (unix seconds) expires as far as this device is
    /// concerned: the server's `expires_at` when it lies within the 15 minutes a request lives,
    /// else 15 minutes after it was made (client review F7: a server can't keep this device
    /// waiting longer).
    public static func deadline(serverExpiresAt: Int64?, requestedAt: Double) -> Int64 {
        let made = Int64(requestedAt.rounded(.down))
        let cap = made + Int64(requestLifetime)
        guard let e = serverExpiresAt, e > made, e <= cap else { return cap }
        return e
    }

    /// The time left until `expiresAt` (unix seconds) as "14:59", "0:05", never below "0:00".
    public static func countdown(expiresAt: Int64, now: Double) -> String {
        let left = max(0, expiresAt - Int64(now.rounded(.down)))
        return "\(left / 60):" + String(format: "%02d", Int(left % 60))
    }

    public static func expiresIn(expiresAt: Int64, now: Double) -> String {
        "Expires in \(countdown(expiresAt: expiresAt, now: now))"
    }

    /// `POST /auth/requests`: `device` is the password sign-in's `device` object.
    public static func requestBody(email: String, publicKey: String, accessCode: String, device: JSON, rememberToken: String?) -> JSON {
        var o: [String: JSON] = [
            "email": .string(email.trimmingCharacters(in: .whitespacesAndNewlines)),
            "public_key": .string(publicKey),
            "access_code": .string(accessCode),
            "device_id": .string(device["id"]?.string ?? ""),
            "device_name": .string(device["name"]?.string ?? ""),
            "device_kind": .string(device["kind"]?.string ?? ""),
        ]
        if let t = rememberToken, !t.isEmpty { o["remember_token"] = .string(t) }
        return .object(o)
    }

    /// An answer of `GET /auth/requests/{id}`. An unknown status counts as still pending (until it expires).
    public static func parsePoll(_ j: JSON) -> DeviceLoginPoll {
        switch j["status"]?.string {
        case "denied": return .ended(message: denied)
        case "expired": return .ended(message: expired)
        case "used": return .ended(message: used)
        case "approved":
            if j["two_factor_required"]?.bool == true {
                return .twoFactor(token: j.str("two_factor_token"), providers: (j["providers"]?.array ?? []).compactMap(\.string))
            }
            return .approved(session: j)
        default: return .pending
        }
    }

    /// A request id as the server makes them (a UUID): anything else never goes into a path.
    public static func isRequestId(_ id: String) -> Bool {
        (1...64).contains(id.count) && id.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
    }

    /// The server turned the feature off (403 `login_with_device_disabled`).
    public static func isDisabled(_ e: Error) -> Bool {
        guard let e = e as? ApiError else { return false }
        return e.status == 403 && e.hasCode("login_with_device_disabled")
    }

    /// Whether a Secret Key that came with another device's approval is kept on this device (client
    /// review F7): only for the email typed here (when the server's answer names the account, it
    /// must be that one, case aside), and never in place of a Secret Key already kept for it (the
    /// one kept stays). Store it under `typedEmail` lowercased.
    public static func keepsSecretKey(typedEmail: String, sessionEmail: String, stored: String?) -> Bool {
        let typed = typedEmail.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let answered = sessionEmail.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !typed.isEmpty, answered.isEmpty || answered == typed else { return false }
        return stored == nil
    }
}

/// The new device's requests to its server (no session).
public protocol DeviceLoginTransport: Sendable {
    /// `POST /auth/requests`.
    func create(_ body: JSON) async throws -> JSON
    /// `GET /auth/requests/{id}` with the access code in `DeviceLogin.accessCodeHeader`.
    func poll(id: String, accessCode: String) async throws -> JSON
}

/// The new device's requests through the app's API client (calls pinned to the account record):
/// no session, the access code in a header.
public struct ApiDeviceLoginTransport: DeviceLoginTransport {
    let api: ApiClient
    let accountId: String

    public init(api: ApiClient, accountId: String) {
        self.api = api
        self.accountId = accountId
    }

    public func create(_ body: JSON) async throws -> JSON {
        try await api.call(accountId, "/auth/requests", body: body, auth: false)
    }

    public func poll(id: String, accessCode: String) async throws -> JSON {
        try await api.call(accountId, "/auth/requests/\(id)", auth: false, headers: [DeviceLogin.accessCodeHeader: accessCode])
    }
}

/// One sign-in request of a new device: `start` it, show the words of the request's key, then
/// `wait` for the other device's answer (polling with growing delays, as long as it lives).
public struct DeviceLoginFlow: Sendable {
    /// A request the server took: its id and when it expires (unix seconds, at most 15 minutes
    /// after it was made: `DeviceLogin.deadline`).
    public struct Started: Equatable, Sendable {
        public let id: String
        public let expiresAt: Int64

        public init(id: String, expiresAt: Int64) {
            self.id = id
            self.expiresAt = expiresAt
        }
    }

    let transport: DeviceLoginTransport
    let now: @Sendable () -> Double
    let sleep: @Sendable (Double) async throws -> Void

    public init(transport: DeviceLoginTransport,
                now: @escaping @Sendable () -> Double = { Date().timeIntervalSince1970 },
                sleep: @escaping @Sendable (Double) async throws -> Void = { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) }) {
        self.transport = transport
        self.now = now
        self.sleep = sleep
    }

    /// Ask to sign in to `email` with the request key's `publicKey`; the server's
    /// `fingerprint_phrase` is never used (the words shown come from the key this device holds).
    public func start(email: String, publicKey: String, accessCode: String, device: JSON, rememberToken: String?) async throws -> Started {
        let requestedAt = now()
        let o: JSON
        do {
            o = try await transport.create(DeviceLogin.requestBody(email: email, publicKey: publicKey, accessCode: accessCode, device: device, rememberToken: rememberToken))
        } catch {
            if DeviceLogin.isDisabled(error) { throw UserError(DeviceLogin.disabled) }
            throw error
        }
        let id = o.str("id")
        guard DeviceLogin.isRequestId(id) else { throw UserError(DeviceLogin.gone) }
        return Started(id: id, expiresAt: DeviceLogin.deadline(serverExpiresAt: o["expires_at"]?.int, requestedAt: requestedAt))
    }

    /// Poll until the request ends: approved (with a session, or two-step login first) or
    /// `.ended`. Waits `DeviceLogin.pollDelay` before each poll, a 429's `Retry-After` when
    /// rate-limited; keeps going through network and server errors until the request is past
    /// its time (`expiresAt` plus a minute's grace, and never more than 16 minutes from now).
    /// Other errors (a disabled account, …) are thrown as they are, and so is cancellation (the
    /// user went back).
    public func wait(id: String, accessCode: String, expiresAt: Int64) async throws -> DeviceLoginPoll {
        let giveUpAt = min(Double(expiresAt), now() + DeviceLogin.requestLifetime) + DeviceLogin.expiryGrace
        var attempt = 0
        while true {
            try await sleep(DeviceLogin.pollDelay(attempt: attempt))
            attempt += 1
            try Task.checkCancellation()
            if now() > giveUpAt { return .ended(message: DeviceLogin.expired) }
            let answer: JSON
            do {
                answer = try await transport.poll(id: id, accessCode: accessCode)
            } catch is CancellationError {
                throw CancellationError()
            } catch let e as ApiError {
                if e.isRateLimited {
                    try await sleep(e.retryAfter.flatMap { $0 > 0 ? Double($0) : nil } ?? DeviceLogin.rateLimitWait)
                    continue
                }
                if e.status >= 500 { continue }
                if e.status == 404 { return .ended(message: DeviceLogin.gone) }
                if DeviceLogin.isDisabled(e) { return .ended(message: DeviceLogin.disabled) }
                throw e
            } catch is UserError {
                // The server couldn't be reached: try again with the next delay.
                continue
            } catch let e as URLError where e.code == .cancelled {
                throw CancellationError()
            }
            let poll = DeviceLogin.parsePoll(answer)
            if poll != .pending { return poll }
        }
    }
}

// MARK: The approving app

/// A sign-in request from a new device waiting for this account's answer (`GET /account/auth-requests`).
public struct AuthRequest: Identifiable, Equatable, Sendable {
    public let id: String
    /// The new device's X25519 key (base64url): the words are worked out from it here.
    public let publicKey: String
    /// A value sealed to this account's key; opening it proves the approval comes from an app
    /// that holds the keys. The server seals it anew for every listing (another ciphertext each
    /// time, the same value inside).
    public let challenge: String
    /// What `challenge` opens to with this account's key (the approval's proof), when the app
    /// could open it; what a later listing's challenge is compared by (`DeviceApprovals.sameRequest`).
    public let challengeProof: String?
    /// What the new device calls itself (it can claim anything: shown as such, cleaned).
    public let deviceName: String
    public let deviceKind: String
    /// The asking app (`X-PassAuth-Client`), when the server recorded it.
    public let client: String?
    /// The address the request came from, when the server keeps addresses.
    public let ip: String?
    public let createdAt: Int64
    public let expiresAt: Int64

    public init(id: String, publicKey: String, challenge: String, deviceName: String, deviceKind: String,
                client: String?, ip: String?, createdAt: Int64, expiresAt: Int64, challengeProof: String? = nil) {
        self.id = id
        self.publicKey = publicKey
        self.challenge = challenge
        self.challengeProof = challengeProof
        self.deviceName = deviceName
        self.deviceKind = deviceKind
        self.client = client
        self.ip = ip
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    /// This request with what its challenge opens to.
    public func withChallengeProof(_ proof: String?) -> AuthRequest {
        AuthRequest(id: id, publicKey: publicKey, challenge: challenge, deviceName: deviceName, deviceKind: deviceKind,
                    client: client, ip: ip, createdAt: createdAt, expiresAt: expiresAt, challengeProof: proof)
    }
}

/// The unlocked account's part of an approval (the core's `Account`; faked in tests).
public protocol ApprovalCrypto: Sendable {
    /// The account key, and `secretKey` when given, sealed to the request's public key for
    /// request `requestId`, with the code to show; only when `phrase` is the request key's own
    /// words (the core's `PhraseMismatch` otherwise).
    func approve(publicKey: String, requestId: String, phrase: String, secretKey: String?) throws -> LoginApproval
    /// The request's challenge opened with the account's private key.
    func proof(challenge: String, requestId: String) throws -> String
}

/// `ApprovalCrypto` with the unlocked account from the Rust core.
public struct AccountApprovalCrypto: ApprovalCrypto {
    let account: Account

    public init(account: Account) { self.account = account }

    public func approve(publicKey: String, requestId: String, phrase: String, secretKey: String?) throws -> LoginApproval {
        try account.approveLoginRequest(requesterPublicKey: publicKey, requestId: requestId, chosenPhrase: phrase, secretKey: secretKey)
    }

    public func proof(challenge: String, requestId: String) throws -> String {
        try account.openLoginChallenge(challenge: challenge, requestId: requestId)
    }
}

/// An approval ready for the server, and the code the new device needs.
public struct LoginApprovalAnswer: Equatable, Sendable {
    /// `{approve: true, sealed_key, proof}`.
    public let body: JSON
    /// 6 digits, shown on this device until Done.
    public let code: String
}

/// The approving app's side: reading the requests, answering one, and the sheet's wording.
public enum DeviceApprovals {
    public static let title = "Sign-in request"
    public static let question = "Which words does the new device show?"
    public static let questionFooter = "Pick the words you see on the new device. If they aren't here, choose None of these."
    public static let cannotCheck = "This request can't be checked, so it can only be denied."
    public static let noneOfThese = "None of these"
    public static let deny = "Deny"
    public static let notNow = "Not now"
    public static let sending = "Sending your answer…"
    public static let denied = "Sign-in denied."
    /// The user picked words that aren't the request key's: the request is denied.
    public static let mismatch = "Those aren't the words for this request, so it was denied."
    /// A later listing dropped the request or changed its key or challenge while it was shown.
    public static let changed = "This request changed, so it was closed. If you're signing in on a new device, start again there."
    public static let expiredHere = "This request expired. If you're signing in on a new device, start again there."
    /// The request's challenge doesn't open with this account's key (not made for it): not approved.
    public static let unverifiable = "This request can't be checked, so it wasn't approved. If you're signing in on a new device, start again there."
    public static let codeTitle = "Sign-in approved"
    public static let codeHeading = "Enter this code on the new device"
    public static let codeNote = "The new device needs it to finish signing in. It works only for this request."
    public static let done = "Done"
    public static let close = "Close"
    /// The header of the request's details, under the word choices.
    public static let aboutRequest = "About this request"
    public static let deviceLabel = "Device (as it calls itself)"
    public static let appLabel = "App"
    public static let ipLabel = "IP address"
    public static let notGiven = "Not given"

    /// The number of word choices (one is the request key's own).
    public static let choiceCount: UInt32 = 3
    /// The choices take taps only this long after the sheet's content appeared.
    public static let armDelay: Double = 1
    /// What a device claims about itself is shown up to this many characters.
    public static let claimedLimit = 64

    /// "A new device wants to sign in to alex@example.com."
    public static func body(email: String) -> String {
        "A new device wants to sign in to \(email)."
    }

    /// What the new device calls itself, as the app shows it (`ShownText`: no control or format
    /// characters, at most 64 characters), or "Not given".
    public static func deviceName(_ r: AuthRequest) -> String {
        let name = ShownText.clean(r.deviceName, limit: claimedLimit)
        return name.isEmpty ? notGiven : name
    }

    /// The asking app in the sessions screen's words, else its device kind; cleaned like the name.
    public static func app(_ r: AuthRequest) -> String {
        let app = ShownText.clean(SessionText.client(r.client) ?? SessionText.kind(r.deviceKind), limit: claimedLimit)
        return app.isEmpty ? notGiven : app
    }

    /// The address the server recorded, cleaned; nil when there is none.
    public static func ip(_ r: AuthRequest) -> String? {
        guard let ip = r.ip.map({ ShownText.clean($0, limit: claimedLimit) }), !ip.isEmpty else { return nil }
        return ip
    }

    /// "Just now", "1 minute ago", "3 minutes ago", "2 hours ago".
    public static func requested(createdAt: Int64, now: Double) -> String {
        let s = max(0, Int64(now.rounded(.down)) - createdAt)
        if s < 60 { return "Just now" }
        if s < 3600 { let m = s / 60; return "\(m) minute\(m == 1 ? "" : "s") ago" }
        let h = s / 3600
        return "\(h) hour\(h == 1 ? "" : "s") ago"
    }

    /// The code as shown: "123 456".
    public static func groupedCode(_ code: String) -> String {
        let digits = code.filter { $0.isASCII && $0.isNumber }
        guard digits.count == 6 else { return digits }
        return "\(digits.prefix(3)) \(digits.suffix(3))"
    }

    /// The words to choose from for a request, worked out here from the key this app holds
    /// (`loginPhraseChoices(key, 3)`: in random order, exactly one is the key's own; never the
    /// server's `fingerprint_phrase`). Made once, when the request's sheet opens. Empty when the
    /// key is malformed (or the core answers anything but 3 different phrases): then the
    /// request can only be denied.
    public static func choices(_ r: AuthRequest, make: (String, UInt32) throws -> [String] = { try loginPhraseChoices(publicKey: $0, count: $1) }) -> [String] {
        guard let list = try? make(r.publicKey, choiceCount), list.count == Int(choiceCount), Set(list).count == list.count,
              list.allSatisfy({ !$0.isEmpty }) else { return [] }
        return list
    }

    /// `{requests: [...]}`, read leniently: entries without what an answer needs (an id, the key,
    /// the challenge) or already expired are left out; newest first. The server's
    /// `fingerprint_phrase` is never read.
    public static func parse(_ value: JSON?, now: Double) -> [AuthRequest] {
        let list = value?["requests"]?.array ?? []
        let out: [AuthRequest] = list.compactMap { o in
            guard case .object = o else { return nil }
            func text(_ key: String) -> String? { o[key]?.string }
            func number(_ key: String) -> Int64? {
                switch o[key] {
                case .int(let n)?: n
                case .double(let x)? where x.isFinite && abs(x) < 1e15: Int64(x)
                default: nil
                }
            }
            guard let id = text("id"), DeviceLogin.isRequestId(id),
                  let key = text("public_key"), !key.isEmpty,
                  let challenge = text("challenge"), !challenge.isEmpty,
                  let expiresAt = number("expires_at"), Double(expiresAt) > now else { return nil }
            let client = text("client")?.trimmingCharacters(in: .whitespaces)
            let ip = text("ip")?.trimmingCharacters(in: .whitespaces)
            return AuthRequest(id: id, publicKey: key, challenge: challenge, deviceName: text("device_name") ?? "", deviceKind: text("device_kind") ?? "",
                               client: client?.isEmpty == false ? client : nil, ip: ip?.isEmpty == false ? ip : nil,
                               createdAt: number("created_at") ?? 0, expiresAt: expiresAt)
        }
        return out.enumerated().sorted { a, b in
            a.element.createdAt != b.element.createdAt ? a.element.createdAt > b.element.createdAt : a.offset < b.offset
        }.map(\.element)
    }

    /// Approving with the words the user picked: the account key (with the Secret Key this app
    /// keeps, so the new device can unlock with the master password later) sealed to the
    /// frozen request's key, its challenge opened as proof, and the code to show. The core
    /// refuses (`PhraseMismatch`) unless `phrase` is that key's own words: nothing is sent then.
    public static func approval(_ r: AuthRequest, phrase: String, crypto: ApprovalCrypto, secretKey: String?) throws -> LoginApprovalAnswer {
        let a = try crypto.approve(publicKey: r.publicKey, requestId: r.id, phrase: phrase, secretKey: secretKey)
        let proof = try crypto.proof(challenge: r.challenge, requestId: r.id)
        return LoginApprovalAnswer(body: ["approve": true, "sealed_key": .string(a.sealed), "proof": .string(proof)], code: a.code)
    }

    /// Denying needs no keys.
    public static let denyBody: JSON = ["approve": false]

    /// Whether a later listing still lists the request frozen on the sheet as it was: the same
    /// key, and the same challenge. The server seals the challenge anew for every listing, so it
    /// is compared by what it opens to when the app could open it (a server can't swap either
    /// in place unseen); else as listed.
    public static func sameRequest(_ shown: AuthRequest, _ listed: AuthRequest) -> Bool {
        guard shown.id == listed.id, shown.publicKey == listed.publicKey else { return false }
        if shown.challengeProof != nil || listed.challengeProof != nil { return shown.challengeProof == listed.challengeProof }
        return shown.challenge == listed.challenge
    }

    /// The core said the picked words aren't the request key's.
    public static func isPhraseMismatch(_ e: Error) -> Bool {
        if case .PhraseMismatch? = e as? CoreError { return true }
        return false
    }

    /// Plain words for an answer that didn't go through: refused by the server, or a request the
    /// account's keys can't answer (its challenge doesn't open); nil for any other error.
    public static func errorMessage(_ e: Error) -> String? {
        if e is CoreError { return isPhraseMismatch(e) ? mismatch : unverifiable }
        guard let e = e as? ApiError else { return nil }
        if e.status == 409 { return "This request was already answered on another device." }
        if e.status == 400 && e.hasCode("expired") { return "This request expired." }
        if e.status == 404 { return "This request is no longer there." }
        return nil
    }
}

/// A request on the approval sheet, frozen as it was when the sheet opened (client review F1):
/// the words, the choices and the answer all come from this copy, never from a newer listing.
public struct ShownApproval: Identifiable, Equatable, Sendable {
    public enum Phase: Equatable, Sendable {
        /// Waiting for the user's pick.
        case choosing
        /// The answer is on its way to the server.
        case sending
        /// Approved: the code for the new device, shown until Done.
        case code(String)
        /// Closed without (or after a failed) answer from here: why, shown until Close.
        case closed(String)
    }

    public let request: AuthRequest
    /// The three phrases to pick from, made once (`DeviceApprovals.choices`); empty when the
    /// request can't be checked (then only Deny).
    public let choices: [String]
    public fileprivate(set) var phase: Phase

    public var id: String { request.id }
}

/// The requests to show, one at a time (client review F1): the shown one stays frozen, newer
/// ones wait their turn, and a listing that changes or drops the shown one while the user is
/// choosing closes it. Requests closed here (Not now, answered, changed) aren't shown again
/// in this run (they expire on the server).
public struct ApprovalQueue: Equatable, Sendable {
    public private(set) var shown: ShownApproval?
    /// From the latest listing, newest first, without the shown one.
    public private(set) var waiting: [AuthRequest] = []
    public private(set) var hidden: Set<String> = []

    public init() {}

    /// A fresh listing from the server (newest first). Nothing in it changes the shown request:
    /// while the user is choosing, a listing that lists it with another key or challenge
    /// (`DeviceApprovals.sameRequest`), or doesn't list it any more, closes it
    /// (`DeviceApprovals.changed`; one past its time says it expired). Once the answer is sent,
    /// listings don't touch it.
    public mutating func listed(_ fresh: [AuthRequest], now: Double, choices: (AuthRequest) -> [String]) {
        if var s = shown, s.phase == .choosing {
            if let same = fresh.first(where: { $0.id == s.request.id }) {
                if !DeviceApprovals.sameRequest(s.request, same) {
                    s.phase = .closed(DeviceApprovals.changed)
                }
            } else {
                s.phase = .closed(Double(s.request.expiresAt) <= now ? DeviceApprovals.expiredHere : DeviceApprovals.changed)
            }
            shown = s
        }
        waiting = fresh.filter { $0.id != shown?.request.id && !hidden.contains($0.id) && Double($0.expiresAt) > now }
        showNext(now: now, choices: choices)
    }

    /// The user's answer to request `id` leaves for the server (only while it is shown and being
    /// decided); the frozen request to send it for.
    public mutating func send(_ id: String) -> AuthRequest? {
        guard var s = shown, s.request.id == id, s.phase == .choosing else { return nil }
        s.phase = .sending
        shown = s
        return s.request
    }

    /// How the answer for request `id` ended: the code to show, or why it closed.
    public mutating func answered(_ id: String, _ phase: ShownApproval.Phase) {
        guard var s = shown, s.request.id == id else { return }
        s.phase = phase
        shown = s
    }

    /// The user closes the sheet of request `id` (Not now, Done, Close): it isn't shown again in
    /// this run, and the next request comes up. Not while the answer is on its way.
    public mutating func close(_ id: String, now: Double, choices: (AuthRequest) -> [String]) {
        guard let s = shown, s.request.id == id, s.phase != .sending else { return }
        remove(id, now: now, choices: choices)
    }

    /// Request `id` leaves the sheet (denied here, answered elsewhere): hidden for this run.
    public mutating func remove(_ id: String, now: Double, choices: (AuthRequest) -> [String]) {
        hidden.insert(id)
        waiting.removeAll { $0.id == id }
        if shown?.request.id == id { shown = nil }
        showNext(now: now, choices: choices)
    }

    /// Answered on another device (live sync): a request still being decided here closes; a
    /// waiting one is dropped. After this device sent its own answer, nothing changes (the
    /// server tells every device, this one too).
    public mutating func answeredElsewhere(_ id: String, now: Double, choices: (AuthRequest) -> [String]) {
        if let s = shown, s.request.id == id, s.phase != .choosing {
            hidden.insert(id)
            return
        }
        remove(id, now: now, choices: choices)
    }

    /// Locked, signed out or another account: nothing to show (hidden ids stay hidden).
    public mutating func clear() {
        shown = nil
        waiting = []
    }

    /// With nothing shown, the newest waiting request opens, frozen with its choices.
    private mutating func showNext(now: Double, choices: (AuthRequest) -> [String]) {
        guard shown == nil else { return }
        while !waiting.isEmpty {
            let next = waiting.removeFirst()
            guard Double(next.expiresAt) > now, !hidden.contains(next.id) else { continue }
            shown = ShownApproval(request: next, choices: choices(next), phase: .choosing)
            return
        }
    }
}
