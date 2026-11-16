import Foundation
import Observation
import PassAuthCore

/// A sign-in request this device made and is waiting on (memory only; its key never leaves the
/// Rust core and dies with the process).
struct PendingDeviceLogin: Sendable {
    let key: LoginRequestKey
    let id: String
    let accessCode: String
    /// The email typed on this device: the only one a received Secret Key is kept for.
    let email: String
    let expiresAt: Int64
    /// The account record the request was made from (the active one at the time).
    let record: String
}

/// An approval that arrived for this device's request, held in memory until the user enters the
/// code the other device shows (`confirmDeviceLogin`): the core keeps the account key and the
/// Secret Key locked until then, and the session's tokens are stored only after it.
struct ApprovedDeviceLogin: Sendable {
    let approved: ApprovedLogin
    let request: PendingDeviceLogin
    /// The approved session answer (tokens, bundle, email, remember token).
    let session: JSON
}

/// What the waiting screen shows for a request: the words come from this device's own key.
public struct DeviceLoginRequest: Equatable, Sendable {
    public let id: String
    public let email: String
    public let phrase: String
    public let expiresAt: Int64
}

/// What follows an approval of this device's request.
public enum DeviceLoginStep: Equatable, Sendable {
    /// Enter the code the other device shows (`confirmDeviceLogin`).
    case enterCode
    /// Two-step login first (`verifyTwoFactor`), then the code.
    case twoFactor(token: String, providers: [String])
}

/// What a finished two-step login leads to.
public enum TwoStepNext: Equatable, Sendable {
    case signedIn
    /// The sign-in was approved by another device: enter its code (`confirmDeviceLogin`).
    case enterDeviceCode
}

// MARK: Sign in with another device: the new device

extension VaultRepository {
    /// Whether the active record's server offers signing in with another device (`/api/config`
    /// `features` has `login_with_device`); false when it can't be asked.
    public func deviceLoginAvailable() async -> Bool {
        await publicConfig()?.features.contains(DeviceLogin.feature) ?? false
    }

    /// Ask to sign in to `email` with another device's approval: a key pair made for this request
    /// (`LoginRequestKey`), a random access code only this device knows, `POST /auth/requests`.
    /// Returns what the waiting screen shows; then `awaitDeviceLogin`.
    public func beginDeviceLogin(email: String) async throws -> DeviceLoginRequest {
        let mail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard mail.contains("@") else { throw UserError("Enter the email address of your account.") }
        dropDeviceLogin()
        let id = activeId
        let s = store.get()
        let key = try await core { try LoginRequestKey.generate() }
        let code = try DeviceLogin.accessCode()
        // This device's "remember me" token for the account skips two-step login, as when signing in with the password.
        let remember = s.secrets.rememberTokens[Self.rememberKey(server: s.file.accounts[id]?.server ?? "", email: mail)]
        let flow = DeviceLoginFlow(transport: ApiDeviceLoginTransport(api: api, accountId: id))
        let started = try await flow.start(email: mail, publicKey: key.publicKey(), accessCode: code, device: deviceInfo, rememberToken: remember)
        pendingDevice = PendingDeviceLogin(key: key, id: started.id, accessCode: code, email: mail, expiresAt: started.expiresAt, record: id)
        return DeviceLoginRequest(id: started.id, email: mail, phrase: key.phrase(), expiresAt: started.expiresAt)
    }

    /// Wait for the other device's answer to the request `beginDeviceLogin` made (polling, see
    /// `DeviceLoginFlow`). Approved: the code step comes next (`.enterCode`), or two-step login
    /// first (`.twoFactor`, then `verifyTwoFactor`). Denied, expired, used or gone: a `UserError`
    /// saying so. Cancelling the task (the user went back) stops it.
    public func awaitDeviceLogin() async throws -> DeviceLoginStep {
        guard let p = pendingDevice else { throw UserError(DeviceLogin.gone) }
        let transport = ApiDeviceLoginTransport(api: api, accountId: p.record)
        let flow = deviceLoginSleep.map { DeviceLoginFlow(transport: transport, sleep: $0) } ?? DeviceLoginFlow(transport: transport)
        let answer: DeviceLoginPoll
        do {
            answer = try await flow.wait(id: p.id, accessCode: p.accessCode, expiresAt: p.expiresAt)
        } catch {
            forgetPending(p)
            throw error
        }
        switch answer {
        case .pending:
            forgetPending(p)
            throw UserError(DeviceLogin.gone)
        case .ended(let message):
            forgetPending(p)
            throw UserError(message)
        case .twoFactor(let token, let providers):
            return .twoFactor(token: token, providers: providers)
        case .approved(let session):
            try await lock.run { try await receiveDeviceApproval(p, session) }
            return .enterCode
        }
    }

    /// Stop (back, Cancel, or another way of signing in): the request key and any approval that
    /// arrived are dropped, and a session the server already made for it is signed out.
    public func cancelDeviceLogin() {
        dropDeviceLogin()
    }

    /// Whether an approval waits for its code (`confirmDeviceLogin`).
    public var deviceCodePending: Bool { approvedDevice != nil }

    /// Check the code the other device shows. Right: unlocked and signed in like a password
    /// sign-in. Wrong: a `UserError` with the tries left. The third wrong code (or an approval
    /// that turns out unusable) ends it all: the session is signed out, the keys are dropped, and
    /// `DeviceLoginStopped` says why (the start screen shows it).
    public func confirmDeviceLogin(code: String) async throws {
        try await lock.run {
            guard let a = approvedDevice else { throw DeviceLoginStopped(DeviceLogin.gone) }
            do {
                try a.approved.confirm(code: code)
            } catch let e as CoreError {
                switch e {
                case .WrongCode:
                    throw UserError(DeviceLogin.wrongCode(left: Int(a.approved.attemptsLeft())))
                case .Invalid:
                    // Not 6 digits: not counted.
                    throw UserError(DeviceLogin.codePrompt)
                case .TooManyWrongCodes:
                    dropDeviceLogin()
                    throw DeviceLoginStopped(DeviceLogin.tooManyCodes)
                default:
                    dropDeviceLogin()
                    throw DeviceLoginStopped(DeviceLogin.unverified)
                }
            }
            approvedDevice = nil
            try await finishDeviceLogin(a)
        }
    }

    /// The request is over: forget it (only if it's still the current one).
    private func forgetPending(_ p: PendingDeviceLogin) {
        if pendingDevice?.id == p.id { pendingDevice = nil }
    }

    /// Everything of a device sign-in in progress goes: the request key, and an approval with its
    /// session (signed out on the server, best effort).
    func dropDeviceLogin() {
        pendingDevice = nil
        if let a = approvedDevice {
            approvedDevice = nil
            discardSession(a.request.record, a.session)
        }
    }

    /// Sign out a session the server made for an approval this device won't use (best effort, in
    /// the background: nothing of it was stored).
    private func discardSession(_ record: String, _ result: JSON) {
        let access = result.str("access_token")
        guard !access.isEmpty, let server = store.get().file.accounts[record]?.server, !server.isEmpty else { return }
        let tokens = Tokens(access: access, refresh: result.str("refresh_token"))
        let api = self.api
        Task { await api.logoutRemote(server: server, tokens: tokens) }
    }

    /// The approved session (the poll's answer, or two-step login's): open the sealed account key
    /// with this request's key, and hold it until the code is confirmed. Nothing is stored yet.
    /// Callers hold the repository's lock.
    func receiveDeviceApproval(_ p: PendingDeviceLogin, _ result: JSON) async throws {
        guard pendingDevice?.id == p.id else {
            discardSession(p.record, result)
            throw UserError(DeviceLogin.gone)
        }
        pendingDevice = nil
        let sealed = result.str("sealed_key"), userId = result.str("user_id")
        let key = p.key, requestId = p.id
        let approved: ApprovedLogin
        do {
            approved = try await core { try key.open(sealed: sealed, accountId: userId, requestId: requestId) }
        } catch is CoreError {
            // Sealed for another key, account or request, or changed on the way: nothing is kept.
            discardSession(p.record, result)
            throw UserError(DeviceLogin.unverified)
        }
        approvedDevice = ApprovedDeviceLogin(approved: approved, request: p, session: result)
    }

    /// After the code was confirmed: unlock the bundle without the master password and finish as
    /// a password sign-in does. A Secret Key that came along is kept only for the email typed
    /// here, and never in place of another one kept for it (`DeviceLogin.keepsSecretKey`).
    /// Callers hold the repository's lock.
    private func finishDeviceLogin(_ a: ApprovedDeviceLogin) async throws {
        let p = a.request, result = a.session
        let bundle = (result["bundle"] ?? .null).text
        let approved = a.approved
        let opened: (Account, String?)
        do {
            opened = try await core { () -> (Account, String?) in (try approved.unlock(bundleJson: bundle), try approved.secretKey()) }
        } catch is CoreError {
            discardSession(p.record, result)
            throw DeviceLoginStopped(DeviceLogin.unverified)
        }
        let server = store.get().file.accounts[p.record]?.server ?? ""
        let typed = p.email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let answered = result.str("email")
        store.update { s in
            if let t = result["remember_token"]?.string, !t.isEmpty { s.secrets.rememberTokens[Self.rememberKey(server: server, email: typed)] = t }
            if let sk = opened.1, DeviceLogin.keepsSecretKey(typedEmail: typed, sessionEmail: answered, stored: s.secrets.secretKeys[typed]) {
                s.secrets.secretKeys[typed] = sk
            }
        }
        finishSession(p.record, account: opened.0, result)
        try? await syncLocked()
        afterOpen()
    }

    nonisolated static func rememberKey(server: String, email: String) -> String {
        "\(server)|\(email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())"
    }
}

// MARK: Sign in with another device: the approving app

extension VaultRepository: AuthRequestSource {
    /// The active account's open sign-in requests (`GET /account/auth-requests`), read leniently;
    /// nil when there is nothing to ask: not the app, the account locked, or a server without
    /// `login_with_device`. Errors are thrown (the list shown stays as it is).
    public func listAuthRequests() async throws -> [AuthRequest]? {
        let id = activeId
        guard isApp, sessions[id] != nil, !state.twoStepRequired else { return nil }
        var features = store.get().file.accounts[id]?.features
        if features == nil { features = await fetchConfig(id)?.features }
        guard features?.contains(DeviceLogin.feature) == true else { return nil }
        let j = try await api.call(id, "/account/auth-requests")
        // Still the same unlocked account after the request.
        guard activeId == id, let session = sessions[id] else { return nil }
        let listed = DeviceApprovals.parse(j, now: Date().timeIntervalSince1970)
        // Each challenge opened here, so a shown request is compared by what it holds (the
        // server seals it anew for every listing).
        let account = session.account
        return try await core {
            listed.map { $0.withChallengeProof(try? account.openLoginChallenge(challenge: $0.challenge, requestId: $0.id)) }
        }
    }

    /// Approve the frozen request `r` with the words the user picked (`approveLoginRequest`,
    /// with the Secret Key this device keeps, and the opened challenge as proof), for the
    /// unlocked active account. Returns the code for the new device. Words that aren't the
    /// request's: the core's `PhraseMismatch`, and nothing is sent.
    public func approveAuthRequest(_ r: AuthRequest, phrase: String) async throws -> String {
        let id = activeId
        guard let session = sessions[id] else { throw UserError("Unlock your vault first.") }
        let s = store.get()
        let secretKey = s.file.accounts[id].flatMap { s.secrets.secretKeys[$0.email.lowercased()] }
        let crypto = AccountApprovalCrypto(account: session.account)
        let answer = try await core { try DeviceApprovals.approval(r, phrase: phrase, crypto: crypto, secretKey: secretKey) }
        guard activeId == id, sessions[id] != nil else { throw UserError("Unlock your vault first.") }
        _ = try await api.call(id, "/account/auth-requests/\(r.id)", body: answer.body)
        return answer.code
    }

    /// Deny request `r` for the active account (no keys needed).
    public func denyAuthRequest(_ r: AuthRequest) async throws {
        let id = activeId
        guard store.get().tokens(id) != nil else { throw UserError("Sign in first.") }
        _ = try await api.call(id, "/account/auth-requests/\(r.id)", body: DeviceApprovals.denyBody)
    }
}

/// Where the inbox gets requests and sends answers (the repository; faked in tests).
@MainActor
public protocol AuthRequestSource: AnyObject {
    /// The active account's open requests, or nil when there is nothing to ask (locked, no feature).
    func listAuthRequests() async throws -> [AuthRequest]?
    /// Approve with the picked words; returns the code to show (`PhraseMismatch` when they aren't the request's).
    func approveAuthRequest(_ r: AuthRequest, phrase: String) async throws -> String
    func denyAuthRequest(_ r: AuthRequest) async throws
}

/// Sign-in requests from new devices waiting for this app's answer (the approving side of "sign
/// in with another device"): listed after unlock, whenever live sync (re)connects and when the
/// socket says one arrived; shown one at a time, frozen (`ApprovalQueue`); dropped when answered
/// anywhere. Only the app lists them, never the AutoFill extensions.
@MainActor
@Observable
public final class AuthRequestInbox {
    public private(set) var queue = ApprovalQueue()
    @ObservationIgnored private weak var source: AuthRequestSource?
    @ObservationIgnored private let now: () -> Double
    @ObservationIgnored private let makeChoices: (AuthRequest) -> [String]
    /// Bumped by `clear`: a listing or answer that started before (another account, locked) is dropped.
    @ObservationIgnored private var generation = 0

    public init(source: AuthRequestSource, now: @escaping () -> Double = { Date().timeIntervalSince1970 },
                choices: @escaping (AuthRequest) -> [String] = { DeviceApprovals.choices($0) }) {
        self.source = source
        self.now = now
        self.makeChoices = choices
    }

    /// The request on the sheet, frozen.
    public var shown: ShownApproval? { queue.shown }

    /// Ask the server again; nothing to ask (locked, no feature) empties the list, an error keeps it.
    public func refresh() async {
        guard let source else { return }
        let started = generation
        do {
            let fresh = try await source.listAuthRequests()
            guard started == generation else { return }
            if let fresh { queue.listed(fresh, now: now(), choices: makeChoices) } else { queue.clear() }
        } catch {}
    }

    /// Answered on another device (live sync).
    public func answered(_ id: String) { queue.answeredElsewhere(id, now: now(), choices: makeChoices) }

    /// Not now, Done or Close on request `id`'s sheet: it goes (and isn't shown again in this run).
    public func close(_ id: String) { queue.close(id, now: now(), choices: makeChoices) }

    /// Locked, signed out or another account: nothing to show.
    public func clear() {
        generation += 1
        queue.clear()
    }

    /// The user picked `phrase` as the words the new device shows for request `id`. Its words:
    /// approved, and the sheet shows the code until Done. Other words: the request is denied and
    /// the sheet says so. Anything else (refused, offline): the sheet says why.
    public func choose(_ phrase: String, for id: String) async {
        guard let r = queue.send(id) else { return }
        let started = generation
        do {
            guard let source else { throw UserError("Unlock your vault first.") }
            let code = try await source.approveAuthRequest(r, phrase: phrase)
            guard started == generation else { return }
            queue.answered(r.id, .code(code))
        } catch {
            guard started == generation else { return }
            if DeviceApprovals.isPhraseMismatch(error) {
                try? await source?.denyAuthRequest(r)
                guard started == generation else { return }
                queue.answered(r.id, .closed(DeviceApprovals.mismatch))
            } else {
                queue.answered(r.id, .closed(DeviceApprovals.errorMessage(error) ?? errorMessage(error)))
            }
        }
    }

    /// "None of these" (or Deny for a request that can't be checked) on request `id`: denied on
    /// the server; the sheet closes either way. Returns what to tell the user.
    public func deny(_ id: String) async -> String? {
        guard let r = queue.send(id) else { return nil }
        let started = generation
        var notice = DeviceApprovals.denied
        do {
            guard let source else { throw UserError("Unlock your vault first.") }
            try await source.denyAuthRequest(r)
        } catch {
            notice = DeviceApprovals.errorMessage(error) ?? errorMessage(error)
        }
        guard started == generation else { return nil }
        queue.remove(r.id, now: now(), choices: makeChoices)
        return notice
    }
}
