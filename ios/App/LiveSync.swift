import Foundation
import PassAuthKit

/// Live sync while the app is on screen: a WebSocket to the active account's server
/// (`/api/ws?access_token=…`), connected only while the scene is active and the active account
/// is unlocked. A change the copy doesn't have yet (a newer vault number, or a profile change)
/// refreshes the vault without pull-to-refresh, through the repository's sync queue (one sync
/// running, one waiting), with delta sync where the server has it. Reconnects with
/// backoff (1 s doubling to 60 s, jitter); each reconnect first goes through the normal API
/// (`/sync/revision`), which refreshes an expired access token and catches up. A server that
/// now requires two-step login first says so on the socket (`two_step_required`, then close code
/// 1008): the loop stops and the app shows the two-step setup screen; it starts again once the
/// account may use the vault.
@MainActor
final class LiveSync {
    private let repo: VaultRepository
    /// Sign-in requests from new devices: listed when the socket opens and when one arrives.
    private let inbox: AuthRequestInbox
    private var target: String?
    private var loop: Task<Void, Never>?
    /// This socket session's live-sync origin (its `hello`). Not used to skip messages: tabs and
    /// processes sharing a session share it, so the vault numbers decide instead.
    private(set) var origin: String?

    private let events = SocketEvents()
    private let sockets: URLSession

    init(repo: VaultRepository, inbox: AuthRequestInbox) {
        self.repo = repo
        self.inbox = inbox
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        sockets = URLSession(configuration: config, delegate: events, delegateQueue: nil)
    }

    /// Call when the scene phase, the active account or its lock state changes.
    func update(foreground: Bool) {
        let s = repo.state
        // The server refuses the socket too while it requires two-step setup first.
        let want = foreground && s.status == .unlocked && !s.twoStepRequired && !s.activeId.isEmpty ? s.activeId : nil
        guard want != target else { return }
        loop?.cancel()
        loop = nil
        target = want
        if let id = want {
            loop = Task { [weak self] in await self?.connectLoop(id) }
        }
    }

    /// How a socket session ended.
    private enum Ended { case failed, closed, twoStepRequired }

    private func connectLoop(_ id: String) async {
        var attempt = 0
        while !Task.isCancelled {
            switch await session(id) {
            case .twoStepRequired:
                // Never reconnect in a loop: the gate's screen stops live sync (`update`), and
                // it starts again when the gate lifts.
                repo.twoStepRequiredBySocket(id)
                return
            case .closed: attempt = 0
            case .failed: break
            }
            if Task.isCancelled { return }
            let wait = LiveSyncProtocol.backoffMillis(attempt: attempt, jitter: Double.random(in: 0...1))
            attempt += 1
            try? await Task.sleep(nanoseconds: UInt64(wait) * 1_000_000)
            if Task.isCancelled { return }
            await repo.refreshIfStale()
        }
    }

    /// One connection; returns when it closes.
    private func session(_ id: String) async -> Ended {
        let s = repo.store.get()
        guard let a = s.file.accounts[id], let tokens = s.tokens(id),
              let url = LiveSyncProtocol.socketURL(server: a.server, accessToken: tokens.access) else { return .failed }
        var request = URLRequest(url: url)
        request.setValue(ApiClient.clientHeader, forHTTPHeaderField: ApiClient.clientHeaderName)
        let socket = sockets.webSocketTask(with: request)
        let open = events.opened(socket)
        socket.resume()
        var opened = false
        var twoStep = false
        await withTaskCancellationHandler {
            // A 401 (expired access token) or an unreachable server fails the handshake.
            guard await open.value else { return }
            opened = true
            // Catch up on anything missed while disconnected, sign-in requests included.
            await repo.refreshIfStale()
            await inbox.refresh()
            let pinger = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 25_000_000_000)
                    if Task.isCancelled { return }
                    if await Self.pingFailed(socket) { socket.cancel(with: .goingAway, reason: nil); return }
                }
            }
            defer { pinger.cancel() }
            while !Task.isCancelled {
                guard let message = try? await socket.receive() else { break }
                guard case .string(let text) = message else { continue }
                let msg = LiveSyncProtocol.parse(text)
                if case .hello(let o)? = msg { origin = o }
                switch LiveSyncProtocol.action(msg, have: repo.syncPosition) {
                case .sync: try? await repo.sync()
                case .checkSession: await repo.checkSession()
                case .listAuthRequests: await inbox.refresh()
                case .authRequestAnswered(let id): inbox.answered(id)
                case .twoStepRequired: twoStep = true
                case .ignore: break
                }
                if twoStep { break }
            }
        } onCancel: {
            socket.cancel(with: .goingAway, reason: nil)
        }
        if LiveSyncProtocol.closedForTwoStep(code: socket.closeCode.rawValue, reason: socket.closeReason) { twoStep = true }
        socket.cancel(with: .goingAway, reason: nil)
        return twoStep ? .twoStepRequired : opened ? .closed : .failed
    }

    /// A ping that reports an error (connection gone). Answers are not waited for: the server
    /// sends pongs along with its next frame.
    private nonisolated static func pingFailed(_ socket: URLSessionWebSocketTask) async -> Bool {
        await withCheckedContinuation { c in
            let once = Once()
            socket.sendPing { error in once.run { c.resume(returning: error != nil) } }
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) { once.run { c.resume(returning: false) } }
        }
    }
}

/// The sockets' own session (ephemeral, redirects refused), reporting when a handshake
/// succeeded or failed.
private final class SocketEvents: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var waiting: [Int: (Bool) -> Void] = [:]

    /// Resolves to true once the socket is open, false if it fails or takes over 20 s.
    func opened(_ task: URLSessionWebSocketTask) -> Task<Bool, Never> {
        let id = task.taskIdentifier
        let result = OpenResult()
        lock.lock()
        waiting[id] = { result.set($0) }
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + 20) { self.finish(id, false) }
        return Task { await result.value }
    }

    private func finish(_ id: Int, _ ok: Bool) {
        lock.lock()
        let done = waiting.removeValue(forKey: id)
        lock.unlock()
        done?(ok)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        finish(webSocketTask.taskIdentifier, true)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(task.taskIdentifier, false)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// A handshake result that may arrive before or after someone waits for it.
private final class OpenResult: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Bool?
    private var waiter: CheckedContinuation<Bool, Never>?

    func set(_ ok: Bool) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = ok
        let w = waiter
        waiter = nil
        lock.unlock()
        w?.resume(returning: ok)
    }

    var value: Bool {
        get async {
            await withCheckedContinuation { c in
                lock.lock()
                if let r = result {
                    lock.unlock()
                    c.resume(returning: r)
                } else {
                    waiter = c
                    lock.unlock()
                }
            }
        }
    }
}

/// Runs its body at most once (from any thread).
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func run(_ body: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { body() }
    }
}
