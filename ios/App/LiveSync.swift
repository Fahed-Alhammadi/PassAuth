import Foundation
import PassAuthKit

/// Live sync while the app is on screen: a WebSocket to the active account's server
/// (`/api/ws?access_token=…`), connected only while the scene is active and the active account
/// is unlocked. A newer revision refreshes the vault without pull-to-refresh. Reconnects with
/// backoff (1 s doubling to 60 s, jitter); each reconnect first goes through the normal API
/// (`/sync/revision`), which refreshes an expired access token and catches up.
@MainActor
final class LiveSync {
    private let repo: VaultRepository
    private var target: String?
    private var loop: Task<Void, Never>?

    private let events = SocketEvents()
    private let sockets: URLSession

    init(repo: VaultRepository) {
        self.repo = repo
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        sockets = URLSession(configuration: config, delegate: events, delegateQueue: nil)
    }

    /// Call when the scene phase, the active account or its lock state changes.
    func update(foreground: Bool) {
        let s = repo.state
        let want = foreground && s.status == .unlocked && !s.activeId.isEmpty ? s.activeId : nil
        guard want != target else { return }
        loop?.cancel()
        loop = nil
        target = want
        if let id = want {
            loop = Task { [weak self] in await self?.connectLoop(id) }
        }
    }

    private func connectLoop(_ id: String) async {
        var attempt = 0
        while !Task.isCancelled {
            if await session(id) { attempt = 0 }
            if Task.isCancelled { return }
            let wait = LiveSyncProtocol.backoffMillis(attempt: attempt, jitter: Double.random(in: 0...1))
            attempt += 1
            try? await Task.sleep(nanoseconds: UInt64(wait) * 1_000_000)
            if Task.isCancelled { return }
            await repo.refreshIfStale()
        }
    }

    /// One connection; returns when it closes (true if it had opened).
    private func session(_ id: String) async -> Bool {
        let s = repo.store.get()
        guard let a = s.file.accounts[id], let tokens = s.tokens(id),
              let url = LiveSyncProtocol.socketURL(server: a.server, accessToken: tokens.access) else { return false }
        let socket = sockets.webSocketTask(with: url)
        let open = events.opened(socket)
        socket.resume()
        var opened = false
        await withTaskCancellationHandler {
            // A 401 (expired access token) or an unreachable server fails the handshake.
            guard await open.value else { return }
            opened = true
            // Catch up on anything missed while disconnected.
            await repo.refreshIfStale()
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
                switch LiveSyncProtocol.action(msg, currentRevision: repo.vault?.revision) {
                case .sync: try? await repo.sync()
                case .checkSession: await repo.checkSession()
                case .ignore: break
                }
            }
        } onCancel: {
            socket.cancel(with: .goingAway, reason: nil)
        }
        socket.cancel(with: .goingAway, reason: nil)
        return opened
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
