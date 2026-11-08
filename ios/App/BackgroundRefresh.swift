import BackgroundTasks
import PassAuthKit
import UIKit

/// Background App Refresh: refreshes every signed-in account's encrypted offline copy
/// (`VaultRepository.refreshCacheLocked`) about every `Settings.backgroundSyncMinutes` minutes;
/// iOS decides the actual timing. Scheduled when the app goes to the background, when the
/// setting changes and after each run; cancelled when the setting is off or no account is
/// signed in.
@MainActor
final class BackgroundRefresh {
    nonisolated static let identifier = "io.passauth.app.refresh"
    /// The instance handling launches: the handler is registered at launch (AppDelegate),
    /// before the model exists.
    static weak var current: BackgroundRefresh?

    private let repo: VaultRepository
    private var pending: BGAppRefreshTask?
    private var running: Task<Void, Never>?

    init(repo: VaultRepository) { self.repo = repo }

    /// Call before the app finishes launching.
    nonisolated static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            guard let task = task as? BGAppRefreshTask else { return }
            nonisolated(unsafe) let refresh = task
            Task { @MainActor in
                guard let current else { return refresh.setTaskCompleted(success: false) }
                current.handle(refresh)
            }
        }
    }

    /// Ask iOS for the next run (or cancel it when off / nothing to refresh).
    func schedule() {
        guard repo.store.loaded else { return }
        let minutes = repo.store.get().settings.backgroundSyncMinutes
        let hasAccounts = repo.state.accounts.contains { $0.status == .locked || $0.status == .unlocked }
        guard minutes > 0, hasAccounts else {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.identifier)
            return
        }
        let request = BGAppRefreshTaskRequest(identifier: Self.identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: TimeInterval(minutes) * 60)
        // Fails only where the scheduler is unavailable (e.g. some simulators).
        try? BGTaskScheduler.shared.submit(request)
    }

    private func handle(_ task: BGAppRefreshTask) {
        if let pending { finish(pending, success: false) }
        running?.cancel()
        pending = task
        nonisolated(unsafe) let task = task
        let work = Task { @MainActor [weak self] in
            let ok = await self?.runOnce() ?? false
            self?.finish(task, success: ok)
        }
        // Time is up: stop the work (a lock in the shared container must be released before
        // the app is suspended) and complete at once with what was done so far.
        task.expirationHandler = { [weak self] in
            work.cancel()
            Task { @MainActor in self?.finish(task, success: false) }
        }
        running = work
    }

    private func finish(_ task: BGAppRefreshTask, success: Bool) {
        guard pending === task else { return }
        pending = nil
        running = nil
        task.setTaskCompleted(success: success)
        schedule()
    }

    private func runOnce() async -> Bool {
        // The state files and Keychain items are readable only while the device is unlocked:
        // nothing to do now, the next run is scheduled by the caller.
        guard UIApplication.shared.isProtectedDataAvailable else { return true }
        repo.store.reload()
        guard repo.store.loaded else { return true }
        var ok = true
        for account in repo.state.accounts where account.status == .locked || account.status == .unlocked {
            if Task.isCancelled { return false }
            do { try await repo.refreshCacheLocked(accountId: account.id) } catch { ok = false }
        }
        return ok && !Task.isCancelled
    }
}
