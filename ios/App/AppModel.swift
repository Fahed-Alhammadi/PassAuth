import Observation
import PassAuthCore
import PassAuthKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// App-wide services for the UI: the repository, vault timeout, clipboard, icons, notices.
@MainActor
@Observable
final class AppModel {
    let repo: VaultRepository
    let icons: IconLoader
    @ObservationIgnored private(set) var lockManager: LockManager!
    @ObservationIgnored private(set) var liveSync: LiveSync!
    let permissions: PermissionCenter
    /// UI tests that aren't about it skip the first-launch permissions screen.
    let skipPermissionsIntro: Bool

    /// The current notice (toast) text.
    private(set) var notice: String?
    @ObservationIgnored private var noticeTask: Task<Void, Never>?

    /// A screen shows a secret outside the unlocked vault (the new Secret Key): cover it in the app switcher.
    var showsSecret = false

    init() {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("-PAResetState") { SecureStore.wipeAll() }
        skipPermissionsIntro = ProcessInfo.processInfo.arguments.contains("-PASkipPermissions")
        #else
        skipPermissionsIntro = false
        #endif
        let store = SecureStore()
        let api = ApiClient(store: store)
        // A token refresh holds a lock in the shared container: finish it even if the app is
        // sent to the background meanwhile (iOS ends apps suspended while holding one).
        api.beginBackgroundWork = {
            let work = BackgroundWork()
            return { work.end() }
        }
        repo = VaultRepository(store: store, api: api)
        icons = IconLoader(session: api.session)
        lockManager = LockManager(repo: repo)
        liveSync = LiveSync(repo: repo)
        permissions = PermissionCenter(repo: repo)
    }

    var state: AppState { repo.state }

    func notify(_ text: String) {
        noticeTask?.cancel()
        notice = text
        UIAccessibility.post(notification: .announcement, argument: text)
        noticeTask = Task {
            try? await Task.sleep(for: .seconds(3.5))
            if !Task.isCancelled { notice = nil }
        }
    }

    /// Run an action, showing its error as a notice.
    func run(_ body: @escaping @MainActor () async throws -> Void) {
        Task {
            do { try await body() } catch is CancellationError {} catch { notify(errorMessage(error)) }
        }
    }

    /// Copy to the clipboard: this device only (no Universal Clipboard), expiring after the user's delay.
    func copy(_ text: String, _ label: String) {
        let after = state.settings.clearClipboard
        Clipboard.copy(text, clearAfter: after)
        notify("\(label) copied." + (after > 0 ? " Clipboard clears in \(secondsLabel(after))." : ""))
    }

    func copyTotp(_ secret: String) {
        guard let c = try? totpCode(secret: secret, unixSeconds: UInt64(Date().timeIntervalSince1970)) else {
            notify("This item's authenticator key isn't valid.")
            return
        }
        copy(c.code, "Verification code")
    }

    func open(_ url: String) {
        guard let u = URL(string: url), let scheme = u.scheme?.lowercased(), scheme == "https" || scheme == "http" else {
            notify("This address can't be opened.")
            return
        }
        UIApplication.shared.open(u)
    }

    /// The account's web vault at a path (path routes).
    func openWebVault(_ path: String = "") {
        open(state.server + path)
    }
}

/// A background task assertion, ended once (by the caller or when the time is up).
@MainActor
final class BackgroundWork {
    private var id = UIBackgroundTaskIdentifier.invalid

    init() {
        id = UIApplication.shared.beginBackgroundTask(withName: "PassAuth token refresh") { [weak self] in
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id)
        id = .invalid
    }
}

/// Website icons from the user's PassAuth server (`/api/icons/{host}`), which learns the
/// website addresses but never the vault contents. Misses are cached too, so a missing
/// icon is only requested once per app run.
@MainActor
final class IconLoader {
    private let session: URLSession
    private var cache: [String: UIImage?] = [:]
    private var running: [String: Task<UIImage?, Never>] = [:]

    init(session: URLSession) { self.session = session }

    func load(server: String, host: String) async -> UIImage? {
        guard !server.isEmpty, !host.isEmpty else { return nil }
        let key = "\(server)|\(host)"
        if let hit = cache[key] { return hit }
        if let t = running[key] { return await t.value }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-:[]"))
        guard let enc = host.addingPercentEncoding(withAllowedCharacters: allowed), let url = URL(string: "\(server)/api/icons/\(enc)") else { return nil }
        let session = self.session
        let task = Task<UIImage?, Never> {
            guard let (data, res) = try? await session.data(from: url), (res as? HTTPURLResponse)?.statusCode == 200 else { return nil }
            return UIImage(data: data)
        }
        running[key] = task
        let image = await task.value
        running[key] = nil
        cache[key] = image
        return image
    }
}

/// Vault timeout, like the extension and the Android app: lock (or log out) every account
/// after the chosen minutes without use, as soon as the app leaves the screen
/// ("Immediately"), only when the app process restarts, or never.
@MainActor
final class LockManager {
    private let repo: VaultRepository
    private var lastActivity = LockManager.now()
    private var lastScheduled: UInt64 = 0
    private var timer: Task<Void, Never>?

    init(repo: VaultRepository) { self.repo = repo }

    /// Continuous clock (keeps counting while the device sleeps), nanoseconds.
    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC) }

    private var minutes: Int? {
        guard let m = repo.state.settings.vaultTimeout.minutes, m > 0 else { return nil }
        return m
    }

    /// Call on user interaction.
    func touch() {
        lastActivity = Self.now()
        // Touches come in bursts: reschedule at most once a second.
        if lastActivity - lastScheduled > 1_000_000_000 { schedule() }
    }

    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            if expired() { fire() } else { schedule() }
        case .background:
            if repo.state.settings.vaultTimeout == .immediately { fire() } else { schedule() }
        default:
            break
        }
    }

    /// Settings changed: start over with the new timeout.
    func settingsChanged() {
        lastActivity = Self.now()
        schedule()
    }

    private func expired() -> Bool {
        guard let m = minutes else { return false }
        return Self.now() - lastActivity >= UInt64(m) * 60_000_000_000
    }

    private func schedule() {
        timer?.cancel()
        lastScheduled = Self.now()
        guard let m = minutes else { return }
        let elapsed = Self.now() - lastActivity
        let total = UInt64(m) * 60_000_000_000
        let wait = total > elapsed ? total - elapsed : 0
        timer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: wait)
            guard !Task.isCancelled else { return }
            self?.fireIfExpired()
        }
    }

    private func fireIfExpired() {
        if expired() { fire() } else { schedule() }
    }

    private func fire() {
        timer?.cancel()
        guard repo.anyUnlocked else { return }
        let action = repo.state.settings.timeoutAction
        Task {
            if action == .logout { await repo.logoutAll() } else { await repo.lockAll() }
        }
    }
}

/// Reports every touch in the window (without taking part in gesture handling): the vault
/// timeout counts from the last interaction.
final class ActivityRecognizer: UIGestureRecognizer, UIGestureRecognizerDelegate {
    var onTouch: (@MainActor () -> Void)?

    override init(target: Any?, action: Selector?) {
        super.init(target: target, action: action)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
        delegate = self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        onTouch?()
        state = .failed
    }

    func gestureRecognizer(_ g: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool { true }
}

/// Gives access to the hosting window (to install the activity recognizer).
struct WindowReader: UIViewRepresentable {
    let onWindow: @MainActor (UIWindow) -> Void

    func makeUIView(context: Context) -> ReaderView {
        let v = ReaderView()
        v.onWindow = onWindow
        return v
    }

    func updateUIView(_ uiView: ReaderView, context: Context) {}

    final class ReaderView: UIView {
        var onWindow: (@MainActor (UIWindow) -> Void)?
        override func didMoveToWindow() {
            super.didMoveToWindow()
            if let window { onWindow?(window) }
        }
    }
}
