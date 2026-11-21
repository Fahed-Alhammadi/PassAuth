import PassAuthKit
import SwiftUI

@main
struct PassAuthApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .tint(Color.paAccent)
        }
    }
}

/// Registers the Background App Refresh handler and the notification delegate before the app
/// finishes launching (a tap that launched the app is delivered right after), and passes the
/// APNs device token on.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        BackgroundRefresh.register()
        PushCenter.shared.start()
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        PushCenter.shared.received(token: deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // No token (no network, simulator without push, entitlement missing): nothing registers.
    }
}

/// Picks the screen for the active account's status, plus app-wide overlays.
struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @State private var window: UIWindow?

    var body: some View {
        let state = model.state
        ZStack {
            Color.paBackground.ignoresSafeArea()
            if !state.loaded {
                ProgressView()
            } else {
                Group {
                    switch state.status {
                    case _ where PermissionRules.showIntro(state.settings.permissions, hasAccounts: !state.accounts.isEmpty, skip: model.skipPermissionsIntro):
                        PermissionsIntroView()
                    // The server requires two-step login and the account has none yet: only
                    // setting a method up (or signing out) until then.
                    case .locked where state.twoStepRequired, .unlocked where state.twoStepRequired:
                        TwoStepRequiredView()
                    case .setup: SetupView()
                    case .loggedOut: LoginView()
                    case .locked: UnlockView()
                    case .unlocked: MainView()
                    }
                }
                // Switching accounts starts each screen fresh.
                .id(state.activeId + "|\(state.status)|\(state.twoStepRequired)")
            }
        }
        .overlay(alignment: .bottom) { NoticeView().padding(.bottom, state.status == .unlocked ? 40 : 0) }
        .overlay {
            // App switcher snapshot and other apps on top: hide the vault.
            if scenePhase != .active && (state.status == .unlocked || model.showsSecret) {
                PrivacyCover()
            }
        }
        .background(WindowReader { w in
            guard window !== w else { return }
            window = w
            let r = ActivityRecognizer(target: nil, action: nil)
            let lock = model.lockManager
            r.onTouch = { lock?.touch() }
            w.addGestureRecognizer(r)
            applyTheme(state.settings.theme)
        })
        .onOpenURL { model.open($0) }
        .task {
            ExportFile.removeTemporaryCopies()
            await model.repo.start()
        }
        .onChange(of: scenePhase) { _, phase in
            model.lockManager.scenePhaseChanged(phase)
            if phase == .active {
                // The AutoFill extension may have rotated tokens or saved a passkey meanwhile.
                model.repo.store.reload()
                Task { await model.repo.refreshIfStale() }
                // Notifications may have been turned on or off in the Settings app meanwhile.
                Task { await model.push.refreshPermission() }
            }
            if phase == .background { model.backgroundRefresh.schedule() }
        }
        .onChange(of: state.settings.backgroundSyncMinutes) { _, _ in model.backgroundRefresh.schedule() }
        // Live sync: only while on screen with the active account unlocked.
        .onChange(of: "\(scenePhase == .active)|\(state.activeId)|\(state.status)|\(state.twoStepRequired)", initial: true) { _, _ in
            model.liveSync.update(foreground: scenePhase == .active)
            // Sign-in requests from new devices: asked again on unlock and when back on screen;
            // locked, signed out or another account: none.
            if state.status == .unlocked && !state.twoStepRequired {
                if scenePhase == .active { Task { await model.authRequests.refresh() } }
            } else {
                model.authRequests.clear()
            }
        }
        // A sign-in (or another account signed in): register this device for sign-in request notifications.
        .onChange(of: state.accounts.filter { $0.status == .locked || $0.status == .unlocked }.map(\.id).joined(separator: ","), initial: true) { _, _ in
            Task { await model.push.sync() }
        }
        // A sign-in request notification was tapped (or arrived on screen): ask for the open
        // requests now; locked, the unlock screen is shown and unlocking asks.
        .onChange(of: model.push.signInRequests) { _, _ in
            if state.status == .unlocked && !state.twoStepRequired { Task { await model.authRequests.refresh() } }
        }
        // "PassAuth for Safari": server, email and Secret Key of the unlocked account, so its
        // sign-in needs only the master password; signed out or another account active: cleared
        // (the same account locked: kept).
        .onChange(of: model.repo.safariHandoffKey, initial: true) { _, _ in
            if state.status == .unlocked {
                SafariHandoff.store(model.repo.safariHandoff)
            } else if SafariHandoff.shouldClear(status: state.status, server: state.server, email: state.email, stored: SafariHandoff.stored()) {
                SafariHandoff.store(nil)
            }
        }
        .onChange(of: state.settings.theme) { _, t in applyTheme(t) }
        .onChange(of: state.settings.vaultTimeout) { _, _ in model.lockManager.settingsChanged() }
    }

    private func applyTheme(_ t: ThemeMode) {
        let style: UIUserInterfaceStyle = t == .light ? .light : t == .dark ? .dark : .unspecified
        for scene in UIApplication.shared.connectedScenes {
            (scene as? UIWindowScene)?.windows.forEach { $0.overrideUserInterfaceStyle = style }
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color.paBackground.ignoresSafeArea()
            VStack(spacing: 14) {
                LogoMark(height: 72)
                Wordmark(size: 24)
            }
        }
        .accessibilityHidden(true)
    }
}

/// Short notices at the bottom (copy confirmations, errors of quick actions).
struct NoticeView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let text = model.notice {
            Text(text)
                .font(.subheadline)
                .foregroundStyle(.white)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Color(white: 0.12).opacity(0.94), in: Capsule())
                .padding(.horizontal, 24)
                .padding(.bottom, 64)
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .accessibilityIdentifier("notice")
                .allowsHitTesting(false)
        }
    }
}

/// The unlocked app: Vault, Generator, Settings.
struct MainView: View {
    enum Tab: Hashable { case vault, generator, settings }
    @Environment(AppModel.self) private var model
    @State private var tab: Tab = .vault

    var body: some View {
        TabView(selection: $tab) {
            VaultTab()
                .tabItem { Label("Vault", systemImage: "lock.shield") }
                .tag(Tab.vault)
            GeneratorTab()
                .tabItem { Label("Generator", systemImage: "dice") }
                .tag(Tab.generator)
            SettingsTab()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(Tab.settings)
        }
        .modifier(BiometricOffer())
        .sheet(item: Binding(get: { model.pendingOtp }, set: { model.pendingOtp = $0 })) { p in
            AddCodeSheet(key: p.key)
        }
        // A new device asks to sign in to this account: one request at a time, frozen while it
        // is shown (`ApprovalQueue`). Only the sheet's own buttons close it (it can't be swiped
        // away), so a dismissal can never be taken for the next request's.
        .sheet(item: Binding(get: { model.authRequests.shown }, set: { _ in })) { shown in
            AuthRequestSheet(initial: shown)
        }
    }
}
