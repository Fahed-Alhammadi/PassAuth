import PassAuthKit
import SwiftUI

@main
struct PassAuthApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .tint(Color.paAccent)
        }
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
                    case .setup: SetupView()
                    case .loggedOut: LoginView()
                    case .locked: UnlockView()
                    case .unlocked: MainView()
                    }
                }
                // Switching accounts starts each screen fresh.
                .id(state.activeId + "|\(state.status)")
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
            }
        }
        // Live sync: only while on screen with the active account unlocked.
        .onChange(of: "\(scenePhase == .active)|\(state.activeId)|\(state.status)", initial: true) { _, _ in
            model.liveSync.update(foreground: scenePhase == .active)
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
    }
}
