import AuthenticationServices
import AVFoundation
import LocalAuthentication
import Network
import PassAuthKit
import SwiftUI
import UIKit

/// The permissions and system features PassAuth uses, in the order they're listed.
enum PermissionKind: String, CaseIterable, Identifiable {
    case autofill, biometrics, camera, localNetwork
    var id: String { rawValue }
}

/// Current status of each permission, and the actions that ask for them. Shared by the
/// first-launch screen and Settings → Permissions.
@MainActor
@Observable
final class PermissionCenter {
    private let repo: VaultRepository
    private(set) var autofill: PermissionStatus = .unknown
    private(set) var camera: PermissionStatus = .unknown
    private(set) var biometrics: PermissionStatus = .unknown
    private(set) var biometryType: LABiometryType = .none
    private(set) var busy: Set<PermissionKind> = []

    init(repo: VaultRepository) { self.repo = repo }

    private var memory: PermissionMemory { repo.state.settings.permissions }

    var localNetwork: PermissionStatus { PermissionRules.localNetworkShown(memory) }

    func status(_ k: PermissionKind) -> PermissionStatus {
        switch k {
        case .autofill: autofill
        case .biometrics: biometrics
        case .camera: camera
        case .localNetwork: localNetwork
        }
    }

    /// Read what iOS reports (and re-check the local network if it was checked before:
    /// once decided, iOS doesn't prompt again).
    func refresh() async {
        camera = PermissionRules.camera(AVCaptureDevice.authorizationStatus(for: .video).rawValue)
        refreshBiometrics()
        let local = memory.localNetwork
        if local == .allowed || local == .denied, !busy.contains(.localNetwork) {
            busy.insert(.localNetwork)
            let now = await LocalNetworkProbe.run(promptExpected: false)
            busy.remove(.localNetwork)
            if now != .unknown { await remember { $0.localNetwork = now } }
        }
        autofill = PermissionRules.autofill(await CredentialIdentitySync.isEnabled(timeout: .seconds(2)))
    }

    private func refreshBiometrics() {
        let c = LAContext()
        var error: NSError?
        let ok = c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        biometryType = c.biometryType
        biometrics = PermissionRules.biometrics(
            canEvaluate: ok, errorCode: error?.code, hasHardware: c.biometryType != .none,
            // Biometric unlock turned on in Account security also means iOS allowed it.
            allowedBefore: memory.biometricsAllowed || repo.state.biometricEnabled)
    }

    private func remember(_ f: @escaping @Sendable (inout PermissionMemory) -> Void) async {
        await repo.updateSettings { f(&$0.permissions) }
    }

    // MARK: Actions

    func request(_ k: PermissionKind) async {
        guard !busy.contains(k) else { return }
        busy.insert(k)
        defer { busy.remove(k) }
        switch k {
        case .camera:
            _ = await AVCaptureDevice.requestAccess(for: .video)
            camera = PermissionRules.camera(AVCaptureDevice.authorizationStatus(for: .video).rawValue)
        case .biometrics:
            if await BiometryKind.confirm(reason: "Allow PassAuth to unlock your vault with \(biometryName)") {
                await remember { $0.biometricsAllowed = true }
            }
            refreshBiometrics()
        case .localNetwork:
            let s = await LocalNetworkProbe.run(promptExpected: true)
            await remember { $0.localNetwork = s }
        case .autofill:
            if let on = await Self.turnOnAutofill(repo) { autofill = PermissionRules.autofill(on) }
        }
    }

    /// Turn on PassAuth for AutoFill: iOS 18's one-tap request, else the AutoFill settings.
    /// Returns the new state when iOS reports it.
    static func turnOnAutofill(_ repo: VaultRepository) async -> Bool? {
        if #available(iOS 18.0, *) {
            let on = await withCheckedContinuation { (c: CheckedContinuation<Bool, Never>) in
                ASSettingsHelper.requestToTurnOnCredentialProviderExtension { c.resume(returning: $0) }
            }
            if on {
                // Just turned on: write the identities again.
                repo.identities.invalidate()
                repo.refreshIdentities()
            }
            return on
        }
        await openAutofillSettings()
        return nil
    }

    /// Settings → General → AutoFill & Passwords (the app's settings if that fails).
    static func openAutofillSettings() async {
        do { try await ASSettingsHelper.openCredentialProviderAppSettings() } catch { await openAppSettings() }
    }

    /// The app's page in the Settings app (camera, Face ID and local network switches).
    static func openAppSettings() async {
        if let url = URL(string: UIApplication.openSettingsURLString) { await UIApplication.shared.open(url) }
    }

    func markIntroShown() async {
        await remember { $0.introShown = true }
    }

    func markBiometricOffered() async {
        await remember { $0.biometricOffered = true }
    }

    // MARK: Text

    var biometryName: String {
        switch biometryType {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        default: "Face ID or Touch ID"
        }
    }

    func title(_ k: PermissionKind) -> String {
        switch k {
        case .autofill: "AutoFill passwords & passkeys"
        case .biometrics: biometryName
        case .camera: "Camera"
        case .localNetwork: "Local network"
        }
    }

    func reason(_ k: PermissionKind) -> String {
        switch k {
        case .autofill: "Fill logins, passkeys and verification codes in Safari and other apps."
        case .biometrics: "Unlock your vault without typing your master password."
        case .camera: "Scan the QR code when you add two-step login to an item."
        case .localNetwork: "Only needed if your server is on your home network, such as http://192.168.1.20."
        }
    }

    func symbol(_ k: PermissionKind) -> String {
        switch k {
        case .autofill: "key.viewfinder"
        case .biometrics: biometryType == .touchID ? "touchid" : biometryType == .opticID ? "opticid" : "faceid"
        case .camera: "camera"
        case .localNetwork: "network"
        }
    }

    /// The status in words ("Allowed", "Not allowed", "Not asked", …).
    func statusText(_ k: PermissionKind) -> String {
        let s = status(k)
        if k == .autofill {
            switch s {
            case .allowed: return "On"
            case .notAsked, .denied: return "Off"
            default: return "Status unknown"
            }
        }
        switch s {
        case .allowed: return "Allowed"
        case .denied: return "Not allowed"
        case .notAsked: return "Not asked"
        case .unavailable: return k == .biometrics ? "Not set up on this device" : "Not available on this device"
        case .unknown: return k == .localNetwork ? "Unknown: iOS doesn't say" : "Unknown"
        }
    }
}

// MARK: Local network

/// Triggers (and reads) the local network permission the way Apple recommends (TN3179):
/// a short Bonjour browse for PassAuth's own service type (in `NSBonjourServices`). iOS has
/// no API for the permission; a denial shows as the browser waiting with "policy denied".
@MainActor
enum LocalNetworkProbe {
    static let serviceType = "_passauth._tcp"

    static func run(promptExpected: Bool) async -> PermissionStatus {
        let box = EventBox()
        let browser = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: NWParameters())
        browser.stateUpdateHandler = { state in
            MainActor.assumeIsolated { box.add(state) }
        }
        let center = NotificationCenter.default
        let resign = center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { box.wentInactive = true }
        }
        let active = center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { if box.wentInactive { box.activeAgain = Date() } }
        }
        defer {
            browser.cancel()
            center.removeObserver(resign)
            center.removeObserver(active)
        }
        browser.start(queue: .main)
        let start = Date()
        // The prompt shows up a moment after the browse starts and makes the app inactive;
        // the answer counts once the app is active again.
        let quiet: TimeInterval = promptExpected ? 2.5 : 1.5
        var settled = false
        while Date().timeIntervalSince(start) < 60 {
            try? await Task.sleep(for: .milliseconds(250))
            if box.events.contains(.policyDenied) { break }
            guard UIApplication.shared.applicationState == .active else { continue }
            if let back = box.activeAgain {
                if Date().timeIntervalSince(back) >= 1.5 { settled = true; break }
            } else if !box.wentInactive, Date().timeIntervalSince(start) >= quiet {
                settled = true
                break
            }
        }
        return PermissionRules.localNetwork(box.events, promptSettled: settled)
    }

    @MainActor
    private final class EventBox {
        var events: [PermissionRules.ProbeEvent] = []
        var wentInactive = false
        var activeAgain: Date?

        func add(_ state: NWBrowser.State) {
            switch state {
            case .ready: events.append(.ready)
            case .waiting(let e): events.append(PermissionRules.probeEvent(dnsError: Self.dnsCode(e), failed: false))
            case .failed(let e): events.append(PermissionRules.probeEvent(dnsError: Self.dnsCode(e), failed: true))
            default: break
            }
        }

        private static func dnsCode(_ e: NWError) -> Int32? {
            if case .dns(let code) = e { return code }
            return nil
        }
    }
}

// MARK: Views

/// One permission: icon, title, reason, status and its button.
struct PermissionRow: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dynamicTypeSize) private var typeSize
    let kind: PermissionKind
    /// On the first-launch screen "Not asked" goes without saying.
    var intro = false

    var body: some View {
        let p = model.permissions
        let status = p.status(kind)
        let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: 10)) : AnyLayout(HStackLayout(alignment: .center, spacing: 12))
        layout {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: p.symbol(kind))
                    .font(.title3)
                    .foregroundStyle(Color.paAccent)
                    .frame(width: 40, height: 40)
                    .background(Color.paAccentSoft, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(p.title(kind)).font(.headline).foregroundStyle(Color.paInk)
                    Text(p.reason(kind)).font(.subheadline).foregroundStyle(Color.paMuted)
                        .fixedSize(horizontal: false, vertical: true)
                    if showsStatusLine(status) {
                        Text(p.statusText(kind))
                            .font(.footnote.weight(.medium))
                            .foregroundStyle(status == .denied ? Color.paWarn : Color.paMuted)
                            .accessibilityIdentifier("perm.\(kind.rawValue).status")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .combine)
            }
            trailing(p, status)
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    private func showsStatusLine(_ s: PermissionStatus) -> Bool {
        switch s {
        case .allowed: false
        // On the first-launch screen only what blocks the button matters.
        case .notAsked, .unknown: !intro
        default: true
        }
    }

    @ViewBuilder
    private func trailing(_ p: PermissionCenter, _ status: PermissionStatus) -> some View {
        if p.busy.contains(kind) {
            ProgressView().frame(minWidth: 44, minHeight: 32)
                .accessibilityLabel("Checking \(p.title(kind))")
        } else {
            switch status {
            case .allowed:
                // Not a Label: in a List it would drop the text.
                HStack(spacing: 5) {
                    Image(systemName: "checkmark.circle.fill")
                    Text(kind == .autofill ? "On" : "Allowed")
                }
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Color.paOk)
                .fixedSize()
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(p.title(kind)): \(kind == .autofill ? "on" : "allowed")")
                .accessibilityIdentifier("perm.\(kind.rawValue).allowed")
            case .denied where kind != .autofill:
                action("Open Settings", hint: "Opens PassAuth in the Settings app") { await PermissionCenter.openAppSettings() }
            case .unavailable:
                EmptyView()
            default:
                action(kind == .autofill ? "Turn on" : "Allow", hint: nil) { await p.request(kind) }
            }
        }
    }

    private func action(_ title: String, hint: String?, _ run: @escaping @MainActor () async -> Void) -> some View {
        Button { Task { await run() } } label: {
            Text(title).font(.subheadline.weight(.semibold)).fixedSize()
        }
        .buttonStyle(.bordered)
        .buttonBorderShape(.capsule)
        .tint(Color.paAccent)
        .accessibilityLabel("\(title), \(model.permissions.title(kind))")
        .accessibilityHint(hint ?? "")
        .accessibilityIdentifier("perm.\(kind.rawValue)")
    }
}

/// First launch: "Set up PassAuth", before "Connect to your server".
struct PermissionsIntroView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        AuthFrame(title: "Set up PassAuth", subtitle: "Choose what PassAuth may use. Allow only what you need; you can change it later in Settings → Permissions.") {
            VStack(spacing: 0) {
                ForEach(Array(PermissionKind.allCases.enumerated()), id: \.element) { i, k in
                    if i > 0 { Divider().overlay(Color.paLine).padding(.leading, 52) }
                    PermissionRow(kind: k, intro: true)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .background(Color.paSurface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Color.paLine, lineWidth: 0.5))
            PrimaryButton(title: "Continue") { finish() }
                .accessibilityIdentifier("perm.continue")
                .padding(.top, 6)
            Button("Skip for now") { finish() }
                .font(.subheadline.weight(.medium))
                .accessibilityIdentifier("perm.skip")
        }
        .task(id: scenePhase) {
            if scenePhase == .active { await model.permissions.refresh() }
        }
    }

    private func finish() {
        Task { await model.permissions.markIntroShown() }
    }
}

/// Settings → Permissions: the same list with the current status.
struct PermissionsPage: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Section {
            ForEach(PermissionKind.allCases) { k in
                PermissionRow(kind: k).paRow()
            }
        } footer: {
            Text("Turn these on or off any time in the Settings app. iOS doesn't let apps read the local network setting; PassAuth shows what it saw at its last check.")
        }
        .task(id: scenePhase) {
            if scenePhase == .active { await model.permissions.refresh() }
        }
    }
}

/// After a sign-in or unlock: offer biometric unlock once if it was allowed on the permissions screen.
struct BiometricOffer: ViewModifier {
    @Environment(AppModel.self) private var model
    @State private var showing = false

    func body(content: Content) -> some View {
        let bio = BiometryKind.current
        content
            .task {
                let s = model.state
                showing = PermissionRules.offerBiometricUnlock(s.settings.permissions, available: bio.available, enabled: s.biometricEnabled)
            }
            .alert("Unlock with \(bio.name)?", isPresented: $showing) {
                Button("Turn on") {
                    model.run {
                        await model.permissions.markBiometricOffered()
                        try await model.repo.enableBiometric()
                        model.notify("\(bio.name) unlock is on.")
                    }
                }
                Button("Not now", role: .cancel) {
                    Task { await model.permissions.markBiometricOffered() }
                }
            } message: {
                Text("Open your vault with \(bio.name) instead of typing your master password. You can change this in Settings → Account security.")
            }
    }
}
