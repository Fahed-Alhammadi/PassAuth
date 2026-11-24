import AuthenticationServices
import Network
import PassAuthKit
import SwiftUI
import UIKit

/// System permissions, asked only where a feature needs them (App Review 5.1.1(iv): no
/// screen of its own before a permission prompt). The camera is asked when scanning a QR
/// code, notifications and AutoFill in Settings, Face ID in Account security, and the local
/// network here, when connecting to a server on it.
@MainActor
final class PermissionCenter {
    private let repo: VaultRepository

    init(repo: VaultRepository) { self.repo = repo }

    /// Connecting to a server on the local network (such as http://192.168.1.20): iOS asks
    /// for the local network the first time. Ask now, so the connection doesn't fail while
    /// the prompt is up. False when PassAuth isn't allowed to use the local network.
    func ensureLocalNetwork(for server: String) async -> Bool {
        guard let origin = try? VaultRepository.normalizeServer(server),
              let host = UrlMatcher.parse(origin)?.hostname,
              VaultRepository.isLocalHost(host), !VaultRepository.isLoopback(host) else { return true }
        if repo.state.settings.permissions.localNetwork == .allowed { return true }
        let status = await LocalNetworkProbe.run(promptExpected: true)
        await repo.updateSettings { $0.permissions.localNetwork = status }
        return status != .denied
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
