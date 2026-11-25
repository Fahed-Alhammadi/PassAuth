import PassAuthKit
import SwiftUI

/// Whether the active account's server sends sign-in request notifications, as last asked
/// (nil: not asked yet).
@MainActor
private func activeServerOffersPush(_ model: AppModel) -> Bool? {
    model.repo.store.get().active?.features.map { PushRules.offered(features: $0) }
}

/// Settings → Account security: "Sign-in request notifications", following what iOS allows.
/// iOS lets only the Settings app turn them off (and back on once refused), so the switch opens
/// it then.
struct PushSettingsSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let push = model.push
        let offered = activeServerOffersPush(model)
        Section {
            Toggle(isOn: Binding(get: { push.permission == .allowed }, set: { on in toggle(on, push.permission) })) {
                Label("Sign-in request notifications", systemImage: "bell.badge")
            }
            .disabled(push.permission == .unknown || push.permission == .unavailable)
            .accessibilityIdentifier("pushToggle")
            if push.permission == .denied {
                Button {
                    Task { await PermissionCenter.openAppSettings() }
                } label: {
                    Label("Open the Settings app", systemImage: "arrow.up.forward.app")
                }
                .accessibilityHint("Opens PassAuth in the Settings app")
                .accessibilityIdentifier("push.openSettings")
            }
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text(footer(push.permission))
                if offered == false {
                    Text("Your PassAuth server doesn't send these notifications: it needs a newer server version, or its administrator turned them off.")
                        .accessibilityIdentifier("push.serverOff")
                }
            }
        }
        .paRow()
    }

    private func footer(_ p: PermissionStatus) -> String {
        switch p {
        case .allowed:
            "PassAuth tells you when a new device asks to sign in to your account. Notifications never show your email or server. To turn them off, use the Settings app."
        case .denied:
            "Notifications are off for PassAuth in the Settings app. Turn on Allow Notifications there to hear about sign-in requests from new devices."
        default:
            "Get notified when a new device asks to sign in to your account, so you can approve it here. Notifications never show your email or server."
        }
    }

    private func toggle(_ on: Bool, _ p: PermissionStatus) {
        if on && p == .notAsked {
            Task {
                await model.push.requestPermission()
                if model.push.permission == .allowed { model.notify("Sign-in request notifications are on.") }
            }
        } else {
            // Refused before (iOS doesn't ask again) or turning off: only the Settings app can.
            Task { await PermissionCenter.openAppSettings() }
        }
    }
}
