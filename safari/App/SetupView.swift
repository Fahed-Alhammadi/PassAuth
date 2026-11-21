import SwiftUI
#if os(macOS)
import SafariServices
#endif

/// The bundle id of the Safari extension (project.yml).
let extensionBundleId = "io.passauth.safari.extension"

/// How to turn the extension on, with the app's version and copyright.
struct SetupView: View {
    @State private var openFailed = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                header
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { i, step in
                        HStack(alignment: .firstTextBaseline, spacing: 12) {
                            Text("\(i + 1)")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.white)
                                .frame(width: 26, height: 26)
                                .background(Circle().fill(Color.accentColor))
                            Text(step).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
                .background(RoundedRectangle(cornerRadius: 16).fill(.background.secondary))
                #if os(macOS)
                Button("Open Safari Extensions Settings", action: openSafariSettings)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                if openFailed {
                    Text("Safari couldn't open its settings. Open Safari, then choose Safari → Settings → Extensions.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                #endif
                Text("Passkeys and AutoFill in other apps come from the PassAuth app.")
                    .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                footer
            }
            .padding(24)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image("Logo").resizable().frame(width: 88, height: 88)
                .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                .shadow(color: .black.opacity(0.15), radius: 8, y: 4)
                .accessibilityHidden(true)
            Text("PassAuth for Safari").font(.title.bold())
            Text("Fill and save logins from your PassAuth vault in Safari.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
    }

    private var footer: some View {
        VStack(spacing: 4) {
            Text("© 2026 Fahed Alhammadi. All rights reserved.")
            Text("Version \(Self.version)")
        }
        .font(.caption).foregroundStyle(.secondary)
    }

    static var version: String {
        let info = Bundle.main.infoDictionary
        let v = info?["CFBundleShortVersionString"] as? String ?? "?"
        let b = info?["CFBundleVersion"] as? String ?? "?"
        return "\(v) (\(b))"
    }

    private var steps: [String] {
        #if os(macOS)
        [
            "Open Safari and choose Safari → Settings → Extensions.",
            "Turn on PassAuth.",
            "Allow it on every website, or on the sites where you sign in.",
            "Click the PassAuth button in Safari's toolbar and sign in to your server.",
        ]
        #else
        [
            "Open the Settings app, then Apps → Safari → Extensions.",
            "Tap PassAuth and turn on Allow Extension.",
            "Set Other Websites to Allow, or allow sites one by one in Safari.",
            "In Safari, tap the page menu in the address bar, then PassAuth, and sign in to your server.",
        ]
        #endif
    }

    #if os(macOS)
    private func openSafariSettings() {
        SFSafariApplication.showPreferencesForExtension(withIdentifier: extensionBundleId) { error in
            Task { @MainActor in openFailed = error != nil }
        }
    }
    #endif
}
