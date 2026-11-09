import AppKit
import PassAuthKit
import SwiftUI

/// Server, email and Secret Key the desktop app on this Mac handed over (a Keychain item in the
/// extension's group, written while its vault is unlocked). The extension still signs in itself and
/// gets its own session; the hand-off only spares the typing, so just the master password is asked.
struct DesktopHandoff: Decodable, Equatable {
    var server: String?
    var email: String?
    var secretKey: String?

    static func read() -> DesktopHandoff? {
        guard let data = Keychain.readDesktopHandoff(),
              let h = try? JSONDecoder().decode(DesktopHandoff.self, from: data),
              let server = h.server, !server.isEmpty else { return nil }
        return h
    }

    /// The hand-off, if it is for the server the extension is connected to.
    static func read(for server: String) -> DesktopHandoff? {
        guard let h = read(), h.server == server else { return nil }
        return h
    }
}

/// The extension's own sign-in (it shares no session with the desktop app): server address,
/// email + master password (+ Secret Key), then two-step login, as the iOS app's
/// `SetupView` / `LoginView` / `TwoStepView` (ios/App/AuthViews.swift). With a desktop hand-off the
/// server is connected by itself and email + Secret Key are filled in.
struct MacSignIn: View {
    @Bindable var model: AutofillModel
    @State private var step: Step?
    @State private var handoff: DesktopHandoff?
    @State private var connecting = false

    enum Step: Equatable {
        case server
        case login
        case twoStep(token: String, providers: [String], email: String)
    }

    var body: some View {
        let current = step ?? (model.state.server.isEmpty ? .server : .login)
        Group {
            if connecting {
                MacFrame(title: "Connecting to your PassAuth server", subtitle: hostOf(handoff?.server ?? "")) {
                    ProgressView().frame(maxWidth: .infinity)
                }
            } else {
                switch current {
                case .server:
                    MacServerStep(model: model, canCancel: !model.state.server.isEmpty, prefill: handoff?.server) { step = .login }
                case .login:
                    MacLoginStep(model: model, handoff: handoff, changeServer: { step = .server }) { token, providers, email in
                        step = .twoStep(token: token, providers: providers, email: email)
                    }
                case .twoStep(let token, let providers, let email):
                    MacTwoStep(model: model, token: token, providers: providers, email: email) { step = .login }
                }
            }
        }
        .task { await applyHandoff() }
    }

    /// No server yet: take the desktop app's and connect to it (plain http was already accepted there).
    private func applyHandoff() async {
        guard step == nil, model.state.server.isEmpty, let h = DesktopHandoff.read(), let server = h.server else { return }
        handoff = h
        connecting = true
        let ok = (try? await model.repo.setServer(server, allowLanHttp: true)) != nil
        connecting = false
        step = ok ? .login : .server
    }
}

private struct MacServerStep: View {
    @Bindable var model: AutofillModel
    let canCancel: Bool
    var prefill: String?
    let done: () -> Void
    @State private var url = ""
    @State private var busy = false
    @State private var error: String?
    @State private var lanHost: String?

    var body: some View {
        MacFrame(title: "Connect to your PassAuth server", subtitle: "PassAuth AutoFill signs in on its own, as a separate device.") {
            MacField(label: "Server address", text: $url, prompt: "https://vault.example.com", content: .URL, submit: submit, autofocus: true)
            Text("Use an https:// address. Plain http works only for test servers on this Mac or your local network.")
                .font(.footnote).foregroundStyle(.secondary)
            ErrorText(text: error)
            MacPrimaryButton(title: busy ? "Checking…" : "Connect", busy: busy, enabled: !url.trimmingCharacters(in: .whitespaces).isEmpty, action: submit)
            if canCancel {
                Button("Back") { done() }.buttonStyle(.link).frame(maxWidth: .infinity)
            }
        }
        .onAppear { if url.isEmpty { url = prefill ?? model.state.server } }
        .alert("Use plain http?", isPresented: Binding(get: { lanHost != nil }, set: { if !$0 { lanHost = nil } })) {
            Button("Connect anyway", role: .destructive) { connect(allowLanHttp: true) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(lanHost ?? "This server") isn't using https. Anyone on this network could read your sign-in and change what the server sends. Only continue on a network you trust, such as a test server at home.")
        }
    }

    private func submit() { connect(allowLanHttp: false) }

    private func connect(allowLanHttp: Bool) {
        guard !busy, !url.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.setServer(url, allowLanHttp: allowLanHttp)
                busy = false
                done()
                return
            } catch let e as PlainHttpConfirmation {
                lanHost = e.host
            } catch { self.error = errorMessage(error) }
            busy = false
        }
    }
}

private struct MacLoginStep: View {
    @Bindable var model: AutofillModel
    var handoff: DesktopHandoff?
    let changeServer: () -> Void
    let twoStep: (String, [String], String) -> Void
    @State private var email = ""
    @State private var password = ""
    @State private var secretKey = ""
    @State private var needKey = false
    @State private var busy = false
    @State private var error: String?
    @State private var fromDesktop = false
    /// The email the hand-off was for: typing another email drops its Secret Key too.
    @State private var handoffEmail = ""
    /// Set once the prefill is known: the first empty box gets the focus.
    @State private var focusPassword = false

    var body: some View {
        MacFrame(title: "Sign in to PassAuth", subtitle: hostOf(model.state.server)) {
            if fromDesktop {
                Notice(text: "Server and email come from the PassAuth app on this Mac. Enter your master password once: AutoFill signs in as its own device and then unlocks with Touch ID or on its own timer.", kind: .ok)
            }
            MacField(label: "Email", text: $email, content: .username, autofocus: !focusPassword)
            MacField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } }, autofocus: focusPassword)
            if needKey {
                if fromDesktop && !secretKey.isEmpty {
                    Text("Secret Key from the PassAuth app on this Mac. Change it here if it's not the right one.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                MacField(label: "Secret Key", text: $secretKey, mono: true, prompt: "PA1-XXXXXX-…", submit: submit)
            }
            ErrorText(text: error)
            MacPrimaryButton(title: busy ? "Signing in…" : "Sign in", busy: busy,
                             enabled: !email.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty, action: submit)
            Button("Change server") { changeServer() }.buttonStyle(.link).frame(maxWidth: .infinity)
        }
        .onAppear {
            guard email.isEmpty else { return }
            if let h = handoff ?? DesktopHandoff.read(for: model.state.server), h.server == model.state.server {
                email = h.email ?? model.state.email
                secretKey = h.secretKey ?? ""
                fromDesktop = !email.isEmpty
                handoffEmail = Self.normalized(email)
                // Shown prefilled, so a wrong or stale key can be corrected.
                needKey = !secretKey.isEmpty
            } else {
                email = model.state.email
            }
            focusPassword = !email.isEmpty
        }
        .onChange(of: email) {
            // Another account than the hand-off's: its Secret Key doesn't apply.
            guard fromDesktop, Self.normalized(email) != handoffEmail else { return }
            fromDesktop = false
            secretKey = ""
            handoffEmail = ""
        }
    }

    private static func normalized(_ email: String) -> String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private func submit() {
        guard !busy, !email.trimmingCharacters(in: .whitespaces).isEmpty, !password.isEmpty else { return }
        busy = true
        error = nil
        let mail = email
        Task {
            do {
                switch try await model.repo.login(email: mail, password: password, secretKey: secretKey.isEmpty ? nil : secretKey) {
                case .twoFactor(let token, let providers):
                    busy = false
                    twoStep(token, providers, mail)
                case .done:
                    password = ""
                    await model.signedIn()
                    busy = false
                }
            } catch {
                if (error as? UserError)?.message == secretKeyRequiredMessage { needKey = true }
                self.error = errorMessage(error)
                busy = false
            }
        }
    }
}

func providerLabel(_ p: String) -> String {
    switch p {
    case "totp": "Authenticator app"
    case "email": "Email code"
    case "recovery": "Recovery code"
    default: p
    }
}

/// Two-step providers PassAuth knows, in the server's order (authenticator app when none is known).
/// Security keys (`passkey`, WebAuthn) are left out: the extension can't use them yet.
func twoStepChoices(_ providers: [String]) -> [String] {
    let known = providers.filter { ["totp", "email", "recovery"].contains($0) }
    return known.isEmpty ? ["totp"] : known
}

/// Whether the account's only method besides recovery codes is a security key.
func securityKeyOnly(_ providers: [String]) -> Bool {
    providers.contains("passkey") && twoStepChoices(providers).allSatisfy { $0 == "recovery" }
}

let securityKeyUnsupportedMessage = "This account uses a security key for two-step login, which this app doesn't support yet. Use a recovery code, or sign in with the web vault."

private struct MacTwoStep: View {
    @Bindable var model: AutofillModel
    let token: String
    let providers: [String]
    let email: String
    let back: () -> Void
    @State private var provider = ""
    @State private var code = ""
    @State private var remember = true
    @State private var busy = false
    @State private var error: String?
    @State private var note: String?

    var body: some View {
        let choices = twoStepChoices(providers)
        MacFrame(title: "Two-step login", subtitle: email) {
            if securityKeyOnly(providers) { Notice(text: securityKeyUnsupportedMessage) }
            if choices.count > 1 {
                Picker("Verify with", selection: $provider) {
                    ForEach(choices, id: \.self) { Text(providerLabel($0)).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .onChange(of: provider) { code = ""; error = nil }
            }
            MacField(label: provider == "recovery" ? "Recovery code" : "6-digit code", text: $code, mono: true,
                     content: provider == "recovery" ? nil : .oneTimeCode, submit: verify)
            if provider == "email" {
                Button {
                    Task {
                        do {
                            try await model.repo.sendTwoFactorEmail(token: token)
                            note = "Code sent to \(email)."
                        } catch { self.error = errorMessage(error) }
                    }
                } label: { Text("Email me a code").frame(maxWidth: .infinity) }
                    .controlSize(.large)
            }
            Toggle(isOn: $remember) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Remember this Mac")
                    Text("Skip two-step login here for a while.").font(.footnote).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)
            if let note { Notice(text: note, kind: .ok) }
            ErrorText(text: error)
            MacPrimaryButton(title: busy ? "Verifying…" : "Verify and sign in", busy: busy,
                             enabled: !code.trimmingCharacters(in: .whitespaces).isEmpty, action: verify)
            Button("Back") { back() }.buttonStyle(.link).frame(maxWidth: .infinity)
        }
        .onAppear { if provider.isEmpty { provider = choices[0] } }
    }

    private func verify() {
        guard !busy, !code.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.verifyTwoFactor(token: token, provider: provider, code: code, remember: remember)
                await model.signedIn()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}
