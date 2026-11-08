import AppKit
import PassAuthKit
import SwiftUI

/// The extension's own sign-in (it shares nothing with the desktop app): server address,
/// email + master password (+ Secret Key), then two-step login, as the iOS app's
/// `SetupView` / `LoginView` / `TwoStepView` (ios/App/AuthViews.swift).
struct MacSignIn: View {
    @Bindable var model: AutofillModel
    @State private var step: Step?

    enum Step: Equatable {
        case server
        case login
        case twoStep(token: String, providers: [String], email: String)
    }

    var body: some View {
        let current = step ?? (model.state.server.isEmpty ? .server : .login)
        switch current {
        case .server:
            MacServerStep(model: model, canCancel: !model.state.server.isEmpty) { step = .login }
        case .login:
            MacLoginStep(model: model, changeServer: { step = .server }) { token, providers, email in
                step = .twoStep(token: token, providers: providers, email: email)
            }
        case .twoStep(let token, let providers, let email):
            MacTwoStep(model: model, token: token, providers: providers, email: email) { step = .login }
        }
    }
}

private struct MacServerStep: View {
    @Bindable var model: AutofillModel
    let canCancel: Bool
    let done: () -> Void
    @State private var url = ""
    @State private var busy = false
    @State private var error: String?
    @State private var lanHost: String?

    var body: some View {
        MacFrame(title: "Connect to your PassAuth server", subtitle: "PassAuth AutoFill signs in on its own, as a separate device.") {
            MacField(label: "Server address", text: $url, prompt: "https://vault.example.com", content: .URL, submit: submit)
            Text("Use an https:// address. Plain http works only for test servers on this Mac or your local network.")
                .font(.footnote).foregroundStyle(.secondary)
            ErrorText(text: error)
            MacPrimaryButton(title: busy ? "Checking…" : "Connect", busy: busy, enabled: !url.trimmingCharacters(in: .whitespaces).isEmpty, action: submit)
            if canCancel {
                Button("Back") { done() }.buttonStyle(.link).frame(maxWidth: .infinity)
            }
        }
        .onAppear { if url.isEmpty { url = model.state.server } }
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
    let changeServer: () -> Void
    let twoStep: (String, [String], String) -> Void
    @State private var email = ""
    @State private var password = ""
    @State private var secretKey = ""
    @State private var needKey = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        MacFrame(title: "Sign in to PassAuth", subtitle: hostOf(model.state.server)) {
            MacField(label: "Email", text: $email, content: .username)
            MacField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } })
            if needKey {
                MacField(label: "Secret Key", text: $secretKey, mono: true, prompt: "PA1-XXXXXX-…", submit: submit)
            }
            ErrorText(text: error)
            MacPrimaryButton(title: busy ? "Signing in…" : "Sign in", busy: busy,
                             enabled: !email.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty, action: submit)
            Button("Change server") { changeServer() }.buttonStyle(.link).frame(maxWidth: .infinity)
        }
        .onAppear { if email.isEmpty { email = model.state.email } }
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
    default: "Recovery code"
    }
}

/// Two-step providers PassAuth knows, in the server's order (authenticator app when none is known).
func twoStepChoices(_ providers: [String]) -> [String] {
    let known = providers.filter { ["totp", "email", "recovery"].contains($0) }
    return known.isEmpty ? ["totp"] : known
}

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
