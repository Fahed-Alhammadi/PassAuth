import PassAuthCore
import PassAuthKit
import SwiftUI
import UniformTypeIdentifiers

private struct LinkRow: View {
    let text: String
    let action: String
    let run: () -> Void
    var body: some View {
        HStack(spacing: 4) {
            Text(text).foregroundStyle(Color.paMuted)
            Button(action, action: run).fontWeight(.medium)
        }
        .font(.subheadline)
    }
}

// MARK: Setup

struct SetupView: View {
    @Environment(AppModel.self) private var model
    var initial = ""
    var onCancel: (() -> Void)? = nil
    @State private var url = ""
    @State private var busy = false
    @State private var error: String?
    @State private var lanHost: String?

    var body: some View {
        AuthFrame(title: "Connect to your PassAuth server") {
            AuthField(label: "Server address", text: $url, keyboard: .URL, content: .URL, prompt: "https://vault.example.com", submit: submit)
            Text("Use an https:// address. Plain http works only for test servers on this device or your local network.")
                .font(.footnote).foregroundStyle(Color.paMuted).frame(maxWidth: .infinity, alignment: .leading)
            ErrorText(text: error)
            PrimaryButton(title: busy ? "Checking…" : "Connect", busy: busy, enabled: !url.trimmingCharacters(in: .whitespaces).isEmpty, action: submit)
            if let onCancel { Button("Cancel", action: onCancel) }
            OtherAccounts()
        }
        .onAppear { if url.isEmpty { url = initial } }
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
            } catch let e as PlainHttpConfirmation {
                lanHost = e.host
            } catch { self.error = errorMessage(error) }
            busy = false
        }
    }
}

// MARK: Login

struct LoginView: View {
    @Environment(AppModel.self) private var model
    @State private var changingServer = false
    @State private var creating = false
    @State private var email = ""
    @State private var password = ""
    @State private var secretKey = ""
    @State private var needKey = false
    @State private var challenge: (token: String, providers: [String])?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        let state = model.state
        if changingServer {
            SetupView(initial: state.server) { changingServer = false }
        } else if creating {
            RegisterView(onSignIn: { e, p, sk in
                creating = false
                email = e
                if let p { signIn(e, p, sk) }
            }, onBack: { creating = false })
        } else if let c = challenge {
            TwoStepView(token: c.token, providers: c.providers, email: email) { challenge = nil }
        } else {
            AuthFrame(title: "Sign in to PassAuth") {
                AuthField(label: "Email", text: $email, keyboard: .emailAddress, content: .username)
                AuthField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } })
                if needKey {
                    AuthField(label: "Secret Key", text: $secretKey, mono: true, prompt: "PA1-XXXXXX-…", submit: submit)
                }
                ErrorText(text: error)
                PrimaryButton(title: busy ? "Signing in…" : "Sign in", busy: busy, enabled: !email.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty, action: submit)
                LinkRow(text: hostOf(state.server), action: "Change server") { changingServer = true }
                LinkRow(text: "New to PassAuth?", action: "Create account") { creating = true }
                OtherAccounts()
            }
            .onAppear { if email.isEmpty { email = state.email } }
        }
    }

    private func submit() {
        guard !busy, !email.trimmingCharacters(in: .whitespaces).isEmpty, !password.isEmpty else { return }
        signIn(email, password, secretKey.isEmpty ? nil : secretKey)
    }

    private func signIn(_ e: String, _ p: String, _ sk: String?) {
        busy = true
        error = nil
        Task {
            do {
                if case .twoFactor(let token, let providers) = try await model.repo.login(email: e, password: p, secretKey: sk) {
                    challenge = (token, providers)
                }
            } catch {
                if (error as? UserError)?.message == secretKeyRequiredMessage { needKey = true }
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}

private func providerLabel(_ p: String) -> String {
    switch p {
    case "totp": "Authenticator app"
    case "email": "Email code"
    default: "Recovery code"
    }
}

struct TwoStepView: View {
    @Environment(AppModel.self) private var model
    let token: String
    let providers: [String]
    let email: String
    let onCancel: () -> Void
    @State private var provider = ""
    @State private var code = ""
    @State private var remember = true
    @State private var busy = false
    @State private var error: String?
    @State private var note: String?

    private var choices: [String] {
        let known = providers.filter { ["totp", "email", "recovery"].contains($0) }
        return known.isEmpty ? ["totp"] : known
    }

    var body: some View {
        AuthFrame(title: "Two-step login") {
            if choices.count > 1 {
                Picker("Verify with", selection: $provider) {
                    ForEach(choices, id: \.self) { Text(providerLabel($0)).tag($0) }
                }
                .pickerStyle(.segmented)
                .onChange(of: provider) { code = ""; error = nil }
            }
            AuthField(label: provider == "recovery" ? "Recovery code" : "6-digit code", text: $code, mono: true,
                      keyboard: provider == "recovery" ? .asciiCapable : .numberPad, content: .oneTimeCode, submit: verify)
            if provider == "email" {
                Button {
                    Task {
                        do {
                            try await model.repo.sendTwoFactorEmail(token: token)
                            note = "Code sent to \(email)."
                        } catch { self.error = errorMessage(error) }
                    }
                } label: { Text("Email me a code").frame(maxWidth: .infinity) }
                    .buttonStyle(.bordered).controlSize(.large)
            }
            Toggle(isOn: $remember) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Remember this device")
                    Text("Skip two-step login on this device for a while.").font(.footnote).foregroundStyle(Color.paMuted)
                }
            }
            if let note { Notice(text: note, kind: .ok) }
            ErrorText(text: error)
            PrimaryButton(title: busy ? "Verifying…" : "Verify and sign in", busy: busy, enabled: !code.trimmingCharacters(in: .whitespaces).isEmpty, action: verify)
            Button("Back", action: onCancel)
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
            } catch {
                self.error = errorMessage(error)
                busy = false
            }
        }
    }
}

// MARK: Register

/// A text file for the Emergency Kit (saved with the system's file picker).
struct TextFile: FileDocument {
    static let readableContentTypes: [UTType] = [.plainText]
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws { text = "" }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: Data(text.utf8)) }
}

private func emergencyKit(server: String, email: String, secretKey: String) -> String {
    [
        "PassAuth Emergency Kit", "",
        "Server:      \(server)",
        "Email:       \(email)",
        "Secret Key:  \(secretKey)", "",
        "Master password: ______________________________", "",
        "Keep this kit somewhere safe and offline, such as a printed copy in a drawer",
        "or safe. You need the Secret Key and your master password to sign in on a new",
        "device. PassAuth cannot recover either of them for you.", "",
    ].joined(separator: "\n")
}

/// Create an account (the web vault's Register). `onSignIn(email, password?, secretKey?)`.
struct RegisterView: View {
    @Environment(AppModel.self) private var model
    let onSignIn: (String, String?, String?) -> Void
    let onBack: () -> Void
    @State private var email = ""
    @State private var name = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var hinted = false
    @State private var withSecretKey = false
    @State private var busy = false
    @State private var error: String?
    @State private var done: Registered?
    @State private var saved = false
    @State private var closed = false
    @State private var exporting = false

    var body: some View {
        if let d = done {
            AuthFrame(title: "Your vault is ready") {
                if let sk = d.secretKey {
                    Text("This is your Secret Key. You need it, together with your master password, to sign in on a new device. Save it now: it is shown only once and PassAuth cannot recover it.")
                        .font(.subheadline).foregroundStyle(Color.paInk)
                    Text(sk)
                        .font(.body.monospaced())
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                        .padding(14)
                        .frame(maxWidth: .infinity)
                        .background(Color.paSurface2, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.paLine))
                        .accessibilityIdentifier("secretKey")
                    VStack(spacing: 10) {
                        Button { exporting = true } label: { Label("Save Emergency Kit", systemImage: "square.and.arrow.down").frame(maxWidth: .infinity) }
                        Button { model.copy(sk, "Secret Key") } label: { Label("Copy Secret Key", systemImage: "doc.on.doc").frame(maxWidth: .infinity) }
                    }
                    .buttonStyle(.bordered).controlSize(.large)
                    Toggle("I saved my Secret Key somewhere safe", isOn: $saved).accessibilityIdentifier("savedToggle")
                }
                if d.emailVerificationRequired {
                    Notice(text: "We sent a verification link to \(email). Open it, then sign in.", kind: .ok)
                }
                PrimaryButton(title: d.emailVerificationRequired ? "Go to sign in" : "Open my vault", enabled: d.secretKey == nil || saved) {
                    model.showsSecret = false
                    onSignIn(email, d.emailVerificationRequired ? nil : password, d.secretKey)
                }
            }
            .onAppear { model.showsSecret = d.secretKey != nil }
            .onDisappear { model.showsSecret = false }
            .fileExporter(isPresented: $exporting, document: TextFile(text: emergencyKit(server: model.state.server, email: email, secretKey: d.secretKey ?? "")),
                          contentType: .plainText, defaultFilename: "PassAuth-Emergency-Kit.txt") { result in
                if case .success = result { model.notify("Emergency Kit saved.") }
            }
        } else {
            AuthFrame(title: "Create your PassAuth account", subtitle: "Everything is encrypted on this device before it reaches the server.") {
                if closed {
                    Notice(text: "Sign-ups are closed on this server. Ask the administrator for an invitation, then create your account with the invited email address.")
                }
                AuthField(label: "Email", text: $email, keyboard: .emailAddress, content: .username)
                AuthField(label: "Your name", text: $name, content: .name)
                AuthField(label: "Master password", text: Binding(get: { password }, set: { password = $0; hinted = false }), secure: true)
                StrengthMeter(password: password, reserveSpace: true)
                AuthField(label: "Confirm master password", text: $confirm, secure: true)
                Notice(text: "Your master password can't be reset. If you forget it, the data in your vault can't be recovered by anyone, including the server administrator.")
                Toggle(isOn: $withSecretKey) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Add a Secret Key")
                        Text("A second, random key that never leaves your devices. Even if the server is breached, your vault can't be cracked by guessing your password. You'll enter it once on each new device.")
                            .font(.footnote).foregroundStyle(Color.paMuted)
                    }
                }
                .accessibilityIdentifier("secretKeyToggle")
                ErrorText(text: error)
                PrimaryButton(title: busy ? "Creating account…" : "Create account", busy: busy, enabled: !email.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty, action: submit)
                LinkRow(text: "Already have an account?", action: "Sign in", run: onBack)
            }
            .task { closed = await model.repo.signupsAllowed() == false }
        }
    }

    private func submit() {
        error = nil
        if password.count < 10 { error = "Use at least 10 characters for your master password."; return }
        if password != confirm { error = "The two passwords don't match."; return }
        if estimateBits(password: password) < 50 && !hinted {
            hinted = true
            error = "This password is easy to guess. Choose a longer one, or select Create account again to use it anyway."
            return
        }
        busy = true
        Task {
            do {
                done = try await model.repo.register(email: email, name: name, password: password, withSecretKey: withSecretKey)
            } catch { self.error = errorMessage(error) }
            busy = false
        }
    }
}

// MARK: Unlock

struct UnlockView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @State private var confirmLogout = false
    @State private var password = ""
    @State private var secretKey = ""
    @State private var busy = false
    @State private var error: String?
    @State private var triedBiometric = false

    var body: some View {
        let state = model.state
        let needKey = state.secretKeyRequired && !state.secretKeyStored
        let bio = BiometryKind.current
        let canBio = state.biometricEnabled && bio.available
        AuthFrame(title: "Unlock PassAuth", subtitle: state.email) {
            AuthField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } })
            if needKey { AuthField(label: "Secret Key", text: $secretKey, mono: true, submit: submit) }
            ErrorText(text: error)
            PrimaryButton(title: busy ? "Unlocking…" : "Unlock", busy: busy, enabled: !password.isEmpty, action: submit)
            if canBio {
                Button(action: biometric) {
                    Label("Unlock with \(bio.name)", systemImage: bio.symbol).frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered).controlSize(.large).disabled(busy)
            }
            Button("Log out", role: .destructive) { confirmLogout = true }
            OtherAccounts()
        }
        .confirmationDialog("Log out of \(state.email)?", isPresented: $confirmLogout, titleVisibility: .visible) {
            Button("Log out", role: .destructive) { model.run { await model.repo.logout() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(state.accounts.count > 1
                ? "This account, its offline copy and Face ID unlock are removed from this device. Your vault stays on your server."
                : "You'll need your master password to sign in again. Your vault stays on your server.")
        }
        // Offer Face ID / Touch ID right away, once, and only while the app is on screen (with
        // "Immediately" the vault locks as the app goes to the background, where the Keychain
        // refuses the biometric read).
        .task(id: scenePhase == .active) {
            guard scenePhase == .active, canBio, !triedBiometric else { return }
            triedBiometric = true
            try? await Task.sleep(for: .milliseconds(350))
            guard scenePhase == .active else { triedBiometric = false; return }
            biometric(auto: true)
        }
    }

    private func submit() {
        guard !busy, !password.isEmpty else { return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.unlock(password: password, secretKey: secretKey.isEmpty ? nil : secretKey)
            } catch {
                self.error = errorMessage(error)
                busy = false
            }
        }
    }

    private func biometric() { biometric(auto: false) }

    private func biometric(auto: Bool) {
        guard !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                let done = try await model.repo.unlockWithBiometric(reason: "Unlock PassAuth")
                // Not shown (the app left the screen meanwhile): offer it again when it's back.
                if !done && auto && scenePhase != .active { triedBiometric = false }
            } catch { self.error = errorMessage(error) }
            busy = false
        }
    }
}

// MARK: Other accounts

func statusLabel(_ s: Status) -> String {
    switch s {
    case .unlocked: "Unlocked"
    case .locked: "Locked"
    case .loggedOut: "Logged out"
    case .setup: ""
    }
}

/// On the setup, sign-in and unlock screens: switch to another account, or cancel adding one.
struct OtherAccounts: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let state = model.state
        let others = state.accounts.filter { $0.id != state.activeId }
        if !others.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text(state.adding ? "Or go back to" : "Switch account").font(.footnote.weight(.medium)).foregroundStyle(Color.paMuted)
                ForEach(others) { a in
                    Button {
                        model.run {
                            if state.adding { await model.repo.cancelAddAccount(to: a.id) } else { try await model.repo.switchAccount(a.id) }
                        }
                    } label: {
                        AccountRow(account: a)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.top, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct AccountRow: View {
    let account: AccountSummary
    var body: some View {
        HStack(spacing: 12) {
            Avatar(text: initials(account.name, account.email), size: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text(account.name.isEmpty ? account.email : account.name).foregroundStyle(Color.paInk).lineLimit(1)
                Text(hostOf(account.server)).font(.footnote).foregroundStyle(Color.paMuted).lineLimit(1)
            }
            Spacer()
            Text(statusLabel(account.status)).font(.caption).foregroundStyle(Color.paMuted)
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}
