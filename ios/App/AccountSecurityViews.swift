import CoreImage
import CoreImage.CIFilterBuiltins
import PassAuthCore
import PassAuthKit
import SwiftUI

// Settings → Account security: change the master password (and the Secret Key setting) and
// two-step login, natively (the web vault's Settings → Security and Two-step login).
// Secrets (passwords, setup key, recovery codes, a new Secret Key) live only in view state:
// they are dropped when a screen closes, and the window gets the privacy cover in the app
// switcher while one is on screen (`AppModel.showsSecret`, the vault is unlocked anyway).

// MARK: Change master password

struct ChangePasswordPage: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var typedKey = ""
    @State private var newPassword = ""
    @State private var confirm = ""
    /// The Secret Key toggle; nil = as the account has it now.
    @State private var useKey: Bool?
    @State private var weakAccepted = false
    @State private var busy = false
    @State private var error: String?
    @State private var confirming = false
    @State private var newKey: String?
    @State private var showKey = false

    var body: some View {
        let s = model.state
        let wasOn = s.secretKeyRequired
        let change = SecretKeyChange.from(wasOn: wasOn, wantOn: useKey ?? wasOn)
        Form {
            Section {
                Text("Your master password encrypts your vault and is never sent to the server. If you forget it, nobody can recover your data.")
                    .foregroundStyle(Color.paInk)
            }
            .paRow()
            Section {
                SecretInput(label: "Current master password", text: $current, mono: false, identifier: "pw.current")
                if wasOn && !s.secretKeyStored {
                    LabeledInput(label: "Secret Key", text: $typedKey, mono: true, autocap: .characters, identifier: "pw.secretKey")
                }
            } header: {
                Text("Current")
            }
            .paRow()
            Section {
                SecretInput(label: "New master password", text: Binding(get: { newPassword }, set: { newPassword = $0; if weakAccepted { error = nil }; weakAccepted = false }),
                            mono: false, content: .newPassword, identifier: "pw.new")
                StrengthMeter(password: newPassword, scale: .masterPassword)
                SecretInput(label: "Confirm new master password", text: $confirm, mono: false, content: .newPassword, identifier: "pw.confirm")
            } header: {
                Text("New")
            } footer: {
                Text("At least \(AccountSecurityLogic.minPasswordLength) characters. A few unrelated words are easy to remember and hard to guess."
                     + (change == .keep ? "" : " Leave both empty to keep your current master password."))
            }
            .paRow()
            Section {
                Toggle("Use a Secret Key", isOn: Binding(get: { useKey ?? wasOn }, set: { useKey = $0 }))
                    .accessibilityIdentifier("pw.useSecretKey")
            } header: {
                Text("Secret Key")
            } footer: {
                Text(secretKeyFooter(change, wasOn: wasOn))
            }
            .paRow()
            Section {
                ErrorText(text: error)
                Button(action: submit) {
                    HStack {
                        Text(busy ? "Changing password…" : "Change master password").fontWeight(.semibold)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("pw.submit")
            } footer: {
                Text("Changing your master password signs out all your other devices.")
            }
            .paRow()
        }
        .paList()
        .navigationTitle("Change master password")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .navigationBarBackButtonHidden(busy)
        .alert(change == .turnOff && newPassword.isEmpty ? "Turn off your Secret Key?" : "Change your master password?", isPresented: $confirming) {
            Button("Cancel", role: .cancel) {}
            Button(change == .turnOff && newPassword.isEmpty ? "Turn off Secret Key" : "Change master password") { run(change) }
        } message: {
            Text(confirmText(change))
        }
        .sheet(isPresented: $showKey, onDismiss: finishNewKey) {
            if let newKey {
                NewSecretKeySheet(secretKey: newKey, email: s.email, server: s.server) { showKey = false }
            }
        }
        .onDisappear { clear() }
    }

    private func secretKeyFooter(_ change: SecretKeyChange, wasOn: Bool) -> String {
        switch change {
        case .keep where wasOn: "Your Secret Key stays the same. You need it, together with your master password, to sign in on a new device."
        case .keep: "A Secret Key is a long random code that's combined with your master password when you sign in on a new device. Even if someone learns your master password, they can't open your vault without it."
        case .turnOn: "PassAuth will create a Secret Key and show it once. You'll need it, together with your master password, to sign in on other devices."
        case .turnOff: "After this, your master password alone unlocks your vault on a new device. Your current Secret Key and Emergency Kit stop working."
        }
    }

    private func confirmText(_ change: SecretKeyChange) -> String {
        var t = "All your other devices will be signed out and need the new details to sign in again. On this device, PassAuth and AutoFill unlock with "
        t += newPassword.isEmpty ? "your current master password." : "the new master password from now on."
        if change == .turnOn { t += " PassAuth then shows your new Secret Key once." }
        if change == .turnOff { t += " Your current Secret Key and Emergency Kit stop working." }
        return t
    }

    private func submit() {
        guard !busy else { return }
        error = nil
        let change = SecretKeyChange.from(wasOn: model.state.secretKeyRequired, wantOn: useKey ?? model.state.secretKeyRequired)
        if let p = AccountSecurityLogic.passwordProblem(current: current, new: newPassword, confirm: confirm, secretKeyChange: change,
                                                        weakAccepted: weakAccepted, bits: { estimateBits(password: $0) }) {
            if p == .weak { weakAccepted = true }
            error = p.message
            UIAccessibility.post(notification: .announcement, argument: p.message)
            return
        }
        confirming = true
    }

    private func run(_ change: SecretKeyChange) {
        busy = true
        error = nil
        let c = current, n = newPassword.isEmpty ? nil : newPassword, k = typedKey.isEmpty ? nil : typedKey
        Task {
            do {
                let sk = try await model.repo.changeMasterPassword(current: c, typedSecretKey: k, newPassword: n, secretKeyChange: change)
                clear()
                useKey = nil
                if let sk {
                    newKey = sk
                    showKey = true
                } else {
                    model.notify(change == .turnOff && n == nil ? "Secret Key turned off. Other devices were signed out." : "Master password changed. Other devices were signed out.")
                    dismiss()
                }
            } catch {
                self.error = securityErrorMessage(error)
            }
            busy = false
        }
    }

    private func finishNewKey() {
        newKey = nil
        model.notify("Master password changed. Other devices were signed out.")
        dismiss()
    }

    private func clear() {
        current = ""
        typedKey = ""
        newPassword = ""
        confirm = ""
        weakAccepted = false
    }
}

/// The new Secret Key, shown once: copy, Emergency Kit (PDF via the share sheet), and
/// "I saved it" before Done. Can't be swiped away before that.
struct NewSecretKeySheet: View {
    @Environment(AppModel.self) private var model
    let secretKey: String
    let email: String
    let server: String
    let onDone: () -> Void
    @State private var saved = false
    @State private var kit: EmergencyKitPDF?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("This is the only time PassAuth shows your Secret Key. Any older Secret Key no longer works. Save it now: without it, you can't sign in on a new device.")
                        .foregroundStyle(Color.paInk)
                }
                .paRow()
                Section("Secret Key") {
                    Text(secretKey)
                        .font(.body.monospaced())
                        .foregroundStyle(Color.paInk)
                        .textSelection(.enabled)
                        .privacySensitive()
                        .padding(.vertical, 4)
                        .accessibilityLabel("Secret Key: \(secretKey.map(String.init).joined(separator: " "))")
                        .accessibilityIdentifier("newSecretKey")
                    Button { model.copy(secretKey, "Secret Key") } label: { Label("Copy Secret Key", systemImage: "doc.on.doc") }
                    if let kit {
                        ShareLink(item: kit, preview: SharePreview("PassAuth Emergency Kit")) {
                            Label("Save or share Emergency Kit", systemImage: "square.and.arrow.up")
                        }
                        .accessibilityIdentifier("shareKit")
                    }
                }
                .paRow()
                Section {
                    Toggle("I saved my Secret Key", isOn: $saved).accessibilityIdentifier("savedToggle")
                } footer: {
                    Text("The Emergency Kit has your server, email and Secret Key, with a line to write your master password on.")
                }
                .paRow()
                Section {
                    Button(action: onDone) { Text("Done").fontWeight(.semibold) }
                        .disabled(!saved)
                        .accessibilityIdentifier("newKey.done")
                }
                .paRow()
            }
            .paList()
            .navigationTitle("Save your new Secret Key")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
        }
        .interactiveDismissDisabled(!saved)
        .onAppear {
            model.showsSecret = true
            kit = EmergencyKitPDF(data: EmergencyKit.pdf(server: server, email: email, secretKey: secretKey))
        }
        .onDisappear {
            kit = nil
            model.showsSecret = false
        }
    }
}

// MARK: Two-step login

private enum ReauthAction: Identifiable, Equatable {
    case disable(TwoFactorProvider)
    case regenerate
    case removeKey(SecurityKeyInfo)

    var id: String {
        switch self {
        case .disable(let p): "disable-\(p.rawValue)"
        case .regenerate: "regenerate"
        case .removeKey(let k): "remove-key-\(k.id)"
        }
    }
}

struct TwoStepPage: View {
    @Environment(AppModel.self) private var model
    @State private var status: TwoFactorStatus?
    @State private var loadError: String?
    @State private var loading = false
    @State private var settingUpTotp = false
    @State private var reauth: ReauthAction?
    // Email codes setup (inline).
    @State private var emailSent = false
    @State private var emailCode = ""
    @State private var emailBusy = false
    @State private var emailError: String?
    @State private var emailCodes = ShownOnce([])
    @State private var showEmailCodes = false

    var body: some View {
        Form {
            Section {
                Text("Two-step login asks for a code after your master password when you sign in on a new device, so a stolen password isn't enough.")
                    .foregroundStyle(Color.paInk)
            }
            .paRow()
            if let status {
                totpSection(status)
                emailSection(status)
                securityKeysSection(status)
                recoverySection(status)
            } else if let loadError {
                Section {
                    ErrorText(text: loadError)
                    Button("Try again") { Task { await load() } }
                }
                .paRow()
            } else {
                Section {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Loading…").foregroundStyle(Color.paMuted)
                    }
                }
                .paRow()
            }
        }
        .paList()
        .navigationTitle("Two-step login")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .task { await load() }
        .refreshable { await load() }
        .sheet(isPresented: $settingUpTotp, onDismiss: { Task { await load() } }) {
            TotpSetupSheet()
        }
        .sheet(item: $reauth, onDismiss: { Task { await load() } }) { action in
            ReauthSheet(action: action, lastMethod: status.map { s -> Bool in
                switch action {
                case .disable(let p): return s.isLast(p)
                case .removeKey: return s.isLastKey()
                case .regenerate: return false
                }
            } ?? false)
        }
        .sheet(isPresented: $showEmailCodes, onDismiss: { emailCodes = ShownOnce([]); Task { await load() } }) {
            NavigationStack {
                Form {
                    RecoveryCodesView(once: $emailCodes) { if emailCodes.close() { showEmailCodes = false } }
                }
                .paList()
                .navigationTitle("Save your recovery codes")
                .navigationBarTitleDisplayMode(.inline)
                .paNavBar()
            }
            .interactiveDismissDisabled(!emailCodes.canClose)
        }
        .onDisappear {
            emailCode = ""
            emailSent = false
        }
    }

    private func load() async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        do {
            status = try await model.repo.twoFactorStatus()
            loadError = nil
        } catch {
            if status == nil { loadError = securityErrorMessage(error) } else { model.notify(securityErrorMessage(error)) }
        }
    }

    @ViewBuilder
    private func totpSection(_ s: TwoFactorStatus) -> some View {
        Section {
            MethodRow(title: "Authenticator app", on: s.totpOn, symbol: "clock.badge.checkmark")
            if s.totpOn {
                Button(role: .destructive) { reauth = .disable(.totp) } label: { Text("Turn off authenticator app") }
                    .accessibilityIdentifier("totp.off")
            } else {
                Button { settingUpTotp = true } label: { Text("Set up authenticator app") }
                    .accessibilityIdentifier("totp.setup")
            }
        } footer: {
            Text("Get a new 6-digit code every 30 seconds from an authenticator app.")
        }
        .paRow()
    }

    @ViewBuilder
    private func emailSection(_ s: TwoFactorStatus) -> some View {
        Section {
            MethodRow(title: "Email codes", on: s.emailOn, symbol: "envelope.badge")
            if s.emailOn {
                Button(role: .destructive) { reauth = .disable(.email) } label: { Text("Turn off email codes") }
                    .accessibilityIdentifier("email.off")
            } else if !s.emailAvailable {
                Text("This server isn't set up to send email, so email codes aren't available. Ask your PassAuth administrator to configure email.")
                    .font(.subheadline).foregroundStyle(Color.paMuted)
            } else if emailSent {
                Text("We sent a code to \(s.email). Enter it below.").font(.subheadline).foregroundStyle(Color.paInk)
                LabeledInput(label: "Verification code", text: $emailCode, mono: true, keyboard: .numberPad, content: .oneTimeCode, autocap: .never, identifier: "email.code")
                ErrorText(text: emailError)
                Button(action: enableEmail) {
                    HStack {
                        Text(emailBusy ? "Checking code…" : "Turn on email codes").fontWeight(.semibold)
                        if emailBusy { Spacer(); ProgressView() }
                    }
                }
                .disabled(emailBusy || !AccountSecurityLogic.isEmailCode(emailCode))
                .accessibilityIdentifier("email.enable")
                Button("Send a new code", action: sendEmail).disabled(emailBusy)
                Button("Cancel") {
                    emailSent = false
                    emailCode = ""
                    emailError = nil
                }
                .disabled(emailBusy)
            } else {
                ErrorText(text: emailError)
                Button(action: sendEmail) {
                    HStack {
                        Text(emailBusy ? "Sending…" : "Send setup code")
                        if emailBusy { Spacer(); ProgressView() }
                    }
                }
                .disabled(emailBusy)
                .accessibilityIdentifier("email.send")
            }
        } footer: {
            Text("Get a one-time code by email at \(s.email) when you sign in.")
        }
        .paRow()
    }

    /// Security keys / passkeys for two-step login: added in the web vault, listed and removed here.
    @ViewBuilder
    private func securityKeysSection(_ s: TwoFactorStatus) -> some View {
        Section {
            MethodRow(title: "Security keys", on: !s.securityKeys.isEmpty, symbol: "key.horizontal")
            ForEach(s.securityKeys) { k in
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(k.name.isEmpty ? "Security key" : k.name).foregroundStyle(Color.paInk)
                        Text(keyDetail(k)).font(.footnote).foregroundStyle(Color.paMuted)
                    }
                    Spacer()
                    Button(role: .destructive) { reauth = .removeKey(k) } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Color.paDanger)
                    .accessibilityLabel("Remove security key \(k.name)")
                    .accessibilityIdentifier("key.remove.\(k.id)")
                }
                .accessibilityElement(children: .combine)
            }
        } footer: {
            Text(s.securityKeys.isEmpty
                 ? "Use a hardware security key or a passkey to confirm your sign-in. Add one in the web vault under Settings → Two-step login."
                 : "Add keys in the web vault. This app can't use a security key to sign in yet, so keep another method on if you sign in here.")
        }
        .paRow()
    }

    private func keyDetail(_ k: SecurityKeyInfo) -> String {
        let f = Date.FormatStyle(date: .abbreviated, time: .omitted)
        var t = "Added \(Date(timeIntervalSince1970: TimeInterval(k.createdAt)).formatted(f))"
        if let u = k.lastUsedAt { t += " · last used \(Date(timeIntervalSince1970: TimeInterval(u)).formatted(f))" } else { t += " · never used" }
        return t
    }

    @ViewBuilder
    private func recoverySection(_ s: TwoFactorStatus) -> some View {
        Section {
            if s.anyOn {
                Text("Use a recovery code to sign in if you lose access to your other methods. You have \(s.recoveryCodesLeft) unused \(s.recoveryCodesLeft == 1 ? "code" : "codes") left.")
                    .foregroundStyle(Color.paInk)
                    .accessibilityIdentifier("recoveryLeft")
                if s.recoveryCodesLeft <= 3 {
                    Notice(text: "You're running low on recovery codes. Generate new ones and store them somewhere safe.")
                        .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                }
                Button { reauth = .regenerate } label: { Text("Generate new recovery codes") }
                    .accessibilityIdentifier("recovery.regenerate")
            } else {
                Text("You'll get recovery codes when you turn on your first two-step method.").foregroundStyle(Color.paMuted)
            }
        } header: {
            Text("Recovery codes")
        }
        .paRow()
    }

    private func sendEmail() {
        emailBusy = true
        emailError = nil
        Task {
            do {
                try await model.repo.sendEmailSetupCode()
                emailSent = true
                emailCode = ""
                model.notify("Code sent to \(status?.email ?? model.state.email).")
            } catch {
                emailError = securityErrorMessage(error)
            }
            emailBusy = false
        }
    }

    private func enableEmail() {
        guard AccountSecurityLogic.isEmailCode(emailCode) else {
            emailError = "Enter the code from the email we sent you."
            return
        }
        emailBusy = true
        emailError = nil
        let code = emailCode
        Task {
            do {
                let codes = try await model.repo.enableEmailCodes(code: code)
                emailSent = false
                emailCode = ""
                model.notify("Email codes turned on.")
                if let codes {
                    emailCodes = ShownOnce(codes)
                    showEmailCodes = true
                } else {
                    await load()
                }
            } catch {
                emailError = securityErrorMessage(error)
            }
            emailBusy = false
        }
    }
}

/// A method's name with its On / Off state.
private struct MethodRow: View {
    let title: String
    let on: Bool
    let symbol: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol).foregroundStyle(Color.paAccent).accessibilityHidden(true)
            Text(title).font(.headline).foregroundStyle(Color.paInk)
            Spacer()
            Text(on ? "On" : "Off")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(on ? Color.paOk : Color.paMuted)
                .padding(.horizontal, 10).padding(.vertical, 3)
                .background((on ? Color.paOk : Color.paMuted).opacity(0.14), in: Capsule())
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title), \(on ? "on" : "off")")
        .accessibilityIdentifier("method.\(title)")
    }
}

/// Authenticator setup: QR code (made on the device), setup key, open in an authenticator
/// app on this device, then the 6-digit code. The first method also shows the recovery codes.
private struct TotpSetupSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var setup: TotpSetup?
    @State private var qr: UIImage?
    @State private var startError: String?
    @State private var code = ""
    @State private var busy = false
    @State private var error: String?
    @State private var codes = ShownOnce([])

    var body: some View {
        NavigationStack {
            Form {
                if !codes.value.isEmpty {
                    RecoveryCodesView(once: $codes) { if codes.close() { dismiss() } }
                } else if let setup {
                    steps(setup)
                } else if let startError {
                    Section {
                        ErrorText(text: startError)
                        Button("Try again") { Task { await start() } }
                    }
                    .paRow()
                } else {
                    Section {
                        HStack(spacing: 10) {
                            ProgressView()
                            Text("Starting setup…").foregroundStyle(Color.paMuted)
                        }
                    }
                    .paRow()
                }
            }
            .paList()
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle(codes.value.isEmpty ? "Authenticator app" : "Save your recovery codes")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                if codes.value.isEmpty {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
                }
            }
        }
        // A typed code isn't thrown away by a stray swipe (Cancel still closes).
        .interactiveDismissDisabled(busy || !code.isEmpty || !codes.value.isEmpty)
        .task { await start() }
        .onAppear { model.showsSecret = true }
        .onDisappear {
            setup = nil
            qr = nil
            code = ""
            model.showsSecret = false
        }
    }

    @ViewBuilder
    private func steps(_ setup: TotpSetup) -> some View {
        Section {
            if let qr {
                Image(uiImage: qr)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 220, maxHeight: 220)
                    .padding(12)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .accessibilityLabel("QR code to add PassAuth to your authenticator app")
                    .accessibilityIdentifier("totp.qr")
            }
            if let url = AccountSecurityLogic.authenticatorURL(setup.uri) {
                Button {
                    openURL(url) { accepted in
                        if !accepted { model.notify("No app on this device opens authenticator setup links. Scan the QR code or enter the setup key instead.") }
                    }
                } label: { Label("Open in authenticator app", systemImage: "arrow.up.forward.app") }
                    .accessibilityIdentifier("totp.open")
            }
        } header: {
            Text("1. Scan the QR code")
        } footer: {
            Text("Scan it with your authenticator app, or open it in an authenticator app on this device.")
        }
        .paRow()
        Section {
            Text(AccountSecurityLogic.groupedSecret(setup.secret))
                .font(.body.monospaced())
                .foregroundStyle(Color.paInk)
                .textSelection(.enabled)
                .privacySensitive()
                .accessibilityLabel("Setup key: \(setup.secret.map(String.init).joined(separator: " "))")
                .accessibilityIdentifier("totp.secret")
            Button { model.copy(setup.secret, "Setup key") } label: { Label("Copy setup key", systemImage: "doc.on.doc") }
        } header: {
            Text("Can't scan it? Enter this setup key")
        }
        .paRow()
        Section {
            LabeledInput(label: "Verification code", text: $code, mono: true, keyboard: .numberPad, content: .oneTimeCode, autocap: .never, identifier: "totp.code")
            ErrorText(text: error)
            Button(action: enable) {
                HStack {
                    Text(busy ? "Checking code…" : "Turn on authenticator app").fontWeight(.semibold)
                    if busy { Spacer(); ProgressView() }
                }
            }
            .disabled(busy || !AccountSecurityLogic.isTotpCode(code))
            .accessibilityIdentifier("totp.enable")
        } header: {
            Text("2. Enter the code the app shows")
        }
        .paRow()
    }

    private func start() async {
        startError = nil
        do {
            let s = try await model.repo.startTotpSetup()
            qr = qrImage(s.uri)
            setup = s
        } catch {
            startError = securityErrorMessage(error)
        }
    }

    private func enable() {
        guard AccountSecurityLogic.isTotpCode(code) else {
            error = "Enter the 6-digit code from your authenticator app."
            return
        }
        busy = true
        error = nil
        let c = code
        Task {
            do {
                let recovery = try await model.repo.enableTotp(code: c)
                code = ""
                model.notify("Authenticator app turned on.")
                setup = nil
                qr = nil
                if let recovery { codes = ShownOnce(recovery) } else { dismiss() }
            } catch {
                self.error = securityErrorMessage(error)
                UIAccessibility.post(notification: .announcement, argument: self.error)
            }
            busy = false
        }
    }
}

/// QR code for a text, made on the device with Core Image (black on white).
func qrImage(_ text: String) -> UIImage? {
    let f = CIFilter.qrCodeGenerator()
    f.message = Data(text.utf8)
    f.correctionLevel = "M"
    guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
          let cg = CIContext().createCGImage(out, from: out.extent) else { return nil }
    return UIImage(cgImage: cg)
}

/// Master password check for turning a method off or new recovery codes (destructive: the
/// action button is red and says what happens). New codes are shown in the same sheet.
private struct ReauthSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let action: ReauthAction
    let lastMethod: Bool
    @State private var password = ""
    @State private var typedKey = ""
    @State private var busy = false
    @State private var error: String?
    @State private var codes = ShownOnce([])

    private var title: String {
        switch action {
        case .disable(.totp): "Turn off authenticator app"
        case .disable(.email): "Turn off email codes"
        case .regenerate: "Generate new recovery codes"
        case .removeKey: "Remove security key"
        }
    }

    private var confirmLabel: String {
        switch action {
        case .disable: "Turn off"
        case .regenerate: "Generate new codes"
        case .removeKey: "Remove"
        }
    }

    private var explanation: String {
        switch action {
        case .disable:
            lastMethod
                ? "This is your only two-step method. Turning it off also deletes your recovery codes, and signing in will need only your master password."
                : "You can turn it on again at any time."
        case .regenerate: "Your current recovery codes stop working as soon as the new ones are created."
        case .removeKey(let k):
            lastMethod
                ? "“\(k.name)” is your only two-step method. Removing it turns two-step login off and deletes your recovery codes."
                : "You won't be able to use “\(k.name)” to sign in any more. You can add it again in the web vault."
        }
    }

    var body: some View {
        let s = model.state
        NavigationStack {
            Form {
                if !codes.value.isEmpty {
                    RecoveryCodesView(once: $codes) { if codes.close() { dismiss() } }
                } else {
                    Section {
                        Text(explanation).foregroundStyle(Color.paInk)
                    }
                    .paRow()
                    Section {
                        SecretInput(label: "Master password", text: $password, mono: false, identifier: "reauth.password")
                        if s.secretKeyRequired && !s.secretKeyStored {
                            LabeledInput(label: "Secret Key", text: $typedKey, mono: true, autocap: .characters, identifier: "reauth.secretKey")
                        }
                    } footer: {
                        Text("Your server checks your master password first.")
                    }
                    .paRow()
                    Section {
                        ErrorText(text: error)
                        Button(role: .destructive, action: confirm) {
                            HStack {
                                Text(busy ? "Working…" : confirmLabel).fontWeight(.semibold)
                                if busy { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(busy)
                        .accessibilityIdentifier("reauth.confirm")
                    }
                    .paRow()
                }
            }
            .paList()
            .navigationTitle(codes.value.isEmpty ? title : "Save your recovery codes")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                if codes.value.isEmpty {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
                }
            }
        }
        .interactiveDismissDisabled(busy || !password.isEmpty || !codes.value.isEmpty)
        .onDisappear {
            password = ""
            typedKey = ""
        }
    }

    private func confirm() {
        guard !busy else { return }
        if password.isEmpty { error = "Enter your master password to continue."; return }
        busy = true
        error = nil
        let pw = password, k = typedKey.isEmpty ? nil : typedKey
        Task {
            do {
                switch action {
                case .disable(let p):
                    try await model.repo.disableTwoFactor(p, password: pw, typedSecretKey: k)
                    password = ""
                    model.notify(p == .totp ? "Authenticator app turned off." : "Email codes turned off.")
                    dismiss()
                case .regenerate:
                    let next = try await model.repo.regenerateRecoveryCodes(password: pw, typedSecretKey: k)
                    password = ""
                    codes = ShownOnce(next)
                case .removeKey(let key):
                    try await model.repo.removeSecurityKey(key.id, password: pw, typedSecretKey: k)
                    password = ""
                    model.notify("Security key removed.")
                    dismiss()
                }
            } catch {
                self.error = securityErrorMessage(error)
            }
            busy = false
        }
    }
}

/// Recovery codes, shown once: Copy all, Share, "I saved them" before Done (the sheet that
/// holds this can't be swiped away until then).
private struct RecoveryCodesView: View {
    @Environment(AppModel.self) private var model
    @Binding var once: ShownOnce
    let onDone: () -> Void

    var body: some View {
        let text = AccountSecurityLogic.recoveryCodesText(once.value, server: model.state.server)
        Section {
            Text("If you lose your phone or can't get email, a recovery code lets you sign in. Each code works once. This is the only time PassAuth shows them.")
                .foregroundStyle(Color.paInk)
        }
        .paRow()
        Section("Recovery codes") {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 130), spacing: 12)], alignment: .leading, spacing: 10) {
                ForEach(Array(once.value.enumerated()), id: \.offset) { i, c in
                    Text(c)
                        .font(.body.monospaced())
                        .foregroundStyle(Color.paInk)
                        .privacySensitive()
                        .accessibilityLabel("Code \(i + 1): \(c.map(String.init).joined(separator: " "))")
                }
            }
            .padding(.vertical, 6)
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("recoveryCodes")
            Button { model.copy(text, "Recovery codes") } label: { Label("Copy all", systemImage: "doc.on.doc") }
                .accessibilityIdentifier("codes.copy")
            ShareLink(item: text, subject: Text("PassAuth recovery codes")) { Label("Share", systemImage: "square.and.arrow.up") }
        }
        .paRow()
        Section {
            Toggle("I saved my recovery codes", isOn: $once.saved).accessibilityIdentifier("codes.saved")
        }
        .paRow()
        Section {
            Button(action: onDone) { Text("Done").fontWeight(.semibold) }
                .disabled(!once.canClose)
                .accessibilityIdentifier("codes.done")
        }
        .paRow()
        .onAppear { model.showsSecret = true }
        .onDisappear { model.showsSecret = false }
    }
}
