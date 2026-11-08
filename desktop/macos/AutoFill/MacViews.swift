import AppKit
import PassAuthKit
import SwiftUI
import os

// The macOS AutoFill sheet: native macOS controls (rounded text fields, grouped forms, push
// buttons) with the PassAuth accent and logo from ios/UI/Theme.swift. Same screens as the iOS
// extension, plus sign-in and the extension's own settings.

struct MacAutofillRoot: View {
    @Bindable var model: AutofillModel
    @State private var settings = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            Group {
                if settings {
                    MacSettings(model: model) { settings = false }
                } else {
                    content
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            footer
        }
        .frame(minWidth: 420, idealWidth: 460, minHeight: 480, idealHeight: 560)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Color.paAccent)
    }

    private var signedIn: Bool {
        let s = model.state.status
        return s == .locked || s == .unlocked
    }

    private var header: some View {
        HStack(spacing: 10) {
            LogoMark(height: 22)
            Text(title).font(.headline)
            Spacer()
            if signedIn && model.screen != .configured && model.screen != .loading {
                Button { settings.toggle() } label: {
                    Image(systemName: settings ? "chevron.backward" : "gearshape")
                }
                .buttonStyle(.borderless)
                .help(settings ? "Back" : "PassAuth AutoFill settings")
                .accessibilityLabel(settings ? "Back" : "Settings")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var title: String {
        if settings { return "Settings" }
        switch model.screen {
        case .list: return model.onlyCodes ? "Verification codes" : "PassAuth"
        case .confirmPasskey: return "Save passkey"
        case .configured: return "PassAuth AutoFill"
        default: return "PassAuth"
        }
    }

    private var footer: some View {
        HStack {
            if model.repo.vault?.offline == true && model.screen == .list {
                Text("Showing the copy on this Mac.").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if model.screen == .configured {
                Button("Done") { model.finishConfiguration() }
                    .keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel") { model.cancel() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    @ViewBuilder private var content: some View {
        switch model.screen {
        case .loading:
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        case .signedOut:
            MacSignIn(model: model)
        case .unlock:
            MacUnlock(model: model)
        case .list:
            MacList(model: model)
        case .confirmPasskey:
            MacPasskey(model: model)
        case .message(let title, let text):
            MacInfo(symbol: "exclamationmark.triangle", title: title, text: text)
        case .configured:
            MacSettings(model: model, onBack: nil)
        case .confirmSave, .generate:
            // iOS only (macOS has no save / generate requests).
            MacInfo(symbol: "exclamationmark.triangle", title: "Not available", text: "This request isn't supported on macOS.")
        }
    }
}

// MARK: Building blocks

/// A centered column with the logo and a title (sign-in, unlock, confirmations).
struct MacFrame<Content: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                LogoMark(height: 44).padding(.top, 20)
                Text(title).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
                    .accessibilityAddTraits(.isHeader)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                VStack(alignment: .leading, spacing: 12) { content }.padding(.top, 4)
            }
            .frame(maxWidth: 340)
            .padding(.horizontal, 24)
            .padding(.bottom, 20)
            .frame(maxWidth: .infinity)
        }
    }
}

/// A labelled text box, native macOS style; `secure` hides the text (with a reveal button).
struct MacField: View {
    let label: String
    @Binding var text: String
    var secure = false
    var mono = false
    var prompt: String? = nil
    var content: NSTextContentType? = nil
    var submit: (() -> Void)? = nil
    @State private var reveal = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.subheadline.weight(.medium))
            HStack(spacing: 6) {
                Group {
                    if secure && !reveal {
                        SecureField("", text: $text, prompt: prompt.map { Text($0) })
                    } else {
                        TextField("", text: $text, prompt: prompt.map { Text($0) })
                            .font(mono ? .body.monospaced() : .body)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .textContentType(content)
                .autocorrectionDisabled()
                .onSubmit { submit?() }
                .accessibilityLabel(label)
                .accessibilityIdentifier(label)
                if secure {
                    Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                        .buttonStyle(.borderless)
                        .help(reveal ? "Hide" : "Show")
                        .accessibilityLabel(reveal ? "Hide \(label.lowercased())" : "Show \(label.lowercased())")
                }
            }
        }
    }
}

/// The main action: full width, prominent, the brand blue, triggered by Return.
struct MacPrimaryButton: View {
    let title: String
    var busy = false
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if busy { ProgressView().controlSize(.small) }
                Text(title).frame(maxWidth: .infinity)
            }
        }
        .buttonStyle(.borderedProminent)
        .tint(Color.paAccentFill)
        .controlSize(.large)
        .keyboardShortcut(.defaultAction)
        .disabled(!enabled || busy)
    }
}

struct MacInfo: View {
    let symbol: String
    let title: String
    let text: String

    var body: some View {
        MacFrame(title: title) {
            Image(systemName: symbol).font(.system(size: 30)).foregroundStyle(Color.paAccent)
                .frame(maxWidth: .infinity).accessibilityHidden(true)
            Text(text).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: .infinity)
                .accessibilityIdentifier("autofillMessage")
        }
    }
}

// MARK: Unlock

struct MacUnlock: View {
    @Bindable var model: AutofillModel
    @State private var password = ""
    @State private var secretKey = ""
    @State private var triedBiometric = false

    var body: some View {
        let state = model.state
        let needKey = state.secretKeyRequired && !state.secretKeyStored
        let bio = BiometryKind.current
        let canBio = state.biometricEnabled && bio.available
        MacFrame(title: "Unlock PassAuth", subtitle: state.email) {
            MacField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } })
            if needKey { MacField(label: "Secret Key", text: $secretKey, mono: true, submit: submit) }
            ErrorText(text: model.error)
            MacPrimaryButton(title: model.busy ? "Unlocking…" : "Unlock", busy: model.busy, enabled: !password.isEmpty, action: submit)
            if canBio {
                Button { model.unlockWithBiometric() } label: {
                    Label("Unlock with \(bio.name)", systemImage: bio.symbol).frame(maxWidth: .infinity)
                }
                .controlSize(.large).disabled(model.busy)
                .accessibilityIdentifier("autofillBiometric")
            }
        }
        .task {
            if canBio && !triedBiometric {
                triedBiometric = true
                try? await Task.sleep(for: .milliseconds(300))
                model.unlockWithBiometric()
            }
        }
    }

    private func submit() {
        model.unlock(password: password, secretKey: secretKey)
    }
}

// MARK: List

struct MacList: View {
    @Bindable var model: AutofillModel
    @State private var query = ""
    @FocusState private var searchFocused: Bool

    var body: some View {
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        let suggestions = model.suggestions
        let _ = Logger(subsystem: "io.passauth.autofill", category: "list").notice("list: \(model.pages.count) pages, \(suggestions.count) suggestions, \(model.repo.vault?.entries.count ?? -1) entries")
        let passkeys = model.passkeyChoices
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search logins", text: $query)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .accessibilityIdentifier("search")
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                        .buttonStyle(.borderless).accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(nsColor: .separatorColor)))
            .padding(.horizontal, 16).padding(.vertical, 10)

            List {
                if model.isVaultPage {
                    Text("PassAuth doesn't fill logins into its own web vault.").foregroundStyle(.secondary)
                }
                if !searching && !passkeys.isEmpty {
                    Section("Passkeys for \(model.passkeyRpId ?? "")") {
                        ForEach(passkeys, id: \.1.credentialId) { e, p in
                            Button { model.pickPasskey(e, p) } label: {
                                MacRow(title: p.userName.isEmpty ? e.item.name : p.userName,
                                       subtitle: p.createdAt > 0 ? "\(e.item.name) · saved \(formatDate(p.createdAt))" : e.item.name, symbol: "person.badge.key")
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("passkey-\(p.userName)")
                        }
                    }
                }
                if !searching && !model.pages.isEmpty && !model.isVaultPage {
                    Section(model.pages.first.map { "Suggestions for \(AutofillMatcher.displayHost($0))" } ?? "Suggestions") {
                        if suggestions.isEmpty {
                            Text(model.onlyCodes ? "No login with a verification code for this website." : "No saved login for this website. Search all logins.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(suggestions) { e in entryRow(e) }
                    }
                }
                let shown = Set(suggestions.map(\.id))
                let results = model.searchResults(query).filter { searching || model.isVaultPage || !shown.contains($0.id) }
                if searching || !results.isEmpty {
                    Section(searching ? "Results" : model.pages.isEmpty ? "All logins" : "Other logins") {
                        if results.isEmpty { Text("No logins found.").foregroundStyle(.secondary) }
                        ForEach(results) { e in entryRow(e) }
                    }
                }
            }
            .listStyle(.inset)
        }
        .onAppear { searchFocused = suggestions.isEmpty && passkeys.isEmpty }
    }

    private func entryRow(_ e: Entry) -> some View {
        Button { model.pick(e) } label: {
            MacRow(title: e.item.name, subtitle: e.item.login?.username ?? "", letter: e.item.name, hasCode: Clipboard.totp(e.item.login?.totp) != nil)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("login-\(e.item.name)")
        .disabled(model.isVaultPage)
    }
}

private struct MacRow: View {
    let title: String
    let subtitle: String
    var symbol: String? = nil
    var letter: String = ""
    var hasCode = false

    var body: some View {
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color.paAccent.opacity(0.12))
                .frame(width: 28, height: 28)
                .overlay {
                    if let symbol {
                        Image(systemName: symbol).foregroundStyle(Color.paAccent)
                    } else {
                        Text(String(letter.trimmingCharacters(in: .whitespaces).first ?? "?").uppercased())
                            .font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.paAccent)
                    }
                }
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(title.isEmpty ? "Untitled" : title).lineLimit(1)
                if !subtitle.isEmpty { Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(1) }
            }
            Spacer(minLength: 0)
            if hasCode {
                Image(systemName: "clock.badge.checkmark").foregroundStyle(.secondary).help("Has a verification code")
                    .accessibilityLabel("Has verification code")
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

// MARK: Passkey registration

struct MacPasskey: View {
    @Bindable var model: AutofillModel

    var body: some View {
        let r = model.registration
        MacFrame(title: "Save a passkey?", subtitle: r?.rpId) {
            Text("For \(r?.user ?? "") on \(r?.rpId ?? ""). PassAuth keeps it in your vault (\(model.state.email)).")
                .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: .infinity)
            ErrorText(text: model.error)
            MacPrimaryButton(title: model.busy ? "Saving…" : "Save passkey", busy: model.busy, action: model.savePasskey)
                .accessibilityIdentifier("savePasskey")
        }
    }
}

// MARK: Settings (configuration screen and the gear button)

/// Default URI match options, as the iOS app's Settings → AutoFill (`ios/App/SettingsViews.swift`).
private let defaultMatches: [(UrlMatch, String)] = [
    (.domain, "Base domain"), (.host, "Host"), (.startsWith, "Starts with"), (.regex, "Regular expression"), (.exact, "Exact"), (.never, "Never"),
]

private func matchHelp(_ m: UrlMatch) -> String {
    switch m {
    case .host: "Same host name and port only: login.example.com doesn't match www.example.com."
    case .startsWith: "The page address must start with the saved website address."
    case .regex: "The saved website is a regular expression tested against the page address. Advanced."
    case .exact: "The page address must be exactly the saved website address."
    case .never: "Never suggest or fill logins automatically. Items can still set their own matching."
    default: "login.example.com and www.example.com both match example.com."
    }
}

struct MacSettings: View {
    @Bindable var model: AutofillModel
    /// Shown from the gear button: back to the request. Nil on the configuration screen.
    let onBack: (() -> Void)?
    @State private var confirmSignOut = false
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        let state = model.state
        let bio = BiometryKind.current
        Form {
            if onBack == nil {
                Section {
                    Label {
                        Text("PassAuth fills your logins, passkeys and verification codes in Safari and apps. Your vault stays encrypted: macOS only learns the website and user name of each login.")
                            .foregroundStyle(.secondary)
                    } icon: {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.paOk)
                    }
                }
            }
            Section("Account") {
                LabeledContent("Email", value: state.email)
                LabeledContent("Server", value: hostOf(state.server))
                LabeledContent("Vault", value: state.status == .unlocked ? "Unlocked" : "Locked")
            }
            Section {
                Picker("Vault timeout", selection: Binding(get: { state.settings.vaultTimeout }, set: { setTimeout($0) })) {
                    ForEach(TimedUnlockPolicy.choices, id: \.self) { Text($0.label).tag($0) }
                }
                if bio.available {
                    Toggle("Unlock with \(bio.name)", isOn: Binding(get: { state.biometricEnabled }, set: { setBiometric($0) }))
                        .disabled(busy || (state.status != .unlocked && !state.biometricEnabled))
                }
                Toggle(isOn: Binding(get: { state.settings.autoCopyTotp }, set: { v in
                    Task { await model.repo.updateSettings { $0.autoCopyTotp = v } }
                })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Copy verification code after filling")
                        Text("On Mac the clipboard isn't cleared automatically. The code is marked as private, so clipboard history apps skip it.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Security")
            } footer: {
                Text(state.settings.vaultTimeout == .never
                     ? "Your vault opens without your master password until you lock it or sign out."
                     : "After this time without AutoFill use, PassAuth asks for your master password\(bio.available ? " or \(bio.name)" : "") again.")
                    .foregroundStyle(.secondary)
            }
            Section {
                Picker("Default URI match detection", selection: Binding(get: { state.settings.defaultMatch }, set: { v in
                    Task { await model.repo.updateSettings { $0.defaultMatch = v } }
                })) {
                    ForEach(defaultMatches, id: \.0) { Text($0.1).tag($0.0) }
                }
            } header: {
                Text("Filling")
            } footer: {
                Text("\(matchHelp(state.settings.defaultMatch)) Applies to websites set to \"Default\" in an item; the same setting as in the apps and the browser extension, kept per device.")
                    .foregroundStyle(.secondary)
            }
            if let error { Text(error).foregroundStyle(Color.paDanger) }
            Section {
                if state.status == .unlocked {
                    Button("Lock now") { lockNow() }
                }
                Button("Sign out…", role: .destructive) { confirmSignOut = true }
            }
        }
        .formStyle(.grouped)
        .disabled(busy)
        .confirmationDialog("Sign out of \(state.email)?", isPresented: $confirmSignOut) {
            Button("Sign out", role: .destructive) { signOut() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("PassAuth AutoFill forgets this account and its copy of your vault on this Mac. Your vault stays on your server.")
        }
    }

    private func setTimeout(_ t: VaultTimeout) {
        Task {
            await model.repo.updateSettings { $0.vaultTimeout = t }
            TimedUnlock.keep(model.repo) // Keeps (or forgets) the keys with the new deadline.
        }
    }

    private func setBiometric(_ on: Bool) {
        error = nil
        if !on { return model.repo.disableBiometric() }
        busy = true
        Task {
            defer { busy = false }
            guard await BiometryKind.confirm(reason: "Turn on \(BiometryKind.current.name) for PassAuth AutoFill") else { return }
            do { try await model.repo.enableBiometric() } catch { self.error = errorMessage(error) }
        }
    }

    private func lockNow() {
        Task {
            TimedUnlock.forget()
            await model.repo.lockAll()
            onBack?()
            model.screen = .unlock
        }
    }

    private func signOut() {
        busy = true
        Task {
            TimedUnlock.forget()
            await model.repo.logout()
            busy = false
            onBack?()
            model.screen = .signedOut
        }
    }
}
