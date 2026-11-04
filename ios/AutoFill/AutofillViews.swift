import PassAuthKit
import SwiftUI

/// The extension's screens, in the app's look (navy bar, brand accent, same form fields).
struct AutofillRoot: View {
    @Bindable var model: AutofillModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(title)
                .navigationBarTitleDisplayMode(.inline)
                .paNavBar()
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(model.screen == .configured ? "Done" : "Cancel") {
                            if model.screen == .configured { model.finishConfiguration() } else { model.cancel() }
                        }
                        .accessibilityIdentifier("autofillCancel")
                    }
                }
        }
        .tint(Color.paAccent)
        #if DEBUG
        // Memory measured around unlocking, read by the UI tests (debug builds only).
        .overlay(alignment: .topLeading) {
            Text(model.memoryNote).font(.system(size: 1)).foregroundStyle(.clear)
                .accessibilityIdentifier("autofillMemory").allowsHitTesting(false)
        }
        #endif
    }

    private var title: String {
        switch model.screen {
        case .list: model.onlyCodes ? "Verification codes" : "PassAuth"
        case .confirmPasskey: "Save passkey"
        case .confirmSave: "Save login"
        case .generate: "Generate password"
        default: "PassAuth"
        }
    }

    @ViewBuilder private var content: some View {
        switch model.screen {
        case .loading:
            ZStack { Color.paBackground.ignoresSafeArea(); ProgressView() }
        case .signedOut:
            InfoView(symbol: "person.crop.circle.badge.questionmark", title: "Sign in to PassAuth",
                     text: "Open the PassAuth app and sign in to your account. Then your logins and passkeys are available here.")
        case .unlock:
            UnlockScreen(model: model)
        case .list:
            ListScreen(model: model)
        case .confirmPasskey:
            PasskeyScreen(model: model)
        case .message(let title, let text):
            InfoView(symbol: "exclamationmark.triangle", title: title, text: text)
        case .confirmSave:
            SaveScreen(model: model)
        case .generate:
            GenerateScreen(model: model)
        case .configured:
            InfoView(symbol: "checkmark.circle", title: "AutoFill is ready",
                     text: "PassAuth now suggests your logins above the keyboard and offers to save and use passkeys. Your vault stays encrypted: iOS only learns the website and user name of each login.")
        }
    }
}

private struct InfoView: View {
    let symbol: String
    let title: String
    let text: String

    var body: some View {
        AuthFrame(title: title) {
            Image(systemName: symbol).font(.system(size: 34)).foregroundStyle(Color.paAccent).accessibilityHidden(true)
            Text(text).font(.subheadline).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
                .accessibilityIdentifier("autofillMessage")
        }
    }
}

// MARK: Unlock

private struct UnlockScreen: View {
    @Bindable var model: AutofillModel
    @State private var password = ""
    @State private var secretKey = ""
    @State private var triedBiometric = false

    var body: some View {
        let state = model.state
        let needKey = state.secretKeyRequired && !state.secretKeyStored
        let bio = BiometryKind.current
        let canBio = state.biometricEnabled && bio.available
        let fits = model.masterPasswordFits
        AuthFrame(title: "Unlock PassAuth", subtitle: state.email) {
            if fits {
                AuthField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } })
                if needKey { AuthField(label: "Secret Key", text: $secretKey, mono: true, submit: submit) }
                ErrorText(text: model.error)
                PrimaryButton(title: model.busy ? "Unlocking…" : "Unlock", busy: model.busy, enabled: !password.isEmpty, action: submit)
            } else {
                Text(canBio
                    ? "Your account's key protection needs more memory than iOS gives AutoFill. Unlock with \(bio.name), or open the PassAuth app."
                    : "Your account's key protection needs more memory than iOS gives AutoFill. Turn on \(bio.available ? bio.name : "biometric") unlock in the PassAuth app (Settings → Account security) to unlock here.")
                    .font(.subheadline).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
                ErrorText(text: model.error)
            }
            if canBio {
                Button { model.unlockWithBiometric() } label: {
                    Label("Unlock with \(bio.name)", systemImage: bio.symbol).frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered).controlSize(.large).disabled(model.busy)
                .accessibilityIdentifier("autofillBiometric")
            }
        }
        .task {
            if canBio && !triedBiometric {
                triedBiometric = true
                try? await Task.sleep(for: .milliseconds(350))
                model.unlockWithBiometric()
            }
        }
    }

    private func submit() {
        model.unlock(password: password, secretKey: secretKey)
    }
}

// MARK: List

private struct ListScreen: View {
    @Bindable var model: AutofillModel
    @State private var query = ""

    var body: some View {
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        let suggestions = model.suggestions
        let passkeys = model.passkeyChoices
        List {
            if model.isVaultPage {
                Section { Text("PassAuth doesn't fill logins into its own web vault.").foregroundStyle(Color.paMuted) }.paRow()
            }
            if !searching && !passkeys.isEmpty {
                Section("Passkeys for \(model.passkeyRpId ?? "")") {
                    ForEach(passkeys, id: \.1.credentialId) { e, p in
                        Button { model.pickPasskey(e, p) } label: {
                            Row(title: p.userName.isEmpty ? e.item.name : p.userName,
                                subtitle: p.createdAt > 0 ? "\(e.item.name) · saved \(formatDate(p.createdAt))" : e.item.name, symbol: "person.badge.key")
                        }
                        .accessibilityIdentifier("passkey-\(p.userName)")
                    }
                }
                .paRow()
            }
            if !searching && !model.pages.isEmpty && !model.isVaultPage {
                Section(model.pages.first.map { "Suggestions for \(AutofillMatcher.displayHost($0))" } ?? "Suggestions") {
                    if suggestions.isEmpty {
                        Text(model.onlyCodes ? "No login with a verification code for this website." : "No saved login for this website. Search all logins below.")
                            .font(.subheadline).foregroundStyle(Color.paMuted)
                    }
                    ForEach(suggestions) { e in entryRow(e) }
                }
                .paRow()
            }
            // Other logins (the suggestions aren't repeated), or the search results.
            let shown = Set(suggestions.map(\.id))
            let results = model.searchResults(query).filter { searching || model.isVaultPage || !shown.contains($0.id) }
            if searching || !results.isEmpty {
                Section(searching ? "Results" : model.pages.isEmpty ? "All logins" : "Other logins") {
                    if results.isEmpty { Text("No logins found.").foregroundStyle(Color.paMuted) }
                    ForEach(results) { e in entryRow(e) }
                }
                .paRow()
            }
        }
        .paList()
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search logins")
        .overlay(alignment: .bottom) {
            if model.repo.vault?.offline == true {
                Text("Showing the copy on this device.").font(.caption).foregroundStyle(Color.paMuted).padding(.bottom, 8)
                    .accessibilityIdentifier("autofillOffline")
            }
        }
    }

    private func entryRow(_ e: Entry) -> some View {
        Button { model.pick(e) } label: {
            Row(title: e.item.name, subtitle: e.item.login?.username ?? "", letter: e.item.name, hasCode: Clipboard.totp(e.item.login?.totp) != nil)
        }
        .accessibilityIdentifier("login-\(e.item.name)")
        .disabled(model.isVaultPage)
    }
}

private struct Row: View {
    let title: String
    let subtitle: String
    var symbol: String? = nil
    var letter: String = ""
    var hasCode = false

    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color.paSurface2)
                .frame(width: 36, height: 36)
                .overlay {
                    if let symbol {
                        Image(systemName: symbol).foregroundStyle(Color.paAccent)
                    } else {
                        Text(String(letter.trimmingCharacters(in: .whitespaces).first ?? "?").uppercased())
                            .font(.system(size: 15, weight: .semibold)).foregroundStyle(Color.paAccent)
                    }
                }
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title.isEmpty ? "Untitled" : title).foregroundStyle(Color.paInk).lineLimit(1)
                if !subtitle.isEmpty { Text(subtitle).font(.subheadline).foregroundStyle(Color.paMuted).lineLimit(1) }
            }
            Spacer(minLength: 0)
            if hasCode {
                Image(systemName: "clock.badge.checkmark").foregroundStyle(Color.paMuted).accessibilityLabel("Has verification code")
            }
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

// MARK: Passkey registration

private struct PasskeyScreen: View {
    @Bindable var model: AutofillModel

    var body: some View {
        let r = model.registration
        AuthFrame(title: "Save a passkey?", subtitle: r?.rpId) {
            Text("For \(r?.user ?? "") on \(r?.rpId ?? ""). PassAuth keeps it in your vault (\(model.state.email)).")
                .font(.subheadline).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
            ErrorText(text: model.error)
            PrimaryButton(title: model.busy ? "Saving…" : "Save passkey", busy: model.busy, action: model.savePasskey)
                .accessibilityIdentifier("savePasskey")
        }
    }
}

// MARK: Saving a login

private struct SaveScreen: View {
    @Bindable var model: AutofillModel
    @State private var reveal = false

    var body: some View {
        let info = model.saveInfo
        let update: Entry? = if case .update(let e)? = model.savePlan { e } else { nil }
        AuthFrame(title: update == nil ? "Save this login?" : "Update the password?", subtitle: model.saveHost) {
            VStack(alignment: .leading, spacing: 10) {
                detail("User name", (info?.username ?? "").isEmpty ? "No user name" : info?.username ?? "", id: "saveUser")
                Divider()
                HStack {
                    detail("Password", reveal ? info?.password ?? "" : String(repeating: "•", count: min(info?.password.count ?? 0, 16)), id: "savePassword", mono: reveal)
                    Spacer(minLength: 8)
                    Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                        .accessibilityLabel(reveal ? "Hide password" : "Show password")
                }
            }
            .padding(14)
            .background(Color.paSurface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            Text(update.map { "Replaces the password of \($0.item.name.isEmpty ? "this login" : $0.item.name). The old one stays in its password history." }
                 ?? "A new login for \(model.saveHost) in your vault (\(model.state.email)).")
                .font(.subheadline).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
                .accessibilityIdentifier("saveSummary")
            ErrorText(text: model.error)
            PrimaryButton(title: model.busy ? "Saving…" : update == nil ? "Save" : "Update", busy: model.busy, action: model.confirmSave)
                .accessibilityIdentifier("saveLogin")
            Button { model.cancel() } label: { Text("Not now").frame(maxWidth: .infinity) }
                .buttonStyle(.bordered).controlSize(.large).disabled(model.busy)
                .accessibilityIdentifier("saveNotNow")
            Button("Never for this site", role: .destructive) { model.neverSaveHere() }
                .disabled(model.busy)
                .accessibilityIdentifier("saveNever")
        }
    }

    private func detail(_ label: String, _ value: String, id: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(Color.paMuted)
            Text(value).font(mono ? .system(.body, design: .monospaced) : .body).foregroundStyle(Color.paInk)
                .lineLimit(2).truncationMode(.middle)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(id == "savePassword" && !mono ? "hidden" : value)
        .accessibilityIdentifier(id)
    }
}

// MARK: Generating a password

private struct GenerateScreen: View {
    @Bindable var model: AutofillModel
    @State private var index = 0

    var body: some View {
        let list = model.generated
        let current = list.indices.contains(index) ? list[index] : list.first
        let page = model.generateInfo?.page.map(AutofillMatcher.displayHost)
        AuthFrame(title: "New password", subtitle: page) {
            if list.count > 1 {
                Picker("Type", selection: $index) {
                    ForEach(list.indices, id: \.self) { i in Text(label(list[i].kind)).tag(i) }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("generateType")
            }
            Text(current?.value ?? "")
                .speechSpellsOutCharacters()
                .font(.system(.title3, design: .monospaced))
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(14)
                .background(Color.paSurface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .textSelection(.enabled)
                .accessibilityIdentifier("generatedPassword")
            StrengthMeter(password: current?.value ?? "")
            if let note {
                Text(note).font(.footnote).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
                    .accessibilityIdentifier("generateNote")
            }
            PrimaryButton(title: "Use this \(current?.kind == .passphrase ? "passphrase" : "password")", enabled: current != nil) {
                if let current { model.useGenerated([current]) }
            }
            .accessibilityIdentifier("useGenerated")
            Button { model.regenerate() } label: {
                Label("Regenerate", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered).controlSize(.large)
            .accessibilityIdentifier("regenerate")
        }
        .onChange(of: list.count) { if index >= list.count { index = 0 } }
    }

    private var note: String? {
        guard let plan = model.generatePlan else { return nil }
        if plan.rules == nil { return "Made with your PassAuth generator settings." }
        return plan.followsRules
            ? "Follows this website's password rules."
            : "This website's password rules can't be met, so your PassAuth generator settings are used. The website may not accept it."
    }

    private func label(_ k: PasswordGeneration.Kind) -> String {
        switch k {
        case .strong: "Strong"
        case .alphanumeric: "No symbols"
        case .passphrase: "Passphrase"
        }
    }
}
