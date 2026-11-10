import PassAuthKit
import SwiftUI

/// The extension's screens. Every one is a prompt with the same anatomy (`ios/UI/DecisionSheet.swift`):
/// brand bar, context row (what is decided, for which site), choices, verification, actions.
struct AutofillRoot: View {
    @Bindable var model: AutofillModel

    var body: some View {
        NavigationStack {
            content
                .promptBar(closeText: model.screen == .configured ? "Done" : nil, closeIdentifier: "autofillCancel") {
                    if model.screen == .configured { model.finishConfiguration() } else { model.cancel() }
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

    @ViewBuilder private var content: some View {
        switch model.screen {
        case .loading:
            ZStack { Color.paBackground.ignoresSafeArea(); ProgressView().accessibilityLabel("Opening your vault") }
        case .signedOut:
            InfoView(symbol: "person.crop.circle.badge.questionmark", title: "Sign in to PassAuth",
                     text: "Open the PassAuth app and sign in to your account. Then your logins and passkeys are available here.") { model.cancel() }
        case .unlock:
            UnlockScreen(model: model)
        case .list:
            ListScreen(model: model)
        case .confirmPasskey:
            PasskeyScreen(model: model)
        case .message(let title, let text):
            InfoView(symbol: "exclamationmark.triangle", title: title, text: text) { model.cancel() }
        case .confirmSave:
            SaveScreen(model: model)
        case .generate:
            GenerateScreen(model: model)
        case .configured:
            InfoView(symbol: "checkmark.circle", title: "AutoFill is ready",
                     text: "PassAuth now suggests your logins above the keyboard and offers to save and use passkeys. Your vault stays encrypted: iOS only learns the website and username of each login.")
        }
    }
}

/// A state with nothing to decide (signed out, ready, something went wrong): centred, like an empty state.
private struct InfoView: View {
    let symbol: String
    let title: String
    let text: String
    /// The way out, when the bar's button isn't the only one worth offering.
    var close: (() -> Void)? = nil

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: symbol)
        } description: {
            Text(text).accessibilityIdentifier("autofillMessage")
        } actions: {
            if let close {
                Button("Close", action: close).buttonStyle(.bordered).controlSize(.large)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.paBackground.ignoresSafeArea())
    }
}

// MARK: Unlock

private struct UnlockScreen: View {
    @Bindable var model: AutofillModel
    @State private var password = ""
    @State private var secretKey = ""
    @State private var triedBiometric = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        let state = model.state
        let needKey = state.secretKeyRequired && !state.secretKeyStored
        let bio = BiometryKind.current
        let canBio = state.biometricEnabled && bio.available
        let fits = model.masterPasswordFits
        PromptScaffold(error: model.error) {
            Section {
                PromptHeader(site: model.requestHost ?? "", symbol: model.requestHost == nil ? "lock.fill" : nil,
                             title: model.unlockTitle, subtitle: model.requestHost ?? state.email)
                    .promptPlainRow()
            }
            if fits {
                Section {
                    SecretInput(label: "Master password", text: $password, mono: false, submit: { if !needKey { submit() } }, focus: $passwordFocused)
                    if needKey { SecretInput(label: "Secret Key", text: $secretKey, content: nil, submit: submit) }
                } footer: {
                    Text("Your vault is locked. Enter the master password for \(state.email).")
                }
                .paRow()
            } else {
                Section {
                    Notice(text: canBio
                        ? "Your account's key protection needs more memory than iOS gives AutoFill. Unlock with \(bio.name), or open the PassAuth app."
                        : "Your account's key protection needs more memory than iOS gives AutoFill. Turn on \(bio.available ? bio.name : "biometric") unlock in the PassAuth app (Settings → Account security) to unlock here.")
                        .promptPlainRow()
                }
            }
        } actions: {
            if fits {
                PrimaryButton(title: model.busy ? "Unlocking…" : "Unlock", busy: model.busy, enabled: !password.isEmpty, action: submit)
                if canBio {
                    QuietActions {
                        QuietButton(title: "Use \(bio.name)", symbol: bio.symbol) { model.unlockWithBiometric() }
                            .disabled(model.busy)
                            .accessibilityIdentifier("autofillBiometric")
                    }
                }
            } else if canBio {
                PrimaryButton(title: "Unlock with \(bio.name)", busy: model.busy) { model.unlockWithBiometric() }
                    .accessibilityIdentifier("autofillBiometric")
            }
        }
        .task {
            if canBio && !triedBiometric {
                triedBiometric = true
                try? await Task.sleep(for: .milliseconds(350))
                model.unlockWithBiometric()
            } else if fits && !canBio {
                // Nothing else to do here but type the password.
                try? await Task.sleep(for: .milliseconds(450))
                passwordFocused = true
            }
        }
    }

    private func submit() {
        model.unlock(password: password, secretKey: secretKey)
    }
}

// MARK: List (choose a login, a passkey or a verification code)

private struct ListScreen: View {
    @Bindable var model: AutofillModel
    @State private var query = ""
    /// A website asked for a passkey and the vault has some: choose one and sign in. Off once
    /// the user asks for a password instead.
    @State private var passkeyPrompt = true

    var body: some View {
        let passkeys = model.passkeyChoices
        if passkeyPrompt && !passkeys.isEmpty {
            PasskeySignIn(model: model, passkeys: passkeys) { passkeyPrompt = false }
        } else {
            picker(passkeys)
        }
    }

    private func picker(_ passkeys: [(Entry, Passkey)]) -> some View {
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        let suggestions = model.suggestions
        let host = model.requestHost
        return List {
            if !searching {
                Section {
                    PromptHeader(site: host ?? "", symbol: host == nil ? (model.onlyCodes ? "clock" : "key.fill") : nil,
                                 title: model.onlyCodes ? "Choose a verification code" : "Choose a login", subtitle: host)
                        .promptPlainRow()
                }
            }
            if !searching && !passkeys.isEmpty {
                Section("Passkeys") {
                    ForEach(passkeys, id: \.1.credentialId) { e, p in
                        Button { model.pickPasskey(e, p) } label: {
                            Row(title: p.userName.isEmpty ? e.item.name : p.userName, subtitle: passkeyDetail(e, p), symbol: "person.badge.key")
                        }
                        .accessibilityIdentifier("passkey-\(p.userName)")
                    }
                }
                .paRow()
            }
            if !searching && !model.pages.isEmpty {
                Section("For this site") {
                    if suggestions.isEmpty {
                        Text(model.onlyCodes ? "No login with a verification code for this site. Search your other logins below." : "No login saved for this site. Search your other logins below.")
                            .font(.subheadline).foregroundStyle(Color.paMuted)
                            .accessibilityIdentifier("autofillNoMatch")
                    }
                    ForEach(suggestions) { e in entryRow(e) }
                }
                .paRow()
            }
            // Other logins (the suggestions aren't repeated), or the search results.
            let shown = Set(suggestions.map(\.id))
            let results = model.searchResults(query).filter { searching || !shown.contains($0.id) }
            if searching || !results.isEmpty {
                Section(searching ? "Results" : model.pages.isEmpty ? "All logins" : "Other logins") {
                    if results.isEmpty { Text("No login matches “\(query.trimmingCharacters(in: .whitespaces))”.").foregroundStyle(Color.paMuted) }
                    ForEach(results) { e in entryRow(e) }
                }
                .paRow()
            }
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(.compact)
        .contentMargins(.top, PA.Space.s, for: .scrollContent)
        .paList()
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search logins")
        .overlay(alignment: .bottom) {
            if model.repo.vault?.offline == true {
                Text("Showing the copy on this device.").font(.caption).foregroundStyle(Color.paMuted).padding(.bottom, PA.Space.s)
                    .accessibilityIdentifier("autofillOffline")
            }
        }
    }

    private func entryRow(_ e: Entry) -> some View {
        Button { model.pick(e) } label: {
            Row(title: e.item.name, subtitle: e.item.login?.username ?? "", letter: e.item.name, hasCode: Clipboard.totp(e.item.login?.totp) != nil)
        }
        .accessibilityIdentifier("login-\(e.item.name)")
    }
}

/// "Lumen Mail · 29 Oct 2026": the login a passkey is in and the day it was saved.
private func passkeyDetail(_ e: Entry, _ p: Passkey) -> String {
    guard p.createdAt > 0 else { return e.item.name }
    let day = Date(timeIntervalSince1970: TimeInterval(p.createdAt)).formatted(date: .abbreviated, time: .omitted)
    return e.item.name.isEmpty ? "Saved \(day)" : "\(e.item.name) · \(day)"
}

/// Sign in with a passkey: choose the account (the newest passkey is preselected), one button.
private struct PasskeySignIn: View {
    @Bindable var model: AutofillModel
    let passkeys: [(Entry, Passkey)]
    let usePassword: () -> Void
    @State private var chosen = ""

    var body: some View {
        let selected = passkeys.first { $0.1.credentialId == chosen } ?? passkeys.first
        PromptScaffold(error: model.error) {
            Section {
                PromptHeader(site: model.passkeyRpId ?? "", title: "Sign in with a passkey", subtitle: model.passkeyRpId)
                    .promptPlainRow()
            }
            Section {
                ForEach(passkeys, id: \.1.credentialId) { e, p in
                    ChoiceRow(title: p.userName.isEmpty ? e.item.name : p.userName, detail: passkeyDetail(e, p), symbol: "person.badge.key",
                              selected: selected?.1.credentialId == p.credentialId) { chosen = p.credentialId }
                        .accessibilityIdentifier("passkey-\(p.userName)")
                }
            } header: {
                if passkeys.count > 1 { Text("Choose an account") }
            }
            .paRow()
        } actions: {
            PrimaryButton(title: model.busy ? "Signing in…" : "Sign in", busy: model.busy, enabled: selected != nil) {
                if let (e, p) = selected { model.pickPasskey(e, p) }
            }
            .accessibilityIdentifier("passkeySignIn")
            QuietActions {
                QuietButton(title: "Use a password instead", action: usePassword)
                    .accessibilityIdentifier("passkeyUsePassword")
            }
        }
    }
}

private struct Row: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    let title: String
    let subtitle: String
    var symbol: String? = nil
    var letter: String = ""
    var hasCode = false

    var body: some View {
        HStack(spacing: PA.Space.m) {
            if !typeSize.isAccessibilitySize { InitialTile(text: letter, symbol: symbol) }
            VStack(alignment: .leading, spacing: 2) {
                Text(title.isEmpty ? "Untitled" : title).foregroundStyle(Color.paInk)
                if !subtitle.isEmpty { Text(subtitle).font(.subheadline).foregroundStyle(Color.paMuted) }
            }
            .lineLimit(typeSize.isAccessibilitySize ? nil : 1)
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
        let rp = r?.rpId ?? ""
        PromptScaffold(error: model.error) {
            Section {
                PromptHeader(site: rp, title: "Save a passkey", subtitle: rp).promptPlainRow()
            }
            Section {
                DetailRow(label: "Passkey for", value: (r?.user ?? "").isEmpty ? rp : r?.user ?? "", identifier: "passkeyUser")
            } footer: {
                if model.passkeyTargets.isEmpty { Text("Saved as a new login for \(rp) in your vault (\(model.state.email)).") }
            }
            .paRow()
            if !model.passkeyTargets.isEmpty {
                Section {
                    ForEach(model.passkeyTargets, id: \.id) { e in
                        // A login in a vault somebody shared says so (its vault's name); it is never preselected.
                        let user = (e.item.login?.username ?? "").isEmpty ? "No username" : e.item.login?.username ?? ""
                        ChoiceRow(title: e.item.name.isEmpty ? rp : e.item.name,
                                  detail: model.sharedVaultName(e).map { "\(user) · shared vault \($0)" } ?? user,
                                  selected: model.passkeyTarget == e.id) { model.passkeyTarget = e.id }
                            .accessibilityIdentifier("saveIn-\(e.id)")
                    }
                    ChoiceRow(title: "New login", detail: rp, symbol: "plus", selected: model.passkeyTarget == PasskeyLogic.newLogin) {
                        model.passkeyTarget = PasskeyLogic.newLogin
                    }
                    .accessibilityIdentifier("saveInNew")
                } header: {
                    Text("Save in")
                } footer: {
                    Text(passkeyFooter)
                }
                .paRow()
                .disabled(model.busy)
            }
        } actions: {
            PrimaryButton(title: model.busy ? "Saving…" : "Save passkey", busy: model.busy, action: model.savePasskey)
                .accessibilityIdentifier("savePasskey")
            QuietActions {
                QuietButton(title: "Cancel") { model.cancel() }.disabled(model.busy)
            }
        }
    }
}

private extension PasskeyScreen {
    /// Where the passkey goes; for a login in a shared vault, who else gets it.
    var passkeyFooter: String {
        if let e = model.passkeyTargets.first(where: { $0.id == model.passkeyTarget }), let shared = model.sharedVaultName(e) {
            return "The passkey is kept with that login in the shared vault \(shared); its members can use it too."
        }
        return "The passkey is kept with that login in your vault (\(model.state.email))."
    }
}

// MARK: Saving a login

private struct SaveScreen: View {
    @Bindable var model: AutofillModel
    @State private var reveal = false

    var body: some View {
        let info = model.saveInfo
        let user = (info?.username ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let password = info?.password ?? ""
        let update = model.saveUpdates
        PromptScaffold(error: model.error) {
            Section {
                PromptHeader(site: model.saveHost, title: update == nil ? "Save login?" : "Update login?", subtitle: model.saveHost)
                    .promptPlainRow()
            }
            Section {
                DetailRow(label: "Username", value: user.isEmpty ? "No username" : user, muted: user.isEmpty,
                          spoken: user.isEmpty ? "none" : user, identifier: "saveUser")
                DetailRow(label: "Password", value: reveal ? password : String(repeating: "•", count: 8), mono: reveal,
                          spoken: reveal ? password : "hidden", identifier: "savePassword") {
                    Button { reveal.toggle() } label: {
                        Image(systemName: reveal ? "eye.slash" : "eye").frame(minWidth: 44, minHeight: 44).contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(reveal ? "Hide password" : "Show password")
                }
            } footer: {
                if model.saveTargets.isEmpty { summary(update, user: user, password: password) }
            }
            .paRow()
            if !model.saveTargets.isEmpty {
                Section {
                    ForEach(model.saveTargets, id: \.id) { e in
                        // A login in a vault somebody shared says so (its vault's name).
                        let user = (e.item.login?.username ?? "").isEmpty ? "No username" : e.item.login?.username ?? ""
                        ChoiceRow(title: e.item.name.isEmpty ? model.saveHost : e.item.name,
                                  detail: model.sharedVaultName(e).map { "\(user) · shared vault \($0)" } ?? user,
                                  selected: model.saveTarget == e.id) { model.chooseSaveTarget(e.id) }
                            .accessibilityIdentifier("saveIn-\(e.id)")
                    }
                    ChoiceRow(title: "New login", detail: model.saveHost, symbol: "plus", selected: model.saveTarget == SaveLogic.newLogin) {
                        model.chooseSaveTarget(SaveLogic.newLogin)
                    }
                    .accessibilityIdentifier("saveInNew")
                } header: {
                    Text("Save in")
                } footer: {
                    summary(update, user: user, password: password)
                }
                .paRow()
                .disabled(model.busy)
            }
        } actions: {
            PrimaryButton(title: model.busy ? "Saving…" : update == nil ? "Save" : "Update", busy: model.busy, action: model.confirmSave)
                .accessibilityIdentifier("saveLogin")
            QuietActions {
                QuietButton(title: "Not now") { model.cancel() }
                    .accessibilityIdentifier("saveNotNow")
                QuietButton(title: "Never for this site") { model.neverSaveHere() }
                    .accessibilityIdentifier("saveNever")
            }
            .disabled(model.busy)
        }
    }

    private func summary(_ update: Entry?, user: String, password: String) -> some View {
        Text(SaveSummary.text(update: update?.item, user: user, password: password, host: model.saveHost, account: model.state.email,
                              sharedVault: update.flatMap(model.sharedVaultName)))
            .accessibilityIdentifier("saveSummary")
    }
}

/// What the save prompt is about to do, in words (names the username and the site or login).
enum SaveSummary {
    /// `sharedVault`: the name of the vault the updated login is in, when somebody shared it.
    static func text(update: Item?, user: String, password: String, host: String, account: String, sharedVault: String? = nil) -> String {
        if let sharedVault {
            return text(update: update, user: user, password: password, host: host, account: account)
                + " This login is in the shared vault \(sharedVault); its members see the change."
        }
        guard let item = update, let login = item.login else {
            return user.isEmpty
                ? "Saves this password as a new login for \(host) in your vault (\(account))."
                : "Saves \(user) as a new login for \(host) in your vault (\(account))."
        }
        let name = item.name.isEmpty ? "this login" : item.name
        let saved = login.username.trimmingCharacters(in: .whitespacesAndNewlines)
        let history = login.password.isEmpty ? "" : " The old password stays in its password history."
        let newPassword = login.password != password
        if user.isEmpty || saved.lowercased() == user.lowercased() {
            return login.password.isEmpty ? "Adds this password to \(name)." : "Updates the password of \(name).\(history)"
        }
        if saved.isEmpty {
            return newPassword ? "Adds the username \(user) to \(name) and updates its password.\(history)" : "Adds the username \(user) to \(name)."
        }
        return newPassword
            ? "Replaces the username (\(saved)) and password of \(name) with \(user) and this password.\(history)"
            : "Replaces the username of \(name) (\(saved)) with \(user)."
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
        let noun = current?.kind == .passphrase ? "passphrase" : "password"
        PromptScaffold {
            Section {
                PromptHeader(site: page ?? "", symbol: page == nil ? "key.fill" : nil, title: "Use a new \(noun)", subtitle: page)
                    .promptPlainRow()
            }
            if list.count > 1 {
                Section {
                    Picker("Type", selection: $index) {
                        ForEach(list.indices, id: \.self) { i in Text(label(list[i].kind)).tag(i) }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("generateType")
                    .promptPlainRow()
                }
            }
            Section {
                Text(current?.value ?? "")
                    .speechSpellsOutCharacters()
                    .font(.system(.title3, design: .monospaced))
                    .foregroundStyle(Color.paInk)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("generatedPassword")
                StrengthMeter(password: current?.value ?? "")
            } footer: {
                if let note { Text(note).accessibilityIdentifier("generateNote") }
            }
            .paRow()
        } actions: {
            PrimaryButton(title: "Use this \(noun)", enabled: current != nil) {
                if let current { model.useGenerated([current]) }
            }
            .accessibilityIdentifier("useGenerated")
            QuietActions {
                QuietButton(title: "Regenerate", symbol: "arrow.clockwise") { model.regenerate() }
                    .accessibilityIdentifier("regenerate")
            }
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
