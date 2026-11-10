import AuthenticationServices
import PassAuthKit
import SwiftUI

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

private func backgroundSyncLabel(_ minutes: Int) -> String {
    switch minutes {
    case 0: "Off"
    case 60: "Every hour"
    case ..<60: "Every \(minutes) minutes"
    default: "Every \(minutes / 60) hours"
    }
}

private func lastSyncText(_ t: Double) -> String {
    guard t > 0 else { return "never" }
    let d = Date(timeIntervalSince1970: t)
    return Calendar.current.isDateInToday(d) ? "today at \(d.formatted(date: .omitted, time: .standard))" : d.formatted(date: .abbreviated, time: .shortened)
}

enum SettingsPage: String, Hashable, CaseIterable {
    case account, security, autofill, permissions, vault, appearance, about, export

    var title: String {
        switch self {
        case .account: "Account"
        case .security: "Account security"
        case .autofill: "AutoFill"
        case .permissions: "Permissions"
        case .vault: "Vault options"
        case .appearance: "Appearance"
        case .about: "About"
        case .export: "Export vault"
        }
    }

    var symbol: String {
        switch self {
        case .account: "person.crop.circle"
        case .security: "lock.shield"
        case .autofill: "key.viewfinder"
        case .permissions: "hand.raised"
        case .vault: "archivebox"
        case .appearance: "paintpalette"
        case .about: "info.circle"
        case .export: "square.and.arrow.up"
        }
    }
}

/// Settings: a list of categories, each opening its own page (like the Android app and extension).
struct SettingsTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = model.state
        NavigationStack {
            List {
                Section {
                    NavigationLink(value: SettingsPage.account) {
                        HStack(spacing: 14) {
                            Avatar(text: initials(s.name, s.email), size: 44)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.name.isEmpty ? s.email : s.name).font(.headline).foregroundStyle(Color.paInk)
                                if !s.name.isEmpty { Text(s.email).font(.subheadline).foregroundStyle(Color.paMuted) }
                                Text(hostOf(s.server)).font(.footnote).foregroundStyle(Color.paMuted)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .accessibilityIdentifier("settings.account")
                    .paRow()
                }
                Section {
                    ForEach([SettingsPage.security, .autofill, .permissions, .vault, .appearance, .about], id: \.self) { p in
                        NavigationLink(value: p) {
                            Label { Text(p.title).foregroundStyle(Color.paInk) } icon: { Image(systemName: p.symbol).foregroundStyle(Color.paAccent) }
                        }
                        .accessibilityIdentifier("settings.\(p.rawValue)")
                        .paRow()
                    }
                }
            }
            .listStyle(.insetGrouped)
            .paList()
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { LogoMark(height: 26) }
                ToolbarItem(placement: .topBarTrailing) { AccountMenu() }
            }
            .navigationDestination(for: SettingsPage.self) { p in
                SettingsPageView(page: p)
            }
        }
    }
}

struct SettingsPageView: View {
    @Environment(AppModel.self) private var model
    let page: SettingsPage

    var body: some View {
        Form {
            switch page {
            case .account: AccountPage()
            case .security: SecurityPage()
            case .autofill: AutofillPage()
            case .permissions: PermissionsPage()
            case .vault: VaultOptionsPage()
            case .appearance: AppearancePage()
            case .about: AboutPage()
            case .export: ExportPage()
            }
        }
        .paList()
        .navigationTitle(page.title)
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
    }
}

@MainActor
private func update(_ model: AppModel, _ f: @escaping @Sendable (inout Settings) -> Void) {
    Task { @MainActor in await model.repo.updateSettings(f) }
}

private struct Help: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View { Text(text).font(.footnote).foregroundStyle(Color.paMuted) }
}

// MARK: Account

private struct AccountPage: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        let s = model.state
        Section("Signed in") {
            LabeledContent("Email", value: s.email)
            if !s.name.isEmpty { LabeledContent("Name", value: s.name) }
            LabeledContent("Server", value: hostOf(s.server))
        }
        .paRow()
        Section {
            ForEach(s.accounts) { a in
                Button {
                    if a.id != s.activeId { model.run { try await model.repo.switchAccount(a.id) } }
                } label: {
                    HStack {
                        AccountRow(account: a)
                        if a.id == s.activeId { Image(systemName: "checkmark").foregroundStyle(Color.paAccent) }
                    }
                }
                .buttonStyle(.plain)
            }
            if s.accounts.count < maxAccounts {
                Button { model.run { try await model.repo.addAccount() } } label: { Label("Add account", systemImage: "person.badge.plus") }
            }
        } header: {
            Text("Accounts on this device")
        } footer: {
            Text("Up to \(maxAccounts) accounts, on the same or different PassAuth servers.")
        }
        .paRow()
        Section {
            Button { model.run { await model.repo.lockActive() } } label: { Label("Lock", systemImage: "lock") }
            Button(role: .destructive) { confirmLogout = true } label: { Label("Log out", systemImage: "rectangle.portrait.and.arrow.right") }
                .accessibilityIdentifier("logout")
        } footer: {
            Text("Logging out removes this account's vault from this device.")
        }
        .paRow()
        .confirmationDialog("Log out?", isPresented: $confirmLogout, titleVisibility: .visible) {
            Button("Log out", role: .destructive) { model.run { await model.repo.logout() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(LogoutCopy.message(email: s.email, others: s.accounts.count > 1))
        }
    }
}

// MARK: Security

private struct SecurityPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = model.state.settings
        let bio = BiometryKind.current
        Section {
            Picker("Vault timeout", selection: Binding(get: { s.vaultTimeout }, set: { v in update(model) { $0.vaultTimeout = v } })) {
                ForEach(VaultTimeout.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            .accessibilityIdentifier("vaultTimeout")
            if s.vaultTimeout == .never {
                Notice(text: "With \"Never\", your vault key is kept on this device without the master password protecting it. Anyone who can unlock this device and open PassAuth can open your vault.", kind: .error)
            }
            Picker("Timeout action", selection: Binding(get: { s.timeoutAction }, set: { v in update(model) { $0.timeoutAction = v } })) {
                Text("Lock").tag(TimeoutAction.lock)
                Text("Log out").tag(TimeoutAction.logout)
            }
        } footer: {
            Text(s.timeoutAction == .lock
                 ? "Locking keeps your encrypted vault here; unlock with your master password or \(bio.available ? bio.name : "biometrics")."
                 : "Logging out removes the vault from this device; sign in again (with two-step login) to use it.")
        }
        .paRow()
        Section {
            Toggle(isOn: Binding(get: { model.state.biometricEnabled }, set: { on in toggleBiometric(on, bio) })) {
                Label("Unlock with \(bio.available ? bio.name : "Face ID")", systemImage: bio.available ? bio.symbol : "faceid")
            }
            .disabled(!bio.available && !model.state.biometricEnabled)
            .accessibilityIdentifier("biometricToggle")
            Button { model.run { await model.repo.lockActive() } } label: { Label("Lock now", systemImage: "lock") }
                .accessibilityIdentifier("lockNow")
        } footer: {
            Text(bio.available
                 ? "Unlock this account with \(bio.name). It turns off by itself if the \(bio.name) set-up on this device changes."
                 : "Set up Face ID or Touch ID in the Settings app to use this.")
        }
        .paRow()
        Section {
            NavigationLink { ChangePasswordPage() } label: {
                PageRow(title: "Change master password", help: "Also turns the Secret Key on or off.", symbol: "key")
            }
            .accessibilityIdentifier("settings.changePassword")
            NavigationLink { TwoStepPage() } label: {
                PageRow(title: "Two-step login", help: "Authenticator app, email codes, security keys and recovery codes.", symbol: "lock.rotation")
            }
            .accessibilityIdentifier("settings.twoStep")
        } header: {
            Text("Master password and sign-in")
        }
        .paRow()
    }

    private func toggleBiometric(_ on: Bool, _ bio: BiometryKind) {
        if !on {
            model.repo.disableBiometric()
            model.notify("\(bio.available ? bio.name : "Biometric") unlock is off.")
            return
        }
        guard bio.available else {
            model.notify("Set up Face ID or Touch ID in the Settings app first.")
            return
        }
        model.run {
            guard await BiometryKind.confirm(reason: "Turn on \(bio.name) unlock for PassAuth") else { return }
            try await model.repo.enableBiometric()
            model.notify("\(bio.name) unlock is on.")
        }
    }
}

/// A settings row that opens a page: icon, title and a line of help.
private struct PageRow: View {
    let title: String
    let help: String
    let symbol: String

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(Color.paInk)
                Text(help).font(.footnote).foregroundStyle(Color.paMuted)
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(Color.paAccent)
        }
    }
}

private struct WebLink: View {
    @Environment(AppModel.self) private var model
    let title: String
    let help: String
    let path: String

    var body: some View {
        Button { model.openWebVault(path) } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).foregroundStyle(Color.paInk)
                    Text(help).font(.footnote).foregroundStyle(Color.paMuted)
                }
                Spacer()
                Image(systemName: "arrow.up.forward.square").foregroundStyle(Color.paMuted)
            }
        }
        .accessibilityHint("Opens in the browser")
    }
}

// MARK: AutoFill

private struct AutofillPage: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @State private var enabled: Bool?

    var body: some View {
        let s = model.state.settings
        Section {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: enabled == true ? "checkmark.circle.fill" : "key.viewfinder")
                    .font(.title2).foregroundStyle(enabled == true ? Color.paOk : Color.paAccent)
                VStack(alignment: .leading, spacing: 4) {
                    Text(enabled == true ? "PassAuth fills passwords and passkeys" : "Use PassAuth for AutoFill").font(.headline)
                    Text(enabled == true
                        ? "Your logins appear above the keyboard in Safari and apps, and PassAuth offers to save and use passkeys."
                        : "Turn on PassAuth in Settings → General → AutoFill & Passwords to fill logins, passkeys and verification codes in Safari and other apps.")
                        .font(.subheadline).foregroundStyle(Color.paMuted)
                }
            }
            .padding(.vertical, 4)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("autofillStatus")
            .accessibilityValue(enabled == true ? "on" : enabled == false ? "off" : "unknown")
            if enabled == false, #available(iOS 18.0, *) {
                Button {
                    Task { if let on = await PermissionCenter.turnOnAutofill(model.repo) { enabled = on } }
                } label: { Label("Turn on AutoFill", systemImage: "switch.2") }
            }
            Button {
                Task { await PermissionCenter.openAutofillSettings() }
            } label: { Label("Open AutoFill settings", systemImage: "gear") }
        } footer: {
            Text("PassAuth gives iOS only the website, user name and passkey ID of your logins for the suggestions; passwords and codes stay encrypted until you pick one.")
        }
        .paRow()
        .task(id: scenePhase) { await refreshState() }
        Section {
            Toggle(isOn: Binding(get: { s.askToSave }, set: { v in update(model) { $0.askToSave = v } })) {
                Text("Ask to save and update logins")
            }
            .accessibilityIdentifier("settings.askToSave")
        } footer: {
            Text("When you sign up or change a password in Safari or an app, PassAuth offers to save the login or update its password (iOS 26.2 or later).")
        }
        .paRow()
        Section {
            if s.neverSave.isEmpty {
                Text("No sites. Choose \"Never for this site\" when PassAuth offers to save a login.").font(.subheadline).foregroundStyle(Color.paMuted)
            }
            ForEach(s.neverSave.sorted(), id: \.self) { site in
                HStack {
                    Text(site).foregroundStyle(Color.paInk)
                    Spacer()
                    Button {
                        update(model) { $0.neverSave.removeAll { $0 == site } }
                    } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(Color.paMuted) }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Remove \(site)")
                }
                .accessibilityIdentifier("neverSave-\(site)")
            }
        } header: {
            Text("Never save on")
        } footer: {
            if !s.neverSave.isEmpty { Text("PassAuth doesn't offer to save logins on these sites and their subdomains.") }
        }
        .paRow()
        Section {
            Picker("Default URI match detection", selection: Binding(get: { s.defaultMatch }, set: { v in update(model) { $0.defaultMatch = v } })) {
                ForEach(defaultMatches, id: \.0) { Text($0.1).tag($0.0) }
            }
        } footer: {
            Text("\(matchHelp(s.defaultMatch)) Applies to websites set to \"Default\" in an item.")
        }
        .paRow()
        Section {
            Toggle(isOn: Binding(get: { s.autoCopyTotp }, set: { v in update(model) { $0.autoCopyTotp = v } })) {
                Text("Copy verification code automatically")
            }
        } footer: {
            Text("After filling a login that has an authenticator key, the current code is copied so you can paste it.")
        }
        .paRow()
        Section {
            Picker("Clear clipboard", selection: Binding(get: { s.clearClipboard }, set: { v in update(model) { $0.clearClipboard = v } })) {
                Text("Never").tag(0)
                ForEach([10, 20, 30, 60, 120, 300], id: \.self) { Text("After \(secondsLabel($0))").tag($0) }
            }
        } footer: {
            Text("Applies to everything PassAuth copies: passwords, usernames and verification codes. Copies stay on this device (no Universal Clipboard).")
        }
        .paRow()
    }
}

extension AutofillPage {
    @MainActor
    func refreshState() async {
        guard scenePhase == .active else { return }
        let on = await CredentialIdentitySync.isEnabled()
        if on && enabled != true {
            // Just turned on: write the identities again.
            model.repo.identities.invalidate()
            model.repo.refreshIdentities()
        }
        enabled = on
    }
}

// MARK: Vault options

private struct VaultOptionsPage: View {
    @Environment(AppModel.self) private var model
    @State private var syncing = false

    var body: some View {
        Section {
            Button {
                syncing = true
                Task {
                    do {
                        try await model.repo.sync()
                        model.notify("Sync complete. Your vault is up to date.")
                    } catch { model.notify("Sync failed: \(errorMessage(error))") }
                    syncing = false
                }
            } label: {
                HStack {
                    Label(syncing ? "Syncing…" : "Sync vault now", systemImage: "arrow.triangle.2.circlepath")
                    if syncing { Spacer(); ProgressView() }
                }
            }
            .disabled(syncing)
        } footer: {
            Text("Last sync: \(lastSyncText(model.state.lastSync))")
        }
        .paRow()
        Section {
            Picker("Background sync", selection: Binding(get: { model.state.settings.backgroundSyncMinutes }, set: { v in update(model) { $0.backgroundSyncMinutes = v } })) {
                ForEach([0, 30, 60, 120, 360, 720], id: \.self) { Text(backgroundSyncLabel($0)).tag($0) }
            }
            .accessibilityIdentifier("backgroundSync")
        } footer: {
            Text("Keeps your offline copy up to date while the app is in the background. iOS decides when it runs.")
        }
        .paRow()
        Section {
            NavigationLink(value: SettingsPage.export) {
                Label { Text("Export vault").foregroundStyle(Color.paInk) } icon: { Image(systemName: "square.and.arrow.up").foregroundStyle(Color.paAccent) }
            }
            .accessibilityIdentifier("settings.export")
        } footer: {
            Text("Save a copy of your items as a file, encrypted or not.")
        }
        .paRow()
        Section("In the web vault") {
            WebLink(title: "Vaults & sharing", help: "Create vaults and share them with others.", path: "/settings/vaults")
            WebLink(title: "Import items", help: "From another password manager or a PassAuth export.", path: "/import")
            WebLink(title: "Open web vault", help: "Everything else, in the browser.", path: "/vault")
        }
        .paRow()
    }
}

// MARK: Appearance

private struct AppearancePage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = model.state.settings
        Section {
            Picker("Theme", selection: Binding(get: { s.theme }, set: { v in update(model) { $0.theme = v } })) {
                Text("Same as system").tag(ThemeMode.system)
                Text("Light").tag(ThemeMode.light)
                Text("Dark").tag(ThemeMode.dark)
            }
            .pickerStyle(.inline)
            .labelsHidden()
        } header: { Text("Theme") }
        .paRow()
        Section {
            Toggle("Show website icons", isOn: Binding(get: { s.showIcons }, set: { v in update(model) { $0.showIcons = v } }))
        } footer: {
            Text("Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents.")
        }
        .paRow()
    }
}

// MARK: About

private struct AboutPage: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        let s = model.state
        let v = AppVersion.current
        Section {
            VStack(spacing: 8) {
                LogoMark(height: 72)
                Wordmark(size: 26)
                Text("Version \(v.name) (\(v.build))").font(.subheadline).foregroundStyle(Color.paMuted)
                    .accessibilityIdentifier("version")
                Text("© Fahed Alhammadi").font(.subheadline).foregroundStyle(Color.paMuted)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
        }
        .paRow()
        Section {
            LabeledContent("Signed in as", value: s.email)
            LabeledContent("Server", value: s.server)
        } footer: {
            Text("To use another PassAuth server, log out and choose \"Change server\" on the sign-in screen.")
        }
        .paRow()
        Section {
            Button("Log out", role: .destructive) { confirmLogout = true }
        }
        .paRow()
        .confirmationDialog("Log out?", isPresented: $confirmLogout, titleVisibility: .visible) {
            Button("Log out", role: .destructive) { model.run { await model.repo.logout() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(LogoutCopy.message(email: s.email, others: s.accounts.count > 1))
        }
        Section {
            NavigationLink {
                DeleteAccountPage()
            } label: {
                Label("Delete account…", systemImage: "person.crop.circle.badge.xmark").foregroundStyle(Color.paDanger)
            }
            .accessibilityIdentifier("deleteAccount")
        } header: {
            Text("Delete account")
        } footer: {
            Text("Permanently delete \(s.email) from \(hostOf(s.server)), with every vault you own and every item in them.")
        }
        .paRow()
    }
}

/// The App Store's in-app account deletion: warning, master password (server
/// re-authentication), `DELETE /api/account`, then the account is forgotten on this device.
private struct DeleteAccountPage: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var secretKey = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        let s = model.state
        let needsSecretKey = s.secretKeyRequired && !s.secretKeyStored
        PromptScaffold(error: error) {
            Section {
                VStack(alignment: .leading, spacing: PA.Space.m) {
                    Text("This permanently deletes \(s.email) from your PassAuth server, with every vault you own and every item in them. People you shared those vaults with lose access too. Vaults others shared with you are not deleted.")
                        .foregroundStyle(Color.paInk)
                    Notice(text: "This can't be undone. Export your vault first if you want to keep a copy.", kind: .error)
                }
                .promptPlainRow()
            }
            Section {
                SecretInput(label: "Master password", text: $password, mono: false, identifier: "delete.password", submit: submit)
                if needsSecretKey {
                    LabeledInput(label: "Secret Key", text: $secretKey, mono: true, autocap: .characters)
                }
            } footer: {
                Text("Your server checks the master password before it deletes anything.")
            }
            .paRow()
        } actions: {
            PrimaryButton(title: busy ? "Deleting…" : "Delete account", busy: busy, destructive: true, action: submit)
                .accessibilityIdentifier("delete.confirm")
        }
            .navigationTitle("Delete account")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .navigationBarBackButtonHidden(busy)
    }

    private func submit() {
        guard !busy else { return }
        if password.isEmpty { error = "Enter your master password."; return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.deleteAccount(password: password, secretKey: secretKey.isEmpty ? nil : secretKey)
                password = ""
                dismiss()
                model.notify("Your account has been deleted.")
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}
