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
    case .regex: "A saved website written as a pattern (such as ^https://example\\.com/) is tested against the page address; a plain address matches by base domain. Advanced."
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
        case .about: "About PassAuth"
        case .export: "Export vault"
        }
    }

    var symbol: String {
        switch self {
        case .account: "person.crop.circle"
        case .security: "lock.shield.fill"
        case .autofill: "key.fill"
        case .permissions: "hand.raised.fill"
        case .vault: "archivebox.fill"
        case .appearance: "paintpalette.fill"
        case .about: "info"
        case .export: "square.and.arrow.up"
        }
    }

    var tint: Color {
        switch self {
        case .security, .account: Color.Tile.blue
        case .autofill: Color.Tile.orange
        case .permissions, .about: Color.Tile.gray
        case .vault, .export: Color.Tile.purple
        case .appearance: Color.Tile.pink
        }
    }
}

/// A settings row label: white symbol on a coloured rounded square (growing with the text size, like the Settings
/// app), the title, and an optional trailing accessory (a count or a warning).
struct TileLabel<Trailing: View>: View {
    let title: String
    let symbol: String
    let tint: Color
    @ViewBuilder var trailing: Trailing
    @ScaledMetric(relativeTo: .body) private var scale: CGFloat = 1

    var body: some View {
        HStack(spacing: 14) {
            let side = 29 * min(scale, 1.5)
            Image(systemName: symbol)
                .font(.system(size: side * 0.5, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: side, height: side)
                .background(RoundedRectangle(cornerRadius: side * 0.24, style: .continuous).fill(tint))
                .accessibilityHidden(true)
            Text(title).foregroundStyle(Color.paInk)
            Spacer(minLength: 8)
            trailing
        }
    }
}

extension TileLabel where Trailing == EmptyView {
    init(title: String, symbol: String, tint: Color) {
        self.init(title: title, symbol: symbol, tint: tint) { EmptyView() }
    }
}

/// "Needs attention" mark at the end of a row.
private struct AttentionMark: View {
    var body: some View {
        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.paDanger)
            .accessibilityLabel("Needs attention")
    }
}

/// Settings: the account on top, then one group per job without header labels (like the Settings app): what you do
/// with the vault, how it's protected and filled, how the app looks and what it may use, and About. Everything about
/// the account itself (switching, adding, locking, logging out, deleting) is on the Account page behind the card.
struct SettingsTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink(value: SettingsPage.account) { AccountCard() }
                        .accessibilityIdentifier("settings.account")
                        .paRow()
                    // Vaults shared with the user and waiting for an answer (only while there are any).
                    if let waiting = model.repo.vault?.invitations.count, waiting > 0 {
                        NavigationLink {
                            InvitationsPage()
                        } label: {
                            TileLabel(title: InvitationText.pageTitle, symbol: "envelope.badge.fill", tint: Color.Tile.blue) {
                                Text("\(waiting)")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.white)
                                    .padding(.horizontal, 8).padding(.vertical, 2)
                                    .background(Color.paAccentFill, in: Capsule())
                            }
                            .accessibilityElement(children: .ignore)
                            .accessibilityLabel("\(InvitationText.pageTitle), \(waiting) waiting")
                        }
                        .accessibilityIdentifier("settings.invitations")
                        .paRow()
                    }
                }
                Section {
                    NavigationLink { HealthView() } label: {
                        TileLabel(title: "Password health", symbol: "checkmark.shield.fill", tint: Color.Tile.green)
                    }
                    .accessibilityIdentifier("settings.health")
                    NavigationLink { SendsPage() } label: {
                        TileLabel(title: "Send", symbol: "paperplane.fill", tint: Color.Tile.teal)
                    }
                    .accessibilityIdentifier("settings.send")
                    // Signed sharing: the shared vaults and who signed them (only while there are any).
                    if let v = model.repo.vault, v.vaults.contains(where: { !$0.personal }) || !v.refused.isEmpty {
                        NavigationLink { SharedVaultsPage() } label: {
                            TileLabel(title: SharingText.sharedVaultsTitle, symbol: "person.2.fill", tint: Color.Tile.indigo) {
                                if !v.refused.isEmpty { AttentionMark() }
                            }
                        }
                        .accessibilityIdentifier("settings.sharedVaults")
                    }
                    NavigationLink { EmergencyPage() } label: {
                        TileLabel(title: "Emergency access", symbol: "lifepreserver.fill", tint: Color.Tile.red) {
                            if model.repo.emergencyNotice != nil { AttentionMark() }
                        }
                    }
                    .accessibilityIdentifier("settings.emergency")
                    pageLink(.vault)
                }
                .paRow()
                Section {
                    pageLink(.security)
                    pageLink(.autofill)
                }
                .paRow()
                Section {
                    pageLink(.appearance)
                    pageLink(.permissions)
                }
                .paRow()
                Section {
                    pageLink(.about)
                } footer: {
                    Text("Version \(AppVersion.current.name)")
                        .frame(maxWidth: .infinity)
                        .padding(.top, PA.Space.s)
                }
                .paRow()
            }
            .listStyle(.insetGrouped)
            .paList()
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { LogoMark(height: 26) }
            }
            .navigationDestination(for: SettingsPage.self) { p in
                SettingsPageView(page: p)
            }
        }
    }

    private func pageLink(_ p: SettingsPage) -> some View {
        NavigationLink(value: p) { TileLabel(title: p.title, symbol: p.symbol, tint: p.tint) }
            .accessibilityIdentifier("settings.\(p.rawValue)")
    }
}

/// The account card at the top of Settings: avatar, name, email and server.
private struct AccountCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = model.state
        HStack(spacing: 14) {
            Avatar(text: initials(s.name, s.email), size: 52)
            VStack(alignment: .leading, spacing: 2) {
                Text(s.name.isEmpty ? s.email : s.name).font(.title3.weight(.semibold)).foregroundStyle(Color.paInk).lineLimit(1)
                if !s.name.isEmpty { Text(s.email).font(.subheadline).foregroundStyle(Color.paMuted).lineLimit(1) }
                HStack(spacing: 4) {
                    Image(systemName: "server.rack").imageScale(.small)
                    Text(hostOf(s.server)).lineLimit(1)
                }
                .font(.footnote).foregroundStyle(Color.paMuted)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
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

/// Settings → Account: everything about the signed-in account in one place. Who and where, the sharing identity,
/// the accounts on this device (switch, add), then Lock and Log out, then Delete account at the bottom.
private struct AccountPage: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        let s = model.state
        Section {
            VStack(spacing: PA.Space.s) {
                Avatar(text: initials(s.name, s.email), size: 72)
                Text(s.name.isEmpty ? s.email : s.name).font(.title2.weight(.semibold)).foregroundStyle(Color.paInk)
                    .multilineTextAlignment(.center)
                if !s.name.isEmpty { Text(s.email).font(.subheadline).foregroundStyle(Color.paMuted) }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, PA.Space.s)
            .accessibilityElement(children: .combine)
            .listRowBackground(Color.clear)
        }
        Section {
            LabeledContent("Server") { Text(s.server).textSelection(.enabled).lineLimit(2) }
        } footer: {
            Text("To use another PassAuth server, add an account or log out and choose \"Change server\" on the sign-in screen.")
        }
        .paRow()
        SigningIdentitySection()
        Section {
            ForEach(s.accounts) { a in
                Button {
                    if a.id != s.activeId { model.run { try await model.repo.switchAccount(a.id) } }
                } label: {
                    HStack {
                        AccountRow(account: a)
                        if a.id == s.activeId { Image(systemName: "checkmark").foregroundStyle(Color.paAccent).accessibilityLabel("Current account") }
                    }
                }
                .buttonStyle(.plain)
            }
            if s.accounts.count < maxAccounts {
                Button { model.run { try await model.repo.addAccount() } } label: { Label("Add account", systemImage: "person.badge.plus") }
                    .accessibilityIdentifier("account.add")
            }
        } header: {
            Text("Accounts on this device")
        } footer: {
            Text("Up to \(maxAccounts) accounts, on the same or different PassAuth servers. Tap one to switch.")
        }
        .paRow()
        Section {
            Button { model.run { await model.repo.lockActive() } } label: { Label("Lock", systemImage: "lock") }
                .accessibilityIdentifier("account.lock")
            Button(role: .destructive) { confirmLogout = true } label: { Label("Log out", systemImage: "rectangle.portrait.and.arrow.right") }
                .accessibilityIdentifier("logout")
        } footer: {
            Text("Locking keeps the encrypted vault on this device. Logging out removes it.")
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
                Label("Delete account", systemImage: "person.crop.circle.badge.xmark").foregroundStyle(Color.paDanger)
            }
            .accessibilityIdentifier("deleteAccount")
        } footer: {
            Text("Permanently deletes \(s.email) from \(hostOf(s.server)), with every vault you own and every item in them.")
        }
        .paRow()
    }
}

// MARK: Security

/// Items and storage against the server's limits (`GET /account`), shown only when the server's
/// admin set a limit.
private struct StorageSection: View {
    @Environment(AppModel.self) private var model
    @State private var usage: AccountUsage?

    var body: some View {
        Group {
            if let u = usage, u.limited {
                Section {
                    if let line = u.itemsLine, let used = u.itemsUsed { row("Items", line, used) }
                    if let line = u.storageLine, let used = u.storageUsed { row("Storage", line, used) }
                    if u.full { Notice(text: quotaExceededMessage, kind: .error) }
                } header: {
                    Text("Storage")
                } footer: {
                    Text("Limits set by your server's admin. Items in the vaults you own count, including the trash.")
                }
                .paRow()
            }
        }
        .task(id: model.state.activeId) { usage = try? await model.repo.accountUsage() }
    }

    private func row(_ title: String, _ value: String, _ used: Double) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent(title, value: value)
            ProgressView(value: used).tint(used >= 1 ? Color.paDanger : Color.paAccent)
        }
        .accessibilityElement(children: .combine)
        .padding(.vertical, 2)
    }
}

private struct SecurityPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = model.state.settings
        let bio = BiometryKind.current
        // The servers' longest allowed timeout (policy; the strictest of the signed-in accounts).
        let limit = model.state.timeoutLimit
        Section {
            Picker("Vault timeout", selection: Binding(get: { s.vaultTimeout }, set: { v in
                update(model) {
                    $0.vaultTimeout = v
                    $0.vaultTimeoutLowered = false
                }
            })) {
                ForEach(PolicyRules.timeoutOptions(max: limit), id: \.self) { Text($0.label).tag($0) }
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
            VStack(alignment: .leading, spacing: 6) {
                Text(s.timeoutAction == .lock
                     ? "Locking keeps your encrypted vault here; unlock with your master password or \(bio.available ? bio.name : "biometrics")."
                     : "Logging out removes the vault from this device; sign in again (with two-step login) to use it.")
                if limit > 0 {
                    Text(PolicyRules.timeoutLimitNote(limit) + (s.vaultTimeoutLowered ? " " + PolicyRules.timeoutLoweredNote(s.vaultTimeout) : ""))
                        .accessibilityIdentifier("vaultTimeout.limit")
                }
            }
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
            NavigationLink { SessionsPage() } label: {
                PageRow(title: "Signed-in devices", help: "Where your account is signed in, and signing devices out.", symbol: "laptopcomputer.and.iphone")
            }
            .accessibilityIdentifier("settings.sessions")
        } header: {
            Text("Master password and sign-in")
        }
        .paRow()
        StorageSection()
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
        if PolicyRules.exportAllowed(model.state.policies) {
            Section {
                NavigationLink(value: SettingsPage.export) {
                    Label { Text("Export vault").foregroundStyle(Color.paInk) } icon: { Image(systemName: "square.and.arrow.up").foregroundStyle(Color.paAccent) }
                }
                .accessibilityIdentifier("settings.export")
            } footer: {
                Text("Save a copy of your items as a file, encrypted or not.")
            }
            .paRow()
        } else {
            Section {
                Label { Text("Export vault").foregroundStyle(Color.paMuted) } icon: { Image(systemName: "square.and.arrow.up").foregroundStyle(Color.paMuted) }
                    .accessibilityIdentifier("settings.exportOff")
            } footer: {
                Text(PolicyRules.exportDisabledFooter)
            }
            .paRow()
        }
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
            // On, but the server's icon service is off (API 2 servers list it as a feature).
            Text("Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents."
                 + (s.showIcons && !model.state.showSiteIcons ? " Your server doesn't offer website icons right now." : ""))
        }
        .paRow()
    }
}

// MARK: About

private enum AboutLinks {
    static let website = URL(string: "https://fahed-alhammadi.github.io/PassAuth/")!
    static let help = URL(string: "https://fahed-alhammadi.github.io/PassAuth/support.html")!
    static let feedback = URL(string: "https://github.com/Fahed-Alhammadi/PassAuth/issues")!
    static let privacy = URL(string: "https://fahed-alhammadi.github.io/PassAuth/privacy.html")!
    /// The App Store's review sheet (6829616391 = the App Store Connect id of io.passauth.app).
    static let rate = URL(string: "https://apps.apple.com/app/id6829616391?action=write-review")!
}

/// Settings → About PassAuth (same layout as the Cloudy app's About): one bold element, the brand panel with the
/// app icon, name, copyright line and version; below it what you do (help, feedback, rating), then what you read
/// (website, privacy policy).
private struct AboutPage: View {
    var body: some View {
        Section {
            BrandPanel()
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.Brand.navy)
        }
        Section {
            Link(destination: AboutLinks.help) { AboutRow(title: "Help", detail: nil, icon: "questionmark.circle") }
            Link(destination: AboutLinks.feedback) { AboutRow(title: "Send feedback", detail: nil, icon: "bubble.left") }
            Link(destination: AboutLinks.rate) { AboutRow(title: "Rate PassAuth", detail: nil, icon: "star") }
        }
        .paRow()
        Section {
            Link(destination: AboutLinks.website) { AboutRow(title: "Website", detail: "fahed-alhammadi.github.io/PassAuth", icon: "globe") }
            Link(destination: AboutLinks.privacy) { AboutRow(title: "Privacy policy", detail: nil, icon: "hand.raised") }
        } footer: {
            Text("Open source under the MIT License.")
                .frame(maxWidth: .infinity)
                .multilineTextAlignment(.center)
                .padding(.top, PA.Space.l)
        }
        .paRow()
    }
}

/// The brand panel: navy into the brand blue (the shield's own gradient), a large faint shield behind, and the app
/// icon (shield on its pale tile), "PassAuth", the copyright line (the README's footer) and the version.
private struct BrandPanel: View {
    var body: some View {
        let v = AppVersion.current
        VStack(spacing: 0) {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(LinearGradient(colors: [.white, Color(red: 0xDC / 255, green: 0xE7 / 255, blue: 0xFD / 255)], startPoint: .top, endPoint: .bottom))
                .frame(width: 88, height: 88)
                .overlay(LogoMark(height: 56))
                .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(.white.opacity(0.25), lineWidth: 1))
                .shadow(color: .black.opacity(0.35), radius: 14, y: 8)
                .accessibilityHidden(true)
            Text(verbatim: "PassAuth")
                .font(.largeTitle.bold()).foregroundStyle(.white)
                .padding(.top, 18)
            Text(verbatim: "© 2026 Fahed Alhammadi. All rights reserved.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.8))
                .multilineTextAlignment(.center)
                .padding(.top, 4)
            Text("Version \(v.name) (\(v.build))")
                .font(.footnote.weight(.medium).monospacedDigit())
                .foregroundStyle(Color.Brand.cyan)
                .padding(.horizontal, 12).padding(.vertical, 5)
                .background(Capsule().fill(.white.opacity(0.1)))
                .padding(.top, 16)
                .accessibilityIdentifier("version")
        }
        .padding(.horizontal, PA.Space.xl)
        .padding(.top, 36).padding(.bottom, 30)
        .frame(maxWidth: .infinity)
        .background {
            ZStack {
                LinearGradient(colors: [Color.Brand.navy, Color(red: 0x0A / 255, green: 0x3F / 255, blue: 0xA8 / 255)],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
                GeometryReader { geo in
                    LogoMark(height: geo.size.height * 1.15)
                        .opacity(0.05)
                        .position(x: geo.size.width * 0.9, y: geo.size.height * 0.62)
                }
            }
            .clipped()
            .accessibilityHidden(true)
        }
        .accessibilityElement(children: .contain)
    }
}

/// A link row: icon in the accent colour, the name, an optional address under it, and the "leaves the app" arrow.
private struct AboutRow: View {
    let title: String
    let detail: String?
    let icon: String

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon).font(.body.weight(.medium)).foregroundStyle(Color.paAccent).frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(Color.paInk)
                if let detail { Text(verbatim: detail).font(.footnote).foregroundStyle(Color.paMuted) }
            }
            Spacer(minLength: 8)
            Image(systemName: "arrow.up.forward").font(.footnote.weight(.semibold)).foregroundStyle(Color.paMuted)
                .accessibilityHidden(true)
        }
        .padding(.vertical, 2)
        .accessibilityHint("Opens in the browser")
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
