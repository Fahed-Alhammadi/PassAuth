import AppKit
import PassAuthKit
import SwiftUI
import os

// The macOS AutoFill sheet: native macOS controls (rounded text fields, grouped forms, push
// buttons) with the PassAuth accent and logo from ios/UI/Theme.swift. Same screens as the iOS
// extension, plus sign-in and the extension's own settings. Every prompt has the same anatomy:
// brand bar (logo, settings, close), a centred column with the context row (what is decided,
// for which site) leading-aligned, the choices on one card, then one primary button with the
// quiet actions on a row beneath it.

struct MacAutofillRoot: View {
    @Bindable var model: AutofillModel
    @State private var settings = false

    var body: some View {
        VStack(spacing: 0) {
            bar
            Divider()
            Group {
                if settings {
                    MacSettings(model: model) { settings = false }
                } else {
                    content
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            if model.screen == .configured {
                Divider()
                HStack {
                    Spacer()
                    Button("Done") { model.finishConfiguration() }
                        .keyboardShortcut(.defaultAction)
                }
                .padding(.horizontal, PA.Space.l)
                .padding(.vertical, 10)
            }
        }
        .frame(minWidth: 420, idealWidth: 460, minHeight: 480, idealHeight: 560)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Color.paAccent)
    }

    private var signedIn: Bool {
        let s = model.state.status
        return s == .locked || s == .unlocked
    }

    /// Brand at the leading edge; settings and close at the trailing edge.
    private var bar: some View {
        HStack(spacing: PA.Space.s) {
            LogoMark(height: 20)
            Text(settings ? "PassAuth settings" : model.screen == .configured ? "PassAuth AutoFill" : "PassAuth").font(.headline)
                .accessibilityAddTraits(.isHeader)
            Spacer()
            if signedIn && model.screen != .configured && model.screen != .loading {
                Button { settings.toggle() } label: {
                    Image(systemName: settings ? "chevron.backward" : "gearshape").frame(width: 28, height: 28).contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help(settings ? "Back" : "PassAuth AutoFill settings")
                .accessibilityLabel(settings ? "Back" : "Settings")
            }
            if model.screen != .configured {
                Button { model.cancel() } label: {
                    Image(systemName: "xmark").frame(width: 28, height: 28).contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .keyboardShortcut(.cancelAction)
                .help("Close")
                .accessibilityLabel("Cancel")
                .accessibilityIdentifier("autofillCancel")
            }
        }
        .padding(.leading, PA.Space.l)
        .padding(.trailing, PA.Space.s)
        .padding(.vertical, 6)
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
            MacInfo(model: model, symbol: "exclamationmark.triangle", title: title, text: text)
        case .configured:
            MacSettings(model: model, onBack: nil)
        case .confirmSave, .generate:
            // iOS only (macOS has no save / generate requests).
            MacInfo(model: model, symbol: "exclamationmark.triangle", title: "Not available", text: "This request isn't supported on macOS.")
        }
    }
}

// MARK: Building blocks

/// The width of the centred content column.
private let columnWidth: CGFloat = 360

/// A prompt: the context row and content in a centred column that scrolls, the actions (one
/// primary button, quiet ones beneath) fixed under it, errors just above the actions.
struct MacPrompt<Content: View, Actions: View>: View {
    /// The site (its first letter is shown), unless `symbol` is set.
    var site = ""
    var symbol: String? = nil
    let title: String
    var subtitle: String? = nil
    var error: String? = nil
    @ViewBuilder let content: Content
    @ViewBuilder let actions: Actions

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: PA.Space.l) {
                    PromptHeader(site: site, symbol: symbol, title: title, subtitle: subtitle)
                    content
                }
                .frame(maxWidth: columnWidth, alignment: .leading)
                .padding(.horizontal, PA.Space.xl)
                .padding(.top, PA.Space.xl)
                .padding(.bottom, PA.Space.m)
                .frame(maxWidth: .infinity)
            }
            VStack(spacing: PA.Space.s) {
                ErrorText(text: error)
                actions
            }
            .frame(maxWidth: columnWidth)
            .padding(.horizontal, PA.Space.xl)
            .padding(.top, PA.Space.s)
            .padding(.bottom, PA.Space.l)
            .frame(maxWidth: .infinity)
        }
    }
}

/// The quiet actions under the primary button: link-style buttons on one row.
struct MacQuietActions<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        HStack(spacing: PA.Space.xl) { content }
            .buttonStyle(.link)
            .frame(maxWidth: .infinity)
            .frame(minHeight: 24)
    }
}

/// One card of choice rows (dividers inset to the text column).
struct MacChoiceCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: PA.Radius.card, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: PA.Radius.card, style: .continuous).stroke(Color(nsColor: .separatorColor)))
            .clipShape(RoundedRectangle(cornerRadius: PA.Radius.card, style: .continuous))
    }
}

/// A row of a choice card: tile, title, detail and the radio mark of the selected row.
struct MacChoiceRow: View {
    let title: String
    var detail = ""
    var symbol: String? = nil
    let selected: Bool
    /// No divider under the last row.
    var last = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                InitialTile(text: title, symbol: symbol, size: 28)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).lineLimit(1).truncationMode(.middle)
                    if !detail.isEmpty { Text(detail).font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                }
                Spacer(minLength: PA.Space.s)
                SelectionMark(selected: selected)
            }
            .padding(.horizontal, PA.Space.m)
            .padding(.vertical, PA.Space.s)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .overlay(alignment: .bottom) {
            if !last { Divider().padding(.leading, PA.Space.m + 28 + 10) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

/// Small title above a card ("Save in").
private struct MacSectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
            .padding(.bottom, -PA.Space.s)
            .accessibilityAddTraits(.isHeader)
    }
}

/// A sign-in step: title and one line under it, leading-aligned, in the centred column.
struct MacFrame<Content: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: PA.Space.m) {
                VStack(alignment: .leading, spacing: PA.Space.xs) {
                    Text(title).font(.title2.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                    if let subtitle, !subtitle.isEmpty {
                        Text(subtitle).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.bottom, PA.Space.xs)
                content
            }
            .frame(maxWidth: columnWidth, alignment: .leading)
            .padding(.horizontal, PA.Space.xl)
            .padding(.top, PA.Space.xl)
            .padding(.bottom, PA.Space.l)
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
    /// Take the keyboard focus when shown (the first box of a step).
    var autofocus = false
    @State private var reveal = false
    @FocusState private var focused: Bool

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
                .controlSize(.large)
                .textContentType(content)
                .autocorrectionDisabled()
                .focused($focused)
                .onSubmit { submit?() }
                .accessibilityLabel(label)
                .accessibilityIdentifier(label)
                .onAppear { if autofocus { takeFocus() } }
                .onChange(of: autofocus) { if autofocus { takeFocus() } }
                if secure {
                    Button { reveal.toggle() } label: {
                        Image(systemName: reveal ? "eye.slash" : "eye").frame(width: 28, height: 28).contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    .help(reveal ? "Hide" : "Show")
                    .accessibilityLabel(reveal ? "Hide \(label.lowercased())" : "Show \(label.lowercased())")
                }
            }
        }
    }

    /// The hosting view isn't always the key view yet when the step appears: ask again shortly after.
    private func takeFocus() {
        focused = true
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(80))
            if autofocus && !focused { focused = true }
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

/// A state with nothing to decide (something went wrong): centred, like an empty state, with a way out.
struct MacInfo: View {
    @Bindable var model: AutofillModel
    let symbol: String
    let title: String
    let text: String

    var body: some View {
        VStack(spacing: PA.Space.m) {
            Image(systemName: symbol).font(.largeTitle).foregroundStyle(.secondary).accessibilityHidden(true)
            Text(title).font(.title3.weight(.semibold)).multilineTextAlignment(.center)
                .accessibilityAddTraits(.isHeader)
            Text(text).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("autofillMessage")
            Button("Close") { model.cancel() }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
                .padding(.top, PA.Space.s)
        }
        .frame(maxWidth: columnWidth)
        .padding(PA.Space.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
        let host = model.requestHost
        MacPrompt(site: host ?? "", symbol: host == nil ? "lock.fill" : nil, title: model.unlockTitle, subtitle: host ?? state.email, error: model.error) {
            MacField(label: "Master password", text: $password, secure: true, content: .password, submit: { if !needKey { submit() } }, autofocus: true)
            if needKey { MacField(label: "Secret Key", text: $secretKey, mono: true, submit: submit) }
            Text("Your vault is locked. Enter the master password for \(state.email).")
                .font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        } actions: {
            MacPrimaryButton(title: model.busy ? "Unlocking…" : "Unlock", busy: model.busy, enabled: !password.isEmpty, action: submit)
            MacQuietActions {
                if canBio {
                    Button { model.unlockWithBiometric() } label: { Label("Use \(bio.name)", systemImage: bio.symbol) }
                        .disabled(model.busy)
                        .accessibilityIdentifier("autofillBiometric")
                }
                Button("Cancel") { model.cancel() }
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

// MARK: List (choose a login, a passkey or a verification code)

/// "Lumen Mail · 29 Oct 2026": the login a passkey is in and the day it was saved.
private func passkeyDetail(_ e: Entry, _ p: Passkey) -> String {
    guard p.createdAt > 0 else { return e.item.name }
    let day = Date(timeIntervalSince1970: TimeInterval(p.createdAt)).formatted(date: .abbreviated, time: .omitted)
    return e.item.name.isEmpty ? "Saved \(day)" : "\(e.item.name) · \(day)"
}

struct MacList: View {
    @Bindable var model: AutofillModel
    @State private var query = ""
    @FocusState private var searchFocused: Bool
    /// `model.suggestions` / `passkeyChoices` match every login against the pages: computed
    /// when the list appears and when the vault or the match setting changes, not per render.
    @State private var suggestions: [Entry] = []
    @State private var passkeys: [(Entry, Passkey)] = []
    @State private var loaded = false
    /// A website asked for a passkey and the vault has some: choose one and sign in. Off once
    /// the user asks for a password instead.
    @State private var passkeyPrompt = true

    /// What the suggestions depend on.
    private struct Inputs: Equatable {
        var revision: Int64?
        var entries: Int
        var match: UrlMatch
    }

    private var inputs: Inputs {
        Inputs(revision: model.repo.vault?.revision, entries: model.repo.vault?.entries.count ?? -1, match: model.state.settings.defaultMatch)
    }

    private static let log = Logger(subsystem: "io.passauth.autofill", category: "list")

    var body: some View {
        Group {
            if !loaded {
                Color.clear
            } else if passkeyPrompt && !passkeys.isEmpty {
                MacPasskeySignIn(model: model, passkeys: passkeys) { passkeyPrompt = false }
            } else {
                picker
            }
        }
        .onAppear {
            recompute()
            loaded = true
            Self.log.notice("list: \(model.pages.count) pages, \(suggestions.count) suggestions, \(model.repo.vault?.entries.count ?? -1) entries")
            searchFocused = suggestions.isEmpty && passkeys.isEmpty
        }
        .onChange(of: inputs) { recompute() }
    }

    private var picker: some View {
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        let host = model.requestHost
        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: PA.Space.m) {
                PromptHeader(site: host ?? "", symbol: host == nil ? (model.onlyCodes ? "clock" : "key.fill") : nil,
                             title: model.onlyCodes ? "Choose a verification code" : "Choose a login", subtitle: host)
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
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: PA.Radius.control, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: PA.Radius.control, style: .continuous).stroke(Color(nsColor: .separatorColor)))
            }
            .padding(.horizontal, PA.Space.l).padding(.top, PA.Space.l).padding(.bottom, PA.Space.s)

            List {
                if !searching && !passkeys.isEmpty {
                    Section("Passkeys") {
                        ForEach(passkeys, id: \.1.credentialId) { e, p in
                            Button { model.pickPasskey(e, p) } label: {
                                MacRow(title: p.userName.isEmpty ? e.item.name : p.userName, subtitle: passkeyDetail(e, p), symbol: "person.badge.key")
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("passkey-\(p.userName)")
                        }
                    }
                }
                if !searching && !model.pages.isEmpty {
                    Section("For this site") {
                        if suggestions.isEmpty {
                            Text(model.onlyCodes ? "No login with a verification code for this site. Search your other logins." : "No login saved for this site. Search your other logins.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(suggestions) { e in entryRow(e) }
                    }
                }
                let shown = Set(suggestions.map(\.id))
                let results = model.searchResults(query).filter { searching || !shown.contains($0.id) }
                if searching || !results.isEmpty {
                    Section(searching ? "Results" : model.pages.isEmpty ? "All logins" : "Other logins") {
                        if results.isEmpty { Text("No login matches “\(query.trimmingCharacters(in: .whitespaces))”.").foregroundStyle(.secondary) }
                        ForEach(results) { e in entryRow(e) }
                    }
                }
            }
            .listStyle(.inset)
            if model.repo.vault?.offline == true {
                Divider()
                Text("Showing the copy on this Mac.").font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, PA.Space.l).padding(.vertical, 6)
            }
        }
    }

    private func recompute() {
        suggestions = model.suggestions
        passkeys = model.passkeyChoices
    }

    private func entryRow(_ e: Entry) -> some View {
        Button { model.pick(e) } label: {
            MacRow(title: e.item.name, subtitle: e.item.login?.username ?? "", letter: e.item.name, hasCode: Clipboard.totp(e.item.login?.totp) != nil)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("login-\(e.item.name)")
    }
}

/// Sign in with a passkey: choose the account (the newest passkey is preselected), one button.
private struct MacPasskeySignIn: View {
    @Bindable var model: AutofillModel
    let passkeys: [(Entry, Passkey)]
    let usePassword: () -> Void
    @State private var chosen = ""

    private var selectedIndex: Int { passkeys.firstIndex { $0.1.credentialId == chosen } ?? 0 }

    var body: some View {
        let selected = passkeys.indices.contains(selectedIndex) ? passkeys[selectedIndex] : nil
        MacPrompt(site: model.passkeyRpId ?? "", title: "Sign in with a passkey", subtitle: model.passkeyRpId, error: model.error) {
            if passkeys.count > 1 { MacSectionTitle("Choose an account") }
            MacChoiceCard {
                ForEach(Array(passkeys.enumerated()), id: \.element.1.credentialId) { n, pair in
                    let (e, p) = pair
                    MacChoiceRow(title: p.userName.isEmpty ? e.item.name : p.userName, detail: passkeyDetail(e, p), symbol: "person.badge.key",
                                 selected: n == selectedIndex, last: n == passkeys.count - 1) { chosen = p.credentialId }
                        .accessibilityIdentifier("passkey-\(p.userName)")
                }
            }
            // Arrow keys move the choice; Return signs in.
            .focusable()
            .focusEffectDisabled()
            .onMoveCommand { direction in
                let next = direction == .up ? selectedIndex - 1 : direction == .down ? selectedIndex + 1 : selectedIndex
                if passkeys.indices.contains(next) { chosen = passkeys[next].1.credentialId }
            }
        } actions: {
            MacPrimaryButton(title: model.busy ? "Signing in…" : "Sign in", busy: model.busy, enabled: selected != nil) {
                if let (e, p) = selected { model.pickPasskey(e, p) }
            }
            .accessibilityIdentifier("passkeySignIn")
            MacQuietActions {
                Button("Use a password instead", action: usePassword)
                    .accessibilityIdentifier("passkeyUsePassword")
                Button("Cancel") { model.cancel() }
            }
        }
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
            InitialTile(text: letter, symbol: symbol, size: 28)
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
        let rp = r?.rpId ?? ""
        let targets = model.passkeyTargets
        MacPrompt(site: rp, title: "Save a passkey", subtitle: rp, error: model.error) {
            MacChoiceCard {
                HStack(spacing: 10) {
                    InitialTile(symbol: "person.badge.key", size: 28)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Passkey for").font(.callout).foregroundStyle(.secondary)
                        Text((r?.user ?? "").isEmpty ? rp : r?.user ?? "").lineLimit(1).truncationMode(.middle)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, PA.Space.m).padding(.vertical, PA.Space.s)
                .frame(minHeight: 44)
                .accessibilityElement(children: .combine)
            }
            if targets.isEmpty {
                Text("Saved as a new login for \(rp) in your vault (\(model.state.email)).")
                    .font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                MacSectionTitle("Save in")
                MacChoiceCard {
                    ForEach(targets, id: \.id) { e in
                        // A login in a vault somebody shared says so (its vault's name); it is never preselected.
                        let user = (e.item.login?.username ?? "").isEmpty ? "No username" : e.item.login?.username ?? ""
                        MacChoiceRow(title: e.item.name.isEmpty ? rp : e.item.name,
                                     detail: model.sharedVaultName(e).map { "\(user) · shared vault \($0)" } ?? user,
                                     selected: model.passkeyTarget == e.id) { model.passkeyTarget = e.id }
                            .accessibilityIdentifier("saveIn-\(e.id)")
                    }
                    MacChoiceRow(title: "New login", detail: rp, symbol: "plus", selected: model.passkeyTarget == PasskeyLogic.newLogin, last: true) {
                        model.passkeyTarget = PasskeyLogic.newLogin
                    }
                    .accessibilityIdentifier("saveInNew")
                }
                .disabled(model.busy)
                .focusable()
                .focusEffectDisabled()
                .onMoveCommand { direction in
                    let ids = targets.map(\.id) + [PasskeyLogic.newLogin]
                    let at = ids.firstIndex(of: model.passkeyTarget) ?? 0
                    let next = direction == .up ? at - 1 : direction == .down ? at + 1 : at
                    if ids.indices.contains(next) { model.passkeyTarget = ids[next] }
                }
                .accessibilityIdentifier("saveIn")
                let shared = targets.first { $0.id == model.passkeyTarget }.flatMap(model.sharedVaultName)
                Text(shared.map { "The passkey is kept with that login in the shared vault \($0); its members can use it too." }
                     ?? "The passkey is kept with that login in your vault (\(model.state.email)).")
                    .font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    .padding(.top, -PA.Space.s)
            }
        } actions: {
            MacPrimaryButton(title: model.busy ? "Saving…" : "Save passkey", busy: model.busy, action: model.savePasskey)
                .accessibilityIdentifier("savePasskey")
            MacQuietActions {
                Button("Cancel") { model.cancel() }.disabled(model.busy)
            }
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
                        Text("PassAuth fills your logins, passkeys and verification codes in Safari and apps. Your vault stays encrypted: macOS only learns the website and username of each login.")
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
