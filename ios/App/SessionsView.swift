import PassAuthKit
import SwiftUI

// Settings → Account security → Signed-in devices (the web vault's Settings → Sessions): every
// session of the account with the app it signed in with (`client`, e.g. "Chrome extension
// 0.6.0"), "Sign out" for each other one, "Sign out other sessions" and "Forget…" for each
// device (both while the server's settings can be read). Each is confirmed in a decision sheet.

/// What a sign-out confirmation is about.
private enum SignOutTarget: Identifiable {
    case one(SessionInfo)
    case others(Int)
    /// Forget the session's device: `sessions` of it are listed, `here` = this device.
    case forget(SessionInfo, sessions: Int, here: Bool)

    var id: String {
        switch self {
        case .one(let s): "one-\(s.id)"
        case .others: "others"
        case .forget(let s, _, _): "forget-\(s.deviceId)"
        }
    }
}

struct SessionsPage: View {
    @Environment(AppModel.self) private var model
    @State private var list: SessionList?
    @State private var loadError: String?
    @State private var loading = false
    @State private var confirming: SignOutTarget?

    var body: some View {
        Form {
            Section {
                Text(SessionText.intro(canForget: list?.canForget ?? false))
                    .foregroundStyle(Color.paInk)
            }
            .paRow()
            if let list {
                Section {
                    ForEach(list.sessions) { s in
                        SessionRow(session: s, signOut: { confirming = .one(s) },
                                   forget: list.canForget(s) ? {
                                       confirming = .forget(s, sessions: list.sessionCount(device: s.deviceId), here: list.isThisDevice(s.deviceId))
                                   } : nil)
                    }
                } header: {
                    Text("Signed in")
                } footer: {
                    if list.others.isEmpty { Text("You're not signed in anywhere else.") }
                }
                .paRow()
                if list.canRevokeOthers && !list.others.isEmpty {
                    Section {
                        Button(role: .destructive) { confirming = .others(list.others.count) } label: {
                            Label("Sign out other sessions", systemImage: "rectangle.portrait.and.arrow.right")
                        }
                        .accessibilityIdentifier("sessions.revokeOthers")
                    } footer: {
                        Text("Signs out every other device and app at once. This device stays signed in.")
                    }
                    .paRow()
                }
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
        .navigationTitle("Signed-in devices")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .task { await load() }
        .refreshable { await load() }
        .sheet(item: $confirming, onDismiss: {
            // Forgetting this device signed the account out: nothing to reload.
            if model.state.status == .unlocked { Task { await load() } }
        }) { target in
            SignOutSheet(target: target)
        }
    }

    private func load() async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        do {
            list = try await model.repo.accountSessions()
            loadError = nil
        } catch {
            if list == nil { loadError = "Couldn't load your sessions. \(errorMessage(error))" } else { model.notify(errorMessage(error)) }
        }
    }
}

/// A session: its device, the app it signed in with, when; "This device" or "Sign out", and
/// "Forget…" for its device where the server offers it.
private struct SessionRow: View {
    let session: SessionInfo
    let signOut: () -> Void
    var forget: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: sessionSymbol(session)).foregroundStyle(Color.paAccent).frame(width: 28).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(session.deviceName.isEmpty ? "Unknown device" : session.deviceName).foregroundStyle(Color.paInk)
                Text(SessionText.app(session)).font(.subheadline).foregroundStyle(Color.paInk)
                Text(SessionText.detail(session)).font(.footnote).foregroundStyle(Color.paMuted)
                if let forget {
                    Button("Forget…", role: .destructive, action: forget)
                        .buttonStyle(.borderless)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(Color.paDanger)
                        .padding(.top, 4)
                        .accessibilityLabel("Forget \(session.deviceName.isEmpty ? "this device" : session.deviceName)")
                        .accessibilityIdentifier("sessions.forget.\(session.id)")
                }
            }
            Spacer(minLength: 8)
            if session.current {
                Text("This device")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(Color.paOk)
                    .padding(.horizontal, 10).padding(.vertical, 3)
                    .background(Color.paOk.opacity(0.14), in: Capsule())
            } else {
                Button("Sign out", role: .destructive, action: signOut)
                    .buttonStyle(.borderless)
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(Color.paDanger)
                    .accessibilityLabel("Sign out \(session.deviceName.isEmpty ? "this device" : session.deviceName)")
                    .accessibilityIdentifier("sessions.revoke.\(session.id)")
            }
        }
        .padding(.vertical, 2)
        // Read as one row; the buttons stay separate elements (and VoiceOver actions).
        .accessibilityElement(children: forget == nil ? .combine : .contain)
    }
}

/// The row's symbol: the app's device type, else the session's device kind.
private func sessionSymbol(_ s: SessionInfo) -> String {
    let name = (s.client ?? "").split(separator: "/").first.map { $0.lowercased() } ?? ""
    switch name {
    case "web": return "globe"
    case "desktop": return "desktopcomputer"
    case "extension", "chrome", "chrome-extension": return "puzzlepiece.extension"
    case "ios", "iphone", "ios-autofill", "android": return "iphone"
    case "ipad": return "ipad"
    case "macos-autofill", "mac-autofill": return "laptopcomputer"
    case "cli": return "terminal"
    default: break
    }
    switch s.deviceKind {
    case "web": return "globe"
    case "extension": return "puzzlepiece.extension"
    case "desktop": return "desktopcomputer"
    case "mobile": return "iphone"
    case "cli": return "terminal"
    default: return "questionmark.app"
    }
}

/// The decision sheet for signing out one device or every other session.
private struct SignOutSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let target: SignOutTarget
    @State private var busy = false
    @State private var error: String?

    private var title: String {
        switch target {
        case .one: "Sign out this device?"
        case .others: "Sign out other sessions?"
        case .forget: SessionText.forgetTitle
        }
    }

    private var subtitle: String {
        switch target {
        case .one(let s): "\(s.deviceName.isEmpty ? "Unknown device" : s.deviceName) · \(SessionText.app(s))"
        case .others(let n): "\(n) other \(n == 1 ? "session" : "sessions") · \(model.state.email)"
        case .forget(let s, _, _): s.deviceName.isEmpty ? "Unknown device" : s.deviceName
        }
    }

    private var explanation: String {
        switch target {
        case .one:
            "PassAuth on that device is signed out at once. It needs your master password to sign in again."
        case .others:
            "Every other device and app signed in to your account is signed out at once, including any you don't recognize. Each one needs your master password to sign in again. This device stays signed in."
        case .forget(_, let n, let here):
            SessionText.forgetBody(sessions: n, here: here)
        }
    }

    var body: some View {
        NavigationStack {
            PromptScaffold(error: error) {
                Section {
                    PromptHeader(symbol: "rectangle.portrait.and.arrow.right", title: title, subtitle: subtitle)
                        .promptPlainRow()
                }
                Section {
                    Text(explanation).foregroundStyle(Color.paInk)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .paRow()
            } actions: {
                PrimaryButton(title: busy ? busyLabel : confirmLabel, busy: busy, destructive: true, action: confirm)
                    .accessibilityIdentifier("sessions.confirm")
            }
            .navigationTitle(isForget ? "Forget device" : "Sign out")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
            }
        }
        .interactiveDismissDisabled(busy)
    }

    private var confirmLabel: String {
        switch target {
        case .one: "Sign out device"
        case .others: "Sign out other sessions"
        case .forget(_, _, let here): SessionText.forgetAction(here: here)
        }
    }

    private var isForget: Bool {
        if case .forget = target { return true }
        return false
    }

    private var busyLabel: String { isForget ? "Forgetting…" : "Signing out…" }

    private func confirm() {
        guard !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                switch target {
                case .one(let s):
                    try await model.repo.revokeSession(s.id)
                    model.notify("\(s.deviceName.isEmpty ? "Device" : s.deviceName) signed out.")
                case .others:
                    let n = try await model.repo.revokeOtherSessions()
                    model.notify(SessionText.revokedOthers(n))
                case .forget(let s, _, _):
                    do {
                        let here = try await model.repo.forgetDevice(s.deviceId)
                        model.notify(SessionText.forgotten(s.deviceName, here: here))
                    } catch let e as ApiError where e.status == 404 {
                        // Already forgotten (or signed out meanwhile): the list is loaded again.
                    }
                }
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}
