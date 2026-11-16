import PassAuthKit
import SwiftUI

// Sign in with another device, the approving side: a new device asks to sign in to the unlocked
// account. The sheet shows the request as it was when the sheet opened (frozen by the inbox's
// `ApprovalQueue`): what the device claims to be, and three sets of words worked out here from
// the request's key (`loginPhraseChoices`, never the server's). The user picks the words the new
// device shows; the right ones approve (`approveLoginRequest`) and the sheet shows the code the
// new device needs, until Done. Rules and wording in Shared/DeviceLogin.swift.

/// The sheet for the inbox's shown request (`AuthRequestInbox.shown`), over the unlocked app.
/// Only its own buttons close it (no swipe), so nothing is answered or dismissed by accident.
struct AuthRequestSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    /// The request the sheet was opened for.
    let initial: ShownApproval
    /// Its latest state while it was the inbox's (kept while the sheet goes away).
    @State private var latest: ShownApproval?
    /// The choices take taps only `DeviceApprovals.armDelay` after the content appeared.
    @State private var armed = false
    @AccessibilityFocusState private var notNowSpoken: Bool
    @FocusState private var notNowFocused: Bool

    /// This sheet's request as the inbox has it now; once the inbox moved on, its last state.
    private var shown: ShownApproval {
        if let live = model.authRequests.shown, live.id == initial.id { return live }
        return latest ?? initial
    }

    /// The inbox still shows this sheet's request (buttons act only then).
    private var current: Bool { model.authRequests.shown?.id == initial.id }

    var body: some View {
        let s = shown
        NavigationStack {
            switch s.phase {
            case .choosing, .sending: choosing(s)
            case .code(let code): approved(code)
            case .closed(let message): closed(message)
            }
        }
        .interactiveDismissDisabled(true)
        .onAppear { latest = model.authRequests.shown.flatMap { $0.id == initial.id ? $0 : nil } }
        .onChange(of: model.authRequests.shown) { _, v in
            if let v, v.id == initial.id { latest = v }
        }
    }

    // MARK: Which words?

    private func choosing(_ s: ShownApproval) -> some View {
        let r = s.request
        let busy = s.phase == .sending || !current
        return PromptScaffold {
            Section {
                PromptHeader(symbol: "iphone.and.arrow.forward", title: DeviceApprovals.title, subtitle: model.state.email)
                    .promptPlainRow()
            }
            Section {
                Text(DeviceApprovals.body(email: model.state.email))
                    .foregroundStyle(Color.paInk)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // The words first (the check that counts), then what the device claims about itself.
            if s.choices.isEmpty {
                Section {
                    WarningNote(text: DeviceApprovals.cannotCheck, identifier: "authRequest.cannotCheck")
                }
            } else {
                Section {
                    ForEach(Array(s.choices.enumerated()), id: \.offset) { i, phrase in
                        Button { choose(phrase) } label: {
                            Text(phrase)
                                .font(.body.weight(.semibold))
                                .multilineTextAlignment(.leading)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                                .contentShape(Rectangle())
                        }
                        .disabled(!armed || busy)
                        .accessibilityHint("Approves the sign-in if the new device shows these words.")
                        .accessibilityIdentifier("authRequest.choice\(i)")
                    }
                    Button(role: .destructive) { deny() } label: {
                        Text(DeviceApprovals.noneOfThese)
                            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                            .contentShape(Rectangle())
                    }
                    .disabled(busy)
                    .accessibilityHint("Denies the sign-in.")
                    .accessibilityIdentifier("authRequest.none")
                } header: {
                    Text(DeviceApprovals.question)
                } footer: {
                    Text(DeviceApprovals.questionFooter)
                }
            }
            Section {
                DetailRow(label: DeviceApprovals.deviceLabel, value: DeviceApprovals.deviceName(r), identifier: "authRequest.device")
                    .lineLimit(3)
                DetailRow(label: DeviceApprovals.appLabel, value: DeviceApprovals.app(r), identifier: "authRequest.app")
                    .lineLimit(3)
                if let ip = DeviceApprovals.ip(r) {
                    DetailRow(label: DeviceApprovals.ipLabel, value: ip, mono: true, identifier: "authRequest.ip")
                        .lineLimit(2)
                }
                TimelineView(.periodic(from: .now, by: 30)) { context in
                    DetailRow(label: "Requested", value: DeviceApprovals.requested(createdAt: r.createdAt, now: context.date.timeIntervalSince1970))
                }
            } header: {
                Text(DeviceApprovals.aboutRequest)
            }
            // What a device claims about itself never draws outside its rows.
            .clipped()
        } actions: {
            if s.phase == .sending {
                HStack(spacing: 8) {
                    ProgressView()
                    Text(DeviceApprovals.sending)
                }
                .font(.subheadline).foregroundStyle(Color.paMuted)
                .accessibilityElement(children: .combine)
            }
            if s.choices.isEmpty {
                PrimaryButton(title: DeviceApprovals.deny, busy: s.phase == .sending, destructive: true) { deny() }
                    .accessibilityIdentifier("authRequest.deny")
            }
            // "Not now" has the focus first: answering takes a deliberate pick.
            Button(action: close) {
                Text(DeviceApprovals.notNow).fontWeight(.semibold).frame(maxWidth: .infinity, minHeight: 30)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .disabled(busy)
            .focused($notNowFocused)
            .accessibilityFocused($notNowSpoken)
            .accessibilityIdentifier("authRequest.notNow")
        }
        .promptBar(closeLabel: DeviceApprovals.notNow) { if !busy { close() } }
        .defaultFocus($notNowFocused, true)
        .accessibilityAction(.escape) { if !busy { close() } }
        // Armed a second after the content appeared, and again after the app was away.
        .task(id: "\(r.id)|\(scenePhase == .active)") {
            armed = false
            guard scenePhase == .active else { return }
            notNowFocused = true
            try? await Task.sleep(for: .milliseconds(300))
            notNowSpoken = true
            try? await Task.sleep(for: .seconds(DeviceApprovals.armDelay - 0.3))
            if !Task.isCancelled { armed = true }
        }
    }

    // MARK: Approved: the code

    private func approved(_ code: String) -> some View {
        PromptScaffold {
            Section {
                PromptHeader(symbol: "checkmark.shield", title: DeviceApprovals.codeTitle, subtitle: model.state.email)
                    .promptPlainRow()
            }
            Section {
                VStack(spacing: PA.Space.m) {
                    Text(DeviceApprovals.codeHeading)
                        .font(.headline).foregroundStyle(Color.paInk)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(DeviceApprovals.groupedCode(code))
                        .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                        .foregroundStyle(Color.paInk)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                        .textSelection(.disabled)
                        .accessibilityLabel("Code: \(code.map(String.init).joined(separator: " "))")
                        .accessibilityIdentifier("authRequest.code")
                    Text(DeviceApprovals.codeNote)
                        .font(.footnote).foregroundStyle(Color.paMuted)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, PA.Space.m)
            }
        } actions: {
            PrimaryButton(title: DeviceApprovals.done, enabled: current, action: close)
                .accessibilityIdentifier("authRequest.done")
        }
        .promptBar()
        .onAppear { UIAccessibility.post(notification: .screenChanged, argument: nil) }
    }

    // MARK: Closed without an answer from here

    private func closed(_ message: String) -> some View {
        PromptScaffold {
            Section {
                PromptHeader(symbol: "exclamationmark.shield", title: DeviceApprovals.title, subtitle: model.state.email)
                    .promptPlainRow()
            }
            Section {
                Text(message)
                    .foregroundStyle(Color.paInk)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("authRequest.closed")
            }
        } actions: {
            PrimaryButton(title: DeviceApprovals.close, enabled: current, action: close)
                .accessibilityIdentifier("authRequest.close")
        }
        .promptBar(closeLabel: DeviceApprovals.close) { close() }
        .accessibilityAction(.escape) { close() }
        .onAppear { UIAccessibility.post(notification: .announcement, argument: message) }
    }

    // MARK: Actions (each for this sheet's request only)

    private func choose(_ phrase: String) {
        guard armed, current else { return }
        let id = initial.id
        Task { await model.authRequests.choose(phrase, for: id) }
    }

    private func deny() {
        guard current else { return }
        let id = initial.id
        Task {
            if let notice = await model.authRequests.deny(id) { model.notify(notice) }
        }
    }

    private func close() {
        model.authRequests.close(initial.id)
    }
}
