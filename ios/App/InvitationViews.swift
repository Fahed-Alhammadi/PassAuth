import PassAuthCore
import PassAuthKit
import SwiftUI

// Vault invitations (servers with `vault_invitations`; wording in `Shared/Invitations.swift`,
// as the web vault's Settings → Vaults & sharing). A vault shared with the user reaches the app
// only once they accept it here. The fingerprint shown is the one the server lists for the sharer:
// the invitation's sealed key is anonymous, so it can't prove the invitation is genuine, and the
// app says to accept only invitations the user expected. The vault list shows a quiet notice
// while invitations wait; Settings lists them.

/// The fingerprint of the key the server lists for the sharer, in the core's format; nil without
/// a key that can be read.
func sharerFingerprint(_ inv: Invitation) -> String? {
    guard let key = inv.invitedBy?.publicKey, !key.isEmpty else { return nil }
    return try? fingerprint(publicKey: key)
}

/// What an invitation's decision sheet is about.
enum InvitationAnswer: Identifiable {
    case accept(Invitation)
    case decline(Invitation)

    var id: String {
        switch self {
        case .accept(let i): "accept-\(i.vaultId)"
        case .decline(let i): "decline-\(i.vaultId)"
        }
    }

    var invitation: Invitation {
        switch self {
        case .accept(let i), .decline(let i): i
        }
    }
}

/// Settings → Vault invitations (also opened from the vault list's notice).
struct InvitationsPage: View {
    @Environment(AppModel.self) private var model
    @State private var answering: InvitationAnswer?
    @State private var trusting: SignerInfo?

    var body: some View {
        let list = model.repo.vault?.invitations ?? []
        Form {
            Section {
                Text(InvitationText.intro).foregroundStyle(Color.paInk)
            }
            .paRow()
            if list.isEmpty {
                Section {
                    Text("No invitations are waiting.").foregroundStyle(Color.paMuted)
                }
                .paRow()
            }
            ForEach(list) { inv in
                InvitationSection(invitation: inv, answer: { answering = $0 }, trustNewKey: { trusting = $0 })
            }
        }
        .paList()
        .navigationTitle(InvitationText.pageTitle)
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .refreshable {
            do { try await model.repo.sync() } catch { model.notify("Sync failed: \(errorMessage(error))") }
        }
        .sheet(item: $answering) { a in
            InvitationSheet(answer: a)
        }
        .sheet(isPresented: Binding(get: { trusting != nil }, set: { if !$0 { trusting = nil } })) {
            if let s = trusting { TrustNewKeySheet(signer: s) }
        }
    }
}

/// One invitation: the vault, who sent it and when, the role, the fingerprint the server lists for
/// the sharer, and Accept… / Decline….
private struct InvitationSection: View {
    let invitation: Invitation
    let answer: (InvitationAnswer) -> Void
    let trustNewKey: (SignerInfo) -> Void

    var body: some View {
        let inv = invitation
        let fp = sharerFingerprint(inv)
        Section {
            HStack(alignment: .top, spacing: PA.Space.m) {
                Image(systemName: "person.2.fill").foregroundStyle(Color.paAccent).frame(width: 28).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(inv.name ?? InvitationText.cantOpenTitle).font(.headline).foregroundStyle(Color.paInk)
                        .accessibilityAddTraits(.isHeader)
                    Text(InvitationText.from(inv)).font(.subheadline).foregroundStyle(Color.paMuted)
                }
                Spacer(minLength: PA.Space.s)
                Text(InvitationText.role(inv.role))
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(Color.paAccentInk)
                    .padding(.horizontal, 10).padding(.vertical, 3)
                    .background(Color.paAccentSoft, in: Capsule())
                    .accessibilityLabel("Role: \(InvitationText.role(inv.role))")
            }
            .padding(.vertical, 2)
            .accessibilityElement(children: .combine)
            if let text = SharingText.consentText(inv) {
                // Signed sharing: a vault the server lists for the account that it never accepted,
                // or an invitation whose verdict needs a word (re-join, held, first signature).
                Text(text)
                    .font(.subheadline).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("invitation.consent.\(inv.vaultId)")
            }
            if inv.name == nil {
                WarningNote(text: InvitationText.cantOpen(inv), identifier: "invitation.cantOpen")
            } else if inv.trust != nil {
                // Signed sharing: who signed it (their identity fingerprint, computed here), or why
                // it can only be declined.
                InvitationTrustView(invitation: inv, trustNewKey: trustNewKey)
            } else if let fp {
                FingerprintRow(label: InvitationText.fingerprintLabel(inv), fingerprint: fp)
                Text(InvitationText.checkHint(inv)).font(.footnote).foregroundStyle(Color.paMuted)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                WarningNote(text: InvitationText.noFingerprint(inv), identifier: "invitation.noFingerprint")
            }
            if inv.canAccept {
                Button("Accept…") { answer(.accept(inv)) }
                    .fontWeight(.semibold)
                    .accessibilityIdentifier("invitation.accept.\(inv.vaultId)")
            }
            if inv.canDecline {
                Button("Decline…", role: .destructive) { answer(.decline(inv)) }
                    .accessibilityIdentifier("invitation.decline.\(inv.vaultId)")
            }
        }
        .paRow()
    }
}

/// A key fingerprint: label above, the groups in monospace (selectable), read out group by group.
struct FingerprintRow: View {
    let label: String
    let fingerprint: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.subheadline).foregroundStyle(Color.paMuted)
            Text(fingerprint)
                .font(.body.monospaced())
                .foregroundStyle(Color.paInk)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(label): \(fingerprint.split(separator: "-").map { $0.map(String.init).joined(separator: " ") }.joined(separator: ", "))")
        .accessibilityIdentifier("invitation.fingerprint")
    }
}

/// The decision sheet for accepting or declining an invitation.
private struct InvitationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let answer: InvitationAnswer
    @State private var busy = false
    /// The decision went through: the entry leaving the list is its result, not a change.
    @State private var finished = false
    @State private var error: String?

    private var accepting: Bool {
        if case .accept = answer { return true }
        return false
    }

    var body: some View {
        let inv = answer.invitation
        let fp = sharerFingerprint(inv)
        NavigationStack {
            PromptScaffold(error: error) {
                Section {
                    PromptHeader(symbol: "person.2.fill",
                                 title: accepting ? InvitationText.acceptTitle(inv.name ?? "") : InvitationText.declineTitle,
                                 subtitle: accepting ? "Shared by \(InvitationText.sharerHeading(inv))" : (inv.name ?? InvitationText.from(inv)))
                        .promptPlainRow()
                }
                Section {
                    if let text = SharingText.consentText(inv) {
                        Text(text)
                            .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                    }
                    Text(accepting ? InvitationText.acceptBody(inv) : InvitationText.declineBody)
                        .foregroundStyle(Color.paInk)
                        .fixedSize(horizontal: false, vertical: true)
                    if accepting, inv.trust != nil {
                        InvitationTrustView(invitation: inv, trustNewKey: { _ in })
                    } else if accepting, let fp {
                        FingerprintRow(label: InvitationText.fingerprintLabel(inv), fingerprint: fp)
                        Text(InvitationText.acceptCheck(inv)).font(.footnote).foregroundStyle(Color.paMuted)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if accepting {
                        WarningNote(text: InvitationText.noFingerprint(inv))
                    }
                }
                .paRow()
            } actions: {
                if accepting {
                    PrimaryButton(title: busy ? "Accepting…" : "Accept invitation", busy: busy, action: confirm)
                        .accessibilityIdentifier("invitation.confirm")
                } else {
                    PrimaryButton(title: busy ? "Declining…" : "Decline invitation", busy: busy, destructive: true, action: confirm)
                        .accessibilityIdentifier("invitation.confirm")
                }
            }
            .navigationTitle(accepting ? "Accept invitation" : "Decline invitation")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
            }
        }
        .interactiveDismissDisabled(busy)
        // The entry changed after it was shown (another key, signer or member list, or gone):
        // this sheet's decision no longer applies, so it closes; the list shows the new state.
        .onChange(of: current) { _, now in
            guard !busy, !finished else { return }
            if now.map({ Invitation.sameDecision(answer.invitation, $0) }) != true {
                model.notify(InvitationText.changed)
                dismiss()
            }
        }
    }

    /// The entry as the repository lists it now.
    private var current: Invitation? {
        model.repo.vault?.invitations.first { $0.vaultId == answer.invitation.vaultId }
    }

    private func confirm() {
        guard !busy else { return }
        busy = true
        error = nil
        let inv = answer.invitation
        let accept = accepting
        Task {
            do {
                if accept {
                    try await model.repo.acceptInvitation(inv)
                    finished = true
                    model.notify(InvitationText.joined(inv.name ?? "the vault"))
                } else {
                    try await model.repo.declineInvitation(inv.vaultId)
                    finished = true
                    model.notify(InvitationText.declined)
                }
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}

// MARK: Notices in the vault list

/// What the vault list's notices open.
enum VaultNoticeTarget: String, Identifiable {
    case invitations, twoStep, changePassword, sharedVaults
    var id: String { rawValue }
}

/// Quiet notices at the top of the vault list: waiting invitations and what the server's
/// policies ask the account to change. Each can be dismissed for this app run (until the set
/// changes).
struct VaultNotices: View {
    @Environment(AppModel.self) private var model
    @Binding var target: VaultNoticeTarget?

    var body: some View {
        let s = model.state
        let invitations = model.repo.vault?.invitations ?? []
        let invitationsKey = InvitationText.key(invitations)
        if let text = InvitationText.notice(invitations), model.dismissedInvitations[s.activeId] != invitationsKey {
            Section {
                NoticeRow(symbol: "envelope.badge", text: text, action: InvitationText.noticeAction(invitations.count), identifier: "notice.invitations") {
                    target = .invitations
                } dismiss: {
                    model.dismissedInvitations[s.activeId] = invitationsKey
                }
            }
            .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
        }
        // Signed sharing: shared vaults that aren't used, or a problem with the account's keys.
        let refused = model.repo.vault?.refused ?? []
        let sharingText = SharingText.refusedNotice(refused) ?? model.repo.sharingNotice
        let sharingKey = refused.map(\.id).sorted().joined(separator: ",") + (model.repo.sharingNotice ?? "")
        if let sharingText, model.dismissedSharing[s.activeId] != sharingKey {
            Section {
                NoticeRow(symbol: "exclamationmark.shield", text: sharingText, action: "Details", identifier: "notice.sharing") {
                    target = .sharedVaults
                } dismiss: {
                    model.dismissedSharing[s.activeId] = sharingKey
                }
            }
            .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
        }
        let notices = PolicyRules.notices(s.policyViolations, s.policies)
        let violationsKey = PolicyRules.violationsKey(s.policyViolations)
        if !notices.isEmpty, model.dismissedViolations[s.activeId] != violationsKey {
            Section {
                ForEach(notices) { n in
                    NoticeRow(symbol: "exclamationmark.shield", text: n.text, action: n.action?.label, identifier: "notice.policy.\(n.violation.rawValue)") {
                        switch n.action {
                        case .setUpTwoStep?: target = .twoStep
                        case .turnOnSecretKey?, .changePassword?: target = .changePassword
                        case nil: break
                        }
                    } dismiss: {
                        model.dismissedViolations[s.activeId] = violationsKey
                    }
                }
            }
            .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
        }
    }
}

/// A notice with an optional action and a dismiss button.
private struct NoticeRow: View {
    let symbol: String
    let text: String
    let action: String?
    let identifier: String
    let run: () -> Void
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(Color.paAccentInk).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(text).font(.subheadline).foregroundStyle(Color.paAccentInk)
                    .fixedSize(horizontal: false, vertical: true)
                if let action {
                    Button(action, action: run)
                        .font(.subheadline.weight(.semibold))
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("\(identifier).open")
                }
            }
            Spacer(minLength: 0)
            Button(action: dismiss) {
                Image(systemName: "xmark").font(.footnote.weight(.semibold)).foregroundStyle(Color.paMuted)
                    .frame(minWidth: 32, minHeight: 32)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Dismiss")
            .accessibilityIdentifier("\(identifier).dismiss")
        }
        .padding(PA.Space.m)
        .background(Color.paAccentSoft, in: RoundedRectangle(cornerRadius: PA.Radius.control, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(identifier)
    }
}

/// A page opened from a vault notice, in a sheet of its own with Done.
struct VaultNoticeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let target: VaultNoticeTarget

    var body: some View {
        NavigationStack {
            Group {
                switch target {
                case .invitations: InvitationsPage()
                case .twoStep: TwoStepPage()
                case .changePassword: ChangePasswordPage()
                case .sharedVaults: SharedVaultsPage()
                }
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}
