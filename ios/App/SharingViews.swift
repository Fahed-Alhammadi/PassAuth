import PassAuthCore
import PassAuthKit
import SwiftUI

// Signed sharing in the app (wording in `Shared/SignedSharing.swift`): the shared vaults with who
// signed them ("Signed by …", "Not yet signed"), the ones PassAuth refused and why (with "Trust the
// new key…" after a signer's keys changed), the user's own identity fingerprint, and the people
// whose keys the account pinned, each with "Mark as verified…" after comparing fingerprints.

/// A short trust label for a vault's header ("Signed by …", "Not yet signed"); nil when there is
/// nothing to say (the account's own vault, or a server without signed sharing).
func trustLabel(_ v: VaultInfo) -> String? {
    switch v.trust {
    case .signed(let s): SharingText.signedBy(s)
    case .notYetSigned: SharingText.notYetSigned
    case .own, .notChecked: nil
    }
}

/// Settings → Shared vaults (also opened from the vault list's notice).
struct SharedVaultsPage: View {
    @Environment(AppModel.self) private var model
    @State private var trusting: SignerInfo?

    var body: some View {
        let v = model.repo.vault
        let shared = (v?.vaults ?? []).filter { !$0.personal }
        let refused = v?.refused ?? []
        Form {
            if let notice = model.repo.sharingNotice {
                Section {
                    Notice(text: notice, kind: .error).listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                }
                .paRow()
            }
            if !refused.isEmpty {
                Section {
                    ForEach(refused) { r in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(r.name.map { "\u{201C}\($0)\u{201D}" } ?? "A shared vault").font(.headline).foregroundStyle(Color.paInk)
                            WarningNote(text: SharingText.refusal(r.reason), identifier: "sharing.refused.\(r.id)")
                            if case .keyChanged(let s) = r.reason {
                                FingerprintRow(label: SharingText.fingerprintLabel(s), fingerprint: s.fingerprint)
                                if s.pin == .changed {
                                    Button(SharingText.trustNewKey) { trusting = s }
                                        .accessibilityIdentifier("sharing.trust.\(r.id)")
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                } header: {
                    Text("Not used")
                }
                .paRow()
            }
            Section {
                if shared.isEmpty {
                    Text("No vaults are shared with you.").foregroundStyle(Color.paMuted)
                }
                ForEach(shared) { vault in
                    SharedVaultRow(vault: vault)
                }
            } header: {
                Text("In use")
            }
            .paRow()
        }
        .paList()
        .navigationTitle(SharingText.sharedVaultsTitle)
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .refreshable {
            do { try await model.repo.sync() } catch { model.notify("Sync failed: \(errorMessage(error))") }
        }
        .sheet(item: Binding(get: { trusting.map(TrustTarget.init) }, set: { if $0 == nil { trusting = nil } })) { t in
            TrustNewKeySheet(signer: t.signer)
        }
    }
}

private struct TrustTarget: Identifiable {
    let signer: SignerInfo
    var id: String { signer.userId + signer.fingerprint }
}

private struct SharedVaultRow: View {
    let vault: VaultInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(vault.name).font(.headline).foregroundStyle(Color.paInk)
            Text(roleLabel(vault)).font(.subheadline).foregroundStyle(Color.paMuted)
            switch vault.trust {
            case .signed(let s):
                Label(SharingText.signedBy(s), systemImage: "checkmark.seal")
                    .font(.subheadline).foregroundStyle(Color.paInk)
                    .accessibilityIdentifier("sharing.signed.\(vault.id)")
                if let other = s.otherListedEmail {
                    Text(SharingText.listedAs(other)).font(.footnote).foregroundStyle(Color.paMuted)
                }
                if s.pin != .me {
                    FingerprintRow(label: SharingText.fingerprintLabel(s), fingerprint: s.fingerprint)
                    if let label = SharingText.pinLabel(s) {
                        Text(label).font(.footnote.weight(.semibold)).foregroundStyle(s.pin == .verified ? Color.paOk : Color.paMuted)
                    }
                    if let first = SharingText.firstTime(s) {
                        Text(first).font(.footnote).foregroundStyle(Color.paMuted).fixedSize(horizontal: false, vertical: true)
                    }
                }
            case .notYetSigned:
                Label(SharingText.notYetSigned, systemImage: "seal")
                    .font(.subheadline).foregroundStyle(Color.paMuted)
                    .accessibilityIdentifier("sharing.unsigned.\(vault.id)")
                Text(SharingText.notYetSignedHelp).font(.footnote).foregroundStyle(Color.paMuted).fixedSize(horizontal: false, vertical: true)
            case .own, .notChecked:
                EmptyView()
            }
        }
        .padding(.vertical, 4)
    }
}

/// "Trust the new key": shows the signer's new fingerprint and asks whether the user compared it.
struct TrustNewKeySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let signer: SignerInfo
    @State private var compared = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            PromptScaffold(error: error) {
                Section {
                    PromptHeader(symbol: "key", title: "Trust the new key?", subtitle: signer.shownName)
                        .promptPlainRow()
                }
                Section {
                    Text(SharingText.keyChanged(signer)).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                    if let other = signer.otherListedEmail {
                        Text(SharingText.listedAs(other)).font(.footnote).foregroundStyle(Color.paMuted)
                    }
                    FingerprintRow(label: SharingText.fingerprintLabel(signer), fingerprint: signer.fingerprint)
                    // Exactly the email pinned with the new key.
                    Text(SharingText.trustSavedAs(signer)).font(.footnote).foregroundStyle(Color.paMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("sharing.trust.email")
                    Text(SharingText.trustNewKeyBody(signer)).font(.footnote).foregroundStyle(Color.paMuted)
                        .fixedSize(horizontal: false, vertical: true)
                    Toggle("I compared this fingerprint with \(signer.shownName)", isOn: $compared)
                        .accessibilityIdentifier("sharing.trust.compared")
                }
                .paRow()
            } actions: {
                PrimaryButton(title: busy ? "Saving…" : "Trust the new key", busy: busy, enabled: compared, action: confirm)
                    .accessibilityIdentifier("sharing.trust.confirm")
            }
            .navigationTitle("Keys changed")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
            }
        }
        .interactiveDismissDisabled(busy)
    }

    private func confirm() {
        guard !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.trustNewKey(signer, compared: compared)
                model.notify("New key trusted.")
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}

/// Settings → Account → People you share with: the pinned identities, each with its
/// fingerprint and "Mark as verified…".
struct KnownPeoplePage: View {
    @Environment(AppModel.self) private var model
    @State private var verifying: PinnedPerson?

    var body: some View {
        let people = model.repo.knownPeople
        Form {
            Section {
                Text(SharingText.peopleHelp).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            if people.isEmpty {
                Section {
                    Text("Nobody yet.").foregroundStyle(Color.paMuted)
                }
                .paRow()
            }
            ForEach(people) { p in
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(p.email.isEmpty ? SharingText.unknownMember : p.email).font(.headline).foregroundStyle(Color.paInk)
                        FingerprintRow(label: "Identity fingerprint", fingerprint: p.fingerprint)
                        Text(p.verified ? SharingText.verified : SharingText.notVerified)
                            .font(.footnote.weight(.semibold)).foregroundStyle(p.verified ? Color.paOk : Color.paMuted)
                    }
                    .padding(.vertical, 4)
                    if !p.verified {
                        Button(SharingText.markVerified) { verifying = p }
                            .accessibilityIdentifier("people.verify.\(p.userId)")
                    }
                }
                .paRow()
            }
        }
        .paList()
        .navigationTitle(SharingText.peopleTitle)
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .confirmationDialog("Mark as verified?", isPresented: Binding(get: { verifying != nil }, set: { if !$0 { verifying = nil } }),
                            titleVisibility: .visible, presenting: verifying) { p in
            Button("I compared it: mark as verified") {
                model.run {
                    try await model.repo.markVerified(p)
                    model.notify("Marked as verified.")
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { p in
            Text(SharingText.markVerifiedBody(p.email) + "\n\n" + p.fingerprint)
        }
    }
}

/// Settings → Account: the user's own identity fingerprint and the people they share with.
struct SigningIdentitySection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let fp = model.repo.ownIdentityFingerprint
        if fp != nil || model.repo.sharingNotice != nil || !model.repo.knownPeople.isEmpty {
            Section {
                if let notice = model.repo.sharingNotice {
                    Notice(text: notice, kind: .error).listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                }
                if let fp {
                    FingerprintRow(label: SharingText.ownFingerprint, fingerprint: fp)
                        .accessibilityIdentifier("account.identityFingerprint")
                }
                NavigationLink { KnownPeoplePage() } label: { Text(SharingText.peopleTitle) }
                    .accessibilityIdentifier("account.people")
            } header: {
                Text("Sharing")
            } footer: {
                Text(SharingText.ownFingerprintHelp)
            }
            .paRow()
        }
    }
}

/// The invitation's signer, as the invitation list and the accept sheet show it.
struct InvitationTrustView: View {
    let invitation: Invitation
    let trustNewKey: (SignerInfo) -> Void

    var body: some View {
        let who = InvitationText.sharerShort(invitation)
        switch invitation.trust {
        case .signed(let s)?:
            // The server's name only for someone not pinned yet ("Verified" never sits next to it).
            Label(SharingText.signedBy(s) + (s.pin != .new || s.name.isEmpty || s.name == s.email ? "" : " (\(s.name))"), systemImage: "checkmark.seal")
                .font(.subheadline).foregroundStyle(Color.paInk)
                .accessibilityIdentifier("invitation.signed")
            if let other = s.otherListedEmail {
                Text(SharingText.listedAs(other)).font(.footnote).foregroundStyle(Color.paMuted)
            }
            if s.pin != .me {
                FingerprintRow(label: SharingText.fingerprintLabel(s), fingerprint: s.fingerprint)
                if let label = SharingText.pinLabel(s) {
                    Text(label).font(.footnote.weight(.semibold)).foregroundStyle(s.pin == .verified ? Color.paOk : Color.paMuted)
                }
                Text(SharingText.firstTime(s) ?? InvitationText.expectedOnly).font(.footnote).foregroundStyle(Color.paMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        case .unsigned? where invitation.consent != nil && invitation.canAccept:
            Label(SharingText.notYetSigned, systemImage: "seal")
                .font(.subheadline).foregroundStyle(Color.paMuted)
                .accessibilityIdentifier("invitation.notYetSigned")
        case .unsigned?:
            WarningNote(text: invitation.consent != nil ? SharingText.consentUnsigned : SharingText.unsignedInvitation(who), identifier: "invitation.unsigned")
        case .refused?:
            WarningNote(text: SharingText.refusedInvitation(who), identifier: "invitation.refused")
        case .keyChanged(let s)?:
            WarningNote(text: SharingText.keyChanged(s), identifier: "invitation.keyChanged")
            FingerprintRow(label: SharingText.fingerprintLabel(s), fingerprint: s.fingerprint)
            if s.pin == .changed {
                Button(SharingText.trustNewKey) { trustNewKey(s) }
                    .accessibilityIdentifier("invitation.trust")
            }
        case nil:
            EmptyView()
        }
    }
}

/// Signed sharing's version-1 review before a key replacement: every member the new key would be
/// sealed to, with their pinned email (else the one the server lists), their identity fingerprint
/// and pin state; replaced only on the user's explicit confirmation (`confirm` gets the review's
/// digest, which the repository checks again against a fresh member list before signing).
struct MemberReviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    let review: KeyReplacement.Review
    let confirm: (String) -> Void
    @State private var compared = false

    var body: some View {
        NavigationStack {
            PromptScaffold(error: nil) {
                Section {
                    PromptHeader(symbol: "person.2.badge.key", title: SharingText.reviewTitle, subtitle: review.name)
                        .promptPlainRow()
                }
                Section {
                    Text(SharingText.reviewFirst).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                }
                .paRow()
                Section {
                    ForEach(review.review.members) { m in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(alignment: .firstTextBaseline) {
                                Text(m.isSelf ? "You" : m.shownEmail).font(.headline).foregroundStyle(Color.paInk)
                                Spacer(minLength: 8)
                                Text(InvitationText.role(m.role)).font(.footnote).foregroundStyle(Color.paMuted)
                            }
                            if let other = m.otherListedEmail {
                                Text(SharingText.listedAs(other)).font(.footnote).foregroundStyle(Color.paMuted)
                            }
                            if !m.isSelf {
                                FingerprintRow(label: "Identity fingerprint", fingerprint: m.fingerprint)
                                Text(m.pinLabel).font(.footnote.weight(.semibold))
                                    .foregroundStyle(m.pin == "match" && m.verified ? Color.paOk : Color.paMuted)
                            }
                        }
                        .padding(.vertical, 4)
                        .accessibilityElement(children: .contain)
                        .accessibilityIdentifier("review.member.\(m.userId)")
                    }
                } header: {
                    Text("Members")
                }
                .paRow()
                Section {
                    Toggle("I compared these fingerprints with the people", isOn: $compared)
                        .accessibilityIdentifier("review.compared")
                }
                .paRow()
            } actions: {
                PrimaryButton(title: SharingText.reviewConfirm, busy: false, enabled: compared) {
                    dismiss()
                    confirm(review.review.digest)
                }
                .accessibilityIdentifier("review.confirm")
            }
            .navigationTitle(SharingText.reviewTitle)
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
    }
}
