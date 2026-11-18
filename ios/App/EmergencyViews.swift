import PassAuthCore
import PassAuthKit
import SwiftUI

// Settings → Emergency access (the web vault's Settings → Emergency access, same rules and
// wording): the contacts this account named, with confirm (after checking their fingerprint),
// approve and change the waiting period (the master password), reject, end and remove (personal
// vault keys replaced at once); the people who named this account, with accept, decline, ask for
// access, view their vaults read-only and step down; the roster's problems ("Use the server's
// list", "Start a new list", "Confirm again"). Logic in `Shared/Emergency.swift` and
// `Shared/EmergencyClient.swift`.

private func whenText(_ s: Int64) -> String {
    Date(timeIntervalSince1970: TimeInterval(s)).formatted(date: .abbreviated, time: .shortened)
}

private func toneColor(_ t: Tone) -> Color {
    switch t {
    case .ok: Color.paOk
    case .warn: Color.paWarn
    case .info: Color.paAccentInk
    }
}

/// A key's fingerprint in the core's format, or nil when it isn't a key.
private func safeFingerprint(_ publicKey: String) -> String? {
    publicKey.isEmpty ? nil : try? fingerprint(publicKey: publicKey)
}

/// What an emergency access row asks the user to decide.
private enum EmergencyAsk: Identifiable {
    case add
    case confirm(Grant, again: Bool)
    case approve(Grant)
    case end(Grant)
    case wait(Grant)
    case remove(Grant)
    case request(Grant)
    case leave(Grant, decline: Bool)
    case reviewList
    case newList

    var id: String {
        switch self {
        case .add: "add"
        case .confirm(let g, let again): "confirm-\(g.id)-\(again)"
        case .approve(let g): "approve-\(g.id)"
        case .end(let g): "end-\(g.id)"
        case .wait(let g): "wait-\(g.id)"
        case .remove(let g): "remove-\(g.id)"
        case .request(let g): "request-\(g.id)"
        case .leave(let g, _): "leave-\(g.id)"
        case .reviewList: "review"
        case .newList: "new"
        }
    }
}

struct EmergencyPage: View {
    @Environment(AppModel.self) private var model
    @State private var lists: GrantLists?
    @State private var roster: RosterState?
    @State private var config: (enabled: Bool, keys: Bool)?
    @State private var loadError: String?
    @State private var ask: EmergencyAsk?
    @State private var busy: String?
    @State private var viewing: Grant?
    @State private var rotating = false
    /// Pending vaults found shared at the last try (a server without signed sharing): their keys
    /// are replaced in the web vault or the desktop app.
    @State private var sharedPending = KeyReplacement()
    /// Signed sharing: vaults whose signed member list names people who left, waiting for the
    /// user to confirm before their keys are replaced without them.
    @State private var confirming: KeyReplacement?
    /// Signed sharing: a shared vault never signed, whose members the user checks before its key
    /// is replaced (version 1 of its member list).
    @State private var reviewing: KeyReplacement.Review?

    private var enabled: Bool { config?.enabled ?? false }

    var body: some View {
        List {
            Section {
                Text("Name someone you trust who can ask to view your personal vaults if you can't, say after an accident. You're told at once and have the waiting period to say no. After that they can view your personal vaults, not the ones you share and not your Sends, and can't change anything.")
                    .foregroundStyle(Color.paInk)
                    .fixedSize(horizontal: false, vertical: true)
                Text("The waiting period is a rule of your server, not of the encryption. Once someone has had access, they keep what they saw. If you stop trusting them, remove them: PassAuth then changes the keys of your personal vaults, so they can't read anything you add afterwards, unless your server is later compromised. Change the passwords that matter too.")
                    .font(.footnote).foregroundStyle(Color.paMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            notices
            if let lists {
                grantorSection(lists)
                granteeSection(lists)
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
        .listStyle(.insetGrouped)
        .paList()
        .navigationTitle("Emergency access")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .task { await load() }
        .refreshable { await load() }
        .sheet(item: $ask, onDismiss: { Task { await load() } }) { a in
            EmergencySheet(ask: a)
        }
        .navigationDestination(isPresented: Binding(get: { viewing != nil }, set: { if !$0 { viewing = nil } })) {
            if let g = viewing { GrantorVaultPage(grant: g) }
        }
        .confirmationDialog("Replace without them?", isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                            titleVisibility: .visible, presenting: confirming) { c in
            Button("Replace the " + (c.confirm.count == 1 ? "key" : "keys")) {
                rotate(c.confirm.map(\.id), confirmed: c.confirmedIds)
            }
            .accessibilityIdentifier("emergency.rotate.confirm")
            Button("Cancel", role: .cancel) {}
        } message: { c in
            Text(c.confirmText ?? "")
        }
        .sheet(item: $reviewing) { r in
            MemberReviewSheet(review: r) { digest in
                rotate([r.id], reviewed: [r.id: digest])
            }
        }
    }

    // MARK: Notices

    @ViewBuilder
    private var notices: some View {
        if let config, config.enabled && !config.keys {
            Section {
                Notice(text: EmergencyText.serverTooOld).listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
            }
            .paRow()
        } else if config != nil && !enabled {
            Section {
                Notice(text: "Emergency access is turned off on this server: nobody can be named, accept or ask for access while it's off. Ask the server's admin if you need it.")
                    .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
            }
            .paRow()
        }
        if let problem = roster?.problem {
            Section {
                Notice(text: problem == .older ? EmergencyText.rolledBack : EmergencyText.unreadable, kind: .error)
                    .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                Button(problem == .older ? "Use the server's list…" : "Start a new list…") { ask = problem == .older ? .reviewList : .newList }
                    .accessibilityIdentifier("emergency.rosterFix")
            }
            .paRow()
        }
        let pending = model.repo.pendingRotations
        if !pending.isEmpty {
            let sharedIds = Set(sharedPending.shared.map(\.id))
            let own = pending.filter { !sharedIds.contains($0.id) }
            let shared = KeyReplacement(shared: pending.filter { sharedIds.contains($0.id) }.map { KeyReplacement.Shared(id: $0.id, name: $0.name) })
            Section {
                Notice(text: "\(pending.map(\.name).joined(separator: ", ")) \(pending.count == 1 ? "needs" : "need") a new key: someone who may have kept the current one no longer has access.", kind: .error)
                    .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                if let text = shared.sharedText {
                    Text(text).foregroundStyle(Color.paInk)
                }
                if !own.isEmpty {
                    Button(rotating ? "Replacing keys…" : "Replace the keys now") { rotate(own.map(\.id)) }
                        .disabled(rotating)
                        .accessibilityIdentifier("emergency.rotate")
                }
            } footer: {
                Text("Every item in those vaults is encrypted again with a new key. Earlier versions kept of their items are deleted.")
            }
            .paRow()
        }
    }

    // MARK: Your trusted contacts

    @ViewBuilder
    private func grantorSection(_ lists: GrantLists) -> some View {
        Section {
            if lists.asGrantor.isEmpty {
                Text("You haven't named anyone yet.").foregroundStyle(Color.paMuted)
            }
            ForEach(lists.asGrantor) { g in grantorRow(g) }
            if enabled && config?.keys == true {
                Button { ask = .add } label: { Label("Add a trusted contact", systemImage: "person.badge.plus") }
                    .accessibilityIdentifier("emergency.add")
            }
        } header: {
            Text("Your trusted contacts")
        }
        .paRow()
    }

    @ViewBuilder
    private func grantorRow(_ g: Grant) -> some View {
        let who = Emergency.personName(g.grantee)
        let removed = roster?.removed.contains(g.id) ?? false
        let unlisted = roster?.confirmAgain.contains(g.id) ?? false
        let status = removed ? (label: "Removed", text: Emergency.removedText(who), tone: Tone.info) : Emergency.grantorStatus(g, when: whenText)
        let actions = Emergency.grantorActions(g)
        VStack(alignment: .leading, spacing: 8) {
            GrantHeader(name: g.grantee.name.trimmingCharacters(in: .whitespaces).isEmpty ? g.grantee.email : "\(who) (\(g.grantee.email))",
                        label: status.label, text: status.text, tone: status.tone)
            if g.v1Exposed { WarningNote(text: Emergency.v1Warning(who), identifier: "emergency.v1") }
            if unlisted {
                Text("Your list of emergency contacts doesn't have \(who) (a change that didn't finish, or a new list), so PassAuth doesn't give them keys to new or changed vaults. Confirm them again to put them back.")
                    .font(.footnote).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            ActionBar {
                if enabled && unlisted { ActionButton(title: "Confirm again…", primary: true) { ask = .confirm(g, again: true) } }
                if enabled && !removed && actions.contains(.confirm) {
                    ActionButton(title: g.reconfirm ? "Check and confirm again…" : "Check and confirm…", primary: true) { ask = .confirm(g, again: false) }
                }
                if actions.contains(.approve) { ActionButton(title: "Approve now…") { ask = .approve(g) } }
                if actions.contains(.reject) {
                    ActionButton(title: busy == g.id ? "Rejecting…" : "Reject request", primary: true) { reject(g) }
                }
                if actions.contains(.end) { ActionButton(title: "End access…", destructive: true) { ask = .end(g) } }
                if actions.contains(.wait) { ActionButton(title: "Change waiting period") { ask = .wait(g) } }
                if actions.contains(.remove) { ActionButton(title: "Remove…", destructive: true) { ask = .remove(g) } }
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
    }

    // MARK: People who trust you

    @ViewBuilder
    private func granteeSection(_ lists: GrantLists) -> some View {
        Section {
            if lists.asGrantee.isEmpty {
                Text("Nobody has named you as their emergency contact.").foregroundStyle(Color.paMuted)
            }
            ForEach(lists.asGrantee) { g in granteeRow(g) }
            if let fp = model.repo.ownFingerprint {
                FingerprintRow(label: "Your key fingerprint", fingerprint: fp)
            }
        } header: {
            Text("People who trust you")
        } footer: {
            Text("Someone who names you checks this fingerprint with you before confirming you. Read it to them in person or on a call.")
        }
        .paRow()
    }

    @ViewBuilder
    private func granteeRow(_ g: Grant) -> some View {
        let who = Emergency.personName(g.grantor)
        let status = Emergency.granteeStatus(g, when: whenText)
        let actions = Emergency.granteeActions(g)
        VStack(alignment: .leading, spacing: 8) {
            GrantHeader(name: g.grantor.name.trimmingCharacters(in: .whitespaces).isEmpty ? g.grantor.email : "\(who) (\(g.grantor.email))",
                        label: status.label, text: status.text, tone: status.tone)
            ActionBar {
                if enabled && actions.contains(.accept) {
                    ActionButton(title: busy == g.id ? "Accepting…" : "Accept", primary: true) { accept(g) }
                }
                if actions.contains(.decline) { ActionButton(title: "Decline…", destructive: true) { ask = .leave(g, decline: true) } }
                if enabled && actions.contains(.request) { ActionButton(title: "Ask for access…") { ask = .request(g) } }
                if enabled && actions.contains(.view) { ActionButton(title: "View \(who)'s vaults", primary: true) { viewing = g } }
                if actions.contains(.remove) { ActionButton(title: "Stop being their contact…", destructive: true) { ask = .leave(g, decline: false) } }
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
    }

    // MARK: Actions

    private func load() async {
        config = await model.repo.emergencyConfig() ?? config
        do {
            let l = try await model.repo.emergency.listGrants()
            roster = try? await model.repo.emergency.rosterState()
            lists = l
            loadError = nil
        } catch {
            if lists == nil { loadError = "Couldn't load your emergency contacts. \(errorMessage(error))" } else { model.notify(errorMessage(error)) }
        }
    }

    private func reject(_ g: Grant) {
        busy = g.id
        Task {
            do {
                try await model.repo.emergency.reject(g.id)
                model.notify("Request rejected.")
            } catch {
                model.notify(errorMessage(error))
            }
            busy = nil
            await load()
        }
    }

    private func accept(_ g: Grant) {
        busy = g.id
        Task {
            do {
                try await model.repo.emergency.accept(g.id)
                model.notify("Accepted. \(Emergency.personName(g.grantor)) confirms you next.")
            } catch {
                model.notify(errorMessage(error))
            }
            busy = nil
            await load()
        }
    }

    private func rotate(_ ids: [String], confirmed: [String: Set<String>] = [:], reviewed: [String: String] = [:]) {
        rotating = true
        Task {
            do {
                let done = try await model.repo.rotateVaultKeys(ids, confirmed: confirmed, reviewed: reviewed)
                if !done.confirm.isEmpty { confirming = KeyReplacement(confirm: done.confirm) }
                if let first = done.review.first { reviewing = first }
                for v in done.shared where !sharedPending.shared.contains(where: { $0.id == v.id }) { sharedPending.shared.append(v) }
                if let text = done.sharedText {
                    model.notify(done.rotated.isEmpty ? text : "Vault keys replaced. \(text)")
                } else if !done.rotated.isEmpty {
                    model.notify("Vault keys replaced.")
                }
            } catch {
                model.notify(errorMessage(error))
            }
            rotating = false
            await load()
        }
    }
}

/// A person, the status label and what it means.
private struct GrantHeader: View {
    let name: String
    let label: String
    let text: String
    let tone: Tone

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text(name).font(.headline).foregroundStyle(Color.paInk).lineLimit(2)
                Spacer(minLength: 8)
                Text(label)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(toneColor(tone))
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(toneColor(tone).opacity(0.14), in: Capsule())
            }
            Text(text).font(.subheadline).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

/// A row's buttons: one line when they fit, else stacked.
private struct ActionBar<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 16) { content }
            VStack(alignment: .leading, spacing: 10) { content }
        }
        .buttonStyle(.borderless)
        .font(.subheadline.weight(.medium))
    }
}

private struct ActionButton: View {
    let title: String
    var primary = false
    var destructive = false
    let action: () -> Void

    var body: some View {
        Button(title, action: action)
            .foregroundStyle(destructive ? Color.paDanger : primary ? Color.paAccent : Color.paInk)
            .fontWeight(primary ? .semibold : .medium)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
    }
}

// MARK: Sheets

/// The decision sheet for each emergency access step.
private struct EmergencySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let ask: EmergencyAsk
    @State private var email = ""
    @State private var days = Emergency.defaultWaitDays
    @State private var password = ""
    @State private var typedKey = ""
    @State private var busy = false
    @State private var error: String?
    @State private var server: ServerRoster?

    private var needsKeyField: Bool { model.state.secretKeyRequired && !model.state.secretKeyStored }

    var body: some View {
        NavigationStack {
            PromptScaffold(error: error) {
                content
            } actions: {
                PrimaryButton(title: busy ? busyTitle : actionTitle, busy: busy, enabled: actionEnabled, destructive: destructive, action: run)
                    .accessibilityIdentifier("emergency.confirm")
            }
            .navigationTitle("Emergency access")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) } }
        }
        .interactiveDismissDisabled(busy || !password.isEmpty)
        .task {
            if case .wait(let g) = ask { days = g.waitDays }
            if case .reviewList = ask { await loadServerList() }
        }
        .onDisappear {
            password = ""
            typedKey = ""
        }
    }

    // MARK: What each step says

    @ViewBuilder
    private var content: some View {
        switch ask {
        case .add:
            header("Add a trusted contact", nil)
            Section {
                LabeledInput(label: "Their email address", text: $email, keyboard: .emailAddress, content: .emailAddress, autocap: .never, identifier: "emergency.email")
                Stepper(value: $days, in: Emergency.minWaitDays...Emergency.maxWaitDays) {
                    Text("Waiting period: \(Emergency.daysText(days))")
                }
                .accessibilityIdentifier("emergency.days")
            } footer: {
                Text("They need an account on this server. They accept, then you confirm them by checking their fingerprint together.")
            }
            .paRow()
            Section { Notice(text: Emergency.confirmMeaning("Your contact")) }.promptPlainRow()
        case .confirm(let g, let again):
            let who = Emergency.personName(g.grantee)
            header(again ? "Confirm \(who) again?" : "Confirm \(who)?", g.grantee.email)
            Section {
                if g.reconfirm && !again { Text(Emergency.reconfirmText(who)).foregroundStyle(Color.paInk) }
                Text(again
                     ? "\(who) gets keys to your new and changed personal vaults again. First make sure it's really their account: the key below is the one your server names for them now."
                     : "Confirming lets \(who) ask for access later: a key to your personal vaults is locked so that only their account can open it. First make sure it's really their account.")
                    .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            if !again { Section { Notice(text: Emergency.confirmMeaning(who, v1Exposed: g.v1Exposed), kind: .error) }.promptPlainRow() }
            Section {
                if let fp = safeFingerprint(g.grantee.publicKey) {
                    FingerprintRow(label: "\(who)'s key fingerprint", fingerprint: fp)
                } else {
                    WarningNote(text: "PassAuth can't show \(who)'s fingerprint, so their account can't be checked and they can't be confirmed. Remove them, then add them again.")
                }
            } footer: {
                Text("Ask \(who) to read you their key fingerprint, in person or on a call. PassAuth shows it under Emergency access. Confirm only if it matches exactly.")
            }
            .paRow()
        case .approve(let g):
            let who = Emergency.personName(g.grantee)
            header("Give \(who) access now?", g.grantee.email)
            Section {
                Text("\(who) can view your personal vaults at once, without waiting. They keep what they see, even if you end their access later.")
                    .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            passwordSection
        case .end(let g):
            let who = Emergency.personName(g.grantee)
            header("End \(who)'s access?", g.grantee.email)
            Section {
                Text("\(who) can't view your vaults any more, but keeps whatever they already saw. They can ask for access again. If you no longer trust them, remove them instead: PassAuth then changes the keys of your personal vaults. Change the passwords that matter too.")
                    .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
        case .wait(let g):
            let who = Emergency.personName(g.grantee)
            header("Change the waiting period", who)
            Section {
                Stepper(value: $days, in: Emergency.minWaitDays...Emergency.maxWaitDays) {
                    Text("Days to say no after \(who) asks: \(days)")
                }
                .accessibilityIdentifier("emergency.days")
            } footer: {
                Text("From \(Emergency.minWaitDays) to \(Emergency.maxWaitDays) days.\(g.status == .requested ? " A request already waiting follows the new period, counted from when they asked." : "")")
            }
            .paRow()
            if days < g.waitDays { passwordSection }
        case .remove(let g):
            let who = Emergency.personName(g.grantee)
            header("Remove \(who)?", "Emergency contact")
            Section {
                Text(Emergency.removalText(g)).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
        case .request(let g):
            let who = Emergency.personName(g.grantor)
            header("Ask for access to \(who)'s vaults?", g.grantor.email)
            Section {
                Text("\(who) is emailed at once. Unless they reject it, you can view their own vaults in \(Emergency.daysText(g.waitDays)). Ask only if they really can't reach their vaults themselves.")
                    .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
        case .leave(let g, let decline):
            let who = Emergency.personName(g.grantor)
            header(decline ? "Decline \(who)'s invitation?" : "Stop being \(who)'s emergency contact?", g.grantor.email)
            Section {
                Text("You won't be able to ask for access to \(who)'s vaults. They can name you again.").foregroundStyle(Color.paInk)
            }
            .paRow()
        case .reviewList:
            header("Use your server's list of emergency contacts?", nil)
            Section {
                Text("Only do this if your server's admin restored a backup. Contacts you removed after that backup could get access to your personal vaults again. Check the list below before you continue.")
                    .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            Section {
                if let server {
                    if server.entries.isEmpty { Text("The server's list has no contacts.").foregroundStyle(Color.paMuted) }
                    ForEach(server.entries, id: \.entry.id) { r in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(Emergency.entryLabel(r.entry)).foregroundStyle(Color.paInk)
                            if r.removed {
                                Text("Removed earlier: stays removed").font(.footnote.weight(.semibold)).foregroundStyle(Color.paMuted)
                            } else if r.wouldReturn {
                                Text("Would get access again").font(.footnote.weight(.semibold)).foregroundStyle(Color.paDanger)
                            }
                            Text("Key fingerprint: \(safeFingerprint(r.entry.contactKey) ?? "unknown")").font(.footnote.monospaced()).foregroundStyle(Color.paMuted)
                        }
                        .accessibilityElement(children: .combine)
                    }
                } else {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Loading…").foregroundStyle(Color.paMuted)
                    }
                }
            } header: {
                Text("Contacts on the server's list")
            }
            .paRow()
            passwordSection
        case .newList:
            header("Start a new list of emergency contacts?", nil)
            Section {
                Text("Your server's list doesn't open with your account's key, so PassAuth can't trust it. A new, empty list keeps the contacts this device knows you removed. Contacts who hold keys then need to be confirmed again.")
                    .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            passwordSection
        }
    }

    @ViewBuilder
    private func header(_ title: String, _ subtitle: String?) -> some View {
        Section { PromptHeader(symbol: "lifepreserver", title: title, subtitle: subtitle).promptPlainRow() }
    }

    @ViewBuilder
    private var passwordSection: some View {
        Section {
            SecretInput(label: "Master password", text: $password, mono: false, identifier: "emergency.password", submit: run)
            if needsKeyField {
                LabeledInput(label: "Secret Key", text: $typedKey, mono: true, autocap: .characters, identifier: "emergency.secretKey")
            }
        } footer: {
            Text("Your server checks your master password first.")
        }
        .paRow()
    }

    private var needsPassword: Bool {
        switch ask {
        case .approve, .reviewList, .newList: true
        case .wait(let g): days < g.waitDays
        default: false
        }
    }

    private var actionTitle: String {
        switch ask {
        case .add: "Add contact"
        case .confirm(_, let again): again ? "Confirm again" : "Confirm contact"
        case .approve: "Approve access"
        case .end: "End access"
        case .wait: "Save"
        case .remove: "Remove contact"
        case .request: "Ask for access"
        case .leave(_, let decline): decline ? "Decline" : "Stop being their contact"
        case .reviewList: "Use the server's list"
        case .newList: "Start a new list"
        }
    }

    private var busyTitle: String {
        switch ask {
        case .add: "Adding…"
        case .confirm: "Confirming…"
        case .approve: "Approving…"
        case .end: "Ending…"
        case .wait, .reviewList, .newList: "Saving…"
        case .remove(let g): Emergency.hasKeys(g) ? "Removing and changing keys…" : "Removing…"
        case .request: "Asking…"
        case .leave: "Removing…"
        }
    }

    private var destructive: Bool {
        switch ask {
        case .end, .remove, .leave, .reviewList: true
        default: false
        }
    }

    private var actionEnabled: Bool {
        switch ask {
        case .confirm(let g, _): safeFingerprint(g.grantee.publicKey) != nil
        case .reviewList: server != nil
        default: true
        }
    }

    private func loadServerList() async {
        do {
            server = try await model.repo.emergency.loadServerRoster()
        } catch {
            self.error = errorMessage(error)
        }
    }

    private func run() {
        guard !busy else { return }
        error = nil
        if needsPassword && password.isEmpty {
            error = { if case .wait = ask { return "Enter your master password to shorten the waiting period." } else { return "Enter your master password to continue." } }()
            return
        }
        if case .add = ask, !email.contains("@") {
            error = "Enter your contact's email address."
            return
        }
        busy = true
        let pw = password
        let key = typedKey.isEmpty ? nil : typedKey
        let client = model.repo.emergency
        Task {
            do {
                switch ask {
                case .add:
                    let g = try await client.inviteContact(email: email, waitDays: days)
                    model.notify("\(Emergency.personName(g.grantee)) was invited. They accept, then you confirm them.")
                case .confirm(let g, let again):
                    if again { try await client.confirmAgain(g) } else { try await client.confirmContact(g) }
                    model.notify(again ? "\(Emergency.personName(g.grantee)) is back on your list of emergency contacts." : "\(Emergency.personName(g.grantee)) is your emergency contact now.")
                case .approve(let g):
                    try await client.approve(g.id, password: pw, secretKey: key)
                    model.notify("\(Emergency.personName(g.grantee)) can view your vaults now.")
                case .end(let g):
                    try await client.reject(g.id)
                    model.notify("Access ended.")
                case .wait(let g):
                    try await client.changeWait(g.id, days: days, password: days < g.waitDays ? pw : nil, secretKey: key)
                    model.notify("Waiting period changed.")
                case .remove(let g):
                    let done = try await client.removeContact(g)
                    let who = Emergency.personName(g.grantee)
                    model.notify(done.failed != nil
                                 ? "\(who) was removed, but the keys of your personal vaults weren't changed yet. Replace them from Emergency access."
                                 : done.shared.map { "\(who) was removed. \($0)" }
                                 ?? (done.rotated > 0 ? "Emergency contact removed and vault keys changed." : "Emergency contact removed."))
                case .request(let g):
                    try await client.requestAccess(g.id)
                    model.notify("\(Emergency.personName(g.grantor)) was told about your request.")
                case .leave(let g, let decline):
                    try await client.leave(g.id)
                    model.notify(decline ? "Invitation declined." : "You're no longer their emergency contact.")
                case .reviewList:
                    guard let server else { throw UserError("Wait for the list to load, then try again.") }
                    do {
                        try await client.useServerRoster(server, password: pw, secretKey: key)
                    } catch let e as UserError where e.message == EmergencyText.rosterChanged {
                        // Changed since it was shown: read it again and show it again, never written unseen.
                        self.server = nil
                        await loadServerList()
                        throw e
                    }
                    model.notify("This device uses your server's list of emergency contacts now.")
                case .newList:
                    try await client.startNewRoster(password: pw, secretKey: key)
                    model.notify("New list of emergency contacts started.")
                }
                password = ""
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}

// MARK: A grantor's vaults, read-only

/// The personal vaults a grantor shared through an approved access: decrypted into this page's
/// memory only (nothing is stored), gone when the page closes or PassAuth locks.
private struct GrantorVaultPage: View {
    @Environment(AppModel.self) private var model
    let grant: Grant
    @State private var opened: GrantorVault?
    @State private var error: String?
    @State private var query = ""

    var body: some View {
        let who = Emergency.personName(grant.grantor)
        List {
            Section {
                Text("View only. Nothing of it is saved on this device: it's gone when you leave this page or PassAuth locks.")
                    .font(.footnote).foregroundStyle(Color.paMuted)
                if let o = opened, o.failed > 0 {
                    Text(o.failed == 1 ? "One item couldn't be opened and is left out." : "\(o.failed) items couldn't be opened and are left out.")
                        .font(.footnote).foregroundStyle(Color.paDanger)
                }
                // Vault manifests: the items sent aren't the ones the vault's record of changes names.
                if let o = opened {
                    ForEach(o.vaults.filter { o.unverified.contains($0.id) }, id: \.id) { v in
                        Text("\(v.name): \(ManifestText.warning)")
                            .font(.footnote).foregroundStyle(Color.paDanger)
                            .accessibilityIdentifier("emergency.manifestWarning")
                    }
                }
            }
            .paRow()
            if let o = opened {
                let q = query.trimmingCharacters(in: .whitespaces).lowercased()
                ForEach(o.vaults, id: \.id) { v in
                    let items = o.items.filter { $0.vaultId == v.id && $0.deletedAt == nil && (q.isEmpty || $0.item.name.lowercased().contains(q)) }
                    Section(v.name) {
                        if items.isEmpty { Text(q.isEmpty ? "No items." : "No matching items.").foregroundStyle(Color.paMuted) }
                        ForEach(items) { e in
                            NavigationLink {
                                ReadOnlyItemPage(entry: e, grantId: grant.id, vaultName: v.name)
                            } label: {
                                Label {
                                    Text(e.item.name.isEmpty ? "Untitled" : e.item.name).foregroundStyle(Color.paInk)
                                } icon: {
                                    Image(systemName: e.item.kind.symbol).foregroundStyle(Color.paAccent)
                                }
                            }
                        }
                    }
                    .paRow()
                }
            } else if let error {
                Section {
                    ErrorText(text: error)
                    Button("Try again") { Task { await open() } }
                }
                .paRow()
            } else {
                Section {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Opening…").foregroundStyle(Color.paMuted)
                    }
                }
                .paRow()
            }
        }
        .listStyle(.insetGrouped)
        .paList()
        .searchable(text: $query, prompt: "Search \(who)'s items")
        .navigationTitle("\(who)'s vaults")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .task { await open() }
        .onChange(of: model.repo.vault == nil) { _, locked in if locked { opened = nil } }
        .onDisappear { opened = nil }
    }

    private func open() async {
        error = nil
        do {
            opened = try await model.repo.openGrantorVault(grant.id)
        } catch {
            self.error = errorMessage(error)
        }
    }
}

/// One of a grantor's items: its fields with copy and reveal, its files with download. Never
/// offered for AutoFill and never stored.
private struct ReadOnlyItemPage: View {
    @Environment(AppModel.self) private var model
    let entry: GrantorVault.Entry
    let grantId: String
    let vaultName: String
    @State private var downloading: String?
    @State private var error: String?

    var body: some View {
        let i = entry.item
        List {
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    Text(i.name.isEmpty ? "Untitled" : i.name).font(.title3.weight(.semibold)).foregroundStyle(Color.paInk)
                        .accessibilityAddTraits(.isHeader)
                    Text("\(vaultName) · View only").font(.caption).foregroundStyle(Color.paMuted)
                }
                .padding(.vertical, 4)
            }
            .paRow()
            if let l = i.login {
                Section("Login credentials") {
                    if !l.username.isEmpty { FieldRow(label: "Username", value: l.username) }
                    if !l.password.isEmpty { FieldRow(label: "Password", value: l.password, mono: true, secret: true) }
                    if let t = l.totp, !t.isEmpty { FieldRow(label: "Authenticator key", value: t, mono: true, secret: true) }
                }
                let urls = l.urls.filter { !$0.url.isEmpty }
                if !urls.isEmpty {
                    Section("Websites") {
                        ForEach(Array(urls.enumerated()), id: \.offset) { n, u in
                            FieldRow(label: urls.count > 1 ? "Website \(n + 1)" : "Website", value: u.url, copyLabel: "Website", lines: 1)
                        }
                    }
                }
            }
            if let c = i.card {
                Section("Card details") {
                    if !c.cardholderName.isEmpty { FieldRow(label: "Cardholder name", value: c.cardholderName) }
                    if !c.number.isEmpty { FieldRow(label: "Number", value: c.number, mono: true, secret: true) }
                    if !c.expMonth.isEmpty || !c.expYear.isEmpty { FieldRow(label: "Expires", value: "\(c.expMonth)/\(c.expYear)", copyable: false) }
                    if !c.code.isEmpty { FieldRow(label: "Security code", value: c.code, mono: true, secret: true) }
                }
            }
            if let idn = i.identity {
                let rows: [(String, String)] = [
                    ("Name", [idn.title, idn.firstName, idn.middleName, idn.lastName].filter { !$0.isEmpty }.joined(separator: " ")),
                    ("Email", idn.email), ("Phone", idn.phone),
                    ("Address", [idn.address1, idn.address2, idn.city, idn.state, idn.postalCode, idn.country].filter { !$0.isEmpty }.joined(separator: ", ")),
                ].filter { !$0.1.isEmpty }
                if !rows.isEmpty || !idn.ssn.isEmpty || !idn.passportNumber.isEmpty {
                    Section("Personal details") {
                        ForEach(rows, id: \.0) { FieldRow(label: $0.0, value: $0.1) }
                        if !idn.passportNumber.isEmpty { FieldRow(label: "Passport number", value: idn.passportNumber, mono: true, secret: true) }
                        if !idn.ssn.isEmpty { FieldRow(label: "National ID number", value: idn.ssn, mono: true, secret: true) }
                    }
                }
            }
            if let k = i.sshKey, !k.privateKey.isEmpty || !k.publicKey.isEmpty {
                Section("SSH key") {
                    if !k.publicKey.isEmpty { FieldRow(label: "Public key", value: k.publicKey, mono: true, lines: 3) }
                    if !k.privateKey.isEmpty { FieldRow(label: "Private key", value: k.privateKey, mono: true, secret: true, lines: 4) }
                }
            }
            if !i.fields.isEmpty {
                Section("Custom fields") {
                    ForEach(Array(i.fields.enumerated()), id: \.offset) { _, f in
                        FieldRow(label: f.name.isEmpty ? "Field" : f.name, value: f.type == .boolean ? (f.value == "true" ? "Yes" : "No") : f.value,
                                 mono: f.type == .hidden, secret: f.type == .hidden, copyable: f.type != .boolean && !f.value.isEmpty)
                    }
                }
            }
            if !i.notes.isEmpty {
                Section("Notes") { Text(i.notes).textSelection(.enabled).foregroundStyle(Color.paInk) }
                    .paRow()
            }
            let files = AttachmentList.read(i)
            if !files.isEmpty {
                Section("Attachments (\(files.count))") {
                    ForEach(files) { f in
                        FileRow(file: f, busy: downloading == f.id, download: { download(f) })
                    }
                    ErrorText(text: error)
                }
                .paRow()
            }
        }
        .listStyle(.insetGrouped)
        .paList()
        .navigationTitle("View item")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
    }

    private func download(_ f: Attachment) {
        guard downloading == nil else { return }
        downloading = f.id
        error = nil
        let itemId = entry.id
        let path = VaultRepository.emergencyAttachmentPath(grant: grantId, attachment: f.id)
        let repo = model.repo
        model.downloads.run(repo: repo, { try await repo.downloadAttachment(f, itemId: itemId, path: path) }) { problem in
            downloading = nil
            if let problem { error = problem }
        }
    }
}
