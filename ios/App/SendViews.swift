import PassAuthKit
import SwiftUI

// Settings → Send (the web vault's Tools → Send): the account's Sends, new and edit, copy and
// share the link, turn the link off and on, delete. Rules and requests in `Shared/Sends.swift`.

private func nowSeconds() -> Int64 { Int64(Date().timeIntervalSince1970) }

private func whenText(_ s: Int64) -> String {
    Date(timeIntervalSince1970: TimeInterval(s)).formatted(date: .abbreviated, time: .shortened)
}

/// What a Send row offers.
private enum SendSheet: Identifiable {
    case new
    case edit(OwnedSend)
    case created(link: String, name: String)
    case delete(OwnedSend)

    var id: String {
        switch self {
        case .new: "new"
        case .edit(let s): "edit-\(s.id)"
        case .created(let link, _): "created-\(link.hashValue)"
        case .delete(let s): "delete-\(s.id)"
        }
    }
}

struct SendsPage: View {
    @Environment(AppModel.self) private var model
    @State private var sends: [OwnedSend]?
    @State private var names: [String: String?] = [:]
    @State private var config: (enabled: Bool, maxDays: Int, maxBytes: Int)?
    @State private var loadError: String?
    @State private var sheet: SendSheet?
    @State private var acting: OwnedSend?

    var body: some View {
        List {
            Section {
                Text("Share a password or a note through a link that works for anyone, even without PassAuth. The text is encrypted on this device and the key is only in the link, so your server can't read it.")
                    .foregroundStyle(Color.paInk)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .paRow()
            if let config, !config.enabled {
                Section {
                    Notice(text: "Send is turned off on this server, so links you made don't open now. Ask the server's admin if you need it.")
                        .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                }
                .paRow()
            }
            if let sends {
                if sends.isEmpty {
                    Section {
                        VStack(spacing: 8) {
                            Image(systemName: "paperplane").font(.title2).foregroundStyle(Color.paAccent).accessibilityHidden(true)
                            Text("No Sends yet").font(.headline).foregroundStyle(Color.paInk)
                            Text("Each Send is deleted on the date you choose, and can stop working sooner: after a number of views, or at an expiry date.")
                                .font(.subheadline).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .accessibilityElement(children: .combine)
                    }
                    .paRow()
                } else {
                    Section("Your Sends") {
                        ForEach(sends) { s in
                            Button { acting = s } label: { SendRow(send: s, name: names[s.id] ?? nil) }
                                .accessibilityIdentifier("send.row")
                                .accessibilityHint("Shows what you can do with this Send")
                        }
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
        .listStyle(.insetGrouped)
        .paList()
        .navigationTitle("Send")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .toolbar {
            if config?.enabled == true {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { sheet = .new } label: { Image(systemName: "plus") }
                        .accessibilityLabel("New Send")
                        .accessibilityIdentifier("send.new")
                }
            }
        }
        .task { await load() }
        .refreshable { await load() }
        .confirmationDialog(acting.flatMap { names[$0.id] ?? nil } ?? "Send", isPresented: Binding(get: { acting != nil }, set: { if !$0 { acting = nil } }),
                            titleVisibility: .visible, presenting: acting) { s in
            let readable = (names[s.id] ?? nil) != nil
            let enabled = config?.enabled ?? false
            if readable {
                Button("Copy link") { copyLink(s) }
                Button("Share link…") { shareLink(s) }
            }
            if readable && enabled { Button("Edit") { sheet = .edit(s) } }
            if enabled { Button(s.disabled ? "Turn on link" : "Turn off link") { toggle(s) } }
            Button("Delete…", role: .destructive) { sheet = .delete(s) }
            Button("Cancel", role: .cancel) {}
        } message: { s in
            if (names[s.id] ?? nil) == nil {
                Text("This Send was made with keys your account no longer has. Delete it and make a new one.")
            }
        }
        .sheet(item: $sheet, onDismiss: { Task { await load() } }) { sheet in
            switch sheet {
            case .new:
                SendEditor(send: nil, maxDays: config?.maxDays ?? SendRules.defaultMaxDays, maxBytes: config?.maxBytes ?? SendRules.defaultMaxBytes) { link, name in
                    self.sheet = link.map { .created(link: $0, name: name) }
                }
            case .edit(let s):
                SendEditor(send: s, maxDays: config?.maxDays ?? SendRules.defaultMaxDays, maxBytes: config?.maxBytes ?? SendRules.defaultMaxBytes) { _, _ in
                    model.notify("Send saved.")
                    self.sheet = nil
                }
            case .created(let link, let name):
                SendCreatedSheet(link: link, name: name)
            case .delete(let s):
                DeleteSendSheet(send: s, name: names[s.id] ?? nil)
            }
        }
    }

    private func load() async {
        config = await model.repo.sendConfig() ?? config
        do {
            let list = try await model.repo.listSends()
            // Names are decrypted once per Send (their key is unwrapped with the account key).
            names = Dictionary(list.map { ($0.id, model.repo.sendName($0)) }, uniquingKeysWith: { a, _ in a })
            sends = list
            loadError = nil
        } catch {
            if sends == nil { loadError = "Couldn't load your Sends. \(errorMessage(error))" } else { model.notify(errorMessage(error)) }
        }
    }

    private func copyLink(_ s: OwnedSend) {
        do { model.copy(try model.repo.sendLink(s), "Link") } catch { model.notify(errorMessage(error)) }
    }

    private func shareLink(_ s: OwnedSend) {
        do { ShareSheet.present(items: [try model.repo.sendLink(s)]) } catch { model.notify(errorMessage(error)) }
    }

    private func toggle(_ s: OwnedSend) {
        Task {
            do {
                var edit = SendEdit()
                edit.disabled = !s.disabled
                try await model.repo.updateSend(s, edit)
                model.notify(s.disabled ? "Link turned on." : "Link turned off.")
                await load()
            } catch {
                model.notify(errorMessage(error))
            }
        }
    }
}

private struct SendRow: View {
    let send: OwnedSend
    let name: String?

    var body: some View {
        let now = nowSeconds()
        let state = send.state(now: now)
        var facts = [send.viewsText]
        if let e = send.expiresAt { facts.append(e > now ? "Link expires \(whenText(e))" : "Link expired \(whenText(e))") }
        facts.append("Kept until \(whenText(send.deleteAt))")
        if send.hasPassword { facts.append("Password") }
        if send.hideEmail { facts.append("Your email hidden") }
        return HStack(alignment: .top, spacing: 12) {
            Image(systemName: "paperplane").foregroundStyle(Color.paAccent).frame(width: 28).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(name ?? "Send that can't be opened").foregroundStyle(Color.paInk).lineLimit(2)
                ForEach(facts, id: \.self) { Text($0).font(.footnote).foregroundStyle(Color.paMuted) }
            }
            Spacer(minLength: 8)
            Text(state.label)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(state == .available ? Color.paOk : Color.paMuted)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background((state == .available ? Color.paOk : Color.paMuted).opacity(0.14), in: Capsule())
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

// MARK: Editor

/// A duration choice: keep the current value, never, one of the durations, or a date.
private enum When: Hashable {
    case keep, never, after(Int), date
}

/// New Send, or changes to one (its text is fetched and decrypted when the editor opens).
private struct SendEditor: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let send: OwnedSend?
    let maxDays: Int
    let maxBytes: Int
    /// After saving: the new Send's link and name (nil link for an edit).
    let onSaved: (String?, String) -> Void

    private enum PasswordMode: Hashable { case keep, set, remove }

    @State private var loaded: (name: String, text: String)?
    @State private var name = ""
    @State private var text = ""
    @State private var passwordMode = PasswordMode.keep
    @State private var password = ""
    @State private var views = ""
    @State private var deletion = When.keep
    @State private var deletionAt = Date()
    @State private var expiry = When.never
    @State private var expiryAt = Date()
    @State private var hideEmail = false
    @State private var disabled = false
    @State private var busy = false
    @State private var error: String?

    private var isNew: Bool { send == nil }
    private var maxText: Int { SendRules.maxTextBytes(maxBytes) }

    var body: some View {
        NavigationStack {
            Group {
                if loaded != nil { form } else if let error { PromptScaffold(error: error) { EmptyView() } actions: { EmptyView() } } else { ProgressView() }
            }
            .navigationTitle(isNew ? "New Send" : "Edit Send")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
            }
        }
        .interactiveDismissDisabled(busy || !text.isEmpty)
        .task { await open() }
        .onDisappear {
            text = ""
            password = ""
        }
    }

    private var form: some View {
        PromptScaffold(error: error) {
            Section {
                LabeledInput(label: "Name", text: $name, identifier: "send.name")
                    .onChange(of: name) { _, v in if v.count > SendRules.nameMax { name = String(v.prefix(SendRules.nameMax)) } }
            } footer: {
                Text("Shown to the people who open it, after any password.")
            }
            .paRow()
            Section {
                TextEditor(text: $text)
                    .font(.body.monospaced())
                    .frame(minHeight: 140)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .accessibilityLabel("Text")
                    .accessibilityIdentifier("send.text")
            } header: {
                Text("Text")
            } footer: {
                let bytes = SendRules.utf8Length(text)
                if bytes * 10 > maxText * 8 {
                    Text("\(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)) of \(ByteCountFormatter.string(fromByteCount: Int64(maxText), countStyle: .file))")
                        .foregroundStyle(bytes > maxText ? Color.paDanger : Color.paMuted)
                }
            }
            .paRow()
            Section {
                if send?.hasPassword == true {
                    Picker("Password", selection: $passwordMode) {
                        Text("Keep the current password").tag(PasswordMode.keep)
                        Text("Set a new password").tag(PasswordMode.set)
                        Text("Remove the password").tag(PasswordMode.remove)
                    }
                }
                if send?.hasPassword != true || passwordMode == .set {
                    SecretInput(label: send?.hasPassword == true ? "New password" : "Password (optional)", text: $password, mono: false, content: .newPassword, identifier: "send.password")
                }
            } footer: {
                Text("People need it, as well as the link, to open the Send. Tell it to them another way than the link.")
            }
            .paRow()
            Section {
                Picker("Delete it", selection: $deletion) {
                    if !isNew, let s = send { Text(whenText(s.deleteAt)).tag(When.keep) }
                    ForEach(SendRules.durationChoices(maxDays), id: \.seconds) { Text("In \($0.label)").tag(When.after($0.seconds)) }
                    Text("On a date…").tag(When.date)
                }
                if deletion == .date {
                    DatePicker("Delete on", selection: $deletionAt, in: Date()..., displayedComponents: [.date, .hourAndMinute])
                }
                Picker("Link expires", selection: $expiry) {
                    if !isNew, let e = send?.expiresAt { Text(whenText(e)).tag(When.keep) }
                    Text("Never").tag(When.never)
                    ForEach(SendRules.durationChoices(maxDays), id: \.seconds) { Text("In \($0.label)").tag(When.after($0.seconds)) }
                    Text("On a date…").tag(When.date)
                }
                if expiry == .date {
                    DatePicker("Expires on", selection: $expiryAt, in: Date()..., displayedComponents: [.date, .hourAndMinute])
                }
                LabeledInput(label: "Maximum views (optional)", text: $views, keyboard: .numberPad, identifier: "send.views")
            } footer: {
                Text("A Send is deleted on its date. An expired or used-up link stops working before that.")
            }
            .paRow()
            Section {
                Toggle("Hide my email address", isOn: $hideEmail)
                if !isNew { Toggle("Turn off the link", isOn: $disabled) }
            } footer: {
                Text("People who open it see your email address unless you hide it.")
            }
            .paRow()
        } actions: {
            PrimaryButton(title: busy ? "Saving…" : (isNew ? "Create Send" : "Save"), busy: busy, action: submit)
                .accessibilityIdentifier("send.save")
        }
    }

    private func open() async {
        guard loaded == nil else { return }
        guard let send else {
            deletion = .after(SendRules.defaultDeletion(maxDays))
            deletionAt = Date().addingTimeInterval(TimeInterval(SendRules.defaultDeletion(maxDays)))
            expiryAt = Date().addingTimeInterval(86400)
            loaded = ("", "")
            return
        }
        passwordMode = send.hasPassword ? .keep : .set
        views = send.maxViews.map(String.init) ?? ""
        deletion = .keep
        deletionAt = Date(timeIntervalSince1970: TimeInterval(send.deleteAt))
        expiry = send.expiresAt == nil ? .never : .keep
        expiryAt = Date(timeIntervalSince1970: TimeInterval(send.expiresAt ?? nowSeconds() + 86400))
        hideEmail = send.hideEmail
        disabled = send.disabled
        do {
            let full = try await model.repo.getSend(send.id)
            let values = (name: model.repo.sendName(full) ?? "", text: try model.repo.sendText(full))
            name = values.name
            text = values.text
            loaded = values
        } catch {
            self.error = "Couldn't open this Send. \(errorMessage(error))"
        }
    }

    /// The deletion or expiry chosen, in Unix seconds (`keep` = the current one).
    private func pick(_ choice: When, _ date: Date, _ current: Int64?, _ now: Int64) -> Int64? {
        switch choice {
        case .never: nil
        case .keep: current
        case .date: Int64(date.timeIntervalSince1970)
        case .after(let s): now + Int64(s)
        }
    }

    private func submit() {
        guard !busy, let loaded else { return }
        error = nil
        let now = nowSeconds()
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { error = "Give this Send a name. People who open it see it too."; return }
        if text.isEmpty { error = "Enter the text to send."; return }
        if SendRules.utf8Length(text) > maxText {
            error = "This text is too long. A Send holds up to \(ByteCountFormatter.string(fromByteCount: Int64(maxText), countStyle: .file)) of text."
            return
        }
        var maxViews: Int64?
        let v = views.trimmingCharacters(in: .whitespaces)
        if !v.isEmpty {
            guard let n = Int64(v), n >= 1, n <= Int64(SendRules.maxViews) else {
                error = "Enter how many times it can be opened: a whole number from 1 to 1,000,000."
                return
            }
            maxViews = n
        }
        guard let deleteAt = pick(deletion, deletionAt, send?.deleteAt, now), deleteAt > now else {
            error = "Pick a deletion date in the future."
            return
        }
        if deletion != .keep && deleteAt > now + Int64(maxDays) * 86400 {
            error = "Pick a deletion date within \(Emergency.daysText(maxDays)): your server keeps Sends no longer."
            return
        }
        let expiresAt = pick(expiry, expiryAt, send?.expiresAt, now)
        if let e = expiresAt {
            if expiry != .keep && e <= now { error = "Pick an expiry date in the future, or choose Never."; return }
            if e >= deleteAt { error = "The Send is deleted before it would expire. Pick an expiry date before the deletion date, or choose Never."; return }
        }
        if send?.hasPassword == true && passwordMode == .set && password.isEmpty { error = "Enter the new password, or keep the current one."; return }
        busy = true
        let pw = password
        Task {
            do {
                if let send {
                    var edit = SendEdit()
                    if trimmed != loaded.name { edit.name = trimmed }
                    if text != loaded.text { edit.text = text }
                    if passwordMode == .remove { edit.password = .some(nil) } else if passwordMode == .set && !pw.isEmpty { edit.password = .some(pw) }
                    if maxViews != send.maxViews { edit.maxViews = .set(maxViews) }
                    if expiresAt != send.expiresAt { edit.expiresAt = .set(expiresAt) }
                    if deleteAt != send.deleteAt { edit.deleteAt = deleteAt }
                    if disabled != send.disabled { edit.disabled = disabled }
                    if hideEmail != send.hideEmail { edit.hideEmail = hideEmail }
                    try await model.repo.updateSend(send, edit)
                    onSaved(nil, trimmed)
                } else {
                    let r = try await model.repo.createSend(NewSend(name: trimmed, text: text, password: pw.isEmpty ? nil : pw, maxViews: maxViews,
                                                                    expiresAt: expiresAt, deleteAt: deleteAt, hideEmail: hideEmail))
                    onSaved(r.link, trimmed)
                }
            } catch {
                self.error = errorMessage(error)
                busy = false
            }
        }
    }
}

/// "Send created": the link with its key hidden, Show, Copy link and Share.
private struct SendCreatedSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let link: String
    let name: String
    @State private var show = false

    var body: some View {
        NavigationStack {
            PromptScaffold {
                Section {
                    PromptHeader(symbol: "paperplane", title: "Send created", subtitle: name).promptPlainRow()
                }
                Section {
                    Text(show ? link : SendRules.masked(link))
                        .font(.footnote.monospaced())
                        .foregroundStyle(Color.paInk)
                        .textSelection(.enabled)
                        .accessibilityLabel(show ? link : "Link, key hidden")
                        .accessibilityIdentifier("send.link")
                    Button(show ? "Hide the key" : "Show the key") { show.toggle() }
                } footer: {
                    Text("Anyone with this link can open the Send. Share it only with the people it's for.")
                }
                .paRow()
            } actions: {
                PrimaryButton(title: "Copy link") { model.copy(link, "Link") }
                    .accessibilityIdentifier("send.copyLink")
                QuietActions {
                    QuietButton(title: "Share…", symbol: "square.and.arrow.up") { ShareSheet.present(items: [link]) }
                    QuietButton(title: "Done") { dismiss() }
                }
            }
            .navigationTitle("Send")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
        }
    }
}

private struct DeleteSendSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let send: OwnedSend
    let name: String?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            PromptScaffold(error: error) {
                Section {
                    PromptHeader(symbol: "paperplane", title: "Delete this Send?", subtitle: name ?? "Send").promptPlainRow()
                }
                Section {
                    Text("Its link stops working at once, for everyone who has it.").foregroundStyle(Color.paInk)
                }
                .paRow()
            } actions: {
                PrimaryButton(title: busy ? "Deleting…" : "Delete Send", busy: busy, destructive: true) {
                    busy = true
                    Task {
                        do {
                            try await model.repo.deleteSend(send.id)
                            model.notify("Send deleted.")
                            dismiss()
                        } catch {
                            self.error = errorMessage(error)
                        }
                        busy = false
                    }
                }
                .accessibilityIdentifier("send.delete")
            }
            .navigationTitle("Delete Send")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) } }
        }
        .presentationDetents([.medium, .large])
    }
}

/// The system share sheet, from the window's top view controller. It never offers Copy: the app
/// has its own copy, which stays on this device and clears itself (`AppModel.copy`). Closing the
/// vault dismisses it (`dismissAll`): a decrypted file or a Send link isn't left on screen.
@MainActor
enum ShareSheet {
    /// The sheet on screen and its completion (run once, however the sheet goes away).
    private static weak var shown: UIActivityViewController?
    private static var pending: (() -> Void)?

    static func present(items: [Any], completion: (() -> Void)? = nil) {
        // Only one at a time: an earlier one is finished first.
        dismissAll()
        let vc = UIActivityViewController(activityItems: items, applicationActivities: nil)
        vc.excludedActivityTypes = [.copyToPasteboard]
        var ran = false
        let finish: () -> Void = {
            guard !ran else { return }
            ran = true
            completion?()
        }
        vc.completionWithItemsHandler = { _, _, _, _ in
            finish()
            if shown == nil || shown === vc { pending = nil }
        }
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first(where: { $0.activationState == .foregroundActive }),
              var top = scene.keyWindow?.rootViewController else {
            finish()
            return
        }
        shown = vc
        pending = finish
        while let next = top.presentedViewController { top = next }
        if let pop = vc.popoverPresentationController {
            pop.sourceView = top.view
            pop.sourceRect = CGRect(x: top.view.bounds.midX, y: top.view.bounds.midY, width: 0, height: 0)
            pop.permittedArrowDirections = []
        }
        top.present(vc, animated: true)
    }

    /// Dismiss the sheet on screen, if any, and run its completion (deleting a shared file).
    static func dismissAll() {
        let vc = shown
        let done = pending
        shown = nil
        pending = nil
        vc?.presentingViewController?.dismiss(animated: false)
        done?()
    }
}
