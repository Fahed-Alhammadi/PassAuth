import PassAuthCore
import PassAuthKit
import SwiftUI

/// One item: copy fields, reveal secrets, live verification code, open websites.
struct ItemView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dynamicTypeSize) private var typeSize
    @Environment(\.dismiss) private var dismiss
    let id: String
    let onEdit: () -> Void
    @State private var confirmTrash = false
    @State private var confirmPurge = false
    @State private var busy = false
    @State private var moving = false

    var body: some View {
        let v = model.repo.vault
        if let v, let entry = v.get(id) {
            content(v, entry)
        } else {
            Color.paBackground
                .onAppear { if v != nil { dismiss() } }
        }
    }

    @ViewBuilder
    private func content(_ v: VaultData, _ entry: Entry) -> some View {
        let i = entry.item
        let canWrite = v.canWrite(entry)
        let trashed = entry.deletedAt != nil
        List {
            Section {
                // Large text: icon above the name, folder and vault on their own lines.
                let big = typeSize.isAccessibilitySize
                let outer = big ? AnyLayout(VStackLayout(alignment: .leading, spacing: 10)) : AnyLayout(HStackLayout(spacing: 14))
                let meta = big ? AnyLayout(VStackLayout(alignment: .leading, spacing: 4)) : AnyLayout(HStackLayout(spacing: 12))
                outer {
                    SiteIcon(host: i.siteHost, name: i.name, kind: i.kind, size: 48)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(i.name.isEmpty ? "Untitled" : i.name).font(.title3.weight(.semibold)).foregroundStyle(Color.paInk)
                            .accessibilityAddTraits(.isHeader)
                        meta {
                            Label(i.folder.flatMap { $0.isEmpty ? nil : $0 } ?? "No folder", systemImage: "folder")
                            Label(v.vaultName(entry.vaultId), systemImage: "lock")
                                .accessibilityLabel("Vault: \(v.vaultName(entry.vaultId))")
                        }
                        .labelStyle(TightLabel())
                        .font(.caption).foregroundStyle(Color.paMuted)
                    }
                    Spacer(minLength: 0)
                    if i.favorite { Image(systemName: "star.fill").foregroundStyle(Color.paAccent).accessibilityLabel("Favorite") }
                }
                .padding(.vertical, 4)
                .paRow()
            }
            if trashed {
                Section {
                    Notice(text: "This item is in the trash" + (entry.deletedAt.map { " since \(formatDate($0))" } ?? "") + ".")
                        .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
                }
            }

            if let l = i.login {
                loginSection(l, entry: entry, canWrite: canWrite && !trashed)
            }
            if let c = i.card {
                Section("Card details") {
                    if !c.cardholderName.isEmpty { FieldRow(label: "Cardholder name", value: c.cardholderName) }
                    if !c.brand.isEmpty { FieldRow(label: "Brand", value: c.brand, copyable: false) }
                    if !c.number.isEmpty { FieldRow(label: "Number", value: c.number, mono: true, secret: true) }
                    if !c.expMonth.isEmpty || !c.expYear.isEmpty { FieldRow(label: "Expires", value: "\(c.expMonth)/\(c.expYear)", copyable: false) }
                    if !c.code.isEmpty { FieldRow(label: "Security code", value: c.code, mono: true, secret: true) }
                }
            }
            if let idn = i.identity {
                let rows: [(String, String)] = [
                    ("Name", [idn.title, idn.firstName, idn.middleName, idn.lastName].filter { !$0.isEmpty }.joined(separator: " ")),
                    ("Username", idn.username), ("Email", idn.email), ("Phone", idn.phone), ("Company", idn.company),
                    ("Address", [idn.address1, idn.address2, idn.city, idn.state, idn.postalCode, idn.country].filter { !$0.isEmpty }.joined(separator: ", ")),
                    ("Passport number", idn.passportNumber), ("Licence number", idn.licenseNumber),
                ].filter { !$0.1.isEmpty }
                if !rows.isEmpty || !idn.ssn.isEmpty {
                    Section("Personal details") {
                        ForEach(rows, id: \.0) { FieldRow(label: $0.0, value: $0.1) }
                        if !idn.ssn.isEmpty { FieldRow(label: "National ID number", value: idn.ssn, mono: true, secret: true) }
                    }
                }
            }
            if let k = i.sshKey {
                Section("SSH key") {
                    if !k.publicKey.isEmpty { FieldRow(label: "Public key", value: k.publicKey, mono: true, lines: 3) }
                    if !k.fingerprint.isEmpty { FieldRow(label: "Fingerprint", value: k.fingerprint, mono: true) }
                    if !k.privateKey.isEmpty { FieldRow(label: "Private key", value: k.privateKey, mono: true, secret: true, lines: 4) }
                }
            }
            let urls = (i.login?.urls ?? []).filter { !$0.url.isEmpty }
            if !urls.isEmpty {
                Section("Autofill options") {
                    ForEach(Array(urls.enumerated()), id: \.offset) { n, u in
                        let openable = u.match != .regex && u.url.contains("://") && (UrlMatcher.parse(u.url)?.scheme.hasPrefix("http") ?? false)
                        FieldRow(label: urls.count > 1 ? "Website \(n + 1)" : "Website", value: u.url, copyLabel: "Website", lines: 1,
                                 extra: openable ? { model.open(u.url) } : nil)
                    }
                }
            }
            if !i.fields.isEmpty {
                Section("Custom fields") {
                    ForEach(Array(i.fields.enumerated()), id: \.offset) { _, f in
                        switch f.type {
                        case .hidden: FieldRow(label: f.name.isEmpty ? "Hidden field" : f.name, value: f.value, mono: true, secret: true)
                        case .boolean: FieldRow(label: f.name.isEmpty ? "Field" : f.name, value: f.value == "true" ? "Yes" : "No", copyable: false)
                        case .text: FieldRow(label: f.name.isEmpty ? "Field" : f.name, value: f.value, copyable: !f.value.isEmpty)
                        }
                    }
                }
            }
            if !i.notes.isEmpty {
                Section("Notes") {
                    Text(i.notes).textSelection(.enabled).foregroundStyle(Color.paInk).paRow()
                        .contextMenu { Button { model.copy(i.notes, "Notes") } label: { Label("Copy", systemImage: "doc.on.doc") } }
                }
            }
            Section("Item history") {
                VStack(alignment: .leading, spacing: 3) {
                    if i.updatedAt > 0 { Text("Last edited \(formatDate(i.updatedAt))") }
                    if i.createdAt > 0 { Text("Created \(formatDate(i.createdAt))") }
                    if let p = i.passwordHistory.first { Text("Password changed \(formatDate(p.changedAt))") }
                }
                .font(.footnote).foregroundStyle(Color.paMuted)
                .accessibilityElement(children: .combine)
                .paRow()
                let previous = PasswordHistory.entries(i.passwordHistory)
                if !previous.isEmpty {
                    NavigationLink {
                        PasswordHistoryView(id: id)
                    } label: {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Password history").foregroundStyle(Color.paInk)
                                Text(PasswordHistory.summary(previous.count)).font(.footnote).foregroundStyle(Color.paMuted)
                            }
                        } icon: {
                            Image(systemName: "clock.arrow.circlepath").foregroundStyle(Color.paAccent)
                        }
                    }
                    .accessibilityIdentifier("passwordHistory")
                    .paRow()
                }
            }
            if canWrite {
                Section {
                    if trashed {
                        Button {
                            run { try await model.repo.restoreItem(entry); model.notify("Item restored.") }
                        } label: { Label("Restore", systemImage: "arrow.uturn.backward") }
                            .disabled(busy).paRow()
                        Button(role: .destructive) { confirmPurge = true } label: { Label("Delete forever", systemImage: "trash.slash") }
                            .disabled(busy).paRow()
                    } else {
                        if !model.repo.moveTargets(entry).isEmpty {
                            Button { moving = true } label: { Label("Move to another vault", systemImage: "folder.badge.gearshape") }
                                .disabled(busy).paRow()
                                .accessibilityIdentifier("moveItem")
                        }
                        Button(role: .destructive) { confirmTrash = true } label: { Label("Move to trash", systemImage: "trash") }
                            .disabled(busy).paRow()
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .paList()
        .navigationTitle("View \(i.kind.label.lowercased())")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .toolbar {
            if canWrite && !trashed {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button {
                        model.run { try await model.repo.setFavorite(entry, !i.favorite) }
                    } label: { Image(systemName: i.favorite ? "star.fill" : "star") }
                        .accessibilityLabel(i.favorite ? "Remove from favorites" : "Add to favorites")
                    Button("Edit", action: onEdit).fontWeight(.semibold)
                }
            }
        }
        .sheet(isPresented: $moving) {
            MoveSheet(entry: entry, from: v.vaultName(entry.vaultId), targets: model.repo.moveTargets(entry))
                .presentationDetents([.medium, .large])
        }
        .confirmationDialog("Move to trash?", isPresented: $confirmTrash, titleVisibility: .visible) {
            Button("Move to trash", role: .destructive) {
                run {
                    try await model.repo.trashItem(entry)
                    model.notify("Moved to trash. You can restore it from the trash.")
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("“\(i.name.isEmpty ? "Untitled" : i.name)” can be restored from the trash.") }
        .confirmationDialog("Delete forever?", isPresented: $confirmPurge, titleVisibility: .visible) {
            Button("Delete forever", role: .destructive) {
                run { try await model.repo.purgeItem(entry); model.notify("Item deleted.") }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("“\(i.name)” will be deleted for good. This can't be undone.") }
    }

    @ViewBuilder
    private func loginSection(_ l: Login, entry: Entry, canWrite: Bool) -> some View {
        let totp = l.totp.flatMap { $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 }
        if !l.username.isEmpty || !l.password.isEmpty || !l.passkeys.isEmpty || totp != nil {
            Section("Login credentials") {
                if !l.username.isEmpty { FieldRow(label: "Username", value: l.username) }
                if !l.password.isEmpty {
                    FieldRow(label: "Password", value: l.password, mono: true, secret: true)
                    if estimateBits(password: l.password) < 50 {
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.shield")
                            Text("This password is easy to guess.")
                            if canWrite { Spacer(); Button("Change it", action: onEdit).buttonStyle(.borderless) }
                        }
                        .font(.footnote).foregroundStyle(Color.paWarn).paRow()
                    }
                }
                ForEach(Array(l.passkeys.enumerated()), id: \.offset) { _, p in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Passkey").font(.caption).foregroundStyle(Color.paMuted)
                        Text(p.userName.isEmpty ? p.rpId : p.userName).foregroundStyle(Color.paInk)
                        Text("\(p.rpId) · Created \(formatDate(p.createdAt))").font(.caption).foregroundStyle(Color.paMuted)
                    }
                    .accessibilityElement(children: .combine)
                    .paRow()
                }
                if let totp { TotpRow(secret: totp) }
            }
        }
    }

    private func run(_ body: @escaping @MainActor () async throws -> Void) {
        busy = true
        Task {
            do { try await body() } catch { model.notify(errorMessage(error)) }
            busy = false
        }
    }
}

/// The live verification code with its countdown ring.
private struct TotpRow: View {
    @Environment(AppModel.self) private var model
    let secret: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let c = try? totpCode(secret: secret, unixSeconds: UInt64(ctx.date.timeIntervalSince1970))
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Verification code").font(.caption).foregroundStyle(Color.paMuted)
                    if let c {
                        Text(c.code.count == 6 ? "\(c.code.prefix(3)) \(c.code.suffix(3))" : c.code)
                            .speechSpellsOutCharacters()
                            // Scales with Dynamic Type (the code matters most at large text sizes).
                            .font(.system(.title, design: .monospaced, weight: .semibold))
                            .foregroundStyle(Color.paAccent)
                            .accessibilityIdentifier("totpCode")
                    } else {
                        Text("This authenticator key isn't valid.").font(.subheadline).foregroundStyle(Color.paDanger)
                    }
                }
                Spacer()
                if let c {
                    TotpRing(remaining: Int(c.remaining), period: Int(c.period))
                    Button { model.copy(c.code, "Verification code") } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Copy verification code")
                        .padding(.leading, 8)
                }
            }
        }
        .paRow()
    }
}

/// Label + value with copy (and reveal for secrets).
struct FieldRow: View {
    @Environment(AppModel.self) private var model
    let label: String
    let value: String
    var mono = false
    var secret = false
    var copyable = true
    var copyLabel: String? = nil
    var lines: Int? = 2
    /// An extra "open" action (websites).
    var extra: (() -> Void)? = nil
    @State private var reveal = false

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption).foregroundStyle(Color.paMuted)
                Text(secret && !reveal ? "••••••••" : value)
                    .font(mono ? .body.monospaced() : .body)
                    .foregroundStyle(Color.paInk)
                    .lineLimit(secret && !reveal ? 1 : (reveal ? nil : lines))
                    .textSelection(.enabled)
                    .accessibilityLabel(secret && !reveal ? "hidden" : value)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 0)
            if secret {
                Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(reveal ? "Hide \(label.lowercased())" : "Show \(label.lowercased())")
            }
            if let extra {
                Button(action: extra) { Image(systemName: "arrow.up.forward.square") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Open website")
            }
            if copyable {
                Button { model.copy(value, copyLabel ?? label) } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Copy \((copyLabel ?? label).lowercased())")
                    .accessibilityIdentifier("copy:\(label)")
            }
        }
        .padding(.vertical, 2)
        .paRow()
    }
}

/// An item's previous passwords, newest first: masked, with reveal and copy.
struct PasswordHistoryView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let id: String

    var body: some View {
        if let entry = model.repo.vault?.get(id) {
            let history = PasswordHistory.entries(entry.item.passwordHistory)
            List {
                Section {
                    if history.isEmpty {
                        Text("This item has no previous passwords.").foregroundStyle(Color.paMuted).paRow()
                    }
                    ForEach(Array(history.enumerated()), id: \.offset) { n, change in
                        HistoryRow(n: n + 1, change: change)
                    }
                } header: {
                    Text(PasswordHistory.summary(history.count))
                } footer: {
                    Text("Earlier passwords of \(entry.item.name.isEmpty ? "this item" : entry.item.name). PassAuth keeps the last 20.")
                }
            }
            .listStyle(.insetGrouped)
            .paList()
            .navigationTitle("Password history")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
        } else {
            Color.paBackground.onAppear { if model.repo.vault != nil { dismiss() } }
        }
    }
}

private struct HistoryRow: View {
    @Environment(AppModel.self) private var model
    let n: Int
    let change: PasswordChange
    @State private var reveal = false

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text(reveal ? change.password : "••••••••")
                    .font(.body.monospaced())
                    .foregroundStyle(Color.paInk)
                    .textSelection(.enabled)
                    .accessibilityLabel(reveal ? change.password : "Password \(n), hidden")
                Text(change.changedAt > 0 ? "Changed \(formatDate(change.changedAt))" : "Date unknown")
                    .font(.caption).foregroundStyle(Color.paMuted)
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("history\(n)")
            Spacer(minLength: 0)
            Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                .buttonStyle(.borderless)
                .accessibilityLabel(reveal ? "Hide password \(n)" : "Show password \(n)")
            Button { model.copy(change.password, "Previous password") } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .accessibilityLabel("Copy password \(n)")
        }
        .padding(.vertical, 2)
        .paRow()
    }
}

/// Choose the vault to move an item to (re-encrypted with that vault's key).
private struct MoveSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let entry: Entry
    let from: String
    let targets: [VaultInfo]
    @State private var selected = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        let target = targets.first { $0.id == selected }
        NavigationStack {
            PromptScaffold(error: error) {
                Section {
                    PromptHeader(symbol: "folder", title: "Move “\(entry.item.name.isEmpty ? "Untitled" : entry.item.name)”", subtitle: "Now in \(from)")
                        .promptPlainRow()
                }
                Section {
                    ForEach(targets) { t in
                        ChoiceRow(title: t.name, detail: roleLabel(t), symbol: "lock.rectangle.stack", selected: t.id == selected) { selected = t.id }
                            .accessibilityIdentifier("vault:\(t.name)")
                    }
                } header: {
                    Text("Move to")
                } footer: {
                    Text("Everyone who can open \(target?.name ?? "the new vault") will see this item, and people who can only open \(from) lose access to it.")
                }
                .paRow()
                .disabled(busy)
            } actions: {
                PrimaryButton(title: busy ? "Moving…" : "Move item", busy: busy, enabled: target != nil) { move(target) }
                    .accessibilityIdentifier("move.confirm")
            }
            .navigationTitle("Move item")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) }
            }
            .interactiveDismissDisabled(busy)
            .onAppear { if selected.isEmpty { selected = targets.first?.id ?? "" } }
        }
    }

    private func move(_ target: VaultInfo?) {
        guard let target, !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.moveItem(entry, to: target.id)
                model.notify("Moved to \(target.name).")
                dismiss()
            } catch is ConflictError {
                error = "This item was changed on another device. Close this, check the item and try again."
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}

func roleLabel(_ v: VaultInfo) -> String {
    switch v.role {
    case .owner: v.personal ? "Your vault" : "Shared with you · you own it"
    case .admin: "Shared with you · you manage it"
    case .write: "Shared with you · you can edit"
    case .read: "Shared with you · view only"
    }
}

/// Icon and title close together (the item header's folder and vault).
private struct TightLabel: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon
            configuration.title
        }
    }
}
