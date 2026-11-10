import PassAuthCore
import PassAuthKit
import SwiftUI

let matchOptions: [(UrlMatch, String)] = [
    (.default, "Default (app setting)"), (.domain, "Base domain"), (.host, "Host"), (.startsWith, "Starts with"),
    (.regex, "Regular expression"), (.exact, "Exact"), (.never, "Never"),
]

/// New item or edit an existing one (the web vault's item editor), shown as a sheet.
struct EditView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// The item as it was when editing started: if a sync brings a newer version meanwhile,
    /// saving reports the conflict (revision check) instead of silently overwriting it.
    /// Kept in state: the sheet is rebuilt with the newest entry after every sync (live sync
    /// included), but saving must use the revision editing started from.
    @State private var entry: Entry?
    let onSaved: (String?) -> Void
    @State private var original: Item
    @State private var item: Item
    @State private var vaultId: String
    @State private var busy = false
    @State private var error: String?
    @State private var conflict = false
    @State private var confirmDiscard = false

    /// `otp`: an authenticator key to add (an otpauth:// link opened in the app); a new login also
    /// takes its issuer as the name and its account as the username.
    init(entry: Entry?, kind: ItemKind, otp: OtpKey? = nil, onSaved: @escaping (String?) -> Void) {
        _entry = State(initialValue: entry)
        self.onSaved = onSaved
        let start = entry?.item ?? Item.empty(kind)
        var edited = start
        if let otp {
            if edited.login == nil { edited.login = Login() }
            edited.login?.totp = otp.value
            if entry == nil {
                if edited.name.isEmpty { edited.name = otp.issuer }
                if edited.login?.username.isEmpty ?? false { edited.login?.username = otp.account }
            }
        }
        _original = State(initialValue: start)
        _item = State(initialValue: edited)
        _vaultId = State(initialValue: entry?.vaultId ?? "")
    }

    private func b<T>(_ kp: WritableKeyPath<Item, T>) -> Binding<T> {
        Binding(get: { item[keyPath: kp] }, set: { item[keyPath: kp] = $0 })
    }

    private func url(_ n: Int) -> Binding<String> {
        Binding(get: { n < (item.login?.urls.count ?? 0) ? item.login!.urls[n].url : "" },
                set: { if n < (item.login?.urls.count ?? 0) { item.login!.urls[n].url = $0 } })
    }

    private func match(_ n: Int) -> Binding<UrlMatch> {
        Binding(get: { n < (item.login?.urls.count ?? 0) ? item.login!.urls[n].match : .default },
                set: { if n < (item.login?.urls.count ?? 0) { item.login!.urls[n].match = $0 } })
    }

    private func field<T>(_ n: Int, _ kp: WritableKeyPath<Field, T>, _ fallback: T) -> Binding<T> {
        Binding(get: { n < item.fields.count ? item.fields[n][keyPath: kp] : fallback },
                set: { if n < item.fields.count { item.fields[n][keyPath: kp] = $0 } })
    }

    private var totp: Binding<String> {
        Binding(get: { item.login?.totp ?? "" }, set: { item.login?.totp = $0.isEmpty ? nil : $0 })
    }

    var body: some View {
        let v = model.repo.vault
        let label = item.kind.label.lowercased()
        NavigationStack {
            Form {
                Section {
                    LabeledInput(label: "Name", text: b(\.name), identifier: "edit.name")
                }
                .paRow()
                if item.login != nil { loginSections }
                if item.card != nil { cardSection }
                if item.identity != nil { identitySection }
                if item.sshKey != nil {
                    Section("SSH key") {
                        LabeledInput(label: "Private key", text: b(\.sshKey!.privateKey), mono: true, autocap: .never, multiline: true)
                        LabeledInput(label: "Public key", text: b(\.sshKey!.publicKey), mono: true, autocap: .never, multiline: true)
                        LabeledInput(label: "Fingerprint", text: b(\.sshKey!.fingerprint), mono: true, autocap: .never)
                    }
                    .paRow()
                }
                fieldsSection
                Section("Other") {
                    LabeledInput(label: "Notes", text: b(\.notes), multiline: true)
                    HStack(alignment: .bottom) {
                        LabeledInput(label: "Folder", text: Binding(get: { item.folder ?? "" }, set: { item.folder = $0.isEmpty ? nil : $0 }))
                        let folders = (v?.folders ?? []).filter { $0 != item.folder }
                        if !folders.isEmpty {
                            Menu {
                                ForEach(folders, id: \.self) { f in Button(f) { item.folder = f } }
                            } label: { Image(systemName: "folder.badge.plus") }
                                .accessibilityLabel("Choose a folder")
                                .padding(.bottom, 6)
                        }
                    }
                    if entry == nil, let writable = v?.writable, writable.count > 1 || (vaultId.isEmpty && !writable.isEmpty) {
                        Picker("Vault", selection: $vaultId) {
                            ForEach(writable) { Text($0.name).tag($0.id) }
                        }
                    }
                    Toggle("Favorite", isOn: b(\.favorite))
                }
                .paRow()
            }
            .paList()
            .navigationTitle(entry != nil ? "Edit \(label)" : "New \(label)")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { if item != original { confirmDiscard = true } else { dismiss() } }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView().tint(Color.paAccent) } else { Button("Save", action: save).fontWeight(.semibold).accessibilityIdentifier("edit.save") }
                }
            }
            .interactiveDismissDisabled(item != original || busy)
            .confirmationDialog("Discard your changes?", isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button("Discard changes", role: .destructive) { dismiss() }
                Button("Keep editing", role: .cancel) {}
            }
            .alert("Couldn't save", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(error ?? "")
            }
            .alert("This item was changed on another device", isPresented: $conflict) {
                Button("Keep my version") { save(overwrite: true) }
                Button("Use the other version", role: .destructive) {
                    model.run { try await model.repo.sync() }
                    dismiss()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Saving now would overwrite those changes. Keep your version, or discard your edits and use the version from the other device.")
            }
            .onAppear {
                // New items go to the account's own vault unless the user picks another one.
                if vaultId.isEmpty { vaultId = v?.defaultVault?.id ?? "" }
            }
            // Typing happens in the keyboard's window, which the activity recognizer doesn't see:
            // count edits as activity for the vault timeout.
            .onChange(of: item) { model.lockManager.touch() }
        }
    }

    @ViewBuilder
    private var loginSections: some View {
        Section("Login credentials") {
            LabeledInput(label: "Username", text: b(\.login!.username), keyboard: .emailAddress, content: .username, autocap: .never, identifier: "edit.username")
            SecretInput(label: "Password", text: b(\.login!.password), onGenerate: {
                if let p = try? generatePassword(optionsJson: nil) { item.login?.password = p }
            }, identifier: "edit.password")
            StrengthMeter(password: item.login?.password ?? "")
            TotpField(value: totp)
        }
        .paRow()
        Section("Autofill options") {
            ForEach(Array((item.login?.urls ?? []).indices), id: \.self) { n in
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .bottom) {
                        LabeledInput(label: n == 0 ? "Website" : "Website \(n + 1)", text: url(n), prompt: "https://example.com", keyboard: .URL, content: .URL, autocap: .never, identifier: "edit.url\(n)")
                        Button(role: .destructive) { item.login?.urls.remove(at: n) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless).foregroundStyle(Color.paDanger)
                            .accessibilityLabel("Remove website")
                            .padding(.bottom, 6)
                    }
                    Picker("Match detection", selection: match(n)) {
                        ForEach(matchOptions, id: \.0) { Text($0.1).tag($0.0) }
                    }
                    .font(.subheadline)
                }
            }
            Button { item.login?.urls.append(LoginUrl()) } label: { Label("Add website", systemImage: "plus") }
            ForEach(item.login?.passkeys ?? [], id: \.credentialId) { p in
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Passkey").font(.caption).foregroundStyle(Color.paMuted)
                        Text(p.userName.isEmpty ? p.rpId : p.userName).foregroundStyle(Color.paInk)
                        Text("\(p.rpId) · Created \(formatDate(p.createdAt))").font(.caption).foregroundStyle(Color.paMuted)
                    }
                    Spacer()
                    Button(role: .destructive) { item.login?.passkeys.removeAll { $0.credentialId == p.credentialId } } label: {
                        Image(systemName: "minus.circle.fill")
                    }
                    .buttonStyle(.borderless).foregroundStyle(Color.paDanger)
                    .accessibilityLabel("Remove passkey for \(p.rpId)")
                    .accessibilityIdentifier("edit.passkey.remove")
                }
            }
            let removed = (original.login?.passkeys.count ?? 0) - (item.login?.passkeys.count ?? 0)
            if removed > 0 {
                Text("\(removed == 1 ? "1 passkey is" : "\(removed) passkeys are") deleted when you save. PassAuth can't sign in with \(removed == 1 ? "it" : "them") after that. The website may still list \(removed == 1 ? "it" : "them") in its security settings; remove \(removed == 1 ? "it" : "them") there too.")
                    .font(.footnote).foregroundStyle(Color.paMuted)
            }
        }
        .paRow()
    }

    private var cardSection: some View {
        Section("Card details") {
            LabeledInput(label: "Cardholder name", text: b(\.card!.cardholderName), content: .name)
            LabeledInput(label: "Card number", text: Binding(get: { item.card?.number ?? "" }, set: { item.card?.number = $0.filter { $0.isNumber || $0 == " " } }),
                         mono: true, keyboard: .numberPad, content: .creditCardNumber)
            LabeledInput(label: "Brand", text: b(\.card!.brand))
            HStack(spacing: 12) {
                LabeledInput(label: "Expiry month", text: b(\.card!.expMonth), keyboard: .numberPad)
                LabeledInput(label: "Expiry year", text: b(\.card!.expYear), keyboard: .numberPad)
            }
            SecretInput(label: "Security code", text: b(\.card!.code), content: nil)
        }
        .paRow()
    }

    private var identitySection: some View {
        Section("Personal details") {
            LabeledInput(label: "Title", text: b(\.identity!.title))
            HStack(spacing: 12) {
                LabeledInput(label: "First name", text: b(\.identity!.firstName), content: .givenName)
                LabeledInput(label: "Last name", text: b(\.identity!.lastName), content: .familyName)
            }
            LabeledInput(label: "Middle name", text: b(\.identity!.middleName), content: .middleName)
            LabeledInput(label: "Username", text: b(\.identity!.username), autocap: .never)
            LabeledInput(label: "Email", text: b(\.identity!.email), keyboard: .emailAddress, content: .emailAddress, autocap: .never)
            LabeledInput(label: "Phone", text: b(\.identity!.phone), keyboard: .phonePad, content: .telephoneNumber)
            LabeledInput(label: "Company", text: b(\.identity!.company), content: .organizationName)
            LabeledInput(label: "Address", text: b(\.identity!.address1), content: .streetAddressLine1)
            LabeledInput(label: "Address line 2", text: b(\.identity!.address2), content: .streetAddressLine2)
            HStack(spacing: 12) {
                LabeledInput(label: "City", text: b(\.identity!.city), content: .addressCity)
                LabeledInput(label: "State", text: b(\.identity!.state), content: .addressState)
            }
            HStack(spacing: 12) {
                LabeledInput(label: "Postal code", text: b(\.identity!.postalCode), content: .postalCode)
                LabeledInput(label: "Country", text: b(\.identity!.country), content: .countryName)
            }
            SecretInput(label: "National ID number", text: b(\.identity!.ssn), content: nil)
            LabeledInput(label: "Passport number", text: b(\.identity!.passportNumber), autocap: .characters)
            LabeledInput(label: "Licence number", text: b(\.identity!.licenseNumber), autocap: .characters)
        }
        .paRow()
    }

    private var fieldsSection: some View {
        Section("Custom fields") {
            ForEach(Array(item.fields.indices), id: \.self) { n in
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .bottom) {
                        LabeledInput(label: "Field name", text: field(n, \.name, ""))
                        Button(role: .destructive) { item.fields.remove(at: n) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless).foregroundStyle(Color.paDanger)
                            .accessibilityLabel("Remove field")
                            .padding(.bottom, 6)
                    }
                    Picker("Type", selection: Binding(get: { n < item.fields.count ? item.fields[n].type : .text }, set: { t in
                        guard n < item.fields.count else { return }
                        item.fields[n].type = t
                        if t == .boolean { item.fields[n].value = "false" }
                    })) {
                        Text("Text").tag(FieldType.text)
                        Text("Hidden").tag(FieldType.hidden)
                        Text("Yes/No").tag(FieldType.boolean)
                    }
                    .pickerStyle(.segmented)
                    switch n < item.fields.count ? item.fields[n].type : .text {
                    case .boolean:
                        Toggle(item.fields[n].name.isEmpty ? "Value" : item.fields[n].name,
                               isOn: Binding(get: { n < item.fields.count && item.fields[n].value == "true" }, set: { v in if n < item.fields.count { item.fields[n].value = v ? "true" : "false" } }))
                    case .hidden:
                        SecretInput(label: "Field value", text: field(n, \.value, ""), content: nil)
                    case .text:
                        LabeledInput(label: "Field value", text: field(n, \.value, ""))
                    }
                }
                .padding(.vertical, 4)
            }
            Button { item.fields.append(Field()) } label: { Label("Add field", systemImage: "plus") }
        }
        .paRow()
    }

    private func cleaned() -> Item {
        var c = item
        c.name = c.name.trimmingCharacters(in: .whitespacesAndNewlines)
        c.folder = c.folder?.trimmingCharacters(in: .whitespacesAndNewlines)
        if c.folder?.isEmpty == true { c.folder = nil }
        if var l = c.login {
            l.urls = l.urls.compactMap { u in
                let t = u.url.trimmingCharacters(in: .whitespacesAndNewlines)
                return t.isEmpty ? nil : LoginUrl(url: t, match: u.match)
            }
            let t = l.totp?.trimmingCharacters(in: .whitespacesAndNewlines)
            l.totp = (t?.isEmpty ?? true) ? nil : OtpAuth.normalize(t!)
            c.login = l
        }
        return c
    }

    private func save() { save(overwrite: false) }

    private func save(overwrite: Bool) {
        guard !busy else { return }
        error = nil
        if item.name.trimmingCharacters(in: .whitespaces).isEmpty { error = "Give this item a name."; return }
        if entry == nil && vaultId.isEmpty {
            error = (model.repo.vault?.writable.isEmpty ?? true) ? "You don't have a vault you can write to." : "Choose a vault for this item."
            return
        }
        let clean = cleaned()
        busy = true
        Task {
            do {
                if let entry {
                    var base = entry
                    if overwrite {
                        // Write on top of the newer version from the server.
                        try await model.repo.sync()
                        guard let fresh = model.repo.vault?.get(entry.id) else { throw UserError("This item was deleted on another device.") }
                        base = fresh
                    }
                    try await model.repo.updateItem(base, clean)
                    model.notify("Changes saved.")
                    onSaved(entry.id)
                } else {
                    let id = try await model.repo.createItem(clean, vaultId: vaultId)
                    model.notify("Item saved.")
                    onSaved(id)
                }
                dismiss()
            } catch is ConflictError {
                conflict = true
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}
