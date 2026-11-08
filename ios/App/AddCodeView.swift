import PassAuthKit
import SwiftUI

/// An authenticator key opened from an otpauth link, shown as a sheet once the vault is unlocked.
struct PendingOtp: Identifiable {
    let id = UUID()
    let key: OtpKey
}

/// Adds an opened authenticator key to a login: an existing one (best name match first) or a new one.
struct AddCodeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let key: OtpKey
    @State private var query = ""
    @State private var target: EditTarget?

    var body: some View {
        switch target {
        case .new:
            EditView(entry: nil, kind: .login, otp: key) { _ in model.notify("Verification code saved.") }
        case .edit(let id):
            if let e = model.repo.vault?.get(id) {
                EditView(entry: e, kind: e.item.kind, otp: key) { _ in model.notify("Verification code saved.") }
            }
        case nil:
            picker
        }
    }

    private var logins: [ItemSummary] {
        guard let v = model.repo.vault else { return [] }
        let issuer = key.issuer.lowercased()
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        func related(_ s: ItemSummary) -> Bool {
            !issuer.isEmpty && (s.name.lowercased().contains(issuer) || s.host.lowercased().contains(issuer))
        }
        return v.entries
            .filter { $0.deletedAt == nil && $0.item.login != nil && v.canWrite($0) }
            .map(ItemSummary.init)
            .filter { s in
                q.isEmpty || s.name.lowercased().contains(q) || s.subtitle.lowercased().contains(q) || s.host.lowercased().contains(q)
            }
            .sorted { a, b in
                let ra = related(a), rb = related(b)
                if ra != rb { return ra }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    private var picker: some View {
        NavigationStack {
            List {
                Section {
                    Text(key.label.isEmpty ? "Choose the login this verification code belongs to." : "Choose the login for \(key.label).")
                        .font(.subheadline).foregroundStyle(Color.paMuted)
                    Button { target = .new(.login) } label: {
                        Label("New login", systemImage: "plus.circle")
                    }
                    .accessibilityIdentifier("addcode.new")
                }
                .paRow()
                Section("Add to a login") {
                    let items = logins
                    if items.isEmpty {
                        Text("No logins found.").foregroundStyle(Color.paMuted)
                    }
                    ForEach(items) { s in
                        Button { target = .edit(s.id) } label: { ItemRow(summary: s) }
                    }
                }
                .paRow()
            }
            .paList()
            .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search logins")
            .navigationTitle("Add verification code")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
    }
}
