import PassAuthKit
import SwiftUI

/// Vault manifests: the warning of each vault whose items aren't the ones its manifest records
/// (the server's copy is older, or items are missing or were put back), at the top of the vault
/// list. The vault stays readable; nothing is written into it until the warning is cleared.
/// Every warning has a way out:
/// - the served manifest describes the served items (`manifestAcceptable`): everyone gets "Use
///   the server's copy", which only changes what this device remembers;
/// - it doesn't: members who can edit get the same button (it writes a new record over the
///   server's copy); readers are told who can;
/// - the only problem is an item that can't be opened (`unopenable`): the warning says so and
///   the item is listed below with "Delete for good" (`UnopenableItems`).
///
/// Above them, when this device's own record of the vaults can't be read: the notice with
/// "Reset on this device".
struct ManifestWarnings: View {
    @Environment(AppModel.self) private var model
    @State private var reviewing: VaultInfo?

    var body: some View {
        let vaults = model.repo.vault?.manifestWarnings ?? []
        if model.repo.memoryProblem { MemoryProblemNotice() }
        if !vaults.isEmpty {
            Section {
                ForEach(vaults) { v in
                    VStack(alignment: .leading, spacing: PA.Space.s) {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "exclamationmark.triangle.fill")
                            VStack(alignment: .leading, spacing: 4) {
                                Text(v.name).fontWeight(.semibold)
                                Text(v.unopenable ? (v.role == .read ? ManifestText.unopenableReader : ManifestText.unopenable) : ManifestText.warning)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                        .accessibilityElement(children: .combine)
                        if v.unopenable {
                            // Deleting the item is the way out (listed below for those who can).
                        } else if v.role == .read && !v.manifestAcceptable {
                            Text(ManifestText.reader).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                        } else {
                            Button(ManifestText.action) { reviewing = v }
                                .buttonStyle(.borderless)
                                .fontWeight(.semibold)
                                .frame(minHeight: 44, alignment: .leading)
                                .accessibilityIdentifier("vault.manifestAction.\(v.id)")
                        }
                    }
                    .font(.subheadline)
                    .foregroundStyle(Color.paDanger)
                    .padding(PA.Space.m)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.paDanger.opacity(0.12), in: RoundedRectangle(cornerRadius: PA.Radius.control, style: .continuous))
                    .accessibilityIdentifier("vault.manifestWarning.\(v.id)")
                }
            }
            .listRowInsets(EdgeInsets()).listRowBackground(Color.clear).listRowSeparator(.hidden)
            .sheet(item: $reviewing) { v in ServerCopySheet(vault: v) }
        }
    }
}

/// "Use the server's copy?": the confirmation before this vault is accepted as the server has it.
private struct ServerCopySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let vault: VaultInfo
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            PromptScaffold(error: error) {
                Section {
                    PromptHeader(symbol: "exclamationmark.triangle", title: ManifestText.confirmTitle, subtitle: vault.name)
                        .promptPlainRow()
                }
                Section {
                    Text(ManifestText.confirmBody).foregroundStyle(Color.paInk)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .paRow()
            } actions: {
                PrimaryButton(title: ManifestText.action, busy: busy, destructive: true, action: confirm)
                    .accessibilityIdentifier("manifest.confirm")
            }
            .navigationTitle(vault.name)
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
                try await model.repo.useServerCopy(vault.id)
                model.notify(ManifestText.accepted)
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}

/// This device's record of the account's vaults can't be read: said once, with the reset.
private struct MemoryProblemNotice: View {
    @Environment(AppModel.self) private var model
    @State private var asking = false
    @State private var busy = false

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: PA.Space.s) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "exclamationmark.triangle.fill")
                    Text(ManifestText.memoryUnreadable).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .accessibilityElement(children: .combine)
                Button(ManifestText.memoryReset) { asking = true }
                    .buttonStyle(.borderless)
                    .fontWeight(.semibold)
                    .frame(minHeight: 44, alignment: .leading)
                    .disabled(busy)
                    .accessibilityIdentifier("vault.memoryReset")
            }
            .font(.subheadline)
            .foregroundStyle(Color.paDanger)
            .padding(PA.Space.m)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.paDanger.opacity(0.12), in: RoundedRectangle(cornerRadius: PA.Radius.control, style: .continuous))
            .accessibilityIdentifier("vault.memoryProblem")
            .confirmationDialog(ManifestText.memoryReset + "?", isPresented: $asking, titleVisibility: .visible) {
                Button(ManifestText.memoryReset, role: .destructive) { reset() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(ManifestText.memoryResetConfirm)
            }
        }
        .listRowInsets(EdgeInsets()).listRowBackground(Color.clear).listRowSeparator(.hidden)
    }

    private func reset() {
        guard !busy else { return }
        busy = true
        Task {
            do {
                try await model.repo.resetDeviceMemory()
            } catch {
                model.notify(errorMessage(error))
            }
            busy = false
        }
    }
}

/// Items the server sent that this device can't open (`VaultData.unopenable`), in the vault list
/// (`trashed` false) or the trash: nothing of them can be shown, so each is one row, "Item that
/// can't be opened", with its vault's name. Members who can edit the vault get "Delete for
/// good"; a vault that holds such an item is warned about until it is gone.
struct UnopenableItems: View {
    @Environment(AppModel.self) private var model
    let trashed: Bool
    @State private var deleting: UnopenableItem?
    @State private var busy = false

    var body: some View {
        let v = model.repo.vault
        let items = (v?.unopenable ?? []).filter { ($0.deletedAt != nil) == trashed }
        if !items.isEmpty {
            Section {
                ForEach(items) { item in
                    let writable = v?.vaults.first { $0.id == item.vaultId }.map { $0.role != .read } ?? false
                    HStack(spacing: 12) {
                        Image(systemName: "questionmark.square.dashed").foregroundStyle(Color.paMuted)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ManifestText.unopenableItem)
                            Text(v?.vaultName(item.vaultId) ?? "Vault").font(.footnote).foregroundStyle(Color.paMuted)
                        }
                        Spacer(minLength: 0)
                        if writable {
                            Button(ManifestText.deleteForGood, role: .destructive) { deleting = item }
                                .buttonStyle(.borderless)
                                .disabled(busy)
                                .accessibilityIdentifier("vault.unopenable.delete.\(item.id)")
                        }
                    }
                    .frame(minHeight: 44)
                    .accessibilityIdentifier("vault.unopenable.\(item.id)")
                }
            }
            .confirmationDialog(ManifestText.deleteForGood + "?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                                titleVisibility: .visible, presenting: deleting) { item in
                Button(ManifestText.deleteForGood, role: .destructive) { delete(item) }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text(ManifestText.deleteConfirm)
            }
        }
    }

    private func delete(_ item: UnopenableItem) {
        guard !busy else { return }
        busy = true
        Task {
            do {
                try await model.repo.deleteUnopenable(item)
                model.notify("Deleted.")
            } catch {
                model.notify(errorMessage(error))
            }
            busy = false
        }
    }
}
