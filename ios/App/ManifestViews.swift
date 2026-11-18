import PassAuthKit
import SwiftUI

/// Vault manifests: the warning of each vault whose items aren't the ones its manifest records
/// (the server's copy is older, or items are missing or were put back), at the top of the vault
/// list. The vault stays readable; nothing is written into it until someone who can edit it
/// accepts the server's copy.
struct ManifestWarnings: View {
    @Environment(AppModel.self) private var model
    @State private var reviewing: VaultInfo?

    var body: some View {
        let vaults = model.repo.vault?.manifestWarnings ?? []
        if !vaults.isEmpty {
            Section {
                ForEach(vaults) { v in
                    VStack(alignment: .leading, spacing: PA.Space.s) {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "exclamationmark.triangle.fill")
                            VStack(alignment: .leading, spacing: 4) {
                                Text(v.name).fontWeight(.semibold)
                                Text(ManifestText.warning).fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                        .accessibilityElement(children: .combine)
                        if v.role == .read {
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
                model.notify("This vault now follows the server's copy.")
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }
}
