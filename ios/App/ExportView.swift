import PassAuthKit
import SwiftUI
import UniformTypeIdentifiers

/// Settings → Vault options → Export: the core builds the file (same formats as the web
/// vault) and the user picks where it goes with the system file exporter. PassAuth never
/// writes the export anywhere itself.
struct ExportPage: View {
    @Environment(AppModel.self) private var model
    @State private var format = ExportFormat.encrypted
    @State private var exportPassword = ""
    @State private var confirm = ""
    @State private var master = ""
    @State private var busy = false
    @State private var error: String?
    /// The finished file, held in memory only between "Export" and the exporter's answer.
    @State private var file: ExportFile?
    @State private var exporting = false

    var body: some View {
        let count = model.repo.vault?.entries.count ?? 0
        Section {
            Text("Exports the \(count) item\(count == 1 ? "" : "s") in all vaults of \(model.state.email). You choose where the file is saved.")
                .foregroundStyle(Color.paInk)
            Picker("File format", selection: $format) {
                ForEach(ExportFormat.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.navigationLink)
            .accessibilityIdentifier("export.format")
        }
        .paRow()
        .onChange(of: format) { _, _ in error = nil }
        if format.isEncrypted {
            Section {
                SecretInput(label: "Export password", text: $exportPassword, mono: false, content: .newPassword, identifier: "export.password")
                SecretInput(label: "Confirm password", text: $confirm, mono: false, content: .newPassword, identifier: "export.confirm")
            } footer: {
                Text("The file is encrypted with an export password. You need that password to import it again; it isn't your master password. At least \(VaultExport.minPassword) characters.")
            }
            .paRow()
        } else {
            Section {
                Notice(text: "This file is not encrypted. Anyone who gets it can read every password in it. Keep it somewhere safe and delete it when you're done.", kind: .error)
                    .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                if format == .csv {
                    Notice(text: "CSV holds logins and secure notes only. Cards, identities and SSH keys are left out; choose JSON for a full export.")
                        .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                }
            }
            .paRow()
        }
        Section {
            SecretInput(label: "Master password", text: $master, mono: false, identifier: "export.master")
        } footer: {
            Text("Confirm it's you before your vault leaves PassAuth.")
        }
        .paRow()
        Section {
            ErrorText(text: error)
            Button(action: export) {
                HStack {
                    Label(busy ? "Exporting…" : "Export vault", systemImage: "square.and.arrow.up").fontWeight(.semibold)
                    if busy { Spacer(); ProgressView() }
                }
            }
            .disabled(busy)
            .accessibilityIdentifier("export.run")
        }
        .paRow()
        .fileExporter(isPresented: $exporting, document: file, contentType: file?.type ?? .json, defaultFilename: file?.name) { result in
            switch result {
            case .success:
                exportPassword = ""
                confirm = ""
                master = ""
                model.notify("Vault exported.")
            case .failure(let e):
                if (e as NSError).code == NSUserCancelledError { model.notify("Export cancelled.") } else { error = errorMessage(e) }
            }
            file = nil
            busy = false
            ExportFile.removeTemporaryCopies()
        }
        .onChange(of: exporting) { _, on in
            guard !on else { return }
            // Cancelling may not call the completion: forget the file once the exporter is gone.
            Task {
                try? await Task.sleep(for: .milliseconds(600))
                ExportFile.removeTemporaryCopies()
                if file != nil {
                    file = nil
                    busy = false
                    model.notify("Export cancelled.")
                }
            }
        }
    }

    private func export() {
        guard !busy else { return }
        error = nil
        let items: (json: String, count: Int)
        do { items = try model.repo.itemsJsonForExport() } catch { self.error = errorMessage(error); return }
        if items.count == 0 { error = "Your vault has no items to export."; return }
        if format.isEncrypted, let p = VaultExport.passwordProblem(exportPassword, confirm) { error = p; return }
        if master.isEmpty { error = "Enter your master password to export."; return }
        busy = true
        let f = format
        let pw = f.isEncrypted ? exportPassword : nil
        Task {
            do {
                try await model.repo.verifyMasterPassword(master)
                let text = try await Task.detached(priority: .userInitiated) { try VaultExport.build(f, itemsJson: items.json, password: pw) }.value
                file = ExportFile(text: text, type: f == .csv ? .commaSeparatedText : .json, name: VaultExport.fileName(f, date: Date()))
                exporting = true
            } catch {
                self.error = errorMessage(error)
                busy = false
            }
        }
    }
}

/// The export as a document for `fileExporter` (in memory only).
struct ExportFile: FileDocument {
    static let readableContentTypes: [UTType] = [.json, .commaSeparatedText]
    static let writableContentTypes: [UTType] = [.json, .commaSeparatedText]
    let text: String
    let type: UTType
    let name: String

    init(text: String, type: UTType, name: String) {
        self.text = text
        self.type = type
        self.name = name
    }

    /// The exporter stages the document in the app's temporary directory: never leave a copy
    /// there (after an export, a cancel, or at launch after a crash mid-export).
    static func removeTemporaryCopies() {
        let fm = FileManager.default
        guard let walk = fm.enumerator(at: fm.temporaryDirectory, includingPropertiesForKeys: nil) else { return }
        for case let url as URL in walk where url.lastPathComponent.hasPrefix("passauth-export-") {
            try? fm.removeItem(at: url)
        }
    }

    init(configuration: ReadConfiguration) throws {
        throw CocoaError(.featureUnsupported)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
