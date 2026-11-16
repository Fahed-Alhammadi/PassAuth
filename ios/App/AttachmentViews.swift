import PassAuthKit
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

// Attachments on the item page (servers with the `attachments` feature): the item's files with
// download (into a temporary file handed to the system share sheet, deleted when it closes) and
// remove, files added from Files or Photos (encrypted 1 MiB at a time into a temporary file and
// uploaded from it, one upload at a time), files the server no longer has marked, and finished
// uploads no item lists offered for deleting. Rules and transfers in `Shared/Attachments.swift`.

private func sizeText(_ n: Int64) -> String { ByteCountFormatter.string(fromByteCount: n, countStyle: .file) }

/// Uploads of every item, one at a time, kept while the user moves around the app. Locking or
/// signing out stops them (their files are deleted on the server again).
@MainActor
@Observable
final class AttachmentUploads {
    enum Phase: Equatable { case queued, encrypting, uploading, saving, failed(String) }

    /// Where an upload reads its file: a picked document (security-scoped, read in place), or a
    /// copy this app made (a photo or video), deleted afterwards.
    enum Source {
        case scoped(URL)
        case owned(URL)
    }

    struct Upload: Identifiable {
        let id = UUID()
        let itemId: String
        let name: String
        let size: Int64
        var phase: Phase = .queued
        var fraction: Double = 0
    }

    private(set) var items: [Upload] = []
    @ObservationIgnored private var tasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var queue: Task<Void, Never>?

    func uploads(for itemId: String) -> [Upload] { items.filter { $0.itemId == itemId } }

    func add(repo: VaultRepository, itemId: String, source: Source, name: String, size: Int64, notify: @escaping (String) -> Void) {
        let up = Upload(itemId: itemId, name: AttachmentList.cleanFileName(name), size: size)
        items.append(up)
        let previous = queue
        let task = Task { @MainActor [weak self] in
            await previous?.value
            await self?.run(up, repo: repo, source: source, notify: notify)
        }
        tasks[up.id] = task
        queue = task
    }

    private func update(_ id: UUID, _ change: (inout Upload) -> Void) {
        if let i = items.firstIndex(where: { $0.id == id }) { change(&items[i]) }
    }

    private func run(_ up: Upload, repo: VaultRepository, source: Source, notify: (String) -> Void) async {
        defer {
            tasks[up.id] = nil
            if case .owned(let url) = source { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        }
        guard !Task.isCancelled, items.contains(where: { $0.id == up.id }) else {
            items.removeAll { $0.id == up.id }
            return
        }
        let url: URL
        var scoped = false
        switch source {
        case .scoped(let u):
            url = u
            scoped = u.startAccessingSecurityScopedResource()
        case .owned(let u):
            url = u
        }
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        update(up.id) { $0.phase = .encrypting }
        let id = up.id
        do {
            try await repo.attachFile(url, name: up.name, size: up.size, to: up.itemId) { [weak self] phase, fraction in
                Task { @MainActor in self?.report(id, phase, fraction) }
            }
            items.removeAll { $0.id == up.id }
            notify("\u{201C}\(up.name)\u{201D} attached.")
        } catch TransferError.cancelled {
            items.removeAll { $0.id == up.id }
        } catch is CancellationError {
            items.removeAll { $0.id == up.id }
        } catch {
            update(up.id) { $0.phase = .failed(fileErrorMessage(error)) }
        }
    }

    @ObservationIgnored private var lastReport: [UUID: Date] = [:]

    /// Progress, at most ten updates a second, and every change of step.
    private func report(_ id: UUID, _ phase: TransferPhase, _ fraction: Double) {
        guard let cur = items.first(where: { $0.id == id }) else { return }
        let next: Phase = phase == .encrypting ? .encrypting : (fraction >= 1 ? .saving : .uploading)
        let now = Date()
        if cur.phase == next && now.timeIntervalSince(lastReport[id] ?? .distantPast) < 0.1 && fraction < 1 { return }
        if case .failed = cur.phase { return }
        lastReport[id] = now
        update(id) {
            $0.phase = next
            $0.fraction = fraction
        }
    }

    /// Stop an upload (its attachment is deleted on the server), or forget a failed one.
    func cancel(_ id: UUID) {
        guard let up = items.first(where: { $0.id == id }) else { return }
        if up.phase == .saving { return }
        tasks[id]?.cancel()
        if case .failed = up.phase { items.removeAll { $0.id == id } }
        if up.phase == .queued { items.removeAll { $0.id == id } }
    }

    /// Locked or signed out: nothing can be saved into an item any more.
    func cancelAll() {
        for (id, t) in tasks where items.first(where: { $0.id == id })?.phase != .saving { t.cancel() }
        items.removeAll { $0.phase != .saving }
    }
}

/// Downloads in progress (item pages and emergency access), tied to the open vault: closing it
/// (`cancelAll`, on lock or sign-out) stops them, and a file decrypted after the vault closed or
/// another account became active is deleted instead of shown.
@MainActor
final class AttachmentDownloads {
    private var tasks: [UUID: Task<Void, Never>] = [:]
    /// Raised each time the vault closes.
    private(set) var generation = 0

    /// Run `fetch` (a download into a temporary file), then hand the file to the share sheet,
    /// which deletes it when it closes. `done` gets an error message, or nil (shared, or stopped
    /// because the vault closed).
    func run(repo: VaultRepository, _ fetch: @escaping @MainActor () async throws -> URL, done: @escaping @MainActor (String?) -> Void) {
        let id = UUID()
        let started = generation
        let account = repo.state.activeId
        let task = Task { @MainActor [weak self] in
            defer { self?.tasks[id] = nil }
            do {
                let url = try await fetch()
                guard let self, Self.stillOpen(started: started, now: self.generation, account: account, active: repo.state.activeId,
                                               unlocked: repo.vault != nil, cancelled: Task.isCancelled) else {
                    AttachmentTransfer.discardDownload(url)
                    done(nil)
                    return
                }
                ShareSheet.present(items: [url]) { AttachmentTransfer.discardDownload(url) }
                done(nil)
            } catch TransferError.cancelled {
                done(nil)
            } catch is CancellationError {
                done(nil)
            } catch {
                done(Task.isCancelled ? nil : fileErrorMessage(error))
            }
        }
        tasks[id] = task
    }

    /// Whether a finished download may be shown: same vault session and account, still unlocked.
    nonisolated static func stillOpen(started: Int, now: Int, account: String, active: String, unlocked: Bool, cancelled: Bool) -> Bool {
        !cancelled && started == now && account == active && unlocked
    }

    /// The vault closed: stop every download.
    func cancelAll() {
        generation += 1
        for t in tasks.values { t.cancel() }
        tasks = [:]
    }
}

/// A file picked in Photos, copied by the system into a temporary file this app then owns.
struct PickedMedia: Transferable {
    let url: URL

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(importedContentType: .item) { received in
            let dir = AttachmentTransfer.defaultDirectory.appendingPathComponent("picked-\(UUID().uuidString.lowercased())", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
            let target = dir.appendingPathComponent(received.file.lastPathComponent.isEmpty ? "photo" : received.file.lastPathComponent)
            try FileManager.default.copyItem(at: received.file, to: target)
            return PickedMedia(url: target)
        }
    }
}

/// The item page's "Attachments" section.
struct AttachmentsSection: View {
    @Environment(AppModel.self) private var model
    let entry: Entry
    let canWrite: Bool
    @State private var config: (enabled: Bool, limitMb: Int?)?
    @State private var stored: [StoredAttachment]?
    @State private var error: String?
    @State private var importing = false
    @State private var photo: PhotosPickerItem?
    @State private var pickingPhotos = false
    @State private var removing: Attachment?
    @State private var downloading: String?
    @State private var cleaning = false
    /// Finished uploads no item lists, worked out after a sync (`load`).
    @State private var unlisted: [StoredAttachment] = []

    var body: some View {
        let files = AttachmentList.read(entry.item)
        let uploads = model.uploads.uploads(for: entry.id)
        let feature = config?.enabled ?? model.repo.cachedFeatures.contains(attachmentsFeature)
        let canAttach = feature && canWrite
        let missing = stored.map { AttachmentList.missingOnServer(files, $0) } ?? []
        let extra = unlisted
        if feature || !files.isEmpty || !uploads.isEmpty {
            Section {
                ForEach(files) { f in
                    FileRow(file: f, missing: missing.contains(f.id), busy: downloading == f.id,
                            download: { download(f) }, remove: canWrite ? { removing = f } : nil)
                        .confirmationDialog("Remove this file?", isPresented: Binding(get: { removing?.id == f.id }, set: { if !$0 { removing = nil } }),
                                            titleVisibility: .visible) {
                            Button("Remove file", role: .destructive) { remove(f) }
                            Button("Cancel", role: .cancel) {}
                        } message: {
                            Text("“\(f.name)” is deleted from the server, for everyone who can open this item. Earlier versions of the item that list it can't bring it back.")
                        }
                }
                ForEach(uploads) { UploadRow(upload: $0) { id in model.uploads.cancel(id) } }
                if canAttach {
                    Button { importing = true } label: { Label("Attach a file", systemImage: "paperclip") }
                        .accessibilityIdentifier("attachments.add")
                        .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                            switch result {
                            case .success(let urls): add(urls.map { ($0, true) })
                            case .failure(let e): error = fileErrorMessage(e)
                            }
                        }
                    Button { pickingPhotos = true } label: { Label("Attach a photo or video", systemImage: "photo.on.rectangle") }
                        .accessibilityIdentifier("attachments.addPhoto")
                        .photosPicker(isPresented: $pickingPhotos, selection: $photo, matching: .any(of: [.images, .videos]), photoLibrary: .shared())
                        .onChange(of: photo) { _, picked in
                            guard let picked else { return }
                            photo = nil
                            Task { await addPhotos([picked]) }
                        }
                }
                if !extra.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Notice(text: "\(extra.count == 1 ? "An upload" : "\(extra.count) uploads") to this item didn't finish, and \(extra.count == 1 ? "its file is" : "their files are") still using \(sizeText(extra.reduce(0) { $0 + $1.size })) of storage.")
                        Button(cleaning ? "Deleting…" : (extra.count == 1 ? "Delete it" : "Delete them")) { clean(extra) }
                            .disabled(cleaning)
                    }
                    .padding(.vertical, 4)
                }
                ErrorText(text: error)
            } header: {
                Text(files.isEmpty ? "Attachments" : "Attachments (\(files.count))")
            } footer: {
                if canAttach && files.isEmpty && uploads.isEmpty {
                    Text("Add scans, documents or keys. Each file is encrypted on this device before it's uploaded\(config?.limitMb.map { ", up to \($0) MB each" } ?? "").")
                }
            }
            .paRow()
            .task(id: "\(entry.id)-\(entry.revision)-\(files.map(\.id).joined(separator: ","))") { await load(files: files) }
        }
    }

    private func load(files: [Attachment]) async {
        if config == nil { config = await model.repo.attachmentConfig() }
        guard (config?.enabled ?? false) || !files.isEmpty else { return }
        if files.isEmpty && !canWrite { return }
        var list = try? await model.repo.storedAttachments(entry.id)
        // A file that looks unlisted may be in an edit this device hasn't synced yet: sync, then
        // look again before offering to delete it.
        if let l = list, !leftovers(l).isEmpty {
            try? await model.repo.sync()
            list = try? await model.repo.storedAttachments(entry.id)
        }
        stored = list
        unlisted = list.map(leftovers) ?? []
    }

    /// The item as the last sync has it (the page's copy may be older).
    private var currentItem: Item? { model.repo.vault?.entries.first { $0.id == entry.id }?.item ?? entry.item }

    private func leftovers(_ stored: [StoredAttachment]) -> [StoredAttachment] {
        canWrite ? AttachmentList.leftovers(currentItem, stored, now: Int64(Date().timeIntervalSince1970)) : []
    }

    /// Picked files (`scoped`: a document read in place) after the size check.
    private func add(_ picked: [(URL, Bool)]) {
        error = nil
        var tooBig: [String] = []
        for (url, scoped) in picked {
            let access = scoped && url.startAccessingSecurityScopedResource()
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init)
            if access { url.stopAccessingSecurityScopedResource() }
            guard let size else {
                error = TransferError.unreadable.errorDescription
                continue
            }
            if AttachmentList.tooLarge(size, maxMb: config?.limitMb, encryptedSize: AttachmentList.encryptedSize) {
                tooBig.append(url.lastPathComponent)
                if !scoped { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
                continue
            }
            model.uploads.add(repo: model.repo, itemId: entry.id, source: scoped ? .scoped(url) : .owned(url), name: url.lastPathComponent, size: size) { model.notify($0) }
        }
        if let p = AttachmentList.sizeProblem(tooBig, maxMb: config?.limitMb) { error = p }
    }

    private func addPhotos(_ picked: [PhotosPickerItem]) async {
        var urls: [(URL, Bool)] = []
        for p in picked {
            do {
                if let media = try await p.loadTransferable(type: PickedMedia.self) { urls.append((media.url, false)) }
            } catch {
                self.error = "A photo or video couldn't be read. Try again."
            }
        }
        add(urls)
    }

    private func download(_ f: Attachment) {
        guard downloading == nil else { return }
        downloading = f.id
        error = nil
        let itemId = entry.id
        let repo = model.repo
        model.downloads.run(repo: repo, { try await repo.downloadAttachment(f, itemId: itemId) }) { problem in
            downloading = nil
            if let problem { error = problem }
        }
    }

    private func remove(_ f: Attachment) {
        Task {
            do {
                try await model.repo.removeAttachment(f.id, from: entry.id)
                model.notify("File removed.")
            } catch {
                self.error = fileErrorMessage(error)
            }
        }
    }

    private func clean(_ extra: [StoredAttachment]) {
        cleaning = true
        Task {
            defer { cleaning = false }
            do {
                // Synced and listed again first: only files still unlisted after that are deleted
                // (another device may have saved an item listing one meanwhile).
                try? await model.repo.sync()
                let offered = Set(extra.map(\.id))
                let still = leftovers(try await model.repo.storedAttachments(entry.id)).filter { offered.contains($0.id) }
                for s in still { try await model.repo.deleteStoredAttachment(s.id) }
                let now = try await model.repo.storedAttachments(entry.id)
                stored = now
                unlisted = leftovers(now)
                if !still.isEmpty { model.notify(still.count == 1 ? "Unfinished upload deleted." : "Unfinished uploads deleted.") }
            } catch {
                self.error = fileErrorMessage(error)
            }
        }
    }
}

/// One file: name, size (or that the server no longer has it), download and remove.
struct FileRow: View {
    let file: Attachment
    var missing = false
    var busy = false
    let download: () -> Void
    var remove: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "doc").foregroundStyle(Color.paAccent).frame(width: 28).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(file.name).foregroundStyle(Color.paInk).lineLimit(2).truncationMode(.middle)
                Text(missing ? "This file is no longer on the server" : sizeText(file.size))
                    .font(.footnote).foregroundStyle(missing ? Color.paDanger : Color.paMuted)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            if busy {
                ProgressView().accessibilityLabel("Downloading \(file.name)")
            } else if !missing {
                Button(action: download) { Image(systemName: "square.and.arrow.down") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Download \(file.name)")
                    .accessibilityIdentifier("attachments.download")
            }
            if let remove {
                Button(action: remove) { Image(systemName: "trash") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Color.paDanger)
                    .accessibilityLabel("Remove \(file.name)")
                    .accessibilityIdentifier("attachments.remove")
            }
        }
        .padding(.vertical, 2)
    }
}

private struct UploadRow: View {
    let upload: AttachmentUploads.Upload
    let cancel: (UUID) -> Void

    private var status: String {
        switch upload.phase {
        case .queued: "Waiting…"
        case .encrypting: "Encrypting… \(Int(upload.fraction * 100))%"
        case .uploading: "Uploading… \(Int(upload.fraction * 100))%"
        case .saving: "Saving…"
        case .failed(let m): m
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.up.doc").foregroundStyle(Color.paAccent).frame(width: 28).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(upload.name).foregroundStyle(Color.paInk).lineLimit(1).truncationMode(.middle)
                if case .failed = upload.phase {} else if upload.phase != .queued {
                    ProgressView(value: upload.fraction).accessibilityHidden(true)
                }
                Text(status).font(.footnote).foregroundStyle({ if case .failed = upload.phase { return Color.paDanger } else { return Color.paMuted } }())
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            if upload.phase != .saving {
                Button { cancel(upload.id) } label: { Image(systemName: "xmark.circle") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel({ if case .failed = upload.phase { return "Dismiss" } else { return "Cancel upload of \(upload.name)" } }())
            }
        }
        .padding(.vertical, 2)
    }
}
