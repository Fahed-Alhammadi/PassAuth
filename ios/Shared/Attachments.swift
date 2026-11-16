import Foundation
import PassAuthCore

/// Attachments (servers with the `attachments` feature): files encrypted on the device, each with
/// a random key of its own, and listed inside the encrypted item as
/// `attachments: [{id, name, size, key}]` (`size` is the file's own size). The server keeps the
/// ciphertext under the attachment's id and never sees a file's name, key or contents.
///
/// Adding one: a new key → `POST /items/{id}/attachments {id, size: encrypted size}` →
/// `PUT /attachments/{id}` with the encrypted file → save the item listing it (if that save fails
/// for good, `DELETE` the attachment). Removing one: save the item without it, then `DELETE`.
/// Entries are changed one by one, so fields a newer app adds to an entry are kept.
///
/// The rules are the web vault's `web/src/lib/attachments.ts` (pure, `AttachmentsTests`); the
/// transfers follow `transfer.ts` (`AttachmentTransfer`, tested with fakes).
public let attachmentsFeature = "attachments"

public struct Attachment: Identifiable, Equatable, Sendable {
    /// As written in the item: the file's encryption is bound to it exactly.
    public let id: String
    /// Cleaned (`AttachmentList.cleanFileName`).
    public let name: String
    /// The file's own size in bytes.
    public let size: Int64
    public let key: String

    public init(id: String, name: String, size: Int64, key: String) {
        self.id = id
        self.name = name
        self.size = size
        self.key = key
    }

    /// The raw entry written into the item.
    public var json: JSON { ["id": .string(id), "name": .string(name), "size": .int(size), "key": .string(key)] }
}

public enum AttachmentList {
    public static let mib: Int64 = 1024 * 1024
    /// Longest file name kept, in characters.
    static let nameMax = 255
    /// Longest name a downloaded file is saved under.
    static let saveMax = 200

    /// Attachment ids are UUIDs (the server refuses anything else).
    static func isUuid(_ s: String) -> Bool {
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.map(\.count) == [8, 4, 4, 4, 12] else { return false }
        return parts.allSatisfy { $0.allSatisfy { $0.isASCII && $0.isHexDigit } }
    }

    /// An entry's id, lowercased for comparing; nil when it isn't a UUID.
    static func entryId(_ v: JSON) -> String? {
        guard let id = v["id"]?.string, isUuid(id) else { return nil }
        return id.lowercased()
    }

    /// Whether two attachment ids name the same attachment (UUIDs, in any letter case).
    public static func sameId(_ a: String, _ b: String) -> Bool { a.lowercased() == b.lowercased() }

    /// Largest size taken from an item (1 PiB): more is shown as this.
    public static let maxSize: Int64 = 1 << 50

    /// The files an item lists. Entries without an id or key, and repeated ids, are left out; ids
    /// kept as written; names cleaned (another member of a shared vault may have chosen one to look
    /// like something else).
    public static func read(_ raw: [JSON]?) -> [Attachment] {
        var seen = Set<String>()
        var out: [Attachment] = []
        for v in raw ?? [] {
            guard let lower = entryId(v), !seen.contains(lower), let key = v["key"]?.string, !key.isEmpty, let id = v["id"]?.string else { continue }
            seen.insert(lower)
            let size: Int64
            switch v["size"] {
            // Any JSON number may be written here (1e300 from a crafted item): never trapped on,
            // and kept within 0…2^50 so sizes can be added up.
            case .int(let n)? where n >= 0: size = min(n, maxSize)
            case .double(let d)? where d >= 0: size = min(JSON.wholeInt64(d) ?? 0, maxSize)
            default: size = 0
            }
            out.append(Attachment(id: id, name: cleanFileName(v["name"]?.string ?? ""), size: size, key: key))
        }
        return out
    }

    public static func read(_ item: Item?) -> [Attachment] { read(item?.attachments) }

    /// `item` listing exactly `list`; an empty list removes the field.
    public static func set(_ item: Item, _ list: [JSON]) -> Item {
        var copy = item
        copy.attachments = list.isEmpty ? nil : list
        return copy
    }

    /// `item` with `added` at the end of its list.
    public static func add(_ item: Item, _ added: [Attachment]) -> Item { set(item, (item.attachments ?? []) + added.map(\.json)) }

    /// `item` without the attachment `id`.
    public static func remove(_ item: Item, _ id: String) -> Item {
        set(item, (item.attachments ?? []).filter { entryId($0) != id.lowercased() })
    }

    /// `item` (an edited draft) listing the files of `from` (the item as last synced): the editor
    /// never changes the list.
    public static func withAttachments(of from: Item?, _ item: Item) -> Item { set(item, from?.attachments ?? []) }

    /// Every entry of `first`, then those of `second` with other ids.
    public static func merge(_ first: [JSON]?, _ second: [JSON]?) -> [JSON] {
        var seen = Set<String>()
        var out: [JSON] = []
        for v in (first ?? []) + (second ?? []) {
            guard let id = entryId(v), !seen.contains(id) else { continue }
            seen.insert(id)
            out.append(v)
        }
        return out
    }

    /// An item for an export file: without its file list (and so without the files' keys).
    public static func strip(_ item: Item) -> Item {
        var copy = item
        copy.attachments = nil
        copy.extra["attachments"] = nil
        return copy
    }

    /// Whether any of `items` lists a file (the export page then says files aren't included).
    public static func any(_ items: [Item]) -> Bool { items.contains { !read($0).isEmpty } }

    // MARK: Sizes

    /// Whether a file of `plainSize` bytes is too large for the server: its limit applies to the
    /// encrypted size. nil `maxMb` (a server that doesn't say) never refuses.
    public static func tooLarge(_ plainSize: Int64, maxMb: Int?, encryptedSize: (Int64) -> Int64) -> Bool {
        guard let maxMb, maxMb > 0 else { return false }
        return encryptedSize(plainSize) > Int64(maxMb) * mib
    }

    /// Highest limit taken from a server (1 PiB in MB): keeps `maxMb * mib` from overflowing.
    static let maxLimitMb: Int64 = 1 << 30

    /// The server's attachment limit in MB from `/api/config` `limits`, or nil.
    public static func limitMb(_ limits: JSON?) -> Int? {
        switch limits?["max_attachment_mb"] {
        case .int(let n)? where n >= 1: Int(min(n, maxLimitMb))
        case .double(let d)? where d.isFinite && d >= 1: Int(min(d, Double(maxLimitMb)).rounded(.down))
        default: nil
        }
    }

    /// The core's encrypted size; 0 for a size it refuses.
    public static func encryptedSize(_ plain: Int64) -> Int64 {
        guard plain >= 0, let n = try? fileEncryptedSize(plainLength: UInt64(plain)) else { return 0 }
        return Int64(n)
    }

    /// "\"a.pdf\" is too large: files can be at most 10 MB on this server." for the files over the limit.
    public static func sizeProblem(_ names: [String], maxMb: Int?) -> String? {
        guard !names.isEmpty, let maxMb else { return nil }
        let list = names.map { "\"\(cleanFileName($0))\"" }.joined(separator: ", ")
        return "\(list) \(names.count == 1 ? "is" : "are") too large: files can be at most \(maxMb) MB on this server."
    }

    // MARK: Names

    /// What every shown or saved name goes through: no control or format characters, one space for
    /// any run of white space, and no dots or spaces at the end.
    static func tidy(_ name: String) -> String {
        var s = PlainText.trim(PlainText.foldSpaces(PlainText.stripInvisible(name)))
        while let l = s.unicodeScalars.last, l == "." || l.properties.isWhitespace { s.unicodeScalars.removeLast() }
        return s
    }

    /// `name` cut to `max` characters (code points), keeping a short extension at its end.
    static func shorten(_ name: String, _ max: Int) -> String {
        let chars = Array(name.unicodeScalars)
        if chars.count <= max { return name }
        var keep: [Unicode.Scalar] = []
        if let dot = chars.lastIndex(of: "."), dot > 0 {
            let ext = Array(chars[dot...])
            if ext.count > 1 && ext.count <= 16 { keep = ext }
        }
        var head = String.UnicodeScalarView()
        head.append(contentsOf: chars.prefix(max - keep.count))
        var h = String(head)
        while let l = h.unicodeScalars.last, l == "." || l.properties.isWhitespace { h.unicodeScalars.removeLast() }
        var tail = String.UnicodeScalarView()
        tail.append(contentsOf: keep)
        return h + String(tail)
    }

    /// The name kept and shown for a file: without folders, control or format characters, runs of
    /// white space or trailing dots and spaces, at most 255 characters; "Attachment" when empty.
    public static func cleanFileName(_ name: String) -> String {
        let stripped = PlainText.stripInvisible(name)
        let base = stripped.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? ""
        let out = shorten(tidy(base), nameMax)
        return out.isEmpty ? "Attachment" : out
    }

    /// The name a downloaded file is saved under: cleaned as above, "_" for `\/:*?"<>|`, no
    /// leading dots, not a Windows device name, at most 200 characters with its extension.
    public static func downloadName(_ name: String) -> String {
        var s = String(tidy(name).map { "\\/:*?\"<>|".contains($0) ? "_" : $0 })
        while let f = s.unicodeScalars.first, f == "." || f.properties.isWhitespace { s.unicodeScalars.removeFirst() }
        let clean = shorten(tidy(s), saveMax)
        if clean.isEmpty { return "attachment" }
        return isDeviceName(clean) ? "_\(clean)" : clean
    }

    /// Names Windows keeps for devices, also with any extension.
    static func isDeviceName(_ s: String) -> Bool {
        let lower = s.lowercased()
        var stem: Substring?
        for prefix in ["con", "prn", "aux", "nul"] where lower.hasPrefix(prefix) {
            stem = lower.dropFirst(3)
        }
        if stem == nil, lower.hasPrefix("com") || lower.hasPrefix("lpt"), let d = lower.dropFirst(3).first, "0123456789¹²³".contains(d) {
            stem = lower.dropFirst(4)
        }
        guard var rest = stem else { return false }
        while let f = rest.first, f.isWhitespace { rest = rest.dropFirst() }
        return rest.isEmpty || rest.first == "."
    }

    // MARK: The server's list

    /// Uploads whose item doesn't list them may still be on their way for this long (seconds).
    public static let leftoverAfter: Int64 = 15 * 60

    /// The listed files the server doesn't have ready.
    public static func missingOnServer(_ list: [Attachment], _ stored: [StoredAttachment]) -> Set<String> {
        let ready = Set(stored.filter { $0.state == .ready }.map(\.id))
        return Set(list.filter { !ready.contains($0.id.lowercased()) }.map(\.id))
    }

    /// Finished uploads on the server that the item doesn't list and that nobody is still attaching.
    public static func leftovers(_ item: Item?, _ stored: [StoredAttachment], now: Int64) -> [StoredAttachment] {
        let listed = Set(read(item).map { $0.id.lowercased() })
        // Compared without subtracting the server's number (any Int64 would overflow `now - updatedAt`).
        return stored.filter { $0.state == .ready && !listed.contains($0.id) && $0.updatedAt <= now - leftoverAfter }
    }
}

/// An attachment as the server lists it (`GET /items/{id}/attachments`): never its name or key.
public struct StoredAttachment: Equatable, Sendable {
    public enum State: String, Sendable { case pending, ready }
    /// Lowercased.
    public let id: String
    /// Bytes of the encrypted file.
    public let size: Int64
    public let state: State
    public let updatedAt: Int64

    public init(id: String, size: Int64, state: State, updatedAt: Int64) {
        self.id = id
        self.size = size
        self.state = state
        self.updatedAt = updatedAt
    }

    /// The server's list for an item; malformed entries left out.
    public static func list(_ j: JSON?) -> [StoredAttachment] {
        (j?["attachments"]?.array ?? []).compactMap { v in
            guard let id = AttachmentList.entryId(v), let s = v["state"]?.string, let state = State(rawValue: s) else { return nil }
            // Sizes kept within 0…2^50 so the page can add them up.
            let size = min(max(VaultRepository.number(v["size"]) ?? 0, 0), 1 << 50)
            return StoredAttachment(id: id, size: size, state: state, updatedAt: VaultRepository.number(v["updated_at"]) ?? 0)
        }
    }
}

// MARK: Transfers

/// The core's streaming encryptor or decryptor (`push` any size, `finish` once).
public protocol FileCipher: AnyObject {
    func push(chunk: Data) throws -> Data
    func finish() throws -> Data
}

extension FileEncryptor: FileCipher {}
extension FileDecryptor: FileCipher {}

public enum TransferError: Error, Equatable, LocalizedError {
    case cancelled
    /// The file is gone from the server (deleted, or never finished uploading).
    case missing
    /// The picked file couldn't be read (moved, deleted or changed since it was picked).
    case unreadable
    /// A download that failed with an HTTP status other than 404.
    case failed(Int)

    public var errorDescription: String? {
        switch self {
        case .cancelled: "Cancelled."
        case .missing: "This file is no longer on the server."
        case .unreadable: "The file couldn't be read. It may have been moved or changed since you picked it. Pick it again."
        case .failed(let s): "The download failed (\(s)). Try again."
        }
    }
}

/// The server's side of a transfer (requests only; `ApiClient` in the app, fakes in tests).
public protocol AttachmentTransport: Sendable {
    /// `POST /items/{itemId}/attachments {id, size}`.
    func register(itemId: String, attachmentId: String, size: Int64) async throws
    /// `PUT /attachments/{id}` with the ciphertext in `file` (`size` bytes).
    func put(attachmentId: String, file: URL, size: Int64, progress: @escaping @Sendable (Double) -> Void) async throws
    /// `DELETE /attachments/{id}`; failures are ignored by the caller.
    func discard(attachmentId: String) async throws
    /// `GET` the encrypted file at `path` (below `/api`) into a temporary file: the file, or the
    /// HTTP status when there is none (404: gone).
    func get(path: String) async throws -> Result<URL, TransferError>
}

public enum TransferPhase: Sendable, Equatable { case encrypting, uploading, downloading, decrypting }

/// Encrypting, uploading, downloading and decrypting attachment files without holding a whole
/// file in memory: files are read and written 1 MiB at a time, in a private temporary folder whose
/// files are deleted as soon as they are no longer needed (`cleanUp` deletes what a crash left).
public struct AttachmentTransfer: Sendable {
    /// Plaintext read and encrypted per step (16 of the core's 64 KiB chunks).
    public static let chunk = 1024 * 1024

    public let transport: AttachmentTransport
    /// Where temporary files go (a folder of their own inside it is made per file).
    public let directory: URL
    public var newId: @Sendable () throws -> String = { try PassAuthCore.newId() }
    public var newKey: @Sendable () throws -> String = { try fileNewKey() }
    public var encryptedSize: @Sendable (Int64) -> Int64 = { AttachmentList.encryptedSize($0) }
    public var encryptor: @Sendable (String, String, String) throws -> FileCipher = { try FileEncryptor(key: $0, itemId: $1, attachmentId: $2) }
    public var decryptor: @Sendable (String, String, String) throws -> FileCipher = { try FileDecryptor(key: $0, itemId: $1, attachmentId: $2) }

    public init(transport: AttachmentTransport, directory: URL) {
        self.transport = transport
        self.directory = directory
    }

    /// The app's folder for transfer files: inside the temporary directory, excluded from backups.
    public static var defaultDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("attachments", isDirectory: true)
    }

    /// Delete every temporary transfer file (start-up, lock, sign-out).
    public static func cleanUp(_ directory: URL = defaultDirectory) {
        try? FileManager.default.removeItem(at: directory)
    }

    private func newFolder() throws -> URL {
        let d = directory.appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        return d
    }

    private static func create(_ url: URL) throws -> FileHandle {
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.protectionKey: FileProtectionType.complete]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        return try FileHandle(forWritingTo: url)
    }

    /// Encrypt `source` (`size` bytes, read in pieces) for item `itemId` and upload it as a new
    /// attachment. Returns its id and key, to list in the item. On a failure or a cancel after the
    /// attachment was registered, it is deleted again (best effort) before this throws.
    public func upload(_ source: URL, size: Int64, itemId: String, progress: @escaping @Sendable (TransferPhase, Double) -> Void = { _, _ in }) async throws -> (id: String, key: String) {
        try Task.checkCancellation()
        let id = try newId()
        let encSize = encryptedSize(size)
        try await transport.register(itemId: itemId, attachmentId: id, size: encSize)
        do {
            try Task.checkCancellation()
            let key = try newKey()
            let folder = try newFolder()
            defer { try? FileManager.default.removeItem(at: folder) }
            let encrypted = folder.appendingPathComponent("upload")
            try encrypt(source, size: size, to: encrypted, cipher: try encryptor(key, itemId, id)) { progress(.encrypting, $0) }
            try Task.checkCancellation()
            progress(.uploading, 0)
            try await transport.put(attachmentId: id, file: encrypted, size: encSize) { progress(.uploading, $0) }
            return (id, key)
        } catch {
            try? await transport.discard(attachmentId: id)
            if Task.isCancelled || error is CancellationError { throw TransferError.cancelled }
            throw error
        }
    }

    /// `source` encrypted into `target`, piece by piece.
    func encrypt(_ source: URL, size: Int64, to target: URL, cipher: FileCipher, progress: (Double) -> Void) throws {
        guard let input = try? FileHandle(forReadingFrom: source) else { throw TransferError.unreadable }
        defer { try? input.close() }
        let output = try Self.create(target)
        defer { try? output.close() }
        var done: Int64 = 0
        progress(0)
        while true {
            try Task.checkCancellation()
            let piece: Data
            do {
                piece = try autoreleasepool { try input.read(upToCount: Self.chunk) ?? Data() }
            } catch {
                throw TransferError.unreadable
            }
            if piece.isEmpty { break }
            done += Int64(piece.count)
            // The file grew since it was picked: the registered size no longer fits.
            if done > size { throw TransferError.unreadable }
            let enc = try cipher.push(chunk: piece)
            if !enc.isEmpty { try output.write(contentsOf: enc) }
            progress(size > 0 ? Double(done) / Double(size) : 1)
        }
        if done != size { throw TransferError.unreadable }
        try output.write(contentsOf: try cipher.finish())
    }

    /// Download and decrypt attachment `att` of item `itemId` from `path` (the item's own, or an
    /// emergency access's) into a temporary file named `downloadName` of its name. Returns the file
    /// only after the core confirmed it whole and authentic (`finish()`); on any error everything
    /// written is deleted. The caller deletes the returned file's folder when done
    /// (`discardDownload`).
    public func download(_ att: Attachment, itemId: String, path: String, progress: @escaping @Sendable (TransferPhase, Double) -> Void = { _, _ in }) async throws -> URL {
        try Task.checkCancellation()
        progress(.downloading, 0)
        let encrypted: URL
        switch try await transport.get(path: path) {
        case .success(let url): encrypted = url
        case .failure(let e): throw e
        }
        defer { try? FileManager.default.removeItem(at: encrypted) }
        let folder = try newFolder()
        let target = folder.appendingPathComponent(AttachmentList.downloadName(att.name))
        do {
            try Task.checkCancellation()
            try decrypt(encrypted, to: target, cipher: try decryptor(att.key, itemId, att.id)) { progress(.decrypting, $0) }
            return target
        } catch {
            try? FileManager.default.removeItem(at: folder)
            if Task.isCancelled || error is CancellationError { throw TransferError.cancelled }
            throw error
        }
    }

    func decrypt(_ source: URL, to target: URL, cipher: FileCipher, progress: (Double) -> Void) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let total = (try? FileManager.default.attributesOfItem(atPath: source.path)[.size] as? Int64) ?? 0
        let output = try Self.create(target)
        defer { try? output.close() }
        var done: Int64 = 0
        while true {
            try Task.checkCancellation()
            let piece = try autoreleasepool { try input.read(upToCount: Self.chunk) ?? Data() }
            if piece.isEmpty { break }
            done += Int64(piece.count)
            let plain = try cipher.push(chunk: piece)
            if !plain.isEmpty { try output.write(contentsOf: plain) }
            progress(total > 0 ? Double(done) / Double(total) : 1)
        }
        try output.write(contentsOf: try cipher.finish())
    }

    /// Delete a file `download` returned (its folder with it).
    public static func discardDownload(_ file: URL) {
        try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
    }
}

/// What went wrong with a file, in plain words.
public func fileErrorMessage(_ e: Error) -> String {
    if let t = e as? TransferError { return t.errorDescription ?? "Something went wrong." }
    if case CoreError.DecryptFailed? = e as? CoreError { return "This file couldn't be decrypted: it is damaged or incomplete. Try again." }
    if let a = e as? ApiError {
        if a.hasCode("too_large") { return "\(apiErrorText(a)) Pick a smaller file." }
        if a.status == 429 && a.retryAfter == nil { return "Too many uploads at once. Wait a minute, then try again." }
    }
    return errorMessage(e)
}

// MARK: Requests

/// `AttachmentTransfer`'s requests through the account's `ApiClient` (bearer token, one session
/// renewal after a 401, the app's error wording).
public struct ApiAttachmentTransport: AttachmentTransport {
    let api: ApiClient
    let accountId: String
    let directory: URL

    public init(api: ApiClient, accountId: String, directory: URL = AttachmentTransfer.defaultDirectory) {
        self.api = api
        self.accountId = accountId
        self.directory = directory
    }

    public func register(itemId: String, attachmentId: String, size: Int64) async throws {
        _ = try await api.call(accountId, "/items/\(VaultRepository.pathPart(itemId))/attachments", body: ["id": .string(attachmentId), "size": .int(size)])
    }

    public func put(attachmentId: String, file: URL, size: Int64, progress: @escaping @Sendable (Double) -> Void) async throws {
        try await api.uploadFile(accountId, "/attachments/\(VaultRepository.pathPart(attachmentId))", file: file, progress: progress)
    }

    public func discard(attachmentId: String) async throws {
        _ = try await api.call(accountId, "/attachments/\(VaultRepository.pathPart(attachmentId))", method: "DELETE")
    }

    public func get(path: String) async throws -> Result<URL, TransferError> {
        let r = try await api.downloadFile(accountId, path, into: directory.appendingPathComponent("incoming", isDirectory: true))
        if let f = r.file { return .success(f) }
        return .failure(r.status == 404 ? .missing : .failed(r.status))
    }
}

extension VaultRepository {
    /// The item's own address for an attachment's file.
    public nonisolated static func attachmentPath(_ id: String) -> String { "/attachments/\(pathPart(id))" }

    /// The active account's server: whether it takes new files, and its size limit per file (MB).
    public func attachmentConfig() async -> (enabled: Bool, limitMb: Int?)? {
        guard let config = await fetchConfig(activeId) else { return nil }
        return (config.features.contains(attachmentsFeature), AttachmentList.limitMb(config.limits))
    }

    /// The active account's transfers.
    public func attachmentTransfer() -> AttachmentTransfer {
        AttachmentTransfer(transport: ApiAttachmentTransport(api: api, accountId: activeId), directory: AttachmentTransfer.defaultDirectory)
    }

    /// The files the server keeps for an item: which listed ones are missing, what was left over.
    public func storedAttachments(_ itemId: String) async throws -> [StoredAttachment] {
        StoredAttachment.list(try await api.call(activeId, "/items/\(Self.pathPart(itemId))/attachments"))
    }

    /// The item as last synced, or why it can't be changed.
    private func attachmentEntry(_ itemId: String) throws -> Entry {
        guard let v = vault else { throw UserError("The vault is locked. Unlock it and try again.") }
        guard let e = v.entries.first(where: { $0.id == itemId }) else {
            throw UserError("This item is no longer in your vault. It may have been deleted on another device.")
        }
        return e
    }

    /// Encrypt and upload the file at `source` (`name` as picked, `size` bytes) and list it in item
    /// `itemId`. If the item can't be saved with it (after up to 3 tries from the item as last
    /// synced), the uploaded file is deleted again.
    public func attachFile(_ source: URL, name: String, size: Int64, to itemId: String,
                           progress: @escaping @Sendable (TransferPhase, Double) -> Void = { _, _ in }) async throws {
        _ = try attachmentEntry(itemId)
        let account = activeId
        let done = try await attachmentTransfer().upload(source, size: size, itemId: itemId, progress: progress)
        let att = Attachment(id: done.id, name: AttachmentList.cleanFileName(name), size: size, key: done.key)
        do {
            try await listInItem(itemId, att, account: account)
        } catch {
            // The item doesn't list the file, so nobody could open it: delete it again.
            try? await deleteStoredAttachment(att.id, account: account)
            throw error
        }
    }

    /// Worth trying the save again after a sync: not an answer that will stay the same.
    public nonisolated static func retryAttachmentSave(_ e: Error) -> Bool {
        if e is ConflictError { return true }
        guard let a = e as? ApiError else { return !(e is UserError) }
        return a.status == 409 || a.status == 429 || (a.status >= 500 && a.status != 507 && !a.hasCode("insufficient_storage"))
    }

    private func listInItem(_ itemId: String, _ att: Attachment, account: String) async throws {
        var attempt = 1
        while true {
            guard activeId == account else { throw UserError("The vault is locked. Unlock it and try again.") }
            let entry = try attachmentEntry(itemId)
            do {
                try await updateItem(entry, AttachmentList.add(entry.item, [att]))
                return
            } catch {
                if attempt >= 3 || !Self.retryAttachmentSave(error) || vault == nil { throw error }
                try await Task.sleep(for: .milliseconds(1500 * attempt))
                try? await sync()
                attempt += 1
            }
        }
    }

    /// Remove a file: the item is saved without it first, then the server deletes the file (a file
    /// already gone is fine).
    public func removeAttachment(_ attachmentId: String, from itemId: String) async throws {
        let entry = try attachmentEntry(itemId)
        try await updateItem(entry, AttachmentList.remove(entry.item, attachmentId))
        try? await deleteStoredAttachment(attachmentId, account: activeId)
    }

    /// Delete a file on the server (one no item lists any more). Already gone counts as done.
    public func deleteStoredAttachment(_ attachmentId: String) async throws {
        try await deleteStoredAttachment(attachmentId, account: activeId)
    }

    private func deleteStoredAttachment(_ attachmentId: String, account: String) async throws {
        do {
            _ = try await api.call(account, Self.attachmentPath(attachmentId), method: "DELETE")
        } catch let e as ApiError where e.status == 404 {}
    }

    /// Download and decrypt a file into a temporary file (delete it with
    /// `AttachmentTransfer.discardDownload` once shared). `path`: the item's own address
    /// (`attachmentPath`), or an emergency access's.
    public func downloadAttachment(_ att: Attachment, itemId: String, path: String? = nil,
                                   progress: @escaping @Sendable (TransferPhase, Double) -> Void = { _, _ in }) async throws -> URL {
        try await attachmentTransfer().download(att, itemId: itemId, path: path ?? Self.attachmentPath(att.id), progress: progress)
    }
}
