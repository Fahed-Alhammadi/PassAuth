import CryptoKit
import Foundation
import Observation

/// On-device state of the app.
///
/// - Accounts, settings and the device id: `state.bin` in the App Group container,
///   encrypted with a random ChaCha20-Poly1305 key from the Keychain, file protection
///   complete, excluded from backups.
/// - Tokens, Secret Keys, two-step remember tokens and (vault timeout "never") unlocked
///   keys: one Keychain item (`WhenUnlockedThisDeviceOnly`).
/// - The last `/sync` response of each account (server ciphertext plus metadata) in
///   `vault/<id>.bin`, encrypted the same way, so the vault opens offline.
///
/// The app and its AutoFill extension both read and write these files (separate processes):
/// every change re-reads the state from disk under a cross-process lock first, so neither
/// overwrites what the other wrote (rotated refresh tokens above all). Only the app creates
/// the state or wipes it; the extension never does.
@MainActor
@Observable
public final class SecureStore {
    public enum Role: Sendable { case app, appExtension }
    public private(set) var stored = Stored()
    /// False until [load] ran (the files are readable only while the device is unlocked).
    public private(set) var loaded = false

    private let dir: URL
    public let role: Role
    @ObservationIgnored private var key: SymmetricKey?

    private var stateURL: URL { dir.appendingPathComponent("state.bin") }
    private var cacheDir: URL { dir.appendingPathComponent("vault", isDirectory: true) }

    public init(directory: URL? = nil, role: Role = .app) {
        dir = directory ?? SharedConfig.dataDirectory()
        self.role = role
    }

    /// The directory holding the state (and the lock files).
    public var directory: URL { dir }

    private var lockURL: URL { FileLock.url("state", directory: dir) }

    /// True when the app has set up PassAuth on this device (the extension sees the same files).
    public var exists: Bool { FileManager.default.fileExists(atPath: stateURL.path) }

    /// Read the state; call once the UI is up (file protection: complete).
    public func load() {
        guard !loaded else { return }
        loaded = true
        let fm = FileManager.default
        if !fm.fileExists(atPath: stateURL.path) {
            // The extension never creates or wipes the app's state.
            guard role == .app else { return }
            // Fresh install (or reset): Keychain items outlive an uninstall, so drop them.
            Keychain.deleteAll()
            try? fm.removeItem(at: cacheDir)
            stored = Stored()
            stored.file.deviceId = UUID().uuidString.lowercased()
            persist(file: true, secrets: true)
            return
        }
        var s: Stored
        switch readState() {
        case .ok(let disk): s = disk
        case .unavailable:
            // The Keychain or the file can't be read right now (not "empty"): stay unloaded and
            // retry later ([reload] on the next activation), instead of starting from an empty
            // state that the next change would write over the real one.
            loaded = false
            return
        case .corrupt: s = Stored()
        }
        if s.file.deviceId.isEmpty { s.file.deviceId = UUID().uuidString.lowercased() }
        stored = s
    }

    private enum DiskRead {
        case ok(Stored)
        /// Can't be read now (Keychain refused, file protected): try again later.
        case unavailable
        /// Readable but not decodable with this device's key.
        case corrupt
    }

    private func readState() -> DiskRead {
        guard let blob = try? Data(contentsOf: stateURL) else { return .unavailable }
        guard let k = storeKey() else { return .unavailable }
        guard let plain = open(blob, aad: "state", key: k),
              let f = try? JSONDecoder().decode(StoredFile.self, from: plain) else { return .corrupt }
        var s = Stored()
        s.file = f
        switch Keychain.lookup("secrets") {
        case .found(let d):
            guard let sec = try? JSONDecoder().decode(Secrets.self, from: d) else { return .corrupt }
            s.secrets = sec
        case .notFound: break
        case .failed: return .unavailable
        }
        return .ok(s)
    }

    /// The state as currently on disk (nil if it can't be read completely right now).
    private func readDisk() -> Stored? {
        if case .ok(let s) = readState() { return s }
        return nil
    }

    /// Pick up changes the other process (app or extension) made, e.g. rotated tokens.
    public func reload() {
        guard loaded else { return load() }
        let lock = FileLock.acquireSync(lockURL)
        defer { lock?.release() }
        if let s = readDisk(), s != stored { stored = s }
    }

    public func get() -> Stored { stored }

    /// Change the stored state; writes only the parts that changed.
    @discardableResult
    public func update(_ transform: (inout Stored) -> Void) -> Stored {
        // Nothing to write to before the app has set up its state, and never before it was
        // read: an unread (empty) state would replace the real one.
        guard role == .app || exists else { return stored }
        guard loaded || !exists else { return stored }
        // Read-modify-write under the cross-process lock. Without the lock (timeout) the
        // change is still made from the freshest state read.
        let lock = FileLock.acquireSync(lockURL)
        defer { lock?.release() }
        if loaded, let disk = readDisk(), disk != stored { stored = disk }
        var next = stored
        transform(&next)
        let fileChanged = next.file != stored.file
        let secretsChanged = next.secrets != stored.secrets
        guard fileChanged || secretsChanged else { return stored }
        // Keep the account order in step with the accounts.
        next.file.order = next.file.order.filter { next.file.accounts[$0] != nil }
            + next.file.accounts.keys.filter { !next.file.order.contains($0) }.sorted()
        stored = next
        persist(file: fileChanged, secrets: secretsChanged)
        return next
    }

    /// Update one account's record (no-op if it was removed meanwhile).
    @discardableResult
    public func updateAccount(_ id: String, _ transform: (inout AccountData) -> Void) -> Stored {
        update { s in
            guard var a = s.file.accounts[id] else { return }
            transform(&a)
            s.file.accounts[id] = a
        }
    }

    private func persist(file: Bool, secrets: Bool) {
        if file, let plain = try? JSONEncoder().encode(stored.file), let blob = seal(plain, aad: "state") {
            write(blob, to: stateURL)
        }
        if secrets, let d = try? JSONEncoder().encode(stored.secrets) {
            Keychain.write("secrets", d)
        }
    }

    // MARK: Offline copy of the last sync

    private func cacheURL(_ id: String) -> URL {
        cacheDir.appendingPathComponent("\(id.filter { $0.isLetter || $0.isNumber || $0 == "-" }).bin")
    }

    public func writeCache(_ id: String, _ json: Data) {
        guard let blob = seal(json, aad: "vault:\(id)") else { return }
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true, attributes: SharedConfig.directoryAttributes)
        write(blob, to: cacheURL(id))
    }

    public func readCache(_ id: String) -> Data? {
        guard let blob = try? Data(contentsOf: cacheURL(id)) else { return nil }
        return open(blob, aad: "vault:\(id)")
    }

    /// [writeCache] off the main thread (sealing and writing a large `/sync` copy takes a while).
    public func writeCacheInBackground(_ id: String, _ json: Data) async {
        guard let k = storeKey() else { return }
        let keyData = k.withUnsafeBytes { Data($0) }
        let url = cacheURL(id), dir = cacheDir, aad = Data("vault:\(id)".utf8)
        await Task.detached(priority: .utility) {
            guard let blob = try? ChaChaPoly.seal(json, using: SymmetricKey(data: keyData), authenticating: aad).combined else { return }
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: SharedConfig.directoryAttributes)
            try? blob.write(to: url, options: SharedConfig.writeOptions)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var u = url
            try? u.setResourceValues(values)
        }.value
    }

    /// [readCache] off the main thread.
    public func readCacheInBackground(_ id: String) async -> Data? {
        guard let k = storeKey() else { return nil }
        let keyData = k.withUnsafeBytes { Data($0) }
        let url = cacheURL(id), aad = Data("vault:\(id)".utf8)
        return await Task.detached(priority: .userInitiated) { () -> Data? in
            guard let blob = try? Data(contentsOf: url), let box = try? ChaChaPoly.SealedBox(combined: blob) else { return nil }
            return try? ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: aad)
        }.value
    }

    public func deleteCache(_ id: String) {
        try? FileManager.default.removeItem(at: cacheURL(id))
        try? FileManager.default.removeItem(at: refreshedURL(id))
        for file in [revsURL(id), manifestsURL(id), trashSeenURL(id)] {
            try? FileManager.default.removeItem(at: file)
            try? FileManager.default.removeItem(at: asideURL(file))
        }
    }

    // MARK: What a background refresh fetched (not checked yet)
    //
    // Background App Refresh runs without the account's keys, so it can't check what the server
    // sent. Its result never replaces the offline copy: it is kept next to it (sealed the same
    // way, under its own name) until the next unlock, which checks it with the keys like any
    // server answer and only then makes it the copy (`VaultRepository.adoptRefreshed`).

    private func refreshedURL(_ id: String) -> URL { memoryFile(id, "next") }

    public func hasRefreshed(_ id: String) -> Bool { FileManager.default.fileExists(atPath: refreshedURL(id).path) }

    public func deleteRefreshed(_ id: String) { try? FileManager.default.removeItem(at: refreshedURL(id)) }

    public func writeRefreshedInBackground(_ id: String, _ json: Data) async {
        guard let k = storeKey() else { return }
        let keyData = k.withUnsafeBytes { Data($0) }
        let url = refreshedURL(id), dir = cacheDir, aad = Data("next:\(id)".utf8)
        await Task.detached(priority: .utility) {
            guard let blob = try? ChaChaPoly.seal(json, using: SymmetricKey(data: keyData), authenticating: aad).combined else { return }
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: SharedConfig.directoryAttributes)
            try? blob.write(to: url, options: SharedConfig.writeOptions)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var u = url
            try? u.setResourceValues(values)
        }.value
    }

    public func readRefreshedInBackground(_ id: String) async -> Data? {
        guard let k = storeKey() else { return nil }
        let keyData = k.withUnsafeBytes { Data($0) }
        let url = refreshedURL(id), aad = Data("next:\(id)".utf8)
        return await Task.detached(priority: .userInitiated) { () -> Data? in
            guard let blob = try? Data(contentsOf: url), let box = try? ChaChaPoly.SealedBox(combined: blob) else { return nil }
            return try? ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: aad)
        }.value
    }

    // MARK: Device memory next to the offline copy (item edit counters, manifest marks, trash first seen)
    //
    // The app and its AutoFill extension both read and write these files. Each write reads what
    // is stored, merges and writes back under one cross-process lock (`memoryLock`), so neither
    // loses what the other learnt. A file that is there but can't be read now (the Keychain, file
    // protection) is "unreadable" (nil), never "nothing remembered": nothing is checked against
    // it and nothing is written over it.

    private var memoryLockURL: URL { FileLock.url("memory", directory: dir) }

    private func memoryFile(_ id: String, _ ext: String) -> URL {
        cacheDir.appendingPathComponent("\(id.filter { $0.isLetter || $0.isNumber || $0 == "-" }).\(ext)")
    }

    private enum MemoryRead {
        case missing
        case unreadable
        case plain(Data)
    }

    private func readMemoryFile(_ url: URL, aad: String) -> MemoryRead {
        guard FileManager.default.fileExists(atPath: url.path) else { return .missing }
        guard let blob = try? Data(contentsOf: url), let plain = open(blob, aad: aad) else { return .unreadable }
        return .plain(plain)
    }

    /// Read, change and write one memory file under the cross-process lock. Nothing is written
    /// while the stored file can't be read, the lock can't be had (the next write merges again),
    /// or `merge` returns nil (nothing to change).
    private func updateMemoryFile(_ url: URL, aad: String, merge: (Data?) -> Data?) {
        guard let lock = FileLock.acquireSync(memoryLockURL) else { return }
        defer { lock.release() }
        let stored: Data?
        switch readMemoryFile(url, aad: aad) {
        case .missing: stored = nil
        case .unreadable: return
        case .plain(let d): stored = d
        }
        guard let plain = merge(stored), plain != stored, let blob = seal(plain, aad: aad) else { return }
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true, attributes: SharedConfig.directoryAttributes)
        write(blob, to: url)
    }

    // Item edit counters seen (rollback detection)

    private func revsURL(_ id: String) -> URL { memoryFile(id, "revs") }

    /// What this device remembers per item id of the account (the highest edit counter `rev` it
    /// saw, the vault it was in, when it was last seen); empty when nothing was kept (a new
    /// device or copy: trust on first sight), nil when the file is there but can't be read now.
    public func readItemRevMemory(_ id: String) -> ItemRevMemory? {
        switch readMemoryFile(revsURL(id), aad: "revs:\(id)") {
        case .missing: ItemRevMemory()
        case .unreadable: nil
        case .plain(let d): ItemRevMemory.read(d)
        }
    }

    /// The highest edit counter per item id (`readItemRevMemory`).
    public func readItemRevs(_ id: String) -> [String: UInt64]? { readItemRevMemory(id)?.revs }

    /// Store `memory` merged into what is on the device (`ItemRevMemory.merged`: no counter is
    /// lowered, nothing the other process learnt is lost), without the ids in `dropped` (items
    /// this device knows are gone for good).
    public func writeItemRevMemory(_ id: String, _ memory: ItemRevMemory, dropped: Set<String> = []) {
        updateMemoryFile(revsURL(id), aad: "revs:\(id)") { stored in
            ItemRevMemory.merged(stored: stored.map(ItemRevMemory.read) ?? ItemRevMemory(), memory, dropped: dropped).encoded()
        }
    }

    /// "Use the server's copy": forget the edit counters of these items, whatever is stored
    /// (the vault is taken as the server has it now, older versions of its items included).
    /// Returns false when the memory can't be read or written now (nothing changed).
    @discardableResult
    public func forgetItemRevs(_ id: String, _ ids: Set<String>) -> Bool {
        guard !ids.isEmpty else { return true }
        updateMemoryFile(revsURL(id), aad: "revs:\(id)") { stored in
            guard let stored else { return nil }
            var memory = ItemRevMemory.read(stored)
            for i in ids { memory.items[i] = nil }
            return memory.encoded()
        }
        guard let now = readItemRevMemory(id) else { return false }
        return ids.allSatisfy { now.items[$0] == nil }
    }

    // Vault manifests seen (rollback and fork detection)

    private func manifestsURL(_ id: String) -> URL { memoryFile(id, "manifests") }

    /// The last manifest (version and link) this device checked or wrote per vault id of the
    /// account; empty when none was kept (a new device: the first manifest seen is trusted, and
    /// so is a memory in the first format, which had no links), nil when the file is there but
    /// can't be read now. Entries of vaults that are gone stay (vault ids are never reused; a
    /// server could hide a vault and show it again).
    public func readManifestMemory(_ id: String) -> [String: ManifestMark]? {
        switch readMemoryFile(manifestsURL(id), aad: "manifests:\(id)") {
        case .missing: [:]
        case .unreadable: nil
        case .plain(let d): VaultManifest.readMemory(d) ?? [:]
        }
    }

    /// Store `marks` merged into what is on the device (`VaultManifest.merged`: per vault the
    /// entry with more acceptances, then the higher version; a link is never replaced at its
    /// version). Nothing is written while the stored ones can't be read.
    public func writeManifestMemory(_ id: String, _ marks: [String: ManifestMark]) {
        updateMemoryFile(manifestsURL(id), aad: "manifests:\(id)") { stored in
            let disk = stored.flatMap(VaultManifest.readMemory) ?? [:]
            let merged = VaultManifest.merged(disk, marks)
            guard merged != disk else { return nil }
            return try? JSONEncoder().encode(merged)
        }
    }

    /// "Use the server's copy": replace what is remembered for `vault` with `mark` (nil: forget
    /// it), whatever is stored, also when the version goes down, and count the acceptance
    /// (`VaultManifest.replaced`). Read, changed and written under the cross-process lock.
    /// Returns the memory as stored afterwards; nil when it can't be read or written now
    /// (nothing changed).
    public func replaceManifestMark(_ id: String, vault: String, with mark: ManifestMark?) -> [String: ManifestMark]? {
        var out: [String: ManifestMark]?
        updateMemoryFile(manifestsURL(id), aad: "manifests:\(id)") { stored in
            var disk = stored.flatMap(VaultManifest.readMemory) ?? [:]
            disk[vault] = VaultManifest.replaced(disk[vault], with: mark)
            guard let data = try? JSONEncoder().encode(disk) else { return nil }
            out = disk
            return data
        }
        // Only what is on the device counts as done.
        guard let wanted = out, readManifestMemory(id) == wanted else { return nil }
        return wanted
    }

    // A memory file that stays unreadable

    private func asideURL(_ url: URL) -> URL { url.appendingPathExtension("unreadable") }

    /// The manifest marks, the item edit counters or the trash first-seen times are stored but
    /// can't be read now.
    public func memoryUnreadable(_ id: String) -> Bool {
        if case .unreadable = readMemoryFile(manifestsURL(id), aad: "manifests:\(id)") { return true }
        if case .unreadable = readMemoryFile(revsURL(id), aad: "revs:\(id)") { return true }
        if case .unreadable = readMemoryFile(trashSeenURL(id), aad: "trashed:\(id)") { return true }
        return false
    }

    /// "Reset on this device": move the account's memory files that can't be read out of the
    /// way (kept next to them as `….unreadable`, deleted with the account's copy), so this
    /// device goes on as one that remembers nothing. Files that read are left alone. Returns
    /// whether every memory file reads (or is missing) afterwards.
    @discardableResult
    public func setAsideUnreadableMemory(_ id: String) -> Bool {
        guard let lock = FileLock.acquireSync(memoryLockURL) else { return false }
        defer { lock.release() }
        for (url, aad) in [(manifestsURL(id), "manifests:\(id)"), (revsURL(id), "revs:\(id)"), (trashSeenURL(id), "trashed:\(id)")] {
            guard case .unreadable = readMemoryFile(url, aad: aad) else { continue }
            let aside = asideURL(url)
            try? FileManager.default.removeItem(at: aside)
            do { try FileManager.default.moveItem(at: url, to: aside) } catch { try? FileManager.default.removeItem(at: url) }
        }
        return !memoryUnreadable(id)
    }

    // Trashed items first seen (old trash is only deleted after this device watched it wait)

    private func trashSeenURL(_ id: String) -> URL { memoryFile(id, "trashed") }

    /// When this device first saw each item of the account in the trash (unix seconds, its own
    /// clock); empty when nothing was kept, nil when the file can't be read now. Kept by the app
    /// only (it alone deletes old trash).
    public func readTrashSeen(_ id: String) -> [String: Int64]? {
        switch readMemoryFile(trashSeenURL(id), aad: "trashed:\(id)") {
        case .missing: [:]
        case .unreadable: nil
        case .plain(let d): (try? JSONDecoder().decode([String: Int64].self, from: d)) ?? [:]
        }
    }

    /// Replace the stored first-seen times with `seen` (the app is their only writer).
    public func writeTrashSeen(_ id: String, _ seen: [String: Int64]) {
        updateMemoryFile(trashSeenURL(id), aad: "trashed:\(id)") { _ in try? JSONEncoder().encode(seen) }
    }

    // MARK: Encryption

    private func storeKey() -> SymmetricKey? {
        if let key { return key }
        switch Keychain.lookup("storeKey") {
        case .found(let d) where d.count == 32:
            key = SymmetricKey(data: d)
            return key
        case .failed:
            // Couldn't read it now: never replace it (a new key would make every file unreadable).
            return nil
        default: break
        }
        if role == .appExtension {
            // Only the app creates the key (a new one would make the app's files unreadable).
            return nil
        } else {
            let k = SymmetricKey(size: .bits256)
            let d = k.withUnsafeBytes { Data($0) }
            guard Keychain.write("storeKey", d) else { return nil }
            key = k
        }
        return key
    }

    private func seal(_ plain: Data, aad: String) -> Data? {
        guard let k = storeKey() else { return nil }
        return try? ChaChaPoly.seal(plain, using: k, authenticating: Data(aad.utf8)).combined
    }

    private func open(_ blob: Data, aad: String, key k: SymmetricKey? = nil) -> Data? {
        guard let k = k ?? storeKey(), let box = try? ChaChaPoly.SealedBox(combined: blob) else { return nil }
        return try? ChaChaPoly.open(box, using: k, authenticating: Data(aad.utf8))
    }

    private func write(_ data: Data, to url: URL) {
        try? data.write(to: url, options: SharedConfig.writeOptions)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var u = url
        try? u.setResourceValues(values)
    }

    /// Debug builds' UI tests: forget everything (files and Keychain).
    public static func wipeAll(directory: URL? = nil) {
        let d = directory ?? SharedConfig.dataDirectory()
        try? FileManager.default.removeItem(at: d.appendingPathComponent("state.bin"))
        try? FileManager.default.removeItem(at: d.appendingPathComponent("vault", isDirectory: true))
        Keychain.deleteAll()
    }
}
