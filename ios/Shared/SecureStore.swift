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
