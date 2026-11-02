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
        var s = readDisk() ?? Stored()
        if s.file.deviceId.isEmpty { s.file.deviceId = UUID().uuidString.lowercased() }
        stored = s
    }

    /// The state as currently on disk (nil if the state file can't be read).
    private func readDisk() -> Stored? {
        guard let blob = try? Data(contentsOf: stateURL), let plain = open(blob, aad: "state"),
              let f = try? JSONDecoder().decode(StoredFile.self, from: plain) else { return nil }
        var s = Stored()
        s.file = f
        if let d = Keychain.read("secrets"), let sec = try? JSONDecoder().decode(Secrets.self, from: d) {
            s.secrets = sec
        }
        return s
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
        // Nothing to write to before the app has set up its state.
        guard role == .app || exists else { return stored }
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
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        write(blob, to: cacheURL(id))
    }

    public func readCache(_ id: String) -> Data? {
        guard let blob = try? Data(contentsOf: cacheURL(id)) else { return nil }
        return open(blob, aad: "vault:\(id)")
    }

    public func deleteCache(_ id: String) {
        try? FileManager.default.removeItem(at: cacheURL(id))
    }

    // MARK: Encryption

    private func storeKey() -> SymmetricKey? {
        if let key { return key }
        if let d = Keychain.read("storeKey"), d.count == 32 {
            key = SymmetricKey(data: d)
        } else if role == .appExtension {
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

    private func open(_ blob: Data, aad: String) -> Data? {
        guard let k = storeKey(), let box = try? ChaChaPoly.SealedBox(combined: blob) else { return nil }
        return try? ChaChaPoly.open(box, using: k, authenticating: Data(aad.utf8))
    }

    private func write(_ data: Data, to url: URL) {
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
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
