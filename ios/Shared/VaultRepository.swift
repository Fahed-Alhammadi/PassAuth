import Foundation
import Observation
import PassAuthCore
#if canImport(UIKit)
import UIKit
#endif

public enum Status: Sendable { case setup, loggedOut, locked, unlocked }

public struct AccountSummary: Identifiable, Equatable, Sendable {
    public let id: String
    public let email: String
    public let name: String
    public let server: String
    public let status: Status
}

/// What the UI needs to know about accounts and settings (no secrets).
public struct AppState: Equatable, Sendable {
    public var loaded = false
    public var status: Status = .setup
    public var activeId = ""
    /// Signed-in (or signed-out but remembered) accounts on this device.
    public var accounts: [AccountSummary] = []
    public var name = ""
    public var server = ""
    public var email = ""
    public var secretKeyRequired = false
    public var secretKeyStored = false
    public var biometricEnabled = false
    public var settings = Settings()
    public var lastSync: Double = 0
    /// The active record is an unfinished "add account".
    public var adding = false
}

/// A decrypted item of the active account.
public struct Entry: Identifiable, Sendable {
    public let id: String
    public let item: Item
    public let vaultId: String
    public let revision: Int64
    public let enc: EncryptedItem
    /// Moved to the trash at (unix seconds); nil for live items.
    public let deletedAt: Int64?

    public init(id: String, item: Item, vaultId: String, revision: Int64, enc: EncryptedItem, deletedAt: Int64?) {
        self.id = id
        self.item = item
        self.vaultId = vaultId
        self.revision = revision
        self.enc = enc
        self.deletedAt = deletedAt
    }
}

public enum Role: String, Sendable { case owner, admin, write, read }

public struct VaultInfo: Identifiable, Equatable, Sendable {
    public static let accountKeyKind = "account"

    public let id: String
    public let name: String
    public let role: Role
    /// `account`: the vault key is wrapped with this account's own key (only this account can
    /// have made it). `sealed`: someone shared the vault with this account.
    public let keyKind: String

    public init(id: String, name: String, role: Role, keyKind: String = VaultInfo.accountKeyKind) {
        self.id = id
        self.name = name
        self.role = role
        self.keyKind = keyKind
    }

    public var personal: Bool { keyKind == Self.accountKeyKind }

    /// Where new items go when the user didn't pick a vault (AutoFill saves, passkeys, the
    /// editor's default): the account's own vault, never one someone else shared, so another
    /// user (or the server) can't make itself the place new logins land.
    public static func defaultSaveVault(_ vaults: [VaultInfo]) -> VaultInfo? {
        vaults.first { $0.personal && $0.role == .owner } ?? vaults.first { $0.personal && $0.role != .read }
    }
}

/// The unlocked vault of the active account.
public struct VaultData: Sendable {
    public var entries: [Entry] = []
    public var trash: [Entry] = []
    public var vaults: [VaultInfo] = []
    public var revision: Int64 = 0
    /// Shown from the on-device copy because the server couldn't be reached.
    public var offline = false

    public init() {}

    public var folders: [String] {
        Array(Set(entries.compactMap { e in e.item.folder.flatMap { $0.isEmpty ? nil : $0 } })).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    public func get(_ id: String) -> Entry? { entries.first { $0.id == id } ?? trash.first { $0.id == id } }
    public func vaultName(_ id: String) -> String { vaults.first { $0.id == id }?.name ?? "Vault" }
    public var defaultVault: VaultInfo? { VaultInfo.defaultSaveVault(vaults) }
    public func canWrite(_ e: Entry) -> Bool { vaults.first { $0.id == e.vaultId }.map { $0.role != .read } ?? false }
    /// In the account's own vault (not one somebody shared) and editable: the only logins that
    /// are picked as a default place to write to (`SaveLogic`).
    public func isOwn(_ e: Entry) -> Bool { vaults.first { $0.id == e.vaultId }.map { $0.personal && $0.role != .read } ?? false }
    /// The name of the entry's vault when it is one somebody shared; nil for the account's own.
    public func sharedVaultName(_ e: Entry) -> String? { vaults.first { $0.id == e.vaultId }.flatMap { $0.personal ? nil : $0.name } }
    public var writable: [VaultInfo] { vaults.filter { $0.role != .read } }
}

public enum LoginResult: Sendable {
    case done
    case twoFactor(token: String, providers: [String])
}

public struct Registered: Sendable {
    public let secretKey: String?
    public let emailVerificationRequired: Bool
}

/// What a locked cache refresh writes (`VaultRepository.offlineCopyUpdate`).
public struct OfflineCopyUpdate: Equatable, Sendable {
    public let revision: Int64
    /// The account bundle as JSON text.
    public let bundle: String?
}

/// Unlocked keys of one account, in memory only (Rust handles, freed when released).
final class Session {
    let accountId: String
    let account: Account
    init(accountId: String, account: Account) {
        self.accountId = accountId
        self.account = account
    }
}

/// Serialises the repository's operations (the Android app's `Mutex`).
@MainActor
final class AsyncLock {
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func run<T>(_ body: () async throws -> T) async rethrows -> T {
        if locked {
            await withCheckedContinuation { waiters.append($0) }
        } else {
            locked = true
        }
        defer {
            if waiters.isEmpty { locked = false } else { waiters.removeFirst().resume() }
        }
        return try await body()
    }
}

/// Rust core calls are CPU-bound (Argon2id, decryption): keep them off the main thread.
func core<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
    try await Task.detached(priority: .userInitiated) { try body() }.value
}

/// The app's single source of truth for accounts, unlock state and the decrypted vault.
/// Mirrors the extension's background `vault.ts` and the Android `VaultRepository`.
@MainActor
@Observable
public final class VaultRepository {
    public let store: SecureStore
    public let api: ApiClient

    @ObservationIgnored let lock = AsyncLock()
    @ObservationIgnored var sessions: [String: Session] = [:]
    private var sessionIds: Set<String> = []
    @ObservationIgnored private var vaultKeys: [String: VaultKey] = [:]
    @ObservationIgnored private var pendingMaster: MasterKeys?
    @ObservationIgnored private var pendingRemember = ""

    /// The active account's decrypted vault; nil while locked.
    public private(set) var vault: VaultData?

    /// Keeps iOS's AutoFill identities (QuickType bar, passkey sheet) in step with the active account.
    @ObservationIgnored public let identities = CredentialIdentitySync()
    /// AutoFill extension: open the vault from the on-device copy first (fast, no network;
    /// shown as offline until a sync with the server succeeded).
    @ObservationIgnored public var preferCache = false

    public init(store: SecureStore, api: ApiClient) {
        self.store = store
        self.api = api
        identities.onWritten = { [weak self] fingerprint in
            self?.store.update { $0.file.identityFingerprint = fingerprint }
        }
        api.onSessionLost = { [weak self] id in
            // Runs later: the request that noticed it may hold the lock.
            Task { @MainActor in
                guard let self else { return }
                await self.lock.run { self.closeSession(id) }
            }
        }
    }

    // MARK: State

    private func statusOf(_ id: String, _ s: Stored) -> Status {
        guard let a = s.file.accounts[id], !a.server.isEmpty else { return .setup }
        if s.tokens(id) == nil { return .loggedOut }
        return sessionIds.contains(id) ? .unlocked : .locked
    }

    public var state: AppState {
        let s = store.stored
        var st = AppState()
        st.loaded = store.loaded
        st.status = statusOf(s.activeId, s)
        st.activeId = s.activeId
        st.accounts = s.file.order.compactMap { id in
            guard let a = s.file.accounts[id], a.isListed else { return nil }
            return AccountSummary(id: id, email: a.email, name: a.name, server: a.server, status: statusOf(id, s))
        }
        let a = s.active
        st.name = a?.name ?? ""
        st.server = a?.server ?? ""
        st.email = a?.email ?? ""
        st.secretKeyRequired = a?.bundle.flatMap { try? JSON.parse($0) }?["secret_key_enabled"]?.bool ?? false
        st.secretKeyStored = a.map { s.secrets.secretKeys[$0.email.lowercased()] != nil } ?? false
        st.biometricEnabled = a?.biometric ?? false
        st.settings = s.settings
        st.lastSync = a?.lastSync ?? 0
        st.adding = a.map { !$0.isListed } ?? false
        return st
    }

    var activeId: String { store.get().activeId }

    /// Read the stored state and, with the vault timeout "never", reopen the kept keys.
    public func start() async {
        store.load()
        _ = await restorePersisted()
    }

    // MARK: Server

    /// Connect the active account record (created if needed) to a server.
    /// `allowLanHttp`: the user confirmed plain http to a local-network address (only loopback
    /// is accepted without asking, as anyone on the network could read or change the traffic).
    public func setServer(_ url: String, allowLanHttp: Bool = false) async throws {
        let origin = try Self.normalizeServer(url)
        if !allowLanHttp, Self.plainHttpOnNetwork(origin), let host = UrlMatcher.parse(origin)?.hostname {
            throw PlainHttpConfirmation(host: host)
        }
        guard let config = URL(string: origin + "/api/config") else { throw UserError("That isn't a valid server address.") }
        let ok: Bool
        do {
            let (data, res) = try await api.get(config)
            ok = res.statusCode == 200 && (try? JSON.parse(data))?.str("name") == "PassAuth"
        } catch {
            throw UserError("No PassAuth server answered at that address.")
        }
        guard ok else { throw UserError("No PassAuth server answered at that address.") }
        await lock.run {
            closeSession(activeId)
            store.update { st in
                let id = st.file.accounts[st.file.activeId] != nil ? st.file.activeId : UUID().uuidString.lowercased()
                var a = st.file.accounts[id] ?? AccountData()
                a.server = origin
                a.bundle = nil
                st.file.accounts[id] = a
                st.file.activeId = id
                st.secrets.tokens[id] = nil
            }
        }
    }

    /// Whether the server allows sign-ups (from `/api/config`); nil if unknown.
    public func signupsAllowed() async -> Bool? {
        guard let server = store.get().active?.server, let url = URL(string: server + "/api/config"),
              let (data, _) = try? await api.get(url), let j = try? JSON.parse(data), let v = j["signups_allowed"]
        else { return nil }
        return v.bool
    }

    // MARK: Login

    var deviceInfo: JSON {
        #if os(iOS)
        ["id": .string(store.get().file.deviceId), "name": .string("PassAuth for iOS (\(UIDevice.current.model))"), "kind": "mobile"]
        #else
        // The desktop app's AutoFill extension signs in on its own: its own device on the server.
        ["id": .string(store.get().file.deviceId), "name": "PassAuth for Mac AutoFill", "kind": "desktop"]
        #endif
    }

    public func login(email: String, password: String, secretKey: String?) async throws -> LoginResult {
        try await lock.run {
            let s = store.get()
            let id = s.activeId
            let mail = email.trimmingCharacters(in: .whitespacesAndNewlines)
            let key = mail.lowercased()
            let typed = secretKey?.trimmingCharacters(in: .whitespacesAndNewlines)
            let sk = (typed?.isEmpty == false ? typed : nil) ?? s.secrets.secretKeys[key]
            let pre = try await api.call(id, "/auth/prelogin", body: ["email": .string(mail)], auth: false)
            let skRequired = pre["secret_key_required"]?.bool ?? false
            if skRequired && sk == nil { throw UserError(secretKeyRequiredMessage) }
            let accountId = pre.str("account_id")
            let kdf = (pre["kdf"] ?? .null).text
            let skArg = skRequired ? sk : nil
            let master = try await core { try deriveMasterKeys(password: password, secretKey: skArg, accountId: accountId, kdfJson: kdf, secretKeyRequired: skRequired) }
            let start = try await core { try opaqueLoginStart(master: master) }
            let resp = try await api.call(id, "/auth/login/start", body: ["email": .string(mail), "message": .string(start.message)], auth: false)
            let message = resp.str("message")
            let fin: String
            do {
                fin = try await core { try opaqueLoginFinish(state: start.state, master: master, response: message) }
            } catch is CoreError {
                throw UserError("Wrong email, master password or Secret Key.")
            }
            let rememberKey = "\(s.active?.server ?? "")|\(key)"
            var body: [String: JSON] = ["login_id": .string(resp.str("login_id")), "message": .string(fin), "device": deviceInfo]
            if let t = s.secrets.rememberTokens[rememberKey] { body["remember_token"] = .string(t) }
            let result = try await api.call(id, "/auth/login/finish", body: .object(body), auth: false)
            if let sk, skRequired { store.update { $0.secrets.secretKeys[key] = sk } }
            if result["two_factor_required"]?.bool == true {
                pendingMaster = master
                pendingRemember = rememberKey
                return .twoFactor(token: result.str("two_factor_token"), providers: (result["providers"]?.array ?? []).compactMap(\.string))
            }
            try await finishLogin(id, master, result)
            try? await syncLocked()
            return .done
        }
    }

    public func verifyTwoFactor(token: String, provider: String, code: String, remember: Bool) async throws {
        try await lock.run {
            let id = activeId
            let clean = code.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: " ", with: "")
            let result = try await api.call(id, "/auth/2fa/verify", body: [
                "two_factor_token": .string(token), "provider": .string(provider), "code": .string(clean), "remember": .bool(remember),
            ], auth: false)
            guard let master = pendingMaster else { throw UserError("Sign-in expired. Start again.") }
            pendingMaster = nil
            if let t = result["remember_token"]?.string {
                let k = pendingRemember
                store.update { $0.secrets.rememberTokens[k] = t }
            }
            try await finishLogin(id, master, result)
            try? await syncLocked()
        }
    }

    public func sendTwoFactorEmail(token: String) async throws {
        _ = try await api.call(activeId, "/auth/2fa/email", body: ["two_factor_token": .string(token)], auth: false)
    }

    private func finishLogin(_ id: String, _ master: MasterKeys, _ result: JSON) async throws {
        let bundle = (result["bundle"] ?? .null).text
        let email = result.str("email")
        let account = try await core { try master.unlock(bundleJson: bundle) }
        let before = store.get()
        let server = before.file.accounts[id]?.server
        // Signing in again to an account that is already listed replaces the old record.
        let dupes = before.file.accounts.filter { $0.key != id && $0.value.server == server && $0.value.email.lowercased() == email.lowercased() }.map(\.key)
        for d in dupes {
            closeSession(d)
            store.deleteCache(d)
            Keychain.deleteBiometric(d)
        }
        store.update { s in
            for d in dupes {
                s.file.accounts[d] = nil
                s.secrets.tokens[d] = nil
                s.secrets.persistedKeys[d] = nil
            }
            var a = s.file.accounts[id] ?? AccountData()
            a.email = email
            a.bundle = bundle
            a.biometric = false
            s.file.accounts[id] = a
            s.file.activeId = id
            s.secrets.tokens[id] = Tokens(access: result.str("access_token"), refresh: result.str("refresh_token"))
            s.secrets.persistedKeys[id] = nil
        }
        Keychain.deleteBiometric(id)
        openSession(id, Session(accountId: Self.bundleAccountId(bundle), account: account))
    }

    /// Create an account on the active record's server (the web vault's Register).
    public func register(email: String, name: String, password: String, withSecretKey: Bool) async throws -> Registered {
        try await lock.run {
            let id = activeId
            let mail = email.trimmingCharacters(in: .whitespacesAndNewlines)
            let initRes = try await api.call(id, "/auth/register/init", body: ["email": .string(mail)], auth: false)
            let accountId = initRes.str("account_id")
            let registrationId = initRes.str("registration_id")
            let created = try await core { try createAccount(accountId: accountId, password: password, withSecretKey: withSecretKey) }
            let master = created.master
            let start = try await core { try opaqueRegisterStart(master: master) }
            let resp = try await api.call(id, "/auth/register/start", body: ["registration_id": .string(registrationId), "message": .string(start.message)], auth: false)
            let message = resp.str("message")
            let upload = try await core { try opaqueRegisterFinish(state: start.state, master: master, response: message) }
            let account = created.account
            let (vaultId, wrapped, meta) = try await core { () -> (String, String, String) in
                let vaultId = try newId()
                let nv = try account.newVaultKey(vaultId: vaultId)
                let meta = try nv.key.encryptMeta(vaultId: vaultId, metaJson: #"{"name":"Personal"}"#)
                return (vaultId, nv.wrapped, meta)
            }
            let done = try await api.call(id, "/auth/register/finish", body: [
                "registration_id": .string(registrationId),
                "upload": .string(upload),
                "bundle": try JSON.parse(created.bundleJson),
                "name": .string(name.trimmingCharacters(in: .whitespacesAndNewlines)),
                "vault": ["id": .string(vaultId), "meta": .string(meta), "wrapped_key": .string(wrapped)],
            ], auth: false)
            if let sk = created.secretKey { store.update { $0.secrets.secretKeys[mail.lowercased()] = sk } }
            return Registered(secretKey: created.secretKey, emailVerificationRequired: done["email_verification_required"]?.bool ?? false)
        }
    }

    // MARK: Unlock

    public func unlock(password: String, secretKey: String?) async throws {
        try await lock.run {
            let s = store.get()
            let id = s.activeId
            guard let a = s.active else { throw UserError("Sign in first.") }
            let bundle: String
            if let b = a.bundle {
                bundle = b
            } else {
                let b = (try await api.call(id, "/sync")["bundle"] ?? .null).text
                store.updateAccount(id) { $0.bundle = b }
                bundle = b
            }
            let b = try JSON.parse(bundle)
            let skEnabled = b["secret_key_enabled"]?.bool ?? false
            let typed = secretKey?.trimmingCharacters(in: .whitespacesAndNewlines)
            let sk = (typed?.isEmpty == false ? typed : nil) ?? s.secrets.secretKeys[a.email.lowercased()]
            if skEnabled && sk == nil { throw UserError(secretKeyRequiredMessage) }
            let accountId = b.str("account_id")
            let kdf = (b["kdf"] ?? .null).text
            let account: Account
            do {
                account = try await core {
                    let master = try deriveMasterKeys(password: password, secretKey: sk, accountId: accountId, kdfJson: kdf, secretKeyRequired: skEnabled)
                    return try master.unlock(bundleJson: bundle)
                }
            } catch is CoreError {
                throw UserError("Wrong master password or Secret Key.")
            }
            if let sk, typed?.isEmpty == false {
                store.update { $0.secrets.secretKeys[a.email.lowercased()] = sk }
            }
            openSession(id, Session(accountId: accountId, account: account))
            try await syncLocked(fallbackToCache: true, cacheFirst: true)
        }
    }

    /// Turn on Face ID / Touch ID unlock: the session bytes go into a biometry-bound Keychain item.
    public func enableBiometric() async throws {
        try await lock.run {
            let id = activeId
            guard let session = sessions[id] else { throw UserError("Unlock your vault first.") }
            var bytes = session.account.toSessionBytes()
            defer { bytes.wipe() }
            try Keychain.storeBiometric(id, bytes)
            store.updateAccount(id) { $0.biometric = true }
        }
    }

    public func disableBiometric() {
        let id = activeId
        Keychain.deleteBiometric(id)
        store.updateAccount(id) { $0.biometric = false }
    }

    /// Unlock with Face ID / Touch ID. Returns false when the user cancelled.
    public func unlockWithBiometric(reason: String) async throws -> Bool {
        try await lock.run {
            let s = store.get()
            let id = s.activeId
            guard let a = s.active else { throw UserError("Sign in first.") }
            guard a.biometric else { throw UserError("Biometric unlock is off.") }
            guard let bundle = a.bundle else { throw UserError("Unlock with your master password.") }
            let result = await Task.detached(priority: .userInitiated) { Keychain.readBiometric(id, reason: reason) }.value
            switch result {
            case .cancelled:
                return false
            case .invalidated:
                Keychain.deleteBiometric(id)
                store.updateAccount(id) { $0.biometric = false }
                throw UserError("Biometrics changed on this device. Unlock with your master password, then turn biometric unlock on again in Settings.")
            case .failed(let m):
                throw UserError(m)
            case .ok(var bytes):
                defer { bytes.wipe() }
                let accountId = Self.bundleAccountId(bundle)
                let copy = bytes
                let account = try await core { try accountFromSessionBytes(accountId: accountId, bytes: copy) }
                openSession(id, Session(accountId: accountId, account: account))
                try await syncLocked(fallbackToCache: true, cacheFirst: true)
                return true
            }
        }
    }

    /// Vault timeout "never": restore keys kept in the Keychain after the app restarts.
    public func restorePersisted() async -> Bool {
        await lock.run {
            let s = store.get()
            guard s.settings.vaultTimeout == .never else { return false }
            var restored = false
            for (id, a) in s.file.accounts {
                guard let keys = s.secrets.persistedKeys[id], let bundle = a.bundle, s.tokens(id) != nil, sessions[id] == nil,
                      var bytes = Data(base64Encoded: keys) else { continue }
                defer { bytes.wipe() }
                let accountId = Self.bundleAccountId(bundle)
                let copy = bytes
                if let account = try? await core({ try accountFromSessionBytes(accountId: accountId, bytes: copy) }) {
                    openSession(id, Session(accountId: accountId, account: account))
                    restored = true
                }
            }
            if restored && sessions[s.activeId] != nil { try? await syncLocked(fallbackToCache: true, cacheFirst: true) }
            return restored
        }
    }

    func openSession(_ id: String, _ session: Session) {
        sessions[id] = session
        sessionIds = Set(sessions.keys)
        persistForNever(id)
    }

    private func persistForNever(_ id: String) {
        guard let session = sessions[id], store.get().settings.vaultTimeout == .never else { return }
        var bytes = session.account.toSessionBytes()
        let b64 = bytes.base64EncodedString()
        bytes.wipe()
        store.update { $0.secrets.persistedKeys[id] = b64 }
    }

    private func closeSession(_ id: String) {
        sessions[id] = nil
        sessionIds = Set(sessions.keys)
        store.update { $0.secrets.persistedKeys[id] = nil }
        if id == activeId { unloadVault() }
    }

    private func unloadVault() {
        vaultKeys = [:]
        vault = nil
    }

    // MARK: Lock / logout

    /// Lock the active account.
    public func lockActive() async {
        await lock.run { closeSession(activeId) }
    }

    /// Vault timeout: lock every account.
    public func lockAll() async {
        await lock.run {
            for id in Array(sessions.keys) { closeSession(id) }
            unloadVault()
        }
    }

    public var anyUnlocked: Bool { !sessionIds.isEmpty }

    /// Vault timeout with the "log out" action: sign every account out (they stay listed).
    public func logoutAll() async {
        await lockAll()
        let s = store.get()
        for (id, a) in s.file.accounts {
            guard let t = s.tokens(id) else { continue }
            await api.logoutRemote(server: a.server, tokens: t)
            store.update { st in
                st.secrets.tokens[id] = nil
                st.file.accounts[id]?.biometric = false
            }
            Keychain.deleteBiometric(id)
            store.deleteCache(id)
        }
        identities.clear()
    }

    /// Log out of the active account and remove it from this device; the next one becomes active.
    public func logout() async {
        await lock.run {
            let s = store.get()
            let id = s.activeId
            if let a = s.active { await api.logoutRemote(server: a.server, tokens: s.tokens(id)) }
            closeSession(id)
            pendingMaster = nil
            Keychain.deleteBiometric(id)
            store.deleteCache(id)
            let listed = s.file.accounts.filter { $0.value.isListed }
            if listed.count > 1 || listed[id] == nil {
                await removeAccount(id)
            } else {
                // The last account stays as a signed-out record, so the sign-in screen remembers the server and email.
                store.update { st in
                    st.secrets.tokens[id] = nil
                    st.file.accounts[id]?.biometric = false
                    st.file.accounts[id]?.bundle = nil
                    st.file.accounts[id]?.lastSync = 0
                }
            }
            refreshIdentities()
        }
    }

    private func removeAccount(_ id: String) async {
        store.update { s in
            s.file.accounts[id] = nil
            s.secrets.tokens[id] = nil
            s.secrets.persistedKeys[id] = nil
            if s.file.activeId == id {
                let rest = s.file.order.filter { $0 != id && s.file.accounts[$0] != nil }
                s.file.activeId = rest.first { s.secrets.tokens[$0] != nil } ?? rest.first ?? ""
            }
        }
        if sessions[activeId] != nil { try? await syncLocked(fallbackToCache: true) }
    }

    public func switchAccount(_ id: String) async throws {
        try await lock.run {
            let s = store.get()
            guard let target = s.file.accounts[id], !target.server.isEmpty else { throw UserError("That account isn't on this device any more.") }
            if id == s.activeId { return }
            unloadVault()
            // Drop an unfinished "add account" record.
            let unfinished = s.active.map { !$0.isListed } ?? false
            store.update { st in
                if unfinished { st.file.accounts[st.file.activeId] = nil }
                st.file.activeId = id
            }
            if sessions[id] != nil { try? await syncLocked(fallbackToCache: true, cacheFirst: true) }
            refreshIdentities()
        }
    }

    /// Start adding an account: an empty record becomes active until it's signed in or cancelled.
    public func addAccount() async throws {
        try await lock.run {
            let s = store.get()
            if s.file.accounts.values.filter(\.isListed).count >= maxAccounts {
                throw UserError("PassAuth supports up to \(maxAccounts) accounts. Log out of one first.")
            }
            unloadVault()
            let id = UUID().uuidString.lowercased()
            store.update { st in
                st.file.accounts = st.file.accounts.filter { !$0.value.server.isEmpty && (!$0.value.email.isEmpty || st.secrets.tokens[$0.key] != nil) }
                st.file.accounts[id] = AccountData()
                st.file.activeId = id
            }
        }
    }

    /// Leave an unfinished "add account" and go back to `to`.
    public func cancelAddAccount(to: String) async {
        await lock.run {
            let s = store.get()
            if s.tokens(s.activeId) == nil, s.file.accounts[to] != nil {
                store.update { st in
                    st.file.accounts[st.file.activeId] = nil
                    st.file.activeId = to
                }
            }
            if sessions[to] != nil { try? await syncLocked(fallbackToCache: true) }
        }
    }

    // MARK: Settings

    public func updateSettings(_ transform: (inout Settings) -> Void) async {
        let before = store.get().settings
        store.update { transform(&$0.file.settings) }
        let after = store.get().settings
        if before.defaultMatch != after.defaultMatch && vault != nil { refreshIdentities() }
        guard before.vaultTimeout != after.vaultTimeout else { return }
        await lock.run {
            if after.vaultTimeout == .never {
                for id in sessions.keys { persistForNever(id) }
            } else {
                store.update { $0.secrets.persistedKeys = [:] }
            }
        }
    }

    // MARK: Sync

    public func sync() async throws {
        try await lock.run { try await syncLocked() }
    }

    /// Re-sync if the server has newer data (cheap revision check). When the server's revision
    /// is the one already shown, the copy is current: only the offline mark is dropped (no
    /// `/sync`, decrypt or cache re-seal). An unanswered revision call keeps it.
    public func refreshIfStale() async {
        guard let current = vault else { return }
        let id = activeId
        guard let r = try? await api.call(id, "/sync/revision")["revision"]?.int else { return }
        if r > current.revision {
            await lock.run { try? await syncLocked() }
        } else if current.offline {
            await lock.run {
                guard activeId == id, let v = vault, v.offline, v.revision == current.revision else { return }
                vault?.offline = false
            }
        }
    }

    /// Fetch and decrypt the active account's vault. With `fallbackToCache` an unreachable
    /// server shows the on-device copy (offline). With `cacheFirst` the on-device copy is shown
    /// straight away: in the app the server sync then runs in the background (unlocking doesn't
    /// wait for a slow or unreachable server); the AutoFill extension (`preferCache`) shows it
    /// as offline and syncs only when needed.
    func syncLocked(fallbackToCache: Bool = false, cacheFirst: Bool = false) async throws {
        let id = activeId
        guard let session = sessions[id] else { return }
        var data: Data
        var offline = false
        var fromServer = true
        do {
            if cacheFirst, let cached = await store.readCacheInBackground(id) {
                data = cached
                offline = preferCache
                fromServer = false
            } else {
                data = try await api.callData(id, "/sync")
            }
        } catch {
            guard fallbackToCache, let cached = await store.readCacheInBackground(id) else {
                if fallbackToCache && !(error is ApiError) {
                    var empty = VaultData()
                    empty.offline = true
                    vault = empty
                    return
                }
                throw error
            }
            data = cached
            offline = true
            fromServer = false
        }
        guard sessions[id] === session else { return }
        let account = session.account
        let raw = data
        let (next, keys, user, bundle) = try await core { try Self.decryptVault(account, raw) }
        guard sessions[id] === session, activeId == id else { return }
        if fromServer {
            await store.writeCacheInBackground(id, data)
            store.updateAccount(id) { a in
                a.lastSync = Date().timeIntervalSince1970
                if let user { a.name = user }
                if let bundle { a.bundle = bundle }
            }
        }
        guard sessions[id] === session, activeId == id else { return }
        vaultKeys = keys
        var v = next
        v.offline = offline
        vault = v
        refreshIdentities()
        if cacheFirst && !fromServer && !offline {
            // Queued behind the current operation (the lock is first in, first out), so a change
            // the user makes next runs after this sync.
            Task { @MainActor [weak self] in await self?.backgroundSync(id, session) }
        }
    }

    /// Background App Refresh: keep an account's encrypted offline copy current without
    /// unlocking it. The `/sync` body is stored as the server sent it (ciphertext and metadata;
    /// nothing is decrypted or kept in memory, the identity store isn't touched), and only when
    /// it is a valid sync response at least as new as the copy on disk ([offlineCopyUpdate]).
    /// The active account, when unlocked, gets a normal sync instead.
    public func refreshCacheLocked(accountId id: String) async throws {
        if sessions[id] != nil && activeId == id {
            try await lock.run { try await syncLocked() }
            return
        }
        let s = store.get()
        guard let a = s.file.accounts[id], a.isListed, s.tokens(id) != nil else { return }
        let data = try await api.callData(id, "/sync")
        try Task.checkCancellation()
        let cached = await store.readCacheInBackground(id)
        guard let update = try await core({ Self.offlineCopyUpdate(fetched: data, cached: cached) }) else {
            throw UserError("The server's answer couldn't be read.")
        }
        try Task.checkCancellation()
        await lock.run {
            // Unlocked and shown meanwhile: its own sync writes the copy.
            guard !(sessions[id] != nil && activeId == id) else { return }
            await store.writeCacheInBackground(id, data)
            store.updateAccount(id) { a in
                a.lastSync = Date().timeIntervalSince1970
                if let bundle = update.bundle { a.bundle = bundle }
            }
        }
    }

    /// Decides what a locked cache refresh may write: `fetched` must decode as a sync response
    /// (numeric revision, bundle, vaults and items present; well-formed rows) and must not be
    /// older than the `cached` copy (never downgrade). An unreadable cached copy is replaced.
    nonisolated public static func offlineCopyUpdate(fetched: Data, cached: Data?) -> OfflineCopyUpdate? {
        guard let res = try? JSONDecoder().decode(SyncResponse.self, from: fetched),
              let revision = res.revision, res.vaults != nil, res.items != nil,
              let bundle = res.bundle, bundle != .null else { return nil }
        if let cached, let old = try? JSONDecoder().decode(SyncRevision.self, from: cached),
           let oldRevision = old.revision, revision < oldRevision {
            return nil
        }
        return OfflineCopyUpdate(revision: revision, bundle: bundle.text)
    }

    private struct SyncRevision: Decodable { let revision: Int64? }

    /// The server sync after a cache-first unlock; an unreachable server leaves the copy marked offline.
    private func backgroundSync(_ id: String, _ session: Session) async {
        await lock.run {
            guard sessions[id] === session, activeId == id else { return }
            do {
                try await syncLocked()
            } catch {
                if sessions[id] === session, activeId == id { vault?.offline = true }
            }
        }
    }

    /// After a write the server already has the change: a failed follow-up sync must not report
    /// the save as failed (a retry would duplicate it). The next revision check syncs again.
    func syncAfterWrite() async {
        do {
            try await syncLocked()
        } catch {
            vault?.offline = true
        }
    }

    /// Write the active account's logins to the AutoFill identity store (or empty it when the
    /// active account is locked or signed out).
    public func refreshIdentities() {
        let s = store.get()
        identities.seed(s.file.identityFingerprint)
        guard let v = vault, sessions[s.activeId] != nil else { return identities.clear() }
        identities.replace(IdentityMapper.records(v.entries, defaultMatch: s.settings.defaultMatch))
    }

    private struct SyncResponse: Decodable {
        struct VaultRow: Decodable {
            let id: String
            let wrapped_key: String
            let key_kind: String
            let meta: String
            let role: String
        }
        struct ItemRow: Decodable {
            let id: String
            let vault_id: String
            let item_key: String
            let data: String
            let revision: Int64?
            let deleted_at: JSON?
        }
        struct User: Decodable { let name: String? }
        let vaults: [VaultRow]?
        let items: [ItemRow]?
        let revision: Int64?
        let user: User?
        let bundle: JSON?
    }

    nonisolated private static func decryptVault(_ account: Account, _ data: Data) throws -> (VaultData, [String: VaultKey], String?, String?) {
        let res = try JSONDecoder().decode(SyncResponse.self, from: data)
        var keys: [String: VaultKey] = [:]
        var out = VaultData()
        for v in res.vaults ?? [] {
            // A vault key that can't be opened (rotated) is skipped.
            guard let key = try? account.openVaultKey(vaultId: v.id, wrapped: v.wrapped_key, kind: v.key_kind) else { continue }
            let name = (try? key.decryptMeta(vaultId: v.id, meta: v.meta)).flatMap { try? JSON.parse($0) }?.str("name") ?? ""
            keys[v.id] = key
            out.vaults.append(VaultInfo(id: v.id, name: name.isEmpty ? "Vault" : name, role: Role(rawValue: v.role) ?? .read,
                                        keyKind: v.key_kind.isEmpty ? VaultInfo.accountKeyKind : v.key_kind))
        }
        for row in res.items ?? [] {
            guard let key = keys[row.vault_id] else { continue }
            let enc = EncryptedItem(id: row.id, vaultId: row.vault_id, key: row.item_key, data: row.data)
            // An undecryptable item is skipped.
            guard let json = try? key.decryptItem(encrypted: enc), let item = try? ItemCodec.decode(json) else { continue }
            let deleted: Int64? = switch row.deleted_at {
            case .none, .some(.null): nil
            case .some(let j): j.int
            }
            let e = Entry(id: row.id, item: item, vaultId: row.vault_id, revision: row.revision ?? 0, enc: enc, deletedAt: deleted)
            if deleted == nil { out.entries.append(e) } else { out.trash.append(e) }
        }
        out.entries.sort { $0.item.name.localizedCaseInsensitiveCompare($1.item.name) == .orderedAscending }
        out.trash.sort { ($0.deletedAt ?? 0) > ($1.deletedAt ?? 0) }
        out.revision = res.revision ?? 0
        let bundle: String? = switch res.bundle {
        case .none, .some(.null): nil
        case .some(let b): b.text
        }
        return (out, keys, res.user?.name, bundle)
    }

    // MARK: Items

    private var now: Int64 { Int64(Date().timeIntervalSince1970) }

    private func requireVault() throws -> VaultData {
        guard let v = vault else { throw UserError("Your vault is locked.") }
        if v.offline { throw UserError("You're offline. Changes can be saved once PassAuth reaches your server.") }
        return v
    }

    private func writableVault(_ v: VaultData) throws -> VaultInfo {
        if let o = v.defaultVault { return o }
        throw UserError("Your own vault isn't available. Choose a vault to save to.")
    }

    @discardableResult
    public func createItem(_ item: Item, vaultId: String?) async throws -> String {
        try await lock.run {
            let v = try requireVault()
            let target = try vaultId.flatMap { id in v.vaults.first { $0.id == id } } ?? writableVault(v)
            guard let key = vaultKeys[target.id] else { throw UserError("Vault not found.") }
            var next = item
            next.createdAt = now
            next.updatedAt = now
            let json = ItemCodec.encode(next)
            let targetId = target.id
            let (id, enc) = try await core { () -> (String, EncryptedItem) in
                let id = try newId()
                return (id, try key.encryptItem(itemJson: json, id: id, vaultId: targetId))
            }
            _ = try await api.call(activeId, "/items", body: Self.json(enc))
            await syncAfterWrite()
            return id
        }
    }

    /// Save changes to an item; with another `targetVaultId` the item also moves to that vault
    /// (re-encrypted with its key under the same id), like the web vault's `updateItem`.
    /// Throws [ConflictError] when the item changed on the server since `entry` was read.
    public func updateItem(_ entry: Entry, _ item: Item, targetVaultId: String? = nil) async throws {
        try await lock.run {
            let v = try requireVault()
            guard let vault = v.vaults.first(where: { $0.id == entry.vaultId }) else { throw UserError("Vault not found.") }
            if vault.role == .read { throw UserError("You can only view items in this vault.") }
            let targetId = targetVaultId ?? entry.vaultId
            guard let target = v.vaults.first(where: { $0.id == targetId }) else { throw UserError("Vault not found.") }
            if target.role == .read { throw UserError("You can't add items to \(target.name).") }
            guard let key = vaultKeys[target.id] else { throw UserError("Vault not found.") }
            var next = item
            next.updatedAt = now
            let old = entry.item.login?.password ?? ""
            if next.login != nil, !old.isEmpty, old != next.login?.password, next.passwordHistory == entry.item.passwordHistory {
                next.passwordHistory = Array(([PasswordChange(password: old, changedAt: now)] + next.passwordHistory).prefix(20))
            }
            let json = ItemCodec.encode(next)
            let enc0 = entry.enc
            let same = target.id == entry.vaultId
            let entryId = entry.id
            let enc = try await core { same ? try key.updateItem(encrypted: enc0, itemJson: json) : try key.encryptItem(itemJson: json, id: entryId, vaultId: targetId) }
            var body = Self.json(enc)
            if case .object(var o) = body {
                o["revision"] = .int(entry.revision)
                body = .object(o)
            }
            do {
                _ = try await api.call(activeId, "/items/\(entry.id)", body: body, method: "PUT")
            } catch let e as ApiError where e.status == 409 {
                throw ConflictError(itemId: entry.id)
            }
            await syncAfterWrite()
        }
    }

    public func setFavorite(_ entry: Entry, _ favorite: Bool) async throws {
        var i = entry.item
        i.favorite = favorite
        try await updateItem(entry, i)
    }

    public func trashItem(_ entry: Entry) async throws {
        try await lock.run {
            let v = try requireVault()
            if !v.canWrite(entry) { throw UserError("You can only view items in this vault.") }
            _ = try await api.call(activeId, "/items/\(entry.id)", method: "DELETE")
            await syncAfterWrite()
        }
    }

    public func restoreItem(_ entry: Entry) async throws {
        try await lock.run {
            let v = try requireVault()
            if !v.canWrite(entry) { throw UserError("You can only view items in this vault.") }
            _ = try await api.call(activeId, "/items/\(entry.id)/restore", method: "POST")
            await syncAfterWrite()
        }
    }

    /// Delete an item in the trash for good.
    public func purgeItem(_ entry: Entry) async throws {
        try await lock.run {
            let v = try requireVault()
            if !v.canWrite(entry) { throw UserError("You can only view items in this vault.") }
            _ = try await api.call(activeId, "/items/\(entry.id)/permanent", method: "DELETE")
            await syncAfterWrite()
        }
    }

    /// Move an item to another vault the user can write to (re-encrypted with that vault's key
    /// under the same id; `PUT /api/items/{id}` with the new `vault_id` and the old revision).
    public func moveItem(_ entry: Entry, to vaultId: String) async throws {
        if vaultId == entry.vaultId { return }
        try await updateItem(entry, entry.item, targetVaultId: vaultId)
    }

    /// Vaults an item can move to: other vaults where the user may add items (owner, admin, write).
    public func moveTargets(_ entry: Entry) -> [VaultInfo] {
        (vault?.vaults ?? []).filter { $0.id != entry.vaultId && $0.role != .read }
    }

    // MARK: Re-authentication, account

    /// A fresh proof of the master password from the server: an OPAQUE login with
    /// `purpose: "reauth"` on the signed-in session (the web vault's `reauth`). The token is
    /// good for one sensitive request within five minutes.
    func reauthToken(_ id: String, password: String, secretKey: String?) async throws -> String {
        let s = store.get()
        guard let a = s.file.accounts[id], s.tokens(id) != nil else { throw UserError("Sign in first.") }
        let typed = secretKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        let sk = (typed?.isEmpty == false ? typed : nil) ?? s.secrets.secretKeys[a.email.lowercased()]
        let pre = try await api.call(id, "/auth/prelogin", body: ["email": .string(a.email)], auth: false)
        let skRequired = pre["secret_key_required"]?.bool ?? false
        if skRequired && sk == nil { throw UserError(secretKeyRequiredMessage) }
        let accountId = pre.str("account_id")
        let kdf = (pre["kdf"] ?? .null).text
        let skArg = skRequired ? sk : nil
        let master = try await core { try deriveMasterKeys(password: password, secretKey: skArg, accountId: accountId, kdfJson: kdf, secretKeyRequired: skRequired) }
        let start = try await core { try opaqueLoginStart(master: master) }
        let resp = try await api.call(id, "/auth/login/start", body: ["email": .string(a.email), "message": .string(start.message)], auth: false)
        let message = resp.str("message")
        let fin: String
        do {
            fin = try await core { try opaqueLoginFinish(state: start.state, master: master, response: message) }
        } catch is CoreError {
            throw UserError("Wrong master password or Secret Key.")
        }
        let result = try await api.call(id, "/auth/login/finish", body: [
            "login_id": .string(resp.str("login_id")), "message": .string(fin), "device": deviceInfo, "purpose": "reauth",
        ])
        guard let token = result["reauth_token"]?.string, !token.isEmpty else {
            throw UserError("Your server didn't confirm the master password. Try again.")
        }
        return token
    }

    /// Delete the active account on the server (with every vault it owns), after
    /// re-authenticating with the master password, then forget it on this device like Log out.
    public func deleteAccount(password: String, secretKey: String?) async throws {
        try await lock.run {
            let s = store.get()
            let id = s.activeId
            guard let a = s.active else { throw UserError("Sign in first.") }
            if vault?.offline == true { throw UserError("You're offline. Deleting your account needs your server.") }
            let token = try await reauthToken(id, password: password, secretKey: secretKey)
            _ = try await api.call(id, "/account", method: "DELETE", headers: ["x-reauth-token": token])
            // The server has ended every session of this account: no remote logout.
            closeSession(id)
            pendingMaster = nil
            Keychain.deleteBiometric(id)
            store.deleteCache(id)
            let email = a.email.lowercased()
            let sameEmailElsewhere = s.file.accounts.contains { $0.key != id && $0.value.email.lowercased() == email }
            store.update { st in
                if !sameEmailElsewhere { st.secrets.secretKeys[email] = nil }
                st.secrets.rememberTokens["\(a.server)|\(email)"] = nil
            }
            let listed = s.file.accounts.filter { $0.value.isListed }
            if listed.count > 1 || listed[id] == nil {
                await removeAccount(id)
            } else {
                // Keep only the server address, so the sign-in screen still knows where to go.
                store.update { st in
                    st.file.accounts[id] = AccountData(server: a.server)
                    st.secrets.tokens[id] = nil
                    st.secrets.persistedKeys[id] = nil
                }
            }
            refreshIdentities()
        }
    }

    /// Check the master password locally against the account bundle (works offline).
    public func verifyMasterPassword(_ password: String) async throws {
        let s = store.get()
        guard let a = s.active else { throw UserError("Sign in first.") }
        guard let bundle = a.bundle else { throw UserError("Sync your vault first.") }
        let b = try JSON.parse(bundle)
        let skEnabled = b["secret_key_enabled"]?.bool ?? false
        let sk = s.secrets.secretKeys[a.email.lowercased()]
        if skEnabled && sk == nil { throw UserError(secretKeyRequiredMessage) }
        let accountId = b.str("account_id")
        let kdf = (b["kdf"] ?? .null).text
        do {
            _ = try await core {
                let master = try deriveMasterKeys(password: password, secretKey: sk, accountId: accountId, kdfJson: kdf, secretKeyRequired: skEnabled)
                return try master.unlock(bundleJson: bundle).publicKey()
            }
        } catch is CoreError {
            throw UserError("Wrong master password.")
        }
    }

    /// The unlocked vault's items (not the trash) as a JSON array in the item format: the input
    /// of the core's export functions.
    public func itemsJsonForExport() throws -> (json: String, count: Int) {
        guard let v = vault else { throw UserError("Your vault is locked.") }
        return ("[" + v.entries.map { ItemCodec.encode($0.item) }.joined(separator: ",") + "]", v.entries.count)
    }

    /// Live sync's "logout" message: check the session (an ended one signs the account out
    /// through the refresh-token path) and catch up.
    public func checkSession() async { await refreshIfStale() }

    // MARK: Queries (AutoFill, phase 2)

    /// Logins of the unlocked active account that match a web page (default match from settings).
    public func loginsFor(_ pageUrl: String) -> [Entry] {
        let fallback = store.get().settings.defaultMatch
        return (vault?.entries ?? []).filter { e in e.item.login.map { UrlMatcher.matchesAny(pageUrl, $0, fallback: fallback) } ?? false }
    }

    /// Passkeys saved for a relying party.
    public func passkeysFor(_ rpId: String) -> [(Entry, Passkey)] {
        (vault?.entries ?? []).flatMap { e in
            (e.item.login?.passkeys ?? []).filter { $0.rpId.lowercased() == rpId.lowercased() }.map { (e, $0) }
        }
    }

    /// The active account is unlocked in this process.
    public var isUnlocked: Bool { sessions[activeId] != nil }

    /// Argon2id memory of the active account (KiB), from its bundle; nil if unknown.
    public var kdfMemoryKiB: Int64? {
        store.get().active?.bundle.flatMap { try? JSON.parse($0) }?["kdf"]?["memory_kib"]?.int
    }

    /// Save a new passkey (AutoFill) in the login the user chose (`PasskeyLogic.saveTargets`),
    /// or a new login. Syncs first, so the vault isn't the offline copy and revisions are current.
    public func storePasskey(_ p: Passkey, target: String) async throws {
        try await sync()
        guard let v = vault else { throw UserError("Your vault is locked.") }
        switch PasskeyLogic.storePlan(v, p, target: target) {
        case .attach(let e, let item): try await updateItem(e, item)
        case .create(let item): try await createItem(item, vaultId: nil)
        }
    }

    public enum SaveOutcome: Sendable { case created, updated, unchanged }

    /// The vault no longer allows what was about to be saved the way it was shown or decided
    /// (the chosen login is gone or not offered any more, the default changed, or the default
    /// needs the user to see it): nothing was written; show the choices again.
    public struct SaveChoiceChanged: Error, Equatable {
        public init() {}
    }

    /// Save a login AutoFill was handed (`SaveLogic`): update a login already saved for the
    /// site (password, and the user name if one was typed; the old password goes into the
    /// history), or create a new login. Syncs first, so it works on the server's current items
    /// and revisions, not the offline copy, and then applies exactly `target`:
    ///
    /// - `target`: the "Save in" choice that was shown or decided (an entry id or
    ///   `SaveLogic.newLogin`). After the sync it must still be one of `SaveLogic.targets`,
    ///   else `SaveChoiceChanged` is thrown and nothing is written. It is never swapped for
    ///   another login.
    /// - `isDefault`: `target` is the default plan's choice, not one the user picked. If the
    ///   synced vault makes another default (say the login was saved on another device
    ///   meanwhile), nothing is written either: already saved → `.unchanged`, otherwise
    ///   `SaveChoiceChanged`.
    /// - `target == nil`: the default plan of the synced vault, without any sheet. A rule-3
    ///   update ("no user name typed, the only login for the site") is refused here with
    ///   `SaveChoiceChanged`: it is only applied after the user saw which login changes.
    public func saveLogin(page: String, username: String, password: String, target: String? = nil, isDefault: Bool = false) async throws -> SaveOutcome {
        guard !password.isEmpty else { throw UserError("There is no password to save.") }
        try await sync()
        guard let v = vault else { throw UserError("Your vault is locked.") }
        let match = store.get().settings.defaultMatch
        let fresh = SaveLogic.plan(page: page, username: username, password: password, vault: v, defaultMatch: match)
        let plan: SaveLogic.Plan
        if let target {
            if isDefault && SaveLogic.defaultTarget(fresh) != target {
                if case .unchanged = fresh { return .unchanged }
                throw SaveChoiceChanged()
            }
            guard let chosen = SaveLogic.plan(target: target, page: page, username: username, password: password, vault: v, defaultMatch: match) else {
                throw SaveChoiceChanged()
            }
            // The default "New login" of a credential that is in the vault by now: nothing to add.
            if isDefault, case .create = chosen, case .unchanged = fresh { return .unchanged }
            plan = chosen
        } else {
            if case .update(_, .only) = fresh { throw SaveChoiceChanged() }
            plan = fresh
        }
        switch plan {
        case .create:
            try await createItem(SaveLogic.newItem(page: page, username: username, password: password), vaultId: nil)
            return .created
        case .update(let e, _):
            try await updateItem(e, SaveLogic.updatedItem(e, username: username, password: password))
            return .updated
        case .unchanged:
            return .unchanged
        case .readOnly(let e):
            throw UserError("This login is in \(v.vaultName(e.vaultId)), which you can only view.")
        case .noPassword:
            throw UserError("There is no password to save.")
        }
    }

    // MARK: Helpers

    private static func json(_ e: EncryptedItem) -> JSON {
        ["id": .string(e.id), "vault_id": .string(e.vaultId), "key": .string(e.key), "data": .string(e.data)]
    }

    nonisolated static func bundleAccountId(_ bundle: String) -> String {
        (try? JSON.parse(bundle))?.str("account_id") ?? ""
    }

    /// Hosts where plain http is allowed: this device and local-network addresses (test servers).
    /// This device only (no network involved).
    nonisolated public static func isLoopback(_ host: String) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if h == "localhost" || h == "::1" || h.hasSuffix(".localhost") { return true }
        let parts = h.split(separator: ".")
        return parts.count == 4 && parts.first == "127" && parts.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
    }

    /// A plain http address that travels over the network (allowed only after the user confirms).
    nonisolated public static func plainHttpOnNetwork(_ origin: String) -> Bool {
        guard let p = UrlMatcher.parse(origin), p.scheme == "http" else { return false }
        return !isLoopback(p.hostname)
    }

    nonisolated public static func isLocalHost(_ host: String) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if h == "localhost" || h == "::1" || h.hasSuffix(".local") || h.hasSuffix(".localhost") { return true }
        let parts = h.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, h.split(separator: ".").count == 4, parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        switch (parts[0], parts[1]) {
        case (127, _), (10, _), (192, 168), (169, 254): return true
        case (172, 16...31): return true
        default: return false
        }
    }

    /// The server address as an origin (plus path), https only except local development hosts.
    nonisolated public static func normalizeServer(_ url: String) throws -> String {
        var clean = url.trimmingCharacters(in: .whitespacesAndNewlines)
        while clean.hasSuffix("/") { clean.removeLast() }
        if clean.isEmpty { throw UserError("Enter your server address.") }
        guard let p = UrlMatcher.parse(clean), !p.hostname.isEmpty else { throw UserError("That isn't a valid server address.") }
        if p.scheme != "https" && !(p.scheme == "http" && isLocalHost(p.hostname)) {
            throw UserError("Use an https:// address. Plain http is only allowed for this device and local network addresses.")
        }
        var path = p.path
        while path.hasSuffix("/") { path.removeLast() }
        return p.origin + path
    }
}

#if os(macOS)
// MARK: Timed unlock (macOS AutoFill extension)

/// macOS starts the AutoFill extension anew for most requests, so its vault timeout keeps the
/// unlocked keys (session bytes, as for the timeout "Never") in its own Keychain until the
/// timeout passes (`desktop/macos/AutoFill/TimedUnlock.swift`).
extension VaultRepository {
    /// The active account's unlocked keys, nil while locked. Wipe the copy after use.
    public func activeSessionBytes() -> Data? {
        sessions[activeId]?.account.toSessionBytes()
    }

    /// Reopen the active account from kept session bytes; false if they don't fit its bundle.
    public func openActive(sessionBytes: Data) async -> Bool {
        await lock.run {
            let s = store.get()
            let id = s.activeId
            guard sessions[id] == nil, let bundle = s.active?.bundle, s.tokens(id) != nil else { return sessions[id] != nil }
            let accountId = Self.bundleAccountId(bundle)
            let copy = sessionBytes
            guard let account = try? await core({ try accountFromSessionBytes(accountId: accountId, bytes: copy) }) else { return false }
            openSession(id, Session(accountId: accountId, account: account))
            try? await syncLocked(fallbackToCache: true, cacheFirst: true)
            return true
        }
    }
}
#endif

/// Thrown by `setServer` for plain http to a local-network address: ask the user first.
public struct PlainHttpConfirmation: Error, Sendable {
    public let host: String
}

extension Data {
    /// Overwrite the bytes with zeros (best effort for key material).
    mutating func wipe() {
        let n = count
        guard n > 0 else { return }
        withUnsafeMutableBytes { p in
            if let b = p.baseAddress { memset_s(b, n, 0, n) }
        }
    }
}
