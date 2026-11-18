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
    /// Website icons for the active account: the user's setting and the server's icon service
    /// (`SiteIcons.shown`).
    public var showSiteIcons = true
    public var lastSync: Double = 0
    /// The active record is an unfinished "add account".
    public var adding = false
    /// The active account's server's policies (the defaults when it has none).
    public var policies = Policies()
    /// The longest vault timeout the signed-in accounts' servers allow, in minutes; 0 = no limit.
    public var timeoutLimit = 0
    /// The active account's server requires two-step login and the account has no method yet:
    /// the app shows the setup screen instead of the vault (`TwoStepGate`).
    public var twoStepRequired = false
    /// What the active account still has to change for its server's policies.
    public var policyViolations: [PolicyViolation] = []
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

/// What `rotateVaultKeys` did: the vaults given a new key, the shared ones it left (a server
/// without signed sharing: this app only seals keys to other members with signatures), and the
/// ones waiting for the user to confirm that people the signed member list names are gone.
public struct KeyReplacement: Equatable, Sendable {
    public struct Shared: Equatable, Sendable {
        public var id: String
        public var name: String

        public init(id: String, name: String) {
            self.id = id
            self.name = name
        }
    }
    /// A vault whose signed member list names people the server no longer lists (they left,
    /// declined or were removed): its key is replaced only once the user confirms.
    public struct Confirm: Equatable, Sendable {
        public var id: String
        public var name: String
        /// Their emails as this device knows them, else "a former member".
        public var people: [String]
        /// Their user ids (what the confirmation covers).
        public var userIds: [String]

        public init(id: String, name: String, people: [String], userIds: [String] = []) {
            self.id = id
            self.name = name
            self.people = people
            self.userIds = userIds
        }
    }
    /// A shared vault without a trusted (signed) member list: its key is replaced only after the
    /// user checked every member in the review and confirmed it (version 1 of its roster).
    public struct Review: Equatable, Sendable, Identifiable {
        public var id: String
        public var name: String
        public var review: MemberReview

        public init(id: String, name: String, review: MemberReview) {
            self.id = id
            self.name = name
            self.review = review
        }
    }
    public var rotated: [String] = []
    public var shared: [Shared] = []
    public var confirm: [Confirm] = []
    public var review: [Review] = []

    public init(rotated: [String] = [], shared: [Shared] = [], confirm: [Confirm] = [], review: [Review] = []) {
        self.rotated = rotated
        self.shared = shared
        self.confirm = confirm
        self.review = review
    }

    /// The confirmations as `rotateVaultKeys(confirmed:)` takes them: per vault, the user ids
    /// shown (a confirmation for one vault doesn't carry over to another).
    public var confirmedIds: [String: Set<String>] {
        Dictionary(confirm.map { ($0.id, Set($0.userIds)) }, uniquingKeysWith: { a, b in a.union(b) })
    }

    /// "bob@example.com is no longer a member of Family. Replace its key without them?", or nil.
    public var confirmText: String? {
        guard !confirm.isEmpty else { return nil }
        return confirm.map { c in
            let name = c.name.isEmpty ? "a vault" : c.name
            var who = c.people.joined(separator: ", ")
            // "a former member" opens the sentence: capitalised (emails are left as they are).
            if who.hasPrefix(SharingText.unknownMember) { who = "A" + who.dropFirst() }
            return "\(who) \(c.people.count == 1 ? "is" : "are") no longer \(c.people.count == 1 ? "a member" : "members") of \(name)."
        }.joined(separator: " ") + " Replace the " + (confirm.count == 1 ? "key" : "keys") + " without them?"
    }

    /// "Family is shared, so its key can only be replaced in the web vault or the desktop app.", or nil.
    public var sharedText: String? {
        guard !shared.isEmpty else { return nil }
        let names = shared.map { $0.name.isEmpty ? "A vault" : $0.name }.joined(separator: ", ")
        return shared.count == 1
            ? "\(names) is shared, so replace its key in the web vault or the desktop app."
            : "\(names) are shared, so replace their keys in the web vault or the desktop app."
    }
}

public struct VaultInfo: Identifiable, Equatable, Sendable {
    public static let accountKeyKind = "account"

    public let id: String
    public let name: String
    public let role: Role
    /// `account`: the vault key is wrapped with this account's own key (only this account can
    /// have made it). `sealed`: someone shared the vault with this account.
    public let keyKind: String
    /// The epoch of the vault key this device holds, from `/sync` (API v2: goes up by one with
    /// every key replacement); nil from older servers. Writes encrypted under that key carry it
    /// (`key_epoch`), so the server refuses them once the key was replaced.
    public let keyEpoch: Int64?
    /// What signed sharing's checks found (`notChecked` on servers without it).
    public let trust: VaultTrust

    public init(id: String, name: String, role: Role, keyKind: String = VaultInfo.accountKeyKind, keyEpoch: Int64? = nil,
                trust: VaultTrust = .notChecked) {
        self.id = id
        self.name = name
        self.role = role
        self.keyKind = keyKind
        self.keyEpoch = keyEpoch
        self.trust = trust
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
    /// Vaults shared with the account and waiting for an answer (the app only; the AutoFill
    /// extensions ignore invitations).
    public var invitations: [Invitation] = []
    /// Shared vaults signed sharing's checks refused: not in `vaults`, their items nowhere (no
    /// fill, save, passkey or display); the app says why.
    public var refused: [RefusedVault] = []

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
    /// In one of the account's own vaults (key wrapped with its own key), whatever the role: the
    /// only logins whose regular-expression websites are used for matching (`AutofillMatcher`).
    /// A login whose vault is unknown counts as somebody else's.
    public func isPersonal(_ e: Entry) -> Bool { vaults.first { $0.id == e.vaultId }?.personal ?? false }
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

/// What one decryption of the copy produced, kept so the next one decrypts only what changed:
/// the shown vault, the opened vault keys and the headers they were opened from.
struct OpenedVault: Sendable {
    var data: VaultData
    var keys: [String: VaultKey]
    var headers: [String: SyncVault]
    /// Vault names read from invitations, by sealed key and encrypted name (nil: can't be opened).
    var names: [String: String?] = [:]
    /// Signed sharing: the key pins and device memory after the checks (nil when they didn't run).
    var sharing: SharingOutputs?
}

/// Unlocked keys of one account, in memory only (Rust handles, freed when released).
final class Session {
    let accountId: String
    let account: Account
    /// Signed sharing: the account's signing identity as opened while unlocked (nil: none yet, or
    /// the record didn't open), the server's record it was opened from, whether sharing is paused
    /// (`identity_mismatch`), whether this unlock already tried to make one, made one, and found
    /// the account's trust memory missing.
    var openedSigning: SigningIdentity?
    var signingRecord: JSON?
    var signingPaused = false
    /// The identity upload was answered (created, 404 or 409): not sent again by this unlock.
    var identityTried = false
    var identityCreated = false
    /// The last sync's checks may keep what they decide (the server has shown it signs).
    var sharingProven = false
    /// The key pins of the last checks this unlock (read-only fallback while this device's memory
    /// can't be read).
    var lastPins: String?
    /// The vault ids of the account's offline copy on this device when this unlock started
    /// (grandfathering rule 1; nil: none), read once (`earlierCopyRead`) before this session
    /// stores a copy of its own.
    var earlierCopy: Set<String>?
    var earlierCopyRead = false
    /// The identity this device signs with: none while paused.
    var signing: SigningIdentity? { signingPaused ? nil : openedSigning }
    /// The account id the core authenticated (the unlocked account's own id): "me" for signed
    /// sharing and emergency access, never `/sync` `user.id`.
    lazy var meId: String = {
        (try? account.legacyIdentityJson()).flatMap { try? JSON.parse($0) }?.str("user_id") ?? ""
    }()
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
    @ObservationIgnored var vaultKeys: [String: VaultKey] = [:]
    /// The vault headers `vaultKeys` were opened from (a changed header opens the key again).
    @ObservationIgnored private var vaultHeaders: [String: SyncVault] = [:]
    /// The active account's copy behind `vault` (ciphertext, cursor, vault numbers): the base of
    /// the next delta sync and of local changes after this device's writes.
    @ObservationIgnored private var copy: (account: String, snapshot: SyncSnapshot)?
    /// Public syncs: one in flight, one waiting (`SyncQueue`).
    @ObservationIgnored private let syncQueue = SyncQueue()
    @ObservationIgnored private var pendingMaster: MasterKeys?
    @ObservationIgnored private var pendingRemember = ""
    /// A sign-in request to another device in progress (`beginDeviceLogin`): its key, made for
    /// it and never stored, waits here in memory, also through two-step login.
    @ObservationIgnored var pendingDevice: PendingDeviceLogin?
    /// Another device's approval of that request, waiting for the code it shows
    /// (`confirmDeviceLogin`); memory only, nothing of it stored before the code is confirmed.
    @ObservationIgnored var approvedDevice: ApprovedDeviceLogin?
    /// How the device sign-in waits between polls; tests make it instant (real time otherwise).
    @ObservationIgnored public var deviceLoginSleep: (@Sendable (Double) async throws -> Void)?
    /// Vault names read from the invitations shown now (see `OpenedVault.names`).
    @ObservationIgnored private var invitationNames: [String: String?] = [:]
    /// Accounts whose server answered 403 `two_step_required` (memory only): the app shows the
    /// two-step setup screen for them until a sync goes through.
    private var twoStepGated: Set<String> = []
    /// `policy_violations` per account (`GET /account` after sign-in and unlock; memory only).
    private var violations: [String: [PolicyViolation]] = [:]
    /// Signed sharing: what this device remembers per account (its key pins version, the rosters
    /// it trusted); the Keychain, or memory in tests.
    @ObservationIgnored public var sharingMemory: SharingMemory = KeychainSharingMemory()
    /// Invitations' roster chains fetched for their checks, by vault, with the latest roster they end at.
    @ObservationIgnored var invitationChains: [String: (latest: String, chain: [String])] = [:]
    /// Signed sharing: tombstones of vaults declined on the server whose key pins write failed,
    /// by account (vault id → trusted roster version), also kept in the device memory when it can
    /// be written (`SharingMemoryRecord.tombstones`); written at the next sync.
    @ObservationIgnored var pendingTombstones: [String: [String: UInt64]] = [:]
    /// Signed sharing: the emails a version-1 member review showed, kept with its digest, by
    /// vault: people seen for the first time are pinned with these, not a later members answer's.
    @ObservationIgnored var reviewedEmails: [String: [String: [String: String]]] = [:]
    /// Signed sharing notice for the active account (sharing paused, an older list of known keys); nil: none.
    public internal(set) var sharingNotice: String?
    /// The active account's key pins, as people (Settings → People you share with).
    public internal(set) var knownPeople: [PinnedPerson] = []

    /// The app itself, not an AutoFill extension: it opens invitations to show their vault's name
    /// and follows the server's policies (config, the account's violations, the vault timeout
    /// limit). The extensions ignore both.
    @ObservationIgnored public var isApp = false

    /// Profile pictures cached on this device (the app sets it; the AutoFill extensions show
    /// none). Setting it loads every cached picture into `avatars`.
    @ObservationIgnored public var avatarCache: AvatarCache? {
        didSet { avatars = avatarCache?.all() ?? [:] }
    }
    /// The accounts' profile pictures (JPEG), by account id; no entry: initials.
    public private(set) var avatars: [String: Data] = [:]
    /// The last picture download started after a sync (tests wait for it).
    @ObservationIgnored public private(set) var avatarFetch: Task<Void, Never>?
    @ObservationIgnored private var avatarFetching: Set<String> = []

    /// Ask for trashed items without their key and data (`trash=summary`): the macOS AutoFill
    /// extension never shows the trash and keeps its own copy. On iOS the app shows the trash and
    /// shares its copy with the AutoFill extension, so both fetch it whole.
    @ObservationIgnored public var trashSummary: Bool = {
        #if os(macOS)
        true
        #else
        false
        #endif
    }()

    /// The active account's decrypted vault; nil while locked.
    public private(set) var vault: VaultData?

    /// Emergency access (the app only): the client, made once (`emergency`), and the vault notice
    /// about the contact list the server sent (nil: none). Cleared when the vault closes.
    @ObservationIgnored var emergencyClient: EmergencyClient?
    public internal(set) var emergencyNotice: String?

    /// Called whenever the decrypted vault is dropped (lock, log out, switching or adding an
    /// account): what the app derived from it for this session (password health) goes too.
    @ObservationIgnored public var onVaultClosed: (@MainActor () -> Void)?

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
        api.onTwoStepRequired = { [weak self] id in
            self?.twoStepGated.insert(id)
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
        st.showSiteIcons = SiteIcons.shown(wanted: s.settings.showIcons, api: a?.api, features: a?.features)
        st.lastSync = a?.lastSync ?? 0
        st.adding = a.map { !$0.isListed } ?? false
        st.policies = a?.policies ?? Policies()
        st.timeoutLimit = s.timeoutLimit
        st.twoStepRequired = s.tokens(s.activeId) != nil && twoStepGated.contains(s.activeId)
        st.policyViolations = violations[s.activeId] ?? []
        return st
    }

    var activeId: String { store.get().activeId }

    /// Read the stored state and, with the vault timeout "never", reopen the kept keys (unless a
    /// server's policy now limits the timeout: it is lowered first, which drops them).
    public func start() async {
        store.load()
        await enforceTimeoutLimit()
        if await restorePersisted() { afterOpen() }
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
            dropDeviceLogin()
            closeSession(activeId)
            store.update { st in
                let id = st.file.accounts[st.file.activeId] != nil ? st.file.activeId : UUID().uuidString.lowercased()
                var a = st.file.accounts[id] ?? AccountData()
                a.server = origin
                a.bundle = nil
                a.features = nil
                a.featuresAt = nil
                a.api = nil
                a.policies = nil
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
            dropDeviceLogin()
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
            afterOpen()
            return .done
        }
    }

    /// The second step of a sign-in. After another device's approval (`awaitDeviceLogin`), the
    /// code that device shows comes next (`.enterDeviceCode`, then `confirmDeviceLogin`).
    @discardableResult
    public func verifyTwoFactor(token: String, provider: String, code: String, remember: Bool) async throws -> TwoStepNext {
        try await lock.run {
            let id = activeId
            let clean = code.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: " ", with: "")
            let result = try await api.call(id, "/auth/2fa/verify", body: [
                "two_factor_token": .string(token), "provider": .string(provider), "code": .string(clean), "remember": .bool(remember),
            ], auth: false)
            // Approved by another device, two-step login done: the session comes with the sealed key.
            if let device = pendingDevice {
                try await receiveDeviceApproval(device, result)
                return .enterDeviceCode
            }
            guard let master = pendingMaster else { throw UserError("Sign-in expired. Start again.") }
            pendingMaster = nil
            if let t = result["remember_token"]?.string {
                let k = pendingRemember
                store.update { $0.secrets.rememberTokens[k] = t }
            }
            try await finishLogin(id, master, result)
            try? await syncLocked()
            afterOpen()
            return .signedIn
        }
    }

    public func sendTwoFactorEmail(token: String) async throws {
        _ = try await api.call(activeId, "/auth/2fa/email", body: ["two_factor_token": .string(token)], auth: false)
    }

    private func finishLogin(_ id: String, _ master: MasterKeys, _ result: JSON) async throws {
        let bundle = (result["bundle"] ?? .null).text
        let account = try await core { try master.unlock(bundleJson: bundle) }
        finishSession(id, account: account, result)
    }

    /// What every sign-in does once the account is unlocked (with the master password or another
    /// device's approval): the session answer's tokens and bundle are kept, an older record of
    /// the same account replaced, and the vault opened in memory.
    func finishSession(_ id: String, account: Account, _ result: JSON) {
        let bundle = (result["bundle"] ?? .null).text
        let email = result.str("email")
        let before = store.get()
        let server = before.file.accounts[id]?.server
        // The bundle opened under the Account Key: its account id is authenticated (round 5, iOS H).
        let authenticated = Self.authenticatedId(account)
        // Another account's device memory on this server under this local record (signed out,
        // then signed in as someone else): this sign-in proves the slot is now this account's.
        let memory = sharingMemory.load(id)
        if !memory.unreadable, !memory.userId.isEmpty, memory.userId != authenticated, memory.server.isEmpty || memory.server == server {
            sharingMemory.clear(id)
        }
        // Signing in again to an account that is already listed replaces the old record.
        let dupes = before.file.accounts.filter { $0.key != id && $0.value.server == server && $0.value.email.lowercased() == email.lowercased() }.map(\.key)
        for d in dupes {
            closeSession(d)
            store.deleteCache(d)
            forgetAvatar(d)
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
            a.accountId = authenticated
            a.biometric = false
            s.file.accounts[id] = a
            s.file.activeId = id
            s.secrets.tokens[id] = Tokens(access: result.str("access_token"), refresh: result.str("refresh_token"))
            s.secrets.persistedKeys[id] = nil
        }
        Keychain.deleteBiometric(id)
        twoStepGated.remove(id)
        violations[id] = nil
        openSession(id, Session(accountId: authenticated, account: account))
    }

    /// Create an account on the active record's server (the web vault's Register), with keys
    /// that meet the server's key-derivation policy (`createAccountWithKdf`).
    public func register(email: String, name: String, password: String, withSecretKey: Bool) async throws -> Registered {
        try await lock.run {
            let id = activeId
            let mail = email.trimmingCharacters(in: .whitespacesAndNewlines)
            let initRes = try await api.call(id, "/auth/register/init", body: ["email": .string(mail)], auth: false)
            let accountId = initRes.str("account_id")
            let registrationId = initRes.str("registration_id")
            // New keys follow the server's key-derivation minimums as they are now.
            let kdf = PolicyRules.kdfMinimums(await publicConfig())
            let created = try await core {
                try createAccountWithKdf(accountId: accountId, password: password, withSecretKey: withSecretKey,
                                         minMemoryMib: kdf.memoryMib, minIterations: kdf.iterations)
            }
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
            let fetched: Bool
            if let b = a.bundle {
                bundle = b
                fetched = false
            } else {
                // Stored only once it opened under the master password (below).
                bundle = (try await api.call(id, "/sync")["bundle"] ?? .null).text
                fetched = true
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
            // Opened with the master password: the bundle's account id is authenticated.
            let authenticated = Self.authenticatedId(account)
            store.updateAccount(id) { acc in
                if fetched { acc.bundle = bundle }
                acc.accountId = authenticated
            }
            openSession(id, Session(accountId: authenticated, account: account))
            try await syncOrGate(fallbackToCache: true, cacheFirst: true)
            afterOpen()
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
                let copy = bytes
                let known = a.accountId
                guard let restored = try? await core({ Self.restoreSession(bundle: bundle, authenticatedId: known, bytes: copy) }) else {
                    throw UserError(Self.restoreRefused)
                }
                openSession(id, Session(accountId: restored.accountId, account: restored.account))
                try await syncOrGate(fallbackToCache: true, cacheFirst: true)
                afterOpen()
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
                let copy = bytes
                let known = a.accountId
                // Only for the stored bundle the kept keys open (round 5, iOS H); else locked.
                if let r = try? await core({ Self.restoreSession(bundle: bundle, authenticatedId: known, bytes: copy) }) {
                    openSession(id, Session(accountId: r.accountId, account: r.account))
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
        vaultHeaders = [:]
        invitationNames = [:]
        invitationChains = [:]
        copy = nil
        vault = nil
        emergencyNotice = nil
        sharingNotice = nil
        knownPeople = []
        onVaultClosed?()
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
            forgetAvatar(id)
            twoStepGated.remove(id)
            violations[id] = nil
        }
        identities.clear()
    }

    /// Log out of the active account and remove it from this device; the next one becomes active.
    public func logout() async {
        await signOut(remote: true, forgetRememberToken: false)
    }

    /// Sign the active account out on this device (Log out). `remote: false` when the server
    /// already ended the session (this device was forgotten); `forgetRememberToken` drops the
    /// two-step "remember this device" token the server no longer knows.
    func signOut(remote: Bool, forgetRememberToken: Bool) async {
        await lock.run {
            let s = store.get()
            let id = s.activeId
            if remote, let a = s.active { await api.logoutRemote(server: a.server, tokens: s.tokens(id)) }
            if forgetRememberToken, let a = s.active {
                let key = "\(a.server)|\(a.email.lowercased())"
                store.update { $0.secrets.rememberTokens[key] = nil }
            }
            twoStepGated.remove(id)
            violations[id] = nil
            closeSession(id)
            pendingMaster = nil
            Keychain.deleteBiometric(id)
            store.deleteCache(id)
            forgetAvatar(id)
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
        sharingMemory.clear(id)
        forgetAvatar(id)
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

    // MARK: Profile picture

    /// The active account's server has profile pictures (`/api/config` feature `avatar`, as last asked).
    public var avatarsSupported: Bool { cachedFeatures.contains(AvatarImage.feature) }

    /// The active account's picture (JPEG), nil: initials.
    public var activeAvatar: Data? { avatars[activeId] }

    /// Set the active account's picture: `jpeg` is what `AvatarImage.prepare` made. Sealed with
    /// the Account Key, then `PUT /account/avatar`.
    public func setAvatar(_ jpeg: Data) async throws {
        let id = activeId
        guard let session = sessions[id] else { throw UserError("Unlock PassAuth first.") }
        guard jpeg.count <= AvatarImage.maxBytes else { throw UserError("This picture is too large. Choose another one.") }
        let account = session.account
        let sealed = try await core { try account.sealAvatar(image: jpeg) }
        let j: JSON
        do {
            j = try await api.call(id, "/account/avatar", body: ["avatar": .string(sealed)], method: "PUT")
        } catch let e as ApiError where e.status == 413 {
            throw UserError("This picture is too large. Choose another one.")
        }
        keepAvatar(id, seq: j["avatar_seq"]?.number, jpeg: jpeg)
    }

    /// Remove the active account's picture (`DELETE /account/avatar`): initials again.
    public func removeAvatar() async throws {
        let id = activeId
        guard sessions[id] != nil else { throw UserError("Unlock PassAuth first.") }
        let j = try await api.call(id, "/account/avatar", method: "DELETE")
        keepAvatar(id, seq: j["avatar_seq"]?.number, jpeg: nil)
    }

    /// After a sync from the server (the app only): fetch the picture when `user.avatar_seq`
    /// differs from the cached version, drop it when the account has none any more. Runs in the
    /// background; a failure keeps what is cached.
    func refreshAvatar(_ id: String, _ session: Session, serverSeq: Int64?) {
        guard isApp, avatarCache != nil else { return }
        let cached = store.get().file.accounts[id]?.avatarSeq
        switch AvatarSyncAction.decide(serverSeq: serverSeq, cachedSeq: cached, hasFile: avatars[id] != nil) {
        case .none: return
        case .clear: keepAvatar(id, seq: 0, jpeg: nil)
        case .fetch:
            guard !avatarFetching.contains(id) else { return }
            avatarFetching.insert(id)
            avatarFetch = Task { @MainActor [weak self] in
                await self?.fetchAvatar(id, session)
                self?.avatarFetching.remove(id)
            }
        }
    }

    private func fetchAvatar(_ id: String, _ session: Session) async {
        guard let j = try? await api.call(id, "/account/avatar"), sessions[id] === session else { return }
        let seq = j["avatar_seq"]?.number ?? 0
        guard let sealed = j["avatar"]?.string, !sealed.isEmpty else {
            keepAvatar(id, seq: seq, jpeg: nil)
            return
        }
        let account = session.account
        // A picture that doesn't open (another account's, changed) shows the initials; its
        // version is kept, so it isn't fetched again until it changes.
        let jpeg = try? await core { try account.openAvatar(sealed: sealed) }
        guard sessions[id] === session else { return }
        keepAvatar(id, seq: seq, jpeg: jpeg)
    }

    /// Cache (or drop, `jpeg` nil) the account's picture at version `seq`.
    private func keepAvatar(_ id: String, seq: Int64?, jpeg: Data?) {
        if let jpeg, !jpeg.isEmpty {
            avatarCache?.write(id, jpeg)
            avatars[id] = jpeg
        } else {
            avatarCache?.delete(id)
            avatars[id] = nil
        }
        if let seq { store.updateAccount(id) { $0.avatarSeq = seq } }
    }

    /// Log out / removal: the account's picture leaves the device.
    private func forgetAvatar(_ id: String) {
        avatarCache?.delete(id)
        avatars[id] = nil
        store.updateAccount(id) { $0.avatarSeq = nil }
    }

    // MARK: Sync

    /// Sync the active account (pull to refresh, live sync, before AutoFill saves). One sync runs
    /// at a time and at most one waits: a request made while one is waiting joins it.
    public func sync() async throws {
        try await syncQueue.run { try await self.lock.run { try await self.syncLocked() } }
    }

    /// The active account's server's `/api/config` `features` as last asked (empty when never).
    public var cachedFeatures: [String] { store.get().active?.features ?? [] }

    /// The active account's user id: the account id the core authenticated when unlocking (the
    /// server's `user.id` must be the same, else its copy isn't used); "" while locked.
    public var currentUserId: String {
        guard vault != nil, let session = sessions[activeId] else { return "" }
        return session.meId
    }

    /// The copy behind the shown vault when it is `id`'s.
    func copyOf(_ id: String) -> SyncSnapshot? {
        guard let c = copy, c.account == id else { return nil }
        return c.snapshot
    }

    /// The active account's vaults the server marked for a new key (`rotation_pending`: someone
    /// who may hold the key left, or an emergency contact who held it was removed) and that this
    /// account can replace (owner or admin).
    public var pendingRotations: [VaultInfo] {
        guard let v = vault, let c = copy, c.account == activeId else { return [] }
        let marked = Set(c.snapshot.vaults.filter { ($0.rotationPending ?? 0) != 0 }.map(\.id))
        return v.vaults.filter { marked.contains($0.id) && ($0.role == .owner || $0.role == .admin) }
    }

    /// Where the open copy is (revision and vault numbers); nil while locked.
    public var syncPosition: SyncPosition? {
        guard let v = vault else { return nil }
        if let c = copy, c.account == activeId { return c.snapshot.position }
        return SyncPosition(revision: v.revision, vaults: nil)
    }

    /// Re-sync if the server has something the copy lacks (cheap `/sync/revision` check: the
    /// revision and, with delta sync, every vault's number; `SyncDecision.isStale`). When the
    /// copy is current only the offline mark is dropped (no `/sync`, decrypt or cache re-seal).
    /// An unanswered check keeps it.
    public func refreshIfStale() async {
        guard vault != nil, let have = syncPosition else { return }
        let id = activeId
        guard let j = try? await api.call(id, "/sync/revision"), let r = j["revision"]?.int else { return }
        twoStepGated.remove(id)
        if SyncDecision.isStale(revision: r, vaults: DeltaSync.vaultNumbers(j["vaults"]), have: have) {
            try? await sync()
        } else if vault?.offline == true {
            await lock.run {
                guard activeId == id, let v = vault, v.offline, syncPosition == have else { return }
                vault?.offline = false
            }
        }
    }

    /// A whole number in a server answer (nil when absent or not a number).
    nonisolated static func number(_ j: JSON?) -> Int64? { j?.number }


    /// Fetch and decrypt the active account's vault. With `fallbackToCache` an unreachable
    /// server shows the on-device copy (offline). With `cacheFirst` the on-device copy is shown
    /// straight away: in the app the server sync then runs in the background (unlocking doesn't
    /// wait for a slow or unreachable server); the AutoFill extension (`preferCache`) shows it
    /// as offline and syncs only when needed.
    ///
    /// With delta sync the server sends only what changed since the copy's cursor; the merged
    /// copy is decrypted incrementally (`open`) and stored with its new cursor in one write, so a
    /// failed or interrupted sync leaves the previous copy and cursor.
    func syncLocked(fallbackToCache: Bool = false, cacheFirst: Bool = false) async throws {
        let id = activeId
        guard let session = sessions[id] else { return }
        var next: SyncSnapshot
        var offline = false
        var fromServer = true
        do {
            if cacheFirst, let cached = await readSnapshot(id) {
                next = cached
                offline = preferCache
                fromServer = false
            } else {
                next = try await fetchSnapshot(id)
                // The server answered `/sync`: it doesn't (or no longer) require two-step setup first.
                twoStepGated.remove(id)
            }
        } catch {
            // An answer that isn't a vault is an error, not "offline".
            if let e = error as? UserError, e == DeltaSync.unreadable { throw e }
            guard fallbackToCache, let cached = await readSnapshot(id) else {
                if fallbackToCache && !(error is ApiError) {
                    var empty = VaultData()
                    empty.offline = true
                    copy = nil
                    vault = empty
                    return
                }
                throw error
            }
            next = cached
            offline = true
            fromServer = false
        }
        guard sessions[id] === session, activeId == id else { return }
        try await show(id, session, next, offline: offline, store: fromServer ? .synced : .none)
        if cacheFirst && !fromServer && !offline {
            // Queued behind the current operation (the lock is first in, first out), so a change
            // the user makes next runs after this sync.
            Task { @MainActor [weak self] in await self?.backgroundSync(id, session) }
        }
    }

    /// What `show` keeps of a copy besides showing it.
    private enum CopyStore { case none, localChange, synced }

    /// Decrypt `snapshot` (only what changed since the copy shown now) and show it. `.synced`:
    /// fresh from the server, stored as the offline copy with the time of the sync, the profile
    /// name and the bundle; `.localChange`: this device's write applied to the copy, stored too.
    ///
    /// Signed sharing: the signing identity, key pins and newer member rosters are made ready
    /// first (`sharingInputs`; with the server only for a copy fresh from it), every vault and
    /// invitation is checked while decrypting, and afterwards the device memory is saved and the
    /// key pins written when they changed (`finishSharing`).
    private func show(_ id: String, _ session: Session, _ given: SyncSnapshot, offline: Bool, store mode: CopyStore) async throws {
        let account = session.account
        var fresh = given
        if !session.earlierCopyRead {
            // Grandfathering rule 1: what this device showed before this session shows anything.
            _ = await earlierCopy(id, session, given: mode == .none ? given : nil)
        }
        let sharing = try await sharingInputs(id, session, &fresh, network: mode != .none)
        let snapshot = fresh
        guard sessions[id] === session, activeId == id else { return }
        let previous: OpenedVault? = copy?.account == id ? vault.map { OpenedVault(data: $0, keys: vaultKeys, headers: vaultHeaders, names: invitationNames) } : nil
        let invitations = isApp
        let opened = try await core { Self.open(account, snapshot, previous: previous, invitations: invitations, sharing: sharing) }
        guard sessions[id] === session, activeId == id else { return }
        if mode != .none {
            let data = try await core { try snapshot.encoded() }
            await store.writeCacheInBackground(id, data)
            if mode == .synced {
                let bundle = snapshot.bundle?.text
                let storeBundle = bundle.map { Self.bundleMayBeStored($0, account: account, authenticatedId: session.meId) } ?? false
                store.updateAccount(id) { a in
                    a.lastSync = Date().timeIntervalSince1970
                    if let name = snapshot.user?["name"]?.string { a.name = name }
                    if storeBundle, let bundle { a.bundle = bundle }
                    if a.accountId == nil, storeBundle { a.accountId = session.meId }
                }
                refreshAvatar(id, session, serverSeq: snapshot.user?["avatar_seq"]?.number)
            }
        }
        guard sessions[id] === session, activeId == id else { return }
        let before = vault.map { Self.keyShape($0.vaults) }
        vaultKeys = opened.keys
        vaultHeaders = opened.headers
        invitationNames = opened.names
        copy = (id, snapshot)
        var v = opened.data
        v.offline = offline
        vault = v
        refreshIdentities()
        if let out = opened.sharing { await finishSharing(id, session, out, network: mode != .none) }
        // What this device showed as usable: the "earlier copy" of later unlocks (rule 6).
        recordSeen(id, session, v.vaults.map(\.id))
        // A vault came or went, or a key was replaced (here or on another device): personal vaults
        // may need new emergency-access wraps. The first sync after unlocking runs it from `afterOpen`.
        if let before, before != Self.keyShape(v.vaults) { vaultKeysChanged() }
    }

    /// What decides which vaults get emergency-access wraps: each vault's id, key epoch, role and
    /// key kind (a vault becoming the user's own, or shared, changes whether it is personal).
    nonisolated static func keyShape(_ vaults: [VaultInfo]) -> [String] {
        vaults.map { "\($0.id):\($0.keyEpoch ?? -1):\($0.role.rawValue):\($0.keyKind)" }
    }

    /// The account's copy after asking the server: since the copy's cursor when the server does
    /// delta sync, else everything. The base is the copy shown now, or the one on the device.
    func fetchSnapshot(_ id: String) async throws -> SyncSnapshot {
        let base: SyncSnapshot? = if let c = copy, c.account == id { c.snapshot } else { await readSnapshot(id) }
        let delta = await deltaSyncEnabled(id)
        let api = self.api
        return try await DeltaSync.fetch(base: base, delta: delta, trashSummary: trashSummary) { path in
            try await api.callData(id, path)
        }
    }

    /// The account's copy on this device (nil if missing or unreadable), read and decoded off the main thread.
    func readSnapshot(_ id: String) async -> SyncSnapshot? {
        guard let data = await store.readCacheInBackground(id) else { return nil }
        return await Task.detached(priority: .userInitiated) { SyncSnapshot.decode(data) }.value
    }

    /// The active account's server's `/api/config` `features`, asked now (password health
    /// follows the admin's breach-check switch as it is) and kept with the account; nil when the
    /// settings couldn't be loaded.
    public func serverFeatures() async -> [String]? {
        await fetchConfig(activeId)?.features
    }

    /// The account's server's `/api/config`, asked now: its `features` and (with the `policies`
    /// feature) `policies` are kept with the account. nil when it couldn't be read. The app then
    /// applies the vault timeout limit (outside whatever operation asked).
    @discardableResult
    func fetchConfig(_ id: String) async -> PublicConfig? {
        guard let a = store.get().file.accounts[id], !a.server.isEmpty, let url = URL(string: a.server + "/api/config"),
              let (data, res) = try? await api.get(url), res.statusCode == 200,
              let j = try? JSON.parse(data), let config = PublicConfig(json: j) else { return nil }
        let before = store.get().file.accounts[id]?.policies
        store.updateAccount(id) { a in
            a.features = config.features
            a.featuresAt = Date().timeIntervalSince1970
            a.api = config.api
            a.policies = config.features.contains(policiesFeature) ? config.policies : nil
        }
        if isApp && store.get().file.accounts[id]?.policies != before {
            // Not here: a sync holding the repository's lock may have asked.
            Task { @MainActor [weak self] in await self?.enforceTimeoutLimit() }
        }
        return config
    }

    /// `/api/config` of the active record's server, before anyone signs in (sign-ups, policies
    /// for creating an account); nil when it couldn't be read.
    public func publicConfig() async -> PublicConfig? {
        guard let server = store.get().active?.server, let url = URL(string: server + "/api/config"),
              let (data, res) = try? await api.get(url), res.statusCode == 200, let j = try? JSON.parse(data) else { return nil }
        return PublicConfig(json: j)
    }

    /// Whether the account's server does delta sync (`/api/config` `features` has
    /// `delta_sync`), asked at most every 6 hours and kept with the account (the macOS AutoFill
    /// extension runs as a new process for each request). A list gone stale is harmless: a
    /// server without the feature ignores `since` and answers in full. Unknown → no.
    func deltaSyncEnabled(_ id: String) async -> Bool {
        guard let a = store.get().file.accounts[id], !a.server.isEmpty else { return false }
        let now = Date().timeIntervalSince1970
        if let f = a.features, let at = a.featuresAt, now >= at, now - at < 6 * 3600 { return f.contains(deltaSyncFeature) }
        guard let config = await fetchConfig(id) else { return a.features?.contains(deltaSyncFeature) ?? false }
        return config.features.contains(deltaSyncFeature)
    }

    /// Background App Refresh: keep an account's encrypted offline copy current without
    /// unlocking it. Nothing is decrypted or kept in memory and the identity store isn't
    /// touched: with delta sync `/sync/revision` decides and only the changes are fetched and
    /// merged into the copy; otherwise the whole `/sync` replaces it. Only a valid sync answer
    /// at least as new as the copy on disk is written (`DeltaSync.refresh`). The active account,
    /// when unlocked, gets a normal sync instead.
    public func refreshCacheLocked(accountId id: String) async throws {
        if sessions[id] != nil && activeId == id {
            try await sync()
            return
        }
        let s = store.get()
        guard let a = s.file.accounts[id], a.isListed, s.tokens(id) != nil else { return }
        let cached = await readSnapshot(id)
        let delta = await deltaSyncEnabled(id)
        let api = self.api
        let result = try await DeltaSync.refresh(cached: cached, delta: delta, trashSummary: trashSummary) { path in
            try await api.callData(id, path)
        }
        twoStepGated.remove(id)
        try Task.checkCancellation()
        guard case .write(let next) = result else {
            if result == .current { store.updateAccount(id) { $0.lastSync = Date().timeIntervalSince1970 } }
            return
        }
        // Another account's bundle (round 5, iOS H): nothing of this answer is kept.
        if let known = a.accountId, !known.isEmpty, let bundle = next.bundle, !Self.bundleMayBeStored(bundle.text, account: nil, authenticatedId: known) {
            return
        }
        let data = try await core { try next.encoded() }
        try Task.checkCancellation()
        await lock.run {
            // Unlocked and shown meanwhile: its own sync writes the copy.
            guard !(sessions[id] != nil && activeId == id) else { return }
            await store.writeCacheInBackground(id, data)
            store.updateAccount(id) { a in
                a.lastSync = Date().timeIntervalSince1970
                if let bundle = next.bundle?.text, Self.bundleMayBeStored(bundle, account: nil, authenticatedId: a.accountId) { a.bundle = bundle }
            }
        }
    }

    /// The first sync after the keys are in memory (unlock): a server that requires two-step login
    /// first (403 `two_step_required`) isn't an error here. The account is marked (see
    /// `ApiClient.onTwoStepRequired`), the app shows the setup screen, and the keys stay for
    /// `continueAfterTwoStep`.
    private func syncOrGate(fallbackToCache: Bool = false, cacheFirst: Bool = false) async throws {
        do {
            try await syncLocked(fallbackToCache: fallbackToCache, cacheFirst: cacheFirst)
        } catch let e as ApiError where TwoStepGate.isRequired(status: e.status, code: e.code) {}
    }

    /// After sign-in, unlock and restore (the app only): what the server's policies ask, in the
    /// background (never holding up the vault).
    func afterOpen() {
        guard isApp else { return }
        Task { @MainActor [weak self] in await self?.refreshPolicies() }
        vaultKeysChanged()
    }

    /// The server's policies (`/api/config`, kept with the account), the vault timeout lowered to
    /// their limit, and what the account still has to change (`GET /account`
    /// `policy_violations`, servers with `policies`). Best effort: a failed request keeps what is
    /// known.
    public func refreshPolicies() async {
        let id = activeId
        guard store.get().tokens(id) != nil, let config = await fetchConfig(id) else { return }
        await enforceTimeoutLimit()
        guard config.features.contains(policiesFeature) else {
            violations[id] = nil
            return
        }
        guard let j = try? await api.call(id, "/account"), activeId == id else { return }
        violations[id] = PolicyRules.readViolations(j["policy_violations"])
    }

    /// Keep the vault timeout within the servers' limit (policy `max_vault_timeout_minutes`, the
    /// strictest of the signed-in accounts): a saved choice above it is lowered to the longest
    /// choice within it ("Never" keys are dropped as for any change) and Settings says so.
    public func enforceTimeoutLimit() async {
        let s = store.get()
        let saved = s.settings.vaultTimeout
        let clamped = PolicyRules.clampTimeout(saved, max: s.timeoutLimit)
        guard clamped != saved else { return }
        await updateSettings {
            $0.vaultTimeout = clamped
            $0.vaultTimeoutLowered = true
        }
    }

    /// The two-step setup screen's "Continue", once a method is on: with the keys in memory the
    /// vault syncs and opens (another 403 keeps the screen); without them (it came up while
    /// locked) the unlock screen follows.
    public func continueAfterTwoStep() async throws {
        let id = activeId
        switch TwoStepGate.afterSetup(keysInMemory: sessions[id] != nil) {
        case .sync:
            try await sync()
        case .unlock:
            twoStepGated.remove(id)
        }
        afterOpen()
    }

    /// The server sync after a cache-first unlock; an unreachable server leaves the copy marked offline.
    private func backgroundSync(_ id: String, _ session: Session) async {
        await lock.run {
            guard sessions[id] === session, activeId == id else { return }
            do {
                try await syncLocked()
            } catch let e as ApiError where TwoStepGate.isRequired(status: e.status, code: e.code) {
                // The server answered: two-step setup comes first (the app shows that screen).
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

    /// After this device's write into `vaultId` (`answer`: the server's reply, with `vault_seq`
    /// on servers with delta sync): when it is the vault's next number nothing else changed
    /// there, so `change` is applied to the copy without asking the server; when the copy
    /// already has it nothing is done; otherwise (other writes too, a move, an older server) the
    /// copy is synced, as before every write.
    private func afterWrite(_ vaultId: String, _ answer: JSON, _ change: LocalChange?) async {
        let id = activeId
        guard let change, let c = copy, c.account == id, let session = sessions[id] else { return await syncAfterWrite() }
        let known = c.snapshot.vaults.first { $0.id == vaultId }?.seq
        let seq = Self.number(answer["vault_seq"])
        switch SyncDecision.afterWrite(known: known, vaultSeq: seq) {
        case .nothing:
            return
        case .sync:
            return await syncAfterWrite()
        case .applyLocally:
            guard let seq, let next = SyncMerge.applyLocal(change, vaultId: vaultId, vaultSeq: seq, to: c.snapshot) else {
                return await syncAfterWrite()
            }
            do {
                try await show(id, session, next, offline: false, store: .localChange)
            } catch {
                await syncAfterWrite()
            }
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

    /// Decrypt a copy, reusing what `previous` already opened: a vault key whose header
    /// (wrapping, kind, epoch) is unchanged, the vault's name while its `meta` is too, and items
    /// whose ciphertext is the same in a vault whose key was kept. A vault key that can't be
    /// opened (rotated) is skipped with its items, and so is an undecryptable item or a trashed
    /// one without data (`trash=summary`), as before.
    ///
    /// `invitations` (the app only): each invitation's sealed key is opened just to read the
    /// vault's name and dropped at once (`Invitation.open`; a name already read from the same
    /// sealed key and encrypted name is reused); one that can't be opened has no name.
    ///
    /// `sharing` (signed sharing on): every vault is checked (`SignedSharing.checkVault`); one that
    /// fails is left out with its items and listed in `refused`, never used. Invitations are
    /// checked too (`SignedSharing.checkInvitation`).
    nonisolated static func open(_ account: Account, _ snap: SyncSnapshot, previous: OpenedVault?, invitations: Bool = false,
                                 sharing: SharingInputs? = nil) -> OpenedVault {
        var keys: [String: VaultKey] = [:]
        var outputs = sharing.map { SharingOutputs(pins: $0.pins, pinsChanged: $0.pinsChanged, memory: $0.memory, keep: $0.keep, holdPins: $0.holdPins,
                                                      notice: $0.notice) }
        var consent: [Invitation] = []
        var headers: [String: SyncVault] = [:]
        var kept = Set<String>()
        var out = VaultData()
        let oldNames = Dictionary((previous?.data.vaults ?? []).map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a })
        for v in snap.vaults {
            let key: VaultKey
            var name: String?
            if let p = previous, let old = p.headers[v.id], old.sameKey(as: v), let k = p.keys[v.id] {
                key = k
                kept.insert(v.id)
                if old.meta == v.meta { name = oldNames[v.id] }
            } else {
                // An `account` wrap opens with the row's key epoch (an epoch-bound wrap only for
                // it; a legacy one only where the key pins allow it).
                let legacy = sharing.map { _ in (try? pinsLegacyWrapAllowed(pinsJson: outputs?.pins, vaultId: v.id)) ?? true } ?? true
                guard let k = try? account.openVaultKey(vaultId: v.id, wrapped: v.wrappedKey, kind: v.keyKind,
                                                        keyEpoch: UInt64(max(0, v.keyEpoch ?? 0)), legacyAllowed: legacy) else { continue }
                key = k
            }
            let n = name ?? ((try? key.decryptMeta(vaultId: v.id, meta: v.meta)).flatMap { try? JSON.parse($0) }?.str("name") ?? "")
            var trust = VaultTrust.notChecked
            let role = v.role
            if let s = sharing, var o = outputs {
                if let reason = s.unavailable, v.keyKind != VaultInfo.accountKeyKind, !v.keyKind.isEmpty {
                    // Nothing to check a shared vault against now (the key pins or the memory).
                    out.refused.append(RefusedVault(id: v.id, name: n.isEmpty ? nil : n, reason: .admission(reason)))
                    continue
                }
                let check = SignedSharing.checkVault(v, key: key, me: s.me, pins: o.pins, remembered: o.memory.rosters[v.id],
                                                     newer: s.fetched[v.id], tooLarge: s.tooLarge.contains(v.id),
                                                     seenSigned: o.memory.signed.contains(v.id), now: s.now)
                switch check {
                case .refused(let reason):
                    out.refused.append(RefusedVault(id: v.id, name: n.isEmpty ? nil : n, reason: reason))
                    continue
                case .consent(let acceptance, let rejoin, let replaced, let own, let signer):
                    if signer == nil && !s.firstSyncDone {
                        // Before this device finished the account's first signed sync an unsigned
                        // vault is neither consent nor declinable: held, checked again next sync.
                        out.refused.append(RefusedVault(id: v.id, name: n.isEmpty ? nil : n, reason: .checking))
                        continue
                    }
                    // Never opened beyond its name: shown like an invitation (the app only).
                    let shownName = ShownText.clean(n, limit: 64)
                    var inv = Invitation(vaultId: v.id, role: v.role, name: shownName.isEmpty ? "Shared vault" : shownName,
                                         invitedBy: signer.map { SyncInvitation.Sharer(id: $0.userId, email: $0.email, name: $0.name) },
                                         trust: signer.map { .signed($0) } ?? .unsigned)
                    inv.consent = replaced ? .replaced : rejoin ? .rejoin : .added
                    inv.own = own
                    // Unsigned: accepted (by the key id shown) only when its key was replaced by an
                    // app from before, or while the account's trust memory is missing or this
                    // device had no earlier copy of it (then labelled "Not yet signed"); otherwise
                    // held with "Ask the vault's owner to sign this vault." Unsigned ones never
                    // offer Decline (cross-client rule 1): a server can't push the user into
                    // leaving vaults they really are in.
                    let waiting = o.memory.missing?.contains(v.id) ?? false
                    inv.acceptance = signer != nil || replaced || waiting ? acceptance : nil
                    inv.declineHidden = waiting || signer == nil
                    consent.append(inv)
                    continue
                case .ok(let t, let roster, let pins):
                    trust = t
                    if pins != o.pins {
                        o.pins = pins
                        o.pinsChanged = true
                    }
                    if let roster, o.memory.rosters[v.id] != roster { o.memory.rosters[v.id] = roster }
                    if case .signed = t, !o.memory.signed.contains(v.id) { o.memory.signed.append(v.id) }
                }
                outputs = o
            }
            keys[v.id] = key
            headers[v.id] = v
            out.vaults.append(VaultInfo(id: v.id, name: n.isEmpty ? "Vault" : n, role: Role(rawValue: role) ?? .read,
                                        keyKind: v.keyKind.isEmpty ? VaultInfo.accountKeyKind : v.keyKind, keyEpoch: v.keyEpoch, trust: trust))
        }
        var before: [String: Entry] = [:]
        if let p = previous {
            for e in p.data.entries + p.data.trash { before[e.id] = e }
        }
        for row in snap.items {
            guard let key = keys[row.vaultId], let itemKey = row.itemKey, let data = row.data else { continue }
            let enc = EncryptedItem(id: row.id, vaultId: row.vaultId, key: itemKey, data: data)
            let item: Item
            if kept.contains(row.vaultId), let old = before[row.id], old.vaultId == row.vaultId, old.enc.key == itemKey, old.enc.data == data {
                item = old.item
            } else {
                guard let json = try? key.decryptItem(encrypted: enc), let decoded = try? ItemCodec.decode(json) else { continue }
                item = decoded
            }
            let e = Entry(id: row.id, item: item, vaultId: row.vaultId, revision: row.revision ?? 0, enc: enc, deletedAt: row.deletedAt)
            if row.deletedAt == nil { out.entries.append(e) } else { out.trash.append(e) }
        }
        out.entries.sort { $0.item.name.localizedCaseInsensitiveCompare($1.item.name) == .orderedAscending }
        out.trash.sort { ($0.deletedAt ?? 0) > ($1.deletedAt ?? 0) }
        out.revision = snap.revision
        if var o = outputs, let m = o.memory.missing {
            // A vault leaves the consent states only once it is settled (round 5 Info): accepted
            // (`accept`), used (an `ok` verdict now) or tombstoned; not because one process (an
            // AutoFill extension, an offline open) didn't see its consent this time.
            let usable = Set(out.vaults.map(\.id))
            let left: Set<String> = if case .object(let l)? = KeyPinsReader.field(o.pins, "left") { Set(l.keys) } else { [] }
            let next = m.filter { !usable.contains($0) && !left.contains($0) }
            if next != m {
                o.memory.missing = next
                outputs = o
            }
        }
        var names: [String: String?] = [:]
        if invitations {
            let opened = Invitation.open(snap.invitations, previous: previous?.names ?? [:]) { inv in
                let key = try account.openVaultKey(vaultId: inv.vaultId, wrapped: inv.wrappedKey, kind: "sealed", keyEpoch: 0, legacyAllowed: false)
                return Invitation.name(fromMeta: try key.decryptMeta(vaultId: inv.vaultId, meta: inv.meta))
            }
            out.invitations = opened.invitations
            names = opened.names
            if let s = sharing, let o = outputs {
                out.invitations = zip(snap.invitations, opened.invitations).map { inv, shown in
                    var shown = shown
                    let key = try? account.openVaultKey(vaultId: inv.vaultId, wrapped: inv.wrappedKey, kind: "sealed", keyEpoch: 0, legacyAllowed: false)
                    let checked = SignedSharing.checkInvitation(inv, key: key, me: s.me, pins: o.pins, remembered: o.memory.rosters[inv.vaultId],
                                                                newer: s.fetched[inv.vaultId], tooLarge: s.tooLarge.contains(inv.vaultId))
                    shown.trust = checked.0
                    shown.acceptance = checked.1
                    shown.own = checked.1?.flags.own ?? false
                    return shown
                }
                out.invitations += consent
            }
        }
        return OpenedVault(data: out, keys: keys, headers: headers, names: names, sharing: outputs)
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

    /// Create an item; `id` keeps the item's id across the caller's retries (an editor or a save
    /// sheet whose first attempt failed or timed out), so a create that did reach the server
    /// isn't saved twice.
    ///
    /// API v2: the body carries the vault key's `key_epoch`. If the key was replaced meanwhile
    /// (409 `vault_key_changed`, nothing written), the vault is synced for the new key and the
    /// item encrypted again under the same id, once. If the id already exists (409
    /// `item_exists`, or "item id already exists" from older servers), an earlier attempt got
    /// through: that item, once synced, is updated with this content instead.
    @discardableResult
    public func createItem(_ item: Item, vaultId: String?, id: String? = nil) async throws -> String {
        try await lock.run { try await createLocked(item, vaultId: vaultId, id: id) }
    }

    private func createLocked(_ item: Item, vaultId: String?, id requested: String?) async throws -> String {
        var v = try requireVault()
        let id: String
        if let requested { id = requested } else { id = try await core { try newId() } }
        var next = item
        next.createdAt = now
        next.updatedAt = now
        let json = ItemCodec.encode(next)
        var retried = false
        var written: (answer: JSON, enc: EncryptedItem, vault: String)?
        while true {
            let target = try vaultId.flatMap { want in v.vaults.first { $0.id == want } } ?? writableVault(v)
            guard let key = vaultKeys[target.id] else { throw UserError("Vault not found.") }
            let targetId = target.id
            let enc = try await core { try key.encryptItem(itemJson: json, id: id, vaultId: targetId) }
            do {
                let answer = try await api.call(activeId, "/items", body: Self.body(enc, keyEpoch: target.keyEpoch))
                written = (answer, enc, targetId)
                break
            } catch let e as ApiError where e.status == 409 && e.hasCode("vault_key_changed") {
                if retried { throw e }
                retried = true
                try await syncLocked()
                v = try requireVault()
            } catch let e as ApiError where e.status == 409 && Self.itemExists(e) {
                try await syncLocked()
                guard let landed = vault?.get(id), landed.vaultId == targetId, landed.deletedAt == nil else { throw e }
                var mine = next
                mine.createdAt = landed.item.createdAt
                try await updateLocked(landed, mine, targetVaultId: nil)
                return id
            }
        }
        if let w = written {
            let change = Self.number(w.answer["revision"]).map { rev in
                LocalChange.put(SyncItem(id: id, vaultId: w.vault, itemKey: w.enc.key, data: w.enc.data, revision: rev, createdAt: now, updatedAt: now))
            }
            await afterWrite(w.vault, w.answer, change)
        }
        return id
    }

    /// A create was refused because the id exists (API v2 code, or the older servers' message).
    nonisolated static func itemExists(_ e: ApiError) -> Bool {
        e.hasCode("item_exists", orMessage: "item id already exists")
    }

    /// Save changes to an item; with another `targetVaultId` the item also moves to that vault
    /// (re-encrypted with its key under the same id), like the web vault's `updateItem`.
    /// Throws [ConflictError] when the item changed on the server since `entry` was read.
    ///
    /// API v2: the body carries the (target) vault key's `key_epoch`. If the key was replaced
    /// meanwhile (409 `vault_key_changed`, nothing written; a key rotation also re-encrypts every
    /// item of the vault), the vault is synced and the change saved again with the new key and
    /// the item's new revision, once, but only when the item's content is still the one the
    /// change was made to (else it is the usual conflict).
    public func updateItem(_ entry: Entry, _ item: Item, targetVaultId: String? = nil) async throws {
        try await lock.run { try await updateLocked(entry, item, targetVaultId: targetVaultId) }
    }

    private func updateLocked(_ base: Entry, _ item: Item, targetVaultId: String?) async throws {
        var v = try requireVault()
        var next = item
        next.updatedAt = now
        let old = base.item.login?.password ?? ""
        if next.login != nil, !old.isEmpty, old != next.login?.password, next.passwordHistory == base.item.passwordHistory {
            next.passwordHistory = Array(([PasswordChange(password: old, changedAt: now)] + next.passwordHistory).prefix(20))
        }
        let json = ItemCodec.encode(next)
        var entry = base
        var retried = false
        var written: (answer: JSON, enc: EncryptedItem, vault: String, moved: Bool)?
        while true {
            guard let vault = v.vaults.first(where: { $0.id == entry.vaultId }) else { throw UserError("Vault not found.") }
            if vault.role == .read { throw UserError("You can only view items in this vault.") }
            let targetId = targetVaultId ?? entry.vaultId
            guard let target = v.vaults.first(where: { $0.id == targetId }) else { throw UserError("Vault not found.") }
            if target.role == .read { throw UserError("You can't add items to \(target.name).") }
            guard let key = vaultKeys[target.id] else { throw UserError("Vault not found.") }
            let enc0 = entry.enc
            let same = target.id == entry.vaultId
            let entryId = entry.id
            let enc = try await core { same ? try key.updateItem(encrypted: enc0, itemJson: json) : try key.encryptItem(itemJson: json, id: entryId, vaultId: targetId) }
            do {
                let answer = try await api.call(activeId, "/items/\(entry.id)", body: Self.body(enc, keyEpoch: target.keyEpoch, revision: entry.revision), method: "PUT")
                written = (answer, enc, targetId, !same)
                break
            } catch let e as ApiError where e.status == 409 && e.hasCode("vault_key_changed") {
                if retried { throw e }
                retried = true
                try await syncLocked()
                v = try requireVault()
                guard let fresh = v.get(base.id), fresh.vaultId == base.vaultId, fresh.deletedAt == base.deletedAt, fresh.item == base.item else {
                    throw ConflictError(itemId: base.id)
                }
                entry = fresh
            } catch let e as ApiError where e.status == 409 {
                throw ConflictError(itemId: entry.id)
            }
        }
        guard let w = written else { return }
        // A move also changed the vault it left (its number isn't in the answer): sync.
        let deletedAt = entry.deletedAt
        let change = w.moved ? nil : Self.number(w.answer["revision"]).map { rev in
            LocalChange.put(SyncItem(id: base.id, vaultId: w.vault, itemKey: w.enc.key, data: w.enc.data, revision: rev, deletedAt: deletedAt, updatedAt: now))
        }
        await afterWrite(w.vault, w.answer, change)
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
            let answer = try await api.call(activeId, "/items/\(entry.id)", method: "DELETE")
            let summary = trashSummary
            let change = Self.number(answer["revision"]).map { LocalChange.trash(id: entry.id, at: now, revision: $0, summary: summary) }
            await afterWrite(entry.vaultId, answer, change)
        }
    }

    public func restoreItem(_ entry: Entry) async throws {
        try await lock.run {
            let v = try requireVault()
            if !v.canWrite(entry) { throw UserError("You can only view items in this vault.") }
            let answer = try await api.call(activeId, "/items/\(entry.id)/restore", method: "POST")
            let change = Self.number(answer["revision"]).map { LocalChange.restore(id: entry.id, revision: $0) }
            await afterWrite(entry.vaultId, answer, change)
        }
    }

    /// Delete an item in the trash for good.
    public func purgeItem(_ entry: Entry) async throws {
        try await lock.run {
            let v = try requireVault()
            if !v.canWrite(entry) { throw UserError("You can only view items in this vault.") }
            let answer = try await api.call(activeId, "/items/\(entry.id)/permanent", method: "DELETE")
            await afterWrite(entry.vaultId, answer, .purge(id: entry.id))
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

    // MARK: Vault key replacement

    /// Replace the keys of these vaults, one after the other (after an emergency contact who may
    /// have kept their keys was removed, or a vault the server marked): a new key wrapped with this
    /// account's own key, every item of the vault (trash included, each with its revision) and its
    /// name re-encrypted with it, in one `POST /vaults/{id}/rotate`. Built only from the copy the
    /// sync at its start verified.
    ///
    /// Signed sharing (`rotateSigned`): a vault with other members is replaced too, the new key
    /// sealed and signed for each of them, with the vault's next signed member roster, after a
    /// member review: the server's member list must match the trusted roster (else it stops,
    /// naming who differs); people the roster names but the server no longer lists are dropped
    /// only once the user confirmed them by user id (`confirmed`; else the vault is listed in
    /// `confirm`); a shared vault without a trusted roster is never replaced automatically: it is
    /// listed in `review` and replaced only with the digest of the review the user confirmed
    /// (`reviewed`). `personalOnly` (emergency access): only vaults the same members answer shows
    /// as personal; others are listed in `shared`. Without signed sharing (older servers) only
    /// vaults whose members are this account alone, as before: a shared one is listed in `shared`.
    ///
    /// Vaults it no longer has or can't manage are skipped. The first other failure stops it and is
    /// thrown (the server keeps asking for the rest, `rotation_pending`).
    @discardableResult
    public func rotateVaultKeys(_ vaultIds: [String], confirmed: [String: Set<String>] = [:], reviewed: [String: String] = [:],
                                personalOnly: Bool = false) async throws -> KeyReplacement {
        try await lock.run {
            defer { vaultKeysChanged() }
            try await syncLocked()
            var done = KeyReplacement()
            for vid in vaultIds {
                switch try await rotateLocked(vid, confirmed: confirmed[vid] ?? [], reviewed: reviewed[vid], personalOnly: personalOnly) {
                case .rotated: done.rotated.append(vid)
                case .shared(let name): done.shared.append(KeyReplacement.Shared(id: vid, name: name))
                case .confirm(let name, let people):
                    done.confirm.append(KeyReplacement.Confirm(id: vid, name: name, people: people.map { $0.email ?? SharingText.unknownMember },
                                                               userIds: people.map(\.userId)))
                case .review(let name, let review): done.review.append(KeyReplacement.Review(id: vid, name: name, review: review))
                case .skipped: break
                }
            }
            try? await syncLocked()
            return done
        }
    }

    enum RotationOutcome: Equatable {
        case rotated, skipped, shared(String)
        case confirm(String, [MemberReview.MissingPerson])
        case review(String, MemberReview)
    }

    /// How often a key replacement is tried again when an item changed meanwhile (`revision_conflict`).
    nonisolated static let rotationAttempts = 3

    private func rotateLocked(_ vid: String, confirmed: Set<String>, reviewed: String?, personalOnly: Bool) async throws -> RotationOutcome {
        var attempt = 1
        var membersRetried = false
        while true {
            do {
                return try await rotateOnce(vid, confirmed: confirmed, reviewed: reviewed, personalOnly: personalOnly)
            } catch let e as ApiError where e.status == 409 && e.hasCode("revision_conflict") {
                // An item of the vault was saved after the sync the replacement was built from:
                // nothing was changed. Sync and build it again from the newer items.
                guard attempt < Self.rotationAttempts else { throw e }
                attempt += 1
                try await syncLocked()
            } catch let e as MembersChanged {
                // Signed sharing: the members (or their roster, or the key) changed after the list
                // it was built from. Sync and check again once; then say who differs.
                guard !membersRetried else { throw UserError(e.text) }
                membersRetried = true
                try await syncLocked()
            }
        }
    }

    private func rotateOnce(_ vid: String, confirmed: Set<String>, reviewed: String?, personalOnly: Bool) async throws -> RotationOutcome {
        let id = activeId
        guard let session = sessions[id], let v = try? requireVault(), let info = v.vaults.first(where: { $0.id == vid }),
              info.role == .owner || info.role == .admin, let oldKey = vaultKeys[vid], let c = copy, c.account == id else { return .skipped }
        let me = session.meId
        let rows = c.snapshot.items.filter { $0.vaultId == vid }
        // One members answer decides everything below (personal or not, who gets the key).
        let answer = try await api.call(id, "/vaults/\(Self.pathPart(vid))/members")
        guard let members = Self.memberRows(answer), EmergencyClient.readMembers(answer) != nil else {
            throw UserError("The server sent an unexpected response. Try again.")
        }
        // Locked or switched meanwhile: nothing is sent for another session.
        guard activeId == id, sessions[id] === session else { return .skipped }
        if signedSharingOn(id, c.snapshot) {
            return try await rotateSigned(id, session, info, row: c.snapshot.vaults.first { $0.id == vid }, oldKey: oldKey, rows: rows,
                                          answer: answer, members: members, confirmed: confirmed, reviewed: reviewed, personalOnly: personalOnly)
        }
        if members.map(\.userId) != [me] { return .shared(info.name) }
        if personalOnly && (info.keyKind != VaultInfo.accountKeyKind || info.role != .owner) { return .shared(info.name) }
        return try await rotatePlain(id, session, info, oldKey: oldKey, rows: rows)
    }

    /// A vault whose members are this account alone: a new key wrapped for it only (no roster,
    /// sealed to nobody).
    func rotatePlain(_ id: String, _ session: Session, _ info: VaultInfo, oldKey: VaultKey, rows: [SyncItem]) async throws -> RotationOutcome {
        let vid = info.id
        let me = session.meId
        let account = session.account
        let name = info.name
        let next = info.keyEpoch.map { UInt64(max(0, $0) + 1) }
        let made: (wrapped: String, items: [JSON], meta: String, epochPin: String?) = try await core {
            let nv = try account.newVaultKey(vaultId: vid)
            let (items, meta) = try Self.reencrypt(rows, vid: vid, name: name, oldKey: oldKey, newKey: nv.key)
            return (nv.wrapped, items, meta, try next.map { try nv.key.epochPinJson(vaultId: vid, keyEpoch: $0) })
        }
        var body: [String: JSON] = [
            "keys": [["user_id": .string(me), "wrapped_key": .string(made.wrapped), "key_kind": .string(VaultInfo.accountKeyKind)]],
            "items": .array(made.items),
            "meta": .string(made.meta),
        ]
        if let e = info.keyEpoch { body["key_epoch"] = .int(e) }
        try await postRotation(id, vid, body)
        // The key this device gave the vault (round 5; no roster: neither version nor hash).
        if let pin = made.epochPin { await recordOwnRotation(id, session, vaultId: vid, epochPin: pin, roster: nil) }
        try await syncLocked()
        return .rotated
    }

    /// `POST /vaults/{id}/rotate`; another device's key replacement in between (409
    /// `vault_key_changed`, nothing changed) is said in the app's words.
    func postRotation(_ id: String, _ vid: String, _ body: [String: JSON]) async throws {
        do {
            _ = try await api.call(id, "/vaults/\(Self.pathPart(vid))/rotate", body: .object(body))
        } catch let e as ApiError where e.status == 409 && e.hasCode("vault_key_changed") {
            try? await syncLocked()
            throw UserError("Someone else replaced this vault's key just now. If the vault still asks for a new key, replace it again.")
        } catch let e as ApiError where e.isRateLimited {
            // At most 30 key replacements per vault and hour (signed sharing's retired key ids).
            throw UserError(SharingText.keyReplacementLimited(e.retryAfter))
        }
    }

    /// Every item of a vault re-encrypted with `newKey` (each with the revision it was read at: an
    /// item saved meanwhile is refused with 409, not overwritten) and the vault's name.
    nonisolated static func reencrypt(_ rows: [SyncItem], vid: String, name: String, oldKey: VaultKey, newKey: VaultKey) throws -> ([JSON], String) {
        var items: [JSON] = []
        for r in rows {
            guard let key = r.itemKey, let data = r.data else { throw UserError("Some items in this vault can't be read here yet, so its key can't be replaced. Try again after a sync.") }
            let json: String
            do {
                json = try oldKey.decryptItem(encrypted: EncryptedItem(id: r.id, vaultId: vid, key: key, data: data))
            } catch {
                throw UserError("Some items in \(name) can't be decrypted, so its key can't be replaced yet.")
            }
            let enc = try newKey.encryptItem(itemJson: json, id: r.id, vaultId: vid)
            items.append(Self.body(enc, keyEpoch: nil, revision: r.revision))
        }
        let meta = try newKey.encryptMeta(vaultId: vid, metaJson: (["name": .string(name)] as JSON).text)
        return (items, meta)
    }

    /// After unlocking, a change to the vaults or a key replacement: add the emergency-access wraps
    /// the server asks for (the app only; in the background, failures ignored).
    func vaultKeysChanged() {
        guard isApp, vault != nil else { return }
        let client = emergency
        Task { @MainActor in try? await client.fill() }
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
            twoStepGated.remove(id)
            violations[id] = nil
            closeSession(id)
            pendingMaster = nil
            Keychain.deleteBiometric(id)
            store.deleteCache(id)
            forgetAvatar(id)
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
        // Files aren't exported: their keys stay out of the file (`AttachmentList.strip`).
        return ("[" + v.entries.map { ItemCodec.encode(AttachmentList.strip($0.item)) }.joined(separator: ",") + "]", v.entries.count)
    }

    /// Live sync's "logout" message: check the session (an ended one signs the account out
    /// through the refresh-token path) and catch up.
    public func checkSession() async { await refreshIfStale() }

    /// The live-sync socket said the server now requires two-step login first (its
    /// `two_step_required` message or close reason): the app shows the setup screen and live
    /// sync stops, as after a 403 `two_step_required`. A sync that goes through lifts it.
    public func twoStepRequiredBySocket(_ id: String) {
        guard store.get().tokens(id) != nil else { return }
        twoStepGated.insert(id)
    }

    // MARK: Queries (AutoFill, phase 2)

    /// Logins of the unlocked active account that match a web page (default match from settings;
    /// regular expressions only from the account's own vaults).
    public func loginsFor(_ pageUrl: String) -> [Entry] {
        let fallback = store.get().settings.defaultMatch
        guard let v = vault else { return [] }
        return v.entries.filter { e in e.item.login.map { UrlMatcher.matchesAny(pageUrl, $0, fallback: fallback, allowRegex: v.isPersonal(e)) } ?? false }
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
    /// - `newItemId`: the id a new login gets, kept by the sheet across its retries (see `createItem`).
    public func saveLogin(page: String, username: String, password: String, target: String? = nil, isDefault: Bool = false, newItemId: String? = nil) async throws -> SaveOutcome {
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
            try await createItem(SaveLogic.newItem(page: page, username: username, password: password), vaultId: nil, id: newItemId)
            return .created
        case .update(let e, _):
            try await updateItem(e, SaveLogic.updatedItem(e, username: username, password: password))
            return .updated
        case .unchanged:
            return .unchanged
        case .noPassword:
            throw UserError("There is no password to save.")
        }
    }

    /// Add the page's origin as one more website (match "Default") of login `id` (`AddSite`).
    /// Syncs first, so it works on the server's current item and revision; nothing but the
    /// websites changes (no password history entry). `.alreadyMatched`: one of its websites
    /// matches the page by now, nothing was written.
    ///
    /// `sameAccount`: the save sheet's choice, made for the typed user name and password. The
    /// login must still be in the user's own vault with exactly those, else `SaveChoiceChanged`
    /// is thrown and nothing is written (the sheet asks again).
    public func addSite(_ id: String, page: String, sameAccount: (username: String, password: String)? = nil) async throws -> AddSite.Outcome {
        guard AddSite.origin(page) != nil else { throw UserError("Only a website's address can be added to a login.") }
        try await sync()
        guard let v = vault else { throw UserError("Your vault is locked.") }
        guard let e = v.entries.first(where: { $0.id == id }), e.item.login != nil else {
            if sameAccount != nil { throw SaveChoiceChanged() }
            throw UserError("This login isn't in your vault any more.")
        }
        if let s = sameAccount, !AddSite.isSameAccount(e, username: s.username, password: s.password, vault: v) { throw SaveChoiceChanged() }
        guard v.canWrite(e) else { throw UserError("You can only view this login, so no website can be added to it.") }
        guard let item = AddSite.updated(e, page: page, vault: v, defaultMatch: store.get().settings.defaultMatch) else { return .alreadyMatched }
        try await updateItem(e, item)
        return .added
    }

    // MARK: Helpers

    /// An item write's body: the encrypted item, the `key_epoch` of the vault key it was
    /// encrypted with (when the server sent one) and, for updates, the revision it was based on.
    nonisolated static func body(_ e: EncryptedItem, keyEpoch: Int64?, revision: Int64? = nil) -> JSON {
        var o: [String: JSON] = ["id": .string(e.id), "vault_id": .string(e.vaultId), "key": .string(e.key), "data": .string(e.data)]
        if let keyEpoch { o["key_epoch"] = .int(keyEpoch) }
        if let revision { o["revision"] = .int(revision) }
        return .object(o)
    }

    nonisolated static func bundleAccountId(_ bundle: String) -> String {
        (try? JSON.parse(bundle))?.str("account_id") ?? ""
    }

    /// The account id the core authenticated for an unlocked account (its own id, as signed
    /// sharing's "me").
    nonisolated static func authenticatedId(_ account: Account) -> String {
        (try? account.legacyIdentityJson()).flatMap { try? JSON.parse($0) }?.str("user_id") ?? ""
    }

    public static let restoreRefused = "PassAuth couldn't confirm the keys kept on this device. Unlock with your master password."

    /// Session bytes kept on this device (Face ID, timeout "Never", the macOS AutoFill timed
    /// unlock) reopened for the stored `bundle` (round 5, iOS H): under the account id an earlier
    /// unlock authenticated (`AccountData.accountId`; the bundle's own id for records from
    /// before), and only when the bundle is that account's own (`Account.matchesBundle`: its
    /// private-key blob opens under this Account Key with associated data bound to its id), so a
    /// server can't make "me" another id by swapping the stored bundle. nil: ask for the master
    /// password.
    nonisolated static func restoreSession(bundle: String, authenticatedId known: String?, bytes: Data) -> (accountId: String, account: Account)? {
        let listed = bundleAccountId(bundle)
        if let known, !known.isEmpty, known != listed { return nil }
        guard !listed.isEmpty, let account = try? accountFromSessionBytes(accountId: listed, bytes: bytes),
              account.matchesBundle(bundleJson: bundle), authenticatedId(account) == listed else { return nil }
        return (listed, account)
    }

    /// Whether a bundle from the server may be stored for the account (round 5, iOS H): never one
    /// with another `account_id` than the authenticated one. Unlocked: it must be this account's
    /// own (`matchesBundle`); locked (a background refresh): its id must be the one an unlock
    /// authenticated (nothing is stored before one did).
    nonisolated static func bundleMayBeStored(_ bundle: String, account: Account?, authenticatedId known: String?) -> Bool {
        if let account { return account.matchesBundle(bundleJson: bundle) && (known.map { $0.isEmpty || $0 == bundleAccountId(bundle) } ?? true) }
        guard let known, !known.isEmpty else { return false }
        return bundleAccountId(bundle) == known
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
            let copy = sessionBytes
            let known = s.active?.accountId
            // Only for the stored bundle the kept keys open (round 5, iOS H); else locked.
            guard let r = try? await core({ Self.restoreSession(bundle: bundle, authenticatedId: known, bytes: copy) }) else { return false }
            openSession(id, Session(accountId: r.accountId, account: r.account))
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
