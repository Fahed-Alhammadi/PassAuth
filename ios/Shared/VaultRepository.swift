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
    /// The server sent an older version of this item than this device saw (`ItemRollback`): the
    /// newer copy is shown when this device had one.
    public var rolledBack = false

    public init(id: String, item: Item, vaultId: String, revision: Int64, enc: EncryptedItem, deletedAt: Int64?, rolledBack: Bool = false) {
        self.id = id
        self.item = item
        self.vaultId = vaultId
        self.revision = revision
        self.enc = enc
        self.deletedAt = deletedAt
        self.rolledBack = rolledBack
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
    /// What the last check of the vault's items against its manifest found (`none`: it has no
    /// manifest). While `unresolved`, nothing is written into the vault from this device.
    public var manifest: ManifestStatus
    /// A warned vault whose served manifest does describe the served items (or that the server
    /// shows without one): "Use the server's copy" only changes this device's memory, so every
    /// member may do it, whatever their role.
    public var manifestAcceptable = false
    /// A warned vault whose manifest matches: the only problem is an item that can't be opened
    /// (`VaultData.unopenable`). Deleting it clears the warning; "Use the server's copy" doesn't
    /// apply.
    public var unopenable = false

    public init(id: String, name: String, role: Role, keyKind: String = VaultInfo.accountKeyKind, keyEpoch: Int64? = nil,
                trust: VaultTrust = .notChecked, manifest: ManifestStatus = .none) {
        self.id = id
        self.name = name
        self.role = role
        self.keyKind = keyKind
        self.keyEpoch = keyEpoch
        self.trust = trust
        self.manifest = manifest
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
    /// Items the server sent older versions of (rollback detection); nil when none.
    public var rollback: ItemRollback?
    /// Rows of usable vaults that don't open with their vault's key (or came without their key):
    /// shown as "Item that can't be opened", with nothing but "Delete for good".
    public var unopenable: [UnopenableItem] = []
    /// Background App Refresh fetched something that didn't pass this unlock's checks (it was
    /// dropped; the copy shown is the last checked one). Tests read it.
    var refreshedRejected = false

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
    /// The vaults whose items don't match their manifest (the vault warning is shown for each).
    public var manifestWarnings: [VaultInfo] { vaults.filter { $0.manifest.warns } }
}

/// A row the server sent that this device can't open: nothing of it can be shown.
public struct UnopenableItem: Identifiable, Equatable, Sendable {
    public let id: String
    public let vaultId: String
    public let revision: Int64?
    public let deletedAt: Int64?
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
    /// Rollback detection: the item edit counters remembered after this decryption (nil: not
    /// checked) and the rows of the copy to replace with the newer ones this device kept.
    var revs: [String: UInt64]?
    var keptRows: [String: SyncItem] = [:]
    /// Vault manifests: what this device remembers per vault after this decryption's checks
    /// (nil: not checked, or the memory can't be read now).
    var manifests: [String: ManifestMark]?
    /// Vaults holding rows that didn't open with their vault's key: never `ok`.
    var unreadable: Set<String> = []
    /// Vaults whose manifest is more than one step ahead of the remembered one: their manifest
    /// log is fetched and they are checked again (`VaultRepository.checkManifests`).
    var needLog: [String] = []
}

/// Where a copy being opened comes from: it decides what its checks may conclude.
enum CopySource: Sendable {
    /// A `/sync` answer (merged into the copy): verdicts are final.
    case server
    /// The copy stored on the device (only ever a copy that was checked with the keys): what
    /// doesn't check out is only "unchecked" until the server answers (the other process may
    /// have moved on), and no item is marked as rolled back from it.
    case cache
    /// What a background refresh fetched without the keys, read back at unlock: a server answer
    /// nobody checked yet. Checked like one (without asking the server anything), then adopted
    /// as the copy only when nothing at all is wrong with it (`VaultRepository.adoptRefreshed`);
    /// never shown otherwise.
    case refreshed
    /// This device's own write applied to the copy shown: only the vaults written to change
    /// (`wrote`: the manifest each now carries), every other vault keeps its verdict. `gone`:
    /// items this device just deleted for good.
    case local(wrote: [String: ManifestMark], gone: Set<String>)
}

/// What this device remembers next to an account's copy, as read at one moment (nil: the file
/// is there but can't be read now).
struct DeviceMemory: Sendable {
    var revs: ItemRevMemory?
    var manifests: [String: ManifestMark]?
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
    /// The last `/sync` said every signed-in app of the account reads epoch-bound account wraps
    /// (`user.account_wraps_v2`, a compatibility hint only): new and replaced personal-vault keys
    /// are then wrapped v2. Unknown, offline or an older server → false (v1, as before).
    var accountWrapsV2 = false
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
    /// Vault manifests: the work after a sync (first manifests, old trash) is running; the syncs
    /// it makes itself don't start it again.
    @ObservationIgnored private var maintaining = false
    /// The vault number (`seq`) at which a first manifest / an old-trash purge was last tried, by
    /// account, vault and kind: one attempt per number, whatever came of it.
    @ObservationIgnored private var manifestTried: [String: Int64] = [:]
    /// The last `/sync` answer fetched was a delta or had the trash as a summary; `fetchedDelta`:
    /// it was a delta.
    @ObservationIgnored private var fetchedPartial = false
    @ObservationIgnored private var fetchedDelta = false
    /// The device memory the copy shown was last checked with and stored with (this process's
    /// own view: the checks after this device's own writes use it, never what another process
    /// wrote since).
    @ObservationIgnored private var known: (account: String, memory: DeviceMemory)?
    /// This device's clock (unix seconds); tests set it.
    @ObservationIgnored var clock: @MainActor () -> Int64 = { Int64(Date().timeIntervalSince1970) }
    /// How often in a row this device's memory of the account's vaults couldn't be read, and
    /// whether a sync with the server went through meanwhile.
    @ObservationIgnored private var memoryFailures: (account: String, count: Int, synced: Bool)?
    /// The active account's record of its vaults on this device can't be read (three times in a
    /// row, across a sync that worked): the app says so and offers "Reset on this device"
    /// (`resetDeviceMemory`).
    public private(set) var memoryProblem = false
    /// Why the active account's server can't be used now ("Update your PassAuth server to keep
    /// using this app."); nil: none. The copy on the device stays readable, as when offline.
    public private(set) var serverProblem: String?
    #if DEBUG
    /// Tests of the client rules for servers from before signed sharing turn this off; release
    /// builds always refuse such servers (`ServerSupport`).
    @ObservationIgnored public var requiresSignedSharing = true
    #else
    @ObservationIgnored let requiresSignedSharing = true
    #endif
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
        guard let url = URL(string: origin + "/api/config") else { throw UserError("That isn't a valid server address.") }
        let ok: Bool
        var read: PublicConfig?
        do {
            let (data, res) = try await api.get(url)
            let j = try? JSON.parse(data)
            ok = res.statusCode == 200 && j?.str("name") == "PassAuth"
            read = j.flatMap { PublicConfig(json: $0) }
        } catch {
            throw UserError("No PassAuth server answered at that address.")
        }
        // A server whose settings can't be read isn't connected to.
        guard ok, let config = read else { throw UserError("No PassAuth server answered at that address.") }
        // Part S: a PassAuth server from before signed sharing isn't connected to.
        if requiresSignedSharing && ServerSupport.refused(features: config.features) { throw UserError(ServerSupport.updateServer) }
        await lock.run {
            dropDeviceLogin()
            closeSession(activeId)
            store.update { st in
                let id = st.file.accounts[st.file.activeId] != nil ? st.file.activeId : UUID().uuidString.lowercased()
                var a = st.file.accounts[id] ?? AccountData()
                a.server = origin
                a.bundle = nil
                // What was just checked is kept (Part S): a server can't have the check skipped
                // later by no longer answering `/api/config`.
                a.features = config.features
                a.featuresAt = Date().timeIntervalSince1970
                a.api = config.api
                a.policies = config.features.contains(policiesFeature) ? config.policies : nil
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
            // Part S: no sign-in is started with a server without signed sharing.
            try await requireSupportedServer(id, ask: true)
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
            try await requireSupportedServer(id, ask: true)
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
                try await requireSupportedServer(id)
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
        serverProblem = nil
        memoryProblem = false
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
        // Part S: a server this app doesn't use is only asked for its config again (by the sync).
        if requiresSignedSharing, ServerSupport.refused(features: store.get().file.accounts[id]?.features) {
            try? await sync()
            return
        }
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
    ///
    /// `upkeep` false (a sync Background App Refresh asked for): no first manifest is started and
    /// no old trash deleted after it.
    func syncLocked(fallbackToCache: Bool = false, cacheFirst: Bool = false, upkeep: Bool = true) async throws {
        let id = activeId
        guard let session = sessions[id] else { return }
        var checked: Checked?
        var offline = false
        var fromServer = true
        do {
            if cacheFirst, let cached = try await openCached(id, session) {
                checked = cached
                offline = preferCache
                fromServer = false
            } else {
                checked = try await fetchChecked(id, session)
            }
        } catch let e as CheckFailed {
            // The answer came but couldn't be opened (signed sharing's own errors): not "offline".
            throw e.error
        } catch {
            // An answer that isn't a vault is an error, not "offline".
            if let e = error as? UserError, e == DeltaSync.unreadable { throw e }
            // A server this app doesn't use (Part S): the copy shown stays, read-only as when offline.
            if let e = error as? UserError, e.message == ServerSupport.updateServer, sessions[id] === session, activeId == id,
               vault != nil, copy?.account == id {
                vault?.offline = true
            }
            guard fallbackToCache, sessions[id] === session, activeId == id else { throw error }
            let cached: Checked?
            do {
                cached = try await openCached(id, session)
            } catch let e as CheckFailed {
                throw e.error
            }
            guard let cached else {
                if !(error is ApiError), sessions[id] === session, activeId == id {
                    var empty = VaultData()
                    empty.offline = true
                    copy = nil
                    vault = empty
                    return
                }
                throw error
            }
            checked = cached
            offline = true
            fromServer = false
        }
        guard let checked, sessions[id] === session, activeId == id else { return }
        try await commit(id, session, checked, offline: offline, store: fromServer ? .synced : .none)
        if fromServer && upkeep { await maintainManifests(id, session) }
        // What a background refresh fetched meanwhile: checked now that the keys are here.
        if cacheFirst && !fromServer { await adoptRefreshed(id, session) }
        if cacheFirst && !fromServer && !offline {
            // Queued behind the current operation (the lock is first in, first out), so a change
            // the user makes next runs after this sync.
            Task { @MainActor [weak self] in await self?.backgroundSync(id, session) }
        }
    }

    /// What `commit` keeps of a copy besides showing it. `adopted`: what a background refresh
    /// fetched, checked at unlock, becomes the stored copy (nothing is asked of the server).
    private enum CopyStore { case none, localChange, synced, adopted }

    /// Background App Refresh kept what it fetched next to the copy (it has no keys to check it
    /// with). Now, unlocked and with the checked copy shown, that answer is checked like any the
    /// server gives after a delta, against the device memory the copy was checked with. It
    /// becomes the copy only when nothing at all is wrong with it: every vault matches its
    /// manifest (or has none and never had), no item is older than this device saw, nothing in
    /// it fails to open or to pass signed sharing's checks that the copy shown didn't already,
    /// and it isn't behind the copy. Anything else: it is deleted, the checked copy stays as it
    /// is, and the next sync with the server decides (with the usual warnings). Rows of an
    /// answer that wasn't checked are never shown or filled from.
    private func adoptRefreshed(_ id: String, _ session: Session) async {
        guard store.hasRefreshed(id), sessions[id] === session, activeId == id, let shown = vault, let base = copyOf(id) else { return }
        // Never judged against a memory that can't be read now: it waits for the next unlock.
        guard let memory = known.flatMap({ $0.account == id ? $0.memory : nil }), memory.manifests != nil, memory.revs != nil else { return }
        guard let data = await store.readRefreshedInBackground(id),
              let side = await Task.detached(priority: .userInitiated, operation: { SyncSnapshot.decode(data) }).value else {
            store.deleteRefreshed(id)
            return
        }
        guard sessions[id] === session, activeId == id, copyOf(id) == base else { return }
        var adopted = false
        if side.revision >= base.revision,
           let checked = try? await evaluate(id, session, side, source: .refreshed, memory: memory, finalIncomplete: false),
           sessions[id] === session, activeId == id, copyOf(id) == base {
            let o = checked.opened.data
            let stale = (o.rollback?.items ?? []).subtracting(shown.rollback?.items ?? [])
            let refused = Set(o.refused.map(\.id)).subtracting(shown.refused.map(\.id))
            let hidden = Set(o.unopenable.map(\.id)).subtracting(shown.unopenable.map(\.id))
            if o.vaults.allSatisfy({ $0.manifest == .ok || $0.manifest == .none }), stale.isEmpty, refused.isEmpty, hidden.isEmpty,
               checked.opened.keptRows.isEmpty {
                adopted = (try? await commit(id, session, checked, offline: shown.offline, store: .adopted)) != nil
            }
        }
        store.deleteRefreshed(id)
        if !adopted, sessions[id] === session, activeId == id { vault?.refreshedRejected = true }
    }

    /// A copy opened and checked, not shown or stored yet (`commit` does that).
    private struct Checked {
        /// The copy as it was opened (with what signed sharing's preparation added).
        var snapshot: SyncSnapshot
        var opened: OpenedVault
        /// The device memory it was checked with.
        var memory: DeviceMemory
        var source: CopySource
    }

    /// An answer was fetched but opening it failed: the error to report as it is.
    private struct CheckFailed: Error { let error: Error }

    /// The device memory as stored now. Always read before the copy it will be checked against
    /// is read or fetched: whatever the other process (the app or its AutoFill extension) learns
    /// after this moment is newer than this memory, never older than the copy, so neither a
    /// manifest nor an item can look "older than this device saw" only because of the order of
    /// the two reads.
    private func readMemory(_ id: String) -> DeviceMemory {
        let memory = DeviceMemory(revs: store.readItemRevMemory(id), manifests: store.readManifestMemory(id))
        noteMemory(id, readable: memory.revs != nil && memory.manifests != nil)
        return memory
    }

    /// Count how often in a row the device memory couldn't be read. After three, across a sync
    /// with the server that went through, the app says so and offers the reset: a file that is
    /// damaged stays unreadable for good, and without the reset every vault with a manifest
    /// would stay unchecked (and unwritable) on this device.
    private func noteMemory(_ id: String, readable: Bool) {
        if readable {
            if memoryFailures?.account == id { memoryFailures = nil }
            if id == activeId, memoryProblem { memoryProblem = false }
            return
        }
        var f = memoryFailures.flatMap { $0.account == id ? $0 : nil } ?? (account: id, count: 0, synced: false)
        f.count += 1
        memoryFailures = f
        if id == activeId, f.count >= 3, f.synced, !memoryProblem { memoryProblem = true }
    }

    /// "Reset on this device" (after the user confirmed): the record this device keeps of the
    /// account's vaults can't be read, so it is moved out of the way and the device goes on as
    /// one that remembers nothing: what the server shows now is checked against its manifests
    /// and trusted as the first sight. Files that do read are left as they are.
    public func resetDeviceMemory() async throws {
        try await lock.run {
            let id = activeId
            guard store.setAsideUnreadableMemory(id) else {
                throw UserError("PassAuth couldn't reset this device's record. Try again in a moment.")
            }
            memoryFailures = nil
            memoryProblem = false
            guard sessions[id] != nil, vault != nil else { return }
            try await syncLocked()
        }
    }

    /// The copy stored on the device, opened and checked against the device memory (read first);
    /// nil when there is none (or the session changed).
    private func openCached(_ id: String, _ session: Session) async throws -> Checked? {
        let memory = readMemory(id)
        guard let cached = await readSnapshot(id) else { return nil }
        guard sessions[id] === session, activeId == id else { return nil }
        do {
            return try await evaluate(id, session, cached, source: .cache, memory: memory, finalIncomplete: false)
        } catch {
            throw CheckFailed(error: error)
        }
    }

    /// The verdicts of the vaults shown now (the active account's), by vault.
    private func shownVerdicts(_ id: String) -> [String: ManifestStatus] {
        guard copy?.account == id, let v = vault else { return [:] }
        return Dictionary(v.vaults.map { ($0.id, $0.manifest) }, uniquingKeysWith: { a, _ in a })
    }

    /// Ask the server and check its answer; nothing is shown or stored here, so whatever fails
    /// leaves the previous copy, cursor and verdicts.
    ///
    /// Vault manifests: before a vault gets a warning it didn't have, the answer must have been
    /// everything: after a delta (whose base is this device's own copy) everything is fetched
    /// once; an answer that is behind what this device remembers is asked for again (twice at
    /// most in all), and what still doesn't match then is the server's answer and is warned
    /// about. Rows that can't be checked yet (trashed rows cached before manifests: no data, no
    /// hash) after a delta or a summary answer: everything is fetched once (the server sends the
    /// hashes now); what still can't be checked then is a mismatch. A vault whose manifest log is
    /// needed and can't be fetched fails the whole sync (`evaluate`).
    private func fetchChecked(_ id: String, _ session: Session) async throws -> Checked? {
        var full = false
        var refetched = 0
        while true {
            let memory = readMemory(id)
            let snapshot = try await fetchSnapshot(id, full: full)
            // The server answered `/sync`: it doesn't (or no longer) require two-step setup first.
            twoStepGated.remove(id)
            guard sessions[id] === session, activeId == id else { return nil }
            let final = full || !fetchedPartial
            let delta = !full && fetchedDelta
            let checked: Checked?
            do {
                checked = try await evaluate(id, session, snapshot, source: .server, memory: memory, finalIncomplete: final)
            } catch let e as ManifestLogUnavailable {
                throw e.error
            } catch {
                throw CheckFailed(error: error)
            }
            guard let checked else { return nil }
            let before = shownVerdicts(id)
            let vaults = checked.opened.data.vaults
            let warned = vaults.filter { $0.manifest.warns && before[$0.id]?.warns != true }
            let incomplete = vaults.contains { $0.manifest == .incomplete }
            let again = (incomplete && !final) || (!warned.isEmpty && (delta || warned.contains { $0.manifest == .rollback }))
            guard again, refetched < 2 else { return checked }
            refetched += 1
            full = true
        }
    }

    /// The vault's manifest log could not be fetched (no answer, a server error, too many
    /// requests): the sync has failed; the previous copy and verdicts stay.
    private struct ManifestLogUnavailable: Error { let error: Error }

    /// `GET /vaults/{id}/manifest-log?after=<version>`: the entries after the version this device
    /// remembers, as one JSON list (pages followed, five requests at most). nil: the server's
    /// answer is that there is no such log (404, 400), an answer that isn't one, or more pages
    /// than a device follows: the manifest doesn't connect (a mismatch). Throws when no answer
    /// came (network, 5xx, 429, a lost session): not a verdict.
    private func manifestLog(_ id: String, _ vaultId: String, after: UInt64) async throws -> String? {
        var entries: [JSON] = []
        var from = Int64(clamping: after)
        for _ in 0..<VaultManifest.logRequests {
            let answer: JSON
            do {
                answer = try await api.call(id, "/vaults/\(Self.pathPart(vaultId))/manifest-log?after=\(from)")
            } catch let e as ApiError where e.status == 404 || e.status == 400 {
                return nil
            }
            guard let page = VaultManifest.logPage(answer) else { return nil }
            entries += page.entries
            guard page.more else { return JSON.array(entries).text }
            // The next page starts after the last entry; a page that doesn't move on isn't a log.
            guard let last = page.last, last > from else { return nil }
            from = last
        }
        return nil
    }

    /// Decrypt `given` (only what changed since the copy shown now) and check it; nothing is
    /// shown or stored (`commit`). nil: the session changed meanwhile.
    ///
    /// Signed sharing: the signing identity, key pins and newer member rosters are made ready
    /// first (`sharingInputs`; with the server unless the copy is the stored one), and every
    /// vault and invitation is checked while decrypting.
    ///
    /// Vault manifests: every usable vault is checked against its manifest (`open`,
    /// `checkManifests`) with `memory`, read before the copy was. A server answer whose manifest
    /// is more than one step ahead of the remembered one needs the vault's manifest log: it is
    /// fetched and the vault checked again with it; when it can't be fetched the whole answer
    /// counts as not received (`ManifestLogUnavailable`).
    ///
    /// `ownCopy`: `given` is the copy this process already showed (checked again after an
    /// acceptance), not a new answer.
    private func evaluate(_ id: String, _ session: Session, _ given: SyncSnapshot, source: CopySource, memory: DeviceMemory,
                          finalIncomplete: Bool, ownCopy: Bool = false) async throws -> Checked? {
        let account = session.account
        var fresh = given
        let cached: Bool = if case .cache = source { true } else { false }
        let refreshed: Bool = if case .refreshed = source { true } else { false }
        // Read from this device (the copy, or what a background refresh kept): nothing is asked
        // of the server for it.
        let stored = cached || refreshed
        if !session.earlierCopyRead {
            // Grandfathering rule 1: what this device showed before this session shows anything.
            _ = await earlierCopy(id, session, given: cached ? given : nil)
        }
        let local: Bool = if case .local = source { true } else { false }
        if local || ownCopy {
            // This device's own write applied to its copy: the copy's `user.key_pins_seq` is from
            // the last answer, read before this session wrote its key pins. Raised to what the
            // server has stored from this device, so the copy isn't taken for a server that
            // sent an older list of known keys.
            let written = loadMemory(id, session).serverBase
            if written > (fresh.user?["key_pins_seq"]?.number ?? 0), case .object(var user)? = fresh.user {
                user["key_pins_seq"] = .int(written)
                fresh.user = .object(user)
            }
        }
        let sharing = try await sharingInputs(id, session, &fresh, network: !stored)
        let served = fresh
        guard sessions[id] === session, activeId == id else { return nil }
        let previous: OpenedVault? = copy?.account == id ? vault.map { OpenedVault(data: $0, keys: vaultKeys, headers: vaultHeaders, names: invitationNames) } : nil
        let invitations = isApp
        let fullRows = !trashSummary
        let revs = memory.revs?.revs
        let marks = memory.manifests
        var opened = try await core {
            Self.open(account, served, previous: previous, invitations: invitations, sharing: sharing, revs: revs,
                      manifests: marks, finalIncomplete: finalIncomplete, source: source, fullRows: fullRows)
        }
        guard sessions[id] === session, activeId == id else { return nil }
        if case .server = source, !opened.needLog.isEmpty {
            var logs: [String: String] = [:]
            var noLog = Set<String>()
            for vid in opened.needLog {
                do {
                    if let log = try await manifestLog(id, vid, after: marks?[vid]?.version ?? 0) { logs[vid] = log } else { noLog.insert(vid) }
                } catch {
                    throw ManifestLogUnavailable(error: error)
                }
                guard sessions[id] === session, activeId == id else { return nil }
            }
            let first = opened, fetched = logs, missing = noLog
            let before = previous.map { Dictionary($0.data.vaults.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }) } ?? [:]
            opened = try await core {
                var o = first
                Self.checkManifests(&o, served, memory: marks, logs: fetched, noLog: missing, source: .server, previous: before,
                                    finalIncomplete: finalIncomplete, fullRows: fullRows)
                return o
            }
        }
        return Checked(snapshot: served, opened: opened, memory: memory, source: source)
    }

    /// This device's own write applied to the copy shown: opened, checked (`CopySource.local`:
    /// with this process's own memory, only the vaults written to), shown and stored.
    private func showLocal(_ id: String, _ session: Session, _ next: SyncSnapshot, wrote: [String: ManifestMark], gone: Set<String> = []) async throws {
        let memory = known.flatMap { $0.account == id ? $0.memory : nil } ?? readMemory(id)
        guard let checked = try await evaluate(id, session, next, source: .local(wrote: wrote, gone: gone), memory: memory, finalIncomplete: false) else { return }
        try await commit(id, session, checked, offline: false, store: .localChange)
    }

    /// Show a checked copy. `.synced`: fresh from the server, stored as the offline copy with the
    /// time of the sync, the profile name and the bundle; `.localChange`: this device's write
    /// applied to the copy, stored too. Afterwards signed sharing's device memory is saved and
    /// the key pins written when they changed (`finishSharing`).
    ///
    /// The device memory (item edit counters, manifest marks, trash first seen) is written after
    /// the copy it was learnt from is stored: a mark is only ever remembered together with the
    /// copy that carries it, and the other process reads the memory before the copy.
    private func commit(_ id: String, _ session: Session, _ checked: Checked, offline: Bool, store mode: CopyStore) async throws {
        let account = session.account
        let opened = checked.opened
        // A rolled-back item whose newer copy this device kept: the copy keeps that row.
        let snapshot = Self.keeping(opened.keptRows, in: checked.snapshot)
        if mode == .synced { session.accountWrapsV2 = snapshot.user?["account_wraps_v2"] == .bool(true) }
        if mode != .none {
            let data = try await core { try snapshot.encoded() }
            await store.writeCacheInBackground(id, data)
            if mode == .synced {
                // Newer than anything a background refresh kept: that is no longer needed.
                store.deleteRefreshed(id)
                if memoryFailures?.account == id {
                    memoryFailures?.synced = true
                    if id == activeId, (memoryFailures?.count ?? 0) >= 3 { memoryProblem = true }
                }
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
        let now = clock()
        var after = checked.memory
        if let before = checked.memory.revs, let observed = opened.revs {
            // An item is forgotten only when its absence is authenticated: gone from a vault whose
            // manifest matched this answer, or deleted for good by this device just now.
            var absentOk = Set<String>()
            var gone = Set<String>()
            switch checked.source {
            case .server, .refreshed: absentOk = Set(opened.data.vaults.filter { $0.manifest == .ok }.map(\.id))
            case .cache: break
            case .local(let wrote, let deleted):
                absentOk = Set(wrote.keys)
                gone = deleted
            }
            var settled = ItemRevCheck.settle(before, observed: observed, rows: snapshot.items.map { (id: $0.id, vault: $0.vaultId) }, absentOk: absentOk, now: now)
            let present = Set(snapshot.items.map(\.id))
            for g in gone where !present.contains(g) && settled.memory.items[g] != nil {
                settled.memory.items[g] = nil
                settled.dropped.insert(g)
            }
            if settled.memory != before { store.writeItemRevMemory(id, settled.memory, dropped: settled.dropped) }
            after.revs = settled.memory
        }
        if let seen = opened.manifests {
            if seen != checked.memory.manifests { store.writeManifestMemory(id, seen) }
            after.manifests = seen
        }
        if isApp, !preferCache, mode != .none, let stored = store.readTrashSeen(id) {
            // Old trash is only deleted after this device itself saw it wait (`maintainManifests`).
            let next = VaultManifest.trashSeen(stored, rows: snapshot.items, now: now)
            if next != stored { store.writeTrashSeen(id, next) }
        }
        guard sessions[id] === session, activeId == id else { return }
        known = (id, after)
        let before = vault.map { Self.keyShape($0.vaults) }
        vaultKeys = opened.keys
        vaultHeaders = opened.headers
        invitationNames = opened.names
        copy = (id, snapshot)
        var v = opened.data
        v.offline = offline
        vault = v
        refreshIdentities()
        if let out = opened.sharing { await finishSharing(id, session, out, network: mode == .synced || mode == .localChange) }
        // What this device showed as usable: the "earlier copy" of later unlocks (rule 6).
        recordSeen(id, session, v.vaults.map(\.id))
        // A vault came or went, or a key was replaced (here or on another device): personal vaults
        // may need new emergency-access wraps. The first sync after unlocking runs it from `afterOpen`.
        if let before, before != Self.keyShape(v.vaults) { vaultKeysChanged() }
    }

    /// `snapshot` with the rows this device kept (rolled-back items' newer copies) in place of the served ones.
    nonisolated static func keeping(_ rows: [String: SyncItem], in snapshot: SyncSnapshot) -> SyncSnapshot {
        guard !rows.isEmpty else { return snapshot }
        var s = snapshot
        for i in s.items.indices { if let r = rows[s.items[i].id], r.vaultId == s.items[i].vaultId { s.items[i] = r } }
        return s
    }

    /// What decides which vaults get emergency-access wraps: each vault's id, key epoch, role and
    /// key kind (a vault becoming the user's own, or shared, changes whether it is personal).
    nonisolated static func keyShape(_ vaults: [VaultInfo]) -> [String] {
        vaults.map { "\($0.id):\($0.keyEpoch ?? -1):\($0.role.rawValue):\($0.keyKind)" }
    }

    /// The account's copy after asking the server: since the copy's cursor when the server does
    /// delta sync, else everything. The base is the copy shown now, or the one on the device.
    /// `full`: everything, whatever the copy holds.
    ///
    /// Part S: nothing is asked of a server without signed sharing (`requireSupportedServer`).
    func fetchSnapshot(_ id: String, full: Bool = false) async throws -> SyncSnapshot {
        let base: SyncSnapshot? = if full { nil } else if let c = copy, c.account == id { c.snapshot } else { await readSnapshot(id) }
        let listed = await deltaSyncEnabled(id)
        try await requireSupportedServer(id)
        let delta = listed && !full
        fetchedDelta = delta && base?.cursor?.isEmpty == false
        fetchedPartial = trashSummary || fetchedDelta
        let api = self.api
        return try await DeltaSync.fetch(base: base, delta: delta, trashSummary: trashSummary) { path in
            try await api.callData(id, path)
        }
    }

    /// Part S: this app only uses a server whose `/api/config` lists signed sharing
    /// (`ServerSupport`). Decided from the features kept with the account; a refusal is asked
    /// again first (the server may have been updated), and `ask` (before a sign-in) always asks.
    /// With a list kept that names signed sharing, a config that can't be fetched now changes
    /// nothing (offline). With none kept (the server's settings were never read on this device),
    /// one that can't be fetched or read means the server isn't used at all: "PassAuth couldn't
    /// reach your server…", so breaking `/api/config` never gets a server past the check. Throws
    /// "Update your PassAuth server to keep using this app."; nothing is requested from or sent
    /// to such a server after that.
    func requireSupportedServer(_ id: String, ask: Bool = false) async throws {
        guard requiresSignedSharing else { return }
        var stored = store.get().file.accounts[id]?.features
        if ask || stored == nil || ServerSupport.refused(features: stored) {
            if let config = await fetchConfig(id) { stored = config.features }
        }
        guard let features = stored else { throw UserError(ServerSupport.unreachable) }
        let refused = ServerSupport.refused(features: features)
        if id == activeId { serverProblem = refused ? ServerSupport.updateServer : nil }
        if refused { throw UserError(ServerSupport.updateServer) }
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
    /// at least as new as the copy on disk is kept (`DeltaSync.refresh`). The active account,
    /// when unlocked, gets a normal sync instead (without the upkeep a sync in the foreground
    /// does: no first manifest, no old trash).
    ///
    /// Nothing can be checked here (no keys), so what is fetched never replaces the offline
    /// copy, which only ever holds what an unlocked app checked: it is kept next to it
    /// (`SecureStore.writeRefreshedInBackground`) and checked at the next unlock
    /// (`adoptRefreshed`). The next refresh goes on from what the last one kept.
    public func refreshCacheLocked(accountId id: String) async throws {
        if sessions[id] != nil && activeId == id {
            try await syncQueue.run { try await self.lock.run { try await self.syncLocked(upkeep: false) } }
            return
        }
        let s = store.get()
        guard let a = s.file.accounts[id], a.isListed, s.tokens(id) != nil else { return }
        let checkedCopy = await readSnapshot(id)
        let kept = await readRefreshed(id)
        // The base: what an earlier refresh kept, unless the checked copy has moved past it.
        let fromKept = kept.map { k in checkedCopy.map { k.revision >= $0.revision } ?? true } ?? false
        let cached = fromKept ? kept : checkedCopy
        let delta = await deltaSyncEnabled(id)
        // Part S: nothing is fetched from a server without signed sharing.
        try await requireSupportedServer(id)
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
            // What it was based on moved on meanwhile (the AutoFill extension synced or saved
            // something, another refresh ran): this answer is based on the older one.
            let current = fromKept ? await readRefreshed(id) : await readSnapshot(id)
            guard current?.revision == cached?.revision, current?.cursor == cached?.cursor, current?.position == cached?.position else { return }
            await store.writeRefreshedInBackground(id, data)
            store.updateAccount(id) { a in
                a.lastSync = Date().timeIntervalSince1970
                if let bundle = next.bundle?.text, Self.bundleMayBeStored(bundle, account: nil, authenticatedId: a.accountId) { a.bundle = bundle }
            }
        }
    }

    /// What a background refresh kept for the account (nil: nothing, or it can't be read).
    private func readRefreshed(_ id: String) async -> SyncSnapshot? {
        guard store.hasRefreshed(id), let data = await store.readRefreshedInBackground(id) else { return nil }
        return await Task.detached(priority: .userInitiated) { SyncSnapshot.decode(data) }.value
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
    ///
    /// Vault manifests: a change is only applied to the copy when the manifest sent with it
    /// (`sent`) is the vault's current one by the answer: its `manifest_link` is the link of
    /// the one sent (the version alone isn't enough: a create sent twice gets the first
    /// attempt's answer, with the same version and another manifest). The vault row then takes
    /// that manifest with the change. A vault with a manifest and none sent, any other link, or
    /// an answer that says the vault's number didn't move: sync (and check).
    private func afterWrite(_ vaultId: String, _ answer: JSON, _ change: LocalChange?, sent: ManifestEntry? = nil) async {
        let id = activeId
        guard let change, let c = copy, c.account == id, let session = sessions[id] else { return await syncAfterWrite() }
        let row = c.snapshot.vaults.first { $0.id == vaultId }
        let known = row?.seq
        let seq = Self.number(answer["vault_seq"])
        let answered = Self.number(answer["manifest_seq"])
        let current = sent.map { answer["manifest_link"]?.string == $0.link } ?? ((row?.manifestVersion ?? 0) == 0 && (answered ?? 0) == 0)
        switch SyncDecision.afterWrite(known: known, vaultSeq: seq) {
        case .nothing:
            // With a manifest sent, the copy can't already have this write: ask.
            if sent != nil { await syncAfterWrite() }
            return
        case .sync:
            return await syncAfterWrite()
        case .applyLocally:
            guard current, let seq, let next = SyncMerge.applyLocal(change, vaultId: vaultId, vaultSeq: seq, manifest: sent, to: c.snapshot) else {
                return await syncAfterWrite()
            }
            // Only the vault written to is touched; with a manifest, the one this device sent
            // (and its link) is what the row now carries and what is remembered with the copy.
            var gone = Set<String>()
            if case .purge(let item) = change { gone = [item] }
            do {
                try await showLocal(id, session, next, wrote: sent.map { [vaultId: $0.mark] } ?? [:], gone: gone)
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
    ///
    /// `revs` (rollback detection; nil: not checked): the highest item edit counter this device
    /// saw per item. An item served with a lower one is marked; the newer copy `previous` holds is
    /// shown instead (and its row kept in the copy, `keptRows`) when its vault's key is unchanged.
    /// The stored copy (`source` `.cache`) marks nothing by its counters: only the server's
    /// answer does. A row that is such a kept newer copy (`servedSha256`) stays marked for as
    /// long as the copy holds it, whatever the counters say, until the row is written again.
    /// The returned `revs` are the counters after this copy (nothing forgotten: `ItemRevCheck.settle`).
    ///
    /// `manifests` (vault manifests; nil: the memory can't be read): what this device remembers
    /// per vault. Every usable vault's rows, as the copy keeps them, are checked against the
    /// vault row's manifest (`checkManifests`); the verdict is on its `VaultInfo`.
    /// `finalIncomplete`: everything was just fetched, so rows that still can't be checked count
    /// as a mismatch. `fullRows`: this app asks for every row whole, so a row without its data
    /// is a mismatch too. `source`: where the copy comes from (`CopySource`).
    nonisolated static func open(_ account: Account, _ snap: SyncSnapshot, previous: OpenedVault?, invitations: Bool = false,
                                 sharing: SharingInputs? = nil, revs: [String: UInt64]? = nil,
                                 manifests: [String: ManifestMark]? = [:], finalIncomplete: Bool = false,
                                 source: CopySource = .server, fullRows: Bool = false) -> OpenedVault {
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
                let epoch = UInt64(max(0, v.keyEpoch ?? 0))
                // With the checks on, a legacy wrap the pins can't be asked about is refused.
                let legacy = sharing.map { _ in (try? pinsLegacyWrapAllowed(pinsJson: outputs?.pins, vaultId: v.id, keyEpoch: epoch)) ?? false } ?? true
                guard let k = try? account.openVaultKey(vaultId: v.id, wrapped: v.wrappedKey, kind: v.keyKind,
                                                        keyEpoch: epoch, legacyAllowed: legacy) else { continue }
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
        var memory = revs
        var rollback = ItemRollback()
        var keptRows: [String: SyncItem] = [:]
        var unreadable = Set<String>()
        let fromCache: Bool = if case .cache = source { true } else { false }
        for row in snap.items {
            guard let key = keys[row.vaultId] else { continue }
            guard let itemKey = row.itemKey, let data = row.data else {
                // A trashed row kept as a summary (neither key nor data) is as this app asked for
                // it. One that has its data but no key, or lacks its data where whole rows are
                // asked for, can never be opened: a hidden item, like one that doesn't decrypt.
                if row.data != nil || fullRows {
                    unreadable.insert(row.vaultId)
                    out.unopenable.append(UnopenableItem(id: row.id, vaultId: row.vaultId, revision: row.revision, deletedAt: row.deletedAt))
                }
                continue
            }
            var enc = EncryptedItem(id: row.id, vaultId: row.vaultId, key: itemKey, data: data)
            var item: Item
            if kept.contains(row.vaultId), let old = before[row.id], old.vaultId == row.vaultId, old.enc.key == itemKey, old.enc.data == data {
                item = old.item
            } else {
                // A row that doesn't open with its vault's key is a hidden item: its vault never
                // counts as matching its manifest (a hash alone would pass).
                guard let json = try? key.decryptItem(encrypted: enc) else {
                    unreadable.insert(row.vaultId)
                    out.unopenable.append(UnopenableItem(id: row.id, vaultId: row.vaultId, revision: row.revision, deletedAt: row.deletedAt))
                    continue
                }
                guard let decoded = try? ItemCodec.decode(json) else { continue }
                item = decoded
            }
            var rolledBack = false
            if row.servedSha256 != nil {
                // A newer copy this device kept after the server sent an older version: marked
                // for as long as the copy holds it.
                rolledBack = true
                rollback.items.insert(row.id)
                rollback.kept.insert(row.id)
            }
            if var m = memory {
                if ItemRevCheck.observe(&m, id: row.id, served: item.rev) == .rollback, !fromCache {
                    rolledBack = true
                    rollback.items.insert(row.id)
                    // The newer copy this device has, while its vault keeps the key it was read with.
                    if kept.contains(row.vaultId), let old = before[row.id], old.vaultId == row.vaultId, old.item.rev > item.rev {
                        item = old.item
                        enc = old.enc
                        rollback.kept.insert(row.id)
                        var r = row
                        r.itemKey = old.enc.key
                        r.data = old.enc.data
                        // What the server sent for it: the vault's manifest is checked with that.
                        r.servedSha256 = VaultManifest.dataHash(data)
                        keptRows[row.id] = r
                    }
                }
                memory = m
            }
            let e = Entry(id: row.id, item: item, vaultId: row.vaultId, revision: row.revision ?? 0, enc: enc, deletedAt: row.deletedAt,
                          rolledBack: rolledBack)
            if row.deletedAt == nil { out.entries.append(e) } else { out.trash.append(e) }
        }
        if !rollback.items.isEmpty { out.rollback = rollback }
        out.unopenable.sort { $0.id < $1.id }
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
        var opened = OpenedVault(data: out, keys: keys, headers: headers, names: names, sharing: outputs, revs: memory, keptRows: keptRows,
                                 unreadable: unreadable)
        let verdicts = Dictionary((previous?.data.vaults ?? []).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        checkManifests(&opened, snap, memory: manifests, source: source, previous: verdicts, finalIncomplete: finalIncomplete, fullRows: fullRows)
        return opened
    }

    /// Vault manifests: every usable vault of an opened copy against its manifest, over the rows
    /// the copy keeps (never over part of an answer; a rolled-back item's newer row counts with
    /// the hash of the data the server sent for it). The verdict goes on the vault's `VaultInfo`,
    /// what to remember from now on into `manifests`.
    ///
    /// - A server's answer (`.server`): the core's verdict. A manifest that is two or more
    ///   versions ahead of the remembered one needs the vault's log: the vault is listed in
    ///   `needLog` and stays `unchecked` until this runs again with it (`logs`: the entries by
    ///   vault; `noLog`: the server has none to give, which is a mismatch).
    /// - Items that can't be opened (`unreadable`, and where this app asks for whole rows,
    ///   `fullRows`, a row without its data): a hidden item is a mismatch, whatever the manifest
    ///   says. When the manifest itself matches, that is the vault's only problem (`unopenable`
    ///   on its `VaultInfo`): the manifest is remembered as for any match, and deleting the item
    ///   clears the warning.
    /// - A warned vault is also checked with nothing remembered (`VaultManifest.accept`): when
    ///   the served manifest describes the served items, or there is none, "Use the server's
    ///   copy" only changes this device's memory (`manifestAcceptable`).
    /// - The stored copy (`.cache`): only `ok`, `none` and `incomplete` are verdicts. Anything
    ///   else is `unchecked`: no warning, no write, until the server's answer is checked (the
    ///   copy may simply be older than what the other process already saw).
    /// - What a background refresh kept (`.refreshed`): checked like a server's answer, without
    ///   the log (a vault that needs it is `unchecked`); the caller adopts it only when every
    ///   vault is `ok` or `none`.
    /// - This device's own write (`.local`): the vaults it wrote to are `ok` at the manifest it
    ///   sent (nothing to verify: it made that manifest), unless an item still can't be opened;
    ///   every other vault keeps its verdict.
    /// - `memory` nil (it can't be read now): nothing is checked against a memory that isn't
    ///   there and nothing is remembered; a warning stays, a vault without a manifest stays as
    ///   writable as it was (`none`), every vault with one is `unchecked`.
    nonisolated static func checkManifests(_ o: inout OpenedVault, _ snap: SyncSnapshot, memory: [String: ManifestMark]?, logs: [String: String] = [:],
                                           noLog: Set<String> = [], source: CopySource, previous: [String: VaultInfo],
                                           finalIncomplete: Bool, fullRows: Bool) {
        var byVault: [String: [SyncItem]] = [:]
        for row in snap.items where o.keys[row.vaultId] != nil {
            let kept = o.keptRows[row.id].flatMap { $0.vaultId == row.vaultId ? $0 : nil }
            byVault[row.vaultId, default: []].append(kept ?? row)
        }
        var marks = memory
        var needLog: [String] = []
        for i in o.data.vaults.indices {
            let vid = o.data.vaults[i].id
            guard let key = o.keys[vid], let header = o.headers[vid] else { continue }
            let before = previous[vid]
            let rows = byVault[vid] ?? []
            // A vault with an item nobody can open never counts as matching its manifest (a hash
            // alone would pass), also right after this device wrote a manifest over it.
            let hidden = o.unreadable.contains(vid) || (fullRows && rows.contains { $0.data == nil })
            func set(_ status: ManifestStatus, acceptable: Bool = false, unopenable: Bool = false) {
                o.data.vaults[i].manifest = status
                o.data.vaults[i].manifestAcceptable = acceptable
                o.data.vaults[i].unopenable = unopenable
            }
            func keep(_ b: VaultInfo) { set(b.manifest, acceptable: b.manifestAcceptable, unopenable: b.unopenable) }
            if case .local(let wrote, _) = source {
                if let mark = wrote[vid] {
                    set(hidden ? .mismatch : .ok, unopenable: hidden)
                    let stored = marks?[vid]
                    if mark.valid, mark.version > (stored?.rank ?? 0) {
                        marks?[vid] = ManifestMark(version: mark.version, link: mark.link, accepts: stored?.accepts ?? 0)
                    }
                } else if let before {
                    keep(before)
                } else {
                    set(header.manifestVersion == 0 && marks != nil && marks?[vid]?.valid != true ? .none : .unchecked)
                }
                continue
            }
            guard var m = marks else {
                if let before, before.manifest.warns { keep(before) } else { set(header.manifestVersion == 0 ? .none : .unchecked) }
                continue
            }
            var check = VaultManifest.verify(header, key: key, remembered: m[vid], log: logs[vid], rows: rows)
            if check.status == .needLog && noLog.contains(vid) { check = (.mismatch, nil) }
            if check.status == .incomplete && finalIncomplete { check = (.mismatch, nil) }
            // The manifest matches (and is remembered as such); the one thing wrong is the item.
            var onlyHidden = false
            if check.status == .ok && hidden {
                VaultManifest.remember(&m, vault: vid, status: .ok, mark: check.mark)
                check = (.mismatch, nil)
                onlyHidden = true
            }
            switch source {
            case .cache:
                if check.status.warns || check.status == .needLog {
                    check = (.unchecked, nil)
                    onlyHidden = false
                }
            default:
                if check.status == .needLog {
                    if case .server = source { needLog.append(vid) }
                    check = (.unchecked, nil)
                }
            }
            var acceptable = false
            if check.status.warns && !onlyHidden {
                let accepted = VaultManifest.accept(header, key: key, rows: rows).status
                acceptable = accepted == .ok || accepted == .none
            }
            VaultManifest.remember(&m, vault: vid, status: check.status, mark: check.mark)
            marks = m
            set(check.status, acceptable: acceptable, unopenable: onlyHidden)
        }
        o.manifests = marks
        o.needLog = needLog
    }

    // MARK: Items

    private var now: Int64 { Int64(Date().timeIntervalSince1970) }

    private func requireVault() throws -> VaultData {
        guard let v = vault else { throw UserError("Your vault is locked.") }
        if v.offline { throw UserError(serverProblem ?? "You're offline. Changes can be saved once PassAuth reaches your server.") }
        // Part S: nothing is written to a server whose known config has no signed sharing.
        if requiresSignedSharing, ServerSupport.refused(features: store.get().file.accounts[activeId]?.features) {
            throw UserError(ServerSupport.updateServer)
        }
        return v
    }

    /// `requireVault` for a write. A vault that isn't checked against an answer of the server yet
    /// (opened from the copy on the device, rows that can't be checked yet) makes the write wait
    /// for a sync first (`synced`: one ran, so what the caller read before may be older).
    private func vaultForWrite() async throws -> (vault: VaultData, synced: Bool) {
        let v = try requireVault()
        guard v.vaults.contains(where: { $0.manifest.pending }) else { return (v, false) }
        try await syncLocked()
        return (try requireVault(), true)
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
        var v = try await vaultForWrite().vault
        let id: String
        if let requested { id = requested } else { id = try await core { try newId() } }
        var next = item
        next.createdAt = now
        next.updatedAt = now
        let json = ItemCodec.encode(next)
        var retried = false
        var sends = 0
        var written: (answer: JSON, enc: EncryptedItem, vault: String, sent: ManifestEntry?)?
        while true {
            let target = try vaultId.flatMap { want in v.vaults.first { $0.id == want } } ?? writableVault(v)
            guard let key = vaultKeys[target.id] else { throw UserError("Vault not found.") }
            let targetId = target.id
            let enc = try await core { try key.encryptItem(itemJson: json, id: id, vaultId: targetId) }
            // The vault's next manifest: with the new row (nil: the vault has none).
            let sent = try await nextManifest(targetId, removed: [], added: [SyncItem(id: id, vaultId: targetId, itemKey: nil, data: enc.data)])
            do {
                let answer = try await api.call(activeId, "/items", body: Self.body(enc, keyEpoch: target.keyEpoch, manifests: [sent]))
                written = (answer, enc, targetId, sent)
                break
            } catch let e as ApiError where VaultManifest.retry(e) {
                // Something else changed in the vault (nothing was written): sync, check, again.
                sends += 1
                guard sends < VaultManifest.attempts else { throw UserError(ManifestText.busy) }
                try await syncLocked()
                v = try requireVault()
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
            await afterWrite(w.vault, w.answer, change, sent: w.sent)
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
        let ready = try await vaultForWrite()
        var v = ready.vault
        var next = item
        next.updatedAt = now
        let old = base.item.login?.password ?? ""
        if next.login != nil, !old.isEmpty, old != next.login?.password, next.passwordHistory == base.item.passwordHistory {
            next.passwordHistory = Array(([PasswordChange(password: old, changedAt: now)] + next.passwordHistory).prefix(20))
        }
        let json = ItemCodec.encode(next)
        var entry = base
        if ready.synced {
            // The copy moved on under the editor: the same rule as after any sync in between.
            guard let fresh = v.get(base.id) else { throw UserError("This item was deleted on another device.") }
            guard fresh.vaultId == base.vaultId, fresh.deletedAt == base.deletedAt, fresh.item == base.item else {
                throw ConflictError(itemId: base.id)
            }
            entry = fresh
        }
        var retried = false
        var sends = 0
        var written: (answer: JSON, enc: EncryptedItem, vault: String, moved: Bool, sent: ManifestEntry?)?
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
            // The next manifest of the item's vault without the row as the copy holds it and, of
            // the vault it is in afterwards (the same, or the one it moves to), with the new one.
            let after = SyncItem(id: entryId, vaultId: targetId, itemKey: nil, data: enc.data, deletedAt: entry.deletedAt)
            let before = copyRows([entryId], in: entry.vaultId)
            // The copy its manifest was checked with no longer has the item.
            if before.isEmpty && hasManifest(entry.vaultId) { throw UserError("This item was deleted on another device.") }
            var manifests: [ManifestEntry?]
            if same {
                manifests = [try await nextManifest(targetId, removed: before, added: [after])]
            } else {
                manifests = [try await nextManifest(entry.vaultId, removed: before, added: []),
                             try await nextManifest(targetId, removed: [], added: [after])]
            }
            do {
                let answer = try await api.call(activeId, "/items/\(entry.id)",
                                                body: Self.body(enc, keyEpoch: target.keyEpoch, revision: entry.revision, manifests: manifests), method: "PUT")
                written = (answer, enc, targetId, !same, same ? manifests[0] : nil)
                break
            } catch let e as ApiError where VaultManifest.retry(e) {
                // Something else changed in the vault (nothing was written): sync and check, then
                // the same rule as for a replaced key: only for the content the change was made to.
                sends += 1
                guard sends < VaultManifest.attempts else { throw UserError(ManifestText.busy) }
                try await syncLocked()
                v = try requireVault()
                guard let fresh = v.get(base.id) else { throw UserError("This item was deleted on another device.") }
                guard fresh.vaultId == base.vaultId, fresh.deletedAt == base.deletedAt, fresh.item == base.item else {
                    throw ConflictError(itemId: base.id)
                }
                entry = fresh
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
        await afterWrite(w.vault, w.answer, change, sent: w.sent)
    }

    public func setFavorite(_ entry: Entry, _ favorite: Bool) async throws {
        var i = entry.item
        i.favorite = favorite
        try await updateItem(entry, i)
    }

    public func trashItem(_ entry: Entry) async throws {
        try await lock.run { try await changeState(entry, .trash) }
    }

    public func restoreItem(_ entry: Entry) async throws {
        try await lock.run { try await changeState(entry, .restore) }
    }

    /// Delete an item in the trash for good.
    public func purgeItem(_ entry: Entry) async throws {
        try await lock.run { try await changeState(entry, .purge) }
    }

    private enum StateChange { case trash, restore, purge }

    /// Trash, restore or delete for good. In a vault with a manifest the request carries the
    /// item's revision and the vault's next manifest (in the query: these requests have no
    /// body). When something else changed meanwhile (`manifest_conflict`, `manifest_required`,
    /// or this item: `revision_conflict`) the vault is synced and checked and the change sent
    /// again, three times at most, unless the item is gone or already where it should be.
    private func changeState(_ entry: Entry, _ kind: StateChange) async throws {
        let ready = try await vaultForWrite()
        var v = ready.vault
        if !v.canWrite(entry) { throw UserError("You can only view items in this vault.") }
        var current = entry
        if ready.synced {
            // Gone, or already where it should be: done.
            guard let fresh = v.get(entry.id), fresh.vaultId == entry.vaultId else { return }
            switch kind {
            case .trash: if fresh.deletedAt != nil { return }
            case .restore: if fresh.deletedAt == nil { return }
            case .purge: break
            }
            current = fresh
        }
        var sends = 0
        while true {
            let vid = current.vaultId
            let before = copyRows([current.id], in: vid)
            // The copy its manifest was checked with no longer has the item: nothing to do.
            if before.isEmpty && hasManifest(vid) { return }
            var added: [SyncItem] = []
            if kind != .purge, var row = before.first {
                row.deletedAt = kind == .trash ? now : nil
                added = [row]
            }
            let sent = try await nextManifest(vid, removed: before, added: added)
            var path = "/items/\(current.id)" + (kind == .restore ? "/restore" : kind == .purge ? "/permanent" : "")
            if let sent { path += "?revision=\(current.revision)&" + sent.query }
            do {
                let answer = try await api.call(activeId, path, method: kind == .restore ? "POST" : "DELETE")
                let change: LocalChange?
                switch kind {
                case .trash:
                    let summary = trashSummary
                    change = Self.number(answer["revision"]).map { LocalChange.trash(id: current.id, at: now, revision: $0, summary: summary) }
                case .restore:
                    change = Self.number(answer["revision"]).map { LocalChange.restore(id: current.id, revision: $0) }
                case .purge:
                    change = .purge(id: current.id)
                }
                await afterWrite(vid, answer, change, sent: sent)
                return
            } catch let e as ApiError where VaultManifest.retry(e) || (sent != nil && e.status == 409 && e.hasCode("revision_conflict")) {
                sends += 1
                guard sends < VaultManifest.attempts else { throw UserError(ManifestText.busy) }
                try await syncLocked()
                v = try requireVault()
                // Gone, or already where it should be: done.
                guard let fresh = v.get(entry.id), fresh.vaultId == entry.vaultId else { return }
                switch kind {
                case .trash: if fresh.deletedAt != nil { return }
                case .restore: if fresh.deletedAt == nil { return }
                case .purge: break
                }
                current = fresh
            }
        }
    }

    // MARK: Vault manifests

    /// The rows of `ids` in vault `vid` as the copy holds them (what its manifest was checked with).
    private func copyRows(_ ids: [String], in vid: String) -> [SyncItem] {
        guard let c = copy, c.account == activeId else { return [] }
        let wanted = Set(ids)
        return c.snapshot.items.filter { $0.vaultId == vid && wanted.contains($0.id) }
    }

    /// The vault has a manifest in the copy shown now.
    private func hasManifest(_ vid: String) -> Bool {
        guard let c = copy, c.account == activeId else { return false }
        return (c.snapshot.vaults.first { $0.id == vid }?.manifestVersion ?? 0) > 0
    }

    /// The manifest a write into vault `vid` carries: the vault's next one, without the rows
    /// `removed` (as the copy holds them before the write) and with `added` (as they are after
    /// it). nil: the vault has no manifest and the write goes as before. Throws "This vault can't
    /// be changed until its warning is resolved." while the vault's items don't match its
    /// manifest: nothing is sent.
    func nextManifest(_ vid: String, removed: [SyncItem], added: [SyncItem]) async throws -> ManifestEntry? {
        guard let c = copy, c.account == activeId, let row = c.snapshot.vaults.first(where: { $0.id == vid }) else { return nil }
        let status = vault?.vaults.first { $0.id == vid }?.manifest ?? .none
        if status.unresolved { throw UserError(ManifestText.held) }
        // Not checked against the server's answer (the sync a write waits for didn't settle it).
        if status.pending { throw UserError(ManifestText.unchecked) }
        let seq = row.manifestVersion
        guard seq > 0 else { return nil }
        guard status == .ok, let sealed = row.manifest, let prev = row.manifestPrev, let key = vaultKeys[vid],
              VaultManifest.complete(removed), VaultManifest.complete(added) else {
            throw UserError(ManifestText.held)
        }
        let epoch = UInt64(max(0, row.keyEpoch ?? 0))
        let removedJson = VaultManifest.rowsJson(removed), addedJson = VaultManifest.rowsJson(added)
        do {
            // The core names the row's manifest as the one this replaces (`prev`) and returns the
            // new one's link, which is remembered once the server stored it.
            let next = try await core {
                try key.manifestNext(vaultId: vid, keyEpoch: epoch, manifestSeq: UInt64(seq), prev: prev, sealed: sealed,
                                     removedJson: removedJson, addedJson: addedJson)
            }
            return ManifestEntry(vaultId: vid, next)
        } catch {
            throw UserError(ManifestText.held)
        }
    }

    /// After a sync with the server (the app only, never an AutoFill extension or a background
    /// refresh): start the first manifest of the vaults that may get one, and delete the trashed
    /// items the server's retention has run out for in vaults with a manifest (the server no
    /// longer deletes there by itself). One attempt each; every failure is left to the next sync.
    ///
    /// Old trash is bounded by what this device saw (`VaultManifest.dueTrash`): the server's
    /// clock, retention and `deleted_at`s aren't covered by the manifest, so an item goes only
    /// after this device itself saw it in the trash for the retention period, with the two
    /// clocks within a day of each other. One request per vault and vault number, of at most
    /// 250 items (fewer when the server's limit is lower); the rest waits for the next sync.
    private func maintainManifests(_ id: String, _ session: Session) async {
        guard isApp, !preferCache, !maintaining, sessions[id] === session, activeId == id, let v = vault, !v.offline,
              let first = copyOf(id) else { return }
        let features = store.get().file.accounts[id]?.features ?? []
        guard features.contains(vaultManifestFeature) else { return }
        maintaining = true
        defer { maintaining = false }
        // Nothing is started or deleted while this device's memory can't be read.
        guard let remembered = known.flatMap({ $0.account == id ? $0.memory.manifests : nil }) ?? store.readManifestMemory(id) else { return }
        let trashSeen = store.readTrashSeen(id)
        let rolledBack = v.rollback?.items ?? []
        var snapshot = first
        var wrote: [String: ManifestMark] = [:]
        var gone = Set<String>()
        var resync = false
        for info in v.vaults where info.role != .read {
            guard sessions[id] === session, activeId == id else { return }
            guard let i = snapshot.vaults.firstIndex(where: { $0.id == info.id }), let key = vaultKeys[info.id] else { continue }
            let row = snapshot.vaults[i]
            let rows = snapshot.items.filter { $0.vaultId == info.id }
            let epoch = UInt64(max(0, row.keyEpoch ?? 0))
            let vid = info.id
            if VaultManifest.mayStart(row, role: info.role, status: info.manifest, remembered: remembered[info.id], rows: rows, features: features,
                                      rolledBack: rows.contains { rolledBack.contains($0.id) },
                                      unopenable: v.unopenable.contains { $0.vaultId == vid }),
               let seq = row.seq {
                guard manifestTried["\(id)|\(info.id)|start"] != seq else { continue }
                manifestTried["\(id)|\(info.id)|start"] = seq
                // The vault's first manifest (it replaces none), from the complete, checked set of
                // this sync answer.
                let json = VaultManifest.rowsJson(rows)
                guard let w = try? await core({ try key.manifestStart(vaultId: vid, keyEpoch: epoch, version: 1, prev: nil, itemsJson: json) }),
                      let answer = try? await api.call(id, "/vaults/\(Self.pathPart(vid))/manifest", body: [
                          "base_seq": 0, "seq": 1, "prev": .string(w.prev), "sealed": .string(w.sealed), "vault_seq": .int(seq),
                      ], method: "PUT") else { continue }
                let (after, overflow) = seq.addingReportingOverflow(1)
                if !overflow, w.seq == 1, answer["manifest_link"]?.string == w.link, Self.number(answer["vault_seq"]) == after {
                    snapshot.vaults[i].manifest = w.sealed
                    snapshot.vaults[i].manifestSeq = 1
                    snapshot.vaults[i].manifestPrev = w.prev
                    snapshot.vaults[i].manifestOk = true
                    snapshot.vaults[i].seq = after
                    wrote[vid] = ManifestMark(version: 1, link: w.link)
                } else {
                    resync = true
                }
                continue
            }
            guard info.manifest == .ok, row.manifestVersion > 0, let trashSeen else { continue }
            let due = VaultManifest.dueTrash(rows, serverTime: first.serverTime, trashDays: first.trashDays, firstSeen: trashSeen, now: clock())
            guard !due.isEmpty, let known = row.seq, manifestTried["\(id)|\(info.id)|purge"] != known else { continue }
            manifestTried["\(id)|\(info.id)|purge"] = known
            let chunk = Array(due.prefix(await importLimit(id)))
            guard sessions[id] === session, activeId == id, let base = row.manifest, let prev = row.manifestPrev else { continue }
            let version = UInt64(row.manifestVersion)
            let removed = VaultManifest.rowsJson(chunk)
            guard let next = try? await core({
                try key.manifestNext(vaultId: vid, keyEpoch: epoch, manifestSeq: version, prev: prev, sealed: base, removedJson: removed, addedJson: "[]")
            }) else { continue }
            let sent = ManifestEntry(vaultId: vid, next)
            let items = chunk.map { r -> JSON in
                var o: [String: JSON] = ["id": .string(r.id)]
                if let revision = r.revision { o["revision"] = .int(revision) }
                return .object(o)
            }
            guard let answer = try? await api.call(id, "/vaults/\(Self.pathPart(vid))/trash/purge", body: [
                "items": .array(items), "manifests": [sent.json],
            ]) else { continue }
            let (after, overflow) = known.addingReportingOverflow(1)
            guard !overflow, answer["manifest_link"]?.string == sent.link, Self.number(answer["vault_seq"]) == after else {
                resync = true
                continue
            }
            let deleted = Set(chunk.map(\.id))
            snapshot.items.removeAll { $0.vaultId == vid && deleted.contains($0.id) }
            snapshot.vaults[i].manifest = sent.sealed
            snapshot.vaults[i].manifestSeq = Int64(clamping: sent.seq)
            snapshot.vaults[i].manifestPrev = sent.prev
            snapshot.vaults[i].seq = after
            wrote[vid] = sent.mark
            gone.formUnion(deleted)
        }
        guard sessions[id] === session, activeId == id, copyOf(id) == first else { return }
        if resync {
            try? await syncLocked()
        } else if !wrote.isEmpty {
            do {
                try await showLocal(id, session, snapshot, wrote: wrote, gone: gone)
            } catch {
                try? await syncLocked()
            }
        }
    }

    /// The most items one purge request takes (`/api/config` `limits.max_import_items`; 250, the
    /// web vault's batch size, when the server doesn't say).
    private func importLimit(_ id: String) async -> Int {
        let n = await fetchConfig(id)?.limits?["max_import_items"]?.number ?? 0
        return n > 0 ? Int(clamping: min(n, Int64(VaultManifest.purgeChunk))) : VaultManifest.purgeChunk
    }

    /// "Use the server's copy" (after the user confirmed), for vault `vaultId`. Everything is
    /// fetched again first and checked as always; a vault that matches after all needs nothing.
    /// Then one of two things, decided by the core's check of the served manifest against the
    /// served items with nothing remembered (`VaultManifest.accept`):
    ///
    /// - It matches (or the server shows no manifest): a **local accept**. This device's memory
    ///   for the vault is replaced by that manifest (or forgotten), also when it remembered a
    ///   higher version. Nothing is sent. Every member may do this, readers too, in the app and
    ///   in the macOS AutoFill extension (which has its own memory).
    /// - It doesn't: only a member who can edit, in the app, can help, by writing a new
    ///   **baseline**: a manifest over exactly the rows served (a newer row this device kept
    ///   counts with the hash of what the server sent), one version above the served one and
    ///   naming it, whatever this device remembers. The memory is then replaced by it. Another
    ///   write in between (`manifest_conflict`) starts over, three times at most; a server that
    ///   limits baselines (429) leaves the warning and its usual "try again later" message.
    ///
    /// A vault whose only problem is an item that can't be opened isn't changed by either
    /// (`deleteUnopenable` is its way out), and stays warned afterwards while such an item is left.
    public func useServerCopy(_ vaultId: String) async throws {
        try await lock.run {
            let id = activeId
            guard let session = sessions[id], vault != nil else { throw UserError("Your vault is locked.") }
            for _ in 0..<VaultManifest.attempts {
                let memory = readMemory(id)
                let full = try await fetchSnapshot(id, full: true)
                guard sessions[id] === session, activeId == id else { return }
                let checked: Checked?
                do {
                    checked = try await evaluate(id, session, full, source: .server, memory: memory, finalIncomplete: true)
                } catch let e as ManifestLogUnavailable {
                    throw e.error
                }
                guard let checked else { return }
                try await commit(id, session, checked, offline: false, store: .synced)
                guard sessions[id] === session, activeId == id, let info = vault?.vaults.first(where: { $0.id == vaultId }) else {
                    throw UserError("Vault not found.")
                }
                // The fresh answer matches its manifest after all: nothing to accept.
                if !info.manifest.unresolved {
                    if info.manifest.pending { throw UserError(ManifestText.unchecked) }
                    return
                }
                if info.unopenable { throw UserError(info.role == .read ? ManifestText.unopenableReader : ManifestText.unopenable) }
                guard let c = copyOf(id), let row = c.vaults.first(where: { $0.id == vaultId }), let key = vaultKeys[vaultId] else {
                    throw UserError("Vault not found.")
                }
                let rows = c.items.filter { $0.vaultId == vaultId }
                let accepted = try await core { VaultManifest.accept(row, key: key, rows: rows) }
                guard sessions[id] === session, activeId == id, copyOf(id) == c else { return }
                if accepted.status == .ok || accepted.status == .none {
                    // Local accept: only this device's memory changes (never one that can't be read).
                    guard store.replaceManifestMark(id, vault: vaultId, with: accepted.mark) != nil else { throw UserError(ManifestText.unchecked) }
                    try await reshow(id, session, c)
                    return
                }
                if info.role == .read { throw UserError(ManifestText.reader) }
                // Nothing is written over the server's copy from an AutoFill extension.
                guard isApp else { throw UserError(ManifestText.reviewElsewhere) }
                guard VaultManifest.complete(rows), let known = row.seq, let seq = VaultManifest.baselineSeq(row: row.manifestVersion) else {
                    throw DeltaSync.unreadable
                }
                // It replaces whatever manifest the server shows now, by that manifest's link (it
                // needn't open or match: that is what is being accepted); none: a first manifest.
                let replaced = VaultManifest.link(of: row)
                if row.manifestVersion > 0 && replaced == nil { throw DeltaSync.unreadable }
                let epoch = UInt64(max(0, row.keyEpoch ?? 0))
                let json = VaultManifest.rowsJson(rows)
                let w: ManifestWrite
                do {
                    w = try await core { try key.manifestStart(vaultId: vaultId, keyEpoch: epoch, version: seq, prev: replaced, itemsJson: json) }
                } catch {
                    throw DeltaSync.unreadable
                }
                let answer: JSON
                do {
                    answer = try await api.call(id, "/vaults/\(Self.pathPart(vaultId))/manifest", body: [
                        "base_seq": .int(row.manifestVersion), "seq": .int(Int64(clamping: w.seq)), "prev": .string(w.prev), "sealed": .string(w.sealed),
                        "vault_seq": .int(known),
                    ], method: "PUT")
                } catch let e as ApiError where e.code == "manifest_conflict" {
                    continue
                } catch let e as ApiError where e.code == "manifest_not_ready" {
                    throw UserError(ManifestText.notReady)
                } catch let e as ApiError where e.isRateLimited {
                    // The warning stays; nothing is tried again by itself.
                    throw UserError(tooManyAttemptsMessage(e) ?? "Too many attempts. Try again later.")
                }
                guard sessions[id] === session, activeId == id else { return }
                // Stored as the vault's manifest (by its link): the memory is replaced by it, also
                // when this device remembered a higher version, and the copy takes it.
                var next = c
                let (after, overflow) = known.addingReportingOverflow(1)
                if !overflow, answer["manifest_link"]?.string == w.link, Self.number(answer["vault_seq"]) == after,
                   let i = next.vaults.firstIndex(where: { $0.id == vaultId }),
                   store.replaceManifestMark(id, vault: vaultId, with: ManifestMark(version: w.seq, link: w.link)) != nil {
                    next.vaults[i].manifest = w.sealed
                    next.vaults[i].manifestSeq = Int64(clamping: w.seq)
                    next.vaults[i].manifestPrev = w.prev
                    next.vaults[i].seq = after
                    do {
                        try await reshow(id, session, next)
                        return
                    } catch {}
                }
                await syncAfterWrite()
                return
            }
            throw UserError(ManifestText.busy)
        }
    }

    /// After an acceptance: the copy checked again with the memory as it is stored now, shown
    /// and stored. Nothing is fetched (the copy is the answer just checked, with at most this
    /// device's own baseline on the vault row).
    private func reshow(_ id: String, _ session: Session, _ snapshot: SyncSnapshot) async throws {
        let memory = readMemory(id)
        guard let checked = try await evaluate(id, session, snapshot, source: .server, memory: memory, finalIncomplete: true, ownCopy: true) else { return }
        try await commit(id, session, checked, offline: false, store: .localChange)
    }

    /// "Delete for good" on an item that can't be opened (after the user confirmed): the row is
    /// removed for everyone. Nothing of it has to be opened: in a vault with a manifest the
    /// request carries the vault's next manifest without the row as it was synced, like any
    /// delete. This is the one write a vault takes while it is warned, and only while such
    /// items are the one thing wrong with it (its manifest matches); a vault whose manifest is
    /// wrong too needs "Use the server's copy" first. A vault without a manifest takes the plain
    /// request. Live rows are deleted the same way as trashed ones. Another write in between is
    /// retried three times at most; an item that is gone or opens meanwhile is left alone.
    public func deleteUnopenable(_ item: UnopenableItem) async throws {
        try await lock.run {
            let id = activeId
            var sends = 0
            var synced = false
            while true {
                let v = try requireVault()
                guard let u = v.unopenable.first(where: { $0.id == item.id && $0.vaultId == item.vaultId }) else { return }
                guard let info = v.vaults.first(where: { $0.id == u.vaultId }) else { throw UserError("Vault not found.") }
                if info.role == .read { throw UserError("You can only view items in this vault.") }
                if info.manifest.pending {
                    // Not checked against the server's answer yet: once.
                    guard !synced else { throw UserError(ManifestText.unchecked) }
                    synced = true
                    try await syncLocked()
                    continue
                }
                guard let c = copyOf(id), let row = c.vaults.first(where: { $0.id == u.vaultId }),
                      let stored = c.items.first(where: { $0.id == u.id && $0.vaultId == u.vaultId }) else { return }
                let vid = u.vaultId
                var sent: ManifestEntry?
                if row.manifestVersion > 0 {
                    guard info.manifest == .ok || (info.manifest == .mismatch && info.unopenable), let sealed = row.manifest, let prev = row.manifestPrev,
                          let key = vaultKeys[vid], VaultManifest.complete([stored]) else { throw UserError(ManifestText.held) }
                    let epoch = UInt64(max(0, row.keyEpoch ?? 0))
                    let version = UInt64(row.manifestVersion)
                    let removed = VaultManifest.rowsJson([stored])
                    do {
                        let next = try await core {
                            try key.manifestNext(vaultId: vid, keyEpoch: epoch, manifestSeq: version, prev: prev, sealed: sealed, removedJson: removed, addedJson: "[]")
                        }
                        sent = ManifestEntry(vaultId: vid, next)
                    } catch {
                        throw UserError(ManifestText.held)
                    }
                } else if info.manifest.unresolved {
                    throw UserError(ManifestText.held)
                }
                var path = "/items/\(Self.pathPart(u.id))/permanent"
                if let sent { path += "?revision=\(stored.revision ?? 0)&" + sent.query }
                do {
                    let answer = try await api.call(id, path, method: "DELETE")
                    await afterWrite(vid, answer, .purge(id: u.id), sent: sent)
                    return
                } catch let e as ApiError where VaultManifest.retry(e) || (e.status == 409 && e.hasCode("revision_conflict")) {
                    sends += 1
                    guard sends < VaultManifest.attempts else { throw UserError(ManifestText.busy) }
                    try await syncLocked()
                } catch let e as ApiError where e.status == 404 {
                    // Deleted on another device meanwhile.
                    await syncAfterWrite()
                    return
                }
            }
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
            } catch let e as ApiError where (e.status == 409 && e.hasCode("revision_conflict")) || VaultManifest.retry(e) {
                // An item of the vault was saved after the sync the replacement was built from
                // (or, with a manifest, anything in the vault changed): nothing was changed.
                // Sync and build it again from the newer items.
                guard attempt < Self.rotationAttempts else { throw VaultManifest.retry(e) ? UserError(ManifestText.busy) : e }
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
        // Vault manifests: a key is only replaced in a vault whose items match its manifest.
        if info.manifest.unresolved { throw UserError(ManifestText.held) }
        // …and that was checked against the server's answer (the sync before this settles it).
        if info.manifest.pending { throw UserError(ManifestText.unchecked) }
        let rows = c.snapshot.items.filter { $0.vaultId == vid }
        // One members answer decides everything below (personal or not, who gets the key).
        let answer = try await api.call(id, "/vaults/\(Self.pathPart(vid))/members")
        guard let members = Self.memberRows(answer), EmergencyClient.readMembers(answer) != nil else {
            throw UserError("The server sent an unexpected response. Try again.")
        }
        // Locked or switched meanwhile: nothing is sent for another session.
        guard activeId == id, sessions[id] === session else { return .skipped }
        let row = c.snapshot.vaults.first { $0.id == vid }
        if signedSharingOn(id, c.snapshot) {
            return try await rotateSigned(id, session, info, row: row, oldKey: oldKey, rows: rows,
                                          answer: answer, members: members, confirmed: confirmed, reviewed: reviewed, personalOnly: personalOnly)
        }
        if members.map(\.userId) != [me] { return .shared(info.name) }
        if personalOnly && (info.keyKind != VaultInfo.accountKeyKind || info.role != .owner) { return .shared(info.name) }
        return try await rotatePlain(id, session, info, oldKey: oldKey, rows: rows, row: row)
    }

    /// A vault whose members are this account alone: a new key wrapped for it only (no roster,
    /// sealed to nobody).
    ///
    /// `row`: the vault's row in the copy the rows are from. With a manifest, the request carries
    /// the vault's next one, made new with the new key for the next epoch over the re-encrypted
    /// items (the key that seals and sums it changes with the vault key), naming the row's
    /// manifest as the one it replaces (`VaultManifest.rotation`).
    func rotatePlain(_ id: String, _ session: Session, _ info: VaultInfo, oldKey: VaultKey, rows: [SyncItem], row: SyncVault?) async throws -> RotationOutcome {
        let vid = info.id
        let me = session.meId
        let account = session.account
        let name = info.name
        let next = info.keyEpoch.map { UInt64(max(0, $0)) + 1 }
        // Epoch-bound (v2) when every app of the account reads it and the row has an epoch.
        let bound = session.accountWrapsV2 ? next : nil
        let made: (wrapped: String, items: [JSON], meta: String, epochPin: String?, manifest: ManifestEntry?) = try await core {
            let nv = try bound.map { try account.newVaultKeyBound(vaultId: vid, keyEpoch: $0) } ?? account.newVaultKey(vaultId: vid)
            let (items, meta) = try Self.reencrypt(rows, vid: vid, name: name, oldKey: oldKey, newKey: nv.key)
            // A vault with a manifest always has a key epoch (the manifest is sealed for it).
            let manifest = try row.flatMap { try VaultManifest.rotation($0, newKey: nv.key, nextEpoch: next, rows: rows, items: items) }
            return (nv.wrapped, items, meta, try next.map { try nv.key.epochPinJson(vaultId: vid, keyEpoch: $0) }, manifest)
        }
        var body: [String: JSON] = [
            "keys": [["user_id": .string(me), "wrapped_key": .string(made.wrapped), "key_kind": .string(VaultInfo.accountKeyKind)]],
            "items": .array(made.items),
            "meta": .string(made.meta),
        ]
        if let e = info.keyEpoch { body["key_epoch"] = .int(e) }
        if let m = made.manifest { body["manifests"] = [m.json] }
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
                    // And what its `/api/config` said (Part S: a record without it would let a
                    // server that stops answering there be signed in to unchecked).
                    var kept = AccountData(server: a.server)
                    kept.features = a.features
                    kept.featuresAt = a.featuresAt
                    kept.api = a.api
                    st.file.accounts[id] = kept
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
    /// `manifests`: the next manifest of every vault the write changes that has one (never in a
    /// header); left out when there is none.
    nonisolated static func body(_ e: EncryptedItem, keyEpoch: Int64?, revision: Int64? = nil, manifests: [ManifestEntry?] = []) -> JSON {
        var o: [String: JSON] = ["id": .string(e.id), "vault_id": .string(e.vaultId), "key": .string(e.key), "data": .string(e.data)]
        if let keyEpoch { o["key_epoch"] = .int(keyEpoch) }
        if let revision { o["revision"] = .int(revision) }
        let sent = manifests.compactMap { $0?.json }
        if !sent.isEmpty { o["manifests"] = .array(sent) }
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
