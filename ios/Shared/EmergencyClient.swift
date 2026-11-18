import Foundation
import PassAuthCore

/// Emergency access requests and keys: the web vault's `emergency-client.ts`, with the same steps
/// and the same refusals (`Emergency` has the rules). Confirming a contact makes an emergency key
/// for the access, after the user compared the contact's fingerprint with them: sealed to the
/// contact, wrapped by this account's key, and wrapping the key of each personal vault. Only vaults
/// this app's own data says are personal are ever wrapped, whatever the server lists.
///
/// The roster (sealed with the account key) lists the accesses this account's apps may add wraps
/// for: confirming adds the access first, removing takes it out first, and every write (and every
/// fill) drops accesses the server no longer lists. The fill never acts on a roster older than the
/// newest this device opened, nor on one that doesn't open. Each device keeps its last trusted
/// roster (sealed, in the Keychain) to compare with.
///
/// Written against small interfaces (`EmergencyEnvironment`) so its flows run in unit tests against
/// a fake server and a fake account (`EmergencyClientTests`, the web's `emergency-client.test.ts`).

/// An emergency key handle (the core's `EmergencyKey`; a fake in tests).
public protocol EmergencyKeyHandle: AnyObject {
    func sealFor(contactPublicKey: String, grantorId: String, grantId: String) throws -> String
    /// The current key of vault `vaultId`, wrapped with this key.
    func wrapVault(_ vaultId: String) throws -> String
}

/// The account's keys as emergency access uses them (the core's `Account`; a fake in tests).
public protocol EmergencyAccountKeys: AnyObject {
    func newEmergencyKey(grantId: String) throws -> (key: EmergencyKeyHandle, wrapped: String)
    func openEmergencyKey(grantId: String, wrapped: String) throws -> EmergencyKeyHandle
    func sealRoster(_ json: String) throws -> String
    func openRoster(_ sealed: String) throws -> String
}

/// The highest roster version this device opened and the last trusted (sealed) roster, per user.
public protocol RosterMemory: AnyObject {
    func load(_ userId: String) -> (version: Int64, sealed: String?)
    func save(_ userId: String, version: Int64, sealed: String?)
}

/// What the client needs of the app.
public struct EmergencyEnvironment {
    /// A signed-in API call (`path` below `/api`).
    public var api: (_ path: String, _ body: JSON?, _ method: String?, _ headers: [String: String]) async throws -> JSON
    /// The unlocked account's keys; nil while locked.
    public var keys: () -> EmergencyAccountKeys?
    /// This account's user id on the server.
    public var me: () -> String
    /// The vaults as the app's latest sync shows them, with the epoch of the key it holds.
    public var vaults: () -> [(vault: Emergency.OwnVault, epoch: Int64?)]
    /// The server's `/api/config` `features` (nil: couldn't be read).
    public var features: () async -> [String]?
    /// A reauth token for the master password and, when this device doesn't keep it, the typed
    /// Secret Key (throws for a wrong one).
    public var reauth: (_ password: String, _ secretKey: String?) async throws -> String
    /// Replace the keys of these vaults (after a contact who held keys was removed): only those
    /// the replacement's own members answer shows as personal (the set that decides is the set
    /// the replacement uses).
    public var rotate: (_ vaultIds: [String]) async throws -> KeyReplacement
    /// Signed sharing: whether a vault has signed history (then it isn't personal).
    public var signedHistory: (String) -> Bool
    public var sync: () async throws -> Void
    public var memory: RosterMemory
    /// The vault notice about the roster (nil hides it).
    public var notice: (String?) -> Void
    /// The active account's id: an operation pins it when it starts, and its later steps are
    /// refused once another account is active (`EmergencyPin`).
    public var account: () -> String

    public init(api: @escaping (String, JSON?, String?, [String: String]) async throws -> JSON, keys: @escaping () -> EmergencyAccountKeys?,
                me: @escaping () -> String, vaults: @escaping () -> [(vault: Emergency.OwnVault, epoch: Int64?)],
                features: @escaping () async -> [String]?, reauth: @escaping (String, String?) async throws -> String,
                rotate: @escaping ([String]) async throws -> KeyReplacement, sync: @escaping () async throws -> Void,
                memory: RosterMemory, notice: @escaping (String?) -> Void, account: @escaping () -> String = { "" },
                signedHistory: @escaping (String) -> Bool = { _ in false }) {
        self.signedHistory = signedHistory
        self.api = api
        self.keys = keys
        self.me = me
        self.vaults = vaults
        self.features = features
        self.reauth = reauth
        self.rotate = rotate
        self.sync = sync
        self.memory = memory
        self.notice = notice
        self.account = account
    }
}

/// The account an emergency operation started on (a task-local value, so operations running at
/// the same time each keep their own).
enum EmergencyPin {
    @TaskLocal static var account: String?
}

/// The roster as the Emergency access page needs it.
public struct RosterState: Equatable, Sendable {
    public enum Problem: Sendable { case older, unreadable }
    public var problem: Problem?
    /// The trusted roster; nil while there is a problem.
    public var roster: Roster?
    /// Accesses holding keys that the roster doesn't list (and didn't remove): "Confirm again".
    public var confirmAgain: Set<String> = []
    /// Accesses the roster removed: never confirmed again, only added as new contacts.
    public var removed: Set<String> = []
}

/// The server's roster for review before "Use the server's list".
public struct ServerRoster: Equatable, Sendable {
    /// The roster as it opened under the account's key; nil when the server has none.
    public var roster: Roster?
    public var entries: [ReviewedEntry]
}

/// What removing a contact did about vault keys.
public struct Removal: Equatable, Sendable {
    /// Vaults given a new key.
    public var rotated: Int
    public var failed: String?
    /// Shared vaults left for the web vault or the desktop app (`KeyReplacement.sharedText`).
    public var shared: String?

    public init(rotated: Int, failed: String?, shared: String? = nil) {
        self.rotated = rotated
        self.failed = failed
        self.shared = shared
    }
}

/// A grantor's vaults, decrypted for viewing: memory only.
public struct GrantorVault: Sendable {
    public struct Entry: Identifiable, Sendable {
        public let id: String
        public let vaultId: String
        public let item: Item
        public let deletedAt: Int64?
    }

    public let grant: Grant
    public let vaults: [(id: String, name: String)]
    public let items: [Entry]
    /// Items (and vaults' items) that couldn't be decrypted.
    public let failed: Int
    /// Vault manifests: the vaults whose items aren't the ones their manifest records (the vault
    /// warning is shown; the view is read-only either way).
    public var unverified: Set<String> = []
}

public enum EmergencyText {
    public static let locked = "The vault is locked. Unlock it and try again."
    public static let unexpected = "The server sent an unexpected response. Try again."
    public static let serverTooOld = "Your PassAuth server needs an update before emergency contacts can be confirmed or their vaults viewed. Ask the server's admin."
    public static let appTooOld = "This emergency access uses keys this version of PassAuth can't open. Update PassAuth, then try again."
    public static let vaultsChanged = "Your vaults changed while this was being saved. Try again."
    public static let notOurs = "This access's key wasn't made by your account. Remove the contact, then name them again."
    public static let rolledBack = "Your server sent an older list of emergency contacts, so PassAuth didn't change their access. Ask your server's admin."
    /// A shared vault's key waits for the user to confirm that people its signed member list
    /// names are gone (`KeyReplacement.confirm`).
    public static let confirmMembers = "Some members of a shared vault left since its member list was signed. Replace its key from Emergency access to confirm."
    public static let unreadable = "Your server sent a list of emergency contacts that PassAuth can't open, so PassAuth didn't change their access. Ask your server's admin."
    public static let notListed = "This emergency contact is no longer on your server's list. Pull to refresh."
    public static let rosterChanged = "Your server's list of emergency contacts changed meanwhile. Check it again before you continue."
    public static let accountChanged = "Another account became active meanwhile, so this was stopped. Switch back and try again."
    public static let notShared = "PassAuth couldn't check that every vault your server lists as personal is yours alone (one may be shared, or couldn't be opened here), so nothing was confirmed. Pull to refresh and try again."

    static func keyChanged(_ who: String) -> String { "\(who)'s key changed. Check their fingerprint again before you confirm them." }
}

@MainActor
public final class EmergencyClient {
    let env: EmergencyEnvironment
    private var filling: Task<Void, Error>?
    private var fillAgain = false

    public init(_ env: EmergencyEnvironment) {
        self.env = env
    }

    private static func path(_ id: String, _ rest: String = "") -> String { "/emergency-access/\(VaultRepository.pathPart(id))\(rest)" }

    private func call(_ path: String, body: JSON? = nil, method: String? = nil, headers: [String: String] = [:]) async throws -> JSON {
        try checkPin()
        return try await env.api(path, body, method, headers)
    }

    private func reauth(_ password: String, _ secretKey: String?) async throws -> String {
        try checkPin()
        return try await env.reauth(password, secretKey)
    }

    private func sync() async throws {
        try checkPin()
        try await env.sync()
    }

    /// Throws when the operation running started on another account than the active one.
    private func checkPin() throws {
        if let pinned = EmergencyPin.account, pinned != env.account() { throw UserError(EmergencyText.accountChanged) }
    }

    /// Run `body` with the active account pinned (kept when an outer operation pinned one).
    private func pinned<T>(_ body: () async throws -> T) async throws -> T {
        if EmergencyPin.account != nil { return try await body() }
        return try await EmergencyPin.$account.withValue(env.account()) { try await body() }
    }

    private func grantOf(_ j: JSON) throws -> Grant {
        guard let g = Emergency.readGrant(j) else { throw UserError(EmergencyText.unexpected) }
        return g
    }

    private func keys() throws -> EmergencyAccountKeys {
        try checkPin()
        guard let k = env.keys() else { throw UserError(EmergencyText.locked) }
        return k
    }

    public func listGrants() async throws -> GrantLists {
        Emergency.readGrants(try await call("/emergency-access"))
    }

    /// Throws unless the server gives contacts emergency keys (v2).
    private func requireEmergencyKeys() async throws {
        guard let f = await env.features() else { throw UserError("Can't reach your PassAuth server. Check the server address and your connection.") }
        if !f.contains(emergencyVaultKeysFeature) { throw UserError(EmergencyText.serverTooOld) }
    }

    /// Name a trusted contact (an account on this server with a verified email address).
    public func inviteContact(email: String, waitDays: Int) async throws -> Grant {
        do {
            return try grantOf(try await call("/emergency-access", body: ["grantee_email": .string(email.trimmingCharacters(in: .whitespacesAndNewlines)), "wait_days": .int(Int64(waitDays))]))
        } catch let e as ApiError where e.status == 404 {
            throw UserError("There's no account with that email address on this server, or it isn't verified yet. Your contact needs an account here first.")
        } catch let e as ApiError where e.status == 409 {
            throw UserError("This person is your emergency contact already.")
        }
    }

    // MARK: The roster

    private func seenVersion() -> Int64 { max(0, env.memory.load(env.me()).version) }

    /// Remember a roster this device trusts (the remembered version never goes down).
    private func rememberRoster(_ version: Int64, _ sealed: String?) {
        if version < seenVersion() { return }
        env.memory.save(env.me(), version: version, sealed: sealed)
    }

    /// This device's last trusted roster, opened with the account's key; nil when none.
    private func trustedRoster() -> Roster? {
        guard let k = env.keys(), let sealed = env.memory.load(env.me()).sealed, let json = try? k.openRoster(sealed) else { return nil }
        return Emergency.readRoster(json)
    }

    private struct Opened {
        var roster: Roster
        var seq: Int64
        var problem: RosterState.Problem?
    }

    /// The account's roster from a listing, opened with its key: empty before any is stored. A
    /// device that remembers nothing trusts the first roster it opens; a trusted one is remembered.
    private func openRoster(_ lists: GrantLists) throws -> Opened {
        let k = try keys()
        let seq = lists.rosterSeq ?? 0
        var roster: Roster? = Emergency.emptyRoster
        if let sealed = lists.roster {
            roster = (try? k.openRoster(sealed)).flatMap(Emergency.readRoster)
        }
        guard let roster else { return Opened(roster: Emergency.emptyRoster, seq: seq, problem: .unreadable) }
        if Emergency.rosterIsOlder(roster, seen: seenVersion()) { return Opened(roster: roster, seq: seq, problem: .older) }
        rememberRoster(roster.version, lists.roster)
        return Opened(roster: roster, seq: seq, problem: nil)
    }

    /// Seal `next` and store it with the compare-and-swap number `seq`, then remember it.
    private func writeRoster(_ next: Roster, seq: Int64) async throws {
        let sealed = try keys().sealRoster(Emergency.rosterJson(next))
        _ = try await call("/emergency-access/roster", body: ["roster": .string(sealed), "seq": .int(seq)], method: "PUT")
        rememberRoster(next.version, sealed)
    }

    private static func listedIds(_ lists: GrantLists) -> Set<String> { Set(lists.asGrantor.map(\.id)) }

    private static func problemText(_ p: RosterState.Problem) -> String { p == .older ? EmergencyText.rolledBack : EmergencyText.unreadable }

    /// Store the roster with one access added or taken out (nil: only the cleanup), and without the
    /// accesses the server no longer lists; once more on 409 `roster_changed`.
    private func changeRoster(_ change: Emergency.RosterChange?) async throws {
        var attempt = 0
        while true {
            let lists = try await listGrants()
            let opened = try openRoster(lists)
            if let p = opened.problem {
                env.notice(Self.problemText(p))
                if case .add? = change { throw UserError(Self.problemText(p)) }
                return
            }
            if case .add(let e)? = change, Emergency.isRemoved(opened.roster, e.id, grantorKeyHash: e.grantorKeyHash) {
                throw UserError(Emergency.removedText("This contact"))
            }
            guard let next = try Emergency.nextRoster(opened.roster, seen: seenVersion(), change, listed: Self.listedIds(lists)) else { return }
            do {
                try await writeRoster(next, seq: opened.seq + 1)
                return
            } catch let e as ApiError where attempt == 0 && e.hasCode("roster_changed") {
                attempt += 1
            }
        }
    }

    public func rosterState() async throws -> RosterState {
        guard env.keys() != nil else { return RosterState() }
        let lists = try await listGrants()
        let opened = try openRoster(lists)
        if let p = opened.problem { return RosterState(problem: p) }
        var state = RosterState(problem: nil, roster: opened.roster)
        for g in lists.asGrantor {
            let hash = g.grantorKey.map(Emergency.sha256b64)
            if Emergency.isRemoved(opened.roster, g.id, grantorKeyHash: hash) { state.removed.insert(g.id) }
            else if Emergency.needsConfirmAgain(g, opened.roster, grantorKeyHash: hash) { state.confirmAgain.insert(g.id) }
        }
        return state
    }

    /// The server's roster, opened with the account's key, for the user to review. Throws when it
    /// doesn't open: such a roster is never taken.
    public func loadServerRoster() async throws -> ServerRoster {
        let lists = try await listGrants()
        let k = try keys()
        guard let sealed = lists.roster else { return ServerRoster(roster: nil, entries: []) }
        guard let roster = (try? k.openRoster(sealed)).flatMap(Emergency.readRoster) else { throw UserError(EmergencyText.unreadable) }
        return ServerRoster(roster: roster, entries: Emergency.reviewRoster(roster, trusted: trustedRoster(), listed: Self.listedIds(lists)))
    }

    /// "Use the server's list", with the master password: exactly what was reviewed, written forward.
    public func useServerRoster(_ reviewed: ServerRoster, password: String, secretKey: String? = nil) async throws {
        try await pinned { try await useServerRosterPinned(reviewed, password: password, secretKey: secretKey) }
    }

    private func useServerRosterPinned(_ reviewed: ServerRoster, password: String, secretKey: String?) async throws {
        _ = try await reauth(password, secretKey)
        let lists = try await listGrants()
        let k = try keys()
        var current: Roster = Emergency.emptyRoster
        if let sealed = lists.roster {
            guard let r = (try? k.openRoster(sealed)).flatMap(Emergency.readRoster) else { throw UserError(EmergencyText.unreadable) }
            current = r
        }
        let same = reviewed.roster.map { lists.roster != nil && Emergency.rosterJson($0) == Emergency.rosterJson(current) } ?? (lists.roster == nil)
        if !same { throw UserError(EmergencyText.rosterChanged) }
        let next = try Emergency.restoredRosterForward(reviewed.entries, server: current, trusted: trustedRoster(), seen: seenVersion(), listedNow: Self.listedIds(lists))
        do {
            try await writeRoster(next, seq: (lists.rosterSeq ?? 0) + 1)
        } catch let e as ApiError where e.hasCode("roster_changed") {
            throw UserError(EmergencyText.rosterChanged)
        }
        env.notice(nil)
        try? await fill()
    }

    /// "Start a new list", with the master password, when the server's roster doesn't open.
    public func startNewRoster(password: String, secretKey: String? = nil) async throws {
        try await pinned { try await startNewRosterPinned(password: password, secretKey: secretKey) }
    }

    private func startNewRosterPinned(password: String, secretKey: String?) async throws {
        _ = try await reauth(password, secretKey)
        let lists = try await listGrants()
        if try openRoster(lists).problem != .unreadable { throw UserError("Your server's list of emergency contacts opens again. Pull to refresh.") }
        do {
            try await writeRoster(try Emergency.freshRoster(seen: seenVersion(), trusted: trustedRoster()), seq: (lists.rosterSeq ?? 0) + 1)
        } catch let e as ApiError where e.hasCode("roster_changed") {
            throw UserError("Your list of emergency contacts changed on another device just now. Try again.")
        }
        env.notice(nil)
    }

    // MARK: The keys

    /// Of the vaults the server names, the ones this app's own data says are personal.
    private func personalOf(_ wanted: [String]) async throws -> (wrap: [String], refused: [String]) {
        let me = env.me()
        let own = Dictionary(env.vaults().map { ($0.vault.id, $0.vault) }, uniquingKeysWith: { a, _ in a })
        var members: [String: [String]] = [:]
        for id in Set(wanted) {
            guard let v = own[id], v.role == .owner, v.keyKind == VaultInfo.accountKeyKind else { continue }
            do {
                if let list = Self.readMembers(try await call("/vaults/\(VaultRepository.pathPart(id))/members")) { members[id] = list }
            } catch let e as ApiError where e.status == 404 {}
        }
        return Emergency.vaultsToWrap(wanted) { Emergency.isPersonal(own[$0], members: members[$0], me: me, signedHistory: env.signedHistory($0)) }
    }

    /// The members' user ids of `GET /vaults/{id}/members`; nil when any row is malformed.
    nonisolated static func readMembers(_ j: JSON) -> [String]? {
        guard case .array(let list)? = j["members"] else { return nil }
        var out: [String] = []
        for m in list {
            guard case .object = m, let id = m["user_id"]?.string, !id.isEmpty, m["email"]?.string != nil, m["name"]?.string != nil,
                  let role = m["role"]?.string, !role.isEmpty, let pk = m["public_key"]?.string, !pk.isEmpty else { return nil }
            out.append(id)
        }
        return out
    }

    /// Each vault's key wrapped with `key`, with the epoch of the key wrapped.
    private func wrapVaults(_ key: EmergencyKeyHandle, _ ids: [String]) throws -> JSON {
        let vaults = env.vaults()
        return .array(try ids.map { id in
            guard let v = vaults.first(where: { $0.vault.id == id }), let epoch = v.epoch else { throw UserError(EmergencyText.vaultsChanged) }
            return ["vault_id": .string(id), "wrapped_key": .string(try key.wrapVault(id)), "key_epoch": .int(epoch)]
        })
    }

    private static func vaultsMoved(_ e: Error) -> Bool {
        guard let a = e as? ApiError else { return false }
        return a.hasCode("emergency_vaults_changed") || a.hasCode("vault_key_changed")
    }

    private func currentAccess(_ id: String) async throws -> Grant {
        guard let g = try await listGrants().asGrantor.first(where: { $0.id == id }) else { throw UserError(EmergencyText.notListed) }
        return g
    }

    /// The grantor's step after the contact accepted (`g` as the user checked it, fingerprint
    /// included); see the web vault's `confirmContact`.
    @discardableResult
    public func confirmContact(_ g: Grant) async throws -> Grant {
        try await pinned { try await confirmPinned(g) }
    }

    private func confirmPinned(_ g: Grant) async throws -> Grant {
        try await requireEmergencyKeys()
        let who = Emergency.personName(g.grantee)
        if g.grantee.publicKey.isEmpty { throw UserError("\(who)'s account has no key to confirm. Ask them to sign in once, then try again.") }
        let lists = try await listGrants()
        guard let fresh = lists.asGrantor.first(where: { $0.id == g.id }) else { throw UserError(EmergencyText.notListed) }
        if fresh.grantee.publicKey != g.grantee.publicKey { throw UserError(EmergencyText.keyChanged(who)) }
        let opened = try openRoster(lists)
        if opened.problem == nil, Emergency.isRemoved(opened.roster, g.id, grantorKeyHash: fresh.grantorKey.map(Emergency.sha256b64)) {
            throw UserError(Emergency.removedText(who))
        }
        if Emergency.hasKeys(fresh) {
            try await confirmAgain(g)
            return try await currentAccess(g.id)
        }
        if fresh.status != .accepted { throw UserError(EmergencyText.vaultsChanged) }
        let made = try keys().newEmergencyKey(grantId: g.id)
        let sealed = try made.key.sealFor(contactPublicKey: g.grantee.publicKey, grantorId: g.grantor.id, grantId: g.id)
        try await changeRoster(.add(Emergency.rosterEntry(g, checkedContactKey: g.grantee.publicKey, grantorKeyHash: Emergency.sha256b64(made.wrapped))))
        var current = fresh
        var attempt = 0
        while true {
            let (wrap, refused) = try await personalOf(current.missingVaults)
            if !refused.isEmpty { throw UserError(EmergencyText.notShared) }
            let body: JSON = ["sealed_key": .string(sealed), "grantor_key": .string(made.wrapped), "vault_keys": try wrapVaults(made.key, wrap)]
            do {
                return try grantOf(try await call(Self.path(g.id, "/confirm"), body: body))
            } catch {
                if attempt == 0 && Self.vaultsMoved(error) {
                    attempt += 1
                    try await sync()
                    let again = try await currentAccess(g.id)
                    if again.grantee.publicKey != g.grantee.publicKey { throw UserError(EmergencyText.keyChanged(who)) }
                    if again.status == .accepted {
                        current = again
                        continue
                    }
                }
                // The access holds a key now (this try's answer was lost, or another app confirmed first).
                if let now = try? await currentAccess(g.id), Emergency.hasKeys(now), now.grantee.publicKey == g.grantee.publicKey {
                    try await confirmAgain(g)
                    return now
                }
                throw error
            }
        }
    }

    /// "Confirm again": put an access that holds keys back into the roster, once the user checked
    /// the contact's fingerprint (`checked`). No new key is made.
    public func confirmAgain(_ checked: Grant) async throws {
        try await pinned { try await confirmAgainPinned(checked) }
    }

    private func confirmAgainPinned(_ checked: Grant) async throws {
        try await requireEmergencyKeys()
        let who = Emergency.personName(checked.grantee)
        let now = try await currentAccess(checked.id)
        if checked.grantee.publicKey.isEmpty || now.grantee.publicKey != checked.grantee.publicKey { throw UserError(EmergencyText.keyChanged(who)) }
        guard Emergency.hasKeys(now), let grantorKey = now.grantorKey else { throw UserError(EmergencyText.vaultsChanged) }
        let hash = Emergency.sha256b64(grantorKey)
        let opened = try openRoster(try await listGrants())
        if opened.problem == nil, Emergency.isRemoved(opened.roster, now.id, grantorKeyHash: hash) { throw UserError(Emergency.removedText(who)) }
        do {
            _ = try keys().openEmergencyKey(grantId: now.id, wrapped: grantorKey)
        } catch {
            throw UserError(EmergencyText.notOurs)
        }
        try await changeRoster(.add(Emergency.rosterEntry(checked, checkedContactKey: checked.grantee.publicKey, grantorKeyHash: hash)))
        try? await fill()
    }

    /// Add the wraps the server says are missing for the accesses the roster lists. One run at a
    /// time, and one more when asked again meanwhile.
    public func fill() async throws {
        if let running = filling {
            fillAgain = true
            return try await running.value
        }
        let task = Task { @MainActor in
            // The last look at `fillAgain` and clearing `filling` happen in one step: a call
            // arriving after it starts a run of its own instead of joining one that has ended.
            defer { filling = nil }
            while true {
                fillAgain = false
                // Each run on the account active when it starts.
                try await EmergencyPin.$account.withValue(env.account()) { try await fillOnce() }
                if !fillAgain { return }
            }
        }
        filling = task
        try await task.value
    }

    private func fillOnce() async throws {
        guard let f = await env.features(), f.contains(emergencyAccessFeature), f.contains(emergencyVaultKeysFeature) else { return }
        guard env.keys() != nil else { return }
        let lists = try await listGrants()
        let opened = try openRoster(lists)
        if let p = opened.problem {
            env.notice(Self.problemText(p))
            return
        }
        env.notice(nil)
        var roster = opened.roster
        let listed = Self.listedIds(lists)
        let pruned = Emergency.pruneRoster(roster, listed: listed)
        if pruned.count < roster.accesses.count {
            roster.accesses = pruned
            try? await changeRoster(nil)
        }
        var hashes: [String: String] = [:]
        for g in lists.asGrantor { if let k = g.grantorKey { hashes[k] = Emergency.sha256b64(k) } }
        let todo = Emergency.fillableAccesses(lists.asGrantor, roster, hashes: hashes)
        if todo.isEmpty { return }
        let personal = Set(try await personalOf(todo.flatMap(\.missingVaults)).wrap)
        for g in todo {
            let vaults = g.missingVaults.filter { personal.contains($0) }
            guard !vaults.isEmpty, let gk = g.grantorKey, let k = env.keys() else { continue }
            guard let key = try? k.openEmergencyKey(grantId: g.id, wrapped: gk) else { continue }
            let wraps = try wrapVaults(key, vaults)
            do {
                _ = try await call(Self.path(g.id, "/vault-keys"), body: ["vault_keys": wraps], method: "PUT")
            } catch {
                if !Self.vaultsMoved(error) { throw error }
            }
        }
    }

    // MARK: Requests

    /// Change the waiting period; a shorter one needs the master password.
    @discardableResult
    public func changeWait(_ id: String, days: Int, password: String?, secretKey: String? = nil) async throws -> Grant {
        var headers: [String: String] = [:]
        if let password { headers["x-reauth-token"] = try await reauth(password, secretKey) }
        return try grantOf(try await call(Self.path(id), body: ["wait_days": .int(Int64(days))], method: "PUT", headers: headers))
    }

    @discardableResult
    public func accept(_ id: String) async throws -> Grant { try grantOf(try await call(Self.path(id, "/accept"), method: "POST")) }

    @discardableResult
    public func requestAccess(_ id: String) async throws -> Grant { try grantOf(try await call(Self.path(id, "/request"), method: "POST")) }

    /// Approve a request now; needs the master password.
    @discardableResult
    public func approve(_ id: String, password: String, secretKey: String? = nil) async throws -> Grant {
        let token = try await reauth(password, secretKey)
        return try grantOf(try await call(Self.path(id, "/approve"), method: "POST", headers: ["x-reauth-token": token]))
    }

    @discardableResult
    public func reject(_ id: String) async throws -> Grant { try grantOf(try await call(Self.path(id, "/reject"), method: "POST")) }

    /// The grantor removes contact `g`: out of the roster first, then the access; when the contact
    /// held the key, the personal vaults the server names are given new keys now.
    public func removeContact(_ g: Grant) async throws -> Removal {
        try await pinned { try await removePinned(g) }
    }

    private func removePinned(_ g: Grant) async throws -> Removal {
        try await changeRoster(.remove(g.id, hash: g.grantorKey.map(Emergency.sha256b64)))
        let answer: JSON
        do {
            answer = try await call(Self.path(g.id), method: "DELETE")
        } catch let e as ApiError where e.status == 404 {
            return Removal(rotated: 0, failed: nil)
        }
        let named = Emergency.vaultsToReKey(answer) { _ in true }
        if named.isEmpty { return Removal(rotated: 0, failed: nil) }
        do {
            let wrap = Set(try await personalOf(named).wrap)
            let vaults = Emergency.vaultsToReKey(answer) { wrap.contains($0) }
            if vaults.isEmpty { return Removal(rotated: 0, failed: nil) }
            try checkPin()
            let done = try await env.rotate(vaults)
            return Removal(rotated: done.rotated.count, failed: nil, shared: done.sharedText ?? done.confirmText.map { _ in EmergencyText.confirmMembers })
        } catch {
            return Removal(rotated: 0, failed: errorMessage(error))
        }
    }

    /// The contact steps down or declines (never replaces anyone's keys). Already gone is done.
    public func leave(_ id: String) async throws {
        do {
            _ = try await call(Self.path(id), method: "DELETE")
        } catch let e as ApiError where e.status == 404 {}
    }

    /// The contact's view of an approved access: the grantor's personal vaults, decrypted into
    /// memory (`open` decrypts with the account's keys).
    public func grantorVaultData(_ id: String) async throws -> (grant: Grant, data: Emergency.GrantorVaultData) {
        try await requireEmergencyKeys()
        let answer = try await call(Self.path(id, "/vault"))
        guard let data = Emergency.readGrantorVault(answer), let grant = Emergency.readGrant(answer["grant"]), grant.id == id else {
            throw UserError(EmergencyText.unexpected)
        }
        if data.keyVersion != Emergency.keyVersion { throw UserError(data.keyVersion == nil ? EmergencyText.serverTooOld : EmergencyText.appTooOld) }
        return (grant, data)
    }
}

// MARK: The app's side

/// The core's emergency key, wrapping vault keys the repository holds.
final class CoreEmergencyKey: EmergencyKeyHandle {
    let key: EmergencyKey
    let vaultKey: (String) -> VaultKey?

    init(_ key: EmergencyKey, vaultKey: @escaping (String) -> VaultKey?) {
        self.key = key
        self.vaultKey = vaultKey
    }

    func sealFor(contactPublicKey: String, grantorId: String, grantId: String) throws -> String {
        try key.sealFor(contactPublicKey: contactPublicKey, grantorId: grantorId, grantId: grantId)
    }

    func wrapVault(_ vaultId: String) throws -> String {
        guard let vk = vaultKey(vaultId) else { throw UserError(EmergencyText.vaultsChanged) }
        return try key.wrapVaultKey(vaultKey: vk, vaultId: vaultId)
    }
}

/// The core's account as emergency access uses it.
final class CoreEmergencyAccount: EmergencyAccountKeys {
    let account: Account
    let vaultKey: (String) -> VaultKey?

    init(_ account: Account, vaultKey: @escaping (String) -> VaultKey?) {
        self.account = account
        self.vaultKey = vaultKey
    }

    func newEmergencyKey(grantId: String) throws -> (key: EmergencyKeyHandle, wrapped: String) {
        let made = try account.newEmergencyKey(grantId: grantId)
        return (CoreEmergencyKey(made.key, vaultKey: vaultKey), made.wrapped)
    }

    func openEmergencyKey(grantId: String, wrapped: String) throws -> EmergencyKeyHandle {
        CoreEmergencyKey(try account.openEmergencyKey(grantId: grantId, wrapped: wrapped), vaultKey: vaultKey)
    }

    func sealRoster(_ json: String) throws -> String { try account.sealEmergencyRoster(json: json) }
    func openRoster(_ sealed: String) throws -> String { try account.openEmergencyRoster(sealed: sealed) }
}

/// The roster memory in this device's Keychain (`emergency-roster.<user id>`): the highest version
/// opened and the last trusted sealed roster. It outlives signing out, as the web vault's
/// `localStorage` copy does.
public final class KeychainRosterMemory: RosterMemory {
    public init() {}

    private static func account(_ userId: String) -> String { "emergency-roster.\(userId)" }

    public func load(_ userId: String) -> (version: Int64, sealed: String?) {
        guard !userId.isEmpty, let d = Keychain.read(Self.account(userId)), let j = try? JSON.parse(d) else { return (0, nil) }
        let v = j["version"]?.int ?? 0
        return (v > 0 ? v : 0, j["sealed"]?.string)
    }

    public func save(_ userId: String, version: Int64, sealed: String?) {
        guard !userId.isEmpty else { return }
        let j: JSON = ["version": .int(version), "sealed": sealed.map(JSON.string) ?? .null]
        Keychain.write(Self.account(userId), j.data)
    }
}

extension VaultRepository {
    /// The active account's emergency access client (made once; it always acts for the account
    /// that is active when it is called).
    public var emergency: EmergencyClient {
        if let c = emergencyClient { return c }
        let memory = KeychainRosterMemory()
        // Weak: the client outlives no repository (a fill may still run when one goes away).
        let locked = UserError(EmergencyText.locked)
        let env = EmergencyEnvironment(
            api: { [weak self] path, body, method, headers in
                guard let self else { throw locked }
                return try await self.api.call(self.activeId, path, body: body, method: method, headers: headers)
            },
            keys: { [weak self] in
                guard let self, self.vault != nil, let s = self.sessions[self.activeId] else { return nil }
                return CoreEmergencyAccount(s.account) { [weak self] id in self?.vaultKeys[id] }
            },
            me: { [weak self] in self?.currentUserId ?? "" },
            vaults: { [weak self] in
                (self?.vault?.vaults ?? []).map { (Emergency.OwnVault(id: $0.id, role: $0.role, keyKind: $0.keyKind), $0.keyEpoch) }
            },
            features: { [weak self] in
                guard let self else { return nil }
                return await self.fetchConfig(self.activeId)?.features
            },
            reauth: { [weak self] password, secretKey in
                guard let self else { throw locked }
                return try await self.reauthToken(self.activeId, password: password, secretKey: secretKey)
            },
            rotate: { [weak self] ids in try await self?.rotateVaultKeys(ids, personalOnly: true) ?? KeyReplacement() },
            sync: { [weak self] in try await self?.sync() },
            memory: memory,
            notice: { [weak self] text in self?.emergencyNotice = text },
            account: { [weak self] in self?.activeId ?? "" },
            signedHistory: { [weak self] vid in self?.hasSignedHistory(vid) ?? true }
        )
        let c = EmergencyClient(env)
        emergencyClient = c
        return c
    }

    /// Whether the active account's server offers emergency access, and with emergency keys.
    public func emergencyConfig() async -> (enabled: Bool, keys: Bool)? {
        guard let f = await fetchConfig(activeId)?.features else { return nil }
        return (f.contains(emergencyAccessFeature), f.contains(emergencyVaultKeysFeature))
    }

    /// Fetch and decrypt the personal vaults a grantor shared through an approved access: the
    /// sealed emergency key is opened for this, each vault key for its items; nothing is stored.
    public func openGrantorVault(_ id: String) async throws -> GrantorVault {
        let (grant, data) = try await emergency.grantorVaultData(id)
        guard let account = sessions[activeId]?.account else { throw UserError(EmergencyText.locked) }
        let opened: GrantorVault = try await core {
            let key: EmergencyKey
            do {
                key = try account.openSealedEmergencyKey(grantorId: grant.grantor.id, grantId: id, sealed: data.sealedKey)
            } catch {
                throw UserError("Your account's keys can't open the access \(Emergency.personName(grant.grantor)) gave you. Ask them to remove you as their emergency contact and name you again.")
            }
            var vaults: [(id: String, name: String)] = []
            var items: [GrantorVault.Entry] = []
            var failed = 0
            var unverified = Set<String>()
            for v in data.vaults {
                let rows = data.items.filter { $0.vaultId == v.id }
                guard let vk = try? key.openVaultKey(vaultId: v.id, wrapped: v.wrappedKey) else {
                    failed += rows.count
                    continue
                }
                // The vault's manifest against exactly the rows of this answer (nothing is
                // remembered for someone else's vault, nothing written).
                if v.manifestSeq > 0 {
                    let header = SyncVault(id: v.id, keyEpoch: v.keyEpoch, manifest: v.manifest, manifestSeq: v.manifestSeq)
                    let all = rows.map { SyncItem(id: $0.id, vaultId: v.id, itemKey: $0.key, data: $0.data, deletedAt: $0.deletedAt) }
                    if VaultManifest.verify(header, key: vk, remembered: nil, rows: all).status != .ok { unverified.insert(v.id) }
                }
                var name = "Vault"
                if let meta = try? vk.decryptMeta(vaultId: v.id, meta: v.meta), let n = (try? JSON.parse(meta))?["name"]?.string,
                   !n.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    name = n
                }
                vaults.append((v.id, name))
                for r in rows {
                    guard let json = try? vk.decryptItem(encrypted: EncryptedItem(id: r.id, vaultId: v.id, key: r.key, data: r.data)),
                          let item = try? ItemCodec.decode(json) else {
                        failed += 1
                        continue
                    }
                    items.append(GrantorVault.Entry(id: r.id, vaultId: v.id, item: item, deletedAt: r.deletedAt))
                }
            }
            items.sort { $0.item.name.localizedCaseInsensitiveCompare($1.item.name) == .orderedAscending }
            return GrantorVault(grant: grant, vaults: vaults, items: items, failed: failed, unverified: unverified)
        }
        return opened
    }

    /// An emergency access's address for one of the grantor's files.
    public nonisolated static func emergencyAttachmentPath(grant: String, attachment: String) -> String {
        "/emergency-access/\(pathPart(grant))/attachments/\(pathPart(attachment))"
    }
}

extension VaultRepository {
    /// The active account's own key fingerprint (what a grantor checks before confirming it).
    public var ownFingerprint: String? {
        guard vault != nil else { return nil }
        return sessions[activeId]?.account.fingerprint()
    }
}
