import Foundation

// Delta sync (servers whose `/api/config` `features` has "delta_sync"; the server side is
// `crates/server/src/vault/sync.rs`). The offline copy of an account is the last `/sync`
// answer with every later change merged in (ciphertext only, the shape of a full answer), so
// the server's opaque `cursor` and each vault's `seq` are always stored together with the
// items they describe. `GET /sync?since=<cursor>` then brings only what changed. The pure
// parts are here (unit-tested in `DeltaSyncTests`); `VaultRepository` does the requests,
// decryption and storage.

/// The `/api/config` feature of servers that answer `GET /sync?since=<cursor>`.
public let deltaSyncFeature = "delta_sync"

/// A vault header of a `/sync` answer, as the server sends it (`meta` and the key encrypted).
public struct SyncVault: Codable, Equatable, Sendable {
    public var id: String
    public var meta: String
    public var role: String
    public var wrappedKey: String
    public var keyKind: String
    public var rotationPending: Int64?
    /// Goes up with every key replacement (API v2); nil from older servers.
    public var keyEpoch: Int64?
    /// Goes up with every write into the vault (delta sync); nil from older servers.
    public var seq: Int64?
    /// Signed sharing: `{signature, signer, signer_deleted}` of a sealed key, `null` when not
    /// signed (read with `ShareRecord.read`; kept as sent so the copy can be checked again).
    public var share: JSON?
    /// Signed sharing: the vault's latest member roster (JSON text as its signer's app made it)
    /// and its version (0 = none); nil from older servers.
    public var memberRoster: String?
    public var memberRosterSeq: Int64?
    /// Vault manifests (servers with `vault_manifest`): the vault's sealed manifest and its
    /// version (0 or nil: the vault has none), read in the same snapshot as the answer's items;
    /// `manifestOk`: while it has none, its first one may be started now.
    public var manifest: String?
    public var manifestSeq: Int64?
    public var manifestOk: Bool?

    public init(id: String, meta: String = "", role: String = "owner", wrappedKey: String = "", keyKind: String = "account",
                rotationPending: Int64? = nil, keyEpoch: Int64? = nil, seq: Int64? = nil, share: JSON? = nil,
                memberRoster: String? = nil, memberRosterSeq: Int64? = nil,
                manifest: String? = nil, manifestSeq: Int64? = nil, manifestOk: Bool? = nil) {
        self.id = id
        self.meta = meta
        self.role = role
        self.wrappedKey = wrappedKey
        self.keyKind = keyKind
        self.rotationPending = rotationPending
        self.keyEpoch = keyEpoch
        self.seq = seq
        self.share = share
        self.memberRoster = memberRoster
        self.memberRosterSeq = memberRosterSeq
        self.manifest = manifest
        self.manifestSeq = manifestSeq
        self.manifestOk = manifestOk
    }

    enum CodingKeys: String, CodingKey {
        case id, meta, role, seq, share, manifest
        case wrappedKey = "wrapped_key", keyKind = "key_kind", rotationPending = "rotation_pending", keyEpoch = "key_epoch"
        case memberRoster = "member_roster", memberRosterSeq = "member_roster_seq"
        case manifestSeq = "manifest_seq", manifestOk = "manifest_ok"
    }

    /// The manifest's version; 0: the vault has none.
    public var manifestVersion: Int64 { max(0, manifestSeq ?? 0) }

    /// The same vault key as `other` describes (wrapping, kind and epoch): an opened key can be kept.
    public func sameKey(as other: SyncVault) -> Bool {
        wrappedKey == other.wrappedKey && keyKind == other.keyKind && keyEpoch == other.keyEpoch
    }
}

/// An item row of a `/sync` answer (ciphertext and metadata).
public struct SyncItem: Codable, Equatable, Sendable {
    public var id: String
    public var vaultId: String
    /// nil for an item in the trash of a `trash=summary` answer.
    public var itemKey: String?
    public var data: String?
    public var revision: Int64?
    /// Moved to the trash at (unix seconds); nil for live items.
    public var deletedAt: Int64?
    public var createdAt: Int64?
    public var updatedAt: Int64?
    /// SHA-256 of the `data` text (base64url), on rows that come without `data` (`trash=summary`,
    /// servers with `vault_manifest`): what the vault's manifest is checked with for that row.
    public var dataSha256: String?
    /// Only in this device's copy, on a row it kept from a newer copy of its own after the
    /// server sent an older version of the item (item rollback): the hash of the data the server
    /// sent. The vault's manifest is checked (and advanced) with it, since that is what the
    /// manifest records for the row.
    public var servedSha256: String?

    public init(id: String, vaultId: String, itemKey: String?, data: String?, revision: Int64? = nil, deletedAt: Int64? = nil,
                createdAt: Int64? = nil, updatedAt: Int64? = nil, dataSha256: String? = nil) {
        self.id = id
        self.vaultId = vaultId
        self.itemKey = itemKey
        self.data = data
        self.revision = revision
        self.deletedAt = deletedAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.dataSha256 = dataSha256
    }

    enum CodingKeys: String, CodingKey {
        case id, data, revision
        case vaultId = "vault_id", itemKey = "item_key", deletedAt = "deleted_at", createdAt = "created_at", updatedAt = "updated_at"
        case dataSha256 = "data_sha256", servedSha256 = "served_sha256"
    }
}

/// An item that left a vault since the cursor (deleted for good, or moved to another vault).
public struct SyncDeleted: Codable, Equatable, Sendable {
    public var id: String
    public var vaultId: String

    public init(id: String, vaultId: String) {
        self.id = id
        self.vaultId = vaultId
    }

    enum CodingKeys: String, CodingKey {
        case id
        case vaultId = "vault_id"
    }
}

/// A `/sync` answer: everything, or (`delta == true`) what changed since the cursor sent.
public struct SyncResponse: Decodable, Sendable {
    public var revision: Int64?
    public var cursor: String?
    public var user: JSON?
    public var bundle: JSON?
    public var vaults: [SyncVault]?
    public var items: [SyncItem]?
    public var deleted: [SyncDeleted]?
    public var reset: [String]?
    public var delta: Bool?
    /// Vaults shared with the account and not accepted yet, always the full list (servers with
    /// `vault_invitations`); read leniently (`SyncInvitation.read`), so a malformed entry never
    /// makes the answer unreadable.
    public var invitations: JSON?
    /// The server's clock when the answer was read (unix seconds) and its trash retention in days
    /// (0: kept forever); servers with `vault_manifest` (old trash is then deleted by the apps).
    public var serverTime: Int64?
    public var trashDays: Int64?

    enum CodingKeys: String, CodingKey {
        case revision, cursor, user, bundle, vaults, items, deleted, reset, delta, invitations
        case serverTime = "server_time", trashDays = "trash_days"
    }
}

/// What this device has of an account: the sync revision of its copy and each vault's
/// sequence number (nil when the copy has no numbers: an older server or copy).
public struct SyncPosition: Equatable, Sendable {
    public var revision: Int64
    public var vaults: [String: Int64]?

    public init(revision: Int64, vaults: [String: Int64]?) {
        self.revision = revision
        self.vaults = vaults
    }
}

/// An account's copy: the last `/sync` answer with every later change merged in, in the shape
/// of a full answer (stored as the offline copy; readable by code that reads a full answer).
public struct SyncSnapshot: Codable, Equatable, Sendable {
    public var revision: Int64
    /// The server's cursor of the answer this copy was last brought up to date with (nil: the
    /// server doesn't do delta sync). Never newer than the items: a local change applied on top
    /// keeps it, so the next delta brings that change again, which is harmless.
    public var cursor: String?
    public var user: JSON?
    /// The account bundle (every server sends it; checked where a copy is stored without
    /// unlocking, `DeltaSync.refresh`).
    public var bundle: JSON?
    public var vaults: [SyncVault]
    public var items: [SyncItem]
    /// The pending vault invitations of the last answer (each answer, full or delta, lists them
    /// all); empty from servers without them and in copies stored before them.
    public var invitations: [SyncInvitation]
    /// The server's clock and trash retention of the answer this copy was last synced with
    /// (`SyncResponse`); not stored with the copy (nil in one read from the device).
    public var serverTime: Int64?
    public var trashDays: Int64?

    public init(revision: Int64, cursor: String?, user: JSON?, bundle: JSON?, vaults: [SyncVault], items: [SyncItem], invitations: [SyncInvitation] = []) {
        self.revision = revision
        self.cursor = cursor
        self.user = user
        self.bundle = bundle
        self.vaults = vaults
        self.items = items
        self.invitations = invitations
    }

    enum CodingKeys: String, CodingKey {
        case revision, cursor, user, bundle, vaults, items, invitations
    }

    /// Copies are read through `decode` (as a `/sync` answer); this keeps a direct decode of an
    /// older copy (without `invitations`) working too.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        revision = try c.decode(Int64.self, forKey: .revision)
        cursor = try c.decodeIfPresent(String.self, forKey: .cursor)
        user = try c.decodeIfPresent(JSON.self, forKey: .user)
        bundle = try c.decodeIfPresent(JSON.self, forKey: .bundle)
        vaults = try c.decode([SyncVault].self, forKey: .vaults)
        items = try c.decode([SyncItem].self, forKey: .items)
        invitations = SyncInvitation.read(try c.decodeIfPresent(JSON.self, forKey: .invitations))
    }

    public var position: SyncPosition {
        var seqs: [String: Int64] = [:]
        for v in vaults {
            guard let s = v.seq else { return SyncPosition(revision: revision, vaults: nil) }
            seqs[v.id] = s
        }
        return SyncPosition(revision: revision, vaults: seqs)
    }

    /// Compact JSON for the offline copy (slashes unescaped: the ciphertext is base64).
    public func encoded() throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return try e.encode(self)
    }

    /// The stored copy, or nil when it can't be read as one.
    public static func decode(_ data: Data) -> SyncSnapshot? {
        guard let r = try? JSONDecoder().decode(SyncResponse.self, from: data) else { return nil }
        return SyncMerge.apply(r, to: nil)
    }
}

/// A write this device made, as the server stored it, to apply to the copy without asking the
/// server again (see `SyncDecision.afterWrite`).
public enum LocalChange: Equatable, Sendable {
    /// Created or changed in place: the row as sent (`itemKey`, `data`) with the server's revision.
    case put(SyncItem)
    /// Moved to the trash (`summary`: the copy keeps trashed items without key and data).
    case trash(id: String, at: Int64, revision: Int64, summary: Bool)
    case restore(id: String, revision: Int64)
    /// Deleted for good.
    case purge(id: String)
}

public enum SyncMerge {
    /// The copy after `response`: a full answer replaces `base`; a delta (`delta: true`) is
    /// applied to it: `deleted` first (only from the vault it names), then the rows of the
    /// `reset` vaults, then `items` upserted by id (an item that moved between two readable
    /// vaults is in both lists), and items of vaults missing from `vaults` dropped with them.
    /// Vault headers, revision, cursor, user, bundle and the invitations (always the full list;
    /// none from older servers) come from the answer.
    ///
    /// nil for an answer that isn't a vault snapshot (a numeric revision, `vaults` and `items`;
    /// well-formed rows, checked by decoding, and only trashed ones without key and data) or a
    /// delta without the copy it was asked for.
    public static func apply(_ r: SyncResponse, to base: SyncSnapshot?) -> SyncSnapshot? {
        guard let revision = r.revision, revision >= 0, let vaults = r.vaults, let items = r.items else { return nil }
        let bundle = r.bundle == .null ? nil : r.bundle
        // Only trashed items may come without key and data (`trash=summary`).
        guard items.allSatisfy({ ($0.itemKey != nil && $0.data != nil) || $0.deletedAt != nil }) else { return nil }
        let invitations = SyncInvitation.read(r.invitations)
        guard r.delta == true else {
            var full = SyncSnapshot(revision: revision, cursor: r.cursor, user: r.user, bundle: bundle, vaults: vaults, items: items, invitations: invitations)
            full.serverTime = r.serverTime
            full.trashDays = r.trashDays
            return full
        }
        guard let base else { return nil }
        let gone = Set((r.deleted ?? []).map { RowKey(vault: $0.vaultId, id: $0.id) })
        let reset = Set(r.reset ?? [])
        let upserted = Set(items.map(\.id))
        let readable = Set(vaults.map(\.id))
        var rows = base.items.filter { row in
            !gone.contains(RowKey(vault: row.vaultId, id: row.id)) && !reset.contains(row.vaultId) && !upserted.contains(row.id)
        }
        // An id twice in one answer (never sent by the server): the later row wins.
        var seen = Set<String>()
        rows += items.reversed().filter { seen.insert($0.id).inserted }.reversed()
        rows.removeAll { !readable.contains($0.vaultId) }
        var merged = SyncSnapshot(revision: revision, cursor: r.cursor, user: r.user ?? base.user, bundle: bundle ?? base.bundle, vaults: vaults, items: rows,
                                  invitations: invitations)
        merged.serverTime = r.serverTime
        merged.trashDays = r.trashDays
        return merged
    }

    /// This device's own `change` in `vaultId`, applied to the copy after the server answered
    /// `vaultSeq` = the copy's number + 1 (nothing else was written there meanwhile): the row is
    /// replaced or removed and the vault's number set. Revision, cursor and invitations stay (the
    /// next delta from that cursor brings the row again). nil when the copy can't take it (vault
    /// or item not there, a summary row to restore): sync instead.
    ///
    /// `manifest`: the vault manifest this device sent with the write, which the server answered
    /// as the vault's current one (`manifest_seq`): the vault row takes it together with the
    /// change, so the copy still matches its manifest.
    public static func applyLocal(_ change: LocalChange, vaultId: String, vaultSeq: Int64, manifest: ManifestEntry? = nil,
                                  to s: SyncSnapshot) -> SyncSnapshot? {
        guard let v = s.vaults.firstIndex(where: { $0.id == vaultId }) else { return nil }
        var next = s
        next.vaults[v].seq = vaultSeq
        if let manifest {
            guard manifest.vaultId == vaultId else { return nil }
            next.vaults[v].manifest = manifest.sealed
            next.vaults[v].manifestSeq = Int64(clamping: manifest.seq)
        }
        switch change {
        case .put(let row):
            guard row.vaultId == vaultId, row.itemKey != nil, row.data != nil else { return nil }
            var row = row
            if let old = s.items.first(where: { $0.id == row.id }) { row.createdAt = row.createdAt ?? old.createdAt }
            next.items.removeAll { $0.id == row.id }
            next.items.append(row)
        case .trash(let id, let at, let revision, let summary):
            guard let i = next.items.firstIndex(where: { $0.id == id && $0.vaultId == vaultId }) else { return nil }
            next.items[i].deletedAt = at
            next.items[i].revision = revision
            next.items[i].updatedAt = at
            if summary {
                // The manifest is checked with the hash of the data the row no longer carries.
                if let data = next.items[i].data { next.items[i].dataSha256 = VaultManifest.dataHash(data) }
                next.items[i].itemKey = nil
                next.items[i].data = nil
            }
        case .restore(let id, let revision):
            guard let i = next.items.firstIndex(where: { $0.id == id && $0.vaultId == vaultId }),
                  next.items[i].itemKey != nil, next.items[i].data != nil else { return nil }
            next.items[i].deletedAt = nil
            next.items[i].revision = revision
            next.items[i].dataSha256 = nil
        case .purge(let id):
            guard next.items.contains(where: { $0.id == id && $0.vaultId == vaultId }) else { return nil }
            next.items.removeAll { $0.id == id && $0.vaultId == vaultId }
        }
        return next
    }

    private struct RowKey: Hashable {
        let vault: String
        let id: String
    }
}

/// When to talk to the server, from the numbers alone.
public enum SyncDecision {
    /// `GET /sync/revision` answered `revision` and (servers with delta sync) each vault's number:
    /// does the copy at `have` lack something? Without vault numbers (older server or copy): only
    /// a newer revision counts, as before. With them: any other revision (profile, bundle and
    /// membership changes have no vault number; after this device's own writes were applied to
    /// the copy its revision is behind, which costs one small delta), or any vault whose number
    /// differs, that is new, or that is gone.
    public static func isStale(revision: Int64, vaults: [String: Int64]?, have: SyncPosition) -> Bool {
        guard let server = vaults, let mine = have.vaults else { return revision > have.revision }
        if revision != have.revision { return true }
        return server != mine
    }

    public enum AfterWrite: Equatable, Sendable {
        /// The copy already has the write (a retried create whose first attempt it holds).
        case nothing
        /// The vault's next number: only this write happened there, apply it to the copy.
        case applyLocally
        /// Other writes too, numbers unknown, or numbers gone backwards (a restored server): sync.
        case sync
    }

    /// After this device's write into a vault: `known` = the copy's number for it, `vaultSeq` =
    /// the server's answer (`vault_seq`; nil from older servers).
    public static func afterWrite(known: Int64?, vaultSeq: Int64?) -> AfterWrite {
        guard let known, let vaultSeq else { return .sync }
        if vaultSeq == known { return .nothing }
        return vaultSeq == known + 1 ? .applyLocally : .sync
    }

    /// A live sync message (`{"type":"sync","revision","vaults"}`) against the copy at `have`
    /// (nil: nothing open to refresh). With `vaults` (servers with delta sync): sync when it is
    /// empty (a profile or account change) or names a vault whose number is newer than the
    /// copy's (or a vault the copy doesn't have), whoever wrote it; this device's own writes
    /// are already in the copy and are skipped that way. Without `vaults` (older servers): a
    /// newer revision, as before.
    public static func onLiveSync(revision: Int64, vaults: [String: Int64]?, have: SyncPosition?) -> Bool {
        guard let have else { return false }
        guard let vaults else { return revision > have.revision }
        if vaults.isEmpty { return true }
        guard let mine = have.vaults else { return true }
        return vaults.contains { id, seq in seq > (mine[id] ?? -1) }
    }
}

/// One sync in flight and at most one waiting: a request made while a sync is already waiting
/// joins that one (it starts after the request was made, so it sees everything the request
/// would have); a request made while one runs waits for the next. Errors go to every waiter.
@MainActor
public final class SyncQueue {
    private var running: (id: Int, task: Task<Void, Error>)?
    private var waiting: (id: Int, task: Task<Void, Error>)?
    private var counter = 0

    public init() {}

    public func run(_ work: @escaping @MainActor () async throws -> Void) async throws {
        if let waiting { return try await waiting.task.value }
        counter += 1
        let id = counter
        let before = running?.task
        let task = Task { @MainActor [weak self] in
            if let before { _ = await before.result }
            if let self, self.waiting?.id == id {
                self.running = self.waiting
                self.waiting = nil
            }
            defer { if let self, self.running?.id == id { self.running = nil } }
            try await work()
        }
        if before == nil { running = (id, task) } else { waiting = (id, task) }
        try await task.value
    }
}

/// The requests of a sync, apart from the transport (`get`: an authenticated GET below `/api`).
public enum DeltaSync {
    /// `/sync`, `/sync?since=<cursor>`, and `trash=summary` for apps that never show the trash.
    public static func path(since: String?, trashSummary: Bool) -> String {
        var query: [String] = []
        if let since, !since.isEmpty {
            // A cursor is base64url; anything else is escaped so it can't add parameters.
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-_")
            query.append("since=" + (since.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""))
        }
        if trashSummary { query.append("trash=summary") }
        return query.isEmpty ? "/sync" : "/sync?" + query.joined(separator: "&")
    }

    /// The copy after a sync from `base`: `since` its cursor when the server does delta sync
    /// (`delta`), else everything. Throws for an answer that isn't a vault snapshot; nothing is
    /// stored here, so a failed or interrupted sync leaves the previous copy and cursor.
    public static func fetch(base: SyncSnapshot?, delta: Bool, trashSummary: Bool,
                             get: @Sendable (String) async throws -> Data) async throws -> SyncSnapshot {
        let since = delta ? base?.cursor : nil
        let answer = try decode(try await get(path(since: since, trashSummary: trashSummary)))
        guard let next = SyncMerge.apply(answer, to: since == nil ? nil : base) else { throw unreadable }
        return next
    }

    public enum CacheRefresh: Equatable, Sendable {
        /// The copy is current (`/sync/revision` matched it): nothing to fetch or write.
        case current
        /// The answer was older than the copy: never downgrade, keep it.
        case keep
        case write(SyncSnapshot)
    }

    /// A locked account's copy brought up to date without decrypting anything: with delta sync
    /// and a cursor, `/sync/revision` decides and only the changes are fetched and merged;
    /// otherwise the whole `/sync` replaces the copy (when not older), as before. The copy
    /// written must carry the account bundle (the next unlock needs it).
    public static func refresh(cached: SyncSnapshot?, delta: Bool, trashSummary: Bool,
                               get: @Sendable (String) async throws -> Data) async throws -> CacheRefresh {
        if delta, let cached, cached.cursor != nil {
            // Network and session errors end the refresh; an unreadable answer just means "fetch".
            let poll = try await get("/sync/revision")
            if let r = try? JSONDecoder().decode(RevisionAnswer.self, from: poll), let revision = r.revision,
               !SyncDecision.isStale(revision: revision, vaults: r.vaults, have: cached.position) {
                return .current
            }
            try Task.checkCancellation()
            let next = try await fetch(base: cached, delta: true, trashSummary: trashSummary, get: get)
            guard next.bundle != nil else { throw unreadable }
            return next.revision < cached.revision ? .keep : .write(next)
        }
        let next = try await fetch(base: nil, delta: false, trashSummary: trashSummary, get: get)
        guard next.bundle != nil else { throw unreadable }
        if let cached, next.revision < cached.revision { return .keep }
        return .write(next)
    }

    /// `{"<vault>": seq}` of `/sync/revision` and live sync messages; nil when absent (older servers).
    public static func vaultNumbers(_ j: JSON?) -> [String: Int64]? {
        guard case .object(let o)? = j else { return nil }
        return o.compactMapValues { $0.number }
    }

    /// `GET /sync/revision`: the account's revision and (delta sync) each vault's number.
    public struct RevisionAnswer: Decodable, Sendable {
        public var revision: Int64?
        public var vaults: [String: Int64]?
    }

    static func decode(_ data: Data) throws -> SyncResponse {
        do {
            return try JSONDecoder().decode(SyncResponse.self, from: data)
        } catch {
            throw unreadable
        }
    }

    static var unreadable: UserError { UserError("The server's answer couldn't be read.") }
}
