import Foundation
import PassAuthCore

// Offline changes (waiting to sync): docs/ARCHITECTURE.md "Offline changes". The rules here are
// pure (the list, merging, what to send, conflicts, the overlay shown); `OfflineSync.swift` keeps
// the list and sends it. Saves from the iOS AutoFill extension go into the same list; the macOS
// AutoFill extension compiles this file but never queues anything (`OfflineQueue.enabled`).

public enum OfflineKind: String, Codable, Sendable { case create, edit, trash }

public enum OfflineState: String, Codable, Sendable { case waiting, held, conflict }

/// The exact body of the last attempt that may have reached the server.
public struct OfflineSent: Codable, Equatable, Sendable {
    public var key: String
    public var data: String
    public var keyEpoch: Int64?

    public init(key: String, data: String, keyEpoch: Int64?) {
        self.key = key
        self.data = data
        self.keyEpoch = keyEpoch
    }

    enum CodingKeys: String, CodingKey {
        case key, data
        case keyEpoch = "key_epoch"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        key = try c.decode(String.self, forKey: .key)
        data = try c.decode(String.self, forKey: .data)
        keyEpoch = try c.decodeIfPresent(Int64.self, forKey: .keyEpoch)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(key, forKey: .key)
        try c.encode(data, forKey: .data)
        try c.encode(keyEpoch, forKey: .keyEpoch)
    }
}

/// One change waiting on this device (the list's JSON shape is the contract's, shared by every app).
public struct OfflineChange: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var kind: OfflineKind
    public var vaultId: String
    public var itemId: String
    /// The server revision the change started from; nil for a create.
    public var baseRevision: Int64?
    /// The decrypted item as the editor saved it (create/edit); nil for trash.
    public var item: JSON?
    public var sent: OfflineSent?
    /// Milliseconds since 1970.
    public var createdAt: Int64
    public var state: OfflineState
    /// The text shown for `held` / `conflict`, else nil.
    public var reason: String?

    public init(id: String = UUID().uuidString.lowercased(), kind: OfflineKind, vaultId: String, itemId: String, baseRevision: Int64? = nil,
                item: JSON? = nil, sent: OfflineSent? = nil, createdAt: Int64, state: OfflineState = .waiting, reason: String? = nil) {
        self.id = id
        self.kind = kind
        self.vaultId = vaultId
        self.itemId = itemId
        self.baseRevision = baseRevision
        self.item = item
        self.sent = sent
        self.createdAt = createdAt
        self.state = state
        self.reason = reason
    }

    enum CodingKeys: String, CodingKey {
        case id, kind, item, sent, state, reason
        case vaultId = "vault_id", itemId = "item_id", baseRevision = "base_revision", createdAt = "created_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(OfflineKind.self, forKey: .kind)
        vaultId = try c.decode(String.self, forKey: .vaultId)
        itemId = try c.decode(String.self, forKey: .itemId)
        baseRevision = try c.decodeIfPresent(Int64.self, forKey: .baseRevision)
        let i = try c.decodeIfPresent(JSON.self, forKey: .item)
        item = i == .null ? nil : i
        sent = try c.decodeIfPresent(OfflineSent.self, forKey: .sent)
        createdAt = try c.decode(Int64.self, forKey: .createdAt)
        state = (try? c.decode(OfflineState.self, forKey: .state)) ?? .waiting
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(kind, forKey: .kind)
        try c.encode(vaultId, forKey: .vaultId)
        try c.encode(itemId, forKey: .itemId)
        try c.encode(baseRevision, forKey: .baseRevision)
        try c.encode(item ?? .null, forKey: .item)
        try c.encode(sent, forKey: .sent)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encode(state, forKey: .state)
        try c.encode(reason, forKey: .reason)
    }

    /// The item as saved (create/edit), nil when it can't be read.
    public var decodedItem: Item? {
        guard let item, case .object = item else { return nil }
        return try? ItemCodec.decode(item.text)
    }
}

/// The stored list: `{"version": 1, "changes": [...]}`.
public struct OfflineChangeList: Codable, Equatable, Sendable {
    public var version = 1
    public var changes: [OfflineChange] = []

    public init(changes: [OfflineChange] = []) { self.changes = changes }

    public static func decode(_ json: String) throws -> OfflineChangeList {
        let list = try JSONDecoder().decode(OfflineChangeList.self, from: Data(json.utf8))
        guard list.version == 1 else { throw UserError(OfflineText.unreadable) }
        return list
    }

    public func encoded() -> String {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: (try? e.encode(self)) ?? Data("{\"version\":1,\"changes\":[]}".utf8), as: UTF8.self)
    }
}

/// A write's request that may have reached the server (`VaultRepository.lastAttempt`).
public struct OfflineAttempt: Equatable, Sendable {
    public var itemId: String
    public var vaultId: String
    public var sent: OfflineSent
}

/// The marker an item with a waiting change carries.
public struct OfflineMark: Equatable, Sendable {
    public var state: OfflineState
    public var reason: String?
    public var kind: OfflineKind
    public var changeId: String

    public init(state: OfflineState, reason: String?, kind: OfflineKind, changeId: String) {
        self.state = state
        self.reason = reason
        self.kind = kind
        self.changeId = changeId
    }

    /// "Waiting to sync", "Not sent: <reason>", "Changed on another device".
    public var label: String {
        switch state {
        case .waiting: OfflineText.waiting
        case .held: OfflineText.held(reason)
        case .conflict: OfflineText.conflict
        }
    }
}

public enum OfflineText {
    public static let waiting = "Waiting to sync"
    public static let conflict = "Changed on another device"
    public static func held(_ reason: String?) -> String { "Not sent: " + (reason.flatMap { $0.isEmpty ? nil : $0 } ?? "try again later.") }
    public static let tooMany = "Too many changes are waiting. Connect to the internet before making more."
    public static let needsConnection = "You're offline. This needs a connection."
    public static let trashedOffline = "This item is in the trash. Restoring it needs a connection."
    public static let unreadable = "The changes waiting on this device can't be read now. Try again in a moment."
    /// The stored list can't be opened (saved by a newer version of PassAuth, or damaged).
    public static let cantOpen = "Changes waiting on this device can't be read. Update PassAuth to send them. Until then, changes can't wait on this device."
    public static let discardTitle = "Discard this change?"
    public static let discardMessage = "Your change to this item will be lost."
    public static let discard = "Discard this change"
    public static let savedWaiting = "Saved on this device. It will sync when you're back online."
    public static let trashedWaiting = "Moved to trash on this device. It will sync when you're back online."
    public static let changedText = "This item was changed on another device."
    public static let deletedText = "This item was deleted on another device."
    public static let offlineCopySuffix = " (offline copy)"
    public static let goneVault = "This vault is gone, or you can no longer change it."
    public static let readOnly = "You can only view items in this vault now."
    public static let refusedVault = "This vault didn't pass PassAuth's sharing checks."
    public static let pendingFirst = "This item has a change waiting to sync. Wait until it's sent, or discard it first."
    public static let idTaken = "Another item already has this item's id."

    /// "N changes waiting to sync" / "N changes need your decision" (nil: nothing waits).
    public static func status(_ changes: [OfflineChange]) -> String? {
        let decide = changes.filter { $0.state == .conflict }.count
        if decide > 0 { return decide == 1 ? "1 change needs your decision" : "\(decide) changes need your decision" }
        let n = changes.count
        if n == 0 { return nil }
        return n == 1 ? "1 change waiting to sync" : "\(n) changes waiting to sync"
    }

    /// The warning before Log out, Change server, removing the account or deleting it.
    public static func lost(_ n: Int) -> String? {
        guard n > 0 else { return nil }
        return n == 1 ? "1 change hasn't been sent and will be lost." : "\(n) changes haven't been sent and will be lost."
    }
}

/// What the decision sheet is about.
public enum OfflineConflictKind: Equatable, Sendable {
    /// An edit of an item changed on another device.
    case changed
    /// An edit of an item deleted for good on another device.
    case deleted
    /// Moving to the trash an item changed on another device.
    case trash
}

public enum OfflineChoice: String, CaseIterable, Sendable {
    case keepMine, keepOther, keepBoth, saveAsNew, discardMine, trashAnyway

    public var title: String {
        switch self {
        case .keepMine: "Keep mine"
        case .keepOther: "Keep the other"
        case .keepBoth: "Keep both"
        case .saveAsNew: "Save mine as a new item"
        case .discardMine: "Discard mine"
        case .trashAnyway: "Move to trash anyway"
        }
    }
}

/// One row of the decision sheet: a field of both versions.
public struct OfflineField: Identifiable, Equatable, Sendable {
    public var label: String
    public var mine: String
    public var theirs: String
    public var secret: Bool
    public var id: String { label }
    public var differs: Bool { mine != theirs }
}

/// The server's row of an item as the copy holds it, for the send decision.
public struct OfflineServerRow: Equatable, Sendable {
    public var revision: Int64
    public var data: String?
    public var trashed: Bool

    public init(revision: Int64, data: String?, trashed: Bool) {
        self.revision = revision
        self.data = data
        self.trashed = trashed
    }
}

/// What to do with one change now.
public enum OfflineStep: Equatable, Sendable {
    /// Create: `POST /items` with the change's item id.
    case post
    /// Create: another item has this id: a new id once, then post.
    case newId
    /// Send the item as an edit of the server's row at this revision.
    case edit(revision: Int64)
    /// Move to the trash at this revision.
    case trash(revision: Int64)
    /// The server already has it: remove the change.
    case done
    case conflict(OfflineConflictKind)
    case hold(String)
}

/// What to do after a request of the sender failed.
public enum OfflineAfterError: Equatable, Sendable {
    /// No answer from the server: stop, try later (the change keeps `sent`).
    case stop
    /// The item changed (`revision_conflict`, `item_exists`): sync and decide again.
    case redecide
    /// The vault changed (`manifest_conflict`, `vault_key_changed`): sync and try again.
    case retry
    case conflict
    case hold(String)
}

public enum OfflineQueue {
    /// At most this many changes wait.
    public static let limit = 500
    /// `revision_conflict` / `manifest_conflict` / `vault_key_changed`: at most this many tries.
    public static let attempts = 3

    /// The iOS app and its AutoFill extension keep a list; the macOS AutoFill extension doesn't
    /// (its writes fail offline as before).
    public static var enabled: Bool {
        #if os(iOS)
        true
        #else
        false
        #endif
    }

    /// A save goes to the list instead of failing: the request got no answer from the server
    /// (no network, DNS, connection refused or reset, TLS, timeout) or a 502/503/504. Never for
    /// any other answer (4xx, 500, 507).
    public static func waits(_ error: Error) -> Bool {
        if let e = error as? ApiError { return [502, 503, 504].contains(e.status) }
        if let e = error as? UserError { return e.message == cantReachServerMessage }
        return error is URLError
    }

    public enum MergeError: Error, Equatable {
        case tooMany
        case trashed

        public var text: String {
            switch self {
            case .tooMany: OfflineText.tooMany
            case .trashed: OfflineText.trashedOffline
            }
        }
    }

    /// `list` with `new` added: one change per item, a new change merged into the item's
    /// existing one (create + edit = create with the new item; edit + edit = edit with the first
    /// `base_revision` and the newest item; edit + trash = trash with the first `base_revision`;
    /// create + trash = removed, or a trash with `base_revision` null when `sent` is set). A
    /// merged change waits again. A trashed item can't be edited. At most `limit` changes.
    public static func merge(_ list: [OfflineChange], _ new: OfflineChange) throws -> [OfflineChange] {
        guard let i = list.firstIndex(where: { $0.itemId == new.itemId }) else {
            guard list.count < limit else { throw MergeError.tooMany }
            return list + [new]
        }
        var out = list
        var old = list[i]
        switch (old.kind, new.kind) {
        case (.create, .create), (.create, .edit), (.edit, .edit), (.edit, .create):
            old.item = new.item
        case (.create, .trash):
            guard old.sent != nil else {
                out.remove(at: i)
                return out
            }
            old.kind = .trash
            old.baseRevision = nil
            old.item = nil
        case (.edit, .trash):
            old.kind = .trash
            old.item = nil
        case (.trash, .trash):
            return list
        case (.trash, _):
            throw MergeError.trashed
        }
        old.state = .waiting
        old.reason = nil
        out[i] = old
        return out
    }

    /// Why a change into vault `vaultId` is held now (nil: it may be sent): the vault is gone,
    /// the user can't write to it any more, or it has a warning (signed sharing's checks,
    /// a manifest that doesn't match or wasn't checked by this sync).
    public static func holdReason(vaultId: String, vaults: [VaultInfo], refused: [RefusedVault]) -> String? {
        guard let v = vaults.first(where: { $0.id == vaultId }) else {
            return refused.contains { $0.id == vaultId } ? OfflineText.refusedVault : OfflineText.goneVault
        }
        if v.role == .read { return OfflineText.readOnly }
        if v.manifest.unresolved { return ManifestText.held }
        if v.manifest.pending { return ManifestText.unchecked }
        return nil
    }

    /// What to send for `c` given the server's row of its item (nil: none) and why its vault is
    /// held (`hold`). `sentMatches`: the item the server holds is the change's own item (the
    /// last attempt landed with the content saved now); a change edited again after an attempt
    /// that landed goes on as an edit of the landed row.
    public static func decide(_ c: OfflineChange, row: OfflineServerRow?, hold: String?, sentMatches: Bool = true) -> OfflineStep {
        if let hold { return .hold(hold) }
        let landed = row.map { r in c.sent != nil && r.data != nil && r.data == c.sent?.data } ?? false
        switch c.kind {
        case .create:
            guard let row else { return .post }
            if landed { return sentMatches ? .done : .edit(revision: row.revision) }
            return .newId
        case .edit:
            guard let row else { return .conflict(.deleted) }
            if landed { return sentMatches ? .done : .edit(revision: row.revision) }
            if row.revision == c.baseRevision { return .edit(revision: row.revision) }
            return .conflict(.changed)
        case .trash:
            guard let row, !row.trashed else { return .done }
            if row.revision == c.baseRevision || landed { return .trash(revision: row.revision) }
            return .conflict(.trash)
        }
    }

    /// After a failed request (`tries`: requests of this kind so far for the change).
    public static func afterError(_ error: Error, tries: Int) -> OfflineAfterError {
        if waits(error) { return .stop }
        guard let e = error as? ApiError else { return .hold(errorMessage(error)) }
        if e.status == 409 && e.hasCode("revision_conflict") { return tries < attempts ? .redecide : .conflict }
        if e.status == 409 && VaultRepository.itemExists(e) { return tries < attempts ? .redecide : .hold(errorMessage(e)) }
        if VaultManifest.retry(e) || (e.status == 409 && e.hasCode("vault_key_changed")) {
            return tries < attempts ? .retry : .hold(ManifestText.busy)
        }
        return .hold(errorMessage(e))
    }

    /// The conflict's kind as the decision sheet shows it: an edit whose item is gone from the
    /// server is about a deleted item.
    public static func conflictKind(_ c: OfflineChange, serverHasItem: Bool) -> OfflineConflictKind {
        switch c.kind {
        case .trash: .trash
        case .create, .edit: serverHasItem ? .changed : .deleted
        }
    }

    public static func choices(_ kind: OfflineConflictKind) -> [OfflineChoice] {
        switch kind {
        case .changed: [.keepMine, .keepOther, .keepBoth]
        case .deleted: [.saveAsNew, .discardMine]
        case .trash: [.trashAnyway, .keepOther]
        }
    }

    /// The text a conflict is held with.
    public static func conflictReason(_ kind: OfflineConflictKind) -> String {
        kind == .deleted ? OfflineText.deletedText : OfflineText.changedText
    }

    /// "Keep both": this device's version as a new item, named so the two can be told apart.
    public static func copyItem(_ item: Item) -> Item {
        var i = item
        i.name = (i.name.isEmpty ? "Untitled" : i.name) + OfflineText.offlineCopySuffix
        i.rev = 0
        return i
    }

    /// The item the change saved and the server's, compared without what only the core sets
    /// (`rev`): is the server's row the change's own content?
    public static func sameContent(_ a: Item, _ b: Item) -> Bool {
        var x = a, y = b
        x.rev = 0
        y.rev = 0
        x.format = nil
        y.format = nil
        return x == y
    }

    /// Both versions field by field (rows where both are empty left out).
    public static func compare(mine: Item?, theirs: Item?) -> [OfflineField] {
        var out: [OfflineField] = []
        func add(_ label: String, _ m: String?, _ t: String?, secret: Bool = false) {
            let a = m ?? "", b = t ?? ""
            if !a.isEmpty || !b.isEmpty { out.append(OfflineField(label: label, mine: a, theirs: b, secret: secret)) }
        }
        add("Name", mine?.name, theirs?.name)
        add("Username", mine?.login?.username, theirs?.login?.username)
        add("Password", mine?.login?.password, theirs?.login?.password, secret: true)
        add("Verification code", mine?.login?.totp, theirs?.login?.totp, secret: true)
        add("Websites", mine?.login.map { $0.urls.map(\.url).joined(separator: "\n") }, theirs?.login.map { $0.urls.map(\.url).joined(separator: "\n") })
        add("Passkeys", mine?.login.map { "\($0.passkeys.count)" }.flatMap { $0 == "0" ? nil : $0 },
            theirs?.login.map { "\($0.passkeys.count)" }.flatMap { $0 == "0" ? nil : $0 })
        add("Cardholder name", mine?.card?.cardholderName, theirs?.card?.cardholderName)
        add("Card number", mine?.card?.number, theirs?.card?.number, secret: true)
        add("Expires", mine?.card.map { expiry($0) }, theirs?.card.map { expiry($0) })
        add("Security code", mine?.card?.code, theirs?.card?.code, secret: true)
        add("Personal details", mine?.identity.map(identity), theirs?.identity.map(identity))
        add("SSH private key", mine?.sshKey?.privateKey, theirs?.sshKey?.privateKey, secret: true)
        let names = Array(Set((mine?.fields ?? []).map(\.name) + (theirs?.fields ?? []).map(\.name))).sorted()
        for n in names {
            let a = mine?.fields.first { $0.name == n }, b = theirs?.fields.first { $0.name == n }
            add(n.isEmpty ? "Field" : n, a?.value, b?.value, secret: a?.type == .hidden || b?.type == .hidden)
        }
        add("Notes", mine?.notes, theirs?.notes)
        add("Folder", mine?.folder, theirs?.folder)
        add("Favorite", (mine?.favorite ?? false) ? "Yes" : nil, (theirs?.favorite ?? false) ? "Yes" : nil)
        return out
    }

    private static func expiry(_ c: Card) -> String {
        c.expMonth.isEmpty && c.expYear.isEmpty ? "" : "\(c.expMonth)/\(c.expYear)"
    }

    private static func identity(_ i: Identity) -> String {
        [i.firstName, i.lastName, i.email, i.phone, i.address1, i.city, i.country].filter { !$0.isEmpty }.joined(separator: ", ")
    }

    /// `v` as shown: the copy with the list applied on top. Created items appear, edits show the
    /// new content, trashed items are in the trash; each carries its marker.
    public static func overlay(_ v: VaultData, _ changes: [OfflineChange]) -> VaultData {
        guard !changes.isEmpty else { return v }
        var out = v
        for c in changes {
            let mark = OfflineMark(state: c.state, reason: c.reason, kind: c.kind, changeId: c.id)
            let base = out.entries.first { $0.id == c.itemId } ?? out.trash.first { $0.id == c.itemId }
            switch c.kind {
            case .create, .edit:
                guard let item = c.decodedItem else { continue }
                let enc = base?.enc ?? EncryptedItem(id: c.itemId, vaultId: c.vaultId, key: "", data: "")
                var e = Entry(id: c.itemId, item: item, vaultId: base?.vaultId ?? c.vaultId, revision: base?.revision ?? (c.baseRevision ?? 0),
                              enc: enc, deletedAt: base?.deletedAt, rolledBack: base?.rolledBack ?? false)
                e.pending = mark
                place(&out, e)
            case .trash:
                guard var e = base else { continue }
                if e.deletedAt == nil { e = Entry(id: e.id, item: e.item, vaultId: e.vaultId, revision: e.revision, enc: e.enc,
                                                  deletedAt: max(1, c.createdAt / 1000), rolledBack: e.rolledBack) }
                e.pending = mark
                place(&out, e)
            }
        }
        out.entries.sort { $0.item.name.localizedCaseInsensitiveCompare($1.item.name) == .orderedAscending }
        out.trash.sort { ($0.deletedAt ?? 0) > ($1.deletedAt ?? 0) }
        return out
    }

    private static func place(_ v: inout VaultData, _ e: Entry) {
        v.entries.removeAll { $0.id == e.id }
        v.trash.removeAll { $0.id == e.id }
        if e.deletedAt == nil { v.entries.append(e) } else { v.trash.append(e) }
    }

    /// The list ordered for sending: oldest first.
    public static func sendOrder(_ list: [OfflineChange]) -> [OfflineChange] {
        list.enumerated().sorted { a, b in
            a.element.createdAt != b.element.createdAt ? a.element.createdAt < b.element.createdAt : a.offset < b.offset
        }.map(\.element)
    }
}
