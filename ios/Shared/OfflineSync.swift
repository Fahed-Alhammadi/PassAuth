import Foundation
import PassAuthCore

// Offline changes (docs/ARCHITECTURE.md "Offline changes"): the list of one account, kept sealed
// with its account key in the shared container (`SecureStore.updateOfflineChanges`, under the
// cross-process lock), and its sender. The iOS AutoFill extension only adds to the list; the app
// sends it. The rules themselves are in `OfflineChanges.swift`.

extension VaultRepository {
    /// The app already knows the server can't be reached: the copy is shown offline because a
    /// request got no answer (not because the server is one this app refuses), or the OS says
    /// there is no network.
    var knownOffline: Bool {
        guard queuesOffline, let v = served else { return false }
        if networkAvailable == false { return true }
        return v.offline && serverProblem == nil
    }

    /// How many changes wait for account `id` (the active one by default), also while locked.
    public func offlineCount(_ id: String? = nil) -> Int {
        store.get().file.accounts[id ?? activeId]?.offlineChanges ?? 0
    }

    /// The changes that need the user's decision.
    public var offlineConflicts: [OfflineChange] { offlineChanges.filter { $0.state == .conflict } }

    // MARK: The list

    /// Read the account's list into `offlineChanges` (the active account). A list that can't be
    /// read now keeps what is shown. One that can't be opened (a newer version's list, a damaged
    /// file) is left as it is: `offlineUnreadable` says so, and `mutateOffline` refuses to write
    /// over it (in this process and in the AutoFill extension), so no waiting change is wiped.
    func loadOfflineChanges(_ id: String, _ session: Session) {
        guard queuesOffline else { return }
        let list: [OfflineChange]
        switch store.readOfflineChanges(id) {
        case .missing: list = []
        case .unreadable: return
        case .sealed(let sealed):
            guard let opened = try? session.account.openOfflineChanges(sealed: sealed),
                  let decoded = try? OfflineChangeList.decode(opened) else {
                if id == activeId {
                    offlineUnreadable = true
                    if !offlineChanges.isEmpty { offlineChanges = [] }
                }
                return
            }
            list = decoded.changes
        }
        if id == activeId, offlineUnreadable { offlineUnreadable = false }
        if store.get().file.accounts[id]?.offlineChanges ?? 0 != list.count {
            store.updateAccount(id) { $0.offlineChanges = list.isEmpty ? nil : list.count }
        }
        if id == activeId, list != offlineChanges { offlineChanges = list }
    }

    /// Change account `id`'s list under the cross-process lock (re-read first: the other process
    /// may have added to it). Throws when it can't be read or written now, and when the stored
    /// list can't be opened (it is never written over then: that would wipe its changes).
    func mutateOffline(_ id: String, _ change: ([OfflineChange]) throws -> [OfflineChange]) throws {
        guard let session = sessions[id] else { throw UserError("Your vault is locked.") }
        let account = session.account
        var result: [OfflineChange] = []
        var unreadable = false
        defer { if unreadable, id == activeId { offlineUnreadable = true } }
        try store.updateOfflineChanges(id) { sealed in
            var list = OfflineChangeList()
            if let sealed {
                guard let opened = try? account.openOfflineChanges(sealed: sealed), let decoded = try? OfflineChangeList.decode(opened) else {
                    unreadable = true
                    throw UserError(OfflineText.cantOpen)
                }
                list = decoded
            }
            list.changes = try change(list.changes)
            result = list.changes
            if list.changes.isEmpty { return nil }
            return try account.sealOfflineChanges(json: list.encoded())
        }
        store.updateAccount(id) { $0.offlineChanges = result.isEmpty ? nil : result.count }
        if id == activeId { offlineChanges = result }
    }

    func removeOfflineChange(_ id: String, _ changeId: String) throws {
        try mutateOffline(id) { $0.filter { $0.id != changeId } }
    }

    private func setOffline(_ id: String, _ changeId: String, _ state: OfflineState, _ reason: String?) throws {
        guard offlineChanges.first(where: { $0.id == changeId }).map({ $0.state != state || $0.reason != reason }) ?? true else { return }
        try mutateOffline(id) { list in
            list.map { c in
                guard c.id == changeId else { return c }
                var n = c
                n.state = state
                n.reason = reason
                return n
            }
        }
    }

    /// The change `c` as stored now (the AutoFill extension may have merged a newer save into it
    /// since `c` was read) gets `body`; false: it isn't in the list any more.
    private func markSent(_ id: String, _ c: OfflineChange, _ body: OfflineSent?) throws -> Bool {
        var found = false
        try mutateOffline(id) { list in
            list.map { stored in
                guard stored.id == c.id else { return stored }
                found = true
                var n = stored
                n.sent = body
                return n
            }
        }
        return found
    }

    /// `c` (as it was sent) is on the server: it leaves the list only while it is still that
    /// change. One the AutoFill extension merged into meanwhile stays (with `sent` of the attempt
    /// that landed), so the next pass sends the newer save as an edit at the row's revision.
    private func finishSent(_ id: String, _ c: OfflineChange) throws {
        var kept = false
        try mutateOffline(id) { list in
            list.filter { stored in
                guard stored.id == c.id else { return true }
                kept = stored.item != c.item || stored.kind != c.kind
                return kept
            }
        }
        if kept { sendAgain = true }
    }

    private func addOffline(_ change: OfflineChange) throws {
        do {
            try mutateOffline(activeId) { try OfflineQueue.merge($0, change) }
        } catch let e as OfflineQueue.MergeError {
            throw UserError(e.text)
        }
    }

    private var nowMs: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: Saves that wait

    /// A new item into the list (create). `id`: the editor's id across its retries.
    func queueCreate(_ item: Item, vaultId: String?, id requested: String?) async throws -> String {
        guard let v = served else { throw UserError("Your vault is locked.") }
        if requiresSignedSharing, ServerSupport.refused(features: store.get().file.accounts[activeId]?.features) {
            throw UserError(ServerSupport.updateServer)
        }
        guard let target = vaultId.flatMap({ want in v.vaults.first { $0.id == want } }) ?? v.defaultVault else {
            throw UserError("Your own vault isn't available. Choose a vault to save to.")
        }
        if target.role == .read { throw UserError("You can't add items to \(target.name).") }
        let id: String
        if let requested { id = requested } else { id = try await core { try newId() } }
        var next = item
        next.createdAt = now
        next.updatedAt = now
        let attempt = lastAttempt.flatMap { $0.itemId == id ? $0.sent : nil }
        try addOffline(OfflineChange(kind: .create, vaultId: target.id, itemId: id, item: try JSON.parse(ItemCodec.encode(next)),
                                     sent: attempt, createdAt: nowMs))
        return id
    }

    /// An edit of `entry` (as shown) into the list.
    func queueEdit(_ entry: Entry, _ item: Item) async throws {
        guard let v = served else { throw UserError("Your vault is locked.") }
        if entry.pending?.kind == .trash || (entry.deletedAt != nil && entry.pending == nil) { throw UserError(OfflineText.trashedOffline) }
        if let info = v.vaults.first(where: { $0.id == entry.vaultId }), info.role == .read {
            throw UserError("You can only view items in this vault.")
        }
        var next = item
        next.updatedAt = now
        let old = entry.item.login?.password ?? ""
        if next.login != nil, !old.isEmpty, old != next.login?.password, next.passwordHistory == entry.item.passwordHistory {
            next.passwordHistory = Array(([PasswordChange(password: old, changedAt: now)] + next.passwordHistory).prefix(20))
        }
        let attempt = lastAttempt.flatMap { $0.itemId == entry.id ? $0.sent : nil }
        let kind: OfflineKind = entry.pending?.kind == .create ? .create : .edit
        try addOffline(OfflineChange(kind: kind, vaultId: entry.vaultId, itemId: entry.id, baseRevision: kind == .create ? nil : entry.revision,
                                     item: try JSON.parse(ItemCodec.encode(next)), sent: attempt, createdAt: nowMs))
    }

    /// Moving `entry` (as shown) to the trash, into the list.
    func queueTrash(_ entry: Entry) throws {
        guard let v = served else { throw UserError("Your vault is locked.") }
        if entry.deletedAt != nil { return }
        if let info = v.vaults.first(where: { $0.id == entry.vaultId }), info.role == .read {
            throw UserError("You can only view items in this vault.")
        }
        try addOffline(OfflineChange(kind: .trash, vaultId: entry.vaultId, itemId: entry.id,
                                     baseRevision: entry.pending?.kind == .create ? nil : entry.revision, createdAt: nowMs))
    }

    /// AutoFill saves: sync first, but a server that can't be reached leaves the copy on the
    /// device to save into (the save waits in the list).
    func syncBeforeSave() async throws {
        do {
            try await sync()
        } catch where queuesOffline && OfflineQueue.waits(error) && served != nil {
            served?.offline = true
        }
    }

    // MARK: Item page and decision sheet

    /// "Discard this change": the item's waiting change is removed (nothing reaches the server).
    public func discardOfflineChange(_ itemId: String) async throws {
        try await lock.run {
            try mutateOffline(activeId) { $0.filter { $0.itemId != itemId } }
        }
    }

    /// The server's version of a change's item as the copy holds it (nil: none, or deleted).
    public func serverEntry(for change: OfflineChange) -> Entry? {
        served?.get(change.itemId)
    }

    /// The user's decision on a conflict. Every choice but "Keep the other" / "Discard mine"
    /// needs the server now; the change stays until the write went through.
    public func resolveOffline(_ changeId: String, _ choice: OfflineChoice) async throws {
        try await lock.run {
            let id = activeId
            guard let c = offlineChanges.first(where: { $0.id == changeId }) else { return }
            switch choice {
            case .keepOther, .discardMine:
                try removeOfflineChange(id, c.id)
                return
            default: break
            }
            if knownOffline { throw UserError(OfflineText.needsConnection) }
            switch choice {
            case .keepMine:
                guard let entry = served?.get(c.itemId), let item = c.decodedItem else { throw UserError(OfflineText.deletedText) }
                try await updateLocked(entry, item, targetVaultId: nil)
            case .keepBoth:
                guard let item = c.decodedItem else { throw UserError(OfflineText.unreadable) }
                try await createLocked(OfflineQueue.copyItem(item), vaultId: c.vaultId, id: nil)
            case .saveAsNew:
                guard var item = c.decodedItem else { throw UserError(OfflineText.unreadable) }
                item.rev = 0
                try await createLocked(item, vaultId: c.vaultId, id: nil)
            case .trashAnyway:
                guard let entry = served?.get(c.itemId) else { break }
                try await changeState(entry, .trash)
            case .keepOther, .discardMine:
                break
            }
            try removeOfflineChange(id, c.id)
        }
    }

    // MARK: Sending

    /// A change waits while the server can be reached (a merge into an item's waiting change,
    /// or the AutoFill extension added some): sync, whose checks come before the sender runs.
    func syncForOfflineChanges() {
        guard queuesOffline, isApp, !knownOffline else { return }
        Task { @MainActor [weak self] in try? await self?.sync() }
    }

    /// Send the waiting changes soon (not from inside the repository's lock). Only after a sync
    /// from the server whose checks ran: never into a vault this sync didn't check.
    func scheduleOfflineSend() {
        guard queuesOffline, isApp else { return }
        Task { @MainActor [weak self] in await self?.sendOfflineChanges() }
    }

    /// Send the active account's list: the app only, while unlocked, one sender at a time,
    /// oldest first, stopping at the first request without an answer.
    public func sendOfflineChanges() async {
        guard queuesOffline, isApp else { return }
        if sendingOffline {
            sendAgain = true
            return
        }
        sendingOffline = true
        defer { sendingOffline = false }
        var passes = 0
        repeat {
            sendAgain = false
            passes += 1
            let id = activeId
            guard let session = sessions[id] else { return }
            // The AutoFill extension may have added to the list meanwhile.
            loadOfflineChanges(id, session)
            if offlineUnreadable { return }
            for c in OfflineQueue.sendOrder(offlineChanges) where c.state != .conflict {
                let go = await lock.run { await sendOne(c.id, id, session) }
                if !go { return }
            }
        } while sendAgain && passes < 5
    }

    /// One change; false: stop sending for now.
    private func sendOne(_ changeId: String, _ id: String, _ session: Session) async -> Bool {
        var tries = 0
        var renamed = false
        while true {
            guard sessions[id] === session, activeId == id, let v = served, !v.offline, !knownOffline, serverProblem == nil,
                  let snap = copyOf(id) else { return false }
            guard let c = offlineChanges.first(where: { $0.id == changeId }), c.state != .conflict else { return true }
            let raw = snap.items.first { $0.id == c.itemId }
            // The vault the request goes to: the one the server's row is in now (another device
            // may have moved the item), else the change's own.
            let hold = OfflineQueue.holdReason(vaultId: raw?.vaultId ?? c.vaultId, vaults: v.vaults, refused: v.refused)
            let row = raw.map { OfflineServerRow(revision: $0.revision ?? 0, data: $0.data, trashed: $0.deletedAt != nil) }
            var sentMatches = true
            if let raw, let sent = c.sent, raw.data == sent.data, let mine = c.decodedItem, let theirs = v.get(c.itemId)?.item {
                sentMatches = OfflineQueue.sameContent(mine, theirs)
            }
            do {
                switch OfflineQueue.decide(c, row: row, hold: hold, sentMatches: sentMatches) {
                case .done:
                    try finishSent(id, c)
                case .hold(let reason):
                    try setOffline(id, c.id, .held, reason)
                case .conflict(let kind):
                    try setOffline(id, c.id, .conflict, OfflineQueue.conflictReason(kind))
                case .newId:
                    guard !renamed else {
                        try setOffline(id, c.id, .held, OfflineText.idTaken)
                        return true
                    }
                    renamed = true
                    let fresh = try await core { try newId() }
                    // On the change as stored now (a merge from the AutoFill extension is kept).
                    try mutateOffline(id) { list in
                        list.map { stored in
                            guard stored.id == c.id else { return stored }
                            var n = stored
                            n.itemId = fresh
                            n.sent = nil
                            return n
                        }
                    }
                    continue
                case .post:
                    try await sendCreate(c, id)
                case .edit(let revision):
                    try await sendEdit(c, id, revision: revision)
                case .trash(let revision):
                    try await sendTrash(c, id, revision: revision)
                }
                return true
            } catch {
                tries += 1
                switch OfflineQueue.afterError(error, tries: tries) {
                case .stop:
                    if sessions[id] === session, activeId == id { served?.offline = true }
                    return false
                case .redecide, .retry:
                    do {
                        try await syncLocked()
                    } catch {
                        if OfflineQueue.waits(error) { return false }
                        try? setOffline(id, changeId, .held, errorMessage(error))
                        return true
                    }
                    continue
                case .conflict:
                    try? setOffline(id, changeId, .conflict, OfflineText.changedText)
                    return true
                case .hold(let reason):
                    try? setOffline(id, changeId, .held, reason)
                    return true
                }
            }
        }
    }

    /// The vault key, epoch and item of a change, for its request.
    private func sendParts(_ c: OfflineChange, vault vid: String) throws -> (key: VaultKey, epoch: Int64?, item: Item) {
        guard let info = served?.vaults.first(where: { $0.id == vid }), let key = vaultKeys[vid] else { throw UserError(OfflineText.goneVault) }
        guard let item = c.decodedItem else { throw UserError(OfflineText.unreadable) }
        return (key, info.keyEpoch, item)
    }

    /// create: encrypt now with the vault's current key; `sent` is saved before the request.
    private func sendCreate(_ change: OfflineChange, _ id: String) async throws {
        _ = try requireVault()
        var c = change
        let vid = c.vaultId, itemId = c.itemId
        let p = try sendParts(c, vault: vid)
        let json = ItemCodec.encode(p.item)
        let key = p.key
        let enc = try await core { try key.encryptItem(itemJson: json, id: itemId, vaultId: vid) }
        let manifest = try await nextManifest(vid, removed: [], added: [SyncItem(id: itemId, vaultId: vid, itemKey: nil, data: enc.data)])
        c.sent = OfflineSent(key: enc.key, data: enc.data, keyEpoch: p.epoch)
        guard try markSent(id, c, c.sent) else { return }
        let answer = try await api.call(id, "/items", body: Self.body(enc, keyEpoch: p.epoch, manifests: [manifest]))
        try finishSent(id, c)
        let local = Self.number(answer["revision"]).map { rev in
            LocalChange.put(SyncItem(id: itemId, vaultId: vid, itemKey: enc.key, data: enc.data, revision: rev,
                                     createdAt: p.item.createdAt, updatedAt: p.item.updatedAt))
        }
        await afterWrite(vid, answer, local, sent: manifest)
    }

    /// edit: `updateItem(current row, item)`, so `rev` counts up from the stored one.
    private func sendEdit(_ change: OfflineChange, _ id: String, revision: Int64) async throws {
        _ = try requireVault()
        var c = change
        guard let entry = served?.get(c.itemId) else { throw UserError(OfflineText.deletedText) }
        let vid = entry.vaultId
        let p = try sendParts(c, vault: vid)
        let json = ItemCodec.encode(p.item)
        let key = p.key, base = entry.enc
        let enc = try await core { try key.updateItem(encrypted: base, itemJson: json) }
        let before = copyRows([entry.id], in: vid)
        let after = SyncItem(id: entry.id, vaultId: vid, itemKey: nil, data: enc.data, deletedAt: entry.deletedAt)
        let manifest = try await nextManifest(vid, removed: before, added: [after])
        c.sent = OfflineSent(key: enc.key, data: enc.data, keyEpoch: p.epoch)
        guard try markSent(id, c, c.sent) else { return }
        let answer = try await api.call(id, "/items/\(entry.id)",
                                        body: Self.body(enc, keyEpoch: p.epoch, revision: revision, manifests: [manifest]), method: "PUT")
        try finishSent(id, c)
        let deletedAt = entry.deletedAt
        let local = Self.number(answer["revision"]).map { rev in
            LocalChange.put(SyncItem(id: entry.id, vaultId: vid, itemKey: enc.key, data: enc.data, revision: rev, deletedAt: deletedAt,
                                     updatedAt: p.item.updatedAt))
        }
        await afterWrite(vid, answer, local, sent: manifest)
    }

    /// trash: the trash request with the vault's next manifest.
    private func sendTrash(_ c: OfflineChange, _ id: String, revision: Int64) async throws {
        _ = try requireVault()
        guard let entry = served?.get(c.itemId) else {
            try finishSent(id, c)
            return
        }
        let vid = entry.vaultId
        let before = copyRows([entry.id], in: vid)
        var added: [SyncItem] = []
        if var row = before.first {
            row.deletedAt = now
            added = [row]
        }
        let manifest = try await nextManifest(vid, removed: before, added: added)
        var path = "/items/\(entry.id)"
        if let manifest { path += "?revision=\(revision)&" + manifest.query }
        let answer = try await api.call(id, path, method: "DELETE")
        try finishSent(id, c)
        let summary = trashSummary, at = now, itemId = entry.id
        let local = Self.number(answer["revision"]).map { LocalChange.trash(id: itemId, at: at, revision: $0, summary: summary) }
        await afterWrite(vid, answer, local, sent: manifest)
    }
}
