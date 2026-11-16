import Foundation
import PassAuthKit
import XCTest

/// Delta sync's pure parts (`Shared/DeltaSync.swift`): merging answers into the copy, applying
/// this device's own writes, the decisions on numbers, the request paths and the sync queue.
/// Shared by the iOS tests and the macOS AutoFill tests.
final class DeltaSyncTests: XCTestCase {
    private let bundle: JSON = ["account_id": "acc", "secret_key_enabled": false]

    private func vault(_ id: String, seq: Int64?, epoch: Int64? = 0, wrapped: String? = nil, meta: String = "m") -> SyncVault {
        SyncVault(id: id, meta: meta, role: "owner", wrappedKey: wrapped ?? "w-\(id)", keyKind: "account", keyEpoch: epoch, seq: seq)
    }

    private func item(_ id: String, _ vault: String, _ data: String = "d", revision: Int64 = 1, deletedAt: Int64? = nil) -> SyncItem {
        SyncItem(id: id, vaultId: vault, itemKey: "k-\(id)", data: "\(data)-\(id)", revision: revision, deletedAt: deletedAt)
    }

    private func snapshot(_ vaults: [SyncVault], _ items: [SyncItem], revision: Int64 = 10, cursor: String? = "c1") -> SyncSnapshot {
        SyncSnapshot(revision: revision, cursor: cursor, user: ["name": "Alex"], bundle: bundle, vaults: vaults, items: items)
    }

    private func answer(_ json: String) throws -> SyncResponse {
        try JSONDecoder().decode(SyncResponse.self, from: Data(json.utf8))
    }

    private func ids(_ s: SyncSnapshot) -> [String] { s.items.map { "\($0.vaultId)/\($0.id)" }.sorted() }

    private let bundleJSON = #""bundle":{"account_id":"acc","secret_key_enabled":false},"user":{"name":"Alex"}"#

    // MARK: Merge

    func testFullAnswerReplacesTheCopy() throws {
        let base = snapshot([vault("A", seq: 3)], [item("1", "A"), item("2", "A")])
        let full = try answer(#"{"revision":12,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"B","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account","key_epoch":0,"seq":1}],"items":[{"id":"9","vault_id":"B","item_key":"k","data":"d","revision":4,"deleted_at":null}]}"#)
        let next = try XCTUnwrap(SyncMerge.apply(full, to: base))
        XCTAssertEqual(next.revision, 12)
        XCTAssertEqual(next.cursor, "c2")
        XCTAssertEqual(ids(next), ["B/9"])
        XCTAssertEqual(next.position, SyncPosition(revision: 12, vaults: ["B": 1]))
    }

    func testDeletedFirstThenUpsertedById() throws {
        let base = snapshot([vault("A", seq: 3)], [item("1", "A"), item("2", "A"), item("3", "A")])
        // 1 deleted for good, 2 changed, 4 new; 3 untouched.
        let delta = try answer(#"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A","key_kind":"account","key_epoch":0,"seq":6}],"items":[{"id":"2","vault_id":"A","item_key":"k","data":"new","revision":5},{"id":"4","vault_id":"A","item_key":"k","data":"d4","revision":6}],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}"#)
        let next = try XCTUnwrap(SyncMerge.apply(delta, to: base))
        XCTAssertEqual(ids(next), ["A/2", "A/3", "A/4"])
        XCTAssertEqual(next.items.first { $0.id == "2" }?.data, "new")
        XCTAssertEqual(next.items.first { $0.id == "3" }?.data, "d-3", "untouched rows are kept")
        XCTAssertEqual(next.cursor, "c2")
        XCTAssertEqual(next.revision, 11)
        XCTAssertEqual(next.vaults.first?.seq, 6)
    }

    func testItemMovedBetweenTwoReadableVaults() throws {
        let base = snapshot([vault("A", seq: 3), vault("B", seq: 7)], [item("1", "A"), item("2", "B")])
        // 1 moved A → B: a tombstone in A and the row in B, in the same answer.
        let delta = try answer(#"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A","key_kind":"account","key_epoch":0,"seq":4},{"id":"B","meta":"m","role":"owner","wrapped_key":"w-B","key_kind":"account","key_epoch":0,"seq":8}],"items":[{"id":"1","vault_id":"B","item_key":"kB","data":"dB","revision":9}],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}"#)
        let next = try XCTUnwrap(SyncMerge.apply(delta, to: base))
        XCTAssertEqual(ids(next), ["B/1", "B/2"])
        XCTAssertEqual(next.items.filter { $0.id == "1" }.count, 1)
        // A tombstone only removes the row from the vault it names: an item already in B stays.
        let stale = try answer(#"{"delta":true,"revision":12,"cursor":"c3",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A","key_kind":"account","key_epoch":0,"seq":4},{"id":"B","meta":"m","role":"owner","wrapped_key":"w-B","key_kind":"account","key_epoch":0,"seq":8}],"items":[],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}"#)
        XCTAssertEqual(ids(try XCTUnwrap(SyncMerge.apply(stale, to: next))), ["B/1", "B/2"])
    }

    func testResetVaultIsReplacedWhole() throws {
        let base = snapshot([vault("A", seq: 3), vault("B", seq: 7)], [item("1", "A"), item("2", "A"), item("3", "B")])
        // The key of A was replaced: every item of A comes again (re-encrypted); 2 is gone from A.
        let delta = try answer(#"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A2","key_kind":"account","key_epoch":1,"seq":9},{"id":"B","meta":"m","role":"owner","wrapped_key":"w-B","key_kind":"account","key_epoch":0,"seq":7}],"items":[{"id":"1","vault_id":"A","item_key":"k2","data":"d2","revision":9}],"deleted":[],"reset":["A"]}"#)
        let next = try XCTUnwrap(SyncMerge.apply(delta, to: base))
        XCTAssertEqual(ids(next), ["A/1", "B/3"])
        XCTAssertEqual(next.items.first { $0.id == "1" }?.itemKey, "k2")
        let a = try XCTUnwrap(next.vaults.first { $0.id == "A" })
        XCTAssertEqual(a.keyEpoch, 1)
        XCTAssertFalse(a.sameKey(as: base.vaults[0]), "a changed header opens the vault key again")
        XCTAssertTrue(next.vaults[1].sameKey(as: base.vaults[1]))
    }

    func testVaultLostTakesItsItems() throws {
        let base = snapshot([vault("A", seq: 3), vault("S", seq: 5)], [item("1", "A"), item("2", "S"), item("3", "S")])
        // Removed from the shared vault S: it is missing from `vaults`.
        let delta = try answer(#"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A","key_kind":"account","key_epoch":0,"seq":3}],"items":[],"deleted":[],"reset":[]}"#)
        let next = try XCTUnwrap(SyncMerge.apply(delta, to: base))
        XCTAssertEqual(ids(next), ["A/1"])
        XCTAssertEqual(next.vaults.map(\.id), ["A"])
    }

    func testDeltaNeedsTheCopyItWasAskedFor() throws {
        let delta = try answer(#"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[],"items":[],"deleted":[],"reset":[]}"#)
        XCTAssertNil(SyncMerge.apply(delta, to: nil))
    }

    func testInvalidAnswersAreRefused() throws {
        let base = snapshot([vault("A", seq: 3)], [item("1", "A")])
        for bad in [
            #"{"revision":"7",\#(bundleJSON),"vaults":[],"items":[]}"#,
            #"{\#(bundleJSON),"vaults":[],"items":[]}"#,
            #"{"revision":7,\#(bundleJSON),"items":[]}"#,
            #"{"revision":7,\#(bundleJSON),"vaults":[]}"#,
            // A live item without its key and data.
            #"{"revision":7,\#(bundleJSON),"vaults":[],"items":[{"id":"1","vault_id":"A"}]}"#,
        ] {
            let r = try? answer(bad)
            XCTAssertNil(r.flatMap { SyncMerge.apply($0, to: base) }, bad)
        }
        // A trashed item without them is a `trash=summary` row.
        let summary = try answer(#"{"revision":7,\#(bundleJSON),"vaults":[],"items":[{"id":"1","vault_id":"A","revision":3,"deleted_at":1700000000}]}"#)
        XCTAssertNotNil(SyncMerge.apply(summary, to: nil))
    }

    func testCopyRoundTripsAndReadsOlderCopies() throws {
        let s = snapshot([vault("A", seq: 3)], [item("1", "A", deletedAt: 1_700_000_000), SyncItem(id: "2", vaultId: "A", itemKey: nil, data: nil, revision: 2, deletedAt: 5)])
        XCTAssertEqual(SyncSnapshot.decode(try s.encoded()), s)
        // A copy stored before delta sync (a plain `/sync` answer): no cursor, no numbers.
        let old = Data(#"{"revision":4,\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account"}],"items":[{"id":"1","vault_id":"A","item_key":"k","data":"d","revision":1,"deleted_at":null}]}"#.utf8)
        let copy = try XCTUnwrap(SyncSnapshot.decode(old))
        XCTAssertNil(copy.cursor)
        XCTAssertEqual(copy.position, SyncPosition(revision: 4, vaults: nil))
        XCTAssertNil(SyncSnapshot.decode(Data("garbage".utf8)))
        XCTAssertFalse(String(decoding: try s.encoded(), as: UTF8.self).contains(#"\/"#), "slashes unescaped")
    }

    // MARK: Local changes

    func testOwnWritesApplyToTheCopy() throws {
        let base = snapshot([vault("A", seq: 3)], [item("1", "A"), item("2", "A")])
        let put = try XCTUnwrap(SyncMerge.applyLocal(.put(SyncItem(id: "1", vaultId: "A", itemKey: "k9", data: "d9", revision: 9)), vaultId: "A", vaultSeq: 4, to: base))
        XCTAssertEqual(put.items.first { $0.id == "1" }?.data, "d9")
        XCTAssertEqual(put.vaults[0].seq, 4)
        XCTAssertEqual(put.cursor, "c1", "the cursor stays: the next delta brings the row again")
        XCTAssertEqual(put.revision, 10)
        let created = try XCTUnwrap(SyncMerge.applyLocal(.put(SyncItem(id: "3", vaultId: "A", itemKey: "k", data: "d", revision: 1)), vaultId: "A", vaultSeq: 5, to: put))
        XCTAssertEqual(ids(created), ["A/1", "A/2", "A/3"])

        let trashed = try XCTUnwrap(SyncMerge.applyLocal(.trash(id: "2", at: 1_700_000_000, revision: 11, summary: false), vaultId: "A", vaultSeq: 6, to: created))
        XCTAssertEqual(trashed.items.first { $0.id == "2" }?.deletedAt, 1_700_000_000)
        XCTAssertNotNil(trashed.items.first { $0.id == "2" }?.data)
        let summary = try XCTUnwrap(SyncMerge.applyLocal(.trash(id: "2", at: 1, revision: 11, summary: true), vaultId: "A", vaultSeq: 6, to: created))
        XCTAssertNil(summary.items.first { $0.id == "2" }?.data, "trash=summary keeps no data for trashed items")
        // Restoring needs the data: a summary row can't be restored locally.
        XCTAssertNil(SyncMerge.applyLocal(.restore(id: "2", revision: 12), vaultId: "A", vaultSeq: 7, to: summary))
        let restored = try XCTUnwrap(SyncMerge.applyLocal(.restore(id: "2", revision: 12), vaultId: "A", vaultSeq: 7, to: trashed))
        XCTAssertNil(restored.items.first { $0.id == "2" }?.deletedAt)
        let purged = try XCTUnwrap(SyncMerge.applyLocal(.purge(id: "2"), vaultId: "A", vaultSeq: 8, to: restored))
        XCTAssertEqual(ids(purged), ["A/1", "A/3"])
        XCTAssertEqual(purged.vaults[0].seq, 8)
        // Not in the copy: sync instead.
        XCTAssertNil(SyncMerge.applyLocal(.purge(id: "zz"), vaultId: "A", vaultSeq: 9, to: purged))
        XCTAssertNil(SyncMerge.applyLocal(.put(item("4", "X")), vaultId: "X", vaultSeq: 1, to: purged))
    }

    // MARK: Decisions

    func testAfterWrite() {
        XCTAssertEqual(SyncDecision.afterWrite(known: 4, vaultSeq: 5), .applyLocally)
        XCTAssertEqual(SyncDecision.afterWrite(known: 4, vaultSeq: 7), .sync, "someone else wrote too")
        XCTAssertEqual(SyncDecision.afterWrite(known: 5, vaultSeq: 5), .nothing, "a retried create the copy already has")
        XCTAssertEqual(SyncDecision.afterWrite(known: 7, vaultSeq: 5), .sync, "numbers gone backwards: a restored server")
        XCTAssertEqual(SyncDecision.afterWrite(known: nil, vaultSeq: 5), .sync)
        XCTAssertEqual(SyncDecision.afterWrite(known: 4, vaultSeq: nil), .sync, "older server")
    }

    func testRevisionPoll() {
        let have = SyncPosition(revision: 10, vaults: ["A": 3, "B": 7])
        XCTAssertFalse(SyncDecision.isStale(revision: 10, vaults: ["A": 3, "B": 7], have: have))
        XCTAssertTrue(SyncDecision.isStale(revision: 11, vaults: ["A": 3, "B": 7], have: have), "profile or bundle change")
        XCTAssertTrue(SyncDecision.isStale(revision: 10, vaults: ["A": 4, "B": 7], have: have))
        XCTAssertTrue(SyncDecision.isStale(revision: 10, vaults: ["A": 3, "B": 7, "C": 1], have: have), "a vault shared with the account")
        XCTAssertTrue(SyncDecision.isStale(revision: 10, vaults: ["A": 3], have: have), "a vault gone")
        XCTAssertTrue(SyncDecision.isStale(revision: 10, vaults: ["A": 2, "B": 7], have: have), "a restored server")
        // Older server or copy without numbers: a newer revision only, as before.
        XCTAssertTrue(SyncDecision.isStale(revision: 11, vaults: nil, have: have))
        XCTAssertFalse(SyncDecision.isStale(revision: 10, vaults: nil, have: have))
        XCTAssertFalse(SyncDecision.isStale(revision: 9, vaults: nil, have: have))
        XCTAssertFalse(SyncDecision.isStale(revision: 10, vaults: ["A": 3], have: SyncPosition(revision: 10, vaults: nil)))
    }

    func testLiveMessages() {
        let have = SyncPosition(revision: 10, vaults: ["A": 3, "B": 7])
        XCTAssertTrue(SyncDecision.onLiveSync(revision: 11, vaults: ["A": 4], have: have))
        XCTAssertFalse(SyncDecision.onLiveSync(revision: 11, vaults: ["A": 3], have: have), "this device's own write, already applied")
        XCTAssertFalse(SyncDecision.onLiveSync(revision: 12, vaults: ["A": 2, "B": 7], have: have), "out of order: older numbers")
        XCTAssertTrue(SyncDecision.onLiveSync(revision: 11, vaults: ["C": 1], have: have), "a vault the copy doesn't have")
        XCTAssertTrue(SyncDecision.onLiveSync(revision: 11, vaults: [:], have: have), "profile or account change")
        XCTAssertTrue(SyncDecision.onLiveSync(revision: 11, vaults: ["A": 3], have: SyncPosition(revision: 10, vaults: nil)), "copy without numbers")
        // Older servers send no vault numbers: a newer revision.
        XCTAssertTrue(SyncDecision.onLiveSync(revision: 11, vaults: nil, have: have))
        XCTAssertFalse(SyncDecision.onLiveSync(revision: 10, vaults: nil, have: have))
        XCTAssertFalse(SyncDecision.onLiveSync(revision: 11, vaults: ["A": 9], have: nil), "locked: nothing to refresh")

        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"hello","origin":"o-1"}"#), .hello(origin: "o-1"))
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"sync","revision":7,"vaults":{"A":3},"origin":"o-1"}"#), .sync(revision: 7, vaults: ["A": 3], origin: "o-1"))
        XCTAssertEqual(LiveSyncProtocol.parse(#"{"type":"sync","revision":8,"vaults":{}}"#), .sync(revision: 8, vaults: [:], origin: nil))
        // Whoever wrote: the numbers decide (a session's own other process shares its origin).
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 11, vaults: ["A": 4], origin: "mine"), have: have), .sync)
        XCTAssertEqual(LiveSyncProtocol.action(.sync(revision: 11, vaults: ["A": 3], origin: "other"), have: have), .ignore)
        XCTAssertEqual(LiveSyncProtocol.action(.hello(origin: "o"), have: have), .ignore)
    }

    func testPaths() {
        XCTAssertEqual(DeltaSync.path(since: nil, trashSummary: false), "/sync")
        XCTAssertEqual(DeltaSync.path(since: "AQgAbc-_9", trashSummary: false), "/sync?since=AQgAbc-_9")
        XCTAssertEqual(DeltaSync.path(since: "AQ", trashSummary: true), "/sync?since=AQ&trash=summary")
        XCTAssertEqual(DeltaSync.path(since: nil, trashSummary: true), "/sync?trash=summary")
        XCTAssertEqual(DeltaSync.path(since: "a&b=c", trashSummary: false), "/sync?since=a%26b%3Dc", "a cursor can't add parameters")
        XCTAssertEqual(DeltaSync.vaultNumbers(["A": 3, "B": .double(4)]), ["A": 3, "B": 4])
        XCTAssertNil(DeltaSync.vaultNumbers(nil))
    }

    // MARK: Fetch and cache refresh against a scripted server

    private final class FakeServer: @unchecked Sendable {
        private let lock = NSLock()
        private var answers: [String: [String]] = [:]
        private(set) var paths: [String] = []

        func answer(_ path: String, _ body: String) {
            lock.lock()
            answers[path, default: []].append(body)
            lock.unlock()
        }

        func get(_ path: String) throws -> Data {
            lock.lock()
            defer { lock.unlock() }
            paths.append(path)
            let key = path.components(separatedBy: "?").first ?? path
            guard var queue = answers[path] ?? answers[key], !queue.isEmpty else { throw UserError("offline") }
            let body = queue.removeFirst()
            if answers[path] != nil { answers[path] = queue } else { answers[key] = queue }
            return Data(body.utf8)
        }
    }

    func testFetchUsesTheCursorOnlyWithDeltaSync() async throws {
        let base = snapshot([vault("A", seq: 3)], [item("1", "A")])
        let server = FakeServer()
        server.answer("/sync", #"{"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[],"items":[]}"#)
        _ = try await DeltaSync.fetch(base: base, delta: false, trashSummary: false) { try server.get($0) }
        XCTAssertEqual(server.paths, ["/sync"], "no delta sync on this server: everything, as before")

        server.answer("/sync?since=c1&trash=summary", #"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A","key_kind":"account","key_epoch":0,"seq":4}],"items":[{"id":"2","vault_id":"A","item_key":"k","data":"d","revision":2}],"deleted":[],"reset":[]}"#)
        let next = try await DeltaSync.fetch(base: base, delta: true, trashSummary: true) { try server.get($0) }
        XCTAssertEqual(server.paths.last, "/sync?since=c1&trash=summary")
        XCTAssertEqual(ids(next), ["A/1", "A/2"])

        // An unreadable answer: an error, nothing to store (the caller keeps its copy and cursor).
        server.answer("/sync", "<html>proxy</html>")
        do {
            _ = try await DeltaSync.fetch(base: base, delta: true, trashSummary: false) { try server.get($0) }
            XCTFail("expected an error")
        } catch let e as UserError {
            XCTAssertEqual(e.message, "The server's answer couldn't be read.")
        }
    }

    func testCacheRefreshAsksForChangesOnly() async throws {
        let cached = snapshot([vault("A", seq: 3)], [item("1", "A")])
        let server = FakeServer()
        // Current: only the revision poll.
        server.answer("/sync/revision", #"{"revision":10,"vaults":{"A":3}}"#)
        let current = try await DeltaSync.refresh(cached: cached, delta: true, trashSummary: false) { try server.get($0) }
        XCTAssertEqual(current, .current)
        XCTAssertEqual(server.paths, ["/sync/revision"])

        // A vault moved on: the changes since the cursor, merged.
        server.answer("/sync/revision", #"{"revision":11,"vaults":{"A":4}}"#)
        server.answer("/sync", #"{"delta":true,"revision":11,"cursor":"c2",\#(bundleJSON),"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w-A","key_kind":"account","key_epoch":0,"seq":4}],"items":[{"id":"2","vault_id":"A","item_key":"k","data":"d","revision":2}],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}"#)
        guard case .write(let next) = try await DeltaSync.refresh(cached: cached, delta: true, trashSummary: false, get: { try server.get($0) }) else {
            return XCTFail("expected a write")
        }
        XCTAssertEqual(server.paths.suffix(2), ["/sync/revision", "/sync?since=c1"])
        XCTAssertEqual(ids(next), ["A/2"])
        XCTAssertEqual(next.cursor, "c2")

        // Without delta sync: the whole answer, never older than the copy.
        server.answer("/sync", #"{"revision":12,"cursor":"c3",\#(bundleJSON),"vaults":[],"items":[]}"#)
        guard case .write(let full) = try await DeltaSync.refresh(cached: cached, delta: false, trashSummary: false, get: { try server.get($0) }) else {
            return XCTFail("expected a write")
        }
        XCTAssertEqual(full.revision, 12)
        server.answer("/sync", #"{"revision":9,\#(bundleJSON),"vaults":[],"items":[]}"#)
        let older = try await DeltaSync.refresh(cached: cached, delta: false, trashSummary: false) { try server.get($0) }
        XCTAssertEqual(older, .keep, "never downgrade")
        // No copy yet: everything.
        server.answer("/sync", #"{"revision":1,\#(bundleJSON),"vaults":[],"items":[]}"#)
        guard case .write = try await DeltaSync.refresh(cached: nil, delta: true, trashSummary: false, get: { try server.get($0) }) else {
            return XCTFail("expected a write")
        }
        XCTAssertEqual(server.paths.last, "/sync")
    }

    // MARK: Sync queue

    @MainActor
    private final class Runs {
        var count = 0
        var gate: CheckedContinuation<Void, Never>?
    }

    @MainActor
    func testOneSyncRunsAndOneWaits() async throws {
        let queue = SyncQueue()
        let runs = Runs()
        let first = Task { @MainActor in
            try await queue.run {
                runs.count += 1
                await withCheckedContinuation { runs.gate = $0 }
            }
        }
        while runs.gate == nil { await Task.yield() }
        // Three requests while the first runs: one more sync, which all three wait for.
        let waiting = (0..<3).map { _ in Task { @MainActor in try await queue.run { runs.count += 1 } } }
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(runs.count, 1)
        runs.gate?.resume()
        try await first.value
        for t in waiting { try await t.value }
        XCTAssertEqual(runs.count, 2)
        // Idle again: the next request runs at once.
        try await queue.run { runs.count += 1 }
        XCTAssertEqual(runs.count, 3)
    }

    // MARK: Quotas

    func testStorageUsageAndQuotaMessage() {
        let u = AccountUsage(json: ["usage": ["item_count": 120, "storage_bytes": 1_258_291], "limits": ["max_items": 500, "max_storage_bytes": 52_428_800]])
        XCTAssertTrue(u.limited)
        XCTAssertEqual(u.itemsLine, "120 of 500 items")
        XCTAssertEqual(u.storageLine, "1.2 MB of 50 MB")
        XCTAssertEqual(u.itemsUsed ?? 0, 0.24, accuracy: 0.0001)
        XCTAssertFalse(u.full)
        let none = AccountUsage(json: ["usage": ["item_count": 3, "storage_bytes": 10], "limits": ["max_items": 0, "max_storage_bytes": 0]])
        XCTAssertFalse(none.limited, "no limit: nothing shown")
        XCTAssertFalse(AccountUsage(json: ["email": "a@example.com"]).limited, "older servers")
        let full = AccountUsage(json: ["usage": ["item_count": 10, "storage_bytes": 0], "limits": ["max_items": 10, "max_storage_bytes": 0]])
        XCTAssertTrue(full.full)
        XCTAssertNil(full.storageLine)
        XCTAssertEqual(AccountUsage.bytes(0), "0 bytes")
        XCTAssertEqual(AccountUsage.bytes(1536), "1.5 KB")
        XCTAssertEqual(AccountUsage.bytes(1_048_576), "1 MB")
        XCTAssertEqual(AccountUsage.bytes(10_485_760 * 3), "30 MB")
        XCTAssertEqual(AccountUsage.bytes(1_073_741_824 * 2), "2 GB")

        let quota = ApiError(status: 403, code: "quota_exceeded", message: "storage limit reached")
        XCTAssertEqual(errorMessage(quota), "You've reached this server's storage limit. Delete items or ask the server's admin.")
        XCTAssertEqual(errorMessage(quota), quotaExceededMessage)
    }
}
