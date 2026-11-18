import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// Vault manifests, the rules without a server (also run by the macOS AutoFill extension's
/// tests): what a write carries, the verdicts of a check and what they do to the device memory,
/// when a first manifest is started, a baseline's version, which trash is due, summary rows and
/// their `data_sha256` through the copy, and the refusal of servers without signed sharing.
final class VaultManifestTests: XCTestCase {
    private struct World {
        let account: Account
        let vaultId: String
        let key: VaultKey
        let wrapped: String
        var rows: [SyncItem]

        func header(seq: Int64, sealed: String?, prev: String? = nil, epoch: Int64 = 1, ok: Bool? = nil, vaultSeq: Int64? = 7, role: String = "owner") throws -> SyncVault {
            SyncVault(id: vaultId, meta: try key.encryptMeta(vaultId: vaultId, metaJson: #"{"name":"Personal"}"#), role: role, wrappedKey: wrapped,
                      keyEpoch: epoch, seq: vaultSeq, manifest: sealed, manifestSeq: seq, manifestPrev: prev, manifestOk: ok)
        }

        /// The vault row carrying manifest `w`.
        func header(_ w: ManifestWrite, epoch: Int64 = 1) throws -> SyncVault {
            try header(seq: Int64(w.seq), sealed: w.sealed, prev: w.prev, epoch: epoch)
        }

        /// A manifest of `version` over `rows` that replaces the one whose link is `prev` (nil: none).
        func start(_ version: UInt64, prev: String? = nil, epoch: UInt64 = 1, rows other: [SyncItem]? = nil) throws -> ManifestWrite {
            try key.manifestStart(vaultId: vaultId, keyEpoch: epoch, version: version, prev: prev, itemsJson: VaultManifest.rowsJson(other ?? rows))
        }

        /// The manifest after `w` when nothing changed in the vault (an edit that kept the data).
        func next(_ w: ManifestWrite) throws -> ManifestWrite {
            try key.manifestNext(vaultId: vaultId, keyEpoch: 1, manifestSeq: w.seq, prev: w.prev, sealed: w.sealed, removedJson: "[]", addedJson: "[]")
        }

        func snapshot(_ v: SyncVault, _ rows: [SyncItem]? = nil) -> SyncSnapshot {
            SyncSnapshot(revision: 5, cursor: "c", user: nil, bundle: nil, vaults: [v], items: rows ?? self.rows)
        }
    }

    private func world(live: Int = 2, trashed: Int = 1) throws -> World {
        let created = try createAccount(accountId: try newId(), password: "correct horse battery staple", withSecretKey: false)
        let vid = try newId()
        let made = try created.account.newVaultKeyBound(vaultId: vid, keyEpoch: 1)
        var rows: [SyncItem] = []
        for i in 0..<(live + trashed) {
            let id = try newId()
            let enc = try made.key.encryptItem(itemJson: ItemCodec.encode(Item(name: "Item \(i)")), id: id, vaultId: vid)
            rows.append(SyncItem(id: id, vaultId: vid, itemKey: enc.key, data: enc.data, revision: 3, deletedAt: i < live ? nil : 1_700_000_000 + Int64(i)))
        }
        return World(account: created.account, vaultId: vid, key: made.key, wrapped: made.wrapped, rows: rows)
    }

    private func summary(_ r: SyncItem) -> SyncItem {
        var s = r
        s.dataSha256 = r.data.map(VaultManifest.dataHash)
        s.data = nil
        s.itemKey = nil
        return s
    }

    private let zeroLink = String(repeating: "A", count: 43)
    private func mark(_ w: ManifestWrite) -> ManifestMark { ManifestMark(version: w.seq, link: w.link) }

    /// The entries of a vault's manifest log for these manifests, as the server sends them.
    private func log(_ writes: [ManifestWrite]) -> String {
        JSON.array(writes.map { w in
            ["seq": .int(Int64(w.seq)), "prev": .string(w.prev), "digest": .string(VaultManifest.dataHash(w.sealed))]
        }).text
    }

    // MARK: What a write carries

    func testAnEntryInABodyAndInAQuery() {
        let e = ManifestEntry(vaultId: "v1", seq: 8, prev: "PrEv-_1", sealed: "AbC-_9", link: "LiNk")
        XCTAssertEqual(e.json, ["vault_id": "v1", "seq": 8, "prev": "PrEv-_1", "sealed": "AbC-_9"], "the link is this device's own: never sent")
        XCTAssertEqual(e.query, "manifest_seq=8&manifest_prev=PrEv-_1&manifest=AbC-_9")
        XCTAssertEqual(ManifestEntry(vaultId: "v1", seq: 2, prev: "p&x=1", sealed: "a&b=c", link: "l").query,
                       "manifest_seq=2&manifest_prev=p%26x%3D1&manifest=a%26b%3Dc", "neither text can add parameters")
        XCTAssertEqual(e.mark, ManifestMark(version: 8, link: "LiNk"))
    }

    func testRowsAsTheCoreTakesThem() throws {
        let live = SyncItem(id: "i1", vaultId: "v", itemKey: "k", data: "DATA", deletedAt: nil)
        XCTAssertEqual(VaultManifest.row(live), ["id": "i1", "deleted_at": nil, "data": "DATA"])
        let trashed = SyncItem(id: "i2", vaultId: "v", itemKey: nil, data: nil, deletedAt: 9, dataSha256: "HASH")
        XCTAssertEqual(VaultManifest.row(trashed), ["id": "i2", "deleted_at": 9, "data_sha256": "HASH"])
        // Data wins over a hash; a row with neither says so by having neither.
        XCTAssertEqual(VaultManifest.row(SyncItem(id: "i3", vaultId: "v", itemKey: "k", data: "D", dataSha256: "H")), ["id": "i3", "deleted_at": nil, "data": "D"])
        XCTAssertEqual(VaultManifest.row(SyncItem(id: "i4", vaultId: "v", itemKey: nil, data: nil, deletedAt: 1)), ["id": "i4", "deleted_at": 1])
        // A newer row this device kept after an item rollback counts with what the server sent.
        var keptRow = live
        keptRow.servedSha256 = "SERVED"
        XCTAssertEqual(VaultManifest.row(keptRow), ["id": "i1", "deleted_at": nil, "data_sha256": "SERVED"])
        XCTAssertTrue(VaultManifest.complete([live, trashed]))
        XCTAssertFalse(VaultManifest.complete([live, SyncItem(id: "i4", vaultId: "v", itemKey: nil, data: nil, deletedAt: 1)]))
        // The hash is the server's `data_sha256`: base64url SHA-256 of the data text.
        XCTAssertEqual(VaultManifest.dataHash("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")
    }

    func testOnlyTheTwoManifestCodesAreRetried() {
        XCTAssertTrue(VaultManifest.retry(ApiError(status: 409, code: "manifest_conflict", message: "x")))
        // 400, not 409: decided by the code.
        XCTAssertTrue(VaultManifest.retry(ApiError(status: 400, code: "manifest_required", message: "Update PassAuth to change this vault.")))
        XCTAssertFalse(VaultManifest.retry(ApiError(status: 409, code: "revision_conflict", message: "x")))
        XCTAssertFalse(VaultManifest.retry(ApiError(status: 409, code: "manifest_not_ready", message: "x")))
        XCTAssertFalse(VaultManifest.retry(ApiError(status: 400, code: "bad_request", message: "manifest_conflict")))
        XCTAssertEqual(VaultManifest.attempts, 3)
    }

    // MARK: Verdicts

    func testVerdictsOfACheck() throws {
        let w = try world()
        let first = try w.start(1)
        let second = try w.next(first)
        let third = try w.next(second)
        XCTAssertEqual(first.prev, zeroLink, "a vault's first manifest replaces none")
        XCTAssertEqual(third.prev, second.link)
        let row = try w.header(third)
        func check(_ v: SyncVault, _ remembered: ManifestMark?, _ rows: [SyncItem], log: String? = nil) -> String {
            let c = VaultManifest.verify(v, key: w.key, remembered: remembered, log: log, rows: rows)
            return c.mark.map { "\(c.status.rawValue) \($0.version)" } ?? c.status.rawValue
        }
        XCTAssertEqual(check(row, nil, w.rows), "ok 3")
        XCTAssertEqual(VaultManifest.verify(row, key: w.key, remembered: nil, rows: w.rows).mark, mark(third), "the version and the link are what is remembered")
        XCTAssertEqual(check(row, mark(second), w.rows), "ok 3", "the next one after the remembered one")
        XCTAssertEqual(check(row, mark(third), w.rows.reversed()), "ok 3", "the same one; the order of the rows doesn't matter")
        // Trashed rows held without their data are checked by its hash.
        XCTAssertEqual(check(row, nil, w.rows.map { $0.deletedAt == nil ? $0 : summary($0) }), "ok 3")
        // An older manifest than this device saw, or none after one was seen.
        let fourth = try w.next(third)
        XCTAssertEqual(check(row, mark(fourth), w.rows), "rollback")
        XCTAssertEqual(check(try w.header(seq: 0, sealed: nil), mark(first), w.rows), "rollback")
        // No manifest, none seen: nothing to check (not even with a sealed text sent along).
        XCTAssertEqual(check(try w.header(seq: 0, sealed: nil), nil, w.rows), "none")
        XCTAssertEqual(check(try w.header(seq: 0, sealed: third.sealed, prev: third.prev), nil, w.rows), "none")
        XCTAssertEqual(check(SyncVault(id: w.vaultId), nil, w.rows), "none", "an older server's row")
        // Hidden, brought back, moved between live and trash, older data.
        XCTAssertEqual(check(row, nil, Array(w.rows.dropFirst())), "mismatch")
        var extra = w.rows
        extra.append(SyncItem(id: try newId(), vaultId: w.vaultId, itemKey: "k", data: "old", deletedAt: nil))
        XCTAssertEqual(check(row, mark(third), extra), "mismatch")
        var restored = w.rows
        restored[2].deletedAt = nil
        XCTAssertEqual(check(row, nil, restored), "mismatch")
        var older = w.rows
        older[0].data = (older[0].data ?? "") + "x"
        XCTAssertEqual(check(row, nil, older), "mismatch")
        // A manifest that doesn't open for this key, vault, epoch, version and predecessor.
        XCTAssertEqual(check(try w.header(seq: 3, sealed: nil, prev: third.prev), nil, w.rows), "mismatch")
        XCTAssertEqual(check(try w.header(seq: 3, sealed: third.sealed, prev: nil), nil, w.rows), "mismatch", "no predecessor named")
        XCTAssertEqual(check(try w.header(seq: 3, sealed: third.sealed, prev: first.link), nil, w.rows), "mismatch", "another predecessor")
        XCTAssertEqual(check(try w.header(seq: 4, sealed: third.sealed, prev: third.prev), nil, w.rows), "mismatch")
        XCTAssertEqual(check(try w.header(third, epoch: 2), nil, w.rows), "mismatch")
        XCTAssertEqual(check(try w.header(seq: 3, sealed: "garbage", prev: third.prev), nil, w.rows), "mismatch")
        // A row that can't be checked yet; an id twice is an error, which is a mismatch.
        var bare = w.rows
        bare[2].data = nil
        bare[2].itemKey = nil
        XCTAssertEqual(check(row, nil, bare), "incomplete")
        XCTAssertEqual(check(row, mark(second), w.rows + [w.rows[0]]), "mismatch")
    }

    /// The chain: a device that saw (or wrote) a version only accepts manifests built on it.
    func testAManifestMustFollowTheOneThisDeviceRemembers() throws {
        let w = try world()
        let first = try w.start(1)
        let second = try w.next(first)
        let third = try w.next(second)
        let fourth = try w.next(third)
        func check(_ m: ManifestWrite, _ remembered: ManifestMark?, log: String? = nil) throws -> ManifestStatus {
            VaultManifest.verify(try w.header(m), key: w.key, remembered: remembered, log: log, rows: w.rows).status
        }
        // Fork then join: another manifest at the version this device remembers (same items,
        // same key, another history).
        let forkSecond = try w.key.manifestNext(vaultId: w.vaultId, keyEpoch: 1, manifestSeq: first.seq, prev: first.prev, sealed: first.sealed,
                                                removedJson: "[]", addedJson: "[]")
        XCTAssertEqual(forkSecond.seq, 2)
        XCTAssertNotEqual(forkSecond.link, second.link, "sealed again: another manifest at the same version")
        XCTAssertEqual(try check(forkSecond, mark(second)), .mismatch, "the same version with another link")
        // A later manifest of the other history: one step ahead, but not on this device's. No
        // log can connect a manifest one version above the remembered one: a mismatch at once.
        let forkThird = try w.next(forkSecond)
        XCTAssertEqual(try check(forkThird, mark(second)), .mismatch)
        XCTAssertEqual(try check(forkThird, mark(second), log: log([forkSecond, forkThird])), .mismatch, "the log doesn't lead back to what this device saw")
        XCTAssertEqual(try check(third, mark(second)), .ok, "one step ahead on this device's history needs no log")
        // Two steps ahead on the other history: only then the log is asked for, and it doesn't connect.
        let forkFourth = try w.next(forkThird)
        XCTAssertEqual(try check(forkFourth, mark(second)), .needLog)
        XCTAssertEqual(try check(forkFourth, mark(second), log: log([forkSecond, forkThird, forkFourth])), .mismatch)
        // Entries that aren't entries are skipped, never fatal (the log goes to the core as it came).
        let rubbish = #"[null,7,"text",{"seq":3},{"seq":"4","prev":1,"digest":2},"# + String(log([second, third, fourth]).dropFirst())
        XCTAssertEqual(try check(fourth, mark(first), log: rubbish), .ok)
        XCTAssertEqual(try check(fourth, mark(first), log: #"{"entries":[]}"#), .mismatch, "a log that isn't a list")
        XCTAssertEqual(try check(forkThird, mark(second), log: "[]"), .mismatch)
        // More than one step ahead on this device's own history: the log connects it.
        XCTAssertEqual(try check(fourth, mark(first)), .needLog)
        XCTAssertEqual(try check(fourth, mark(first), log: log([second, third, fourth])), .ok)
        XCTAssertEqual(try check(fourth, mark(first), log: log([fourth, second, third, first])), .ok, "any order, extra entries ignored")
        XCTAssertEqual(try check(fourth, mark(first), log: log([third, fourth])), .mismatch, "a gap")
        XCTAssertEqual(VaultManifest.verify(try w.header(fourth), key: w.key, remembered: mark(first), log: log([second, third, fourth]), rows: w.rows).mark, mark(fourth))
        // Nothing remembered: first sight, no log needed.
        XCTAssertEqual(try check(fourth, nil), .ok)
        // Half a memory (or one that isn't a link) is nothing remembered, never passed to the core.
        XCTAssertEqual(try check(fourth, ManifestMark(version: 2, link: "short")), .ok)
        XCTAssertEqual(try check(fourth, ManifestMark(version: 0, link: second.link)), .ok)
    }

    /// "In the trash" is exactly `deleted_at != null`; a `deleted_at` that is no time (0, below
    /// 0) is an answer the core refuses: a mismatch, never a live item.
    func testADeletedAtThatIsNoTimeIsAMismatch() throws {
        let w = try world()
        let m = try w.start(3)
        let row = try w.header(m)
        XCTAssertEqual(VaultManifest.verify(row, key: w.key, remembered: nil, rows: w.rows).status, .ok)
        for bad: Int64 in [0, -1] {
            var rows = w.rows
            rows[2].deletedAt = bad
            XCTAssertEqual(VaultManifest.verify(row, key: w.key, remembered: nil, rows: rows).status, .mismatch, "deleted_at \(bad)")
            // And the app itself lists such a row in the trash, never among the live items.
            let o = VaultRepository.open(w.account, w.snapshot(row, rows), previous: nil)
            XCTAssertEqual(o.data.entries.count, 2)
            XCTAssertEqual(o.data.trash.map(\.id), [rows[2].id])
            XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        }
    }

    func testTheMemoryIsRaisedOnlyByAnOkCheckAndNeverLowered() {
        let l5 = String(repeating: "a", count: 43), l7 = String(repeating: "b", count: 43), l2 = String(repeating: "c", count: 43)
        let other = String(repeating: "d", count: 43)
        var m: [String: ManifestMark] = ["a": ManifestMark(version: 5, link: l5)]
        VaultManifest.remember(&m, vault: "a", status: .ok, mark: ManifestMark(version: 7, link: l7))
        VaultManifest.remember(&m, vault: "b", status: .ok, mark: ManifestMark(version: 2, link: l2))
        XCTAssertEqual(m, ["a": ManifestMark(version: 7, link: l7), "b": ManifestMark(version: 2, link: l2)])
        VaultManifest.remember(&m, vault: "a", status: .ok, mark: ManifestMark(version: 3, link: l5))
        XCTAssertEqual(m["a"]?.version, 7, "never lowered")
        VaultManifest.remember(&m, vault: "a", status: .ok, mark: ManifestMark(version: 7, link: other))
        XCTAssertEqual(m["a"]?.link, l7, "never another link at the same version")
        for s in [ManifestStatus.rollback, .mismatch, .incomplete, .none, .needLog, .unchecked] {
            VaultManifest.remember(&m, vault: "a", status: s, mark: ManifestMark(version: 99, link: other))
            VaultManifest.remember(&m, vault: "c", status: s, mark: ManifestMark(version: 99, link: other))
        }
        VaultManifest.remember(&m, vault: "c", status: .ok, mark: ManifestMark(version: 4, link: "not a link"))
        VaultManifest.remember(&m, vault: "c", status: .ok, mark: nil)
        XCTAssertEqual(m, ["a": ManifestMark(version: 7, link: l7), "b": ManifestMark(version: 2, link: l2)], "nothing is remembered unless the check was ok")
        // The app and an AutoFill extension both write it: the higher version per vault, the
        // stored link at the same version; vaults that are gone stay.
        let stored = ["a": ManifestMark(version: 7, link: l7), "gone": ManifestMark(version: 4, link: l5)]
        XCTAssertEqual(VaultManifest.merged(stored, ["a": ManifestMark(version: 6, link: l5), "b": ManifestMark(version: 9, link: l2)]),
                       ["a": ManifestMark(version: 7, link: l7), "b": ManifestMark(version: 9, link: l2), "gone": ManifestMark(version: 4, link: l5)])
        XCTAssertEqual(VaultManifest.merged(stored, ["a": ManifestMark(version: 7, link: other)])["a"]?.link, l7)
        XCTAssertEqual(VaultManifest.merged(stored, ["a": ManifestMark(version: 8, link: other)])["a"], ManifestMark(version: 8, link: other))
        XCTAssertEqual(VaultManifest.merged(stored, ["a": ManifestMark(version: 8, link: "half")])["a"]?.version, 7)
        // An acceptance ("Use the server's copy") replaces the entry, also downwards, and counts.
        // The count orders the merge first, so a process that still holds the memory from before
        // (a higher version) can't bring it back.
        let accepted = VaultManifest.replaced(stored["a"], with: ManifestMark(version: 3, link: l2))
        XCTAssertEqual(accepted, ManifestMark(version: 3, link: l2, accepts: 1))
        XCTAssertEqual(VaultManifest.merged(["a": accepted], ["a": ManifestMark(version: 7, link: l7)])["a"], accepted, "the stale higher version loses")
        XCTAssertEqual(VaultManifest.merged(["a": ManifestMark(version: 7, link: l7)], ["a": accepted])["a"], accepted)
        XCTAssertEqual(VaultManifest.merged(["a": accepted], ["a": ManifestMark(version: 4, link: l5, accepts: 1)])["a"], ManifestMark(version: 4, link: l5, accepts: 1),
                       "with as many acceptances the higher version wins, as before")
        XCTAssertEqual(VaultManifest.merged(["a": accepted], ["a": ManifestMark(version: 3, link: other, accepts: 1)])["a"], accepted, "never another link at the same version")
        // Forgetting (the server shows no manifest) keeps the count and nothing else.
        let forgotten = VaultManifest.replaced(accepted, with: nil)
        XCTAssertEqual(forgotten, ManifestMark.forgotten(accepts: 2))
        XCTAssertFalse(forgotten.valid)
        XCTAssertEqual(VaultManifest.merged(["a": forgotten], ["a": ManifestMark(version: 9, link: l7, accepts: 1)])["a"], forgotten)
        XCTAssertEqual(VaultManifest.merged(["a": forgotten], ["a": ManifestMark(version: 1, link: l7, accepts: 2)])["a"], ManifestMark(version: 1, link: l7, accepts: 2),
                       "a first manifest started after it")
        XCTAssertEqual(VaultManifest.replaced(nil, with: ManifestMark(version: 2, link: l2)), ManifestMark(version: 2, link: l2, accepts: 1))
        XCTAssertEqual(VaultManifest.replaced(forgotten, with: ManifestMark(version: 2, link: "half")), ManifestMark.forgotten(accepts: 3), "never half an entry")
        // An ordinary `ok` after an acceptance raises the version and keeps the count.
        var later = ["a": accepted, "f": forgotten]
        VaultManifest.remember(&later, vault: "a", status: .ok, mark: ManifestMark(version: 4, link: l5))
        VaultManifest.remember(&later, vault: "a", status: .ok, mark: ManifestMark(version: 2, link: l7))
        VaultManifest.remember(&later, vault: "f", status: .ok, mark: ManifestMark(version: 1, link: l7))
        XCTAssertEqual(later, ["a": ManifestMark(version: 4, link: l5, accepts: 1), "f": ManifestMark(version: 1, link: l7, accepts: 2)])
        // Which verdicts warn, which hold writes back, which wait for the next sync.
        XCTAssertTrue(ManifestStatus.rollback.unresolved && ManifestStatus.mismatch.unresolved)
        XCTAssertTrue(ManifestStatus.rollback.warns && ManifestStatus.mismatch.warns)
        for s in [ManifestStatus.incomplete, .unchecked, .needLog] {
            XCTAssertTrue(s.pending, s.rawValue)
            XCTAssertFalse(s.warns || s.unresolved, "\(s.rawValue): no warning before the server's answer was checked")
        }
        XCTAssertFalse(ManifestStatus.ok.unresolved || ManifestStatus.none.unresolved || ManifestStatus.ok.pending || ManifestStatus.none.pending)
    }

    /// The stored memory: `{vault: {version, link}}`. The first format (a bare number per vault),
    /// half an entry and a link that isn't one read as nothing remembered.
    func testAMemoryInAnotherShapeIsNothingRemembered() {
        let link = String(repeating: "x", count: 43)
        let text = #"{"v1":{"version":4,"link":"\#(link)"},"old":7,"half":{"version":3},"nolink":{"version":3,"link":"abc"},"zero":{"version":0,"link":"\#(link)"},"text":{"version":"4","link":"\#(link)"}}"#
        XCTAssertEqual(VaultManifest.readMemory(Data(text.utf8)), ["v1": ManifestMark(version: 4, link: link)])
        // With the count of acceptances; an entry that is only a count remembers no manifest;
        // the all-zero link (a first manifest's predecessor) is never a remembered one.
        let counted = #"{"a":{"version":4,"link":"\#(link)","accepts":2},"f":{"accepts":3},"z":{"version":2,"link":"\#(zeroLink)"},"zc":{"version":2,"link":"\#(zeroLink)","accepts":1},"n":{"accepts":-1},"t":{"accepts":"2"}}"#
        let read = VaultManifest.readMemory(Data(counted.utf8))
        XCTAssertEqual(read, ["a": ManifestMark(version: 4, link: link, accepts: 2), "f": .forgotten(accepts: 3), "zc": .forgotten(accepts: 1)])
        // Written and read back the same, a forgotten entry without version and link.
        let written = try? JSONEncoder().encode(read)
        XCTAssertEqual(written.flatMap(VaultManifest.readMemory), read)
        XCTAssertEqual(written.map { String(decoding: $0, as: UTF8.self).contains("\"version\":0") }, false)
        let plain = (try? JSONEncoder().encode(["v": ManifestMark(version: 4, link: link)])).map { String(decoding: $0, as: UTF8.self) } ?? ""
        XCTAssertFalse(plain.contains("accepts"), "as before for a device that never accepted anything")
        XCTAssertEqual(VaultManifest.readMemory(Data(plain.utf8)), ["v": ManifestMark(version: 4, link: link)])
        XCTAssertEqual(VaultManifest.readMemory(Data(#"{"v1":5,"v2":2}"#.utf8)), [:], "the first format")
        XCTAssertNil(VaultManifest.readMemory(Data("[1,2]".utf8)))
        XCTAssertTrue(VaultManifest.isLink(link))
        XCTAssertFalse(VaultManifest.isLink(link + "x"))
        XCTAssertFalse(VaultManifest.isLink(String(repeating: "+", count: 43)), "base64url only")
    }

    // MARK: Decrypting a copy checks every vault

    private func open(_ w: World, _ v: SyncVault, _ rows: [SyncItem], _ memory: [String: ManifestMark]?, final: Bool = false, source: CopySource = .server,
                      previous: OpenedVault? = nil, fullRows: Bool = false, revs: [String: UInt64]? = nil) -> OpenedVault {
        VaultRepository.open(w.account, w.snapshot(v, rows), previous: previous, revs: revs, manifests: memory, finalIncomplete: final, source: source,
                             fullRows: fullRows)
    }

    func testOpeningACopyChecksItsVaultsAndRemembersVersions() throws {
        let w = try world()
        let m3 = try w.start(3)
        let m4 = try w.next(m3), m5 = try w.next(m4)
        let other = ManifestMark(version: 2, link: String(repeating: "o", count: 43))
        var o = open(w, try w.header(m3), w.rows, [:])
        XCTAssertEqual(o.data.vaults.first?.manifest, .ok)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m3)])
        // A vault this device saw at version 5 served at 3: rollback, the memory untouched.
        o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m5), "other": other])
        XCTAssertEqual(o.data.vaults.first?.manifest, .rollback)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m5), "other": other])
        // An item hidden: mismatch, nothing remembered.
        o = open(w, try w.header(m3), Array(w.rows.dropLast()), [:])
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(o.manifests, [:])
        // No manifest: nothing to check.
        XCTAssertEqual(open(w, try w.header(seq: 0, sealed: nil), w.rows, [:]).data.vaults.first?.manifest, ManifestStatus.none)
        // A summary row from before the hashes: incomplete until everything was fetched once,
        // then a mismatch.
        var bare = w.rows
        bare[2].data = nil
        bare[2].itemKey = nil
        XCTAssertEqual(open(w, try w.header(m3), bare, [:]).data.vaults.first?.manifest, .incomplete)
        o = open(w, try w.header(m3), bare, [:], final: true)
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(o.manifests, [:])
        // With the hash the trashed row is checked without its data (and isn't shown).
        var hashed = w.rows
        hashed[2] = summary(hashed[2])
        XCTAssertEqual(open(w, try w.header(m3), hashed, [:]).data.vaults.first?.manifest, .ok)
        // An app that asks for every row whole (iOS) never accepts a row without its data:
        // the item would be counted and not shown.
        XCTAssertEqual(open(w, try w.header(m3), hashed, [:], fullRows: true).data.vaults.first?.manifest, .mismatch)
        // More than a step ahead of what is remembered: not a verdict yet, the log is needed.
        let m1 = try w.start(1)
        o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m1)])
        XCTAssertEqual(o.needLog, [w.vaultId])
        XCTAssertEqual(o.data.vaults.first?.manifest, .unchecked)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m1)], "nothing is remembered before the log decided")
    }

    /// A row that doesn't open with its vault's key is a hidden item: with a matching hash the
    /// manifest alone would add up, so its vault is a mismatch.
    func testARowThatDoesNotOpenIsAMismatch() throws {
        let w = try world()
        var rows = w.rows
        // The right data (so the manifest's sum is right) under a wrong item key.
        let stray = try w.key.encryptItem(itemJson: ItemCodec.encode(Item(name: "Other")), id: rows[0].id, vaultId: w.vaultId)
        rows[0].itemKey = stray.key
        let m = try w.start(3)
        XCTAssertEqual(VaultManifest.verify(try w.header(m), key: w.key, remembered: nil, rows: rows).status, .ok, "the sum alone can't tell")
        let o = open(w, try w.header(m), rows, [:])
        XCTAssertEqual(o.unreadable, [w.vaultId])
        XCTAssertEqual(o.data.entries.count, 1, "the item isn't shown")
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        // The manifest itself matches: it is remembered, the item is the vault's one problem,
        // and it is listed so it can be deleted. "Use the server's copy" has nothing to accept.
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m)])
        XCTAssertEqual(o.data.vaults.first?.unopenable, true)
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, false)
        XCTAssertEqual(o.data.unopenable, [UnopenableItem(id: rows[0].id, vaultId: w.vaultId, revision: 3, deletedAt: nil)])
        // Also after this device wrote a manifest over it: the manifest is this device's
        // (remembered), the item is still hidden, the warning stays.
        let mine = ManifestMark(version: 4, link: String(repeating: "m", count: 43))
        let after = open(w, try w.header(m), rows, [:], source: .local(wrote: [w.vaultId: mine], gone: []), previous: o)
        XCTAssertEqual(after.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(after.data.vaults.first?.unopenable, true)
        XCTAssertEqual(after.manifests, [w.vaultId: mine])
        // A row that has its data but came without its key can't be opened either (it used to be
        // skipped, with no warning and nothing in the trash).
        var keyless = w.rows
        keyless[2].itemKey = nil
        let k = open(w, try w.header(m), keyless, [:], fullRows: true)
        XCTAssertEqual(k.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(k.data.vaults.first?.unopenable, true)
        XCTAssertEqual(k.data.unopenable.map(\.id), [keyless[2].id])
        XCTAssertEqual(k.data.unopenable.first?.deletedAt, keyless[2].deletedAt)
        XCTAssertTrue(k.data.trash.isEmpty)
        // Where the trash is kept as a summary, a row with neither key nor data is as asked for.
        let s = open(w, try w.header(m), [w.rows[0], w.rows[1], summary(w.rows[2])], [:])
        XCTAssertEqual(s.data.vaults.first?.manifest, .ok)
        XCTAssertTrue(s.data.unopenable.isEmpty)
        // The manifest is wrong as well (an item is missing): an ordinary warning; the item is
        // still listed, and the record has to be settled first.
        let both = open(w, try w.header(m), Array(rows.dropLast()), [:])
        XCTAssertEqual(both.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(both.data.vaults.first?.unopenable, false)
        XCTAssertEqual(both.data.unopenable.count, 1)
        // A vault without a manifest stays as it was (writable); the item is listed, and no
        // first manifest is started over it.
        let bare = open(w, try w.header(seq: 0, sealed: nil, ok: true), rows, [:])
        XCTAssertEqual(bare.data.vaults.first?.manifest, ManifestStatus.none)
        XCTAssertEqual(bare.data.unopenable.count, 1)
        XCTAssertFalse(VaultManifest.mayStart(try w.header(seq: 0, sealed: nil, ok: true), role: .owner, status: .none, remembered: nil, rows: rows,
                                              features: [vaultManifestFeature], unopenable: true))
    }

    /// A warned vault is also checked with nothing remembered: when the served manifest
    /// describes the served items (or none is served), "Use the server's copy" only changes this
    /// device's memory, which every member may do.
    func testAWarnedVaultKnowsWhetherItsServedCopyCanBeAccepted() throws {
        let w = try world()
        let m3 = try w.start(3)
        let m4 = try w.next(m3), m5 = try w.next(m4)
        // A restored backup: an older manifest that matches its items. Rollback, acceptable.
        var o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m5)])
        XCTAssertEqual(o.data.vaults.first?.manifest, .rollback)
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, true)
        XCTAssertEqual(VaultManifest.accept(try w.header(m3), key: w.key, rows: w.rows).mark, mark(m3))
        // The manifest vanished: acceptable too (the memory is forgotten).
        o = open(w, try w.header(seq: 0, sealed: nil), w.rows, [w.vaultId: mark(m5)])
        XCTAssertEqual(o.data.vaults.first?.manifest, .rollback)
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, true)
        XCTAssertEqual(VaultManifest.accept(try w.header(seq: 0, sealed: nil), key: w.key, rows: w.rows).status, ManifestStatus.none)
        // Items that aren't the ones recorded: nothing to accept without a new record.
        o = open(w, try w.header(m3), Array(w.rows.dropLast()), [:])
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, false)
        XCTAssertEqual(VaultManifest.accept(try w.header(m3), key: w.key, rows: Array(w.rows.dropLast())).status, .mismatch)
        XCTAssertNil(VaultManifest.accept(try w.header(m3), key: w.key, rows: Array(w.rows.dropLast())).mark)
        XCTAssertEqual(VaultManifest.accept(try w.header(seq: 3, sealed: "doesn't open", prev: m3.prev), key: w.key, rows: w.rows).status, .mismatch)
        // A vault that is fine carries neither flag; a verdict that is kept keeps them.
        o = open(w, try w.header(m3), w.rows, [:])
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, false)
        let warned = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m5)])
        o = open(w, try w.header(m3), w.rows, nil, previous: warned)
        XCTAssertEqual(o.data.vaults.first?.manifest, .rollback)
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, true, "kept with the warning while the memory can't be read")
        o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m5)], source: .local(wrote: [:], gone: []), previous: warned)
        XCTAssertEqual(o.data.vaults.first?.manifestAcceptable, true)
    }

    /// The copy on the device never warns by itself and this device's own write only touches the
    /// vault it wrote to; a memory that can't be read checks nothing.
    func testOnlyTheServersAnswerWarns() throws {
        let w = try world()
        let m3 = try w.start(3)
        let m4 = try w.next(m3), m5 = try w.next(m4)
        // The stored copy is older than what this device (its other process) already saw.
        var o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m4)], source: .cache)
        XCTAssertEqual(o.data.vaults.first?.manifest, .unchecked)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m4)])
        // It doesn't match (or needs the log): still not a warning before the server answered.
        XCTAssertEqual(open(w, try w.header(m3), Array(w.rows.dropLast()), [:], source: .cache).data.vaults.first?.manifest, .unchecked)
        o = open(w, try w.header(m5), w.rows, [w.vaultId: mark(m3)], source: .cache)
        XCTAssertEqual(o.data.vaults.first?.manifest, .unchecked)
        XCTAssertTrue(o.needLog.isEmpty, "no log is fetched for a stored copy")
        // A stored copy that checks out is as good as an answer.
        o = open(w, try w.header(m4), w.rows, [w.vaultId: mark(m3)], source: .cache)
        XCTAssertEqual(o.data.vaults.first?.manifest, .ok)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m4)])
        // This device's own write: the vault written to is at the manifest sent, whatever the
        // stored memory says by now; no other vault is looked at again.
        let shown = open(w, try w.header(m3), w.rows, [:])
        o = open(w, try w.header(m4), w.rows, [w.vaultId: mark(m3)], source: .local(wrote: [w.vaultId: mark(m4)], gone: []), previous: shown)
        XCTAssertEqual(o.data.vaults.first?.manifest, .ok)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m4)])
        var warned = shown
        warned.data.vaults[0].manifest = .mismatch
        o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m5)], source: .local(wrote: ["another": mark(m4)], gone: []), previous: warned)
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch, "a vault the write didn't touch keeps its verdict")
        o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m5)], source: .local(wrote: [:], gone: []), previous: shown)
        XCTAssertEqual(o.data.vaults.first?.manifest, .ok, "not checked again against a memory another process raised")
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m5)])
        // The memory can't be read now: nothing is checked against "nothing remembered", nothing
        // is remembered; a warning stays, everything else waits.
        o = open(w, try w.header(m3), w.rows, nil)
        XCTAssertEqual(o.data.vaults.first?.manifest, .unchecked)
        XCTAssertNil(o.manifests)
        XCTAssertEqual(open(w, try w.header(m3), w.rows, nil, previous: warned).data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(open(w, try w.header(m3), w.rows, nil, previous: shown).data.vaults.first?.manifest, .unchecked, "an earlier ok isn't carried over to new rows")
        // A vault without a manifest stays as writable as it was while the memory can't be read.
        o = open(w, try w.header(seq: 0, sealed: nil), w.rows, nil)
        XCTAssertEqual(o.data.vaults.first?.manifest, ManifestStatus.none)
        XCTAssertNil(o.manifests)
        // What a background refresh kept is checked like an answer (its caller adopts it only
        // when every vault is ok or none); a vault that would need the log is never ok there.
        o = open(w, try w.header(m3), Array(w.rows.dropLast()), [:], source: .refreshed)
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        o = open(w, try w.header(m3), w.rows, [w.vaultId: mark(m4)], source: .refreshed)
        XCTAssertEqual(o.data.vaults.first?.manifest, .rollback)
        o = open(w, try w.header(m5), w.rows, [w.vaultId: mark(m3)], source: .refreshed)
        XCTAssertEqual(o.data.vaults.first?.manifest, .unchecked)
        XCTAssertTrue(o.needLog.isEmpty)
        o = open(w, try w.header(m4), w.rows, [w.vaultId: mark(m3)], source: .refreshed)
        XCTAssertEqual(o.data.vaults.first?.manifest, .ok)
    }

    /// The log decides a vault that was more than a step ahead; a server without a log for it,
    /// or one that doesn't connect, is a mismatch.
    func testTheLogDecidesAVaultThatWasAhead() throws {
        let w = try world()
        let m1 = try w.start(1)
        let m2 = try w.next(m1), m3 = try w.next(m2)
        let snap = w.snapshot(try w.header(m3))
        func decided(logs: [String: String] = [:], noLog: Set<String> = []) -> OpenedVault {
            var o = open(w, try! w.header(m3), w.rows, [w.vaultId: mark(m1)])
            VaultRepository.checkManifests(&o, snap, memory: [w.vaultId: mark(m1)], logs: logs, noLog: noLog, source: .server, previous: [:],
                                           finalIncomplete: false, fullRows: false)
            return o
        }
        var o = decided(logs: [w.vaultId: log([m2, m3])])
        XCTAssertEqual(o.data.vaults.first?.manifest, .ok)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m3)])
        XCTAssertTrue(o.needLog.isEmpty)
        o = decided(logs: [w.vaultId: log([m3])])
        XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(o.manifests, [w.vaultId: mark(m1)])
        XCTAssertEqual(decided(noLog: [w.vaultId]).data.vaults.first?.manifest, .mismatch, "404 from the log endpoint is an answer")
    }

    // MARK: Fields only this device sets

    /// `served_sha256` is this device's own note on a row it kept; a server's answer never sets
    /// it. With it a server could serve old data and name the hash it is checked with.
    func testAServerCannotNameTheHashARowIsCheckedWith() throws {
        let w = try world()
        let m = try w.start(3)
        // The item's current data is what the manifest records; the server sends an older
        // ciphertext of the same item with the current data's hash as `served_sha256`.
        let current = try XCTUnwrap(w.rows[0].data)
        let older = try w.key.encryptItem(itemJson: ItemCodec.encode(Item(name: "Older")), id: w.rows[0].id, vaultId: w.vaultId)
        func answer(delta: Bool) throws -> SyncResponse {
            let row: [String: Any] = ["id": w.rows[0].id, "vault_id": w.vaultId, "item_key": older.key, "data": older.data, "revision": 3,
                                      "deleted_at": NSNull(), "served_sha256": VaultManifest.dataHash(current)]
            let header = try JSONSerialization.jsonObject(with: try JSONEncoder().encode(try w.header(m)))
            let rest = try w.rows.dropFirst().map { try JSONSerialization.jsonObject(with: try JSONEncoder().encode($0)) }
            let all: [Any] = delta ? [row] : [row as Any] + rest
            var body: [String: Any] = ["revision": 6, "cursor": "c2", "vaults": [header], "items": all]
            if delta {
                body["delta"] = true
                body["deleted"] = [Any]()
                body["reset"] = [Any]()
            }
            return try JSONDecoder().decode(SyncResponse.self, from: try JSONSerialization.data(withJSONObject: body))
        }
        let base = w.snapshot(try w.header(m))
        for delta in [false, true] {
            let merged = try XCTUnwrap(SyncMerge.apply(try answer(delta: delta), to: delta ? base : nil))
            XCTAssertTrue(merged.items.allSatisfy { $0.servedSha256 == nil }, "dropped from the answer (delta: \(delta))")
            let o = VaultRepository.open(w.account, merged, previous: nil)
            XCTAssertEqual(o.data.vaults.first?.manifest, .mismatch, "the old data is checked as what it is (delta: \(delta))")
            XCTAssertEqual(o.manifests, [:])
        }
        // This device's own stored copy keeps the field (and only that path does).
        var mine = base
        mine.items[0].servedSha256 = "SERVED"
        XCTAssertEqual(try XCTUnwrap(SyncSnapshot.decode(try mine.encoded())).items[0].servedSha256, "SERVED")
        // A delta leaves the rows it doesn't name as this device holds them.
        let untouched = try JSONDecoder().decode(SyncResponse.self, from: Data(#"{"delta":true,"revision":7,"cursor":"c3","vaults":\#(String(decoding: try JSONEncoder().encode([try w.header(m)]), as: UTF8.self)),"items":[],"deleted":[],"reset":[]}"#.utf8))
        XCTAssertEqual(SyncMerge.apply(untouched, to: mine)?.items.first { $0.id == mine.items[0].id }?.servedSha256, "SERVED")
    }

    /// A newer copy this device kept after the server sent an older version stays marked for as
    /// long as the copy holds that row: also when it is opened again from the device (after a
    /// lock), where its counter is simply the one remembered.
    func testAKeptNewerCopyStaysMarked() throws {
        let w = try world(live: 2, trashed: 0)
        // Served: an older version of item 0. Kept: the newer one, with the served data's hash.
        let newer = try w.key.updateItem(encrypted: EncryptedItem(id: w.rows[0].id, vaultId: w.vaultId, key: try XCTUnwrap(w.rows[0].itemKey),
                                                                  data: try XCTUnwrap(w.rows[0].data)), itemJson: ItemCodec.encode(Item(name: "Newer")))
        let served = w.rows
        let m = try w.start(3, rows: served)
        var keptRows = served
        keptRows[0].data = newer.data
        keptRows[0].servedSha256 = VaultManifest.dataHash(try XCTUnwrap(served[0].data))
        let rev = try ItemCodec.decode(try w.key.decryptItem(encrypted: newer)).rev
        for source in [CopySource.cache, .server, .local(wrote: [:], gone: [])] {
            let o = open(w, try w.header(m), keptRows, [:], source: source, revs: [w.rows[0].id: rev])
            XCTAssertEqual(o.data.entries.first { $0.id == w.rows[0].id }?.rolledBack, true, "\(source)")
            XCTAssertEqual(o.data.entries.first { $0.id == w.rows[1].id }?.rolledBack, false)
            XCTAssertEqual(o.data.rollback, ItemRollback(items: [w.rows[0].id], kept: [w.rows[0].id]), "\(source)")
            if case .local = source { continue }
            XCTAssertEqual(o.data.vaults.first?.manifest, .ok, "checked with what the server sent for it (\(source))")
        }
        // Without a memory of the item (a new device) the row is marked all the same.
        XCTAssertEqual(open(w, try w.header(m), keptRows, [:], source: .cache, revs: [:]).data.rollback?.items, [w.rows[0].id])
        // The stored copy alone never marks an item by its counter (the other process may have
        // seen a newer one); the server's answer does.
        let ahead = [w.rows[1].id: UInt64(99)]
        XCTAssertNil(open(w, try w.header(m), served, [:], source: .cache, revs: ahead).data.rollback)
        XCTAssertEqual(open(w, try w.header(m), served, [:], source: .server, revs: ahead).data.rollback?.items, [w.rows[1].id])
        // A first manifest isn't started over such rows, or in a vault with rolled-back items.
        let ready = try w.header(seq: 0, sealed: nil, ok: true)
        let features = [vaultManifestFeature]
        XCTAssertTrue(VaultManifest.mayStart(ready, role: .owner, status: .none, remembered: nil, rows: served, features: features))
        XCTAssertFalse(VaultManifest.mayStart(ready, role: .owner, status: .none, remembered: nil, rows: keptRows, features: features))
        XCTAssertFalse(VaultManifest.mayStart(ready, role: .owner, status: .none, remembered: nil, rows: served, features: features, rolledBack: true))
    }

    // MARK: Item edit counters remembered

    /// An item's counter is forgotten only when its absence is authenticated; a server that
    /// hides an item (or its vault) for one sync doesn't get an old version accepted as new.
    func testAnItemsCounterIsForgottenOnlyOnAuthenticatedAbsence() {
        let before = ItemRevMemory(items: ["a": .init(rev: 5, vault: "v1", seen: 10), "b": .init(rev: 2, vault: "v1", seen: 10),
                                           "c": .init(rev: 9, vault: "v2", seen: 10), "old": .init(rev: 4)])
        // The answer has only `a` (now at 6); nothing is authenticated as gone.
        var s = ItemRevCheck.settle(before, observed: ["a": 6, "b": 2, "c": 9, "old": 4], rows: [(id: "a", vault: "v1")], absentOk: [], now: 20)
        XCTAssertEqual(s.memory.items["a"], .init(rev: 6, vault: "v1", seen: 20))
        XCTAssertEqual(s.memory.revs, ["a": 6, "b": 2, "c": 9, "old": 4], "hidden items stay remembered")
        XCTAssertTrue(s.dropped.isEmpty)
        // `v1` matched its manifest: `b` is really gone. `c`'s vault isn't there: kept. An entry
        // from before vaults were kept with the counters stays until the item is seen again.
        s = ItemRevCheck.settle(before, observed: ["a": 5, "b": 2, "c": 9, "old": 4], rows: [(id: "a", vault: "v1")], absentOk: ["v1"], now: 20)
        XCTAssertEqual(s.memory.revs, ["a": 5, "c": 9, "old": 4])
        XCTAssertEqual(s.dropped, ["b"])
        // An item that moved is seen in its new vault, never forgotten with the old one.
        s = ItemRevCheck.settle(before, observed: ["a": 5, "b": 2, "c": 9, "old": 4], rows: [(id: "b", vault: "v2")], absentOk: ["v1"], now: 20)
        XCTAssertEqual(s.memory.items["b"], .init(rev: 2, vault: "v2", seen: 20))
        XCTAssertEqual(s.dropped, ["a"])
        // A counter is never lowered by what a copy showed.
        s = ItemRevCheck.settle(before, observed: ["a": 3], rows: [(id: "a", vault: "v1")], absentOk: [], now: 20)
        XCTAssertEqual(s.memory.items["a"]?.rev, 5)
        // A row that didn't open (no counter read) keeps what was remembered.
        s = ItemRevCheck.settle(before, observed: [:], rows: [(id: "a", vault: "v1")], absentOk: ["v1"], now: 20)
        XCTAssertEqual(s.memory.items["a"], before.items["a"])
    }

    func testTheCounterMemoryIsCappedMergedAndReadsItsOlderFormat() throws {
        // At most 20,000 items: the most recently seen stay.
        XCTAssertEqual(ItemRevMemory.limit, 20_000)
        var many = ItemRevMemory()
        for i in 0..<12 { many.items["i\(i)"] = .init(rev: 1, vault: "v", seen: Int64(i)) }
        XCTAssertEqual(Set(many.capped(5).items.keys), ["i7", "i8", "i9", "i10", "i11"])
        XCTAssertEqual(many.capped(50), many)
        // Two processes' memories: every id of either, the higher counter, the later sighting.
        let stored = ItemRevMemory(items: ["a": .init(rev: 5, vault: "v1", seen: 10), "theirs": .init(rev: 1, vault: "v1", seen: 12)])
        let mine = ItemRevMemory(items: ["a": .init(rev: 4, vault: "v2", seen: 15), "mine": .init(rev: 3, vault: "v1", seen: 15), "x": .init(rev: 1, vault: "v", seen: 1)])
        let merged = ItemRevMemory.merged(stored: stored, mine, dropped: ["x"])
        XCTAssertEqual(merged.items, ["a": .init(rev: 5, vault: "v2", seen: 15), "theirs": .init(rev: 1, vault: "v1", seen: 12), "mine": .init(rev: 3, vault: "v1", seen: 15)])
        // The format before vaults and times were kept: its counters still count.
        XCTAssertEqual(ItemRevMemory.read(Data(#"{"a":7,"b":2}"#.utf8)).revs, ["a": 7, "b": 2])
        XCTAssertEqual(ItemRevMemory.read(try XCTUnwrap(merged.encoded())), merged)
        XCTAssertEqual(ItemRevMemory.read(Data("garbage".utf8)), ItemRevMemory())
    }

    // MARK: Starting, a new baseline, old trash

    func testWhenAFirstManifestIsStarted() throws {
        let w = try world()
        let features = [vaultManifestFeature, "delta_sync"]
        let ready = try w.header(seq: 0, sealed: nil, ok: true)
        func start(_ v: SyncVault, role: Role = .owner, status: ManifestStatus = .none, remembered: ManifestMark? = nil, rows: [SyncItem]? = nil,
                   features f: [String]? = nil) -> Bool {
            VaultManifest.mayStart(v, role: role, status: status, remembered: remembered, rows: rows ?? w.rows, features: f ?? features)
        }
        XCTAssertTrue(start(ready))
        XCTAssertTrue(start(ready, role: .write))
        XCTAssertTrue(start(ready, role: .admin))
        XCTAssertFalse(start(ready, role: .read), "readers don't write manifests")
        XCTAssertFalse(start(try w.header(seq: 0, sealed: nil, ok: false)), "a member's app is too old")
        XCTAssertFalse(start(try w.header(seq: 0, sealed: nil, ok: nil)))
        XCTAssertFalse(start(try w.header(seq: 2, sealed: "x", ok: true)), "it has one")
        XCTAssertFalse(start(ready, features: ["delta_sync"]), "the server doesn't keep manifests")
        XCTAssertFalse(start(ready, remembered: ManifestMark(version: 4, link: String(repeating: "o", count: 43))), "this device saw one: that is a rollback, not a start")
        XCTAssertFalse(start(ready, status: .rollback))
        XCTAssertFalse(start(ready, status: .unchecked))
        XCTAssertFalse(start(try w.header(seq: 0, sealed: nil, ok: true, vaultSeq: nil)), "pinned to the vault's number")
        var bare = w.rows
        bare[2].data = nil
        XCTAssertFalse(start(ready, rows: bare), "every row must be in it")
        bare[2].dataSha256 = "h"
        XCTAssertTrue(start(ready, rows: bare))
        // A memory that was forgotten by an acceptance remembers no manifest: a start is fine.
        XCTAssertTrue(start(ready, remembered: .forgotten(accepts: 1)))
        XCTAssertFalse(VaultManifest.mayStart(ready, role: .owner, status: .none, remembered: nil, rows: w.rows, features: features, unopenable: true),
                       "never over an item that can't be opened")
    }

    /// A baseline is always the served version + 1, whatever this device remembers (the server
    /// takes nothing else, so no version can be pushed out of reach).
    func testABaselineIsOneAboveTheServedRow() throws {
        XCTAssertEqual(VaultManifest.baselineSeq(row: 5), 6)
        XCTAssertEqual(VaultManifest.baselineSeq(row: 0), 1)
        XCTAssertEqual(VaultManifest.baselineSeq(row: Int64(VaultManifest.maxNumber) - 1), VaultManifest.maxNumber)
        XCTAssertNil(VaultManifest.baselineSeq(row: Int64(VaultManifest.maxNumber)), "nothing above the last number")
        XCTAssertNil(VaultManifest.baselineSeq(row: -1))
        // It names the manifest the server shows now, by its link (it needn't open).
        let w = try world()
        let m = try w.start(3)
        XCTAssertEqual(VaultManifest.link(of: try w.header(m)), m.link)
        XCTAssertEqual(VaultManifest.link(of: try w.header(seq: 3, sealed: "doesn't open", prev: m.prev)),
                       try manifestLink(manifestSeq: 3, prev: m.prev, sealed: "doesn't open"))
        XCTAssertNil(VaultManifest.link(of: try w.header(seq: 0, sealed: nil)), "none: a first manifest")
        XCTAssertNil(VaultManifest.link(of: try w.header(seq: 3, sealed: m.sealed, prev: nil)))
    }

    /// Old trash is deleted by this device only when the server's rule says so AND this device
    /// itself saw the item in the trash for the retention period AND the clocks agree within a day.
    func testTrashIsDueOnlyAfterThisDeviceWatchedItWait() {
        let day: Int64 = 86400
        let now: Int64 = 1_800_000_000
        let rows = [
            SyncItem(id: "live", vaultId: "v", itemKey: "k", data: "d", deletedAt: nil),
            SyncItem(id: "old", vaultId: "v", itemKey: "k", data: "d", deletedAt: now - 31 * day),
            SyncItem(id: "edge", vaultId: "v", itemKey: "k", data: "d", deletedAt: now - 30 * day),
            SyncItem(id: "new", vaultId: "v", itemKey: "k", data: "d", deletedAt: now - 3 * day),
        ]
        let watched = ["live": now - 99 * day, "old": now - 31 * day, "edge": now - 30 * day, "new": now - 3 * day]
        func due(_ time: Int64?, _ days: Int64?, seen: [String: Int64]? = nil, clock: Int64? = nil) -> [String] {
            VaultManifest.dueTrash(rows, serverTime: time, trashDays: days, firstSeen: seen ?? watched, now: clock ?? now).map(\.id)
        }
        XCTAssertEqual(due(now, 30), ["old"], "strictly older than the retention")
        XCTAssertEqual(due(now, 1), ["old", "edge"], "never before this device saw it wait a week, whatever retention the server names")
        XCTAssertEqual(due(now, 1, seen: ["new": now - 7 * day + 1]), [])
        XCTAssertEqual(due(now, 1, seen: ["new": now - 7 * day]), ["new"], "a week at the least")
        XCTAssertEqual(due(now, 3, seen: ["new": now - 7 * day]), [], "the server's rule is strict: deleted exactly the retention ago isn't due")
        XCTAssertEqual(VaultManifest.trashFloorDays, 7)
        XCTAssertEqual(due(now, 0), [], "0 = kept forever")
        XCTAssertEqual(due(nil, 30), [], "never without the server's clock")
        XCTAssertEqual(due(now, nil), [])
        XCTAssertEqual(due(now, -1), [])
        XCTAssertEqual(due(now, Int64.max), [])
        // What a server can say isn't enough: a far-off clock, a short retention, early
        // `deleted_at`s. Nothing goes before this device saw it wait that long itself.
        XCTAssertEqual(due(now, 30, seen: [:]), [], "right after the update nothing is deleted")
        XCTAssertEqual(due(now, 1, seen: ["old": now - 2 * day, "edge": now - 3600, "new": now]), [], "a day's retention and early deleted_at empty nothing")
        XCTAssertEqual(due(now, 1, seen: ["old": now - 8 * day, "edge": now - 3600, "new": now]), ["old"])
        XCTAssertEqual(due(now, 30, seen: ["old": now - 29 * day]), [], "seen for less than the retention")
        XCTAssertEqual(due(now, 30, seen: ["old": now - 30 * day]), ["old"])
        XCTAssertEqual(due(9_000_000_000_000_000_000, 1), [], "a server clock far from this device's")
        XCTAssertEqual(due(now + 2 * day, 1), [])
        XCTAssertEqual(due(now - 2 * day, 1), [])
        XCTAssertEqual(due(now + day, 1), ["old", "edge"], "within a day")
        XCTAssertEqual(due(now, 30, clock: 0), [])
        XCTAssertEqual(due(Int64.max, 1, clock: -5), [], "no arithmetic overflows on these numbers")
        XCTAssertEqual(due(Int64.max, 1, clock: Int64.min), [])
        // A `deleted_at` that is no time is never due.
        let bad = [SyncItem(id: "zero", vaultId: "v", itemKey: "k", data: "d", deletedAt: 0), SyncItem(id: "neg", vaultId: "v", itemKey: "k", data: "d", deletedAt: -5)]
        XCTAssertEqual(VaultManifest.dueTrash(bad, serverTime: now, trashDays: 1, firstSeen: ["zero": 1, "neg": 1], now: now).map(\.id), [])
        // The memory: first sight is kept, an item that is live again or gone is forgotten, a
        // time from the future isn't trusted.
        let seen = VaultManifest.trashSeen(["old": 100, "live": 50, "gone": 60, "new": now + 999], rows: rows, now: now)
        XCTAssertEqual(seen, ["old": 100, "edge": now, "new": now])
        XCTAssertEqual(VaultManifest.purgeChunk, 250)
    }

    // MARK: The copy carries the new fields

    func testTheNewFieldsGoThroughAnAnswerADeltaAndTheStoredCopy() throws {
        let full = Data("""
        {"revision":5,"cursor":"c1","server_time":1800000000,"trash_days":30,
         "vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account","key_epoch":2,"seq":4,
                    "manifest":"SEALED","manifest_seq":9,"manifest_prev":"PREV","manifest_ok":true}],
         "items":[{"id":"i1","vault_id":"v1","item_key":"k","data":"d","revision":3,"deleted_at":null},
                  {"id":"i2","vault_id":"v1","revision":4,"deleted_at":1700000000,"data_sha256":"HASH"}]}
        """.utf8)
        let snap = try XCTUnwrap(SyncSnapshot.decode(full))
        XCTAssertEqual(snap.vaults[0].manifest, "SEALED")
        XCTAssertEqual(snap.vaults[0].manifestSeq, 9)
        XCTAssertEqual(snap.vaults[0].manifestPrev, "PREV")
        XCTAssertEqual(snap.vaults[0].manifestOk, true)
        XCTAssertEqual(snap.vaults[0].manifestVersion, 9)
        XCTAssertEqual(snap.items[1].dataSha256, "HASH")
        XCTAssertNil(snap.items[0].dataSha256)
        XCTAssertEqual(snap.serverTime, 1_800_000_000)
        XCTAssertEqual(snap.trashDays, 30)
        // Stored and read again: the rows and their manifest (all three fields) stay together
        // (the server's clock of that answer isn't kept: old trash is only deleted right after
        // a sync).
        let stored = try XCTUnwrap(SyncSnapshot.decode(try snap.encoded()))
        XCTAssertEqual(stored.vaults, snap.vaults)
        XCTAssertEqual(stored.items, snap.items)
        XCTAssertNil(stored.serverTime)
        // A delta: the vault row's new manifest and a trashed summary row with its hash.
        let delta = try JSONDecoder().decode(SyncResponse.self, from: Data("""
        {"delta":true,"revision":6,"cursor":"c2","server_time":1800000100,"trash_days":7,
         "vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account","key_epoch":2,"seq":5,
                    "manifest":"NEXT","manifest_seq":10,"manifest_prev":"LINK9","manifest_ok":true}],
         "items":[{"id":"i1","vault_id":"v1","revision":5,"deleted_at":1700000500,"data_sha256":"H1"}],"deleted":[],"reset":[]}
        """.utf8))
        let merged = try XCTUnwrap(SyncMerge.apply(delta, to: stored))
        XCTAssertEqual(merged.vaults[0].manifest, "NEXT")
        XCTAssertEqual(merged.vaults[0].manifestSeq, 10)
        XCTAssertEqual(merged.vaults[0].manifestPrev, "LINK9")
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: merged.items.map { ($0.id, $0.dataSha256) }), ["i1": "H1", "i2": "HASH"])
        XCTAssertEqual(merged.trashDays, 7)
        // A copy from before manifests reads as "no manifest".
        let old = try XCTUnwrap(SyncSnapshot.decode(Data(#"{"revision":1,"vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account"}],"items":[]}"#.utf8)))
        XCTAssertNil(old.vaults[0].manifestSeq)
        XCTAssertNil(old.vaults[0].manifestPrev)
        XCTAssertEqual(old.vaults[0].manifestVersion, 0)
    }

    /// The numbers the apps count with must be whole numbers up to 2^53 − 1 (a vault's not below
    /// 0): anything else isn't an answer, and nothing is ever added to a server's number unchecked.
    func testNumbersOutOfRangeAreNotAnAnswer() throws {
        func answer(vault: String = "", item: String = #""deleted_at":null"#) -> SyncSnapshot? {
            let text = #"{"revision":5,"vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account"\#(vault)}],"items":[{"id":"i1","vault_id":"v1","item_key":"k","data":"d",\#(item)}]}"#
            guard let r = try? JSONDecoder().decode(SyncResponse.self, from: Data(text.utf8)) else { return nil }
            return SyncMerge.apply(r, to: nil)
        }
        XCTAssertNotNil(answer())
        XCTAssertNotNil(answer(vault: #","seq":9007199254740991,"manifest_seq":9007199254740991,"key_epoch":9007199254740991"#))
        for field in ["seq", "manifest_seq", "key_epoch"] {
            XCTAssertNil(answer(vault: #","\#(field)":9007199254740992"#), "\(field) above 2^53 − 1")
            XCTAssertNil(answer(vault: #","\#(field)":9223372036854775807"#), field)
            XCTAssertNil(answer(vault: #","\#(field)":-1"#), "\(field) below 0")
            XCTAssertNil(answer(vault: #","\#(field)":1.5"#), "\(field) not whole")
            XCTAssertNil(answer(vault: #","\#(field)":"7""#), "\(field) as text")
        }
        XCTAssertNotNil(answer(item: #""deleted_at":9007199254740991"#))
        XCTAssertNil(answer(item: #""deleted_at":9007199254740992"#))
        XCTAssertNil(answer(item: #""deleted_at":1.5"#))
        XCTAssertNil(answer(item: #""deleted_at":"soon""#))
        // 0 reaches the check as it is, where the core refuses it (a mismatch); a time below 0
        // isn't an answer at all, as in the Android app.
        XCTAssertEqual(answer(item: #""deleted_at":0"#)?.items.first?.deletedAt, 0)
        XCTAssertNil(answer(item: #""deleted_at":-1"#))
        XCTAssertNil(answer(item: #""deleted_at":-9223372036854775808"#))
        // A write's answer far from the copy's number is never "the next one" (and nothing traps).
        XCTAssertEqual(SyncDecision.afterWrite(known: Int64.max, vaultSeq: Int64.min), .sync)
        XCTAssertEqual(SyncDecision.afterWrite(known: Int64.max, vaultSeq: Int64.max), .nothing)
        XCTAssertEqual(SyncDecision.afterWrite(known: 7, vaultSeq: 8), .applyLocally)
        XCTAssertEqual(SyncDecision.afterWrite(known: 7, vaultSeq: Int64.max), .sync)
    }

    func testAWriteAppliedToTheCopyTakesItsManifestAndASummaryRowKeepsItsHash() throws {
        let w = try world(live: 2, trashed: 0)
        let m3 = try w.start(3)
        let base = w.snapshot(try w.header(m3))
        // This device trashes the first item (an app that keeps trashed rows without data).
        var after = w.rows
        after[0].deletedAt = 1_800_000_000
        let next = try w.key.manifestNext(vaultId: w.vaultId, keyEpoch: 1, manifestSeq: 3, prev: m3.prev, sealed: m3.sealed,
                                          removedJson: VaultManifest.rowsJson([w.rows[0]]), addedJson: VaultManifest.rowsJson([after[0]]))
        let sent = ManifestEntry(vaultId: w.vaultId, next)
        XCTAssertEqual(sent.seq, 4)
        XCTAssertEqual(sent.prev, m3.link, "it names the manifest it replaces")
        let applied = try XCTUnwrap(SyncMerge.applyLocal(.trash(id: w.rows[0].id, at: 1_800_000_000, revision: 4, summary: true),
                                                         vaultId: w.vaultId, vaultSeq: 8, manifest: sent, to: base))
        XCTAssertEqual(applied.vaults[0].seq, 8)
        XCTAssertEqual(applied.vaults[0].manifestSeq, 4)
        XCTAssertEqual(applied.vaults[0].manifest, sent.sealed)
        XCTAssertEqual(applied.vaults[0].manifestPrev, sent.prev)
        XCTAssertEqual(VaultManifest.link(of: applied.vaults[0]), sent.link, "the row's link is the one remembered")
        let row = try XCTUnwrap(applied.items.first { $0.id == w.rows[0].id })
        XCTAssertNil(row.data)
        XCTAssertNil(row.itemKey)
        XCTAssertEqual(row.dataSha256, VaultManifest.dataHash(try XCTUnwrap(w.rows[0].data)))
        // The copy still matches the manifest it now carries, also after it was stored and read.
        XCTAssertEqual(VaultManifest.verify(applied.vaults[0], key: w.key, remembered: mark(m3), rows: applied.items).status, .ok)
        let stored = try XCTUnwrap(SyncSnapshot.decode(try applied.encoded()))
        XCTAssertEqual(VaultManifest.verify(stored.vaults[0], key: w.key, remembered: sent.mark, rows: stored.items).status, .ok)
        // Without `summary` the row keeps its data and needs no hash.
        let kept = try XCTUnwrap(SyncMerge.applyLocal(.trash(id: w.rows[0].id, at: 1_800_000_000, revision: 4, summary: false),
                                                      vaultId: w.vaultId, vaultSeq: 8, manifest: sent, to: base))
        XCTAssertNotNil(kept.items.first { $0.id == w.rows[0].id }?.data)
        XCTAssertEqual(VaultManifest.verify(kept.vaults[0], key: w.key, remembered: nil, rows: kept.items).status, .ok)
        // A manifest for another vault is never put on this row; without one the row keeps its own.
        XCTAssertNil(SyncMerge.applyLocal(.purge(id: w.rows[1].id), vaultId: w.vaultId, vaultSeq: 8,
                                          manifest: ManifestEntry(vaultId: "other", seq: 4, prev: "p", sealed: "x", link: "l"), to: base))
        XCTAssertEqual(SyncMerge.applyLocal(.purge(id: w.rows[1].id), vaultId: w.vaultId, vaultSeq: 8, to: base)?.vaults[0].manifestSeq, 3)
    }

    // MARK: Key replacement

    func testAKeyReplacementCarriesANewManifestUnderTheNewKeyAndEpoch() throws {
        let w = try world()
        let m6 = try w.start(6)
        let old = try w.header(m6)
        let made = try w.account.newVaultKeyBound(vaultId: w.vaultId, keyEpoch: 2)
        let (items, _) = try VaultRepository.reencrypt(w.rows, vid: w.vaultId, name: "Personal", oldKey: w.key, newKey: made.key)
        let entry = try XCTUnwrap(try VaultManifest.rotation(old, newKey: made.key, nextEpoch: 2, rows: w.rows, items: items))
        XCTAssertEqual(entry.seq, 7)
        XCTAssertEqual(entry.vaultId, w.vaultId)
        XCTAssertEqual(entry.prev, m6.link, "it names the manifest it replaces (sealed under the old key: only its link is taken)")
        // What the vault holds afterwards: every item where it was, with its new data.
        let after = zip(w.rows, items).map { r, item in SyncItem(id: r.id, vaultId: r.vaultId, itemKey: item.str("key"), data: item.str("data"), deletedAt: r.deletedAt) }
        let row = SyncVault(id: w.vaultId, keyEpoch: 2, manifest: entry.sealed, manifestSeq: 7, manifestPrev: entry.prev)
        // The chain crosses the key replacement: a device that remembers version 6 accepts it.
        let check = VaultManifest.verify(row, key: made.key, remembered: mark(m6), rows: after)
        XCTAssertEqual(check.status, .ok)
        XCTAssertEqual(check.mark, entry.mark)
        // Not under the old key, the old epoch, or over the old data.
        XCTAssertEqual(VaultManifest.verify(row, key: w.key, remembered: nil, rows: after).status, .mismatch)
        XCTAssertEqual(VaultManifest.verify(SyncVault(id: w.vaultId, keyEpoch: 1, manifest: entry.sealed, manifestSeq: 7, manifestPrev: entry.prev),
                                            key: made.key, remembered: nil, rows: after).status, .mismatch)
        XCTAssertEqual(VaultManifest.verify(row, key: made.key, remembered: nil, rows: w.rows).status, .mismatch)
        // A vault without a manifest gets none; one whose manifest can't be named isn't replaced.
        XCTAssertNil(try VaultManifest.rotation(try w.header(seq: 0, sealed: nil), newKey: made.key, nextEpoch: 2, rows: w.rows, items: items))
        XCTAssertThrowsError(try VaultManifest.rotation(try w.header(seq: 6, sealed: m6.sealed, prev: nil), newKey: made.key, nextEpoch: 2, rows: w.rows, items: items))
        XCTAssertThrowsError(try VaultManifest.rotation(old, newKey: made.key, nextEpoch: nil, rows: w.rows, items: items))
    }

    // MARK: Emergency access

    func testTheEmergencyViewReadsTheVaultsManifest() {
        let answer: JSON = ["key_version": 2, "sealed_key": "SK",
                            "items": [["id": "i1", "vault_id": "v1", "item_key": "k", "data": "d", "deleted_at": nil, "updated_at": 5],
                                      // Rows that can't be shown: a hash in place of the data, no key.
                                      ["id": "i2", "vault_id": "v1", "data_sha256": "HASH", "deleted_at": nil],
                                      ["id": "i3", "vault_id": "v2", "data": "d"]],
                            "vaults": [["id": "v1", "meta": "m", "wrapped_key": "w", "key_epoch": 3, "manifest": "SEALED", "manifest_seq": 5, "manifest_prev": "PREV"],
                                       ["id": "v2", "meta": "m", "wrapped_key": "w"]]]
        let data = Emergency.readGrantorVault(answer)
        XCTAssertEqual(data?.vaults.map(\.manifestSeq), [5, 0])
        XCTAssertEqual(data?.vaults.first?.manifest, "SEALED")
        XCTAssertEqual(data?.vaults.first?.manifestPrev, "PREV")
        XCTAssertNil(data?.vaults.last?.manifestPrev)
        XCTAssertEqual(data?.vaults.first?.keyEpoch, 3)
        XCTAssertEqual(data?.items.map(\.id), ["i1"])
        XCTAssertEqual(data?.incomplete, ["v1", "v2"], "a vault with a row that can't be shown is never 'checked'")
    }

    // MARK: Part S

    func testAServerWithoutSignedSharingIsRefused() {
        XCTAssertEqual(ServerSupport.updateServer, "Update your PassAuth server to keep using this app.")
        XCTAssertEqual(ServerSupport.unreachable, "PassAuth couldn't reach your server. Check the connection and try again.")
        // API 2 without the feature, and a server from before API 2 (no features at all).
        XCTAssertTrue(ServerSupport.refused(features: ["delta_sync", "key_epoch"]))
        XCTAssertTrue(ServerSupport.refused(features: []))
        XCTAssertFalse(ServerSupport.refused(features: ["delta_sync", signedSharingFeature]))
        // Nothing kept isn't a refusal by itself: the server is asked, and not used without an answer.
        XCTAssertFalse(ServerSupport.refused(features: nil))
        XCTAssertEqual(PublicConfig(json: ["name": "PassAuth"]).map { ServerSupport.refused(features: $0.features) }, true)
        XCTAssertEqual(PublicConfig(json: ["name": "PassAuth", "api": 2, "features": ["signed_sharing", "vault_manifest"]]).map { ServerSupport.refused(features: $0.features) }, false)
    }

    /// With signed sharing's checks on, a legacy (not epoch-bound) wrap of a vault key is only
    /// opened where the key pins allow it. When the pins can't be asked (the core fails on
    /// them) the wrap is refused, never allowed.
    func testALegacyWrapIsRefusedWhenThePinsCannotBeAsked() throws {
        let created = try createAccount(accountId: try newId(), password: "correct horse battery staple", withSecretKey: false)
        let vid = try newId()
        let legacy = try created.account.newVaultKey(vaultId: vid)
        XCTAssertFalse(accountWrapIsBound(wrapped: legacy.wrapped))
        let snap = SyncSnapshot(revision: 1, cursor: nil, user: nil, bundle: nil, vaults: [SyncVault(id: vid, wrappedKey: legacy.wrapped, keyEpoch: 1)], items: [])
        XCTAssertThrowsError(try pinsLegacyWrapAllowed(pinsJson: "not key pins", vaultId: vid, keyEpoch: 1))
        func sharing(_ pins: String?) -> SharingInputs {
            SharingInputs(me: SharingSelf(identity: "", userId: "me", signingHash: nil, paused: false), pins: pins, pinsChanged: false,
                          memory: SharingMemoryRecord(), fetched: [:], tooLarge: [], now: 1_800_000_000)
        }
        XCTAssertTrue(VaultRepository.open(created.account, snap, previous: nil, sharing: sharing("not key pins")).keys.isEmpty, "not opened")
        // Without the checks (a server from before signed sharing, in tests only) it opens as before.
        XCTAssertEqual(VaultRepository.open(created.account, snap, previous: nil).keys.count, 1)
    }

    func testTheWordingIsTheSameInEveryApp() {
        XCTAssertEqual(ManifestText.warning, "Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date.")
        XCTAssertEqual(ManifestText.action, "Use the server's copy")
        XCTAssertEqual(ManifestText.confirmTitle, "Use the server's copy?")
        XCTAssertEqual(ManifestText.confirmBody, "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. Do this only if you know why it changed, for example after the server was restored from a backup.")
        XCTAssertEqual(ManifestText.reader, "Someone who can edit this vault can review it.")
        XCTAssertEqual(ManifestText.held, "This vault can't be changed until its warning is resolved.")
        XCTAssertEqual(ManifestText.busy, "This vault changed on another device. Try again.")
        XCTAssertEqual(ManifestText.notReady, "This can't be done until every member's apps are up to date.")
        XCTAssertEqual(ItemRollback.itemWarning, "Your server sent an older version of this item.")
        XCTAssertEqual(ManifestText.unchecked, "PassAuth couldn't check this vault with your server yet. Try again in a moment.")
        XCTAssertEqual(ManifestText.viewUnchecked, "This vault has no record of changes yet, so PassAuth couldn't check that nothing is missing or out of date.")
        XCTAssertEqual(ManifestText.reviewElsewhere, "Open the web vault or the desktop app to review this vault.")
        XCTAssertEqual(ManifestText.unopenable, "An item in this vault can't be opened. Delete it to keep using the vault.")
        XCTAssertEqual(ManifestText.unopenableReader, "An item in this vault can't be opened. Someone who can edit this vault can delete it.")
        XCTAssertEqual(ManifestText.unopenableItem, "Item that can't be opened")
        XCTAssertEqual(ManifestText.deleteForGood, "Delete for good")
        XCTAssertEqual(ManifestText.deleteConfirm, "This item can't be opened on this device. Deleting it removes it for everyone.")
        XCTAssertEqual(ManifestText.memoryUnreadable, "PassAuth can't read this device's record of your vaults.")
        XCTAssertEqual(ManifestText.memoryReset, "Reset on this device")
        XCTAssertEqual(ManifestText.memoryResetConfirm, "PassAuth will trust what your server shows now and start a new record on this device.")
        XCTAssertEqual(VaultRepository.sendPasswordNeeded, "Enter this Send's password to change its text.")
    }
}
