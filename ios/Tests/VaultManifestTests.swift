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

        func header(seq: Int64, sealed: String?, epoch: Int64 = 1, ok: Bool? = nil, vaultSeq: Int64? = 7, role: String = "owner") throws -> SyncVault {
            SyncVault(id: vaultId, meta: try key.encryptMeta(vaultId: vaultId, metaJson: #"{"name":"Personal"}"#), role: role, wrappedKey: wrapped,
                      keyEpoch: epoch, seq: vaultSeq, manifest: sealed, manifestSeq: seq, manifestOk: ok)
        }

        func sealed(_ version: UInt64, epoch: UInt64 = 1, rows other: [SyncItem]? = nil) throws -> String {
            try key.manifestStart(vaultId: vaultId, keyEpoch: epoch, version: version, itemsJson: VaultManifest.rowsJson(other ?? rows))
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

    // MARK: What a write carries

    func testAnEntryInABodyAndInAQuery() {
        let e = ManifestEntry(vaultId: "v1", seq: 8, sealed: "AbC-_9")
        XCTAssertEqual(e.json, ["vault_id": "v1", "seq": 8, "sealed": "AbC-_9"])
        XCTAssertEqual(e.query, "manifest_seq=8&manifest=AbC-_9")
        XCTAssertEqual(ManifestEntry(vaultId: "v1", seq: 2, sealed: "a&b=c").query, "manifest_seq=2&manifest=a%26b%3Dc", "a sealed text can't add parameters")
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
        let sealed = try w.sealed(3)
        let row = try w.header(seq: 3, sealed: sealed)
        func check(_ v: SyncVault, _ remembered: UInt64?, _ rows: [SyncItem]) -> String {
            let c = VaultManifest.verify(v, key: w.key, remembered: remembered, rows: rows)
            return "\(c.status.rawValue) \(c.version)"
        }
        XCTAssertEqual(check(row, nil, w.rows), "ok 3")
        XCTAssertEqual(check(row, 2, w.rows), "ok 3")
        XCTAssertEqual(check(row, 3, w.rows.reversed()), "ok 3", "the order doesn't matter")
        // Trashed rows held without their data are checked by its hash.
        XCTAssertEqual(check(row, nil, w.rows.map { $0.deletedAt == nil ? $0 : summary($0) }), "ok 3")
        // An older manifest than this device saw, or none after one was seen.
        XCTAssertEqual(check(row, 4, w.rows), "rollback 4")
        XCTAssertEqual(check(try w.header(seq: 0, sealed: nil), 1, w.rows), "rollback 1")
        // No manifest, none seen: nothing to check (not even with a sealed text sent along).
        XCTAssertEqual(check(try w.header(seq: 0, sealed: nil), nil, w.rows), "none 0")
        XCTAssertEqual(check(try w.header(seq: 0, sealed: sealed), nil, w.rows), "none 0")
        XCTAssertEqual(check(SyncVault(id: w.vaultId), nil, w.rows), "none 0", "an older server's row")
        // Hidden, brought back, moved between live and trash, older data.
        XCTAssertEqual(check(row, nil, Array(w.rows.dropFirst())), "mismatch 0")
        var extra = w.rows
        extra.append(SyncItem(id: try newId(), vaultId: w.vaultId, itemKey: "k", data: "old", deletedAt: nil))
        XCTAssertEqual(check(row, 3, extra), "mismatch 3")
        var restored = w.rows
        restored[2].deletedAt = nil
        XCTAssertEqual(check(row, nil, restored), "mismatch 0")
        var older = w.rows
        older[0].data = (older[0].data ?? "") + "x"
        XCTAssertEqual(check(row, nil, older), "mismatch 0")
        // A manifest that doesn't open for this key, vault, epoch and version.
        XCTAssertEqual(check(try w.header(seq: 3, sealed: nil), nil, w.rows), "mismatch 0")
        XCTAssertEqual(check(try w.header(seq: 4, sealed: sealed), nil, w.rows), "mismatch 0")
        XCTAssertEqual(check(try w.header(seq: 3, sealed: sealed, epoch: 2), nil, w.rows), "mismatch 0")
        XCTAssertEqual(check(try w.header(seq: 3, sealed: "garbage"), nil, w.rows), "mismatch 0")
        // A row that can't be checked yet; an id twice is an error, which is a mismatch.
        var bare = w.rows
        bare[2].data = nil
        bare[2].itemKey = nil
        XCTAssertEqual(check(row, nil, bare), "incomplete 0")
        XCTAssertEqual(check(row, 2, w.rows + [w.rows[0]]), "mismatch 2")
    }

    func testTheMemoryIsRaisedOnlyByAnOkCheckAndNeverLowered() {
        var m: [String: UInt64] = ["a": 5]
        VaultManifest.remember(&m, vault: "a", status: .ok, version: 7)
        VaultManifest.remember(&m, vault: "b", status: .ok, version: 2)
        XCTAssertEqual(m, ["a": 7, "b": 2])
        VaultManifest.remember(&m, vault: "a", status: .ok, version: 3)
        XCTAssertEqual(m["a"], 7, "never lowered")
        for s in [ManifestStatus.rollback, .mismatch, .incomplete, .none] {
            VaultManifest.remember(&m, vault: "a", status: s, version: 99)
            VaultManifest.remember(&m, vault: "c", status: s, version: 99)
        }
        XCTAssertEqual(m, ["a": 7, "b": 2], "nothing is remembered unless the check was ok")
        // The app and an AutoFill extension both write it: the higher number per vault; vaults
        // that are gone stay.
        XCTAssertEqual(VaultManifest.merged(["a": 7, "gone": 4], ["a": 6, "b": 9]), ["a": 7, "b": 9, "gone": 4])
        XCTAssertTrue(ManifestStatus.rollback.unresolved && ManifestStatus.mismatch.unresolved && ManifestStatus.incomplete.unresolved)
        XCTAssertFalse(ManifestStatus.ok.unresolved || ManifestStatus.none.unresolved)
        XCTAssertTrue(ManifestStatus.rollback.warns && ManifestStatus.mismatch.warns)
        XCTAssertFalse(ManifestStatus.incomplete.warns, "rows that can't be checked yet are fetched first, not warned about")
    }

    // MARK: Decrypting a copy checks every vault

    func testOpeningACopyChecksItsVaultsAndRemembersVersions() throws {
        let w = try world()
        let sealed = try w.sealed(3)
        func open(_ v: SyncVault, _ rows: [SyncItem], _ memory: [String: UInt64]?, final: Bool = false) -> (ManifestStatus?, [String: UInt64]?) {
            let snap = SyncSnapshot(revision: 5, cursor: "c", user: nil, bundle: nil, vaults: [v], items: rows)
            let o = VaultRepository.open(w.account, snap, previous: nil, manifests: memory, finalIncomplete: final)
            return (o.data.vaults.first?.manifest, o.manifests)
        }
        var r = open(try w.header(seq: 3, sealed: sealed), w.rows, [:])
        XCTAssertEqual(r.0, .ok)
        XCTAssertEqual(r.1, [w.vaultId: 3])
        // A vault this device saw at version 5 served at 3: rollback, the memory untouched.
        r = open(try w.header(seq: 3, sealed: sealed), w.rows, [w.vaultId: 5, "other": 2])
        XCTAssertEqual(r.0, .rollback)
        XCTAssertEqual(r.1, [w.vaultId: 5, "other": 2])
        // An item hidden: mismatch, nothing remembered.
        r = open(try w.header(seq: 3, sealed: sealed), Array(w.rows.dropLast()), [:])
        XCTAssertEqual(r.0, .mismatch)
        XCTAssertEqual(r.1, [:])
        // No manifest: nothing to check. Not checked at all without a memory (nil).
        r = open(try w.header(seq: 0, sealed: nil), w.rows, [:])
        XCTAssertEqual(r.0, ManifestStatus.none)
        r = open(try w.header(seq: 3, sealed: sealed), Array(w.rows.dropLast()), nil)
        XCTAssertEqual(r.0, ManifestStatus.none)
        XCTAssertNil(r.1)
        // A summary row from before the hashes: incomplete until everything was fetched once,
        // then a mismatch.
        var bare = w.rows
        bare[2].data = nil
        bare[2].itemKey = nil
        XCTAssertEqual(open(try w.header(seq: 3, sealed: sealed), bare, [:]).0, .incomplete)
        r = open(try w.header(seq: 3, sealed: sealed), bare, [:], final: true)
        XCTAssertEqual(r.0, .mismatch)
        XCTAssertEqual(r.1, [:])
        // With the hash the trashed row is checked without its data (and isn't shown).
        var hashed = w.rows
        hashed[2] = summary(hashed[2])
        XCTAssertEqual(open(try w.header(seq: 3, sealed: sealed), hashed, [:]).0, .ok)
    }

    // MARK: Starting, a new baseline, old trash

    func testWhenAFirstManifestIsStarted() throws {
        let w = try world()
        let features = [vaultManifestFeature, "delta_sync"]
        let ready = try w.header(seq: 0, sealed: nil, ok: true)
        func start(_ v: SyncVault, role: Role = .owner, status: ManifestStatus = .none, remembered: UInt64? = nil, rows: [SyncItem]? = nil,
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
        XCTAssertFalse(start(ready, remembered: 4), "this device saw one: that is a rollback, not a start")
        XCTAssertFalse(start(ready, status: .rollback))
        XCTAssertFalse(start(try w.header(seq: 0, sealed: nil, ok: true, vaultSeq: nil)), "pinned to the vault's number")
        var bare = w.rows
        bare[2].data = nil
        XCTAssertFalse(start(ready, rows: bare), "every row must be in it")
        bare[2].dataSha256 = "h"
        XCTAssertTrue(start(ready, rows: bare))
    }

    func testABaselineIsAboveTheRowAndAboveWhatThisDeviceRemembers() {
        XCTAssertEqual(VaultManifest.baselineSeq(row: 5, remembered: nil), 6)
        XCTAssertEqual(VaultManifest.baselineSeq(row: 5, remembered: 3), 6)
        XCTAssertEqual(VaultManifest.baselineSeq(row: 5, remembered: 9), 10)
        XCTAssertEqual(VaultManifest.baselineSeq(row: 0, remembered: 4), 5, "the manifest vanished")
        XCTAssertEqual(VaultManifest.baselineSeq(row: 0, remembered: nil), 1)
    }

    func testTrashIsDueByTheServersClockAndRetention() {
        let day: Int64 = 86400
        let now: Int64 = 1_800_000_000
        let rows = [
            SyncItem(id: "live", vaultId: "v", itemKey: "k", data: "d", deletedAt: nil),
            SyncItem(id: "old", vaultId: "v", itemKey: "k", data: "d", deletedAt: now - 31 * day),
            SyncItem(id: "edge", vaultId: "v", itemKey: "k", data: "d", deletedAt: now - 30 * day),
            SyncItem(id: "new", vaultId: "v", itemKey: "k", data: "d", deletedAt: now - 3 * day),
        ]
        func due(_ time: Int64?, _ days: Int64?) -> [String] { VaultManifest.dueTrash(rows, serverTime: time, trashDays: days).map(\.id) }
        XCTAssertEqual(due(now, 30), ["old"], "strictly older than the retention")
        XCTAssertEqual(due(now, 1), ["old", "edge", "new"])
        XCTAssertEqual(due(now, 0), [], "0 = kept forever")
        XCTAssertEqual(due(nil, 30), [], "never by the device's clock")
        XCTAssertEqual(due(now, nil), [])
        XCTAssertEqual(due(now, -1), [])
        XCTAssertEqual(due(now, Int64.max), [])
    }

    // MARK: The copy carries the new fields

    func testTheNewFieldsGoThroughAnAnswerADeltaAndTheStoredCopy() throws {
        let full = Data("""
        {"revision":5,"cursor":"c1","server_time":1800000000,"trash_days":30,
         "vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account","key_epoch":2,"seq":4,
                    "manifest":"SEALED","manifest_seq":9,"manifest_ok":true}],
         "items":[{"id":"i1","vault_id":"v1","item_key":"k","data":"d","revision":3,"deleted_at":null},
                  {"id":"i2","vault_id":"v1","revision":4,"deleted_at":1700000000,"data_sha256":"HASH"}]}
        """.utf8)
        let snap = try XCTUnwrap(SyncSnapshot.decode(full))
        XCTAssertEqual(snap.vaults[0].manifest, "SEALED")
        XCTAssertEqual(snap.vaults[0].manifestSeq, 9)
        XCTAssertEqual(snap.vaults[0].manifestOk, true)
        XCTAssertEqual(snap.vaults[0].manifestVersion, 9)
        XCTAssertEqual(snap.items[1].dataSha256, "HASH")
        XCTAssertNil(snap.items[0].dataSha256)
        XCTAssertEqual(snap.serverTime, 1_800_000_000)
        XCTAssertEqual(snap.trashDays, 30)
        // Stored and read again: the rows and their manifest stay together (the server's clock
        // of that answer isn't kept: old trash is only deleted right after a sync).
        let stored = try XCTUnwrap(SyncSnapshot.decode(try snap.encoded()))
        XCTAssertEqual(stored.vaults, snap.vaults)
        XCTAssertEqual(stored.items, snap.items)
        XCTAssertNil(stored.serverTime)
        // A delta: the vault row's new manifest and a trashed summary row with its hash.
        let delta = try JSONDecoder().decode(SyncResponse.self, from: Data("""
        {"delta":true,"revision":6,"cursor":"c2","server_time":1800000100,"trash_days":7,
         "vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account","key_epoch":2,"seq":5,
                    "manifest":"NEXT","manifest_seq":10,"manifest_ok":true}],
         "items":[{"id":"i1","vault_id":"v1","revision":5,"deleted_at":1700000500,"data_sha256":"H1"}],"deleted":[],"reset":[]}
        """.utf8))
        let merged = try XCTUnwrap(SyncMerge.apply(delta, to: stored))
        XCTAssertEqual(merged.vaults[0].manifest, "NEXT")
        XCTAssertEqual(merged.vaults[0].manifestSeq, 10)
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: merged.items.map { ($0.id, $0.dataSha256) }), ["i1": "H1", "i2": "HASH"])
        XCTAssertEqual(merged.trashDays, 7)
        // A copy from before manifests reads as "no manifest".
        let old = try XCTUnwrap(SyncSnapshot.decode(Data(#"{"revision":1,"vaults":[{"id":"v1","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account"}],"items":[]}"#.utf8)))
        XCTAssertNil(old.vaults[0].manifestSeq)
        XCTAssertEqual(old.vaults[0].manifestVersion, 0)
    }

    func testAWriteAppliedToTheCopyTakesItsManifestAndASummaryRowKeepsItsHash() throws {
        let w = try world(live: 2, trashed: 0)
        let base = SyncSnapshot(revision: 5, cursor: "c", user: nil, bundle: nil, vaults: [try w.header(seq: 3, sealed: try w.sealed(3))], items: w.rows)
        // This device trashes the first item (an app that keeps trashed rows without data).
        var after = w.rows
        after[0].deletedAt = 1_800_000_000
        let next = try w.key.manifestNext(vaultId: w.vaultId, keyEpoch: 1, manifestSeq: 3, sealed: try w.sealed(3),
                                          removedJson: VaultManifest.rowsJson([w.rows[0]]), addedJson: VaultManifest.rowsJson([after[0]]))
        let sent = ManifestEntry(vaultId: w.vaultId, seq: next.seq, sealed: next.sealed)
        XCTAssertEqual(sent.seq, 4)
        let applied = try XCTUnwrap(SyncMerge.applyLocal(.trash(id: w.rows[0].id, at: 1_800_000_000, revision: 4, summary: true),
                                                         vaultId: w.vaultId, vaultSeq: 8, manifest: sent, to: base))
        XCTAssertEqual(applied.vaults[0].seq, 8)
        XCTAssertEqual(applied.vaults[0].manifestSeq, 4)
        XCTAssertEqual(applied.vaults[0].manifest, sent.sealed)
        let row = try XCTUnwrap(applied.items.first { $0.id == w.rows[0].id })
        XCTAssertNil(row.data)
        XCTAssertNil(row.itemKey)
        XCTAssertEqual(row.dataSha256, VaultManifest.dataHash(try XCTUnwrap(w.rows[0].data)))
        // The copy still matches the manifest it now carries, also after it was stored and read.
        XCTAssertEqual(VaultManifest.verify(applied.vaults[0], key: w.key, remembered: 3, rows: applied.items).status, .ok)
        let stored = try XCTUnwrap(SyncSnapshot.decode(try applied.encoded()))
        XCTAssertEqual(VaultManifest.verify(stored.vaults[0], key: w.key, remembered: 4, rows: stored.items).status, .ok)
        // Without `summary` the row keeps its data and needs no hash.
        let kept = try XCTUnwrap(SyncMerge.applyLocal(.trash(id: w.rows[0].id, at: 1_800_000_000, revision: 4, summary: false),
                                                      vaultId: w.vaultId, vaultSeq: 8, manifest: sent, to: base))
        XCTAssertNotNil(kept.items.first { $0.id == w.rows[0].id }?.data)
        XCTAssertEqual(VaultManifest.verify(kept.vaults[0], key: w.key, remembered: nil, rows: kept.items).status, .ok)
        // A manifest for another vault is never put on this row; without one the row keeps its own.
        XCTAssertNil(SyncMerge.applyLocal(.purge(id: w.rows[1].id), vaultId: w.vaultId, vaultSeq: 8,
                                          manifest: ManifestEntry(vaultId: "other", seq: 4, sealed: "x"), to: base))
        XCTAssertEqual(SyncMerge.applyLocal(.purge(id: w.rows[1].id), vaultId: w.vaultId, vaultSeq: 8, to: base)?.vaults[0].manifestSeq, 3)
    }

    // MARK: Key replacement

    func testAKeyReplacementCarriesANewManifestUnderTheNewKeyAndEpoch() throws {
        let w = try world()
        let made = try w.account.newVaultKeyBound(vaultId: w.vaultId, keyEpoch: 2)
        let (items, _) = try VaultRepository.reencrypt(w.rows, vid: w.vaultId, name: "Personal", oldKey: w.key, newKey: made.key)
        let entry = try XCTUnwrap(try VaultRepository.rotationManifest(w.vaultId, newKey: made.key, nextEpoch: 2, manifestSeq: 6, rows: w.rows, items: items))
        XCTAssertEqual(entry.seq, 7)
        XCTAssertEqual(entry.vaultId, w.vaultId)
        // What the vault holds afterwards: every item where it was, with its new data.
        let after = zip(w.rows, items).map { r, item in SyncItem(id: r.id, vaultId: r.vaultId, itemKey: item.str("key"), data: item.str("data"), deletedAt: r.deletedAt) }
        let row = SyncVault(id: w.vaultId, keyEpoch: 2, manifest: entry.sealed, manifestSeq: 7)
        XCTAssertEqual(VaultManifest.verify(row, key: made.key, remembered: 6, rows: after).status, .ok)
        // Not under the old key, the old epoch, or over the old data.
        XCTAssertEqual(VaultManifest.verify(row, key: w.key, remembered: nil, rows: after).status, .mismatch)
        XCTAssertEqual(VaultManifest.verify(SyncVault(id: w.vaultId, keyEpoch: 1, manifest: entry.sealed, manifestSeq: 7), key: made.key, remembered: nil, rows: after).status, .mismatch)
        XCTAssertEqual(VaultManifest.verify(row, key: made.key, remembered: nil, rows: w.rows).status, .mismatch)
        // A vault without a manifest gets none.
        XCTAssertNil(try VaultRepository.rotationManifest(w.vaultId, newKey: made.key, nextEpoch: 2, manifestSeq: 0, rows: w.rows, items: items))
    }

    // MARK: Emergency access

    func testTheEmergencyViewReadsTheVaultsManifest() {
        let answer: JSON = ["key_version": 2, "sealed_key": "SK", "items": [],
                            "vaults": [["id": "v1", "meta": "m", "wrapped_key": "w", "key_epoch": 3, "manifest": "SEALED", "manifest_seq": 5],
                                       ["id": "v2", "meta": "m", "wrapped_key": "w"]]]
        let data = Emergency.readGrantorVault(answer)
        XCTAssertEqual(data?.vaults.map(\.manifestSeq), [5, 0])
        XCTAssertEqual(data?.vaults.first?.manifest, "SEALED")
        XCTAssertEqual(data?.vaults.first?.keyEpoch, 3)
    }

    // MARK: Part S

    func testAServerWithoutSignedSharingIsRefused() {
        XCTAssertEqual(ServerSupport.updateServer, "Update your PassAuth server to keep using this app.")
        // API 2 without the feature, and a server from before API 2 (no features at all).
        XCTAssertTrue(ServerSupport.refused(features: ["delta_sync", "key_epoch"]))
        XCTAssertTrue(ServerSupport.refused(features: []))
        XCTAssertFalse(ServerSupport.refused(features: ["delta_sync", signedSharingFeature]))
        // A config that couldn't be fetched is not a refusal.
        XCTAssertFalse(ServerSupport.refused(features: nil))
        XCTAssertEqual(PublicConfig(json: ["name": "PassAuth"]).map { ServerSupport.refused(features: $0.features) }, true)
        XCTAssertEqual(PublicConfig(json: ["name": "PassAuth", "api": 2, "features": ["signed_sharing", "vault_manifest"]]).map { ServerSupport.refused(features: $0.features) }, false)
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
    }
}
