import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// The offline change list's rules (docs/ARCHITECTURE.md "Offline changes"): the stored shape,
/// one change per item, when a save waits, what is sent, conflicts, holds and what is shown.
final class OfflineChangesTests: XCTestCase {
    private func item(_ name: String, password: String = "pw") -> JSON {
        var i = Item.empty(.login, now: 1_700_000_000)
        i.name = name
        i.login?.password = password
        return try! JSON.parse(ItemCodec.encode(i))
    }

    private func change(_ kind: OfflineKind, item id: String = "item-1", base: Int64? = 3, name: String = "A",
                        sent: OfflineSent? = nil, at: Int64 = 1) -> OfflineChange {
        OfflineChange(id: "c-\(kind.rawValue)-\(at)", kind: kind, vaultId: "v1", itemId: id, baseRevision: kind == .create ? nil : base,
                      item: kind == .trash ? nil : item(name), sent: sent, createdAt: at)
    }

    // MARK: The stored shape

    func testListShapeHasEveryFieldWithNulls() throws {
        let list = OfflineChangeList(changes: [change(.trash)])
        let j = try JSON.parse(list.encoded())
        XCTAssertEqual(j["version"], .int(1))
        guard case .array(let changes)? = j["changes"], case .object(let c)? = changes.first else { return XCTFail("changes") }
        XCTAssertEqual(Set(c.keys), ["id", "kind", "vault_id", "item_id", "base_revision", "item", "sent", "created_at", "state", "reason"])
        XCTAssertEqual(c["kind"], .string("trash"))
        XCTAssertEqual(c["item"], .null)
        XCTAssertEqual(c["sent"], .null)
        XCTAssertEqual(c["reason"], .null)
        XCTAssertEqual(c["state"], .string("waiting"))
        XCTAssertEqual(c["base_revision"], .int(3))
    }

    func testListRoundTripsWithSentAndCreateWithoutBase() throws {
        var c = change(.create, sent: OfflineSent(key: "k", data: "d", keyEpoch: nil))
        c.state = .held
        c.reason = "Nope"
        let back = try OfflineChangeList.decode(OfflineChangeList(changes: [c]).encoded())
        XCTAssertEqual(back.changes, [c])
        XCTAssertNil(back.changes[0].baseRevision)
        let sent = try JSON.parse(OfflineChangeList(changes: [c]).encoded())["changes"]
        guard case .array(let a)? = sent else { return XCTFail() }
        XCTAssertEqual(a[0]["sent"]?["key_epoch"], .null)
        XCTAssertEqual(a[0]["base_revision"], .null)
    }

    func testOtherListVersionIsRefused() {
        XCTAssertThrowsError(try OfflineChangeList.decode(#"{"version":2,"changes":[]}"#))
    }

    // MARK: When a save waits

    func testNoAnswerWaits() {
        XCTAssertTrue(OfflineQueue.waits(UserError(cantReachServerMessage)))
        XCTAssertTrue(OfflineQueue.waits(URLError(.timedOut)))
        for s in [502, 503, 504] { XCTAssertTrue(OfflineQueue.waits(ApiError(status: s, code: "error", message: "")), "\(s)") }
    }

    func testAnswersDontWait() {
        for s in [400, 401, 403, 404, 409, 413, 429, 500, 507] {
            XCTAssertFalse(OfflineQueue.waits(ApiError(status: s, code: "error", message: "")), "\(s)")
        }
        XCTAssertFalse(OfflineQueue.waits(UserError("Something else")))
    }

    // MARK: One change per item

    func testNewChangeIsAdded() throws {
        let out = try OfflineQueue.merge([change(.edit, item: "x")], change(.create, item: "y"))
        XCTAssertEqual(out.map(\.itemId), ["x", "y"])
    }

    func testCreateThenEditIsCreateWithTheNewItem() throws {
        let out = try OfflineQueue.merge([change(.create, name: "Old")], change(.edit, name: "New", at: 2))
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].kind, .create)
        XCTAssertNil(out[0].baseRevision)
        XCTAssertEqual(out[0].decodedItem?.name, "New")
        XCTAssertEqual(out[0].createdAt, 1, "keeps its place (oldest first)")
    }

    func testEditThenEditKeepsTheFirstBase() throws {
        let out = try OfflineQueue.merge([change(.edit, base: 3, name: "One")], change(.edit, base: 9, name: "Two", at: 2))
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].kind, .edit)
        XCTAssertEqual(out[0].baseRevision, 3)
        XCTAssertEqual(out[0].decodedItem?.name, "Two")
    }

    func testEditThenTrashIsTrashWithTheFirstBase() throws {
        let out = try OfflineQueue.merge([change(.edit, base: 3)], change(.trash, base: 9, at: 2))
        XCTAssertEqual(out[0].kind, .trash)
        XCTAssertEqual(out[0].baseRevision, 3)
        XCTAssertNil(out[0].item)
    }

    func testCreateThenTrashRemovesTheChange() throws {
        let out = try OfflineQueue.merge([change(.create), change(.edit, item: "other")], change(.trash, at: 2))
        XCTAssertEqual(out.map(\.itemId), ["other"], "nothing reaches the server")
    }

    func testSentCreateThenTrashBecomesTrashWithoutBase() throws {
        let sent = OfflineSent(key: "k", data: "d", keyEpoch: 1)
        let out = try OfflineQueue.merge([change(.create, sent: sent)], change(.trash, at: 2))
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].kind, .trash)
        XCTAssertNil(out[0].baseRevision)
        XCTAssertEqual(out[0].sent, sent)
        XCTAssertNil(out[0].item)
    }

    func testTrashedItemCantBeEditedOffline() {
        XCTAssertThrowsError(try OfflineQueue.merge([change(.trash)], change(.edit, at: 2))) {
            XCTAssertEqual($0 as? OfflineQueue.MergeError, .trashed)
        }
        XCTAssertEqual(try OfflineQueue.merge([change(.trash)], change(.trash, at: 2)), [change(.trash)])
    }

    func testMergedChangeWaitsAgain() throws {
        var held = change(.edit)
        held.state = .conflict
        held.reason = OfflineText.changedText
        let out = try OfflineQueue.merge([held], change(.edit, name: "B", at: 2))
        XCTAssertEqual(out[0].state, .waiting)
        XCTAssertNil(out[0].reason)
    }

    func testAtMost500Changes() throws {
        let full = (0..<500).map { change(.edit, item: "i\($0)", at: Int64($0)) }
        XCTAssertThrowsError(try OfflineQueue.merge(full, change(.create, item: "new"))) {
            XCTAssertEqual($0 as? OfflineQueue.MergeError, .tooMany)
        }
        XCTAssertEqual(OfflineQueue.MergeError.tooMany.text, "Too many changes are waiting. Connect to the internet before making more.")
        // A change to an item that already has one still merges.
        XCTAssertEqual(try OfflineQueue.merge(full, change(.edit, item: "i7", name: "Z", at: 900)).count, 500)
    }

    // MARK: Sending: create

    func testCreateWithoutServerRowIsPosted() {
        XCTAssertEqual(OfflineQueue.decide(change(.create), row: nil, hold: nil), .post)
    }

    func testCreateWhoseSentDataIsStoredIsDone() {
        let c = change(.create, sent: OfflineSent(key: "k", data: "D", keyEpoch: nil))
        XCTAssertEqual(OfflineQueue.decide(c, row: OfflineServerRow(revision: 1, data: "D", trashed: false), hold: nil), .done)
        // Edited again after that attempt: the landed row is edited with the newer content.
        XCTAssertEqual(OfflineQueue.decide(c, row: OfflineServerRow(revision: 1, data: "D", trashed: false), hold: nil, sentMatches: false), .edit(revision: 1))
    }

    func testCreateWhoseIdHoldsAnotherItemGetsANewId() {
        let c = change(.create, sent: OfflineSent(key: "k", data: "D", keyEpoch: nil))
        XCTAssertEqual(OfflineQueue.decide(c, row: OfflineServerRow(revision: 1, data: "X", trashed: false), hold: nil), .newId)
        XCTAssertEqual(OfflineQueue.decide(change(.create), row: OfflineServerRow(revision: 1, data: "X", trashed: false), hold: nil), .newId)
    }

    // MARK: Sending: edit

    func testEditAtTheBaseRevisionIsSent() {
        XCTAssertEqual(OfflineQueue.decide(change(.edit, base: 3), row: OfflineServerRow(revision: 3, data: "X", trashed: false), hold: nil), .edit(revision: 3))
    }

    func testEditOfADeletedItemIsAConflict() {
        XCTAssertEqual(OfflineQueue.decide(change(.edit), row: nil, hold: nil), .conflict(.deleted))
    }

    func testEditWhoseSentDataIsStoredIsDone() {
        let c = change(.edit, base: 3, sent: OfflineSent(key: "k", data: "D", keyEpoch: 1))
        XCTAssertEqual(OfflineQueue.decide(c, row: OfflineServerRow(revision: 4, data: "D", trashed: false), hold: nil), .done)
    }

    func testEditOfAChangedItemIsAConflict() {
        XCTAssertEqual(OfflineQueue.decide(change(.edit, base: 3), row: OfflineServerRow(revision: 4, data: "X", trashed: false), hold: nil),
                       .conflict(.changed))
    }

    // MARK: Sending: trash

    func testTrashOfAGoneOrTrashedItemIsDone() {
        XCTAssertEqual(OfflineQueue.decide(change(.trash), row: nil, hold: nil), .done)
        XCTAssertEqual(OfflineQueue.decide(change(.trash, base: 3), row: OfflineServerRow(revision: 8, data: nil, trashed: true), hold: nil), .done)
    }

    func testTrashAtTheBaseRevisionIsSent() {
        XCTAssertEqual(OfflineQueue.decide(change(.trash, base: 3), row: OfflineServerRow(revision: 3, data: "X", trashed: false), hold: nil),
                       .trash(revision: 3))
    }

    func testTrashOfASentCreateIsSentWhenTheDataIsItsOwn() {
        var c = change(.trash, sent: OfflineSent(key: "k", data: "D", keyEpoch: nil))
        c.baseRevision = nil
        XCTAssertEqual(OfflineQueue.decide(c, row: OfflineServerRow(revision: 2, data: "D", trashed: false), hold: nil), .trash(revision: 2))
        XCTAssertEqual(OfflineQueue.decide(c, row: OfflineServerRow(revision: 2, data: "X", trashed: false), hold: nil), .conflict(.trash))
    }

    func testTrashOfAChangedItemIsAConflict() {
        XCTAssertEqual(OfflineQueue.decide(change(.trash, base: 3), row: OfflineServerRow(revision: 5, data: "X", trashed: false), hold: nil),
                       .conflict(.trash))
    }

    // MARK: Holds

    func testHeldVaultsAreNeverSentInto() {
        let row = OfflineServerRow(revision: 3, data: "X", trashed: false)
        for k in [OfflineKind.create, .edit, .trash] {
            XCTAssertEqual(OfflineQueue.decide(change(k), row: k == .create ? nil : row, hold: "why"), .hold("why"))
        }
    }

    func testHoldReasons() {
        var ok = VaultInfo(id: "v1", name: "Mine", role: .owner, manifest: .ok)
        XCTAssertNil(OfflineQueue.holdReason(vaultId: "v1", vaults: [ok], refused: []))
        XCTAssertEqual(OfflineQueue.holdReason(vaultId: "gone", vaults: [ok], refused: []), OfflineText.goneVault)
        XCTAssertEqual(OfflineQueue.holdReason(vaultId: "r", vaults: [ok], refused: [RefusedVault(id: "r", name: nil, reason: .unverified)]),
                       OfflineText.refusedVault)
        XCTAssertEqual(OfflineQueue.holdReason(vaultId: "v1", vaults: [VaultInfo(id: "v1", name: "S", role: .read)], refused: []), OfflineText.readOnly)
        ok.manifest = .mismatch
        XCTAssertEqual(OfflineQueue.holdReason(vaultId: "v1", vaults: [ok], refused: []), ManifestText.held)
        ok.manifest = .rollback
        XCTAssertEqual(OfflineQueue.holdReason(vaultId: "v1", vaults: [ok], refused: []), ManifestText.held)
        ok.manifest = .unchecked
        XCTAssertEqual(OfflineQueue.holdReason(vaultId: "v1", vaults: [ok], refused: []), ManifestText.unchecked)
        ok.manifest = .none
        XCTAssertNil(OfflineQueue.holdReason(vaultId: "v1", vaults: [ok], refused: []))
    }

    // MARK: Errors while sending

    func testErrorsWhileSending() {
        XCTAssertEqual(OfflineQueue.afterError(UserError(cantReachServerMessage), tries: 1), .stop)
        XCTAssertEqual(OfflineQueue.afterError(ApiError(status: 503, code: "error", message: ""), tries: 1), .stop)
        let rev = ApiError(status: 409, code: "revision_conflict", message: "")
        XCTAssertEqual(OfflineQueue.afterError(rev, tries: 1), .redecide)
        XCTAssertEqual(OfflineQueue.afterError(rev, tries: 3), .conflict, "at most 3 times, then a conflict")
        let manifest = ApiError(status: 409, code: "manifest_conflict", message: "")
        XCTAssertEqual(OfflineQueue.afterError(manifest, tries: 2), .retry)
        XCTAssertEqual(OfflineQueue.afterError(manifest, tries: 3), .hold(ManifestText.busy), "at most 3 times, then held")
        let key = ApiError(status: 409, code: "vault_key_changed", message: "")
        XCTAssertEqual(OfflineQueue.afterError(key, tries: 1), .retry)
        XCTAssertEqual(OfflineQueue.afterError(key, tries: 3), .hold(ManifestText.busy))
        XCTAssertEqual(OfflineQueue.afterError(ApiError(status: 409, code: "item_exists", message: ""), tries: 1), .redecide)
        let quota = ApiError(status: 403, code: "quota_exceeded", message: "")
        XCTAssertEqual(OfflineQueue.afterError(quota, tries: 1), .hold(quotaExceededMessage), "any other error: held with the app's wording")
        XCTAssertEqual(OfflineQueue.afterError(ApiError(status: 507, code: "insufficient_storage", message: ""), tries: 1), .hold(outOfStorageMessage))
    }

    // MARK: Conflicts

    func testConflictKindsAndChoices() {
        XCTAssertEqual(OfflineQueue.conflictKind(change(.edit), serverHasItem: true), .changed)
        XCTAssertEqual(OfflineQueue.conflictKind(change(.edit), serverHasItem: false), .deleted)
        XCTAssertEqual(OfflineQueue.conflictKind(change(.trash), serverHasItem: true), .trash)
        XCTAssertEqual(OfflineQueue.choices(.changed), [.keepMine, .keepOther, .keepBoth])
        XCTAssertEqual(OfflineQueue.choices(.deleted), [.saveAsNew, .discardMine])
        XCTAssertEqual(OfflineQueue.choices(.trash), [.trashAnyway, .keepOther])
        XCTAssertEqual(OfflineChoice.allCases.map(\.title),
                       ["Keep mine", "Keep the other", "Keep both", "Save mine as a new item", "Discard mine", "Move to trash anyway"])
    }

    func testKeepBothNamesTheCopy() {
        var i = Item(name: "Bank")
        i.rev = 7
        let copy = OfflineQueue.copyItem(i)
        XCTAssertEqual(copy.name, "Bank (offline copy)")
        XCTAssertEqual(copy.rev, 0)
    }

    func testSameContentIgnoresTheCounter() {
        var a = Item(name: "A")
        var b = a
        b.rev = 4
        XCTAssertTrue(OfflineQueue.sameContent(a, b))
        a.notes = "x"
        XCTAssertFalse(OfflineQueue.sameContent(a, b))
    }

    func testCompareMarksDifferingFieldsAndHidesSecrets() {
        var mine = Item.empty(.login, now: 1)
        mine.name = "Shop"
        mine.login?.username = "alice"
        mine.login?.password = "one"
        var theirs = mine
        theirs.login?.password = "two"
        theirs.notes = "added elsewhere"
        let rows = OfflineQueue.compare(mine: mine, theirs: theirs)
        let byLabel = Dictionary(uniqueKeysWithValues: rows.map { ($0.label, $0) })
        XCTAssertEqual(byLabel["Password"]?.differs, true)
        XCTAssertEqual(byLabel["Password"]?.secret, true)
        XCTAssertEqual(byLabel["Username"]?.differs, false)
        XCTAssertEqual(byLabel["Notes"]?.mine, "")
        XCTAssertEqual(byLabel["Notes"]?.differs, true)
        XCTAssertNil(byLabel["Card number"], "fields empty on both sides are left out")
    }

    // MARK: Showing it

    private func entry(_ id: String, _ name: String, revision: Int64 = 3, trashed: Bool = false) -> Entry {
        Entry(id: id, item: Item(name: name), vaultId: "v1", revision: revision,
              enc: EncryptedItem(id: id, vaultId: "v1", key: "k", data: "d"), deletedAt: trashed ? 100 : nil)
    }

    func testOverlayShowsCreatesEditsAndTrash() {
        var v = VaultData()
        v.entries = [entry("a", "Alpha"), entry("b", "Beta")]
        var waiting = change(.create, item: "n", name: "New")
        waiting.state = .waiting
        var edited = change(.edit, item: "a", name: "Alpha 2")
        edited.state = .conflict
        edited.reason = OfflineText.changedText
        var held = change(.trash, item: "b", at: 5_000)
        held.state = .held
        held.reason = "No"
        let shown = OfflineQueue.overlay(v, [waiting, edited, held])
        XCTAssertEqual(shown.entries.map(\.item.name), ["Alpha 2", "New"])
        XCTAssertEqual(shown.trash.map(\.id), ["b"])
        XCTAssertEqual(shown.trash.first?.deletedAt, 5)
        XCTAssertEqual(shown.get("n")?.pending?.label, "Waiting to sync")
        XCTAssertEqual(shown.get("a")?.pending?.label, "Changed on another device")
        XCTAssertEqual(shown.get("b")?.pending?.label, "Not sent: No")
        XCTAssertEqual(shown.get("a")?.revision, 3, "an edit keeps the server's row and revision")
        XCTAssertNil(OfflineQueue.overlay(v, []).get("a")?.pending)
        XCTAssertEqual(v.entries.map(\.item.name), ["Alpha", "Beta"], "the copy itself is unchanged")
    }

    func testOverlayShowsAnEditOfAnItemGoneFromTheCopy() {
        let shown = OfflineQueue.overlay(VaultData(), [change(.edit, item: "gone", name: "Mine")])
        XCTAssertEqual(shown.get("gone")?.item.name, "Mine")
        XCTAssertNil(OfflineQueue.overlay(VaultData(), [change(.trash, item: "gone")]).get("gone"))
    }

    func testStatusAndWarnings() {
        XCTAssertNil(OfflineText.status([]))
        XCTAssertEqual(OfflineText.status([change(.edit)]), "1 change waiting to sync")
        XCTAssertEqual(OfflineText.status([change(.edit), change(.create, item: "y")]), "2 changes waiting to sync")
        var c = change(.edit)
        c.state = .conflict
        XCTAssertEqual(OfflineText.status([c, change(.create, item: "y")]), "1 change needs your decision")
        XCTAssertNil(OfflineText.lost(0))
        XCTAssertEqual(OfflineText.lost(3), "3 changes haven't been sent and will be lost.")
        XCTAssertEqual(OfflineText.lost(1), "1 change hasn't been sent and will be lost.")
    }

    func testSendOrderIsOldestFirst() {
        let list = [change(.edit, item: "b", at: 5), change(.edit, item: "a", at: 2), change(.edit, item: "c", at: 5)]
        XCTAssertEqual(OfflineQueue.sendOrder(list).map(\.itemId), ["a", "b", "c"])
    }

    func testOnlyIOSKeepsAList() {
        #if os(iOS)
        XCTAssertTrue(OfflineQueue.enabled)
        #else
        XCTAssertFalse(OfflineQueue.enabled)
        #endif
    }
}
