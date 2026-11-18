import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// Security round 7/8/9 (docs/ARCHITECTURE.md "Account wraps", "Send", "Item edit counter"):
/// epoch-bound own wraps, Send v2 and item rollback detection, through this app's bindings and
/// its own code (`ItemRevCheck`, `VaultRepository.open`, `OwnedSend`, `SendChanges`).
final class Sec789Tests: XCTestCase {
    private typealias Object = [String: Any]

    nonisolated(unsafe) private static let vectors: Object = {
        guard let url = Bundle(for: Sec789Tests.self).url(forResource: "vectors", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? Object
        else { return [:] }
        return object
    }()

    private func account() throws -> Account {
        try accountFromSessionBytes(accountId: "rev", bytes: Data(repeating: 3, count: 64))
    }

    // MARK: 9. Item edit counter

    func testItemRevVectorsThroughTheBinding() throws {
        let v = try XCTUnwrap(Self.vectors["itemRev"] as? Object)
        let checks = try XCTUnwrap(v["checks"] as? [Object])
        XCTAssertFalse(checks.isEmpty)
        for c in checks {
            let remembered = (c["remembered"] as? Int).map { UInt64($0) }
            let served = UInt64(try XCTUnwrap(c["served"] as? Int))
            XCTAssertEqual(try itemRevCheck(remembered: remembered, served: served), c["expected"] as? String, "\(c)")
            XCTAssertEqual(ItemRevCheck.verdict(remembered: remembered, served: served).rawValue, c["expected"] as? String, "\(c)")
        }
    }

    func testTheCoreCountsEveryEncryptionAndTheItemKeepsItsCounter() throws {
        let key = try account().newVaultKey(vaultId: "vault").key
        func rev(_ e: EncryptedItem) throws -> UInt64 { try ItemCodec.decode(try key.decryptItem(encrypted: e)).rev }
        var item = Item.empty(.login, now: 1)
        item.name = "x"
        let made = try key.encryptItem(itemJson: ItemCodec.encode(item), id: "item", vaultId: "vault")
        XCTAssertEqual(try rev(made), 1)
        var edited = try ItemCodec.decode(try key.decryptItem(encrypted: made))
        edited.name = "y"
        let second = try key.updateItem(encrypted: made, itemJson: ItemCodec.encode(edited))
        XCTAssertEqual(try rev(second), 2)
        // A move re-encrypts the decrypted item: the counter goes on.
        let moved = try key.encryptItem(itemJson: try key.decryptItem(encrypted: second), id: "item", vaultId: "vault")
        XCTAssertEqual(try rev(moved), 3)
        // Written back only when counted (an item from before has none).
        XCTAssertFalse(ItemCodec.encode(Item.empty(.note, now: 1)).contains("\"rev\""))
        XCTAssertTrue(ItemCodec.encode(try ItemCodec.decode(try key.decryptItem(encrypted: moved))).contains("\"rev\":3"))
    }

    func testMemoryLearnsNeverLowersAndForgetsGoneItems() {
        var m: [String: UInt64] = [:]
        XCTAssertEqual(ItemRevCheck.observe(&m, id: "a", served: 2), .new)
        XCTAssertEqual(ItemRevCheck.observe(&m, id: "a", served: 3), .newer)
        XCTAssertEqual(ItemRevCheck.observe(&m, id: "a", served: 3), .same)
        XCTAssertEqual(ItemRevCheck.observe(&m, id: "a", served: 1), .rollback)
        XCTAssertEqual(m["a"], 3)
        // Forgetting is `ItemRevCheck.settle` (only an authenticated absence; `VaultManifestTests`).
        m["b"] = 1
        let settled = ItemRevCheck.settle(ItemRevMemory(items: ["a": .init(rev: 3, vault: "v"), "b": .init(rev: 1, vault: "v")]), observed: m,
                                          rows: [(id: "a", vault: "v")], absentOk: [], now: 9)
        XCTAssertEqual(settled.memory.revs, ["a": 3, "b": 1], "an item the copy doesn't have stays remembered")
    }

    func testRollbackKeepsTheNewerCopyAndMarksTheItem() throws {
        let acct = try account()
        let nv = try acct.newVaultKey(vaultId: "vault")
        var item = Item.empty(.login, now: 1)
        item.name = "Bank"
        item.login?.password = "old"
        let v1 = try nv.key.encryptItem(itemJson: ItemCodec.encode(item), id: "item", vaultId: "vault")
        var newer = try ItemCodec.decode(try nv.key.decryptItem(encrypted: v1))
        newer.login?.password = "new"
        let v2 = try nv.key.updateItem(encrypted: v1, itemJson: ItemCodec.encode(newer))
        let vault = SyncVault(id: "vault", meta: "", wrappedKey: nv.wrapped, keyEpoch: 0)
        func snap(_ e: EncryptedItem, revision: Int64) -> SyncSnapshot {
            SyncSnapshot(revision: revision, cursor: nil, user: nil, bundle: nil, vaults: [vault],
                         items: [SyncItem(id: "item", vaultId: "vault", itemKey: e.key, data: e.data, revision: revision)])
        }
        // First sight of the newer version: learnt.
        let first = VaultRepository.open(acct, snap(v2, revision: 2), previous: nil, revs: [:])
        XCTAssertEqual(first.revs, ["item": 2])
        XCTAssertNil(first.data.rollback)
        // The server sends the older ciphertext again: the newer copy is kept, the item marked.
        let back = VaultRepository.open(acct, snap(v1, revision: 3), previous: first, revs: first.revs)
        let entry = try XCTUnwrap(back.data.get("item"))
        XCTAssertTrue(entry.rolledBack)
        XCTAssertEqual(entry.item.login?.password, "new")
        XCTAssertEqual(entry.revision, 3, "the server's revision, so an edit isn't refused as a conflict")
        XCTAssertEqual(back.data.rollback, ItemRollback(items: ["item"], kept: ["item"]))
        XCTAssertEqual(back.revs, ["item": 2], "never lowered")
        XCTAssertEqual(back.keptRows["item"]?.data, v2.data)
        let kept = VaultRepository.keeping(back.keptRows, in: snap(v1, revision: 3))
        XCTAssertEqual(kept.items.first?.data, v2.data)
        XCTAssertEqual(back.data.rollback?.notice, "Your server sent older versions of some items. PassAuth kept the newer copies it had.")
        // No newer copy on this device (a fresh unlock): shown, but marked.
        let fresh = VaultRepository.open(acct, snap(v1, revision: 3), previous: nil, revs: ["item": 2])
        XCTAssertEqual(try XCTUnwrap(fresh.data.get("item")).item.login?.password, "old")
        XCTAssertTrue(try XCTUnwrap(fresh.data.get("item")).rolledBack)
        XCTAssertEqual(fresh.data.rollback?.notice, "Your server sent older versions of some items.")
        // Not checked without a memory.
        XCTAssertNil(VaultRepository.open(acct, snap(v1, revision: 3), previous: nil).data.rollback)
    }

    // MARK: 7. Epoch-bound own wraps

    func testBoundWrapsOpenOnlyAtTheirEpoch() throws {
        let acct = try account()
        let made = try acct.newVaultKeyBound(vaultId: "vault", keyEpoch: 1)
        XCTAssertTrue(accountWrapIsBound(wrapped: made.wrapped))
        XCTAssertFalse(accountWrapIsBound(wrapped: try acct.newVaultKey(vaultId: "vault").wrapped))
        XCTAssertNoThrow(try acct.openVaultKey(vaultId: "vault", wrapped: made.wrapped, kind: "account", keyEpoch: 1, legacyAllowed: false))
        XCTAssertThrowsError(try acct.openVaultKey(vaultId: "vault", wrapped: made.wrapped, kind: "account", keyEpoch: 2, legacyAllowed: true))
        let rewrapped = try made.key.wrapForBound(account: acct, vaultId: "vault", keyEpoch: 4)
        XCTAssertTrue(accountWrapIsBound(wrapped: rewrapped))
        XCTAssertNoThrow(try acct.openVaultKey(vaultId: "vault", wrapped: rewrapped, kind: "account", keyEpoch: 4, legacyAllowed: false))
    }

    func testObservationsCarryBoundWrapOnlyWhenTrue() throws {
        let with = try XCTUnwrap(try JSON.parse(SignedSharing.observation(vaultId: "v", kind: "account", epochPin: nil, rosterVersion: nil,
                                                                           signedShare: false, paused: false, boundWrap: true)))
        XCTAssertEqual(with["bound_wrap"], .bool(true))
        let without = try XCTUnwrap(try JSON.parse(SignedSharing.observation(vaultId: "v", kind: "account", epochPin: nil, rosterVersion: nil,
                                                                              signedShare: false, paused: false)))
        XCTAssertNil(without["bound_wrap"])
    }

    // MARK: 8. Send v2

    func testSendV2VectorsThroughTheBinding() throws {
        let v = try XCTUnwrap(Self.vectors["sendV2"] as? Object)
        let key = try XCTUnwrap(v["key"] as? String)
        let keys = try sendPasswordKeys(password: try XCTUnwrap(v["password"] as? String), salt: try XCTUnwrap(v["salt"] as? String), key: key)
        XCTAssertEqual(keys.verifier, v["verifier"] as? String)
        XCTAssertEqual(keys.contentKey, v["contentKey"] as? String)
        let data = try XCTUnwrap(v["data"] as? String)
        XCTAssertEqual(try sendOpen(key: key, contentKey: keys.contentKey, field: "data", ciphertext: data), v["text"] as? String)
        XCTAssertEqual(try sendFieldVersion(ciphertext: data), 2)
        XCTAssertThrowsError(try sendOpen(key: key, contentKey: nil, field: "data", ciphertext: data))
        // A v1 field still opens without a content key.
        let v1 = try sendEncrypt(key: key, field: "name", plaintext: "Door code")
        XCTAssertEqual(try sendOpen(key: key, contentKey: nil, field: "name", ciphertext: v1), "Door code")
        // The owner keeps the content key wrapped by the account key.
        let acct = try account()
        let wrapped = try acct.wrapSendContentKey(contentKey: keys.contentKey)
        XCTAssertEqual(try acct.unwrapSendContentKey(wrapped: wrapped), keys.contentKey)
    }

    func testOwnedSendReadsTheContentKeyAndChangesWriteIt() throws {
        let json: JSON = ["id": "s1", "name": "n", "owner_key": "k", "owner_content_key": "ck", "delete_at": 10, "has_password": true]
        XCTAssertEqual(OwnedSend(json: json)?.ownerContentKey, "ck")
        XCTAssertTrue(VaultRepository.isV2(try XCTUnwrap(OwnedSend(json: json))))
        let old: JSON = ["id": "s1", "name": "n", "owner_key": "k", "delete_at": 10]
        XCTAssertNil(OwnedSend(json: old)?.ownerContentKey)
        var c = SendChanges()
        XCTAssertNil(c.body["owner_content_key"])
        c.ownerContentKey = .set(nil)
        XCTAssertEqual(c.body["owner_content_key"], .null)
        c.ownerContentKey = .set("w")
        XCTAssertEqual(c.body["owner_content_key"], .string("w"))
    }

    /// A Send is what its fields say: v2 text exactly with a content key. Anything else can't be
    /// read here and is never "repaired" by writing it again; and a password is only ever set in
    /// the v2 format.
    func testASendsFormatIsReadFromItsFieldsAndAPasswordNeedsV2() throws {
        let v = try XCTUnwrap(Self.vectors["sendV2"] as? Object)
        let key = try XCTUnwrap(v["key"] as? String)
        let v2 = try XCTUnwrap(v["data"] as? String)
        let v1 = try sendEncrypt(key: key, field: "name", plaintext: "Door code")
        func send(name: String, data: String?, contentKey: String?) -> OwnedSend {
            var o: [String: JSON] = ["id": "s1", "name": .string(name), "owner_key": "k", "delete_at": 10]
            if let data { o["data"] = .string(data) }
            if let contentKey { o["owner_content_key"] = .string(contentKey) }
            return OwnedSend(json: .object(o))!
        }
        XCTAssertTrue(VaultRepository.sendFormatConsistent(send(name: v1, data: v1, contentKey: nil)))
        XCTAssertTrue(VaultRepository.sendFormatConsistent(send(name: v1, data: nil, contentKey: nil)))
        XCTAssertTrue(VaultRepository.sendFormatConsistent(send(name: v2, data: v2, contentKey: "ck")))
        XCTAssertFalse(VaultRepository.sendFormatConsistent(send(name: v2, data: v2, contentKey: nil)), "v2 text without its key")
        XCTAssertFalse(VaultRepository.sendFormatConsistent(send(name: v1, data: v1, contentKey: "ck")), "a key with link-only text")
        XCTAssertFalse(VaultRepository.sendFormatConsistent(send(name: v2, data: v1, contentKey: "ck")), "the text downgraded")
        XCTAssertFalse(VaultRepository.sendFormatConsistent(send(name: "not a field", data: nil, contentKey: nil)))
        XCTAssertEqual(VaultRepository.sendPasswordNeedsV2, "Update your PassAuth server to protect a Send with a password.")
    }
}
