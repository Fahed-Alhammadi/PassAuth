import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// The offline change list in the repository against a scripted server: saves that wait, the
/// sealed list, the sender after a sync, conflicts and the decision, discard, lock and log out.
@MainActor
final class OfflineQueueRepoTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-offline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    private struct Fixture {
        let created: NewAccount
        let vaultId: String
        let key: VaultKey
        let wrapped: String
        let itemId: String
        let item: Item
    }

    private func fixture() throws -> Fixture {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let a = try newId()
        let k = try created.account.newVaultKey(vaultId: a)
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Shop"
        item.login?.username = "alice"
        item.login?.password = "pw-1"
        return Fixture(created: created, vaultId: a, key: k.key, wrapped: k.wrapped, itemId: try newId(), item: item)
    }

    private func syncBody(_ f: Fixture, item: Item? = nil, revision: Int64 = 3, trashed: Bool = false, extra: [[String: Any]] = []) throws -> Data {
        let enc = try f.key.encryptItem(itemJson: ItemCodec.encode(item ?? f.item), id: f.itemId, vaultId: f.vaultId)
        let vault: [String: Any] = ["id": f.vaultId, "wrapped_key": f.wrapped, "key_kind": "account", "key_epoch": 1,
                                    "meta": try f.key.encryptMeta(vaultId: f.vaultId, metaJson: #"{"name":"Personal"}"#), "role": "owner"]
        return try JSONSerialization.data(withJSONObject: [
            "vaults": [vault],
            "items": [["id": f.itemId, "vault_id": f.vaultId, "item_key": enc.key, "data": enc.data, "revision": revision,
                       "deleted_at": trashed ? 1_700_000_100 : NSNull()] as [String: Any]] + extra,
            "revision": 5 + revision,
        ] as [String: Any])
    }

    private func repo(_ f: Fixture, app: Bool = true) async throws -> VaultRepository {
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = f.created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] }).allowingOlderServers()
        try await repo.unlock(password: password, secretKey: nil)
        repo.isApp = app
        return repo
    }

    private func writes(_ method: String? = nil) -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.path.hasPrefix("/api/items") && (method == nil || $0.method == method) }
    }

    private func until(_ what: String, _ check: @MainActor () -> Bool) async throws {
        for _ in 0..<250 {
            if check() { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTFail("timed out waiting for: \(what)")
    }

    private func decrypt(_ f: Fixture, _ r: ScriptedServer.Request) throws -> Item {
        let enc = EncryptedItem(id: r.body["id"] as! String, vaultId: f.vaultId, key: r.body["key"] as! String, data: r.body["data"] as! String)
        return try ItemCodec.decode(try f.key.decryptItem(encrypted: enc))
    }

    /// A create whose request gets no answer (503) waits in the sealed list, shows with its
    /// marker, and is sent with the same id after the next sync.
    func testCreateWithoutAnswerWaitsAndIsSentAfterTheNextSync() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        ScriptedServer.answer("POST /api/items", 503, "")
        let id = try await repo.createItem(Item(name: "Offline note"), vaultId: nil)
        XCTAssertTrue(repo.lastWriteQueued)
        XCTAssertEqual(repo.vault?.get(id)?.pending?.state, .waiting)
        XCTAssertEqual(repo.vault?.get(id)?.item.name, "Offline note")
        XCTAssertEqual(repo.offlineCount(), 1)
        XCTAssertEqual(repo.offlineChanges.first?.sent?.data, writes("POST").first?.body["data"] as? String, "the attempt is remembered")
        guard case .sealed(let sealed) = repo.store.readOfflineChanges("acc") else { return XCTFail("no sealed list") }
        XCTAssertFalse(sealed.contains("Offline note"), "kept sealed with the account key")
        XCTAssertEqual(OfflineText.status(repo.offlineChanges), "1 change waiting to sync")

        // The next save while offline goes straight to the list.
        _ = try await repo.createItem(Item(name: "Second"), vaultId: nil)
        XCTAssertEqual(writes("POST").count, 1)
        XCTAssertEqual(repo.offlineChanges.count, 2)

        try await repo.sync()
        try await until("sent") { repo.offlineChanges.isEmpty }
        let posts = writes("POST")
        XCTAssertEqual(posts.count, 3)
        XCTAssertEqual(posts[1].body["id"] as? String, id, "the app's own item id")
        XCTAssertEqual(try decrypt(f, posts[1]).name, "Offline note")
        XCTAssertEqual(try decrypt(f, posts[2]).name, "Second", "oldest first")
        XCTAssertEqual(repo.offlineCount(), 0)
        XCTAssertEqual(repo.store.readOfflineChanges("acc"), .missing)
    }

    /// Answers other than "no answer" are shown as before; nothing waits.
    func testErrorAnswersAreNotQueued() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        ScriptedServer.answer("POST /api/items", 500, #"{"error":"internal","message":"boom"}"#)
        do {
            _ = try await repo.createItem(Item(name: "X"), vaultId: nil)
            XCTFail("expected an error")
        } catch {}
        XCTAssertTrue(repo.offlineChanges.isEmpty)
        XCTAssertFalse(repo.lastWriteQueued)
    }

    /// Offline (the OS says so): an edit waits without a request; the server's copy changed
    /// meanwhile, so the sender marks a conflict; "Keep both" saves this device's version as a
    /// new item named "… (offline copy)".
    func testEditConflictKeepBoth() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        repo.networkAvailable = false
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var mine = e.item
        mine.login?.password = "mine"
        try await repo.updateItem(e, mine)
        XCTAssertTrue(writes().isEmpty)
        XCTAssertEqual(repo.vault?.get(f.itemId)?.item.login?.password, "mine")
        XCTAssertEqual(repo.offlineChanges.first?.baseRevision, 3)
        XCTAssertEqual(repo.vault?.get(f.itemId)?.item.passwordHistory.first?.password, "pw-1", "history as for any edit")

        var theirs = f.item
        theirs.login?.password = "theirs"
        ScriptedServer.syncBodies = [try syncBody(f, item: theirs, revision: 4)]
        repo.networkAvailable = true
        try await repo.sync()
        try await until("conflict") { repo.offlineChanges.first?.state == .conflict }
        XCTAssertTrue(writes().isEmpty, "nothing is sent until the user decides")
        XCTAssertEqual(repo.vault?.get(f.itemId)?.pending?.label, "Changed on another device")
        XCTAssertEqual(OfflineText.status(repo.offlineChanges), "1 change needs your decision")
        let c = try XCTUnwrap(repo.offlineChanges.first)
        XCTAssertEqual(repo.serverEntry(for: c)?.item.login?.password, "theirs")
        XCTAssertEqual(OfflineQueue.conflictKind(c, serverHasItem: true), .changed)

        try await repo.resolveOffline(c.id, .keepBoth)
        let post = try XCTUnwrap(writes("POST").first)
        XCTAssertNotEqual(post.body["id"] as? String, f.itemId)
        XCTAssertEqual(try decrypt(f, post).name, "Shop (offline copy)")
        XCTAssertEqual(try decrypt(f, post).login?.password, "mine")
        XCTAssertTrue(repo.offlineChanges.isEmpty)
    }

    /// "Keep mine": sent as an edit at the server's current revision.
    func testEditConflictKeepMine() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        repo.networkAvailable = false
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var mine = e.item
        mine.notes = "mine"
        try await repo.updateItem(e, mine)
        ScriptedServer.syncBodies = [try syncBody(f, revision: 6)]
        repo.networkAvailable = true
        try await repo.sync()
        try await until("conflict") { repo.offlineChanges.first?.state == .conflict }
        try await repo.resolveOffline(try XCTUnwrap(repo.offlineChanges.first).id, .keepMine)
        let put = try XCTUnwrap(writes("PUT").first)
        XCTAssertEqual((put.body["revision"] as? NSNumber)?.int64Value, 6)
        XCTAssertEqual(try decrypt(f, put).notes, "mine")
        XCTAssertTrue(repo.offlineChanges.isEmpty)
    }

    /// An edit whose base is still the server's revision goes out as a plain edit.
    func testEditAtTheSameRevisionIsSent() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        repo.networkAvailable = false
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var mine = e.item
        mine.notes = "offline edit"
        try await repo.updateItem(e, mine)
        repo.networkAvailable = true
        try await repo.sync()
        try await until("sent") { repo.offlineChanges.isEmpty }
        let put = try XCTUnwrap(writes("PUT").first)
        XCTAssertEqual((put.body["revision"] as? NSNumber)?.int64Value, 3)
        XCTAssertEqual(try decrypt(f, put).notes, "offline edit")
    }

    /// Trash while offline shows the item in the trash and is sent later; a trash of an item
    /// changed meanwhile asks, and "Move to trash anyway" trashes it.
    func testTrashWaitsAndIsSent() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        repo.networkAvailable = false
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(f.itemId)))
        XCTAssertTrue(repo.lastWriteQueued)
        XCTAssertEqual(repo.vault?.trash.map(\.id), [f.itemId])
        XCTAssertNotNil(repo.vault?.trash.first?.pending)
        // A trashed item can't be edited offline.
        let trashed = try XCTUnwrap(repo.vault?.get(f.itemId))
        do {
            try await repo.updateItem(trashed, trashed.item)
            XCTFail("expected a refusal")
        } catch {}

        ScriptedServer.syncBodies = [try syncBody(f, revision: 9)]
        repo.networkAvailable = true
        try await repo.sync()
        try await until("conflict") { repo.offlineChanges.first?.state == .conflict }
        XCTAssertEqual(OfflineQueue.conflictKind(try XCTUnwrap(repo.offlineChanges.first), serverHasItem: true), .trash)
        try await repo.resolveOffline(try XCTUnwrap(repo.offlineChanges.first).id, .trashAnyway)
        XCTAssertEqual(writes("DELETE").first?.path, "/api/items/\(f.itemId)")
        XCTAssertTrue(repo.offlineChanges.isEmpty)
    }

    /// Edit of an item deleted on another device: "Save mine as a new item".
    func testEditOfADeletedItem() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        repo.networkAvailable = false
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var mine = e.item
        mine.notes = "keep me"
        try await repo.updateItem(e, mine)
        ScriptedServer.syncBodies = [try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": f.vaultId, "wrapped_key": f.wrapped, "key_kind": "account", "key_epoch": 1,
                        "meta": try f.key.encryptMeta(vaultId: f.vaultId, metaJson: #"{"name":"Personal"}"#), "role": "owner"]],
            "items": [], "revision": 20,
        ] as [String: Any])]
        repo.networkAvailable = true
        try await repo.sync()
        try await until("conflict") { repo.offlineChanges.first?.state == .conflict }
        let c = try XCTUnwrap(repo.offlineChanges.first)
        XCTAssertNil(repo.serverEntry(for: c))
        XCTAssertEqual(OfflineQueue.conflictKind(c, serverHasItem: false), .deleted)
        XCTAssertEqual(repo.vault?.get(f.itemId)?.item.notes, "keep me", "still shown from the list")
        try await repo.resolveOffline(c.id, .saveAsNew)
        let post = try XCTUnwrap(writes("POST").first)
        XCTAssertEqual(try decrypt(f, post).notes, "keep me")
        XCTAssertNotEqual(post.body["id"] as? String, f.itemId)
    }

    /// "Discard this change" removes it; restoring an item trashed offline drops that change.
    func testDiscardAndRestore() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        repo.networkAvailable = false
        let e = try XCTUnwrap(repo.vault?.get(f.itemId))
        var mine = e.item
        mine.name = "Changed"
        try await repo.updateItem(e, mine)
        try await repo.discardOfflineChange(f.itemId)
        XCTAssertTrue(repo.offlineChanges.isEmpty)
        XCTAssertEqual(repo.vault?.get(f.itemId)?.item.name, "Shop")

        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(f.itemId)))
        try await repo.restoreItem(try XCTUnwrap(repo.vault?.get(f.itemId)))
        XCTAssertTrue(repo.offlineChanges.isEmpty)
        XCTAssertNil(repo.vault?.get(f.itemId)?.deletedAt)
        XCTAssertTrue(writes().isEmpty)
    }

    /// Lock keeps the list (read again at the next unlock); Log out deletes it.
    func testLockKeepsTheListLogOutDeletesIt() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f, app: false)
        repo.networkAvailable = false
        _ = try await repo.createItem(Item(name: "Waiting"), vaultId: nil)
        await repo.lockActive()
        XCTAssertTrue(repo.offlineChanges.isEmpty)
        XCTAssertEqual(repo.offlineCount(), 1, "the count is known while locked (warnings)")
        try await repo.unlock(password: password, secretKey: nil)
        XCTAssertEqual(repo.offlineChanges.map { $0.decodedItem?.name }, ["Waiting"])
        await repo.logout()
        XCTAssertEqual(repo.store.readOfflineChanges("acc"), .missing)
        XCTAssertEqual(repo.offlineCount("acc"), 0)
    }

    /// The AutoFill extension (not the app) adds to the list but never sends it.
    func testAutoFillAddsButDoesntSend() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f, app: false)
        ScriptedServer.answer("GET /api/sync", 503, "")
        let outcome = try await repo.saveLogin(page: "https://new.example.org/login", username: "bob", password: "s3cret")
        XCTAssertEqual(outcome, .created)
        XCTAssertEqual(repo.offlineChanges.first?.kind, .create)
        XCTAssertEqual(repo.loginsFor("https://new.example.org/").map(\.item.login?.username), ["bob"], "fills show the list too")
        try await repo.sync()
        try await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(repo.offlineChanges.count, 1)
        XCTAssertTrue(writes().isEmpty)
    }

    /// The AutoFill extension merges a newer save into a change while the app's request for it is
    /// on the way: the app keeps the merged change (it doesn't write its stale copy back or
    /// remove it) and sends the newer save as an edit of the row that landed.
    func testAMergeDuringTheRequestIsKeptAndSentAsAnEdit() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let app = try await repo(f)
        let autofill = try await repo(f, app: false)
        ScriptedServer.answer("POST /api/items", 503, "")
        let id = try await app.createItem(Item(name: "Offline note"), vaultId: nil)
        XCTAssertEqual(app.offlineChanges.count, 1)
        var merged = false
        var landed: Data?
        ScriptedServer.handler = { r in
            // After the create, the server's answers hold its row.
            if r.method == "GET", r.path == "/api/sync", let landed { return (200, landed) }
            guard r.method == "POST", r.path == "/api/items", !merged else { return nil }
            merged = true
            landed = try? self.syncBody(f, extra: [["id": id, "vault_id": f.vaultId, "item_key": r.body["key"] as Any,
                                                     "data": r.body["data"] as Any, "revision": 7]])
            DispatchQueue.main.sync {
                MainActor.assumeIsolated {
                    let edit = OfflineChange(kind: .edit, vaultId: f.vaultId, itemId: id, baseRevision: nil,
                                             item: try? JSON.parse(ItemCodec.encode(Item(name: "Merged in AutoFill"))), createdAt: 1)
                    do { try autofill.mutateOffline("acc") { try OfflineQueue.merge($0, edit) } } catch { XCTFail("merge: \(error)") }
                }
            }
            return nil
        }
        try await app.sync()
        try await until("sent") { app.offlineChanges.isEmpty && !app.sendingOffline }
        XCTAssertTrue(merged)
        XCTAssertEqual(writes("POST").count, 2)
        XCTAssertEqual(try decrypt(f, writes("POST")[1]).name, "Offline note")
        let puts = writes("PUT")
        XCTAssertEqual(puts.count, 1, "the merged save goes on as an edit")
        XCTAssertEqual(puts.first?.path, "/api/items/\(id)")
        XCTAssertEqual(puts.first?.body["revision"] as? Int, 7, "at the revision of the row that landed")
        XCTAssertEqual(try puts.first.map { try decrypt(f, $0).name }, "Merged in AutoFill")
        XCTAssertEqual(app.store.readOfflineChanges("acc"), .missing)
    }

    /// A stored list this version can't open (a newer version's) is never written over: saves
    /// can't wait (with a message), nothing is sent, the list stays as it is.
    func testAListThatCantBeOpenedIsNeverOverwritten() async throws {
        let f = try fixture()
        ScriptedServer.syncBodies = [try syncBody(f)]
        let repo = try await repo(f)
        let newer = try f.created.account.sealOfflineChanges(json: #"{"version":2,"changes":[{"id":"x"}]}"#)
        try repo.store.updateOfflineChanges("acc") { _ in newer }
        await repo.lockActive()
        try await repo.unlock(password: password, secretKey: nil)
        XCTAssertTrue(repo.offlineUnreadable)
        XCTAssertTrue(repo.offlineChanges.isEmpty)
        XCTAssertEqual(repo.store.readOfflineChanges("acc"), .sealed(newer), "not wiped at unlock")

        repo.networkAvailable = false
        do {
            _ = try await repo.createItem(Item(name: "Waiting"), vaultId: nil)
            XCTFail("the save can't wait")
        } catch {
            XCTAssertEqual(errorMessage(error), OfflineText.cantOpen)
        }
        XCTAssertThrowsError(try repo.mutateOffline("acc") { _ in [] })
        repo.networkAvailable = nil
        await repo.sendOfflineChanges()
        XCTAssertTrue(writes().isEmpty)
        XCTAssertEqual(repo.store.readOfflineChanges("acc"), .sealed(newer), "left as it is")
    }
}
