import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// Vault manifests and the refusal of servers without signed sharing, against the scripted
/// server (the client side of docs/ARCHITECTURE.md "Vault manifests"): every write carries the
/// vault's next manifest, an answer is only applied to the copy when it names that manifest,
/// another device's write in between is retried three times at most, every sync is checked and a
/// vault that doesn't match is warned about and not written to, first manifests, old trash and
/// "Use the server's copy" are the app's own, and a server without signed sharing isn't used.
@MainActor
final class ManifestContractTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"
    private static let modern = #"{"name":"PassAuth","api":2,"features":["signed_sharing","key_epoch","delta_sync","vault_manifest"],"limits":{"max_import_items":2}}"#

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-manifest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
        ScriptedServer.config = Self.modern
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    // MARK: The server's side

    /// One vault as the server holds it: its key, rows and numbers.
    private final class Vault {
        let id: String
        var key: VaultKey
        var wrapped: String
        var epoch: Int64 = 1
        var name: String
        var role = "owner"
        var seq: Int64 = 3
        var manifestSeq: Int64 = 0
        var manifestOk = true
        var rows: [[String: Any]] = []

        init(_ account: Account, name: String) throws {
            id = try newId()
            let made = try account.newVaultKeyBound(vaultId: id, keyEpoch: 1)
            key = made.key
            wrapped = made.wrapped
            self.name = name
        }

        @discardableResult
        func add(_ title: String, username: String = "", password: String = "", url: String? = nil, trashedAt: Int64? = nil, revision: Int64 = 3) throws -> String {
            let itemId = try newId()
            var item = Item.empty(.login, now: 1_700_000_000)
            item.name = title
            item.login?.username = username
            item.login?.password = password
            if let url { item.login?.urls = [LoginUrl(url: url, match: .default)] }
            let enc = try key.encryptItem(itemJson: ItemCodec.encode(item), id: itemId, vaultId: id)
            rows.append(["id": itemId, "vault_id": id, "item_key": enc.key, "data": enc.data, "revision": revision,
                         "deleted_at": trashedAt.map { $0 as Any } ?? NSNull(), "created_at": 1_700_000_000, "updated_at": 1_700_000_000])
            return itemId
        }

        /// `rows` as the core takes them (id, where it is, data or its hash).
        static func manifestRows(_ rows: [[String: Any]]) throws -> String {
            let list = rows.map { r -> [String: Any] in
                var o: [String: Any] = ["id": r["id"] ?? "", "deleted_at": r["deleted_at"] ?? NSNull()]
                if let d = r["data"] { o["data"] = d } else if let h = r["data_sha256"] { o["data_sha256"] = h }
                return o
            }
            return String(decoding: try JSONSerialization.data(withJSONObject: list, options: [.withoutEscapingSlashes]), as: UTF8.self)
        }

        /// The manifest of exactly `rows` at `version` (the vault's own rows and number by default).
        func sealed(version: Int64? = nil, rows other: [[String: Any]]? = nil) throws -> String {
            try key.manifestStart(vaultId: id, keyEpoch: UInt64(epoch), version: UInt64(version ?? manifestSeq), itemsJson: try Self.manifestRows(other ?? rows))
        }

        /// What a check of `rows` against a manifest a client sent says.
        func check(_ seq: Int64, _ sealed: String, rows other: [[String: Any]]? = nil, key otherKey: VaultKey? = nil, epoch otherEpoch: Int64? = nil) throws -> String {
            try (otherKey ?? key).manifestVerify(vaultId: id, keyEpoch: UInt64(otherEpoch ?? epoch), manifestSeq: UInt64(seq), sealed: sealed, remembered: nil,
                                                 itemsJson: try Self.manifestRows(other ?? rows)).status
        }

        func row(manifest: String?? = nil) throws -> [String: Any] {
            let text: String? = try manifest ?? (manifestSeq > 0 ? try sealed() : nil)
            return ["id": id, "wrapped_key": wrapped, "key_kind": "account", "role": role, "rotation_pending": 0, "key_epoch": epoch, "seq": seq,
                    "meta": try key.encryptMeta(vaultId: id, metaJson: "{\"name\":\"\(name)\"}"), "share": NSNull(), "member_roster": NSNull(),
                    "member_roster_seq": 0, "manifest": text.map { $0 as Any } ?? NSNull(), "manifest_seq": manifestSeq, "manifest_ok": manifestOk]
        }

        /// A trashed row as `trash=summary` sends it (`hash`: with the data's hash, as servers with manifests do).
        static func summary(_ r: [String: Any], hash: Bool = true) -> [String: Any] {
            var s = r
            if hash, let d = r["data"] as? String { s["data_sha256"] = manifestDataHash(data: d) }
            s["data"] = nil
            s["item_key"] = nil
            return s
        }
    }

    private struct World {
        let created: NewAccount
        var accountId: String { (try? JSON.parse(created.account.legacyIdentityJson()))?.str("user_id") ?? "" }
        var revision: Int64 = 5
        var serverTime: Int64 = 1_800_000_000
        var trashDays: Int64 = 0

        /// A full `/sync` answer for these vaults (`rows`: other rows than the vaults' own).
        func body(_ vaults: [Vault], rows: [[String: Any]]? = nil, manifest: [String: String?] = [:]) throws -> Data {
            let headers = try vaults.map { v in try manifest[v.id].map { try v.row(manifest: .some($0)) } ?? v.row() }
            return try JSONSerialization.data(withJSONObject: [
                "revision": revision, "cursor": "c\(revision)", "server_time": serverTime, "trash_days": trashDays,
                "user": ["id": accountId, "email": "a@example.com", "name": "Alex", "email_verified": true, "key_pins_seq": 0, "identity": NSNull()],
                "bundle": try JSONSerialization.jsonObject(with: Data(created.bundleJson.utf8)),
                "vaults": headers, "items": rows ?? vaults.flatMap(\.rows), "invitations": [],
            ] as [String: Any])
        }
    }

    private func world() throws -> (World, Vault) {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        return (World(created: created), try Vault(created.account, name: "Personal"))
    }

    private func store() -> SecureStore {
        let s = SecureStore(directory: dir, role: .app)
        s.load()
        return s
    }

    private func repo(_ w: World, app: Bool = false, unlock: Bool = true, in existing: SecureStore? = nil,
                      configure: (VaultRepository) -> Void = { _ in }) async throws -> VaultRepository {
        let store = existing ?? self.store()
        if existing == nil {
            store.update { s in
                var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
                acc.bundle = w.created.bundleJson
                s.file.accounts["acc"] = acc
                s.file.activeId = "acc"
                s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
            }
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] })
        repo.sharingMemory = InMemorySharingMemory()
        repo.isApp = app
        configure(repo)
        if unlock { try await repo.unlock(password: password, secretKey: nil) }
        return repo
    }

    // MARK: Reading what was sent

    private func sent(_ method: String, _ suffix: String) -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.method == method && $0.path.hasSuffix(suffix) }
    }

    private func syncs() -> [ScriptedServer.Request] { sent("GET", "/api/sync") }

    private func itemWrites() -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.path.hasPrefix("/api/items") }
    }

    private func manifests(_ r: ScriptedServer.Request) -> [(vault: String, seq: Int64, sealed: String)] {
        (r.body["manifests"] as? [[String: Any]] ?? []).map {
            ($0["vault_id"] as? String ?? "", ($0["seq"] as? NSNumber)?.int64Value ?? -1, $0["sealed"] as? String ?? "")
        }
    }

    private func query(_ r: ScriptedServer.Request) -> [String: String] {
        var out: [String: String] = [:]
        for part in r.query.split(separator: "&") {
            let kv = part.split(separator: "=", maxSplits: 1).map(String.init)
            if kv.count == 2 { out[kv[0]] = kv[1].removingPercentEncoding ?? kv[1] }
        }
        return out
    }

    /// The answer of a write the server applied as the vault's next number and manifest.
    private func accept(_ key: String, _ v: Vault, revision: Int64 = 8) {
        v.seq += 1
        v.manifestSeq += 1
        ScriptedServer.answer(key, 200, #"{"revision":\#(revision),"vault_seq":\#(v.seq),"manifest_seq":\#(v.manifestSeq)}"#)
    }

    private let conflict = #"{"error":"manifest_conflict","message":"the vault changed"}"#
    private let required = #"{"error":"manifest_required","message":"Update PassAuth to change this vault."}"#

    private func assertThrows(_ text: String, file: StaticString = #filePath, line: UInt = #line, _ body: () async throws -> Void) async {
        do {
            try await body()
            XCTFail("expected: \(text)", file: file, line: line)
        } catch {
            XCTAssertEqual(errorMessage(error), text, file: file, line: line)
        }
    }

    private func named(_ name: String) -> Item {
        var i = Item.empty(.login, now: 1_700_000_000)
        i.name = name
        return i
    }

    // MARK: Writes

    /// A vault without a manifest is written to exactly as before: no `manifests`, no query.
    func testVaultsWithoutAManifestSendNothingNew() async throws {
        let (w, v) = try world()
        v.manifestOk = false
        let itemId = try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, ManifestStatus.none)
        try await repo.createItem(named("Note"), vaultId: nil)
        var e = try XCTUnwrap(repo.vault?.get(itemId))
        try await repo.updateItem(e, named("Shop 2"))
        e = try XCTUnwrap(repo.vault?.get(itemId))
        try await repo.trashItem(e)
        try await repo.restoreItem(e)
        try await repo.purgeItem(e)
        let writes = itemWrites()
        XCTAssertEqual(writes.map { "\($0.method) \($0.path)" }, ["POST /api/items", "PUT /api/items/\(itemId)", "DELETE /api/items/\(itemId)",
                                                                 "POST /api/items/\(itemId)/restore", "DELETE /api/items/\(itemId)/permanent"])
        for r in writes {
            XCTAssertNil(r.body["manifests"], "\(r.method) \(r.path)")
            XCTAssertEqual(r.query, "", "\(r.method) \(r.path)")
        }
        XCTAssertEqual(store().readManifestVersions("acc"), [:])
    }

    /// Create, edit, trash, restore and delete for good each carry the vault's next manifest
    /// (body, or query for the requests without one, with the item's revision); an answer that
    /// names it is applied to the copy without a sync, so the next write builds on it.
    func testEveryWriteCarriesTheNextManifestAndIsAppliedToTheCopy() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 4])
        let before = syncs().count
        var expected = v.rows

        // Create.
        accept("POST /api/items", v)
        let newId = try await repo.createItem(named("Note"), vaultId: nil)
        var r = try XCTUnwrap(sent("POST", "/api/items").last)
        var m = manifests(r)
        XCTAssertEqual(m.map(\.vault), [v.id])
        XCTAssertEqual(m.first?.seq, 5)
        expected.append(["id": newId, "deleted_at": NSNull(), "data": r.body["data"] ?? ""])
        XCTAssertEqual(try v.check(5, m[0].sealed, rows: expected), "ok")
        XCTAssertEqual(r.query, "", "never in a header or a query when there is a body")
        XCTAssertNil(r.headers.keys.first { $0.lowercased().contains("manifest") })

        // Edit.
        accept("PUT /api/items/\(itemId)", v, revision: 9)
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        r = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        m = manifests(r)
        XCTAssertEqual(m.first?.seq, 6)
        expected[0]["data"] = r.body["data"]
        XCTAssertEqual(try v.check(6, m[0].sealed, rows: expected), "ok")
        XCTAssertEqual((r.body["revision"] as? NSNumber)?.int64Value, 3)

        // Trash: revision and manifest in the query.
        accept("DELETE /api/items/\(itemId)", v, revision: 10)
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        r = try XCTUnwrap(sent("DELETE", "/api/items/\(itemId)").last)
        var q = query(r)
        XCTAssertEqual(q["revision"], "9")
        XCTAssertEqual(q["manifest_seq"], "7")
        expected[0]["deleted_at"] = 1
        XCTAssertEqual(try v.check(7, q["manifest"] ?? "", rows: expected), "ok")
        XCTAssertTrue(r.body.isEmpty)
        XCTAssertNotNil(repo.vault?.trash.first { $0.id == itemId })

        // Restore.
        accept("POST /api/items/\(itemId)/restore", v, revision: 11)
        try await repo.restoreItem(try XCTUnwrap(repo.vault?.get(itemId)))
        q = query(try XCTUnwrap(sent("POST", "/api/items/\(itemId)/restore").last))
        XCTAssertEqual(q["revision"], "10")
        XCTAssertEqual(q["manifest_seq"], "8")
        expected[0]["deleted_at"] = NSNull()
        XCTAssertEqual(try v.check(8, q["manifest"] ?? "", rows: expected), "ok")

        // Delete the trashed item for good.
        let old = try XCTUnwrap(repo.vault?.trash.first)
        accept("DELETE /api/items/\(old.id)/permanent", v)
        try await repo.purgeItem(old)
        q = query(try XCTUnwrap(sent("DELETE", "/api/items/\(old.id)/permanent").last))
        XCTAssertEqual(q["revision"], "3")
        XCTAssertEqual(q["manifest_seq"], "9")
        expected.remove(at: 1)
        XCTAssertEqual(try v.check(9, q["manifest"] ?? "", rows: expected), "ok")

        // All of it without asking the server again; the vault still matches, the version is remembered.
        XCTAssertEqual(syncs().count, before)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.entries.map(\.item.name).sorted(), ["Note", "Shop 2"])
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 9])
    }

    /// An answer that doesn't name the manifest this device sent (another number, or none) is
    /// never applied to the copy: sync, and check.
    func testAnAnswerWithoutThisManifestSyncsInstead() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        let before = syncs().count
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":8,"vault_seq":4,"manifest_seq":6}"#)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(syncs().count, before + 1)
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":8,"vault_seq":4}"#)
        try await repo.createItem(named("Note 2"), vaultId: nil)
        XCTAssertEqual(syncs().count, before + 2)
    }

    /// 409 `manifest_conflict`: sync, check, compute the manifest again from the fresh row and
    /// resend, three times in all; then "This vault changed on another device. Try again."
    func testAConflictIsRetriedThreeTimesAtMost() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)

        // Another device wrote meanwhile: the vault is at 5 with one more item.
        ScriptedServer.answer("POST /api/items", 409, conflict)
        v.manifestSeq = 5
        v.seq = 4
        try v.add("Theirs")
        ScriptedServer.syncBodies = [try w.body([v])]
        accept("POST /api/items", v)
        let id = try await repo.createItem(named("Mine"), vaultId: nil)
        let posts = sent("POST", "/api/items")
        XCTAssertEqual(posts.count, 2)
        XCTAssertEqual(posts.map { manifests($0).first?.seq }, [5, 6])
        XCTAssertEqual(posts.map { $0.body["id"] as? String }, [id, id], "a create keeps its id")
        XCTAssertEqual(try v.check(6, manifests(posts[1])[0].sealed, rows: v.rows + [["id": id, "deleted_at": NSNull(), "data": posts[1].body["data"] ?? ""]]), "ok")

        // An edit: not the "changed on another device — overwrite?" conflict, as long as the
        // item itself is as it was.
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("PUT /api/items/\(itemId)", 409, conflict)
        ScriptedServer.answer("PUT /api/items/\(itemId)", 409, conflict)
        try await repo.sync()
        let entry = try XCTUnwrap(repo.vault?.get(itemId))
        try await repo.updateItem(entry, named("Shop 2"))
        XCTAssertEqual(sent("PUT", "/api/items/\(itemId)").count, 3)

        // Conflicts every time: given up after three sends, in the app's words.
        for _ in 0..<5 { ScriptedServer.answer("DELETE /api/items/\(itemId)", 409, conflict) }
        await assertThrows("This vault changed on another device. Try again.") {
            try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        }
        XCTAssertEqual(sent("DELETE", "/api/items/\(itemId)").count, 3)
        for _ in 0..<5 { ScriptedServer.answer("PUT /api/items/\(itemId)", 409, conflict) }
        do {
            try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 3"))
            XCTFail("expected an error")
        } catch {
            XCTAssertFalse(error is ConflictError, "never the overwrite question")
            XCTAssertEqual(errorMessage(error), ManifestText.busy)
        }
        // The attachment flows try such a save again after a sync.
        XCTAssertTrue(VaultRepository.retryAttachmentSave(UserError(ManifestText.busy)))
        XCTAssertFalse(VaultRepository.retryAttachmentSave(UserError(ManifestText.held)))
    }

    /// After a conflict the write's own rules run on the fresh copy: an item whose content
    /// changed elsewhere is the usual conflict, one that is gone says so, and a trash, restore
    /// or delete that is already done is done.
    func testAfterAConflictTheItemsOwnRulesDecide() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        let goneId = try v.add("Gone")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        let entry = try XCTUnwrap(repo.vault?.get(itemId))
        let gone = try XCTUnwrap(repo.vault?.get(goneId))

        // Meanwhile: "Shop" was edited and "Gone" deleted on another device.
        v.rows.removeAll { $0["id"] as? String == goneId }
        let changed = named("Shop (edited elsewhere)")
        let enc = try v.key.encryptItem(itemJson: ItemCodec.encode(changed), id: itemId, vaultId: v.id)
        v.rows[0]["item_key"] = enc.key
        v.rows[0]["data"] = enc.data
        v.rows[0]["revision"] = 4
        v.manifestSeq = 6
        v.seq = 5
        ScriptedServer.syncBodies = [try w.body([v])]

        // Trashing what is gone by now: done after the sync, nothing sent again.
        ScriptedServer.answer("DELETE /api/items/\(goneId)", 409, conflict)
        try await repo.trashItem(gone)
        XCTAssertEqual(sent("DELETE", "/api/items/\(goneId)").count, 1)
        XCTAssertNil(repo.vault?.get(goneId))
        ScriptedServer.answer("PUT /api/items/\(itemId)", 409, conflict)
        do {
            try await repo.updateItem(entry, named("Shop mine"))
            XCTFail("expected the conflict")
        } catch {
            XCTAssertTrue(error is ConflictError, "\(error)")
        }
        // An item the checked copy no longer has: said so, nothing sent; trashing it is done.
        await assertThrows("This item was deleted on another device.") { try await repo.updateItem(gone, self.named("Gone 2")) }
        try await repo.trashItem(gone)
        XCTAssertTrue(sent("PUT", "/api/items/\(goneId)").isEmpty)
        XCTAssertEqual(sent("DELETE", "/api/items/\(goneId)").count, 1)
        // The item's own revision conflict on a trash (the revision is sent with a manifest):
        // synced; it is in the trash by now, so done.
        v.rows[0]["deleted_at"] = 1_800_000_000
        v.manifestSeq = 7
        v.seq = 6
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("DELETE /api/items/\(itemId)", 409, #"{"error":"revision_conflict","message":"item changed"}"#)
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        XCTAssertEqual(sent("DELETE", "/api/items/\(itemId)").count, 1)
        XCTAssertNotNil(repo.vault?.trash.first { $0.id == itemId })
    }

    /// 400 `manifest_required`: this device's copy still said "no manifest". Treated like a
    /// conflict: sync (the vault has one now), check, send again with it.
    func testManifestRequiredFromAStaleCopy() async throws {
        let (w, v) = try world()
        v.manifestOk = false
        let itemId = try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        v.manifestSeq = 1
        v.seq = 4
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("PUT /api/items/\(itemId)", 400, required)
        accept("PUT /api/items/\(itemId)", v)
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        let puts = sent("PUT", "/api/items/\(itemId)")
        XCTAssertEqual(puts.count, 2)
        XCTAssertNil(puts[0].body["manifests"])
        XCTAssertEqual(manifests(puts[1]).first?.seq, 2)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 2])
        // The same for a request without a body (the server holds the edit by now).
        v.rows[0]["item_key"] = puts[1].body["key"]
        v.rows[0]["data"] = puts[1].body["data"]
        v.rows[0]["revision"] = 8
        ScriptedServer.syncBodies = [try w.body([v])]
        for _ in 0..<4 { ScriptedServer.answer("DELETE /api/items/\(itemId)", 400, required) }
        await assertThrows(ManifestText.busy) { try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId))) }
        XCTAssertEqual(sent("DELETE", "/api/items/\(itemId)").count, 3)
    }

    /// A move changes two vaults: the request carries each one's next manifest (without the item
    /// in the vault it leaves, with its re-encrypted data in the one it enters), only for vaults
    /// that have one; the copy is synced afterwards.
    func testAMoveCarriesBothVaultsManifests() async throws {
        let (w, a) = try world()
        let b = try Vault(w.created.account, name: "Work")
        let plain = try Vault(w.created.account, name: "Plain")
        plain.manifestOk = false
        a.manifestSeq = 4
        b.manifestSeq = 2
        let itemId = try a.add("Shop")
        try a.add("Stays")
        try b.add("There")
        ScriptedServer.syncBodies = [try w.body([a, b, plain])]
        let repo = try await repo(w)
        let before = syncs().count
        try await repo.moveItem(try XCTUnwrap(repo.vault?.get(itemId)), to: b.id)
        var put = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        var m = manifests(put)
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: m.map { ($0.vault, $0.seq) }), [a.id: 5, b.id: 3])
        XCTAssertEqual(put.body["vault_id"] as? String, b.id)
        let left = try XCTUnwrap(m.first { $0.vault == a.id }), entered = try XCTUnwrap(m.first { $0.vault == b.id })
        XCTAssertEqual(try a.check(5, left.sealed, rows: [a.rows[1]]), "ok")
        XCTAssertEqual(try b.check(3, entered.sealed, rows: b.rows + [["id": itemId, "deleted_at": NSNull(), "data": put.body["data"] ?? ""]]), "ok")
        XCTAssertEqual(syncs().count, before + 1, "a move is never applied to the copy")
        // Into a vault without a manifest: only the one it leaves.
        try await repo.moveItem(try XCTUnwrap(repo.vault?.get(itemId)), to: plain.id)
        put = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        m = manifests(put)
        XCTAssertEqual(m.map(\.vault), [a.id])
    }

    // MARK: Checks after a sync

    /// An answer whose items aren't the ones the manifest records: the vault stays readable,
    /// its warning is shown, nothing is written into it (and no request made), nothing is
    /// remembered, and it clears by itself with an answer that matches.
    func testAMismatchWarnsAndHoldsWritesBack() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop", username: "alice", password: "pw-1", url: "https://shop.example.com")
        let hiddenId = try v.add("Hidden")
        // The server hides one item (its manifest still records both).
        ScriptedServer.syncBodies = [try w.body([v], rows: [v.rows[0]])]
        let repo = try await repo(w)
        let info = try XCTUnwrap(repo.vault?.vaults.first)
        XCTAssertEqual(info.manifest, .mismatch)
        XCTAssertEqual(repo.vault?.manifestWarnings.map(\.id), [v.id])
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Shop"], "still readable")
        XCTAssertEqual(repo.loginsFor("https://shop.example.com/login").count, 1, "AutoFill still fills")
        XCTAssertEqual(store().readManifestVersions("acc"), [:], "nothing is remembered")

        let entry = try XCTUnwrap(repo.vault?.get(itemId))
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        await assertThrows(ManifestText.held) { try await repo.updateItem(entry, self.named("Shop 2")) }
        await assertThrows(ManifestText.held) { try await repo.trashItem(entry) }
        await assertThrows(ManifestText.held) { try await repo.restoreItem(entry) }
        await assertThrows(ManifestText.held) { try await repo.purgeItem(entry) }
        // AutoFill's saves (they sync first, so they check first): the short message, nothing saved.
        await assertThrows(ManifestText.held) { _ = try await repo.saveLogin(page: "https://new.example.com/", username: "bob", password: "pw") }
        await assertThrows(ManifestText.held) { _ = try await repo.saveLogin(page: "https://shop.example.com/", username: "alice", password: "pw-2") }
        await assertThrows(ManifestText.held) { _ = try await repo.addSite(itemId, page: "https://elsewhere.test/") }
        var passkey = Passkey()
        passkey.credentialId = "c"
        passkey.rpId = "new.example.com"
        passkey.userName = "bob"
        await assertThrows(ManifestText.held) { try await repo.storePasskey(passkey, target: PasskeyLogic.newLogin) }
        await assertThrows(ManifestText.held) { _ = try await repo.rotateVaultKeys([v.id]) }
        XCTAssertTrue(itemWrites().isEmpty, "nothing was sent")
        XCTAssertTrue(sent("POST", "/rotate").isEmpty)

        // The whole set again: the warning is gone, the version remembered, writes go.
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 4])
        XCTAssertNotNil(repo.vault?.get(hiddenId))
        accept("POST /api/items", v)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 5)
    }

    /// Every way the server's copy can differ is a mismatch: an item brought back, one put back
    /// from the trash, an older version of one, a manifest that isn't this vault's.
    func testWhatAServerCanChangeIsNoticed() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Trashed", trashedAt: 1_700_000_500)
        let good = try w.body([v])
        ScriptedServer.syncBodies = [good]
        let repo = try await repo(w)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        func after(_ body: Data) async throws -> ManifestStatus? {
            ScriptedServer.syncBodies = [body]
            try await repo.sync()
            return repo.vault?.vaults.first?.manifest
        }
        // A deleted item brought back.
        var rows = v.rows
        let extra = try v.key.encryptItem(itemJson: ItemCodec.encode(named("Back again")), id: try newId(), vaultId: v.id)
        rows.append(["id": extra.id, "vault_id": v.id, "item_key": extra.key, "data": extra.data, "revision": 2, "deleted_at": NSNull()])
        var s = try await after(try w.body([v], rows: rows))
        XCTAssertEqual(s, .mismatch)
        s = try await after(good)
        XCTAssertEqual(s, .ok, "it clears by itself")
        // A trashed item served as live.
        rows = v.rows
        rows[1]["deleted_at"] = NSNull()
        s = try await after(try w.body([v], rows: rows))
        XCTAssertEqual(s, .mismatch)
        // An older version of an item (other data under the same id).
        rows = v.rows
        let older = try v.key.encryptItem(itemJson: ItemCodec.encode(named("Shop, before")), id: rows[0]["id"] as? String ?? "", vaultId: v.id)
        rows[0]["item_key"] = older.key
        rows[0]["data"] = older.data
        s = try await after(try w.body([v], rows: rows))
        XCTAssertEqual(s, .mismatch)
        // The manifest withheld, or one of another version under this number.
        s = try await after(try w.body([v], manifest: [v.id: nil]))
        XCTAssertEqual(s, .mismatch)
        s = try await after(try w.body([v], manifest: [v.id: try v.sealed(version: 3)]))
        XCTAssertEqual(s, .mismatch)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 4], "never lowered, nothing new remembered")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
    }

    /// An older manifest than this device saw (a restored backup, or a server replaying an old
    /// state that is consistent in itself), and no manifest after one was seen: a rollback.
    func testAnOlderOrVanishedManifestIsARollback() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        let old = try w.body([v])
        v.manifestSeq = 6
        try v.add("Newer")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 6])
        ScriptedServer.syncBodies = [old]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 6])
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        // No manifest at all any more (and a server that no longer lists the feature).
        v.manifestSeq = 0
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["signed_sharing","key_epoch","delta_sync"]}"#
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        XCTAssertTrue(itemWrites().isEmpty)
    }

    /// The copy on the device is checked when it is opened with keys: a cache-first unlock (the
    /// AutoFill extension), and a copy a background refresh stored without keys. What the app
    /// remembered is read by the extension too.
    func testTheCopyOnTheDeviceIsCheckedWhenItIsOpened() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Second")
        ScriptedServer.syncBodies = [try w.body([v])]
        let shared = store()
        let app = try await repo(w)
        XCTAssertEqual(app.vault?.vaults.first?.manifest, .ok)
        // A background refresh (no keys: nothing checked) stores an answer with an item hidden.
        ScriptedServer.syncBodies = [try w.body([v], rows: [v.rows[0]])]
        let locked = try await repo(w, unlock: false, in: app.store)
        try await locked.refreshCacheLocked(accountId: "acc")
        // The next unlock, from that copy and without the server: the warning.
        let requests = ScriptedServer.recorded().count
        let autofill = try await repo(w, in: app.store) { $0.preferCache = true }
        XCTAssertEqual(autofill.vault?.offline, true)
        XCTAssertEqual(autofill.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(ScriptedServer.recorded().count, requests, "checked without the server")
        XCTAssertEqual(shared.readManifestVersions("acc"), [v.id: 4])
        // A copy older than what the app remembers (the extension reads the app's memory).
        v.manifestSeq = 9
        app.store.writeManifestVersions("acc", [v.id: 9])
        v.manifestSeq = 4
        ScriptedServer.syncBodies = [try w.body([v])]
        try await locked.refreshCacheLocked(accountId: "acc")
        let again = try await repo(w, in: app.store) { $0.preferCache = true }
        XCTAssertEqual(again.vault?.vaults.first?.manifest, .rollback)
    }

    // MARK: Summary rows (apps that keep trashed items without their data)

    /// With `trash=summary` the server sends each trashed row's `data_sha256`, which the check
    /// uses and the copy keeps; this device's own trash keeps the hash of the data it drops.
    func testSummaryRowsAreCheckedByTheirHash() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        ScriptedServer.syncBodies = [try w.body([v], rows: [v.rows[0], Vault.summary(v.rows[1])])]
        let repo = try await repo(w) { $0.trashSummary = true }
        XCTAssertEqual(syncs().last?.query, "trash=summary")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.trash.count, 0, "a trashed item without data isn't shown")
        // Trash another one here: applied to the copy without its data, with the data's hash.
        accept("DELETE /api/items/\(itemId)", v)
        let before = syncs().count
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        XCTAssertEqual(syncs().count, before)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        let kept = try XCTUnwrap(repo.copyOf("acc")?.items.first { $0.id == itemId })
        XCTAssertNil(kept.data)
        XCTAssertEqual(kept.dataSha256, manifestDataHash(data: v.rows[0]["data"] as? String ?? ""))
        // The next write builds on rows held by hash only.
        accept("POST /api/items", v)
        let id = try await repo.createItem(named("Note"), vaultId: nil)
        let post = try XCTUnwrap(sent("POST", "/api/items").last)
        var expected = v.rows
        expected[0]["deleted_at"] = 1
        expected.append(["id": id, "deleted_at": NSNull(), "data": post.body["data"] ?? ""])
        XCTAssertEqual(try v.check(6, manifests(post)[0].sealed, rows: expected), "ok")
        // Read again from the device (a new process): still checkable.
        let next = try await self.repo(w, in: repo.store) {
            $0.trashSummary = true
            $0.preferCache = true
        }
        XCTAssertEqual(next.vault?.vaults.first?.manifest, .ok)
    }

    /// A copy cached before this release holds trashed rows without data and without a hash:
    /// they can't be checked (`incomplete`, no warning), so everything is fetched once. Rows
    /// that still can't be checked after that are a mismatch.
    func testRowsCachedBeforeTheHashesAreFetchedOnce() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        let shared = store()
        shared.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = w.created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        // The old copy: the summary row without `data_sha256`.
        let bare = try w.body([v], rows: [v.rows[0], Vault.summary(v.rows[1], hash: false)])
        shared.writeCache("acc", try XCTUnwrap(SyncSnapshot.decode(bare)).encoded())
        // From the device: not checkable yet, no warning, nothing written into it.
        let cached = try await repo(w, in: shared) {
            $0.trashSummary = true
            $0.preferCache = true
        }
        XCTAssertEqual(cached.vault?.vaults.first?.manifest, .incomplete)
        XCTAssertEqual(cached.vault?.manifestWarnings.count, 0)
        // The next sync: the delta brings nothing for that row, so everything is fetched (no
        // `since`), now with the hash.
        ScriptedServer.syncBodies = [
            try JSONSerialization.data(withJSONObject: ["delta": true, "revision": 5, "cursor": "c5", "vaults": [try v.row()], "items": [], "deleted": [], "reset": []] as [String: Any]),
            try w.body([v], rows: [v.rows[0], Vault.summary(v.rows[1])]),
        ]
        try await cached.sync()
        let asked = syncs().suffix(2).map(\.query)
        XCTAssertEqual(asked, ["since=c5&trash=summary", "trash=summary"])
        XCTAssertEqual(cached.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(shared.readManifestVersions("acc"), [v.id: 4])
        // A server that still sends no hash: a mismatch after the one full fetch.
        ScriptedServer.syncBodies = [bare]
        try await cached.sync()
        XCTAssertEqual(cached.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(cached.vault?.manifestWarnings.count, 1)
    }

    // MARK: Starting a manifest, old trash (the app only)

    /// The app starts a vault's first manifest after a sync when the server says every member's
    /// apps know manifests: version 1 over the complete set, pinned to the vault's number, one
    /// attempt. Not from an AutoFill extension, not while the gate is closed, not for a reader.
    func testTheAppStartsAVaultsFirstManifest() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 200, #"{"revision":6,"vault_seq":4,"manifest_seq":1}"#)
        let repo = try await repo(w, app: true)
        let put = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").first)
        XCTAssertEqual((put.body["base_seq"] as? NSNumber)?.int64Value, 0)
        XCTAssertEqual((put.body["seq"] as? NSNumber)?.int64Value, 1)
        XCTAssertEqual((put.body["vault_seq"] as? NSNumber)?.int64Value, 3)
        XCTAssertEqual(try v.check(1, put.body["sealed"] as? String ?? ""), "ok")
        // Applied to the copy: the vault has its manifest, the next write carries version 2.
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 1])
        XCTAssertEqual(repo.copyOf("acc")?.vaults.first?.seq, 4)
        v.seq = 4
        v.manifestSeq = 1
        accept("POST /api/items", v)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 2)
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 1, "once")
    }

    func testAFirstManifestIsNotStartedWhenItMayNotBe() async throws {
        // The gate is closed (a member's app is too old).
        var (w, v) = try world()
        v.manifestOk = false
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        _ = try await repo(w, app: true)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        // An AutoFill extension never starts one.
        tearDownStore()
        (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        _ = try await repo(w, app: false)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        // A reader doesn't.
        tearDownStore()
        (w, v) = try world()
        v.role = "read"
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        _ = try await repo(w, app: true)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        // A server without the feature gets nothing.
        tearDownStore()
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["signed_sharing","key_epoch","delta_sync"]}"#
        (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        _ = try await repo(w, app: true)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        // A refusal (`manifest_not_ready`, a conflict) is left to the next sync: no retry, no error.
        tearDownStore()
        ScriptedServer.config = Self.modern
        (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 409, #"{"error":"manifest_not_ready","message":"an app is too old"}"#)
        let repo = try await repo(w, app: true)
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 1)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, ManifestStatus.none)
        XCTAssertEqual(repo.vault?.offline, false)
        XCTAssertEqual(repo.vault?.entries.count, 1)
        // Not again at every sync: once per vault number.
        try await repo.sync()
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 1)
        v.seq = 9
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 2)
    }

    /// A new directory and store for the next case of one test.
    private func tearDownStore() {
        SecureStore.wipeAll(directory: dir)
        ScriptedServer.requests = []
        ScriptedServer.answers = [:]
    }

    /// In a vault with a manifest the server no longer deletes old trash by itself: after a sync
    /// the app deletes what the server's retention has run out for, by the server's clock, in
    /// one request per chunk with the next manifest. One attempt.
    func testTheAppDeletesTrashTheRetentionHasRunOutFor() async throws {
        var (w, v) = try world()
        w.trashDays = 30
        v.manifestSeq = 4
        let day: Int64 = 86400
        try v.add("Shop")
        let a = try v.add("Old 1", trashedAt: w.serverTime - 40 * day, revision: 11)
        let b = try v.add("Old 2", trashedAt: w.serverTime - 31 * day, revision: 12)
        let c = try v.add("Old 3", trashedAt: w.serverTime - 35 * day, revision: 13)
        let recent = try v.add("Recent", trashedAt: w.serverTime - 2 * day)
        ScriptedServer.syncBodies = [try w.body([v])]
        // The server takes at most 2 items per request (`limits.max_import_items`): two chunks.
        ScriptedServer.answer("POST /api/vaults/\(v.id)/trash/purge", 200, #"{"purged":2,"revision":6,"vault_seq":4,"manifest_seq":5}"#)
        ScriptedServer.answer("POST /api/vaults/\(v.id)/trash/purge", 200, #"{"purged":1,"revision":7,"vault_seq":5,"manifest_seq":6}"#)
        let repo = try await repo(w, app: true)
        let purges = sent("POST", "/api/vaults/\(v.id)/trash/purge")
        XCTAssertEqual(purges.count, 2)
        func ids(_ r: ScriptedServer.Request) -> [String] { (r.body["items"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? String } }
        XCTAssertEqual(ids(purges[0]), [a, b])
        XCTAssertEqual(ids(purges[1]), [c])
        XCTAssertEqual((purges[0].body["items"] as? [[String: Any]])?.compactMap { ($0["revision"] as? NSNumber)?.int64Value }, [11, 12])
        var m = manifests(purges[0])
        XCTAssertEqual(m.first?.seq, 5)
        XCTAssertEqual(try v.check(5, m[0].sealed, rows: v.rows.filter { ![a, b].contains($0["id"] as? String ?? "") }), "ok")
        m = manifests(purges[1])
        XCTAssertEqual(m.first?.seq, 6)
        XCTAssertEqual(try v.check(6, m[0].sealed, rows: v.rows.filter { ![a, b, c].contains($0["id"] as? String ?? "") }), "ok")
        XCTAssertEqual(repo.vault?.trash.map(\.id), [recent])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(syncs().count, 1, "applied to the copy")

        // A failure is ignored and not tried again until the next sync; an AutoFill extension,
        // a server that keeps its trash, and a vault without a manifest delete nothing.
        tearDownStore()
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("POST /api/vaults/\(v.id)/trash/purge", 409, conflict)
        let failing = try await self.repo(w, app: true)
        XCTAssertEqual(sent("POST", "/trash/purge").count, 1)
        XCTAssertEqual(failing.vault?.trash.count, 4)
        XCTAssertEqual(failing.vault?.vaults.first?.manifest, .ok)
        try await failing.sync()
        XCTAssertEqual(sent("POST", "/trash/purge").count, 1, "once per vault number")
        tearDownStore()
        _ = try await self.repo(w, app: false)
        XCTAssertTrue(sent("POST", "/trash/purge").isEmpty)
        tearDownStore()
        w.trashDays = 0
        ScriptedServer.syncBodies = [try w.body([v])]
        _ = try await self.repo(w, app: true)
        XCTAssertTrue(sent("POST", "/trash/purge").isEmpty)
        tearDownStore()
        w.trashDays = 30
        v.manifestSeq = 0
        v.manifestOk = false
        ScriptedServer.syncBodies = [try w.body([v])]
        _ = try await self.repo(w, app: true)
        XCTAssertTrue(sent("POST", "/trash/purge").isEmpty, "the server sweeps vaults without a manifest")
    }

    // MARK: "Use the server's copy"

    /// The user accepts the vault as the server has it: everything is fetched again and a new
    /// manifest written over it, its version above the row's and above what this device
    /// remembers; the warning is gone and writes go again.
    func testUseTheServersCopyWritesANewBaseline() async throws {
        let (w, v) = try world()
        v.manifestSeq = 9
        try v.add("Shop")
        try v.add("Second")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w, app: true)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 9])
        // The server was restored from a backup: the vault at manifest 6 with one item.
        v.rows.removeLast()
        v.manifestSeq = 6
        v.seq = 2
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)

        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 200, #"{"revision":7,"vault_seq":3,"manifest_seq":10}"#)
        let before = syncs().count
        try await repo.useServerCopy(v.id)
        XCTAssertEqual(syncs().count, before + 1)
        XCTAssertEqual(syncs().last?.query, "", "everything is fetched, not a delta")
        let put = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").last)
        XCTAssertEqual((put.body["base_seq"] as? NSNumber)?.int64Value, 6)
        XCTAssertEqual((put.body["seq"] as? NSNumber)?.int64Value, 10, "above what this device remembers")
        XCTAssertEqual((put.body["vault_seq"] as? NSNumber)?.int64Value, 2)
        XCTAssertEqual(try v.check(10, put.body["sealed"] as? String ?? ""), "ok")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(store().readManifestVersions("acc"), [v.id: 10])
        v.manifestSeq = 10
        v.seq = 3
        accept("POST /api/items", v)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 11)
    }

    func testUseTheServersCopyConflictsGateAndReaders() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Hidden")
        let tampered = try w.body([v], rows: [v.rows[0]])
        ScriptedServer.syncBodies = [tampered]
        let repo = try await repo(w, app: true)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
        // Another write in between: started over (fetched again), three times at most.
        for _ in 0..<5 { ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 409, conflict) }
        let before = syncs().count
        await assertThrows(ManifestText.busy) { try await repo.useServerCopy(v.id) }
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 3)
        XCTAssertEqual(syncs().count, before + 3)
        XCTAssertEqual((sent("PUT", "/api/vaults/\(v.id)/manifest").last?.body["seq"] as? NSNumber)?.int64Value, 5)
        XCTAssertEqual(try v.check(5, sent("PUT", "/api/vaults/\(v.id)/manifest").last?.body["sealed"] as? String ?? "", rows: [v.rows[0]]), "ok")
        XCTAssertEqual(store().readManifestVersions("acc"), [:], "nothing is remembered for a baseline that wasn't stored")
        // The manifest vanished and a member's app is too old for a new one.
        ScriptedServer.answers = [:]
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 409, #"{"error":"manifest_not_ready","message":"an app is too old"}"#)
        await assertThrows(ManifestText.notReady) { try await repo.useServerCopy(v.id) }
        // The fresh answer matches after all: nothing to accept, nothing written.
        ScriptedServer.answers = [:]
        ScriptedServer.requests = []
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.useServerCopy(v.id)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        // A reader can't.
        v.role = "read"
        ScriptedServer.syncBodies = [try w.body([v], rows: [v.rows[0]])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
        await assertThrows(ManifestText.reader) { try await repo.useServerCopy(v.id) }
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
    }

    /// An older version of an item than this device saw, under a manifest made over it (say
    /// after "Use the server's copy" on another device): this device keeps showing its newer
    /// copy, and that row counts in the check with the hash of what the server sent, so the vault
    /// matches; saving the item again replaces what the manifest records for it.
    func testANewerRowThisDeviceKeptCountsWithWhatTheServerSent() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w, app: true)
        accept("PUT /api/items/\(itemId)", v)
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        XCTAssertEqual(repo.vault?.get(itemId)?.item.name, "Shop 2")
        // The server: the item as it was, under a manifest of the current number made over that.
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.get(itemId)?.item.name, "Shop 2", "the newer copy is kept")
        XCTAssertEqual(repo.vault?.rollback?.kept, [itemId])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.copyOf("acc")?.items.first?.servedSha256, manifestDataHash(data: v.rows[0]["data"] as? String ?? ""))
        // Read again from the device (a new process): the kept row still counts that way.
        let again = try await self.repo(w, in: repo.store) { $0.preferCache = true }
        XCTAssertEqual(again.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(again.vault?.get(itemId)?.item.name, "Shop 2")
        // Saved again: the next manifest drops the served version and takes the new data.
        accept("PUT /api/items/\(itemId)", v)
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 3"))
        let put = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        XCTAssertEqual(try v.check(6, manifests(put)[0].sealed, rows: [["id": itemId, "deleted_at": NSNull(), "data": put.body["data"] ?? ""]]), "ok")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(repo.copyOf("acc")?.items.first?.servedSha256)
    }

    // MARK: Key replacement

    /// A key replacement carries the vault's next manifest, made new with the new key for the
    /// next epoch over the re-encrypted items; `manifest_conflict` is retried like an item's
    /// `revision_conflict`.
    func testAKeyReplacementCarriesARecomputedManifest() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        // The rules for a vault this account has alone, as scripted for servers before signed sharing.
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync","vault_manifest"]}"#
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w) { _ = $0.allowingOlderServers() }
        let members = #"{"members":[{"user_id":"\#(w.accountId)","email":"a@example.com","name":"Alex","role":"owner","public_key":"pk"}]}"#
        for _ in 0..<4 { ScriptedServer.answer("GET /api/vaults/\(v.id)/members", 200, members) }
        ScriptedServer.answer("POST /api/vaults/\(v.id)/rotate", 409, conflict)
        let done = try await repo.rotateVaultKeys([v.id])
        XCTAssertEqual(done.rotated, [v.id])
        let posts = sent("POST", "/api/vaults/\(v.id)/rotate")
        XCTAssertEqual(posts.count, 2, "sent again after the conflict")
        let body = posts[1].body
        let m = manifests(posts[1])
        XCTAssertEqual(m.map(\.vault), [v.id])
        XCTAssertEqual(m.first?.seq, 5)
        // Under the new key at the next epoch, over the re-encrypted items where they were.
        let wrapped = ((body["keys"] as? [[String: Any]])?.first?["wrapped_key"] as? String) ?? ""
        let newKey = try w.created.account.openVaultKey(vaultId: v.id, wrapped: wrapped, kind: "account", keyEpoch: 2, legacyAllowed: true)
        let items = body["items"] as? [[String: Any]] ?? []
        let after = zip(v.rows, items).map { old, new in ["id": new["id"] ?? "", "deleted_at": old["deleted_at"] ?? NSNull(), "data": new["data"] ?? ""] as [String: Any] }
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(try v.check(5, m[0].sealed, rows: after, key: newKey, epoch: 2), "ok")
        XCTAssertEqual(try v.check(5, m[0].sealed, rows: after), "mismatch", "not the old key's")
        // Conflicts every time: given up, in the app's words.
        ScriptedServer.answers = [:]
        for _ in 0..<5 {
            ScriptedServer.answer("GET /api/vaults/\(v.id)/members", 200, members)
            ScriptedServer.answer("POST /api/vaults/\(v.id)/rotate", 409, conflict)
        }
        await assertThrows(ManifestText.busy) { _ = try await repo.rotateVaultKeys([v.id]) }
    }

    // MARK: Part S

    /// A server that doesn't list signed sharing isn't used: no `/sync` is asked for, the copy on
    /// the device stays readable (offline) with the message, and nothing can be written.
    func testAServerWithoutSignedSharingIsNotSyncedWith() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let first = try await repo(w)
        XCTAssertEqual(first.vault?.entries.count, 1)
        XCTAssertNil(first.serverProblem)
        // The server is replaced by one without signed sharing (the features are asked again:
        // a new process, kept features gone stale).
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync"]}"#
        first.store.updateAccount("acc") { $0.featuresAt = 0 }
        let before = syncs().count
        await assertThrows(ServerSupport.updateServer) { try await first.sync() }
        XCTAssertEqual(syncs().count, before, "nothing is asked of it")
        XCTAssertEqual(first.serverProblem, ServerSupport.updateServer)
        XCTAssertEqual(first.vault?.entries.count, 1, "the copy stays readable")
        XCTAssertEqual(first.vault?.offline, true)
        await assertThrows(ServerSupport.updateServer) { try await first.createItem(self.named("Note"), vaultId: nil) }
        XCTAssertTrue(itemWrites().isEmpty)
        // A new unlock: the copy from the device, offline, with the message; still no `/sync`.
        let second = try await repo(w, in: first.store)
        await assertThrows(ServerSupport.updateServer) { try await second.createItem(self.named("Note"), vaultId: nil) }
        // (The sync behind a cache-first unlock runs after it; this one waits for it.)
        await assertThrows(ServerSupport.updateServer) { try await second.sync() }
        XCTAssertEqual(second.vault?.entries.count, 1)
        XCTAssertEqual(second.vault?.offline, true)
        XCTAssertEqual(second.serverProblem, ServerSupport.updateServer)
        XCTAssertEqual(syncs().count, before)
        // A background refresh fetches nothing either, and coming back to the app asks only for
        // the server's config.
        let locked = try await repo(w, unlock: false, in: first.store)
        try? await locked.refreshCacheLocked(accountId: "acc")
        XCTAssertEqual(syncs().count, before)
        ScriptedServer.requests = []
        await second.refreshIfStale()
        XCTAssertEqual(Set(ScriptedServer.recorded().map(\.path)), ["/api/config"])
        XCTAssertEqual(second.vault?.offline, true)
        // A server from before API 2 (no `api`, no features) is refused the same way.
        ScriptedServer.config = #"{"name":"PassAuth","signups_allowed":true}"#
        await assertThrows(ServerSupport.updateServer) { try await second.sync() }
        XCTAssertEqual(syncs().count, 0)
        // Once the server is updated, the next sync goes through and the message is gone.
        ScriptedServer.config = Self.modern
        try await second.sync()
        XCTAssertEqual(syncs().count, 1)
        XCTAssertNil(second.serverProblem)
        XCTAssertEqual(second.vault?.offline, false)
    }

    /// A config that can't be fetched is not a refusal: the app goes on with what it knows.
    func testAConfigThatCannotBeFetchedIsNotARefusal() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        for _ in 0..<20 { ScriptedServer.answer("GET /api/config", 503, #"{"error":"unavailable","message":"down"}"#) }
        let repo = try await repo(w)
        XCTAssertEqual(repo.vault?.entries.count, 1)
        XCTAssertEqual(repo.vault?.offline, false)
        XCTAssertNil(repo.serverProblem)
        XCTAssertEqual(syncs().count, 1)
    }

    /// Connecting to a server and signing in: refused before anything is sent to it.
    func testNoSignInWithAServerWithoutSignedSharing() async throws {
        let s = store()
        let repo = VaultRepository(store: s, api: ApiClient(store: s) { $0.protocolClasses = [ScriptedServer.self] })
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync"]}"#
        await assertThrows(ServerSupport.updateServer) { try await repo.setServer("https://fake.passauth.test") }
        XCTAssertEqual(repo.state.server, "")
        ScriptedServer.config = #"{"name":"PassAuth"}"#
        await assertThrows(ServerSupport.updateServer) { try await repo.setServer("https://fake.passauth.test") }
        // A server with signed sharing is connected to.
        ScriptedServer.config = Self.modern
        try await repo.setServer("https://fake.passauth.test")
        XCTAssertEqual(repo.state.server, "https://fake.passauth.test")
        // It is downgraded before the sign-in: nothing of the sign-in is sent.
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync"]}"#
        ScriptedServer.requests = []
        await assertThrows(ServerSupport.updateServer) { _ = try await repo.login(email: "a@example.com", password: self.password, secretKey: nil) }
        await assertThrows(ServerSupport.updateServer) { _ = try await repo.register(email: "a@example.com", name: "A", password: self.password, withSecretKey: false) }
        await assertThrows(ServerSupport.updateServer) { _ = try await repo.beginDeviceLogin(email: "a@example.com") }
        XCTAssertEqual(Set(ScriptedServer.recorded().map(\.path)), ["/api/config"])
    }

    // MARK: Device memory

    /// The versions seen are kept sealed next to the item edit counters: merged by the higher
    /// number (the app and its AutoFill extension both write them), kept for vaults that are
    /// gone, and deleted with the account's other device memory.
    func testTheDeviceMemoryOfManifestVersions() throws {
        let app = store()
        let ext = SecureStore(directory: dir, role: .appExtension)
        ext.load()
        XCTAssertEqual(app.readManifestVersions("acc"), [:])
        app.writeManifestVersions("acc", ["v1": 5, "v2": 2])
        ext.writeManifestVersions("acc", ["v1": 3, "v2": 4, "v3": 1])
        XCTAssertEqual(app.readManifestVersions("acc"), ["v1": 5, "v2": 4, "v3": 1])
        // Only what was seen is written: a vault that isn't named stays, 0 is never stored.
        app.writeManifestVersions("acc", ["v3": 0, "v4": 0])
        XCTAssertEqual(ext.readManifestVersions("acc"), ["v1": 5, "v2": 4, "v3": 1])
        XCTAssertEqual(app.readManifestVersions("other"), [:], "per account")
        // Sealed on the device (not readable as JSON), in the vault folder.
        let file = dir.appendingPathComponent("vault/acc.manifests")
        let blob = try Data(contentsOf: file)
        XCTAssertNil(try? JSONSerialization.jsonObject(with: blob))
        // A file that can't be opened: unknown (nil), and never written over.
        try Data("garbage".utf8).write(to: file)
        XCTAssertNil(app.readManifestVersions("acc"))
        app.writeManifestVersions("acc", ["v1": 1])
        XCTAssertEqual(try Data(contentsOf: file), Data("garbage".utf8))
        // Signing out removes it with the copy and the item edit counters.
        app.deleteCache("acc")
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertEqual(app.readManifestVersions("acc"), [:])
    }
}
