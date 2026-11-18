import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// Vault manifests and the refusal of servers without signed sharing, against a live fake server
/// (the client side of docs/ARCHITECTURE.md "Vault manifests"): every write carries the vault's
/// next manifest, which names the one it replaces; an answer is only applied to the copy when it
/// names that manifest; another device's write in between is retried three times at most; every
/// sync is checked (the chain included: a manifest that isn't built on the one this device
/// remembers is refused, with the vault's manifest log when it is more than a step ahead) and a
/// vault that doesn't match is warned about and not written to; warnings only ever come from
/// the server's answer; first manifests, old trash and "Use the server's copy" are the app's
/// own; and a server without signed sharing (or whose settings can't be read) isn't used.
@MainActor
final class ManifestContractTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"
    private static let modern = #"{"name":"PassAuth","api":2,"features":["signed_sharing","key_epoch","delta_sync","vault_manifest"],"limits":{"max_import_items":2}}"#
    nonisolated private static let zeroLink = String(repeating: "A", count: 43)

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

    /// One vault as the server holds it: its key, rows, numbers and its chain of manifests.
    ///
    /// `manifestSeq` is the version the vault is at (0: none). A test that moves it up (or
    /// changes the rows) plays other devices' writes: the manifests in between are made, each
    /// naming the one before, as honest apps would. Moving it back to a version it had with the
    /// same rows serves that manifest again (a restored backup); the same version over other
    /// rows is another manifest on the same predecessor (a fork).
    private final class Vault {
        struct Head {
            let seq: Int64
            let prev: String
            let sealed: String
            let link: String
            /// The rows it was made over (as the core takes them).
            let rows: String
        }

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
        private var head: Head?
        private var history: [Int64: Head] = [:]
        private var entries: [String: (seq: Int64, prev: String, digest: String)] = [:]

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

        /// `rows` as the core takes them (id, where it is, data or its hash). Only live or
        /// trashed counts (not when), so any time in the trash is written as 1.
        static func manifestRows(_ rows: [[String: Any]]) throws -> String {
            let list = rows.map { r -> [String: Any] in
                let trashed = r["deleted_at"].map { !($0 is NSNull) } ?? false
                var o: [String: Any] = ["id": r["id"] ?? "", "deleted_at": trashed ? 1 as Any : NSNull()]
                if let d = r["data"] { o["data"] = d } else if let h = r["data_sha256"] { o["data_sha256"] = h }
                return o
            }
            return String(decoding: try JSONSerialization.data(withJSONObject: list, options: [.withoutEscapingSlashes, .sortedKeys]), as: UTF8.self)
        }

        private func store(_ h: Head) {
            head = h
            history[h.seq] = h
            entries[h.link] = (h.seq, h.prev, manifestDataHash(data: h.sealed))
        }

        /// The vault's manifest now (nil: none); made when the test moved the vault on.
        func current() throws -> Head? {
            guard manifestSeq > 0 else { return nil }
            let sig = try Self.manifestRows(rows)
            if let h = head, h.seq == manifestSeq, h.rows == sig { return h }
            if let h = history[manifestSeq], h.rows == sig {
                head = h
                return h
            }
            var prev: String?
            var from = manifestSeq
            if let h = head, h.seq < manifestSeq {
                // Other devices' writes since: one manifest per version, each on the one before.
                prev = h.link
                from = h.seq + 1
            } else if head != nil {
                // Back to (or still at) a version over other rows: on that version's predecessor.
                prev = history[manifestSeq - 1]?.link
            } else {
                from = 1
            }
            for version in from...manifestSeq {
                let w = try key.manifestStart(vaultId: id, keyEpoch: UInt64(epoch), version: UInt64(version), prev: prev, itemsJson: sig)
                store(Head(seq: Int64(w.seq), prev: w.prev, sealed: w.sealed, link: w.link, rows: sig))
                prev = w.link
            }
            return head
        }

        /// A manifest a client wrote, stored as the vault's current one (over the rows as they are now).
        func adopt(seq: Int64, prev: String, sealed: String) throws {
            let link = try manifestLink(manifestSeq: UInt64(seq), prev: prev, sealed: sealed)
            store(Head(seq: seq, prev: prev, sealed: sealed, link: link, rows: try Self.manifestRows(rows)))
            manifestSeq = seq
        }

        /// The link of the vault's current manifest.
        func link() throws -> String { try XCTUnwrap(try current()).link }

        /// `GET …/manifest-log?after=`: the manifests of the current history above `after`, oldest first.
        func log(after: Int64) throws -> [[String: Any]] {
            var out: [[String: Any]] = []
            var at = try current()?.link
            while let l = at, let e = entries[l], e.seq > after {
                out.append(["seq": e.seq, "prev": e.prev, "digest": e.digest])
                at = e.prev
            }
            return out.reversed()
        }

        /// What a check of `rows` against a manifest a client sent says.
        func check(_ seq: Int64, prev: String, _ sealed: String, rows other: [[String: Any]]? = nil, key otherKey: VaultKey? = nil, epoch otherEpoch: Int64? = nil) throws -> String {
            try (otherKey ?? key).manifestVerify(vaultId: id, keyEpoch: UInt64(otherEpoch ?? epoch), manifestSeq: UInt64(seq), prev: prev, sealed: sealed,
                                                 rememberedVersion: nil, rememberedLink: nil, logJson: nil, itemsJson: try Self.manifestRows(other ?? rows)).status
        }

        /// The vault row of a `/sync` answer. `manifest`: another sealed text than the vault's
        /// own (`.some(nil)`: withheld); `prev`: another predecessor.
        func row(manifest: String?? = nil, prev: String?? = nil) throws -> [String: Any] {
            let h = try current()
            let text: String? = manifest ?? h?.sealed
            let before: String? = prev ?? h?.prev
            return ["id": id, "wrapped_key": wrapped, "key_kind": "account", "role": role, "rotation_pending": 0, "key_epoch": epoch, "seq": seq,
                    "meta": try key.encryptMeta(vaultId: id, metaJson: "{\"name\":\"\(name)\"}"), "share": NSNull(), "member_roster": NSNull(),
                    "member_roster_seq": 0, "manifest": text.map { $0 as Any } ?? NSNull(), "manifest_seq": manifestSeq,
                    "manifest_prev": before.map { $0 as Any } ?? NSNull(), "manifest_ok": manifestOk]
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

    /// The account's server: its vaults, and the requests it answers by itself (installed as
    /// `ScriptedServer.handler`; answers a test queued come first). Writes are applied as the
    /// real server applies them: a manifest that isn't the next one on the vault's current
    /// manifest is refused (409 `manifest_conflict`), one that is missing too (400
    /// `manifest_required`); a stored manifest is then checked against the rows the vault now
    /// holds (`problems`: every manifest a client wrote that didn't match).
    private final class Server: @unchecked Sendable {
        let created: NewAccount
        var vaults: [Vault] = []
        var accountId: String { (try? JSON.parse(created.account.legacyIdentityJson()))?.str("user_id") ?? "" }
        var revision: Int64 = 5
        var serverTime: Int64 = 1_800_000_000
        var trashDays: Int64 = 0
        /// Answer `/api/sync` from the state as it is now (everything, never a delta).
        var liveSync = false
        /// What the manifest log endpoint answers instead of the log (500, 429, 404, …).
        var logStatus: Int?
        /// Entries per answer of the log.
        var logPage = 2000
        var itemRevision: Int64 = 20
        var problems: [String] = []
        /// How many baselines the server still stores before it answers 429 (nil: no limit).
        var baselinesLeft: Int?
        /// A create of an id the server already has, with the same data, gets the first
        /// attempt's answer again (the real server's idempotent create) instead of `item_exists`.
        var replayCreates = false
        /// The next writes are stored but their answers are lost on the way (the client sees 502).
        var loseAnswers = 0
        /// Items the server no longer sends (lost or hidden) while its manifests still record
        /// them. A baseline a client writes is over what is served: they are gone for good then.
        var hidden = Set<String>()

        init(created: NewAccount) { self.created = created }

        /// A full `/sync` answer for these vaults (`rows`: other rows than the vaults' own).
        func body(_ vaults: [Vault], rows: [[String: Any]]? = nil, manifest: [String: String?] = [:], prev: [String: String?] = [:]) throws -> Data {
            let headers = try vaults.map { v in
                try v.row(manifest: manifest[v.id], prev: prev[v.id])
            }
            return try JSONSerialization.data(withJSONObject: [
                "revision": revision, "cursor": "c\(revision)", "server_time": serverTime, "trash_days": trashDays,
                "user": ["id": accountId, "email": "a@example.com", "name": "Alex", "email_verified": true, "key_pins_seq": 0, "identity": NSNull()],
                "bundle": try JSONSerialization.jsonObject(with: Data(created.bundleJson.utf8)),
                "vaults": headers, "items": rows ?? vaults.flatMap(\.rows).filter { !hidden.contains($0["id"] as? String ?? "") }, "invitations": [],
            ] as [String: Any])
        }

        private func json(_ status: Int, _ o: [String: Any]) -> (status: Int, body: Data) {
            (status, (try? JSONSerialization.data(withJSONObject: o)) ?? Data("{}".utf8))
        }

        private func refuse(_ status: Int, _ code: String) -> (status: Int, body: Data) { json(status, ["error": code, "message": code]) }

        private typealias Sent = (seq: Int64, prev: String, sealed: String)

        private func sent(_ body: [String: Any], _ vault: String) -> Sent? {
            (body["manifests"] as? [[String: Any]] ?? []).first { $0["vault_id"] as? String == vault }.flatMap { m in
                guard let seq = (m["seq"] as? NSNumber)?.int64Value, let prev = m["prev"] as? String, let sealed = m["sealed"] as? String else { return nil }
                return (seq, prev, sealed)
            }
        }

        private func sent(query: String) -> (manifest: Sent?, revision: Int64?) {
            var q: [String: String] = [:]
            for part in query.split(separator: "&") {
                let kv = part.split(separator: "=", maxSplits: 1).map(String.init)
                if kv.count == 2 { q[kv[0]] = kv[1].removingPercentEncoding ?? kv[1] }
            }
            let revision = q["revision"].flatMap { Int64($0) }
            guard let seq = q["manifest_seq"].flatMap({ Int64($0) }), let prev = q["manifest_prev"], let sealed = q["manifest"] else { return (nil, revision) }
            return ((seq, prev, sealed), revision)
        }

        /// The server's rule for a write's manifest; nil: accepted.
        private func refusal(_ v: Vault, _ m: Sent?) -> (status: Int, body: Data)? {
            guard let head = try? v.current() else { return m == nil ? nil : refuse(409, "manifest_conflict") }
            guard let m else { return refuse(400, "manifest_required") }
            return m.seq == head.seq + 1 && m.prev == head.link ? nil : refuse(409, "manifest_conflict")
        }

        /// Store a write's manifest with the rows as they are after it, and check it describes them.
        private func stored(_ v: Vault, _ m: Sent?, _ what: String) {
            v.seq += 1
            guard let m else { return }
            do {
                try v.adopt(seq: m.seq, prev: m.prev, sealed: m.sealed)
                let verdict = try v.check(m.seq, prev: m.prev, m.sealed)
                if verdict != "ok" { problems.append("\(what): the manifest sent is \(verdict) for the vault's rows") }
            } catch {
                problems.append("\(what): \(error)")
            }
        }

        /// The link of the vault's manifest now, as write answers carry it (`manifest_link`).
        private func link(_ v: Vault) -> Any { (try? v.current())?.link as Any? ?? NSNull() }

        private func answer(_ v: Vault, _ extra: [String: Any] = [:]) -> (status: Int, body: Data) {
            itemRevision += 1
            var o: [String: Any] = ["revision": itemRevision, "vault_seq": v.seq, "manifest_seq": v.manifestSeq, "manifest_link": link(v)]
            o.merge(extra) { _, new in new }
            return json(200, o)
        }

        private func find(_ item: String) -> (vault: Vault, index: Int)? {
            for v in vaults {
                if let i = v.rows.firstIndex(where: { $0["id"] as? String == item }) { return (v, i) }
            }
            return nil
        }

        func handle(_ r: ScriptedServer.Request) -> (status: Int, body: Data)? {
            guard let out = answer(to: r) else { return nil }
            if r.method != "GET", out.status == 200, loseAnswers > 0 {
                loseAnswers -= 1
                return refuse(502, "bad_gateway")
            }
            return out
        }

        private func answer(to r: ScriptedServer.Request) -> (status: Int, body: Data)? {
            let parts = r.path.split(separator: "/").map(String.init)
            if r.method == "GET", r.path == "/api/sync" {
                guard liveSync, let body = try? body(vaults) else { return nil }
                return (200, body)
            }
            if r.method == "GET", r.path == "/api/sync/revision" {
                guard liveSync else { return nil }
                return json(200, ["revision": revision, "vaults": Dictionary(uniqueKeysWithValues: vaults.map { ($0.id, $0.seq) })])
            }
            // /api/vaults/{id}/…
            if parts.count == 4, parts[1] == "vaults", let v = vaults.first(where: { $0.id == parts[2] }) {
                switch (r.method, parts[3]) {
                case ("GET", "manifest-log"):
                    if let s = logStatus { return refuse(s, s == 404 ? "not_found" : "unavailable") }
                    let after = sent(query: r.query.replacingOccurrences(of: "after=", with: "revision=")).revision ?? 0
                    guard let all = try? v.log(after: after) else { return refuse(500, "internal") }
                    return json(200, ["entries": Array(all.prefix(logPage)), "more": all.count > logPage])
                case ("PUT", "manifest"):
                    let b = r.body
                    guard let base = (b["base_seq"] as? NSNumber)?.int64Value, let seq = (b["seq"] as? NSNumber)?.int64Value,
                          let prev = b["prev"] as? String, let sealed = b["sealed"] as? String,
                          let vaultSeq = (b["vault_seq"] as? NSNumber)?.int64Value else { return refuse(400, "bad_request") }
                    if v.role == "read" { return refuse(403, "forbidden") }
                    let head = try? v.current()
                    guard base == (head?.seq ?? 0), prev == (head?.link ?? ManifestContractTests.zeroLink), vaultSeq == v.seq else {
                        return refuse(409, "manifest_conflict")
                    }
                    // Every manifest is the next version, a first one and a baseline too.
                    if seq != base + 1 { return refuse(400, "bad_request") }
                    if base == 0 && !v.manifestOk { return refuse(409, "manifest_not_ready") }
                    if base > 0, let left = baselinesLeft {
                        if left <= 0 { return refuse(429, "rate_limited") }
                        baselinesLeft = left - 1
                    }
                    v.rows.removeAll { hidden.contains($0["id"] as? String ?? "") }
                    stored(v, (seq, prev, sealed), "PUT manifest")
                    return answer(v)
                default:
                    return nil
                }
            }
            if parts.count == 5, parts[1] == "vaults", parts[3] == "trash", parts[4] == "purge", r.method == "POST",
               let v = vaults.first(where: { $0.id == parts[2] }) {
                let items = r.body["items"] as? [[String: Any]] ?? []
                guard !items.isEmpty, items.count <= 2 else { return refuse(400, "bad_request") }
                let m = sent(r.body, v.id)
                if let no = refusal(v, m) { return no }
                var gone = Set<String>()
                for i in items {
                    guard let id = i["id"] as? String, let row = v.rows.first(where: { $0["id"] as? String == id }), !(row["deleted_at"] is NSNull),
                          gone.insert(id).inserted else { return refuse(409, "revision_conflict") }
                    if let rev = (i["revision"] as? NSNumber)?.int64Value, rev != (row["revision"] as? NSNumber)?.int64Value { return refuse(409, "revision_conflict") }
                }
                v.rows.removeAll { gone.contains($0["id"] as? String ?? "") }
                stored(v, m, "trash/purge")
                return answer(v, ["purged": gone.count])
            }
            guard parts.count >= 2, parts[1] == "items" else { return nil }
            // POST /api/items
            if parts.count == 2, r.method == "POST" {
                guard let vid = r.body["vault_id"] as? String, let v = vaults.first(where: { $0.id == vid }), let id = r.body["id"] as? String else { return refuse(400, "bad_request") }
                if let at = find(id) {
                    // The same create again: the first attempt's answer (the manifest sent this
                    // time is not stored; the answer names the one that is).
                    let row = at.vault.rows[at.index]
                    guard replayCreates, at.vault === v, row["data"] as? String == r.body["data"] as? String else { return refuse(409, "item_exists") }
                    return json(200, ["revision": row["revision"] ?? 0, "vault_seq": v.seq, "manifest_seq": v.manifestSeq, "manifest_link": link(v)])
                }
                let m = sent(r.body, vid)
                if let no = refusal(v, m) { return no }
                itemRevision += 1
                v.rows.append(["id": id, "vault_id": vid, "item_key": r.body["key"] ?? "", "data": r.body["data"] ?? "", "revision": itemRevision,
                               "deleted_at": NSNull(), "created_at": 1_700_000_000, "updated_at": 1_700_000_000])
                stored(v, m, "POST items")
                return json(200, ["revision": itemRevision, "vault_seq": v.seq, "manifest_seq": v.manifestSeq, "manifest_link": link(v)])
            }
            guard parts.count >= 3, let at = find(parts[2]) else { return parts.count >= 3 ? refuse(404, "not_found") : nil }
            let v = at.vault
            let rowRevision = (v.rows[at.index]["revision"] as? NSNumber)?.int64Value
            switch (r.method, parts.count == 4 ? parts[3] : "") {
            case ("PUT", ""):
                if let rev = (r.body["revision"] as? NSNumber)?.int64Value, rev != rowRevision { return refuse(409, "revision_conflict") }
                let target = vaults.first { $0.id == r.body["vault_id"] as? String } ?? v
                var row = v.rows[at.index]
                itemRevision += 1
                row["item_key"] = r.body["key"] ?? ""
                row["data"] = r.body["data"] ?? ""
                row["revision"] = itemRevision
                if target === v {
                    let m = sent(r.body, v.id)
                    if let no = refusal(v, m) { return no }
                    v.rows[at.index] = row
                    stored(v, m, "PUT items")
                } else {
                    // A move: each vault's own manifest, both or nothing.
                    let left = sent(r.body, v.id), entered = sent(r.body, target.id)
                    if let no = refusal(v, left) ?? refusal(target, entered) { return no }
                    row["vault_id"] = target.id
                    v.rows.remove(at: at.index)
                    target.rows.append(row)
                    stored(v, left, "PUT items (the vault it leaves)")
                    stored(target, entered, "PUT items (the vault it enters)")
                }
                var o: [String: Any] = ["revision": itemRevision, "vault_seq": target.seq, "manifest_seq": target.manifestSeq, "manifest_link": link(target)]
                if target !== v { o["manifest_links"] = [v.id: link(v), target.id: link(target)] }
                return json(200, o)
            case ("DELETE", ""), ("POST", "restore"), ("DELETE", "permanent"):
                let q = sent(query: r.query)
                if let rev = q.revision, rev != rowRevision { return refuse(409, "revision_conflict") }
                if let no = refusal(v, q.manifest) { return no }
                if parts.count == 4 && parts[3] == "permanent" {
                    v.rows.remove(at: at.index)
                } else {
                    let restored: Any = NSNull(), trashed: Any = serverTime
                    v.rows[at.index]["deleted_at"] = parts.count == 4 ? restored : trashed
                    itemRevision += 1
                    v.rows[at.index]["revision"] = itemRevision
                }
                stored(v, q.manifest, "\(r.method) \(parts.count == 4 ? parts[3] : "items")")
                return json(200, ["revision": itemRevision, "vault_seq": v.seq, "manifest_seq": v.manifestSeq, "manifest_link": link(v)])
            default:
                return nil
            }
        }
    }

    private func world() throws -> (Server, Vault) {
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let server = Server(created: created)
        let vault = try Vault(created.account, name: "Personal")
        server.vaults = [vault]
        ScriptedServer.handler = { [server] r in server.handle(r) }
        return (server, vault)
    }

    private func store(_ role: SecureStore.Role = .app) -> SecureStore {
        let s = SecureStore(directory: dir, role: role)
        s.load()
        return s
    }

    private func seed(_ store: SecureStore, _ w: Server, features: [String]? = nil) {
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = w.created.bundleJson
            if let features {
                acc.features = features
                acc.featuresAt = Date().timeIntervalSince1970
                acc.api = 2
            }
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
    }

    private func repo(_ w: Server, app: Bool = false, unlock: Bool = true, in existing: SecureStore? = nil,
                      configure: (VaultRepository) -> Void = { _ in }) async throws -> VaultRepository {
        let store = existing ?? self.store()
        if existing == nil { seed(store, w) }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] })
        repo.sharingMemory = InMemorySharingMemory()
        repo.isApp = app
        configure(repo)
        if unlock { try await repo.unlock(password: password, secretKey: nil) }
        return repo
    }

    /// The sync a cache-first unlock starts in the background has run (it queues behind the lock).
    private func settled(_ repo: VaultRepository) async {
        await repo.lock.run {}
        await Task.yield()
        await repo.lock.run {}
    }

    // MARK: Reading what was sent

    private func sent(_ method: String, _ suffix: String) -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.method == method && $0.path.hasSuffix(suffix) }
    }

    private func syncs() -> [ScriptedServer.Request] { sent("GET", "/api/sync") }
    private func logs() -> [ScriptedServer.Request] { sent("GET", "/manifest-log") }

    private func itemWrites() -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.path.hasPrefix("/api/items") }
    }

    private func manifests(_ r: ScriptedServer.Request) -> [(vault: String, seq: Int64, prev: String, sealed: String)] {
        (r.body["manifests"] as? [[String: Any]] ?? []).map {
            ($0["vault_id"] as? String ?? "", ($0["seq"] as? NSNumber)?.int64Value ?? -1, $0["prev"] as? String ?? "", $0["sealed"] as? String ?? "")
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

    /// What the device remembers for `v` (version and link).
    private func remembered(_ v: Vault, in s: SecureStore? = nil) -> ManifestMark? { (s ?? store()).readManifestMemory("acc")?[v.id] }

    /// The vault's manifest as the server holds it now, as a device would remember it.
    private func mark(_ v: Vault) throws -> ManifestMark {
        let h = try XCTUnwrap(try v.current())
        return ManifestMark(version: UInt64(h.seq), link: h.link)
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
        e = try XCTUnwrap(repo.vault?.get(itemId))
        try await repo.restoreItem(e)
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        try await repo.purgeItem(try XCTUnwrap(repo.vault?.get(itemId)))
        let writes = itemWrites()
        XCTAssertEqual(writes.map { "\($0.method) \($0.path)" }, ["POST /api/items", "PUT /api/items/\(itemId)", "DELETE /api/items/\(itemId)",
                                                                 "POST /api/items/\(itemId)/restore", "DELETE /api/items/\(itemId)", "DELETE /api/items/\(itemId)/permanent"])
        for r in writes {
            XCTAssertNil(r.body["manifests"], "\(r.method) \(r.path)")
            XCTAssertEqual(r.query, "", "\(r.method) \(r.path)")
        }
        XCTAssertEqual(store().readManifestMemory("acc"), [:])
        XCTAssertEqual(w.problems, [])
    }

    /// Create, edit, trash, restore and delete for good each carry the vault's next manifest
    /// (body, or query for the requests without one, with the item's revision), which names the
    /// manifest it replaces; an answer that names it is applied to the copy without a sync, so
    /// the next write builds on it, and its link is what the device remembers.
    func testEveryWriteCarriesTheNextManifestAndIsAppliedToTheCopy() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v), "the version and the link of the manifest checked")
        XCTAssertEqual(remembered(v)?.version, 4)
        let before = syncs().count

        // Create.
        var link = try v.link()
        try await repo.createItem(named("Note"), vaultId: nil)
        var r = try XCTUnwrap(sent("POST", "/api/items").last)
        var m = manifests(r)
        XCTAssertEqual(m.map(\.vault), [v.id])
        XCTAssertEqual(m.first?.seq, 5)
        XCTAssertEqual(m.first?.prev, link, "it names the manifest it replaces")
        XCTAssertEqual(r.query, "", "never in a header or a query when there is a body")
        XCTAssertNil(r.headers.keys.first { $0.lowercased().contains("manifest") })
        XCTAssertEqual(remembered(v), try mark(v), "what this device wrote is remembered with its link")
        XCTAssertEqual(repo.copyOf("acc")?.vaults.first?.manifestPrev, link, "the row carries all three fields")

        // Edit.
        link = try v.link()
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        r = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        m = manifests(r)
        XCTAssertEqual(m.first?.seq, 6)
        XCTAssertEqual(m.first?.prev, link)
        XCTAssertEqual((r.body["revision"] as? NSNumber)?.int64Value, 3)

        // Trash: revision and manifest (version, predecessor, text) in the query.
        link = try v.link()
        let edited = try XCTUnwrap(repo.vault?.get(itemId)).revision
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        r = try XCTUnwrap(sent("DELETE", "/api/items/\(itemId)").last)
        var q = query(r)
        XCTAssertEqual(q["revision"], "\(edited)")
        XCTAssertEqual(q["manifest_seq"], "7")
        XCTAssertEqual(q["manifest_prev"], link)
        XCTAssertNotNil(q["manifest"])
        XCTAssertTrue(r.body.isEmpty)
        XCTAssertNotNil(repo.vault?.trash.first { $0.id == itemId })

        // Restore.
        link = try v.link()
        try await repo.restoreItem(try XCTUnwrap(repo.vault?.get(itemId)))
        q = query(try XCTUnwrap(sent("POST", "/api/items/\(itemId)/restore").last))
        XCTAssertEqual(q["manifest_seq"], "8")
        XCTAssertEqual(q["manifest_prev"], link)

        // Delete the trashed item for good.
        link = try v.link()
        let old = try XCTUnwrap(repo.vault?.trash.first)
        try await repo.purgeItem(old)
        q = query(try XCTUnwrap(sent("DELETE", "/api/items/\(old.id)/permanent").last))
        XCTAssertEqual(q["revision"], "3")
        XCTAssertEqual(q["manifest_seq"], "9")
        XCTAssertEqual(q["manifest_prev"], link)

        // All of it without asking the server again; every manifest matched the rows the server
        // then held; the vault still matches, the last version and link are remembered.
        XCTAssertEqual(w.problems, [])
        XCTAssertEqual(syncs().count, before)
        XCTAssertTrue(logs().isEmpty)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.entries.map(\.item.name).sorted(), ["Note", "Shop 2"])
        XCTAssertEqual(remembered(v), try mark(v))
        XCTAssertEqual(remembered(v)?.version, 9)
        // A sync that shows the same version shows the same link: still fine.
        w.liveSync = true
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
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
        XCTAssertEqual(remembered(v)?.version, 4, "nothing is remembered for a write the copy doesn't carry")
    }

    /// A write that isn't built on the vault's current manifest is refused by the server (409
    /// `manifest_conflict`): sync, check, compute the manifest again from the fresh row and
    /// resend, three times in all; then "This vault changed on another device. Try again."
    func testAConflictIsRetriedThreeTimesAtMost() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        let fourth = try v.link()

        // Another device wrote meanwhile: the vault is at 5 with one more item.
        v.manifestSeq = 5
        v.seq = 4
        try v.add("Theirs")
        let fifth = try v.link()
        let id = try await repo.createItem(named("Mine"), vaultId: nil)
        let posts = sent("POST", "/api/items")
        XCTAssertEqual(posts.count, 2)
        XCTAssertEqual(posts.map { manifests($0).first?.seq }, [5, 6])
        XCTAssertEqual(posts.map { manifests($0).first?.prev }, [fourth, fifth], "the first wasn't built on the vault's current manifest; the second is")
        XCTAssertEqual(posts.map { $0.body["id"] as? String }, [id, id], "a create keeps its id")
        XCTAssertEqual(w.problems, [])
        XCTAssertEqual(repo.vault?.entries.count, 3)

        // An edit: not the "changed on another device — overwrite?" conflict, as long as the
        // item itself is as it was.
        ScriptedServer.answer("PUT /api/items/\(itemId)", 409, conflict)
        ScriptedServer.answer("PUT /api/items/\(itemId)", 409, conflict)
        let entry = try XCTUnwrap(repo.vault?.get(itemId))
        try await repo.updateItem(entry, named("Shop 2"))
        XCTAssertEqual(sent("PUT", "/api/items/\(itemId)").count, 3)

        // Conflicts every time: given up after three sends, in the app's words.
        for _ in 0..<5 { ScriptedServer.answer("DELETE /api/items/\(itemId)", 409, conflict) }
        await assertThrows("This vault changed on another device. Try again.") {
            try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        }
        XCTAssertEqual(sent("DELETE", "/api/items/\(itemId)").count, 3)
        ScriptedServer.answers = [:]
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
        XCTAssertEqual(w.problems, [])
    }

    /// After a conflict the write's own rules run on the fresh copy: an item whose content
    /// changed elsewhere is the usual conflict, one that is gone says so, and a trash, restore
    /// or delete that is already done is done.
    func testAfterAConflictTheItemsOwnRulesDecide() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        let goneId = try v.add("Gone")
        w.liveSync = true
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

        // Trashing what is gone by now: done after the sync, nothing sent again.
        ScriptedServer.answer("DELETE /api/items/\(goneId)", 409, conflict)
        try await repo.trashItem(gone)
        XCTAssertEqual(sent("DELETE", "/api/items/\(goneId)").count, 1)
        XCTAssertNil(repo.vault?.get(goneId))
        XCTAssertEqual(logs().count, 1, "two versions ahead: the log connected them")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
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
        w.liveSync = true
        let repo = try await repo(w)
        // Another device started the vault's manifest since.
        v.manifestSeq = 1
        v.seq = 4
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        let puts = sent("PUT", "/api/items/\(itemId)")
        XCTAssertEqual(puts.count, 2)
        XCTAssertNil(puts[0].body["manifests"])
        XCTAssertEqual(manifests(puts[1]).first?.seq, 2)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v))
        XCTAssertEqual(remembered(v)?.version, 2)
        XCTAssertEqual(w.problems, [])
        // The same for a request without a body.
        for _ in 0..<4 { ScriptedServer.answer("DELETE /api/items/\(itemId)", 400, required) }
        await assertThrows(ManifestText.busy) { try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId))) }
        XCTAssertEqual(sent("DELETE", "/api/items/\(itemId)").count, 3)
    }

    /// A move changes two vaults: the request carries each one's next manifest (without the item
    /// in the vault it leaves, with its re-encrypted data in the one it enters), each naming its
    /// own vault's current one, only for vaults that have one; the copy is synced afterwards.
    func testAMoveCarriesBothVaultsManifests() async throws {
        let (w, a) = try world()
        let b = try Vault(w.created.account, name: "Work")
        let plain = try Vault(w.created.account, name: "Plain")
        plain.manifestOk = false
        w.vaults = [a, b, plain]
        a.manifestSeq = 4
        b.manifestSeq = 2
        let itemId = try a.add("Shop")
        try a.add("Stays")
        try b.add("There")
        w.liveSync = true
        let repo = try await repo(w)
        let before = syncs().count
        let links = [a.id: try a.link(), b.id: try b.link()]
        try await repo.moveItem(try XCTUnwrap(repo.vault?.get(itemId)), to: b.id)
        var put = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        var m = manifests(put)
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: m.map { ($0.vault, $0.seq) }), [a.id: 5, b.id: 3])
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: m.map { ($0.vault, $0.prev) }), links)
        XCTAssertEqual(put.body["vault_id"] as? String, b.id)
        XCTAssertEqual(w.problems, [], "each manifest matched its vault's rows after the move")
        XCTAssertEqual(syncs().count, before + 1, "a move is never applied to the copy")
        XCTAssertEqual(repo.vault?.vaults.map(\.manifest), [.ok, .ok, ManifestStatus.none])
        XCTAssertEqual(remembered(a), try mark(a))
        XCTAssertEqual(remembered(b), try mark(b))
        // Into a vault without a manifest: only the one it leaves.
        try await repo.moveItem(try XCTUnwrap(repo.vault?.get(itemId)), to: plain.id)
        put = try XCTUnwrap(sent("PUT", "/api/items/\(itemId)").last)
        m = manifests(put)
        XCTAssertEqual(m.map(\.vault), [b.id])
        XCTAssertEqual(w.problems, [])
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
        XCTAssertEqual(store().readManifestMemory("acc"), [:], "nothing is remembered")

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
        XCTAssertEqual(remembered(v), try mark(v))
        XCTAssertNotNil(repo.vault?.get(hiddenId))
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 5)
        XCTAssertEqual(w.problems, [])
    }

    /// Every way the server's copy can differ is a mismatch: an item brought back, one put back
    /// from the trash, an older version of one (also when the server names the hash to check it
    /// with), an item that can't be opened or comes without its data, a `deleted_at` that is no
    /// time, a manifest that isn't this vault's or names another predecessor.
    func testWhatAServerCanChangeIsNoticed() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Trashed", trashedAt: 1_700_000_500)
        let good = try w.body([v])
        ScriptedServer.syncBodies = [good]
        let repo = try await repo(w)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        let seen = try XCTUnwrap(remembered(v))
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
        // The same, with the hash of the current data in `served_sha256`: that field is this
        // device's own note on a row it kept, never a server's to set.
        _ = try await after(good)
        rows[0]["served_sha256"] = manifestDataHash(data: v.rows[0]["data"] as? String ?? "")
        s = try await after(try w.body([v], rows: rows))
        XCTAssertEqual(s, .mismatch, "the row is checked with the data the server sent")
        XCTAssertEqual(repo.vault?.entries.first?.item.name, "Shop, before")
        XCTAssertTrue(repo.copyOf("acc")?.items.allSatisfy { $0.servedSha256 == nil } ?? false, "and never stored from an answer")
        // A key that doesn't open the item (the data, and so the sum, is right): this device
        // opened the row before, so it goes on with the key it has (T1 a). Nothing is hidden.
        _ = try await after(good)
        rows = v.rows
        rows[0]["item_key"] = older.key
        s = try await after(try w.body([v], rows: rows))
        XCTAssertEqual(s, .ok)
        XCTAssertEqual(repo.vault?.entries.count, 1, "still shown, from the row the device has")
        XCTAssertEqual(repo.vault?.unopenable, [])
        // A trashed item without its data, with the right hash: this app asks for whole rows.
        // The manifest adds up; the row is listed as one that can't be opened (T1 c).
        _ = try await after(good)
        s = try await after(try w.body([v], rows: [v.rows[0], Vault.summary(v.rows[1])]))
        XCTAssertEqual(s, .ok)
        XCTAssertEqual(repo.vault?.unopenable.map(\.id), [v.rows[1]["id"] as? String ?? ""])
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 1)
        // A `deleted_at` that is no time: never a live item, never a match.
        _ = try await after(good)
        rows = v.rows
        rows[1]["deleted_at"] = 0
        s = try await after(try w.body([v], rows: rows))
        XCTAssertEqual(s, .mismatch)
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Shop"], "in the trash for this app, as for the core")
        // The manifest withheld, one of another version under this number, another predecessor.
        s = try await after(try w.body([v], manifest: [v.id: nil]))
        XCTAssertEqual(s, .mismatch)
        let other = try v.key.manifestStart(vaultId: v.id, keyEpoch: 1, version: 3, prev: nil, itemsJson: try Vault.manifestRows(v.rows))
        s = try await after(try w.body([v], manifest: [v.id: other.sealed]))
        XCTAssertEqual(s, .mismatch)
        s = try await after(try w.body([v], prev: [v.id: nil]))
        XCTAssertEqual(s, .mismatch)
        s = try await after(try w.body([v], prev: [v.id: Self.zeroLink]))
        XCTAssertEqual(s, .mismatch)
        XCTAssertEqual(remembered(v), seen, "never lowered, nothing new remembered")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
    }

    /// An older manifest than this device saw (a restored backup, or a server replaying an old
    /// state that is consistent in itself), and no manifest after one was seen: a rollback. An
    /// answer behind what this device remembers is asked for again, in full, twice at most,
    /// before the warning is raised.
    func testAnOlderOrVanishedManifestIsARollback() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        let old = try w.body([v])
        v.manifestSeq = 6
        try v.add("Newer")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        let seen = try XCTUnwrap(remembered(v))
        XCTAssertEqual(seen.version, 6)
        ScriptedServer.syncBodies = [old]
        var before = syncs().count
        try await repo.sync()
        XCTAssertEqual(syncs().suffix(3).map(\.query), ["since=c5", "", ""], "everything is fetched again, twice at most, before it is believed")
        XCTAssertEqual(syncs().count, before + 3)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(remembered(v), seen)
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        // Already warned about: the next sync is one request.
        before = syncs().count
        try await repo.sync()
        XCTAssertEqual(syncs().count, before + 1)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        // An answer that was only behind for a moment (the second try is current): no warning.
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        ScriptedServer.syncBodies = [old, try w.body([v])]
        before = syncs().count
        try await repo.sync()
        XCTAssertEqual(syncs().count, before + 2)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        // No manifest at all any more (and a server that no longer lists the feature).
        v.manifestSeq = 0
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["signed_sharing","key_epoch","delta_sync"]}"#
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        XCTAssertTrue(itemWrites().isEmpty)
    }

    // MARK: The chain

    /// Fork then join, without the log: this device wrote version 5; the server then shows
    /// another manifest at version 5 (a branch another device built on the older state, which
    /// lacks this device's item). The same version with another link: a mismatch.
    func testForkThenJoinAtTheSameVersionIsNoticed() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        let branchPoint = v.rows
        let mine = try await repo.createItem(named("Mine"), vaultId: nil)
        XCTAssertEqual(remembered(v)?.version, 5)
        let own = try XCTUnwrap(remembered(v))
        // The other branch: version 5 over the rows without this device's item, plus an edit.
        v.rows = branchPoint
        try v.add("Theirs")
        XCTAssertNotEqual(try v.link(), own.link)
        XCTAssertEqual(try v.current()?.seq, 5)
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch, "consistent in itself, but not the history this device wrote")
        XCTAssertNil(repo.vault?.get(mine), "the server's rows are shown, with the warning")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(remembered(v), own, "what this device remembers is untouched")
        XCTAssertTrue(logs().isEmpty, "no log is needed to see it")
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
    }

    /// Fork then join, with the log: the other branch has moved on past this device's version.
    /// The manifest is ahead, so the vault's log is fetched; it doesn't lead back to the manifest
    /// this device remembers: a mismatch.
    func testForkThenJoinFurtherAheadIsNoticedThroughTheLog() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        let branchPoint = v.rows
        try await repo.createItem(named("Mine"), vaultId: nil)
        let own = try XCTUnwrap(remembered(v))
        XCTAssertEqual(own.version, 5)
        // The other branch, two writes further: versions 5 (another one), 6 and 7.
        v.rows = branchPoint
        try v.add("Theirs")
        _ = try v.current()
        v.manifestSeq = 7
        try v.add("Theirs too")
        try await repo.sync()
        XCTAssertEqual(logs().last?.query, "after=5", "asked from the version this device remembers")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(remembered(v), own)
        // One step ahead on the other branch (its version 6 names its own version 5): the same.
        v.manifestSeq = 6
        v.rows.removeLast()
        _ = try v.current()
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
    }

    /// Several honest writes ahead: the manifest log connects what the server shows to what this
    /// device remembers (pages followed), and the new version and link are remembered.
    func testSeveralVersionsAheadAreConnectedByTheLog() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        XCTAssertTrue(logs().isEmpty, "first sight needs no log")
        // One version ahead names the remembered manifest itself: no log.
        v.manifestSeq = 5
        try v.add("Five")
        try await repo.sync()
        XCTAssertTrue(logs().isEmpty)
        XCTAssertEqual(remembered(v), try mark(v))
        // Three ahead.
        v.manifestSeq = 8
        try v.add("Eight")
        try await repo.sync()
        XCTAssertEqual(logs().map(\.query), ["after=5"])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v))
        XCTAssertEqual(remembered(v)?.version, 8)
        // The log in pages: each next page asked from the last entry of the one before.
        ScriptedServer.requests = []
        w.logPage = 1
        v.manifestSeq = 11
        try v.add("Eleven")
        try await repo.sync()
        XCTAssertEqual(logs().map(\.query), ["after=8", "after=9", "after=10"])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v)?.version, 11)
        // More pages than a device follows (five requests): the log doesn't connect.
        ScriptedServer.requests = []
        v.manifestSeq = 18
        try v.add("Eighteen")
        try await repo.sync()
        XCTAssertEqual(logs().count, 2 * VaultManifest.logRequests, "asked again in full before the warning, five requests each time")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(remembered(v)?.version, 11)
        // With whole pages again it connects, and the warning is gone.
        w.logPage = 2000
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v))
    }

    /// The log can't be fetched (no answer, a server error, too many requests): the sync has
    /// failed. The answer isn't adopted: the previous copy and verdict stay, nothing is
    /// remembered, no warning is shown, and the next sync tries again.
    func testAnAnswerWhoseLogCannotBeFetchedIsNotAdopted() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        let seen = try XCTUnwrap(remembered(v))
        let copy = try XCTUnwrap(repo.copyOf("acc"))
        v.manifestSeq = 7
        try v.add("Newer")
        for status in [500, 503, 429] {
            w.logStatus = status
            do {
                try await repo.sync()
                XCTFail("the sync failed (\(status))")
            } catch {
                XCTAssertTrue(error is ApiError, "\(error)")
            }
            XCTAssertEqual(repo.copyOf("acc"), copy, "the previous copy, rows and cursor (\(status))")
            XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Shop"], "never the new rows with the old verdict")
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
            XCTAssertEqual(repo.vault?.manifestWarnings.count, 0, "no warning")
            XCTAssertEqual(remembered(v), seen)
        }
        // Nothing is written into the vault meanwhile either: the server refuses a write built
        // on the older manifest, and the sync that follows fails the same way.
        do {
            try await repo.createItem(named("Note"), vaultId: nil)
            XCTFail("the write waits")
        } catch {
            XCTAssertTrue(error is ApiError, "\(error)")
        }
        XCTAssertEqual(v.rows.count, 2, "nothing reached the vault")
        // The copy on the device is the previous one too (a new process opens that).
        let other = try await self.repo(w, in: repo.store) { $0.preferCache = true }
        XCTAssertEqual(other.vault?.entries.map(\.item.name), ["Shop"])
        XCTAssertEqual(other.vault?.vaults.first?.manifest, .ok)
        // The log answers again: adopted, checked, remembered.
        w.logStatus = nil
        try await repo.sync()
        XCTAssertEqual(repo.vault?.entries.map(\.item.name).sorted(), ["Newer", "Shop"])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v))
    }

    /// 404 (or 400) from the log endpoint is an answer, not a failure: there is no such history.
    func testNoLogForTheVaultIsAMismatch() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        v.manifestSeq = 7
        try v.add("Newer")
        for status in [404, 400] {
            let seen = try XCTUnwrap(remembered(v))
            w.logStatus = status
            try await repo.sync()
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch, "\(status)")
            XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
            XCTAssertEqual(remembered(v), seen)
            w.logStatus = nil
            try await repo.sync()
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
            v.manifestSeq += 3
        }
    }

    // MARK: The copy on the device, the app and its AutoFill extension

    /// Background App Refresh has no keys, so it can't check what the server sends. What it
    /// fetches never replaces the copy on the device (which only ever holds what an unlocked app
    /// checked): it waits next to it and is checked at the next unlock. A server that answers a
    /// background refresh with an item hidden, an item brought back, an older version of an item
    /// or an older state of the whole vault gets nowhere: the next AutoFill open and the next app
    /// unlock show (and fill from) the checked rows, nothing is asked of the server for that, and
    /// no item is lost from the device. (rereview-mobile F1, rule S3.)
    func testABackgroundRefreshNeverReplacesTheCheckedCopy() async throws {
        let (w, v) = try world()
        let shopId = try v.add("Shop", username: "alice", password: "pw-old", url: "https://shop.example.com")
        try v.add("Second")
        // An older state of the whole vault (manifest 3, Shop with its old password)…
        v.manifestSeq = 3
        let olderState = try w.body([v])
        let oldShop = v.rows[0]
        // …and the vault as it is now: Shop edited (its edit counter went up), manifest 4.
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Shop"
        item.login?.username = "alice"
        item.login?.password = "pw-new"
        item.login?.urls = [LoginUrl(url: "https://shop.example.com", match: .default)]
        let edited = try v.key.updateItem(encrypted: EncryptedItem(id: shopId, vaultId: v.id, key: oldShop["item_key"] as? String ?? "", data: oldShop["data"] as? String ?? ""),
                                          itemJson: ItemCodec.encode(item))
        v.rows[0]["item_key"] = edited.key
        v.rows[0]["data"] = edited.data
        v.rows[0]["revision"] = 4
        v.manifestSeq = 4
        let honest = try w.body([v])
        try v.add("Ghost")
        let ghost = v.rows.removeLast()

        ScriptedServer.syncBodies = [honest]
        let shared = store()
        seed(shared, w)
        let first = try await repo(w, in: shared)
        XCTAssertEqual(first.vault?.vaults.first?.manifest, .ok)
        let seen = try XCTUnwrap(remembered(v, in: shared))
        XCTAssertEqual(seen.version, 4)
        let locked = try await repo(w, unlock: false, in: shared)

        func assertChecked(_ r: VaultRepository, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertEqual(r.vault?.entries.map(\.item.name).sorted(), ["Second", "Shop"], what, file: file, line: line)
            XCTAssertEqual(r.vault?.get(shopId)?.item.login?.password, "pw-new", "\(what): what AutoFill fills", file: file, line: line)
            XCTAssertNil(r.vault?.rollback, what, file: file, line: line)
            XCTAssertEqual(r.vault?.manifestWarnings.count, 0, what, file: file, line: line)
        }
        let tampered: [(String, Data)] = [
            ("an item hidden", try w.body([v], rows: [v.rows[0]])),
            ("an item brought back", try w.body([v], rows: v.rows + [ghost])),
            ("an older version of an item", try w.body([v], rows: [oldShop, v.rows[1]])),
            ("an older state of the vault", olderState),
        ]
        for (what, body) in tampered {
            // The refresh keeps the answer aside; the copy on the device is untouched.
            let checkedCopy = try XCTUnwrap(shared.readCache("acc"))
            ScriptedServer.syncBodies = [body]
            try await locked.refreshCacheLocked(accountId: "acc")
            XCTAssertTrue(shared.hasRefreshed("acc"), what)
            XCTAssertEqual(shared.readCache("acc"), checkedCopy, "\(what): the checked copy is still on the device")
            // The next AutoFill open (cache first, no sync): the checked rows, the answer dropped.
            let requests = ScriptedServer.recorded().count
            let autofill = try await repo(w, in: shared) { $0.preferCache = true }
            XCTAssertEqual(ScriptedServer.recorded().count, requests, "\(what): checked without the server")
            XCTAssertEqual(autofill.vault?.offline, true)
            assertChecked(autofill, "\(what), AutoFill")
            XCTAssertEqual(autofill.vault?.vaults.first?.manifest, .ok, what)
            XCTAssertEqual(autofill.vault?.refreshedRejected, true, what)
            XCTAssertFalse(shared.hasRefreshed("acc"), "\(what): dropped")
            XCTAssertEqual(shared.readCache("acc"), checkedCopy, what)
            XCTAssertEqual(remembered(v, in: shared), seen, what)

            // Again, and this time the app unlocks next.
            ScriptedServer.syncBodies = [body]
            try await locked.refreshCacheLocked(accountId: "acc")
            XCTAssertTrue(shared.hasRefreshed("acc"), what)
            ScriptedServer.syncBodies = [honest]
            let app = try await repo(w, app: true, in: shared)
            assertChecked(app, "\(what), the app at unlock")
            XCTAssertEqual(app.vault?.refreshedRejected, true, what)
            await settled(app)
            assertChecked(app, "\(what), the app after its sync")
            XCTAssertEqual(app.vault?.vaults.first?.manifest, .ok, what)
            XCTAssertFalse(shared.hasRefreshed("acc"), what)
            XCTAssertEqual(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.items.first { $0.id == shopId }?.data, edited.data,
                           "\(what): the newer copy of the item is still on the device")
            XCTAssertEqual(remembered(v, in: shared), seen, what)
        }
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        XCTAssertTrue(itemWrites().isEmpty)
    }

    /// An honest background refresh is adopted at the next unlock: checked with the keys like
    /// any answer of the server (every vault matches its manifest, nothing is older than this
    /// device saw), it becomes the copy and is shown, without asking the server.
    func testAnHonestBackgroundRefreshIsAdoptedAtUnlock() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let shared = store()
        seed(shared, w)
        _ = try await repo(w, in: shared)
        let locked = try await repo(w, unlock: false, in: shared)
        // Another device saved an item: the vault is one manifest further.
        try v.add("Third")
        v.manifestSeq = 5
        v.seq += 1
        w.revision += 1
        ScriptedServer.syncBodies = [try w.body([v])]
        try await locked.refreshCacheLocked(accountId: "acc")
        XCTAssertTrue(shared.hasRefreshed("acc"))
        XCTAssertEqual(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.items.count, 1, "not the copy yet: nobody checked it")
        let requests = ScriptedServer.recorded().filter { $0.path != "/api/config" }.count
        let autofill = try await repo(w, in: shared) { $0.preferCache = true }
        XCTAssertEqual(ScriptedServer.recorded().filter { $0.path != "/api/config" }.count, requests, "checked without the server")
        XCTAssertEqual(autofill.vault?.entries.map(\.item.name).sorted(), ["Shop", "Third"])
        XCTAssertEqual(autofill.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(autofill.vault?.refreshedRejected, false)
        XCTAssertEqual(autofill.vault?.manifestWarnings.count, 0)
        XCTAssertFalse(shared.hasRefreshed("acc"), "it is the copy now")
        XCTAssertEqual(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.items.count, 2)
        XCTAssertEqual(remembered(v, in: shared), try mark(v), "remembered with the copy that carries it")
        // The same copy opens checked from then on.
        let again = try await repo(w, in: shared) { $0.preferCache = true }
        XCTAssertEqual(again.vault?.entries.count, 2)
        XCTAssertEqual(again.vault?.vaults.first?.manifest, .ok)

        // Two writes further (two refreshes, the second going on from what the first kept): the
        // manifest is more than a step ahead of what this device remembers, which only the
        // vault's log can connect. Nothing is asked of the server at unlock, so it isn't adopted;
        // the sync with the server, which fetches the log, decides. No warning either way.
        try v.add("Fourth")
        v.manifestSeq = 6
        v.seq += 1
        w.revision += 1
        ScriptedServer.syncBodies = [try w.body([v])]
        try await locked.refreshCacheLocked(accountId: "acc")
        try v.add("Fifth")
        v.manifestSeq = 7
        v.seq += 1
        w.revision += 1
        ScriptedServer.syncBodies = [try w.body([v])]
        try await locked.refreshCacheLocked(accountId: "acc")
        XCTAssertTrue(shared.hasRefreshed("acc"))
        let ahead = try await repo(w, in: shared) { $0.preferCache = true }
        XCTAssertEqual(ahead.vault?.entries.count, 2, "the checked copy")
        XCTAssertEqual(ahead.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(ahead.vault?.manifestWarnings.count, 0)
        XCTAssertFalse(shared.hasRefreshed("acc"))
        try await ahead.sync()
        XCTAssertEqual(logs().count, 1)
        XCTAssertEqual(ahead.vault?.entries.count, 4)
        XCTAssertEqual(ahead.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v, in: shared)?.version, 7)
        // Signing out removes what a refresh kept with the copy.
        try await locked.refreshCacheLocked(accountId: "acc")
        shared.deleteCache("acc")
        XCTAssertFalse(shared.hasRefreshed("acc"))
    }

    /// A sync that Background App Refresh runs for the unlocked account does no upkeep: no first
    /// manifest is started and no old trash deleted from the background (rereview-mobile F7).
    func testNoUpkeepFromABackgroundRefresh() async throws {
        let (w, v) = try world()
        w.liveSync = true
        w.trashDays = 30
        v.manifestSeq = 0
        v.manifestOk = false
        try v.add("Shop")
        let day: Int64 = 86400
        var now = w.serverTime
        let repo = try await repo(w, app: true) { $0.clock = { now } }
        await settled(repo)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        // Now a first manifest could be started…
        v.manifestOk = true
        v.seq += 1
        try await repo.refreshCacheLocked(accountId: "acc")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, ManifestStatus.none)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "not from the background")
        try await repo.sync()
        XCTAssertEqual(sent("PUT", "/manifest").count, 1, "the next sync in the foreground starts it")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        // …and old trash would be due.
        try v.add("Old", trashedAt: now - 40 * day)
        v.manifestSeq = 2
        v.seq += 1
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        now += 31 * day
        w.serverTime = now
        v.seq += 1
        try await repo.refreshCacheLocked(accountId: "acc")
        XCTAssertTrue(sent("POST", "/trash/purge").isEmpty, "not from the background")
        try await repo.sync()
        XCTAssertEqual(sent("POST", "/trash/purge").count, 1)
        XCTAssertEqual(w.problems, [])
    }

    /// The app and its AutoFill extension are two processes with one device memory and one copy
    /// on the device. Each writing while the other holds an older copy never produces a vault
    /// warning or an "older version" mark: this device's own write only touches the vault it
    /// wrote to, and the memory is read before the copy it is checked against.
    func testTheAppAndItsAutoFillExtensionNeverWarnAboutEachOther() async throws {
        let (w, p) = try world()
        let other = try Vault(w.created.account, name: "Work")
        w.vaults = [p, other]
        p.manifestSeq = 4
        other.manifestSeq = 2
        let shopId = try p.add("Shop", username: "alice", password: "pw-1", url: "https://shop.example.com")
        let workId = try other.add("Work item")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        let app = try await repo(w, app: true, in: shared)
        XCTAssertEqual(app.vault?.vaults.map(\.manifest), [.ok, .ok])
        func calm(_ r: VaultRepository, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertEqual(r.vault?.manifestWarnings.count, 0, what, file: file, line: line)
            XCTAssertNil(r.vault?.rollback, what, file: file, line: line)
            XCTAssertFalse(r.vault?.entries.contains { $0.rolledBack } ?? true, what, file: file, line: line)
        }

        // The AutoFill extension (its own process: its own store object on the same files) opens
        // the copy, syncs and saves a changed password for Shop: the personal vault moves to 5,
        // the item's counter up, and both memories on the device say so.
        let extStore = store(.appExtension)
        let ext = try await repo(w, in: extStore) { $0.preferCache = true }
        _ = try await ext.saveLogin(page: "https://shop.example.com/", username: "alice", password: "pw-2")
        XCTAssertEqual(p.manifestSeq, 5)
        XCTAssertEqual(remembered(p, in: shared)?.version, 5)
        calm(ext, "the extension")

        // Back in the app, before any sync: its copy still has the personal vault at 4 and Shop
        // at the older counter. It saves something in the other vault. Applied to its copy; the
        // personal vault isn't looked at again, nothing is marked.
        let before = syncs().count
        try await app.updateItem(try XCTUnwrap(app.vault?.get(workId)), named("Work item 2"))
        XCTAssertEqual(syncs().count, before, "applied to the copy")
        XCTAssertEqual(app.vault?.vaults.map(\.manifest), [.ok, .ok])
        calm(app, "the app after its own write to another vault")
        XCTAssertEqual(remembered(p, in: shared)?.version, 5, "the extension's memory isn't lowered by the app's write")
        XCTAssertEqual(remembered(other, in: shared), try mark(other))

        // The extension opens again, from the copy the app just stored (the personal vault at 4,
        // behind what the extension itself remembers): unchecked, never a warning.
        let ext2 = try await repo(w, in: store(.appExtension)) { $0.preferCache = true }
        XCTAssertEqual(ext2.vault?.vaults.first?.manifest, .unchecked)
        calm(ext2, "the extension over the app's older copy")
        try await ext2.sync()
        XCTAssertEqual(ext2.vault?.vaults.map(\.manifest), [.ok, .ok])
        calm(ext2, "the extension after its sync")

        // The app now writes into the personal vault from its older copy: the server refuses
        // (not built on the current manifest), the app syncs, checks, sends again. No warning.
        try await app.createItem(named("From the app"), vaultId: p.id)
        XCTAssertEqual(app.vault?.vaults.map(\.manifest), [.ok, .ok])
        XCTAssertEqual(app.vault?.get(shopId)?.item.login?.password, "pw-2")
        calm(app, "the app after writing to the vault the extension wrote to")
        XCTAssertEqual(p.manifestSeq, 6)
        XCTAssertEqual(remembered(p, in: shared), try mark(p))

        XCTAssertEqual(w.problems, [])
    }

    /// A sync answer that was read before the other process's write (it arrives after the
    /// device memory says more): everything is fetched again before anything is said, and the
    /// current answer is fine. No warning, no "older version" mark.
    func testASyncAnswerFromBeforeTheOtherProcessWroteIsNotARollback() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let shopId = try v.add("Shop", username: "alice", password: "pw-1", url: "https://shop.example.com")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        let app = try await repo(w, app: true, in: shared)
        let ext = try await repo(w, in: store(.appExtension)) { $0.preferCache = true }
        let stale = try w.body([v])
        _ = try await ext.saveLogin(page: "https://shop.example.com/", username: "alice", password: "pw-2")
        XCTAssertEqual(remembered(v, in: shared)?.version, 5)
        // The app's next answer is the one from before that save.
        ScriptedServer.answer("GET /api/sync", 200, String(decoding: stale, as: UTF8.self))
        let before = syncs().count
        try await app.sync()
        XCTAssertEqual(syncs().count, before + 2, "asked again, in full")
        XCTAssertEqual(syncs().last?.query, "")
        XCTAssertEqual(app.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(app.vault?.manifestWarnings.count, 0)
        XCTAssertNil(app.vault?.rollback)
        XCTAssertEqual(app.vault?.get(shopId)?.item.login?.password, "pw-2")
        XCTAssertEqual(w.problems, [])
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
        let data = v.rows[0]["data"] as? String ?? ""
        let before = syncs().count
        try await repo.trashItem(try XCTUnwrap(repo.vault?.get(itemId)))
        XCTAssertEqual(syncs().count, before)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        let kept = try XCTUnwrap(repo.copyOf("acc")?.items.first { $0.id == itemId })
        XCTAssertNil(kept.data)
        XCTAssertEqual(kept.dataSha256, manifestDataHash(data: data))
        // The next write builds on rows held by hash only.
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 6)
        XCTAssertEqual(w.problems, [], "the manifests matched the server's rows")
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
        seed(shared, w)
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
        XCTAssertEqual(remembered(v, in: shared), try mark(v))
        // A server that still sends no hash: a mismatch after the one full fetch.
        ScriptedServer.syncBodies = [bare]
        try await cached.sync()
        XCTAssertEqual(cached.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(cached.vault?.manifestWarnings.count, 1)
    }

    // MARK: Starting a manifest, old trash (the app only)

    /// The app starts a vault's first manifest after a sync when the server says every member's
    /// apps know manifests: version 1 over the complete set, replacing none, pinned to the
    /// vault's number, one attempt. Not from an AutoFill extension, not while the gate is
    /// closed, not for a reader.
    func testTheAppStartsAVaultsFirstManifest() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w, app: true)
        let put = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").first)
        XCTAssertEqual((put.body["base_seq"] as? NSNumber)?.int64Value, 0)
        XCTAssertEqual((put.body["seq"] as? NSNumber)?.int64Value, 1)
        XCTAssertEqual(put.body["prev"] as? String, Self.zeroLink, "a first manifest replaces none")
        XCTAssertEqual((put.body["vault_seq"] as? NSNumber)?.int64Value, 3)
        XCTAssertEqual(w.problems, [], "it matched the vault's rows")
        // Applied to the copy: the vault has its manifest (all three fields), its link is
        // remembered, the next write carries version 2 on it.
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v))
        XCTAssertEqual(remembered(v)?.version, 1)
        XCTAssertEqual(repo.copyOf("acc")?.vaults.first?.seq, 4)
        XCTAssertEqual(repo.copyOf("acc")?.vaults.first?.manifestPrev, Self.zeroLink)
        XCTAssertEqual(syncs().count, 1)
        let first = try v.link()
        try await repo.createItem(named("Note"), vaultId: nil)
        let post = try XCTUnwrap(sent("POST", "/api/items").last)
        XCTAssertEqual(manifests(post).first?.seq, 2)
        XCTAssertEqual(manifests(post).first?.prev, first)
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 1, "once")
        XCTAssertEqual(w.problems, [])
    }

    /// A new account: the first sync writes this device's key pins (the answer it was read from
    /// still said "none"), then the vault's first manifest is started and applied to the copy,
    /// and then the user saves something. The copy's older pins number is this device's own
    /// bookkeeping, never "Your server sent an older list of known keys."
    func testANewAccountsFirstManifestAndWritesRaiseNoPinsWarning() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let memory = InMemorySharingMemory()
        let repo = try await repo(w, app: true) { $0.sharingMemory = memory }
        XCTAssertEqual(sent("PUT", "/api/account/key-pins").count, 1, "the first sync wrote the pins")
        XCTAssertGreaterThan(memory.load("acc").serverBase, 0)
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 1, "then the first manifest was started and applied to the copy")
        XCTAssertEqual(syncs().count, 1)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(repo.sharingNotice)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(syncs().count, 1, "applied to the copy too")
        XCTAssertNil(repo.sharingNotice)
        XCTAssertNotEqual(repo.sharingNotice, SharingText.pinsRolledBack)
        XCTAssertEqual(repo.copyOf("acc")?.user?["key_pins_seq"]?.number, memory.load("acc").serverBase)
        // A server that really sends an older number than this device wrote is still told apart.
        try await repo.sync()
        XCTAssertEqual(repo.sharingNotice, SharingText.pinsRolledBack)
        XCTAssertEqual(w.problems, [])
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
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 409, conflict)
        v.seq = 9
        ScriptedServer.syncBodies = [try w.body([v])]
        try await repo.sync()
        XCTAssertEqual(sent("PUT", "/api/vaults/\(v.id)/manifest").count, 2)
        XCTAssertEqual(store().readManifestMemory("acc"), [:], "nothing is remembered for a manifest that wasn't stored")
    }

    /// A new directory and store for the next case of one test.
    private func tearDownStore() {
        SecureStore.wipeAll(directory: dir)
        ScriptedServer.requests = []
        ScriptedServer.answers = [:]
    }

    /// In a vault with a manifest the server no longer deletes old trash by itself: after a sync
    /// the app deletes what the server's retention has run out for. The server's clock,
    /// retention and `deleted_at`s aren't covered by the manifest, so an item only goes after
    /// this device itself saw it in the trash for the retention period, with the two clocks
    /// within a day: a server can't have the trash emptied by saying it is the year 3000.
    func testTheAppDeletesOldTrashOnlyAfterItWatchedItWait() async throws {
        let (w, v) = try world()
        w.trashDays = 30
        w.liveSync = true
        v.manifestSeq = 4
        let day: Int64 = 86400
        var now = w.serverTime
        try v.add("Shop")
        let a = try v.add("Old 1", trashedAt: now - 40 * day, revision: 11)
        let b = try v.add("Old 2", trashedAt: now - 31 * day, revision: 12)
        let c = try v.add("Old 3", trashedAt: now - 35 * day, revision: 13)
        let recent = try v.add("Recent", trashedAt: now - 2 * day)
        let shared = store()
        seed(shared, w)
        let clock: (VaultRepository) -> Void = { repo in repo.clock = { now } }
        let repo = try await repo(w, app: true, in: shared, configure: clock)
        func purges() -> [ScriptedServer.Request] { sent("POST", "/api/vaults/\(v.id)/trash/purge") }
        func ids(_ r: ScriptedServer.Request) -> [String] { (r.body["items"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? String } }

        // The server's rule says three items are due. This device has only just seen them in
        // the trash: nothing is deleted.
        XCTAssertTrue(purges().isEmpty, "first sight")
        XCTAssertEqual(shared.readTrashSeen("acc"), [a: now, b: now, c: now, recent: now])
        // A server that claims any time, retention or `deleted_at` it likes gets nothing either.
        w.serverTime = 9_000_000_000_000_000
        try await repo.sync()
        w.serverTime = now
        w.trashDays = 1
        for i in v.rows.indices where !(v.rows[i]["deleted_at"] is NSNull) { v.rows[i]["deleted_at"] = 1 }
        // (Other `deleted_at`s: the manifest only records live or trashed, so it still matches.)
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertTrue(purges().isEmpty, "the trash is not emptied on the server's say-so")
        // A day later the one-day retention has passed on this device too… but not while the
        // server's clock is more than a day from this device's.
        now += day + 60
        w.serverTime = now + 3 * day
        try await repo.sync()
        XCTAssertTrue(purges().isEmpty, "clocks more than a day apart")
        // 29 days with the real retention: still waiting. (The items' real times again.)
        w.trashDays = 30
        v.rows[1]["deleted_at"] = now - 40 * day
        v.rows[2]["deleted_at"] = now - 31 * day
        v.rows[3]["deleted_at"] = now - 35 * day
        v.rows[4]["deleted_at"] = now + 27 * day
        now += 28 * day
        w.serverTime = now
        try await repo.sync()
        XCTAssertTrue(purges().isEmpty, "seen for less than the retention")
        XCTAssertEqual(shared.readTrashSeen("acc")?[a], 1_800_000_000, "first sight is kept")

        // After 30 days of its own watching: deleted, in one request of at most the server's
        // limit (2 here) with the vault's next manifest; the rest waits for the next sync.
        now += 2 * day
        w.serverTime = now
        var link = try v.link()
        let before = syncs().count
        try await repo.sync()
        XCTAssertEqual(purges().count, 1, "one request per sync and vault number")
        XCTAssertEqual(ids(purges()[0]), [a, b])
        XCTAssertEqual((purges()[0].body["items"] as? [[String: Any]])?.compactMap { ($0["revision"] as? NSNumber)?.int64Value }, [11, 12])
        var m = manifests(purges()[0])
        XCTAssertEqual(m.first?.seq, 5)
        XCTAssertEqual(m.first?.prev, link)
        XCTAssertEqual(syncs().count, before + 1, "applied to the copy")
        XCTAssertEqual(Set(repo.vault?.trash.map(\.id) ?? []), [c, recent])
        XCTAssertEqual(remembered(v, in: shared), try mark(v))
        XCTAssertEqual(shared.readTrashSeen("acc").map { Set($0.keys) }, [c, recent], "what is gone is forgotten")
        link = try v.link()
        try await repo.sync()
        XCTAssertEqual(purges().count, 2)
        XCTAssertEqual(ids(purges()[1]), [c])
        m = manifests(purges()[1])
        XCTAssertEqual(m.first?.seq, 6)
        XCTAssertEqual(m.first?.prev, link)
        XCTAssertEqual(repo.vault?.trash.map(\.id), [recent])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(w.problems, [], "each manifest matched what the vault then held")
        try await repo.sync()
        XCTAssertEqual(purges().count, 2, "nothing else is due")

        // An item this device trashes itself is first seen now.
        let shop = try XCTUnwrap(repo.vault?.entries.first)
        try await repo.trashItem(shop)
        XCTAssertEqual(shared.readTrashSeen("acc")?[shop.id], now)
        // …and one that is restored is forgotten.
        try await repo.restoreItem(try XCTUnwrap(repo.vault?.get(shop.id)))
        XCTAssertNil(shared.readTrashSeen("acc")?[shop.id])
    }

    /// A failed purge is ignored and not tried again until the vault changed; an AutoFill
    /// extension, a server that keeps its trash, and a vault without a manifest delete nothing.
    func testOldTrashIsOneAttemptAndTheAppsOwn() async throws {
        let (w, v) = try world()
        w.trashDays = 30
        v.manifestSeq = 4
        let day: Int64 = 86400
        let start = w.serverTime
        try v.add("Shop")
        try v.add("Old 1", trashedAt: start - 40 * day)
        try v.add("Old 2", trashedAt: start - 31 * day)
        func run(app: Bool, _ body: (VaultRepository) async throws -> Void) async throws {
            tearDownStore()
            w.serverTime = start
            w.liveSync = true
            var now = start
            let repo = try await repo(w, app: app) { $0.clock = { now } }
            now += 31 * day
            w.serverTime = now
            try await body(repo)
        }
        try await run(app: true) { repo in
            ScriptedServer.answer("POST /api/vaults/\(v.id)/trash/purge", 409, self.conflict)
            try await repo.sync()
            XCTAssertEqual(self.sent("POST", "/trash/purge").count, 1)
            XCTAssertEqual(repo.vault?.trash.count, 2)
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
            try await repo.sync()
            XCTAssertEqual(self.sent("POST", "/trash/purge").count, 1, "once per vault number")
        }
        try await run(app: false) { repo in
            try await repo.sync()
            XCTAssertTrue(self.sent("POST", "/trash/purge").isEmpty, "never an AutoFill extension")
        }
        w.trashDays = 0
        try await run(app: true) { repo in
            try await repo.sync()
            XCTAssertTrue(self.sent("POST", "/trash/purge").isEmpty, "the server keeps its trash")
        }
        w.trashDays = 30
        v.manifestSeq = 0
        v.manifestOk = false
        try await run(app: true) { repo in
            try await repo.sync()
            XCTAssertTrue(self.sent("POST", "/trash/purge").isEmpty, "the server sweeps vaults without a manifest")
        }
    }

    // MARK: "Use the server's copy"

    /// After the server was restored from a backup, what it serves is consistent in itself (an
    /// older manifest over the items of that time): a rollback for every device that saw more.
    /// "Use the server's copy" then only changes what this device remembers (a local accept):
    /// nothing is sent, the memory is replaced by the served manifest although it remembered a
    /// higher version, and writes go on from there. Every member can do it, a reader too
    /// (rereview-mobile F3, rule S1).
    func testAfterARestoredBackupEveryMemberAcceptsOnTheirOwnDevice() async throws {
        for role in ["owner", "read"] {
            tearDownStore()
            ScriptedServer.requests = []
            let (w, v) = try world()
            v.role = role
            v.manifestSeq = 9
            try v.add("Shop")
            try v.add("Second")
            w.liveSync = true
            let repo = try await repo(w, app: true)
            XCTAssertEqual(remembered(v)?.version, 9, role)
            // The backup: the vault at manifest 6 with one item.
            v.rows.removeLast()
            v.manifestSeq = 6
            v.seq = 2
            let restored = try mark(v)
            try await repo.sync()
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback, role)
            XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, true, "\(role): the served manifest describes the served items")
            if role != "read" { await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) } }

            let before = syncs().count
            try await repo.useServerCopy(v.id)
            XCTAssertEqual(syncs().count, before + 1, role)
            XCTAssertEqual(syncs().last?.query, "", "\(role): everything is fetched, not a delta")
            XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "\(role): nothing is written to the server")
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, role)
            XCTAssertEqual(repo.vault?.manifestWarnings.count, 0, role)
            XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Shop"], role)
            XCTAssertEqual(remembered(v), ManifestMark(version: restored.version, link: restored.link, accepts: 1), "\(role): replaced, downwards, and counted")
            // A process that still holds the memory from before (its AutoFill extension) writes
            // its whole map: the acceptance isn't undone.
            store().writeManifestMemory("acc", [v.id: ManifestMark(version: 9, link: String(repeating: "s", count: 43))])
            XCTAssertEqual(remembered(v)?.version, 6, role)
            try await repo.sync()
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, role)
            // A new unlock, from the copy and from the server: still fine.
            let again = try await self.repo(w, app: true, in: store())
            await settled(again)
            XCTAssertEqual(again.vault?.vaults.first?.manifest, .ok, role)
            if role == "read" { continue }
            // Writes go on from the accepted manifest, one version at a time.
            try await repo.createItem(named("Note"), vaultId: nil)
            XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 7)
            XCTAssertEqual(remembered(v), ManifestMark(version: 7, link: try v.link(), accepts: 1))
            XCTAssertEqual(w.problems, [])
        }
    }

    /// The macOS AutoFill extension keeps its own memory (nothing the desktop app does reaches
    /// it), so it has the local accept too, also for a reader; what needs a write to the server
    /// is left to the web vault or the desktop app.
    func testTheMacExtensionAcceptsOnItsOwnMemory() async throws {
        let (w, v) = try world()
        v.manifestSeq = 9
        try v.add("Shop")
        try v.add("Second", trashedAt: 1_700_000_500)
        w.liveSync = true
        let mac: (VaultRepository) -> Void = { $0.trashSummary = true; $0.preferCache = true }
        let repo = try await repo(w, configure: mac)
        try await repo.sync()
        XCTAssertEqual(remembered(v)?.version, 9)
        // Restored from a backup.
        v.manifestSeq = 6
        v.seq = 2
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, true)
        try await repo.useServerCopy(v.id)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), ManifestMark(version: 6, link: try v.link(), accepts: 1))
        // A new process (one per request on macOS) opens it fine.
        let next = try await self.repo(w, in: store(), configure: mac)
        try await next.sync()
        XCTAssertEqual(next.vault?.vaults.first?.manifest, .ok)
        // Items that aren't the ones recorded: nothing is written from an extension.
        w.hidden = [v.rows[0]["id"] as? String ?? ""]
        try await next.sync()
        XCTAssertEqual(next.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(next.vault?.vaults.first?.manifestAcceptable, false)
        await assertThrows(ManifestText.reviewElsewhere) { try await next.useServerCopy(v.id) }
        v.role = "read"
        await assertThrows(ManifestText.reader) { try await next.useServerCopy(v.id) }
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        XCTAssertEqual(next.vault?.manifestWarnings.count, 1)
    }

    /// The server shows no manifest where this device remembers one (a backup from before the
    /// vault's first manifest): accepting forgets the memory, and the app starts a first
    /// manifest by the ordinary rule at its next sync (version 1, never above what it remembered).
    func testAcceptingAVaultWhoseManifestIsGoneForgetsIt() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w, app: true)
        XCTAssertEqual(remembered(v)?.version, 4)
        // The same vault as the backup has it: no manifest.
        v.manifestSeq = 0
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, true)
        // T3: accepting this means the vault is no longer checked; the confirmation says so
        // (`manifestGone` picks `ManifestText.confirmNoRecord`).
        XCTAssertEqual(repo.vault?.vaults.first?.manifestGone, true)
        XCTAssertEqual(repo.vault?.notCheckedVaults.count, 0)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "no first manifest over a rollback")
        // The server can't start a record now (not every member's apps are up to date).
        v.manifestOk = false
        try await repo.useServerCopy(v.id)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "accepting sends nothing")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, ManifestStatus.none)
        XCTAssertEqual(remembered(v), .forgotten(accepts: 1, noRecord: true))
        // The quiet note, for as long as the vault has no manifest: after syncs, and for every
        // later open of the copy (a new process, the AutoFill extension).
        XCTAssertEqual(repo.vault?.notCheckedVaults.map(\.id), [v.id], "This vault isn't being checked for missing or restored items.")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        try await repo.sync()
        XCTAssertEqual(repo.vault?.notCheckedVaults.map(\.id), [v.id])
        let reopened = try await self.repo(w, in: store()) { $0.preferCache = true }
        XCTAssertEqual(reopened.vault?.notCheckedVaults.map(\.id), [v.id])
        try await repo.createItem(named("Still writable"), vaultId: nil)
        XCTAssertEqual(repo.vault?.notCheckedVaults.map(\.id), [v.id])
        v.manifestOk = true
        // Not undone by a stale memory, and readable after a restart.
        XCTAssertEqual(store().readManifestMemory("acc")?[v.id]?.valid, false)
        // The next sync starts the vault's first manifest: version 1 on nothing.
        v.seq += 1
        try await repo.sync()
        let put = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").last)
        XCTAssertEqual((put.body["base_seq"] as? NSNumber)?.int64Value, 0)
        XCTAssertEqual((put.body["seq"] as? NSNumber)?.int64Value, 1)
        XCTAssertEqual(put.body["prev"] as? String, Self.zeroLink)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), ManifestMark(version: 1, link: try v.link(), accepts: 1))
        XCTAssertEqual(repo.vault?.notCheckedVaults.count, 0, "a record again: the note is gone")
        XCTAssertEqual(w.problems, [])
    }

    /// T3 is enforced, not only worded: the confirmation the user gave goes with the request.
    /// The ordinary text was confirmed and the server drops the vault's record behind the
    /// sheet: nothing is accepted or forgotten, the vault stays warned, and the next
    /// confirmation is the "no record" one.
    func testNoRecordIsNeverAcceptedUnderTheOrdinaryConfirmation() async throws {
        let (w, v) = try world()
        v.manifestSeq = 9
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w, app: true)
        let before = try XCTUnwrap(remembered(v))
        XCTAssertEqual(before.version, 9)
        // Restored from a backup: an older record that describes the items (acceptable).
        v.manifestSeq = 6
        v.seq = 2
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, true)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestGone, false, "the sheet opens with the ordinary text")
        // Behind the sheet the server stops showing a record at all.
        v.manifestSeq = 0
        w.revision += 1
        let outcome = try await repo.useServerCopy(v.id, noRecord: false)
        XCTAssertEqual(outcome, .askAgain(noRecord: true))
        XCTAssertEqual(remembered(v), before, "nothing forgotten")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest.warns, true, "still warned")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(repo.vault?.notCheckedVaults.count, 0)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestGone, true, "the next confirmation is the no-record one")
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        // A new process sees the same: warned, with its memory.
        let again = try await self.repo(w, app: true, in: store())
        await settled(again)
        XCTAssertEqual(again.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(remembered(v), before)
        // Confirmed with the text that says what it means: forgotten now.
        v.manifestOk = false
        let second = try await repo.useServerCopy(v.id, noRecord: true)
        XCTAssertEqual(second, .done)
        XCTAssertEqual(remembered(v), .forgotten(accepts: 1, noRecord: true))
        XCTAssertEqual(repo.vault?.notCheckedVaults.map(\.id), [v.id])
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(w.problems, [])
    }

    /// The reverse: the "no record" text was confirmed and the server shows a record again
    /// behind the sheet. Nothing is accepted; the next confirmation is the ordinary one.
    func testARecordIsNeverAcceptedUnderTheNoRecordConfirmation() async throws {
        for baseline in [false, true] {
            tearDownStore()
            ScriptedServer.requests = []
            let (w, v) = try world()
            v.manifestSeq = 9
            try v.add("Shop")
            let second = try v.add("Second")
            w.liveSync = true
            let repo = try await repo(w, app: true)
            let before = try XCTUnwrap(remembered(v))
            XCTAssertEqual(before.version, 9, "\(baseline)")
            v.manifestSeq = 0
            try await repo.sync()
            XCTAssertEqual(repo.vault?.vaults.first?.manifestGone, true, "\(baseline): the sheet opens with the no-record text")
            // Behind the sheet: an older record again (and, for the baseline case, an item lost).
            v.manifestSeq = 6
            v.seq = 2
            w.revision += 1
            if baseline { w.hidden = [second] }
            let outcome = try await repo.useServerCopy(v.id, noRecord: true)
            XCTAssertEqual(outcome, .askAgain(noRecord: false), "\(baseline)")
            XCTAssertEqual(remembered(v), before, "\(baseline): the memory is as it was")
            XCTAssertEqual(repo.vault?.manifestWarnings.count, 1, "\(baseline): still warned")
            XCTAssertEqual(repo.vault?.vaults.first?.manifestGone, false, "\(baseline): the next confirmation is the ordinary one")
            XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "\(baseline): nothing written")
            let next = try await repo.useServerCopy(v.id, noRecord: false)
            XCTAssertEqual(next, .done, "\(baseline)")
            XCTAssertEqual(sent("PUT", "/manifest").count, baseline ? 1 : 0, "\(baseline)")
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, "\(baseline)")
            XCTAssertEqual(remembered(v)?.version, baseline ? 7 : 6, "\(baseline)")
            XCTAssertEqual(remembered(v)?.accepts, 1, "\(baseline)")
            XCTAssertEqual(w.problems, [], "\(baseline)")
        }
    }

    /// T4 lets go of the edit counters of the accepted vault's items only where the accepted
    /// copy doesn't list them under another vault. An item moved from Work to Personal and
    /// edited; Personal is accepted while the answer lists the item under Work again in its old
    /// ciphertext: its counter is kept, so it is still marked as an older version there.
    func testAcceptingKeepsTheCounterOfAnItemServedInAnotherVault() async throws {
        let (w, v) = try world()
        let work = try Vault(w.created.account, name: "Work")
        work.manifestOk = false
        w.vaults = [v, work]
        v.manifestSeq = 4
        let stays = try v.add("Stays")
        let moved = try work.add("Moved")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        let repo = try await repo(w, app: true, in: shared)
        let backup = (rows: v.rows, workRows: work.rows, manifestSeq: v.manifestSeq)
        // Moved into Personal and edited there (and another item edited, for the contrast).
        try await repo.moveItem(try XCTUnwrap(repo.vault?.get(moved)), to: v.id)
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(moved)), named("Moved 2"))
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(stays)), named("Stays 2"))
        XCTAssertEqual(repo.vault?.get(moved)?.vaultId, v.id)
        let counter = try XCTUnwrap(shared.readItemRevs("acc")?[moved])
        XCTAssertGreaterThan(counter, 1)
        XCTAssertEqual(w.problems, [])
        // Other devices write on; then the server serves an older record of Personal over the
        // same items: warned, acceptable, the item still in Personal on this device.
        let at = v.manifestSeq
        v.manifestSeq = at + 3
        w.revision += 1
        try await repo.sync()
        XCTAssertEqual(remembered(v)?.version, UInt64(at + 3))
        v.manifestSeq = at
        w.revision += 1
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, true)
        XCTAssertEqual(repo.copyOf("acc")?.items.first { $0.id == moved }?.vaultId, v.id)
        // Behind the sheet: everything as the backup had it, the item in Work in its old ciphertext.
        v.rows = backup.rows
        v.manifestSeq = backup.manifestSeq
        work.rows = backup.workRows
        w.revision += 1
        let outcome = try await repo.useServerCopy(v.id, noRecord: false)
        XCTAssertEqual(outcome, .done)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.get(stays)?.item.name, "Stays", "Personal's own item is as the server has it")
        XCTAssertEqual(repo.vault?.get(stays)?.rolledBack, false)
        XCTAssertEqual(shared.readItemRevs("acc")?[stays], 1, "and its counter is the served one")
        // The item that is in Work again keeps its counter and its mark.
        XCTAssertEqual(repo.vault?.get(moved)?.vaultId, work.id)
        XCTAssertEqual(shared.readItemRevs("acc")?[moved], counter, "the counter of an item listed under another vault is kept")
        XCTAssertEqual(repo.vault?.get(moved)?.rolledBack, true, "still marked as an older version")
        XCTAssertEqual(repo.vault?.rollback?.items, [moved])
        // Also after a sync and in a new process.
        try await repo.sync()
        XCTAssertEqual(repo.vault?.get(moved)?.rolledBack, true)
        let again = try await self.repo(w, app: true, in: store())
        await settled(again)
        XCTAssertEqual(again.vault?.get(moved)?.rolledBack, true)
        XCTAssertEqual(again.vault?.get(stays)?.rolledBack, false)
    }

    /// The served items aren't the ones the served manifest records: there is nothing to accept
    /// as it is. A member who can edit writes a new baseline over what is served: exactly one
    /// version above the served one and naming it, whatever this device remembers (the server
    /// takes nothing else), and the memory is replaced by it, also downwards.
    func testUseTheServersCopyWritesABaselineOneAboveTheServedVersion() async throws {
        let (w, v) = try world()
        v.manifestSeq = 9
        try v.add("Shop")
        let lost = try v.add("Second")
        w.liveSync = true
        let repo = try await repo(w, app: true)
        XCTAssertEqual(remembered(v)?.version, 9)
        // Restored from a backup (manifest 6) and one item lost on the way.
        v.manifestSeq = 6
        v.seq = 2
        w.hidden = [lost]
        let shown = try v.link()
        try await repo.sync()
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, false)

        let before = syncs().count
        try await repo.useServerCopy(v.id)
        XCTAssertEqual(syncs().count, before + 1)
        XCTAssertEqual(syncs().last?.query, "", "everything is fetched, not a delta")
        XCTAssertEqual(sent("PUT", "/manifest").count, 1)
        let put = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").last)
        XCTAssertEqual((put.body["base_seq"] as? NSNumber)?.int64Value, 6)
        XCTAssertEqual((put.body["seq"] as? NSNumber)?.int64Value, 7, "the served version + 1, not above what this device remembered")
        XCTAssertEqual(put.body["prev"] as? String, shown, "it replaces the manifest the server shows")
        XCTAssertEqual((put.body["vault_seq"] as? NSNumber)?.int64Value, 2)
        XCTAssertEqual(w.problems, [])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(remembered(v), ManifestMark(version: 7, link: try v.link(), accepts: 1), "replaced although 9 was remembered")
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 8)
        XCTAssertEqual(w.problems, [])
        // The next sync shows the baseline this device wrote: still fine.
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        // Another device that still remembers 9 sees that baseline (version 7) as a rollback it
        // can accept by itself, whatever its role: the baseline matches the served items.
        tearDownStore()
        let stale = store()
        seed(stale, w)
        stale.writeManifestMemory("acc", [v.id: ManifestMark(version: 9, link: String(repeating: "A", count: 42) + "E")])
        v.role = "read"
        let reader = try await self.repo(w, app: true, in: stale)
        await settled(reader)
        XCTAssertEqual(reader.vault?.vaults.first?.manifest, .rollback)
        XCTAssertEqual(reader.vault?.vaults.first?.manifestAcceptable, true)
        try await reader.useServerCopy(v.id)
        XCTAssertEqual(reader.vault?.vaults.first?.manifest, .ok)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        XCTAssertEqual(remembered(v, in: stale), ManifestMark(version: 8, link: try v.link(), accepts: 1))
    }

    /// A baseline over a manifest that doesn't even open names it by its link all the same; the
    /// server's limit on baselines (429) leaves the warning with the usual message and nothing
    /// is tried again by itself.
    func testABaselineNamesWhateverTheServerShowsAndRespectsTheLimit() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        let repo = try await { () async throws -> VaultRepository in
            ScriptedServer.syncBodies = [try w.body([v])]
            return try await self.repo(w, app: true)
        }()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        // The server now shows a manifest nobody can open, at the same version.
        let prev = try XCTUnwrap(try v.current()).prev
        ScriptedServer.syncBodies = [try w.body([v], manifest: [v.id: "AAAA"])]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, false)
        // The limit: the warning stays, one request, the usual wording.
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 429, #"{"error":"rate_limited","message":"slow down"}"#, headers: ["Retry-After": "1800"])
        await assertThrows("Too many attempts. Try again in 30 minutes.") { try await repo.useServerCopy(v.id) }
        XCTAssertEqual(sent("PUT", "/manifest").count, 1, "not tried again by itself")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 429, #"{"error":"rate_limited","message":"slow down"}"#)
        await assertThrows("Too many attempts. Try again later.") { try await repo.useServerCopy(v.id) }
        XCTAssertEqual(sent("PUT", "/manifest").count, 2)
        let put = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").last)
        XCTAssertEqual(put.body["prev"] as? String, try manifestLink(manifestSeq: 4, prev: prev, sealed: "AAAA"), "the link of what the server shows")
        XCTAssertEqual((put.body["base_seq"] as? NSNumber)?.int64Value, 4)
        XCTAssertEqual((put.body["seq"] as? NSNumber)?.int64Value, 5)
        XCTAssertEqual(remembered(v)?.accepts, 0, "nothing is replaced by a baseline that wasn't stored")
        // An answer that doesn't name this baseline (another write won): nothing is replaced
        // either; the sync after it decides.
        ScriptedServer.answer("PUT /api/vaults/\(v.id)/manifest", 200, #"{"revision":9,"vault_seq":4,"manifest_seq":5,"manifest_link":"\#(String(repeating: "z", count: 43))"}"#)
        ScriptedServer.syncBodies = [try w.body([v], manifest: [v.id: "AAAA"])]
        try await repo.useServerCopy(v.id)
        XCTAssertEqual(remembered(v)?.accepts, 0)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 1)
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
        let last = try XCTUnwrap(sent("PUT", "/api/vaults/\(v.id)/manifest").last)
        XCTAssertEqual((last.body["seq"] as? NSNumber)?.int64Value, 5)
        XCTAssertEqual(last.body["prev"] as? String, try v.link())
        XCTAssertEqual(try v.check(5, prev: last.body["prev"] as? String ?? "", last.body["sealed"] as? String ?? "", rows: [v.rows[0]]), "ok")
        XCTAssertEqual(store().readManifestMemory("acc"), [:], "nothing is remembered for a baseline that wasn't stored")
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

    // MARK: An older version of an item

    /// An older version of an item than this device saw, under a manifest made over it (say
    /// after "Use the server's copy" on another device): this device keeps showing its newer
    /// copy, and that row counts in the check with the hash of what the server sent, so the vault
    /// matches. The item stays marked for as long as this device holds that newer copy: across
    /// later syncs, its own writes and a lock and unlock; until it is saved again (or the server
    /// serves that version).
    func testAKeptNewerCopyStaysMarkedUntilItIsWrittenAgain() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let itemId = try v.add("Shop")
        let otherId = try v.add("Other")
        w.liveSync = true
        let repo = try await repo(w, app: true)
        let original = v.rows[0]
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        XCTAssertEqual(repo.vault?.get(itemId)?.item.name, "Shop 2")
        // The server: the item as it was, under a newer manifest made over that.
        v.rows[0] = original
        v.manifestSeq += 1
        func marked(_ r: VaultRepository, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertEqual(r.vault?.get(itemId)?.item.name, "Shop 2", "the newer copy is shown (\(what))", file: file, line: line)
            XCTAssertEqual(r.vault?.get(itemId)?.rolledBack, true, "\(what): Your server sent an older version of this item.", file: file, line: line)
            XCTAssertEqual(r.vault?.rollback, ItemRollback(items: [itemId], kept: [itemId]), what, file: file, line: line)
            XCTAssertEqual(r.vault?.vaults.first?.manifest, .ok, what, file: file, line: line)
            XCTAssertEqual(r.copyOf("acc")?.items.first { $0.id == itemId }?.servedSha256, manifestDataHash(data: original["data"] as? String ?? ""), what, file: file, line: line)
        }
        try await repo.sync()
        marked(repo, "the sync that served the older version")
        // A later sync (a delta that doesn't bring the item again).
        ScriptedServer.answer("GET /api/sync", 200, String(decoding: try JSONSerialization.data(withJSONObject: [
            "delta": true, "revision": w.revision, "cursor": "c\(w.revision)", "vaults": [try v.row()], "items": [], "deleted": [], "reset": [],
        ] as [String: Any]), as: UTF8.self))
        try await repo.sync()
        marked(repo, "a later delta")
        // This device's own write to another item.
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(otherId)), named("Other 2"))
        marked(repo, "after an own write elsewhere")
        // Read again from the device (a lock and unlock, a new process).
        let again = try await self.repo(w, in: repo.store) { $0.preferCache = true }
        marked(again, "opened again from the device")
        // A first manifest is never started over such a vault (nothing to start here: it has one).
        // Saved again: the next manifest drops the served version and takes the new data; the
        // mark is gone with the kept copy.
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 3"))
        XCTAssertEqual(w.problems, [], "the manifest took the row the server held out and put the new one in")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(repo.copyOf("acc")?.items.first { $0.id == itemId }?.servedSha256)
        XCTAssertEqual(repo.vault?.get(itemId)?.rolledBack, false)
        XCTAssertNil(repo.vault?.rollback)
    }

    /// An item's edit counter is forgotten only when its absence is authenticated. A server that
    /// hides an item for one sync (in a vault without a manifest nothing says it shouldn't) and
    /// then serves an older version of it is still noticed.
    func testAHiddenThenOlderItemIsStillNoticed() async throws {
        let (w, v) = try world()
        v.manifestOk = false
        let itemId = try v.add("Shop")
        try v.add("Other")
        w.liveSync = true
        let repo = try await repo(w)
        let original = v.rows[0]
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(itemId)), named("Shop 2"))
        let newer = v.rows[0]
        let rev = try XCTUnwrap(store().readItemRevs("acc")?[itemId])
        XCTAssertEqual(rev, 2)
        // Hidden for one sync…
        v.rows.remove(at: 0)
        try await repo.sync()
        XCTAssertNil(repo.vault?.get(itemId))
        XCTAssertEqual(store().readItemRevs("acc")?[itemId], rev, "not forgotten: nothing authenticated that it is gone")
        // …then served as it was before the edit.
        v.rows.insert(original, at: 0)
        try await repo.sync()
        XCTAssertEqual(repo.vault?.get(itemId)?.rolledBack, true)
        XCTAssertEqual(repo.vault?.rollback?.items, [itemId])
        // In a vault whose manifest matches, an item that is gone is really gone: forgotten.
        v.rows[0] = newer
        v.manifestOk = true
        v.manifestSeq = 1
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(repo.vault?.rollback)
        v.rows.remove(at: 0)
        v.manifestSeq = 2
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(store().readItemRevs("acc")?[itemId])
        // And one this device deletes for good itself.
        let last = try XCTUnwrap(repo.vault?.entries.first)
        XCTAssertNotNil(store().readItemRevs("acc")?[last.id])
        try await repo.trashItem(last)
        try await repo.purgeItem(try XCTUnwrap(repo.vault?.get(last.id)))
        XCTAssertNil(store().readItemRevs("acc")?[last.id])
        XCTAssertEqual(w.problems, [])
    }

    // MARK: Key replacement

    /// A key replacement carries the vault's next manifest, made new with the new key for the
    /// next epoch over the re-encrypted items, naming the manifest it replaces (by its link: the
    /// old one is sealed under the old key and never opened again); `manifest_conflict` is
    /// retried like an item's `revision_conflict`.
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
        XCTAssertEqual(m.first?.prev, try v.link(), "it names the manifest it replaces")
        // Under the new key at the next epoch, over the re-encrypted items where they were.
        let wrapped = ((body["keys"] as? [[String: Any]])?.first?["wrapped_key"] as? String) ?? ""
        let newKey = try w.created.account.openVaultKey(vaultId: v.id, wrapped: wrapped, kind: "account", keyEpoch: 2, legacyAllowed: true)
        let items = body["items"] as? [[String: Any]] ?? []
        let after = zip(v.rows, items).map { old, new in ["id": new["id"] ?? "", "deleted_at": old["deleted_at"] ?? NSNull(), "data": new["data"] ?? ""] as [String: Any] }
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(try v.check(5, prev: m[0].prev, m[0].sealed, rows: after, key: newKey, epoch: 2), "ok")
        XCTAssertEqual(try v.check(5, prev: m[0].prev, m[0].sealed, rows: after), "mismatch", "not the old key's")
        // A device that remembers the old manifest accepts the new one: the chain crosses the key.
        let seen = try XCTUnwrap(remembered(v))
        let check = try newKey.manifestVerify(vaultId: v.id, keyEpoch: 2, manifestSeq: 5, prev: m[0].prev, sealed: m[0].sealed,
                                              rememberedVersion: seen.version, rememberedLink: seen.link, logJson: nil, itemsJson: try Vault.manifestRows(after))
        XCTAssertEqual(check.status, "ok")
        // Conflicts every time: given up, in the app's words.
        ScriptedServer.answers = [:]
        for _ in 0..<5 {
            ScriptedServer.answer("GET /api/vaults/\(v.id)/members", 200, members)
            ScriptedServer.answer("POST /api/vaults/\(v.id)/rotate", 409, conflict)
        }
        await assertThrows(ManifestText.busy) { _ = try await repo.rotateVaultKeys([v.id]) }
    }

    // MARK: Numbers a server sends

    /// A vault number no honest server sends (above 2^53 − 1) isn't an answer; nothing is added
    /// to such a number, so nothing traps.
    func testAHugeNumberFromTheServerIsRefusedNotCrashedOn() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w, app: true)
        XCTAssertEqual(repo.vault?.entries.count, 1)
        v.seq = Int64.max
        ScriptedServer.syncBodies = [try w.body([v])]
        await assertThrows("The server's answer couldn't be read.") { try await repo.sync() }
        XCTAssertEqual(repo.vault?.entries.count, 1, "the copy shown stays")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        // A write's answer with such numbers is never applied to the copy.
        v.seq = 3
        ScriptedServer.syncBodies = [try w.body([v])]
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":8,"vault_seq":9223372036854775807,"manifest_seq":9223372036854775807}"#)
        let before = syncs().count
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(syncs().count, before + 1, "synced instead")
        // A vault without a manifest whose number is at the top: a first manifest's answer.
        tearDownStore()
        let plain = try Vault(w.created.account, name: "Plain")
        plain.seq = Int64(VaultManifest.maxNumber)
        try plain.add("Item")
        w.vaults = [plain]
        ScriptedServer.syncBodies = [try w.body([plain])]
        ScriptedServer.answer("PUT /api/vaults/\(plain.id)/manifest", 200, #"{"revision":6,"vault_seq":9223372036854775807,"manifest_seq":1}"#)
        let second = try await self.repo(w, app: true)
        XCTAssertEqual(sent("PUT", "/api/vaults/\(plain.id)/manifest").count, 1)
        XCTAssertEqual(second.vault?.entries.count, 1)
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

    /// The check can't be dodged by breaking `/api/config`. With nothing kept about the server
    /// (its settings were never read on this device), a config that can't be fetched or read
    /// means the server isn't used at all: no `/sync` is asked for and nothing of one is shown.
    /// With a kept list that names signed sharing, a config that can't be fetched now changes
    /// nothing (the app works on, as when offline).
    func testAnUnreadableConfigWithNothingKeptIsNotConnectedTo() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        for body in [#"{"error":"unavailable","message":"down"}"#, "<html>oops</html>"] {
            tearDownStore()
            for _ in 0..<20 { ScriptedServer.answer("GET /api/config", body.hasPrefix("{") ? 503 : 200, body) }
            let repo = try await repo(w)
            XCTAssertEqual(syncs().count, 0, "nothing is asked of a server whose settings were never read")
            XCTAssertEqual(repo.vault?.entries.count, 0, "and nothing of it is shown")
            XCTAssertEqual(repo.vault?.offline, true)
            await assertThrows(ServerSupport.unreachable) { try await repo.sync() }
            await assertThrows(ServerSupport.unreachable) { try await repo.requireSupportedServer("acc", ask: true) }
            XCTAssertEqual(syncs().count, 0)
            XCTAssertNil(repo.store.get().file.accounts["acc"]?.features)
            XCTAssertTrue(repo.signedSharingOn("acc"), "the checks are on whatever a server lists or withholds")
            // A background refresh of a locked account: the same.
            let locked = try await self.repo(w, unlock: false, in: repo.store)
            do {
                try await locked.refreshCacheLocked(accountId: "acc")
                XCTFail("nothing is fetched")
            } catch {
                XCTAssertEqual(errorMessage(error), ServerSupport.unreachable)
            }
            XCTAssertEqual(syncs().count, 0)
            // The config answers: the server is used.
            ScriptedServer.answers = [:]
            try await repo.sync()
            XCTAssertEqual(repo.vault?.entries.count, 1)
            XCTAssertEqual(repo.vault?.offline, false)
        }
        // A kept list with signed sharing: the config failing now is not a refusal.
        tearDownStore()
        let kept = store()
        seed(kept, w, features: ["signed_sharing", "key_epoch", "delta_sync", "vault_manifest"])
        kept.updateAccount("acc") { $0.featuresAt = 0 }
        for _ in 0..<20 { ScriptedServer.answer("GET /api/config", 503, #"{"error":"unavailable","message":"down"}"#) }
        let repo = try await repo(w, in: kept)
        XCTAssertEqual(repo.vault?.entries.count, 1)
        XCTAssertEqual(repo.vault?.offline, false)
        XCTAssertNil(repo.serverProblem)
        XCTAssertEqual(syncs().count, 1)
        try await repo.requireSupportedServer("acc", ask: true)
    }

    /// Connecting to a server and signing in: refused before anything is sent to it. What was
    /// checked when connecting is kept, so a server that stops answering `/api/config` (or
    /// answers garbage) afterwards isn't taken for one that needs no check.
    func testNoSignInWithAServerWithoutSignedSharing() async throws {
        let s = store()
        let repo = VaultRepository(store: s, api: ApiClient(store: s) { $0.protocolClasses = [ScriptedServer.self] })
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync"]}"#
        await assertThrows(ServerSupport.updateServer) { try await repo.setServer("https://fake.passauth.test") }
        XCTAssertEqual(repo.state.server, "")
        ScriptedServer.config = #"{"name":"PassAuth"}"#
        await assertThrows(ServerSupport.updateServer) { try await repo.setServer("https://fake.passauth.test") }
        // A server with signed sharing is connected to, and what it listed is kept.
        ScriptedServer.config = Self.modern
        try await repo.setServer("https://fake.passauth.test")
        XCTAssertEqual(repo.state.server, "https://fake.passauth.test")
        XCTAssertEqual(s.get().active?.features, ["signed_sharing", "key_epoch", "delta_sync", "vault_manifest"])
        XCTAssertEqual(s.get().active?.api, 2)
        XCTAssertNotNil(s.get().active?.featuresAt)
        // It is downgraded before the sign-in: nothing of the sign-in is sent.
        ScriptedServer.config = #"{"name":"PassAuth","api":2,"features":["key_epoch","delta_sync"]}"#
        ScriptedServer.requests = []
        await assertThrows(ServerSupport.updateServer) { _ = try await repo.login(email: "a@example.com", password: self.password, secretKey: nil) }
        await assertThrows(ServerSupport.updateServer) { _ = try await repo.register(email: "a@example.com", name: "A", password: self.password, withSecretKey: false) }
        await assertThrows(ServerSupport.updateServer) { _ = try await repo.beginDeviceLogin(email: "a@example.com") }
        XCTAssertEqual(Set(ScriptedServer.recorded().map(\.path)), ["/api/config"])
        // A record that knows nothing about its server (an install from before the list was
        // kept, an account record that was reset) and a config that can't be read: no sign-in.
        ScriptedServer.config = Self.modern
        s.updateAccount(s.get().activeId) { a in
            a.features = nil
            a.featuresAt = nil
            a.api = nil
        }
        ScriptedServer.requests = []
        for _ in 0..<20 { ScriptedServer.answer("GET /api/config", 500, "boom") }
        await assertThrows(ServerSupport.unreachable) { _ = try await repo.login(email: "a@example.com", password: self.password, secretKey: nil) }
        await assertThrows(ServerSupport.unreachable) { _ = try await repo.register(email: "a@example.com", name: "A", password: self.password, withSecretKey: false) }
        XCTAssertEqual(Set(ScriptedServer.recorded().map(\.path)), ["/api/config"])
        XCTAssertTrue(repo.signedSharingOn(s.get().activeId), "signed sharing's checks never depend on the list")
    }

    // MARK: Sends

    /// A password is only ever put on a Send in the format that encrypts the text with it; a
    /// server that doesn't (or no longer) list `send_v2` gets no password Send written the
    /// link-only way.
    func testAPasswordSendIsRefusedWithoutSendV2() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let repo = try await repo(w)
        let new = NewSend(name: "Door code", text: "1234", password: "hunter2", maxViews: nil, expiresAt: nil, deleteAt: 1_900_000_000, hideEmail: false)
        await assertThrows("Update your PassAuth server to protect a Send with a password.") { _ = try await repo.createSend(new) }
        XCTAssertTrue(sent("POST", "/api/sends").isEmpty, "nothing was sent")
        // Setting or changing a password on an existing Send: the same.
        let key = try sendNewKey()
        let owned = try XCTUnwrap(OwnedSend(json: ["id": "s1", "name": .string(try sendEncrypt(key: key, field: "name", plaintext: "Door code")),
                                                  "data": .string(try sendEncrypt(key: key, field: "data", plaintext: "1234")),
                                                  "owner_key": .string(try w.created.account.wrapSendKey(key: key)), "delete_at": 1_900_000_000]))
        var edit = SendEdit()
        edit.password = .some("hunter2")
        await assertThrows(VaultRepository.sendPasswordNeedsV2) { _ = try await repo.updateSend(owned, edit) }
        XCTAssertTrue(sent("PUT", "/api/sends/s1").isEmpty)
    }

    /// A Send from before v2 that the server says has a password, on a server with `send_v2`:
    /// its name and text are only written again together with the password (it then becomes v2,
    /// encrypted with the password too), never in the link-only format beside a password (rule S8).
    func testAnOldPasswordSendIsOnlyRewrittenWithItsPassword() async throws {
        let (w, v) = try world()
        try v.add("Shop")
        ScriptedServer.syncBodies = [try w.body([v])]
        let key = try sendNewKey()
        func send(password: Bool) throws -> OwnedSend {
            try XCTUnwrap(OwnedSend(json: ["id": "s1", "name": .string(try sendEncrypt(key: key, field: "name", plaintext: "Door code")),
                                          "data": .string(try sendEncrypt(key: key, field: "data", plaintext: "1234")),
                                          "owner_key": .string(try w.created.account.wrapSendKey(key: key)), "delete_at": 1_900_000_000,
                                          "has_password": .bool(password)]))
        }
        func puts() -> [ScriptedServer.Request] { sent("PUT", "/api/sends/s1") }
        var text = SendEdit()
        text.text = "5678"
        var name = SendEdit()
        name.name = "Gate code"
        // Without `send_v2` on the server nothing changes (a v1 Send is edited as before).
        var repo = try await repo(w)
        _ = try? await repo.updateSend(try send(password: true), text)
        XCTAssertEqual(puts().count, 1)
        // With it: refused, nothing sent.
        tearDownStore()
        ScriptedServer.config = Self.modern.replacingOccurrences(of: #""vault_manifest""#, with: #""vault_manifest","send_v2""#)
        repo = try await self.repo(w)
        XCTAssertTrue(repo.cachedFeatures.contains("send_v2"))
        await assertThrows("Enter this Send's password to change its text.") { _ = try await repo.updateSend(try send(password: true), text) }
        await assertThrows(VaultRepository.sendPasswordNeeded) { _ = try await repo.updateSend(try send(password: true), name) }
        XCTAssertTrue(puts().isEmpty)
        // Other settings still go.
        var views = SendEdit()
        views.disabled = true
        _ = try? await repo.updateSend(try send(password: true), views)
        XCTAssertEqual(puts().count, 1)
        XCTAssertNil(puts().last?.body["data"])
        // Together with the password: sent, in the v2 format, with the content key.
        var both = text
        both.password = .some("hunter2")
        _ = try? await repo.updateSend(try send(password: true), both)
        XCTAssertEqual(puts().count, 2)
        let body = try XCTUnwrap(puts().last?.body)
        XCTAssertEqual(try sendFieldVersion(ciphertext: body["data"] as? String ?? ""), 2)
        XCTAssertEqual(try sendFieldVersion(ciphertext: body["name"] as? String ?? ""), 2)
        XCTAssertNotNil(body["owner_content_key"] as? String)
        // Removing the password with the edit, and a Send without a password: as before.
        var removing = text
        removing.password = .some(nil)
        _ = try? await repo.updateSend(try send(password: true), removing)
        XCTAssertEqual(puts().count, 3)
        _ = try? await repo.updateSend(try send(password: false), text)
        XCTAssertEqual(puts().count, 4)
        XCTAssertEqual(try sendFieldVersion(ciphertext: puts().last?.body["data"] as? String ?? ""), 1)
    }

    // MARK: Items that can't be opened

    /// T1 (c): a row that can't be decrypted (and that this device never opened) is listed as
    /// "Item that can't be opened" and its vault gets the notice. The manifest still matches, so
    /// nothing is warned or held: other writes go on. Members who can edit may delete it for
    /// good, an ordinary manifest write without the row; a reader can't.
    func testAnItemThatCannotBeOpenedIsListedAndDeleted() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        let bad = try v.add("Broken", revision: 9)
        // The right data under a key that doesn't open it.
        let stray = try v.key.encryptItem(itemJson: ItemCodec.encode(named("Other")), id: bad, vaultId: v.id)
        v.rows[1]["item_key"] = stray.key
        // And a trashed row that came with its data but without its key.
        let keyless = try v.add("Keyless", trashedAt: 1_700_000_900, revision: 10)
        v.rows[2]["item_key"] = NSNull()
        w.liveSync = true
        let repo = try await repo(w, app: true)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, "its manifest matches: nothing is warned")
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(repo.vault?.unopenableNotices.map(\.id), [v.id], "An item in this vault can't be opened.")
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Shop"])
        XCTAssertEqual(repo.vault?.trash.count, 0)
        XCTAssertEqual(Set(repo.vault?.unopenable.map(\.id) ?? []), [bad, keyless])
        XCTAssertEqual(repo.vault?.unopenable.first { $0.id == keyless }?.deletedAt, 1_700_000_900, "listed in the trash")
        XCTAssertNil(repo.vault?.unopenable.first?.name, "never read on this device: no name to show")
        XCTAssertEqual(remembered(v), try mark(v), "the manifest is remembered: it matches")
        XCTAssertNil(repo.copyOf("acc")?.warned)
        // No write hold: the vault is used as before.
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 5)
        XCTAssertEqual(w.problems, [], "the manifest counts the rows it can't open by their data")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 1, "the notice stays while the rows do")
        // A new process (the AutoFill extension) opens the copy the same way.
        let ext = try await self.repo(w, in: store()) { $0.preferCache = true }
        XCTAssertEqual(ext.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(ext.vault?.manifestWarnings.count, 0)

        // Delete for good: an ordinary manifest write without the row as it was synced. A live
        // row goes with the same request.
        var link = try v.link()
        let live = try XCTUnwrap(repo.vault?.unopenable.first { $0.id == bad })
        // A reader can't.
        v.role = "read"
        try await repo.sync()
        await assertThrows("You can only view items in this vault.") { try await repo.deleteUnopenable(live) }
        v.role = "owner"
        try await repo.sync()
        try await repo.deleteUnopenable(live)
        var del = try XCTUnwrap(sent("DELETE", "/api/items/\(bad)/permanent").last)
        XCTAssertEqual(query(del)["revision"], "9")
        XCTAssertEqual(query(del)["manifest_seq"], "6")
        XCTAssertEqual(query(del)["manifest_prev"], link)
        XCTAssertEqual(w.problems, [])
        XCTAssertEqual(repo.vault?.unopenable.map(\.id), [keyless])
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 1, "one is left")
        link = try v.link()
        try await repo.deleteUnopenable(try XCTUnwrap(repo.vault?.unopenable.first))
        del = try XCTUnwrap(sent("DELETE", "/api/items/\(keyless)/permanent").last)
        XCTAssertEqual(query(del)["manifest_seq"], "7")
        XCTAssertEqual(query(del)["manifest_prev"], link)
        XCTAssertEqual(w.problems, [])
        XCTAssertEqual(repo.vault?.unopenable, [])
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 0)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), try mark(v))
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(w.problems, [])
        // Deleting one that is gone meanwhile is nothing.
        try await repo.deleteUnopenable(live)
    }

    /// A vault whose manifest is wrong as well is warned for that, and "Use the server's copy"
    /// is its way out (the baseline counts the item it can't open); the notice for the item
    /// stays afterwards until it is deleted. Another device's write in between is retried.
    func testAnUnopenableItemBesideAWrongManifest() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let shop = try v.add("Shop")
        let bad = try v.add("Broken")
        let stray = try v.key.encryptItem(itemJson: ItemCodec.encode(named("Other")), id: bad, vaultId: v.id)
        v.rows[1]["item_key"] = stray.key
        w.liveSync = true
        let repo = try await repo(w, app: true)
        XCTAssertEqual(repo.vault?.vaults.first?.unopenable, true)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        let item = try XCTUnwrap(repo.vault?.unopenable.first)
        // The server also lost an item: the record is wrong.
        w.hidden = [shop]
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .mismatch)
        XCTAssertEqual(repo.vault?.vaults.first?.unopenable, true, "the item's notice is its own")
        XCTAssertEqual(repo.vault?.unopenable.map(\.id), [bad], "listed all the same")
        await assertThrows(ManifestText.held) { try await repo.deleteUnopenable(item) }
        XCTAssertTrue(itemWrites().isEmpty)
        try await repo.useServerCopy(v.id)
        XCTAssertEqual(sent("PUT", "/manifest").count, 1)
        XCTAssertEqual(w.problems, [], "the baseline counts the row it can't open by its data")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 1, "the notice stays while the row remains")
        // Another device's write gets in first: synced, checked, sent again.
        ScriptedServer.answer("DELETE /api/items/\(bad)/permanent", 409, conflict)
        try await repo.deleteUnopenable(item)
        XCTAssertEqual(sent("DELETE", "/api/items/\(bad)/permanent").count, 2)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.unopenable, [])
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 0)
        XCTAssertEqual(w.problems, [])
    }

    /// T1 (a): only the served `item_key` fails for an item this device already opened with the
    /// same data. The device goes on with the row it has: the item is shown, filled and
    /// editable, nothing is listed, warned or held, and the copy on the device keeps the key
    /// that opens it (so a later open, another process, still has the item).
    func testADamagedKeyForAnItemTheDeviceHasChangesNothing() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        let shop = try v.add("Shop", username: "alice", password: "pw-1", url: "https://shop.example.com")
        try v.add("Other")
        w.liveSync = true
        let repo = try await repo(w, app: true)
        let good = try XCTUnwrap(v.rows[0]["item_key"] as? String)
        // The server damages the key (the data, which the manifest records, stays).
        let stray = try v.key.encryptItem(itemJson: ItemCodec.encode(named("Stray")), id: shop, vaultId: v.id)
        v.rows[0]["item_key"] = stray.key
        w.revision += 1
        try await repo.sync()
        XCTAssertEqual(repo.vault?.get(shop)?.item.login?.password, "pw-1", "still the item")
        XCTAssertEqual(repo.vault?.unopenable, [])
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 0)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(repo.vault?.rollback)
        XCTAssertEqual(repo.copyOf("acc")?.items.first { $0.id == shop }?.itemKey, good, "the copy keeps the key that opens it")
        XCTAssertEqual(SyncSnapshot.decode(try XCTUnwrap(repo.store.readCache("acc")))?.items.first { $0.id == shop }?.itemKey, good)
        // Again and again (every answer carries the bad key), and from a new process.
        try await repo.sync()
        XCTAssertEqual(repo.vault?.get(shop)?.item.name, "Shop")
        let ext = try await self.repo(w, in: store()) { $0.preferCache = true }
        XCTAssertEqual(ext.vault?.get(shop)?.item.login?.password, "pw-1")
        try await ext.sync()
        XCTAssertEqual(ext.vault?.get(shop)?.item.login?.password, "pw-1")
        XCTAssertEqual(ext.vault?.unopenable, [])
        // Writable: saving it again sends a row that opens everywhere.
        try await repo.updateItem(try XCTUnwrap(repo.vault?.get(shop)), named("Shop 2"))
        XCTAssertEqual(repo.vault?.get(shop)?.item.name, "Shop 2")
        XCTAssertEqual(w.problems, [])
        // A device that never had the item can't do that: listed, with no name.
        tearDownStore()
        v.rows[0]["item_key"] = stray.key
        let fresh = try await self.repo(w, app: true)
        XCTAssertEqual(fresh.vault?.unopenable.map(\.id), [shop])
        XCTAssertEqual(fresh.vault?.vaults.first?.manifest, .ok)
    }

    /// The name of an item that stops opening is the one this device last read (its data changed
    /// too, so the device's own row can't stand in).
    func testAnItemThatStopsOpeningKeepsItsLastKnownName() async throws {
        let (w, v) = try world()
        v.manifestOk = false
        let shop = try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w, app: true)
        let other = try Vault(w.created.account, name: "Elsewhere")
        let foreign = try other.key.encryptItem(itemJson: ItemCodec.encode(named("X")), id: shop, vaultId: v.id)
        v.rows[0]["item_key"] = foreign.key
        v.rows[0]["data"] = foreign.data
        try await repo.sync()
        XCTAssertEqual(repo.vault?.unopenable.map(\.id), [shop])
        XCTAssertEqual(repo.vault?.unopenable.first?.name, "Shop")
        XCTAssertEqual(repo.vault?.unopenableNotices.count, 1)
    }

    // MARK: Round 3: warnings stay with the stored copy (N1)

    /// A whole server answer that failed its check becomes the stored copy together with its
    /// warning. Everyone who opens that copy later (the app after a lock and unlock or a
    /// restart, the iOS AutoFill extension, the macOS extension) is warned too, without the
    /// server, and AutoFill doesn't hand a login of that vault over unseen. The warning clears
    /// with a later answer that checks out. Vaults the answer didn't warn about keep the quiet
    /// two-process rule.
    func testAWarningStaysWithTheStoredCopy() async throws {
        for what in ["an item hidden", "an older state of the vault"] {
            tearDownStore()
            ScriptedServer.requests = []
            let (w, v) = try world()
            let calm = try Vault(w.created.account, name: "Calm")
            w.vaults = [v, calm]
            calm.manifestSeq = 2
            try calm.add("Calm item")
            v.manifestSeq = 3
            let shop = try v.add("Shop", username: "alice", password: "pw-1", url: "https://shop.example.com")
            let olderState = (rows: v.rows, seq: v.seq)
            try v.add("Second")
            v.manifestSeq = 4
            v.seq += 1
            w.liveSync = true
            let shared = store()
            seed(shared, w)
            let app = try await repo(w, app: true, in: shared)
            XCTAssertEqual(app.vault?.vaults.map(\.manifest), [.ok, .ok], what)
            XCTAssertNil(app.copyOf("acc")?.warned, what)

            // The server turns bad; the app (unlocked, in the foreground) syncs.
            if what == "an item hidden" {
                w.hidden = [v.rows[1]["id"] as? String ?? ""]
            } else {
                v.rows = olderState.rows
                v.manifestSeq = 3
                v.seq = olderState.seq
                w.revision -= 1
            }
            try await app.sync()
            XCTAssertEqual(app.vault?.manifestWarnings.map(\.id), [v.id], what)
            let warned = try XCTUnwrap(app.vault?.vaults.first?.manifest)
            XCTAssertEqual(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.warned, LocalWarnings(vaults: [v.id], items: []),
                           "\(what): kept with the stored copy")
            XCTAssertEqual(remembered(v, in: shared)?.version, 4, what)

            // From here on the server doesn't answer at all (5xx): nothing but the copy.
            w.liveSync = false
            func assertWarned(_ r: VaultRepository, _ who: String, file: StaticString = #filePath, line: UInt = #line) throws {
                XCTAssertEqual(r.vault?.manifestWarnings.map(\.id), [v.id], "\(what), \(who)", file: file, line: line)
                XCTAssertEqual(r.vault?.vaults.first?.manifest, warned, "\(what), \(who)", file: file, line: line)
                XCTAssertEqual(r.vault?.vaults.last?.manifest, .ok, "\(what), \(who): the other vault is fine", file: file, line: line)
                // What the AutoFill model asks before it fills, and what its list shows.
                let login = try XCTUnwrap(r.vault?.get(shop), file: file, line: line)
                XCTAssertEqual(r.vault?.fillNeedsReview(login), true, "\(what), \(who): not filled unseen", file: file, line: line)
                XCTAssertEqual(r.vault?.fillWarning, "Personal: " + ManifestText.warning, "\(what), \(who)", file: file, line: line)
                XCTAssertEqual(r.vault?.vaults.first?.manifestAcceptable, what == "an older state of the vault", "\(what), \(who)", file: file, line: line)
            }
            let before = ScriptedServer.recorded().count
            // The iOS AutoFill extension: its own process on the same files; also what
            // `provideWithoutUserInteraction` opens (kept keys, no sync).
            let ext = try await repo(w, in: store(.appExtension)) { $0.preferCache = true }
            try assertWarned(ext, "the AutoFill extension")
            XCTAssertEqual(ScriptedServer.recorded().count, before, "\(what): from the copy alone")
            // The macOS extension (summary rows, its own store role).
            if what == "an older state of the vault" {
                let mac = try await repo(w, in: store()) { $0.trashSummary = true; $0.preferCache = true }
                try assertWarned(mac, "the macOS extension")
            }
            // The app after a lock and unlock (the same object), and after a restart.
            await app.lockActive()
            try await app.unlock(password: password, secretKey: nil)
            try assertWarned(app, "the app after lock and unlock")
            await settled(app)
            try assertWarned(app, "the app after its background sync failed")
            let relaunched = try await repo(w, app: true, in: store())
            try assertWarned(relaunched, "the app after a restart")
            await settled(relaunched)
            try assertWarned(relaunched, "the restarted app, server still silent")

            // The server answers again, still bad: the warning stays (and stays stored), and
            // nothing is written into the vault, from the app or from AutoFill's save.
            w.liveSync = true
            try await relaunched.sync()
            try assertWarned(relaunched, "after another bad answer")
            XCTAssertEqual(syncs().last?.query, "", "\(what): a warned copy is checked against everything, not a delta")
            await assertThrows(ManifestText.held) { try await relaunched.createItem(self.named("Note"), vaultId: v.id) }
            await assertThrows(ManifestText.held) { _ = try await ext.saveLogin(page: "https://shop.example.com/", username: "alice", password: "pw-2") }
            XCTAssertTrue(itemWrites().isEmpty, what)
            // A later answer that checks out clears it, in the copy too, for everyone.
            if what == "an item hidden" {
                w.hidden = []
            } else {
                try v.add("Second again")
                v.manifestSeq = 4
                v.seq += 1
                w.revision += 2
                // (not the state this device saw at 4: only "Use the server's copy" settles it)
                try await relaunched.sync()
                XCTAssertEqual(relaunched.vault?.manifestWarnings.map(\.id), [v.id], "a fork at the remembered version")
                try await relaunched.useServerCopy(v.id)
            }
            try await relaunched.sync()
            XCTAssertEqual(relaunched.vault?.manifestWarnings.count, 0, what)
            XCTAssertEqual(relaunched.vault?.vaults.map(\.manifest), [.ok, .ok], what)
            XCTAssertNil(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.warned, "\(what): cleared with the copy")
            let after = try await repo(w, in: store(.appExtension)) { $0.preferCache = true }
            XCTAssertEqual(after.vault?.manifestWarnings.count, 0, what)
            XCTAssertEqual(after.vault?.fillNeedsReview(try XCTUnwrap(after.vault?.get(shop))), false, what)
            XCTAssertNil(after.vault?.fillWarning, what)
        }
    }

    /// An item the server sent an older version of, with no newer copy on this device to show
    /// instead (it came with a whole answer after this device had only the counter): the mark
    /// stays with the stored copy too, so a later open still says so and AutoFill doesn't fill
    /// it unseen. Items the answer didn't mark stay unmarked from the copy (two processes).
    func testAnOlderItemWithoutANewerCopyStaysMarkedInTheStoredCopy() async throws {
        let (w, v) = try world()
        v.manifestOk = false
        let shop = try v.add("Shop", username: "alice", password: "pw-old", url: "https://shop.example.com")
        let other = try v.add("Other")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        let app = try await repo(w, app: true, in: shared)
        let original = v.rows[0]
        var edited = try XCTUnwrap(app.vault?.get(shop)).item
        edited.login?.password = "pw-new"
        try await app.updateItem(try XCTUnwrap(app.vault?.get(shop)), edited)
        XCTAssertEqual(shared.readItemRevs("acc")?[shop], 2)
        // The copy on the device is lost (the app was reinstalled over its data, a new copy is
        // fetched); the counters stay. The server serves the item as it was before the edit.
        try FileManager.default.removeItem(at: dir.appendingPathComponent("vault/acc.bin"))
        v.rows[0] = original
        let fresh = try await repo(w, app: true, in: store())
        await settled(fresh)
        XCTAssertEqual(fresh.vault?.get(shop)?.rolledBack, true)
        XCTAssertEqual(fresh.vault?.rollback, ItemRollback(items: [shop], kept: []))
        XCTAssertEqual(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.warned, LocalWarnings(vaults: [], items: [shop]))
        // A new process opens that copy, with no server.
        w.liveSync = false
        let ext = try await repo(w, in: store(.appExtension)) { $0.preferCache = true }
        XCTAssertEqual(ext.vault?.get(shop)?.rolledBack, true, "still marked from the copy")
        XCTAssertEqual(ext.vault?.get(other)?.rolledBack, false)
        XCTAssertEqual(ext.vault?.fillNeedsReview(try XCTUnwrap(ext.vault?.get(shop))), true)
        XCTAssertEqual(ext.vault?.fillNeedsReview(try XCTUnwrap(ext.vault?.get(other))), false)
        XCTAssertEqual(ext.vault?.fillWarning, "Your server sent older versions of some items.")
        XCTAssertEqual(ext.vault?.manifestWarnings.count, 0)
        // The newer version again: the mark is gone, in the copy too.
        w.liveSync = true
        try await app.updateItem(try XCTUnwrap(fresh.vault?.get(shop)), edited)
        try await ext.sync()
        XCTAssertEqual(ext.vault?.get(shop)?.rolledBack, false)
        XCTAssertNil(ext.vault?.rollback)
        XCTAssertNil(SyncSnapshot.decode(try XCTUnwrap(shared.readCache("acc")))?.warned)
    }

    // MARK: Round 3: a restored server (T2), accepting (T3, T4), adoption (N10)

    /// T2: a server restored from a backup answers with a LOWER revision (and lower vault
    /// numbers). That answer is judged like any other, never dropped as "older than what I
    /// have": the revision check sees a difference, the sync fetches, the manifest check reports
    /// the rollback, and "Use the server's copy" works.
    func testALowerRevisionAfterARestoreIsJudged() async throws {
        let (w, v) = try world()
        v.manifestSeq = 9
        try v.add("Shop")
        let backup = (rows: v.rows, seq: v.seq, revision: w.revision)
        try v.add("Second")
        v.manifestSeq = 10
        v.seq += 1
        w.revision += 3
        w.liveSync = true
        let repo = try await repo(w, app: true)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.revision, backup.revision + 3)
        // The restore: everything as it was, the revision too.
        v.rows = backup.rows
        v.manifestSeq = 9
        v.seq = backup.seq
        w.revision = backup.revision
        let before = syncs().count
        await repo.refreshIfStale()
        XCTAssertGreaterThan(syncs().count, before, "a lower revision is a reason to sync")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback, "judged, not ignored")
        XCTAssertEqual(repo.vault?.revision, backup.revision, "the answer is the copy now, with its warning")
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Shop"])
        XCTAssertEqual(repo.copyOf("acc")?.warned?.vaults, [v.id])
        await assertThrows(ManifestText.held) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        // A plain sync and a new unlock say the same.
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .rollback)
        let again = try await self.repo(w, app: true, in: store())
        XCTAssertEqual(again.vault?.vaults.first?.manifest, .rollback)
        await settled(again)
        XCTAssertEqual(again.vault?.vaults.first?.manifest, .rollback)
        // The way out works.
        XCTAssertEqual(repo.vault?.vaults.first?.manifestAcceptable, true)
        XCTAssertEqual(repo.vault?.vaults.first?.manifestGone, false)
        try await repo.useServerCopy(v.id)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertNil(repo.copyOf("acc")?.warned)
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 10)
        XCTAssertEqual(w.problems, [])
    }

    /// T4: "Use the server's copy" also lets go of what this device held against the server's
    /// copy of that vault's items: the newer copies it kept and the edit counters it remembered.
    /// No "older versions" notice is left, the items are shown as the server has them, and
    /// nothing comes back at the next sync or open. Another vault's items keep their marks.
    func testAcceptingAlsoClearsTheVaultsOlderItemMarks() async throws {
        for baseline in [false, true] {
            tearDownStore()
            ScriptedServer.requests = []
            let (w, v) = try world()
            let other = try Vault(w.created.account, name: "Work")
            w.vaults = [v, other]
            v.manifestSeq = 4
            other.manifestOk = false
            let shop = try v.add("Shop")
            try v.add("Second")
            let work = try other.add("Work item")
            w.liveSync = true
            let shared = store()
            seed(shared, w)
            let repo = try await repo(w, app: true, in: shared)
            let backup = (rows: v.rows, seq: v.seq, revision: w.revision, workRows: other.rows)
            // Edits since the backup, in both vaults.
            try await repo.updateItem(try XCTUnwrap(repo.vault?.get(shop)), named("Shop 2"))
            try await repo.updateItem(try XCTUnwrap(repo.vault?.get(work)), named("Work item 2"))
            XCTAssertEqual(shared.readItemRevs("acc")?[shop], 2)
            // The admin restores the backup.
            v.rows = backup.rows
            v.manifestSeq = 4
            v.seq = backup.seq
            other.rows = backup.workRows
            w.revision = backup.revision
            if baseline { w.hidden = [v.rows[1]["id"] as? String ?? ""] }
            try await repo.sync()
            XCTAssertTrue(repo.vault?.vaults.first?.manifest.warns == true, "\(baseline)")
            XCTAssertEqual(repo.vault?.rollback, ItemRollback(items: [shop, work], kept: [shop, work]), "\(baseline)")
            XCTAssertEqual(repo.vault?.get(shop)?.item.name, "Shop 2", "the newer copy is shown until the user decides")

            try await repo.useServerCopy(v.id)
            XCTAssertEqual(sent("PUT", "/manifest").count, baseline ? 1 : 0, "\(baseline)")
            XCTAssertEqual(w.problems, [], "\(baseline)")
            XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, "\(baseline)")
            XCTAssertEqual(repo.vault?.get(shop)?.item.name, "Shop", "\(baseline): as the server has it")
            XCTAssertEqual(repo.vault?.get(shop)?.rolledBack, false, "\(baseline)")
            XCTAssertNil(repo.copyOf("acc")?.items.first { $0.id == shop }?.servedSha256, "\(baseline): the kept copy is gone")
            XCTAssertEqual(shared.readItemRevs("acc")?[shop], 1, "\(baseline): the counter is the served one")
            // Only that vault: the other vault's item is still the newer copy, still marked.
            XCTAssertEqual(repo.vault?.rollback, ItemRollback(items: [work], kept: [work]), "\(baseline)")
            XCTAssertEqual(repo.vault?.get(work)?.item.name, "Work item 2", "\(baseline)")
            XCTAssertEqual(shared.readItemRevs("acc")?[work], 2, "\(baseline)")
            // Nothing comes back: a sync, a new process, a restart.
            try await repo.sync()
            XCTAssertEqual(repo.vault?.rollback?.items, [work], "\(baseline)")
            XCTAssertEqual(repo.vault?.get(shop)?.item.name, "Shop", "\(baseline)")
            let again = try await self.repo(w, app: true, in: store())
            await settled(again)
            XCTAssertEqual(again.vault?.rollback?.items, [work], "\(baseline)")
            XCTAssertEqual(again.vault?.get(shop)?.rolledBack, false, "\(baseline)")
            XCTAssertEqual(again.vault?.vaults.first?.manifest, .ok, "\(baseline)")
            // And the vault is written to from what was accepted.
            try await repo.updateItem(try XCTUnwrap(repo.vault?.get(shop)), named("Shop 3"))
            XCTAssertEqual(w.problems, [], "\(baseline)")
        }
    }

    /// N10: what a background refresh kept is judged against the device memory as it is stored
    /// when it is adopted (not as this process read it when it opened the copy), and only over
    /// the copy this process opened. The app writes between the extension's open and its
    /// adoption: the answer from before that write is dropped, the app's newer copy stays.
    func testAnOlderRefreshNeverReplacesANewerStoredCopy() async throws {
        let (w, v) = try world()
        let other = try Vault(w.created.account, name: "Work")
        w.vaults = [v, other]
        v.manifestSeq = 4
        other.manifestSeq = 2
        try v.add("Shop")
        try other.add("Work item")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        let app = try await repo(w, app: true, in: shared)
        // The extension opens the copy (nothing kept aside yet) and stays open.
        let ext = try await repo(w, in: store(.appExtension)) { $0.preferCache = true }
        let locked = try await repo(w, unlock: false, in: store())
        // Another device saves into the other vault; a keyless refresh keeps that answer aside.
        try other.add("Second work item")
        other.manifestSeq = 3
        other.seq += 1
        w.revision += 1
        try await locked.refreshCacheLocked(accountId: "acc")
        XCTAssertTrue(shared.hasRefreshed("acc"))
        // The app saves into the personal vault from its copy (applied to it, no sync): the
        // stored copy and the memory are at 5 now. The answer kept aside has it at 4.
        let before = syncs().count
        try await app.createItem(named("From the app"), vaultId: v.id)
        XCTAssertEqual(syncs().count, before, "applied to the copy")
        XCTAssertEqual(remembered(v, in: shared)?.version, 5)
        XCTAssertTrue(shared.hasRefreshed("acc"), "still there")
        let newer = try XCTUnwrap(shared.readCache("acc"))
        // The extension adopts now, with the memory it read before the app's write.
        await ext.adoptRefreshedNow()
        XCTAssertEqual(shared.readCache("acc"), newer, "the app's newer copy stays")
        XCTAssertEqual(SyncSnapshot.decode(newer)?.vaults.first?.manifestVersion, 5)
        XCTAssertFalse(shared.hasRefreshed("acc"), "dropped")
        XCTAssertEqual(ext.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(remembered(v, in: shared)?.version, 5)
        // Its next sync brings everything.
        try await ext.sync()
        XCTAssertEqual(ext.vault?.vaults.map(\.manifest), [.ok, .ok])
        XCTAssertEqual(ext.vault?.entries.map(\.item.name).sorted(), ["From the app", "Second work item", "Shop", "Work item"])
    }

    /// The unreadable-memory way out also counts the app's record of when it first saw each
    /// trashed item: unreadable alone, it gets the notice and "Reset on this device" too.
    func testAnUnreadableTrashRecordAlsoHasTheWayOut() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        try v.add("Old", trashedAt: 1_700_000_500)
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        _ = try await repo(w, app: true, in: shared)
        let file = dir.appendingPathComponent("vault/acc.trashed")
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        try Data("garbage".utf8).write(to: file)
        let repo = try await self.repo(w, app: true, in: shared)
        await settled(repo)
        try await repo.sync()
        try await repo.sync()
        XCTAssertTrue(repo.memoryProblem, "three failed reads across syncs that worked")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, "the vault itself is checked: its memory reads")
        // The AutoFill extension doesn't keep that record: nothing to say there.
        let ext = try await self.repo(w, in: store(.appExtension)) { $0.preferCache = true }
        try await ext.sync()
        try await ext.sync()
        try await ext.sync()
        XCTAssertFalse(ext.memoryProblem)
        try await repo.resetDeviceMemory()
        XCTAssertFalse(repo.memoryProblem)
        XCTAssertEqual(try Data(contentsOf: file.appendingPathExtension("unreadable")), Data("garbage".utf8))
        XCTAssertNotNil(shared.readTrashSeen("acc"))
    }

    /// No first manifest is started over a vault with an item that can't be opened (every
    /// member's app would warn about it for good). The vault stays as writable as it was, the
    /// item is listed, and deleting it (a plain request: there is no manifest) lets the next
    /// sync start the manifest.
    func testNoFirstManifestOverAnItemThatCannotBeOpened() async throws {
        let (w, v) = try world()
        v.manifestSeq = 0
        try v.add("Shop")
        let bad = try v.add("Broken")
        let stray = try v.key.encryptItem(itemJson: ItemCodec.encode(named("Other")), id: bad, vaultId: v.id)
        v.rows[1]["item_key"] = stray.key
        w.liveSync = true
        let repo = try await repo(w, app: true)
        await settled(repo)
        try await repo.sync()
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "not started")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, ManifestStatus.none)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(repo.vault?.unopenable.map(\.id), [bad])
        try await repo.createItem(named("Note"), vaultId: nil)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        try await repo.deleteUnopenable(try XCTUnwrap(repo.vault?.unopenable.first))
        let del = try XCTUnwrap(sent("DELETE", "/api/items/\(bad)/permanent").last)
        XCTAssertEqual(del.query, "", "a vault without a manifest takes the plain request")
        XCTAssertEqual(repo.vault?.unopenable, [])
        try await repo.sync()
        XCTAssertEqual(sent("PUT", "/manifest").count, 1, "now it is started")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(w.problems, [])
    }

    // MARK: Write answers

    /// An own write is applied to the copy only when the answer names the manifest this device
    /// sent, by its link. A create that reached the server once and is sent again gets the first
    /// attempt's answer: the same version, another manifest (it was sealed again). Taking that
    /// for this device's own would remember a manifest the server doesn't have, and the next
    /// sync would call the vault a mismatch. It syncs instead (rule S6). And an answer that says
    /// the vault's number didn't move, for a write that carried a manifest, syncs too (F8).
    func testAWriteAnswerIsOnlyAppliedForTheManifestSent() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let repo = try await repo(w)
        // The first attempt is stored, its answer lost.
        w.loseAnswers = 1
        let id = try newId()
        do {
            try await repo.createItem(named("Note"), vaultId: nil, id: id)
            XCTFail("the answer was lost")
        } catch {}
        XCTAssertEqual(v.manifestSeq, 5)
        let storedLink = try v.link()
        let row = try XCTUnwrap(v.rows.last)
        XCTAssertEqual(remembered(v)?.version, 4)
        // The same create again: the server replays the first answer (version 5, its link).
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":\#(row["revision"] ?? 0),"vault_seq":\#(v.seq),"manifest_seq":5,"manifest_link":"\#(storedLink)"}"#)
        let before = syncs().count
        try await repo.createItem(named("Note"), vaultId: nil, id: id)
        let again = try XCTUnwrap(sent("POST", "/api/items").last)
        XCTAssertEqual(manifests(again).first?.seq, 5, "the same version as the stored one…")
        XCTAssertNotEqual(try manifestLink(manifestSeq: 5, prev: manifests(again).first?.prev ?? "", sealed: manifests(again).first?.sealed ?? ""), storedLink,
                          "…but sealed again: another manifest")
        XCTAssertEqual(syncs().count, before + 1, "not applied to the copy: synced")
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertEqual(remembered(v), ManifestMark(version: 5, link: storedLink), "the manifest the server has, not the one sent twice")
        XCTAssertNotNil(repo.vault?.get(id))
        try await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok, "no false mismatch afterwards")
        XCTAssertEqual(w.problems, [])
        // The vault's number unchanged in the answer to a write that carried a manifest: asked.
        let known = try XCTUnwrap(repo.copyOf("acc")?.vaults.first?.seq)
        ScriptedServer.answer("POST /api/items", 200, #"{"revision":40,"vault_seq":\#(known),"manifest_seq":6,"manifest_link":"\#(String(repeating: "q", count: 43))"}"#)
        let count = syncs().count
        try await repo.createItem(named("Other"), vaultId: nil)
        XCTAssertEqual(syncs().count, count + 1)
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .ok)
        XCTAssertEqual(remembered(v), ManifestMark(version: 5, link: storedLink))
    }

    // MARK: Device memory

    /// What this device remembers per vault (version and link) is kept sealed next to the item
    /// edit counters: merged by the higher version (the app and its AutoFill extension both
    /// write it), never another link at the same version, kept for vaults that are gone, and
    /// deleted with the account's other device memory. A memory in the first format (bare
    /// numbers) is nothing remembered; one that can't be read is never checked against or
    /// written over.
    func testTheDeviceMemoryOfManifests() throws {
        let app = store()
        let ext = store(.appExtension)
        func m(_ version: UInt64, _ c: Character) -> ManifestMark { ManifestMark(version: version, link: String(repeating: c, count: 43)) }
        XCTAssertEqual(app.readManifestMemory("acc"), [:])
        app.writeManifestMemory("acc", ["v1": m(5, "a"), "v2": m(2, "b")])
        ext.writeManifestMemory("acc", ["v1": m(3, "c"), "v2": m(4, "d"), "v3": m(1, "e")])
        XCTAssertEqual(app.readManifestMemory("acc"), ["v1": m(5, "a"), "v2": m(4, "d"), "v3": m(1, "e")])
        // Never another link at the same version; only what was seen is written (a vault that
        // isn't named stays); half an entry is never stored.
        ext.writeManifestMemory("acc", ["v1": m(5, "z"), "v4": ManifestMark(version: 0, link: String(repeating: "f", count: 43)), "v5": ManifestMark(version: 3, link: "short")])
        XCTAssertEqual(app.readManifestMemory("acc"), ["v1": m(5, "a"), "v2": m(4, "d"), "v3": m(1, "e")])
        XCTAssertEqual(app.readManifestMemory("other"), [:], "per account")
        // An acceptance replaces one vault's entry under the same lock, also downwards, counts
        // it, and a whole-map write from a process that still holds the older memory loses.
        XCTAssertEqual(ext.replaceManifestMark("acc", vault: "v1", with: m(2, "r"))?["v1"], ManifestMark(version: 2, link: m(2, "r").link, accepts: 1))
        app.writeManifestMemory("acc", ["v1": m(5, "a"), "v2": m(4, "d")])
        XCTAssertEqual(app.readManifestMemory("acc")?["v1"], ManifestMark(version: 2, link: m(2, "r").link, accepts: 1))
        XCTAssertEqual(app.replaceManifestMark("acc", vault: "v3", with: nil)?["v3"], .forgotten(accepts: 1, noRecord: true))
        ext.writeManifestMemory("acc", ["v3": m(1, "e")])
        XCTAssertEqual(app.readManifestMemory("acc")?["v3"], .forgotten(accepts: 1, noRecord: true), "what was forgotten isn't brought back")
        XCTAssertEqual(app.replaceManifestMark("acc", vault: "v1", with: m(5, "a"))?["v1"]?.accepts, 2)
        XCTAssertEqual(app.replaceManifestMark("acc", vault: "v3", with: m(1, "e"))?["v3"], ManifestMark(version: 1, link: m(1, "e").link, accepts: 2))
        // Sealed on the device (not readable as JSON), in the vault folder.
        let file = dir.appendingPathComponent("vault/acc.manifests")
        let blob = try Data(contentsOf: file)
        XCTAssertNil(try? JSONSerialization.jsonObject(with: blob))
        // The lock the two processes share: while the other holds it nothing is written (the
        // next write merges again), so neither overwrites what the other is in the middle of.
        let held = try XCTUnwrap(FileLock.tryAcquire(FileLock.url("memory", directory: dir)))
        let g = ManifestMark(version: 9, link: m(9, "g").link, accepts: 2)
        app.writeManifestMemory("acc", ["v1": g])
        XCTAssertEqual(try Data(contentsOf: file), blob)
        XCTAssertNil(app.replaceManifestMark("acc", vault: "v1", with: m(1, "x")), "nor replaced: not done is said")
        held.release()
        app.writeManifestMemory("acc", ["v1": g])
        XCTAssertEqual(ext.readManifestMemory("acc")?["v1"], g)
        // A file that can't be opened: unknown (nil), and never written over.
        try Data("garbage".utf8).write(to: file)
        XCTAssertNil(app.readManifestMemory("acc"))
        app.writeManifestMemory("acc", ["v1": m(10, "h")])
        XCTAssertNil(app.replaceManifestMark("acc", vault: "v1", with: m(10, "h")))
        XCTAssertEqual(try Data(contentsOf: file), Data("garbage".utf8))
        XCTAssertTrue(app.memoryUnreadable("acc"))
        // Signing out removes it with the copy, the item edit counters and the trash times.
        app.writeTrashSeen("acc", ["i1": 5])
        app.deleteCache("acc")
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertEqual(app.readManifestMemory("acc"), [:])
        XCTAssertEqual(app.readTrashSeen("acc"), [:])
    }

    /// The item edit counters: both processes' writes are merged under the same lock (every id
    /// of either, no counter lowered); a file that can't be read is never taken for an empty one.
    func testTheDeviceMemoryOfItemCounters() throws {
        let app = store()
        let ext = store(.appExtension)
        XCTAssertEqual(app.readItemRevs("acc"), [:])
        app.writeItemRevMemory("acc", ItemRevMemory(items: ["a": .init(rev: 5, vault: "v", seen: 10), "b": .init(rev: 1, vault: "v", seen: 10)]))
        ext.writeItemRevMemory("acc", ItemRevMemory(items: ["a": .init(rev: 3, vault: "v", seen: 12), "c": .init(rev: 7, vault: "v", seen: 12)]))
        XCTAssertEqual(app.readItemRevs("acc"), ["a": 5, "b": 1, "c": 7], "nothing one process learnt is lost by the other's write")
        app.writeItemRevMemory("acc", ItemRevMemory(items: ["a": .init(rev: 5, vault: "v", seen: 14)]), dropped: ["b"])
        XCTAssertEqual(ext.readItemRevs("acc"), ["a": 5, "c": 7])
        let file = dir.appendingPathComponent("vault/acc.revs")
        let blob = try Data(contentsOf: file)
        let held = try XCTUnwrap(FileLock.tryAcquire(FileLock.url("memory", directory: dir)))
        ext.writeItemRevMemory("acc", ItemRevMemory(items: ["d": .init(rev: 2, vault: "v", seen: 15)]))
        XCTAssertEqual(try Data(contentsOf: file), blob, "not while the other process holds the lock")
        held.release()
        try Data("garbage".utf8).write(to: file)
        XCTAssertNil(app.readItemRevMemory("acc"), "unreadable isn't empty")
        app.writeItemRevMemory("acc", ItemRevMemory(items: ["e": .init(rev: 1)]))
        XCTAssertEqual(try Data(contentsOf: file), Data("garbage".utf8))
    }

    /// While the device memory can't be read nothing is checked against "nothing remembered"
    /// (that would accept any older state as first sight) and nothing is started or accepted:
    /// no warning, and writes wait.
    func testAMemoryThatCannotBeReadChecksNothing() async throws {
        let (w, v) = try world()
        v.manifestSeq = 4
        try v.add("Shop")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        let first = try await repo(w, app: true, in: shared)
        XCTAssertEqual(first.vault?.vaults.first?.manifest, .ok)
        let file = dir.appendingPathComponent("vault/acc.manifests")
        try Data("garbage".utf8).write(to: file)
        // The server serves an older state: with an empty memory that would pass as first sight.
        v.manifestSeq = 2
        let repo = try await self.repo(w, app: true, in: shared)
        await settled(repo)
        try? await repo.sync()
        XCTAssertEqual(repo.vault?.vaults.first?.manifest, .unchecked)
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        await assertThrows(ManifestText.unchecked) { try await repo.createItem(self.named("Note"), vaultId: nil) }
        await assertThrows(ManifestText.unchecked) { try await repo.useServerCopy(v.id) }
        XCTAssertTrue(itemWrites().isEmpty)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty)
        XCTAssertEqual(try Data(contentsOf: file), Data("garbage".utf8), "never written over")
    }

    /// A memory that stays unreadable has a way out and doesn't block vaults without a manifest
    /// (rereview-mobile F4, rule S4): those stay writable; after three failed reads in a row,
    /// across a sync that worked, the app says so and offers "Reset on this device", which moves
    /// the file aside and goes on as a device that remembers nothing. A file that reads again
    /// before that (the Keychain was only busy) is simply used.
    func testAMemoryThatStaysUnreadableHasAWayOut() async throws {
        let (w, p) = try world()
        let plain = try Vault(w.created.account, name: "Plain")
        plain.manifestOk = false
        w.vaults = [p, plain]
        p.manifestSeq = 4
        try p.add("Shop")
        try plain.add("Other")
        w.liveSync = true
        let shared = store()
        seed(shared, w)
        _ = try await repo(w, app: true, in: shared)
        let file = dir.appendingPathComponent("vault/acc.manifests")
        let good = try Data(contentsOf: file)
        // Unreadable once, then fine again: nothing is said.
        try Data("garbage".utf8).write(to: file)
        let repo = try await self.repo(w, app: true, in: shared)
        await settled(repo)
        XCTAssertFalse(repo.memoryProblem, "two failed reads aren't three")
        XCTAssertEqual(repo.vault?.vaults.map(\.manifest), [.unchecked, ManifestStatus.none], "a vault without a manifest stays as it was")
        try good.write(to: file)
        try await repo.sync()
        XCTAssertFalse(repo.memoryProblem)
        XCTAssertEqual(repo.vault?.vaults.map(\.manifest), [.ok, ManifestStatus.none])
        // Unreadable for good.
        try Data("garbage".utf8).write(to: file)
        try await repo.sync()
        try await repo.sync()
        XCTAssertFalse(repo.memoryProblem)
        // The vault without a manifest is still written to (the third failed read is the sync before this write).
        try await repo.createItem(named("Into plain"), vaultId: plain.id)
        XCTAssertEqual(sent("POST", "/api/items").count, 1)
        XCTAssertTrue(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).isEmpty)
        XCTAssertTrue(repo.memoryProblem, "three in a row, with syncs that worked in between")
        await assertThrows(ManifestText.unchecked) { try await repo.createItem(self.named("Note"), vaultId: p.id) }
        XCTAssertEqual(repo.vault?.manifestWarnings.count, 0)
        XCTAssertTrue(sent("PUT", "/manifest").isEmpty, "nothing is started without the memory")
        // Reset on this device.
        try await repo.resetDeviceMemory()
        XCTAssertFalse(repo.memoryProblem)
        XCTAssertEqual(try Data(contentsOf: file.appendingPathExtension("unreadable")), Data("garbage".utf8), "moved aside, not destroyed")
        XCTAssertEqual(repo.vault?.vaults.map(\.manifest), [.ok, ManifestStatus.none])
        XCTAssertEqual(remembered(p, in: shared), try mark(p), "a new record, from what the server shows now")
        try await repo.createItem(named("Note"), vaultId: p.id)
        XCTAssertEqual(manifests(try XCTUnwrap(sent("POST", "/api/items").last)).first?.seq, 5)
        XCTAssertEqual(w.problems, [])
        // A reset with nothing unreadable changes nothing.
        try await repo.resetDeviceMemory()
        XCTAssertEqual(remembered(p, in: shared), try mark(p))
        // Signing out removes the file that was moved aside too.
        shared.deleteCache("acc")
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.appendingPathExtension("unreadable").path))
    }
}

private extension VaultRepository {
    /// "Use the server's copy" as the views call it: with the confirmation the vault's state
    /// picks when the sheet opens, and nothing changing behind it.
    func useServerCopy(_ vaultId: String, file: StaticString = #filePath, line: UInt = #line) async throws {
        let noRecord = vault?.vaults.first { $0.id == vaultId }?.manifestGone ?? false
        let outcome = try await useServerCopy(vaultId, noRecord: noRecord)
        XCTAssertEqual(outcome, .done, file: file, line: line)
    }
}
