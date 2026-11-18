import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// Signed sharing through the repository against the scripted server (`ScriptedServer` in
/// ContractTests.swift): the signing identity made, uploaded and remembered at unlock (paused when
/// the server lists another or none after one was remembered), "me" from the core (a copy of
/// another account refused), grandfathering only at the identity's creation and only unsigned
/// shares, a vault the account never accepted held for consent, signed shared vaults checked on
/// sync, invitations accepted only when signed (pins written on accepting, a tombstone on
/// declining), and key replacement only after the member review: members the roster doesn't
/// know stop it, people who left need a confirmation per user id, a vault without a signed
/// roster is never sealed to anyone the user didn't review (review C1), and emergency access
/// replaces only what the same members answer shows as personal.
@MainActor
final class SignedSharingRepoTests: XCTestCase {
    private var dir: URL!
    private let password = "correct horse battery staple"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-signed-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        ScriptedServer.reset()
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
        ScriptedServer.reset()
    }

    /// An account: its id (also its server user id), its keys and signing identity.
    private struct Person {
        let id: String
        let email: String
        let created: NewAccount
        let signing: SigningIdentity
        let record: String
        var account: Account { created.account }
        var pub: String { (try? signing.publicIdentityJson()) ?? "" }

        /// A member row of `GET /vaults/{id}/members`.
        func row(_ role: String, kind: String) -> [String: Any] {
            var o = (try? JSONSerialization.jsonObject(with: Data(pub.utf8))) as? [String: Any] ?? [:]
            o["email"] = email
            o["name"] = email
            o["role"] = role
            o["status"] = "active"
            o["key_kind"] = kind
            return o
        }
    }

    private func person(_ email: String) throws -> Person {
        let id = try newId()
        let created = try createAccount(accountId: id, password: password, withSecretKey: false)
        let made = try created.account.newSigningIdentity()
        return Person(id: id, email: email, created: created, signing: made.identity, record: made.recordJson)
    }

    private func json(_ s: String) -> Any { (try? JSONSerialization.jsonObject(with: Data(s.utf8))) ?? NSNull() }
    private func text(_ o: Any) throws -> String { String(data: try JSONSerialization.data(withJSONObject: o), encoding: .utf8) ?? "" }

    private func member(_ p: Person, _ role: String) -> JSON { SharingIdentity.memberJson(p.pub, role: role) ?? .null }

    /// A shared vault: Alice owns it, Bob may edit; its key, the share to Bob signed by Alice, roster v1.
    private struct Shared {
        let id: String
        let key: VaultKey
        let wrappedForOwner: String
        let sealedForBob: String
        let signature: String
        let roster: String
        let itemId: String
    }

    /// `legacy`: shared with Bob before he had a signing identity (his app makes one later).
    private func shared(owner: Person, member bob: Person, legacy: Bool = false) throws -> Shared {
        let id = try newId()
        let made = try owner.account.newVaultKey(vaultId: id)
        let to = legacy ? try bob.account.legacyIdentityJson() : bob.pub
        let share = try owner.signing.sealAndSignShare(vaultKey: made.key, vaultId: id, recipientJson: to, role: "write", keyEpoch: 0)
        let roster = try SignedSharingTests.signRoster(owner.signing, key: made.key, vault: id, previous: nil, epoch: 0,
                                                       members: [member(owner, "owner"), SharingIdentity.memberJson(to, role: "write") ?? .null])
        return Shared(id: id, key: made.key, wrappedForOwner: made.wrapped, sealedForBob: share.sealedKey, signature: share.signature, roster: roster,
                      itemId: try newId())
    }

    private func item(_ name: String, _ key: VaultKey, vault: String, id: String, revision: Int64 = 3) throws -> [String: Any] {
        var i = Item.empty(.login, now: 1_700_000_000)
        i.name = name
        i.login?.urls = [LoginUrl(url: "https://\(name.lowercased())-site.com", match: .default)]
        let enc = try key.encryptItem(itemJson: ItemCodec.encode(i), id: id, vaultId: vault)
        return ["id": id, "vault_id": vault, "item_key": enc.key, "data": enc.data, "revision": revision, "deleted_at": NSNull(),
                "created_at": 1_700_000_000, "updated_at": 1_700_000_000]
    }

    private func shareJSON(_ signature: String, by signer: Person) -> [String: Any] {
        var s = json(signer.pub) as? [String: Any] ?? [:]
        s["email"] = signer.email
        s["name"] = "Alice"
        return ["signature": signature, "signer": s, "signer_deleted": false]
    }

    /// A `/sync` answer for `me` with these vaults, items and invitations.
    private func syncBody(_ me: Person, identity: Bool = true, identityRecord: Any? = nil, userId: String? = nil, vaults: [[String: Any]],
                          items: [[String: Any]], invitations: [[String: Any]] = [], pinsSeq: Int64 = 0, bundle: String? = nil) throws -> Data {
        var user: [String: Any] = ["id": userId ?? me.id, "email": me.email, "name": "Me", "email_verified": true, "key_pins_seq": pinsSeq]
        user["identity"] = identity ? (identityRecord ?? json(me.record)) : NSNull()
        return try JSONSerialization.data(withJSONObject: [
            "revision": 5, "user": user, "bundle": json(bundle ?? me.created.bundleJson),
            "vaults": vaults, "items": items, "invitations": invitations,
        ] as [String: Any])
    }

    /// The account's own vault (one login).
    private func personal(_ me: Person) throws -> (row: [String: Any], item: [String: Any]) {
        let id = try newId()
        let made = try me.account.newVaultKey(vaultId: id)
        return (["id": id, "wrapped_key": made.wrapped, "key_kind": "account", "role": "owner", "key_epoch": 0, "seq": 1,
                 "meta": try made.key.encryptMeta(vaultId: id, metaJson: #"{"name":"Personal"}"#), "share": NSNull(), "member_roster": NSNull(),
                 "member_roster_seq": 0],
                try item("Mine", made.key, vault: id, id: try newId()))
    }

    /// Bob's row for Alice's vault.
    private func bobRow(_ s: Shared, by alice: Person, signature: String? = nil, name: String = "Family") throws -> [String: Any] {
        ["id": s.id, "wrapped_key": s.sealedForBob, "key_kind": "sealed", "role": "write", "key_epoch": 0, "seq": 1,
         "meta": try s.key.encryptMeta(vaultId: s.id, metaJson: "{\"name\":\"\(name)\"}"),
         "share": shareJSON(signature ?? s.signature, by: alice), "member_roster": s.roster, "member_roster_seq": 1]
    }

    private func rosterAnswer(_ s: Shared, times: Int = 1) throws {
        for _ in 0..<times {
            ScriptedServer.answer("GET /api/vaults/\(s.id)/rosters", 200, try text(["rosters": [s.roster], "latest": 1, "more": false]))
        }
    }

    /// The device memory of an account whose key pins (`pins`, version 1, on the server too) were
    /// written before.
    private func memory(_ me: Person, pins: String, rosters: [String: String] = [:]) throws -> InMemorySharingMemory {
        let m = InMemorySharingMemory()
        var r = SharingMemoryRecord()
        r.pinsSeq = 1
        r.sealedPins = try me.account.sealKeyPins(pinsJson: pins, seq: 1)
        r.rosters = rosters
        m.put("acc", r)
        return m
    }

    /// `earlier`: the account's offline copy on this device from an earlier session (a `/sync`
    /// answer); then the unlock shows it first and syncs after (awaited here). `features` nil and
    /// `config: false`: the server's features were never read (and can't be now).
    private func repo(_ me: Person, _ bodies: [Data], memory: InMemorySharingMemory = InMemorySharingMemory(), earlier: Data? = nil,
                      features: [String]? = [signedSharingFeature], config: Bool = true, olderServers: Bool = false) async throws -> VaultRepository {
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: me.email)
            acc.bundle = me.created.bundleJson
            acc.features = features
            acc.featuresAt = features == nil ? nil : Date().timeIntervalSince1970
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        if let earlier { store.writeCache("acc", try XCTUnwrap(SyncSnapshot.decode(earlier)).encoded()) }
        ScriptedServer.syncBodies = bodies
        for _ in 0..<40 {
            if config {
                ScriptedServer.answer("GET /api/config", 200, #"{"api":2,"features":["signed_sharing"]}"#)
            } else {
                ScriptedServer.answer("GET /api/config", 503, #"{"error":"unavailable","message":"down"}"#)
            }
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] })
        repo.sharingMemory = memory
        repo.isApp = true
        // The rules for servers whose settings were never read only exist where such a server is
        // used at all (tests of the client rules for servers from before signed sharing): a
        // release build refuses it ("PassAuth couldn't reach your server…", `ManifestContractTests`).
        if olderServers { _ = repo.allowingOlderServers() }
        try await repo.unlock(password: password, secretKey: nil)
        if earlier != nil { try await repo.sync() }
        return repo
    }

    /// The entry the app shows now for `vaultId` (what an Accept tap passes on).
    private func shownInvitation(_ repo: VaultRepository, _ vaultId: String) throws -> Invitation {
        try XCTUnwrap(repo.vault?.invitations.first { $0.vaultId == vaultId }, "no invitation for \(vaultId)")
    }

    private func requests(_ method: String, _ path: String) -> [ScriptedServer.Request] {
        ScriptedServer.recorded().filter { $0.method == method && $0.path == path }
    }

    /// The grandfathered vault ids of key pins (`{vault id: key id}` since round 5); nil: not written.
    private func grandfatheredIds(_ pins: JSON) -> Set<String>? {
        guard case .object(let g)? = pins["grandfathered"] else { return nil }
        return Set(g.keys)
    }

    /// The key pins the app wrote last, opened.
    private func writtenPins(_ me: Person) throws -> JSON {
        let put = try XCTUnwrap(requests("PUT", "/api/account/key-pins").last, "key pins written")
        let seq = UInt64(put.body["seq"] as? Int ?? 0)
        return try JSON.parse(try me.account.openKeyPins(sealed: put.body["key_pins"] as? String ?? "", seq: seq))
    }

    // MARK: Unlock and sync

    func testUnlockMakesTheIdentityRemembersItAndGrandfathersOnlyUnsignedShares() async throws {
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let s = try shared(owner: alice, member: bob, legacy: true)
        // A share from before signed sharing, present at the account's first signed sync.
        let oldId = try newId()
        let oldKey = try alice.account.newVaultKey(vaultId: oldId).key
        let unsigned: [String: Any] = ["id": oldId, "wrapped_key": try oldKey.shareTo(vaultId: oldId, recipientPublicKey: bob.account.publicKey()),
                                       "key_kind": "sealed", "role": "read", "key_epoch": 0, "seq": 1,
                                       "meta": try oldKey.encryptMeta(vaultId: oldId, metaJson: #"{"name":"Old"}"#), "share": NSNull(),
                                       "member_roster": NSNull(), "member_roster_seq": 0]
        try rosterAnswer(s, times: 3)
        let memory = InMemorySharingMemory()
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true,"created":true}"#)
        // This device's copy from an earlier session had the old share (rule 1).
        let earlier = try syncBody(bob, identity: false, vaults: [own.row, unsigned], items: [own.item])
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, unsigned, try bobRow(s, by: alice)],
                                                     items: [own.item, try item("Bank", s.key, vault: s.id, id: s.itemId)])], memory: memory,
                                  earlier: earlier)
        let put = try XCTUnwrap(requests("PUT", "/api/account/identity").first, "identity uploaded")
        XCTAssertEqual((put.body["signing_key"] as? String)?.count, 43)
        XCTAssertEqual((put.body["x25519_signature"] as? String)?.count, 86)
        let fp = try XCTUnwrap(repo.ownIdentityFingerprint)
        let opened = try bob.account.openSigningIdentity(recordJson: try text(put.body))
        XCTAssertEqual(opened.fingerprint(), fp)
        // The key pins remember the own identity; only the unsigned share is grandfathered.
        let pins = try writtenPins(bob)
        XCTAssertEqual(pins["own_identity"]?.string, opened.identityHash())
        XCTAssertTrue(pins["grandfathered"]?[oldId] != nil)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == oldId }?.trust, .notYetSigned)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == own.row["id"] as? String }?.trust, .own)
        // Review H2: the signed vault the account never accepted isn't used: it waits for consent.
        XCTAssertNil(repo.vault?.vaults.first { $0.id == s.id })
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Mine"])
        let consent = try XCTUnwrap(repo.vault?.invitations.first { $0.vaultId == s.id },
                                    "invitations \(String(describing: repo.vault?.invitations)) refused \(String(describing: repo.vault?.refused))")
        XCTAssertEqual(consent.consent, .added)
        XCTAssertEqual(consent.name, "Family")
        XCTAssertTrue(consent.canAccept)
        XCTAssertNil(memory.load("acc").rosters[s.id], "nothing remembered before the user accepts")
        // Accepting: nothing asked of the server (it already lists it), the pins written, the vault used.
        try await repo.acceptInvitation(try shownInvitation(repo, s.id))
        XCTAssertTrue(requests("POST", "/api/vaults/\(s.id)/invitation/accept").isEmpty)
        let after = try writtenPins(bob)
        XCTAssertNotNil(after["epochs"]?[s.id])
        // Round 4: accepted with `pins_accept` (the roster's version and hash recorded).
        XCTAssertEqual(after["epochs"]?[s.id]?["roster_hash"]?.string, try rosterHash(rosterJson: s.roster))
        XCTAssertEqual(after["epochs"]?[s.id]?["roster_version_max"]?.number, 1)
        XCTAssertEqual(after["pins"]?.array.map { $0.str("user_id") }, [alice.id])
        XCTAssertEqual(after["pins"]?.array.first?.str("email"), "alice@example.com")
        // Review L2: the key pins remember the identity and the grandfathered list, so the pending
        // identity and the candidates are done with for good.
        let settled = memory.load("acc")
        XCTAssertTrue(settled.settled)
        XCTAssertNil(settled.pendingIdentity)
        XCTAssertNil(settled.candidates)
        XCTAssertTrue(settled.proven)
        XCTAssertEqual(Set(settled.seen ?? []), [own.row["id"] as? String ?? "", oldId, s.id], "what this device showed as usable")
        XCTAssertEqual(memory.load("acc").rosters[s.id], s.roster)
        guard case .signed(let signer)? = repo.vault?.vaults.first(where: { $0.id == s.id })?.trust else {
            return XCTFail("\(String(describing: repo.vault?.vaults))")
        }
        XCTAssertEqual(signer.pinnedEmail, "alice@example.com")
        XCTAssertEqual(repo.vault?.entries.map(\.item.name).sorted(), ["Bank", "Mine", ])
    }

    func testAnIdentityThatIsntTheAccountsPausesSharing() async throws {
        let me = try person("bob@example.com")
        let other = try person("mallory@example.com")
        let own = try personal(me)
        var body = try JSONSerialization.jsonObject(with: try syncBody(me, vaults: [own.row], items: [own.item])) as? [String: Any] ?? [:]
        var user = body["user"] as? [String: Any] ?? [:]
        user["identity"] = json(other.record)
        body["user"] = user
        let repo = try await repo(me, [try JSONSerialization.data(withJSONObject: body)])
        XCTAssertNil(repo.ownIdentityFingerprint)
        XCTAssertEqual(repo.sharingNotice, SharingText.paused)
        XCTAssertTrue(requests("PUT", "/api/account/identity").isEmpty, "nothing replaces the listed identity")
        XCTAssertEqual(repo.vault?.vaults.count, 1, "the account's own vault stays usable")
    }

    func testAnIdentityTheServerStopsListingPausesInsteadOfMakingANewOne() async throws {
        // Review L4: the key pins remember Bob's identity; the server now lists none.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: s.id, keyKind: "sealed", currentJson: try s.key.epochPinJson(vaultId: s.id, keyEpoch: 0), rosterVersion: 1,
                                        rosterHash: try rosterHash(rosterJson: s.roster))
        let memory = try memory(bob, pins: pins, rosters: [s.id: s.roster])
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, try bobRow(s, by: alice)],
                                                     items: [own.item, try item("Bank", s.key, vault: s.id, id: s.itemId)], pinsSeq: 1)],
                                  memory: memory)
        XCTAssertTrue(requests("PUT", "/api/account/identity").isEmpty, "no new identity over the remembered one")
        XCTAssertEqual(repo.sharingNotice, SharingText.paused)
        XCTAssertNil(repo.ownIdentityFingerprint)
        // Paused: every shared vault refused.
        XCTAssertEqual(repo.vault?.refused.map(\.reason), [.paused])
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Mine"])
    }

    func testACopyOfAnotherAccountIsRefused() async throws {
        // Review L3: "me" is the account the core unlocked, never the server's `user.id`.
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        do {
            let repo = try await repo(bob, [try syncBody(bob, userId: try newId(), vaults: [own.row], items: [own.item])])
            XCTAssertTrue(repo.vault?.entries.isEmpty ?? true, "another account's copy shown")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.wrongAccount)
        }
    }

    func testASignedSharedVaultIsUsedAndAForgedOneLeftOut() async throws {
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        // Bob accepted the vault, signed, on another device (its epoch and roster in the account's
        // pins; accepted unsigned it would need consent for its first signature, round 5).
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: s.id, keyKind: "sealed", currentJson: try s.key.epochPinJson(vaultId: s.id, keyEpoch: 0), rosterVersion: 1,
                                        rosterHash: try rosterHash(rosterJson: s.roster))
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        let sharedItem = try item("Bank", s.key, vault: s.id, id: s.itemId)
        let good = try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)], items: [own.item, sharedItem], pinsSeq: 1)
        let wrongSig = try alice.signing.signShare(vaultId: s.id, recipientJson: bob.pub, role: "admin", keyEpoch: 0, sealedKey: s.sealedForBob)
        let forged = try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice, signature: wrongSig)], items: [own.item, sharedItem], pinsSeq: 2)
        try rosterAnswer(s)
        let memory = try memory(bob, pins: pins)
        let repo = try await repo(bob, [good, forged], memory: memory)

        let family = try XCTUnwrap(repo.vault?.vaults.first { $0.id == s.id })
        guard case .signed(let signer) = family.trust else { return XCTFail("\(family.trust)") }
        XCTAssertEqual(signer.email, "alice@example.com")
        XCTAssertEqual(signer.fingerprint, alice.signing.fingerprint())
        XCTAssertEqual(signer.pin, .new)
        XCTAssertEqual(repo.vault?.entries.map(\.item.name).sorted(), ["Bank", "Mine"])
        XCTAssertEqual(repo.loginsFor("https://bank-site.com").count, 1)
        XCTAssertEqual(requests("GET", "/api/vaults/\(s.id)/rosters").first?.query, "after=0")
        XCTAssertEqual(memory.load("acc").rosters[s.id], s.roster)
        XCTAssertEqual(memory.load("acc").signed, [s.id])
        XCTAssertEqual(repo.knownPeople.map(\.email), ["alice@example.com"])
        let written = try writtenPins(bob)
        XCTAssertEqual(written["pins"]?.array.map { $0.str("user_id") }, [alice.id])
        XCTAssertNotNil(written["epochs"]?[s.id]?["signed_since"]?.number)

        // The next sync brings a share that doesn't verify: the vault and its items go from
        // everything (list, AutoFill, save targets) and the app says why.
        try await repo.sync()
        XCTAssertNil(repo.vault?.vaults.first { $0.id == s.id })
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Mine"])
        XCTAssertEqual(repo.vault?.refused, [RefusedVault(id: s.id, name: "Family", reason: .unverified)])
        XCTAssertEqual(repo.loginsFor("https://bank-site.com").count, 0)
        let ownId = own.row["id"] as? String ?? ""
        XCTAssertEqual(repo.vault?.writable.map(\.id) ?? [], [ownId])
        XCTAssertEqual(requests("GET", "/api/vaults/\(s.id)/rosters").count, 1, "the remembered roster is the server's: nothing fetched")
    }

    func testInvitationsNeedASignatureAndWritePinsOnAcceptAndATombstoneOnDecline() async throws {
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        let meta = try s.key.encryptMeta(vaultId: s.id, metaJson: #"{"name":"Family"}"#)
        let by: [String: Any] = ["id": alice.id, "email": alice.email, "name": "Alice", "public_key": alice.account.publicKey()]
        let signed: [String: Any] = ["vault_id": s.id, "role": "write", "wrapped_key": s.sealedForBob, "meta": meta, "invited_by": by,
                                     "invited_at": 1_700_000_000, "key_epoch": 0, "share": shareJSON(s.signature, by: alice),
                                     "member_roster": s.roster, "member_roster_seq": 1]
        let plainId = try newId()
        let plainKey = try alice.account.newVaultKey(vaultId: plainId).key
        let unsigned: [String: Any] = ["vault_id": plainId, "role": "read", "wrapped_key": try plainKey.shareTo(vaultId: plainId, recipientPublicKey: bob.account.publicKey()),
                                       "meta": try plainKey.encryptMeta(vaultId: plainId, metaJson: #"{"name":"Planted"}"#), "invited_by": by,
                                       "key_epoch": 0, "share": NSNull(), "member_roster": NSNull(), "member_roster_seq": 0]
        try rosterAnswer(s)
        let memory = InMemorySharingMemory()
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], invitations: [signed, unsigned])], memory: memory)
        let list = try XCTUnwrap(repo.vault?.invitations)
        XCTAssertEqual(list.count, 2)
        guard case .signed(let signer)? = list[0].trust else { return XCTFail("\(String(describing: list[0].trust))") }
        XCTAssertEqual(signer.fingerprint, alice.signing.fingerprint())
        XCTAssertTrue(list[0].canAccept)
        XCTAssertEqual(list[1].trust, .unsigned)
        XCTAssertFalse(list[1].canAccept)
        XCTAssertTrue(repo.knownPeople.isEmpty, "the signer isn't pinned before the user accepts")
        do {
            try await repo.acceptInvitation(try shownInvitation(repo, plainId))
            XCTFail("an unsigned invitation was accepted")
        } catch {
            XCTAssertEqual(errorMessage(error), InvitationText.cantAcceptUnverified)
        }
        XCTAssertTrue(requests("POST", "/api/vaults/\(plainId)/invitation/accept").isEmpty)
        // Accepting the signed one pins its signer and the vault's epoch, and remembers its roster.
        try await repo.acceptInvitation(try shownInvitation(repo, s.id))
        XCTAssertEqual(requests("POST", "/api/vaults/\(s.id)/invitation/accept").count, 1)
        XCTAssertEqual(memory.load("acc").rosters[s.id], s.roster)
        var pins = try writtenPins(bob)
        XCTAssertEqual(pins["pins"]?.array.map { $0.str("user_id") }, [alice.id])
        XCTAssertNotNil(pins["epochs"]?[s.id])
        // Declining the other one tombstones it (review L3).
        try await repo.declineInvitation(plainId)
        XCTAssertEqual(requests("DELETE", "/api/vaults/\(plainId)/invitation").count, 1)
        pins = try writtenPins(bob)
        XCTAssertNotNil(pins["left"]?[plainId])
        // Round 5 M2 (`pins_decline`): at roster version 0, never a server-chosen one.
        XCTAssertEqual(pins["left"]?[plainId]?["roster_version"]?.number, 0)
    }

    func testDecliningAVaultTheServerAddedLeavesIt() async throws {
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        try rosterAnswer(s, times: 3)
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)],
                                                     items: [own.item, try item("Bank", s.key, vault: s.id, id: s.itemId)], pinsSeq: 1)],
                                  memory: try memory(bob, pins: pins))
        XCTAssertEqual(repo.vault?.invitations.first?.consent, .added)
        XCTAssertTrue(try shownInvitation(repo, s.id).canDecline, "signed, declinable")
        try await repo.declineInvitation(s.id)
        // Round 5 M2: a vault among this sync's rows is never tombstoned (`pins_decline`); it is
        // left on the server.
        for write in requests("PUT", "/api/account/key-pins") {
            let p = try bob.account.openKeyPins(sealed: write.body["key_pins"] as? String ?? "", seq: UInt64(write.body["seq"] as? Int ?? 0))
            XCTAssertNil(try JSON.parse(p)["left"]?[s.id], "no tombstone for a current row")
        }
        XCTAssertEqual(requests("DELETE", "/api/vaults/\(s.id)/members/\(bob.id)").count, 1)
        XCTAssertTrue(requests("DELETE", "/api/vaults/\(s.id)/invitation").isEmpty)
        // Served again: asks again (nothing given up for good).
        XCTAssertEqual(repo.vault?.invitations.first?.consent, .added)
        XCTAssertTrue(repo.vault?.refused.isEmpty ?? false)
    }

    /// An unsigned share of Alice's vault to Bob (an app from before) at `epoch` with `key`.
    private func unsignedRow(_ id: String, key: VaultKey, to bob: Person, epoch: Int) throws -> [String: Any] {
        ["id": id, "wrapped_key": try key.shareTo(vaultId: id, recipientPublicKey: bob.account.publicKey()), "key_kind": "sealed", "role": "read",
         "key_epoch": epoch, "seq": 1, "meta": try key.encryptMeta(vaultId: id, metaJson: #"{"name":"Old"}"#), "share": NSNull(),
         "member_roster": NSNull(), "member_roster_seq": 0]
    }

    func testAnUnsignedKeyReplacementOfAnAcceptedVaultAsksFirst() async throws {
        // Round 3 M2: the server can't swap in a key of its own on a vault never seen signed.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let first = try alice.account.newVaultKey(vaultId: vid).key
        let second = try alice.account.newVaultKey(vaultId: vid).key
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: SignedSharing.candidatesJson([(vid, try first.keyId(vaultId: vid))]), createdIdentity: true)
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: vid, keyKind: "sealed", currentJson: try first.epochPinJson(vaultId: vid, keyEpoch: 0), rosterVersion: nil,
                                        rosterHash: nil)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row, try unsignedRow(vid, key: second, to: bob, epoch: 1)],
                                                     items: [own.item, try item("Old", second, vault: vid, id: try newId())], pinsSeq: 1)],
                                  memory: try memory(bob, pins: pins))
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid }, "the replaced key isn't used before the user says so")
        let consent = try XCTUnwrap(repo.vault?.invitations.first { $0.vaultId == vid })
        XCTAssertEqual(consent.consent, .replaced)
        XCTAssertTrue(consent.canAccept)
        // No Decline for an unsigned consent (cross-client rule 1): declining throws, nothing
        // written, nothing asked of the server; "Not now" keeps it locked.
        XCTAssertFalse(consent.canDecline)
        let writes = requests("PUT", "/api/account/key-pins").count
        do {
            try await repo.declineInvitation(vid)
            XCTFail("an unsigned key replacement can't be declined")
        } catch let e as UserError {
            XCTAssertEqual(e.message, SharingText.cantDecline)
        }
        XCTAssertEqual(requests("PUT", "/api/account/key-pins").count, writes)
        XCTAssertTrue(requests("DELETE", "/api/vaults/\(vid)/members/\(bob.id)").isEmpty)
        // Accepting pins the new key; then it is used, still "Not yet signed".
        try await repo.acceptInvitation(try shownInvitation(repo, vid))
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == vid }?.trust, .notYetSigned)
    }

    func testMissingTrustMemoryAsksForEverySharedVault() async throws {
        // Round 3 M3: the account has an identity but the server returns no key pins.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row, try unsignedRow(vid, key: key, to: bob, epoch: 0)],
                                                     items: [own.item])])
        XCTAssertEqual(repo.sharingNotice, SharingText.trustMemoryMissing)
        let written = try writtenPins(bob)
        XCTAssertEqual(grandfatheredIds(written), [], "nothing grandfathered")
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid })
        let consent = try XCTUnwrap(repo.vault?.invitations.first { $0.vaultId == vid })
        XCTAssertEqual(consent.trust, .unsigned)
        XCTAssertTrue(consent.canAccept, "unsigned vaults can be accepted in this state")
        try await repo.acceptInvitation(try shownInvitation(repo, vid))
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == vid }?.trust, .notYetSigned)
    }


    // MARK: Final review fixes (M-A, M-B, L-A…L-F)

    /// A signed invitation of `s` (or of another key `key` for the same vault) to Bob.
    private func signedInvitation(_ s: Shared, by alice: Person, sealed: String? = nil, signature: String? = nil, roster: String? = nil,
                                  key: VaultKey? = nil) throws -> [String: Any] {
        let by: [String: Any] = ["id": alice.id, "email": alice.email, "name": "Alice", "public_key": alice.account.publicKey()]
        return ["vault_id": s.id, "role": "write", "wrapped_key": sealed ?? s.sealedForBob,
                "meta": try (key ?? s.key).encryptMeta(vaultId: s.id, metaJson: #"{"name":"Family"}"#), "invited_by": by,
                "invited_at": 1_700_000_000, "key_epoch": 0, "share": shareJSON(signature ?? s.signature, by: alice),
                "member_roster": roster ?? s.roster, "member_roster_seq": 1]
    }

    func testAcceptingIsBoundToTheInvitationAsShown() async throws {
        // M-A: the user saw invitation A; the server then lists B (another key and member list for
        // the same vault). Accepting A accepts nothing, and nothing is asked of the server.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        let keyB = try alice.account.newVaultKey(vaultId: s.id).key
        let shareB = try alice.signing.sealAndSignShare(vaultKey: keyB, vaultId: s.id, recipientJson: bob.pub, role: "write", keyEpoch: 0)
        let rosterB = try SignedSharingTests.signRoster(alice.signing, key: keyB, vault: s.id, previous: nil, epoch: 0,
                                                        members: [member(alice, "owner"), member(bob, "write")])
        ScriptedServer.answer("GET /api/vaults/\(s.id)/rosters", 200, try text(["rosters": [s.roster], "latest": 1, "more": false]))
        ScriptedServer.answer("GET /api/vaults/\(s.id)/rosters", 200, try text(["rosters": [rosterB], "latest": 1, "more": false]))
        let a = try syncBody(bob, vaults: [own.row], items: [own.item], invitations: [try signedInvitation(s, by: alice)])
        let b = try syncBody(bob, vaults: [own.row], items: [own.item],
                             invitations: [try signedInvitation(s, by: alice, sealed: shareB.sealedKey, signature: shareB.signature, roster: rosterB, key: keyB)])
        let repo = try await repo(bob, [a, b])
        let shownA = try shownInvitation(repo, s.id)
        XCTAssertTrue(shownA.canAccept)
        try await repo.sync()
        let current = try shownInvitation(repo, s.id)
        XCTAssertTrue(current.canAccept)
        XCTAssertFalse(Invitation.sameDecision(shownA, current))
        let pinWrites = requests("PUT", "/api/account/key-pins").count
        do {
            try await repo.acceptInvitation(shownA)
            XCTFail("an invitation other than the one shown was accepted")
        } catch {
            XCTAssertEqual(errorMessage(error), InvitationText.changed)
        }
        XCTAssertTrue(requests("POST", "/api/vaults/\(s.id)/invitation/accept").isEmpty, "nothing asked of the server")
        XCTAssertEqual(requests("PUT", "/api/account/key-pins").count, pinWrites, "nothing pinned")
        // The invitation as it is shown now can be accepted.
        XCTAssertTrue(Invitation.sameDecision(current, try shownInvitation(repo, s.id)))
        try await repo.acceptInvitation(current)
        XCTAssertEqual(requests("POST", "/api/vaults/\(s.id)/invitation/accept").count, 1)
    }

    func testAFreshDeviceGrandfathersNothingAndAsksForEachUnsignedVault() async throws {
        // Rule 1: no offline copy from an earlier session (a fresh install): a server answering
        // `created: true` gets a consent prompt, never a silently used vault.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true,"created":true}"#)
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, try unsignedRow(vid, key: key, to: bob, epoch: 0)],
                                                     items: [own.item])])
        XCTAssertEqual(grandfatheredIds(try writtenPins(bob)), [], "nothing grandfathered")
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid })
        XCTAssertEqual(repo.sharingNotice, SharingText.newDevice)
        let consent = try shownInvitation(repo, vid)
        XCTAssertEqual(consent.trust, .unsigned)
        XCTAssertTrue(consent.canAccept, "accepted by the key shown")
        XCTAssertTrue(consent.declineHidden, "a server can't push the user into leaving it")
        XCTAssertFalse(consent.canDecline)
        XCTAssertEqual(consent.shownKeyId?.count, 19, "the key accepting pins is shown")
        do {
            try await repo.declineInvitation(vid)
            XCTFail("an unsigned vault the server added can't be declined")
        } catch {}
        XCTAssertTrue(requests("DELETE", "/api/vaults/\(vid)/members/\(bob.id)").isEmpty)
        try await repo.acceptInvitation(consent)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == vid }?.trust, .notYetSigned)
        XCTAssertNotEqual(repo.sharingNotice, SharingText.newDevice, "nothing waits any more")
    }

    func testAnUploadAnswerWithoutCreatedGrandfathersOnlyOnceTheListedIdentityIsTheKeptOne() async throws {
        // M-B / L-A: `created` missing is not `true`: nothing grandfathered then. The identity's
        // hash was kept before the upload; the next sync lists a record that opens to it: made here.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let row = try unsignedRow(vid, key: key, to: bob, epoch: 0)
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true}"#)
        let memory = InMemorySharingMemory()
        let body = try syncBody(bob, identity: false, vaults: [own.row, row], items: [own.item])
        let repo = try await repo(bob, [body], memory: memory, earlier: body)
        let put = try XCTUnwrap(requests("PUT", "/api/account/identity").first)
        for write in requests("PUT", "/api/account/key-pins") {
            let pins = try bob.account.openKeyPins(sealed: write.body["key_pins"] as? String ?? "", seq: UInt64(write.body["seq"] as? Int ?? 0))
            XCTAssertNil(KeyPinsReader.field(pins, "grandfathered"), "nothing grandfathered")
            XCTAssertNil(KeyPinsReader.field(pins, "own_identity"), "no identity remembered")
        }
        let kept = try XCTUnwrap(memory.load("acc").pendingIdentity)
        XCTAssertEqual(try bob.account.openSigningIdentity(recordJson: try text(put.body)).identityHash(), kept)
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid })
        let seq = Int64(requests("PUT", "/api/account/key-pins").last?.body["seq"] as? Int ?? 0)
        ScriptedServer.syncBodies = [try syncBody(bob, identityRecord: put.body, vaults: [own.row, row], items: [own.item], pinsSeq: seq)]
        try await repo.sync()
        XCTAssertEqual(requests("PUT", "/api/account/identity").count, 1, "the same identity, uploaded once")
        XCTAssertTrue(try writtenPins(bob)["grandfathered"]?[vid] != nil)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == vid }?.trust, .notYetSigned)
        XCTAssertNil(repo.sharingNotice)
    }

    func testAnUploadTriedAgainSendsTheIdentityKeptBefore() async throws {
        // L-A: the first upload's answer was lost (a network error); the next unlock sends the same record.
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        let memory = InMemorySharingMemory()
        ScriptedServer.answer("PUT /api/account/identity", 502, #"{"error":"bad_gateway","message":"x"}"#)
        _ = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row], items: [own.item])], memory: memory)
        let first = try XCTUnwrap(requests("PUT", "/api/account/identity").first)
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true,"created":true}"#)
        let again = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row], items: [own.item])], memory: memory)
        try await again.sync()
        let puts = requests("PUT", "/api/account/identity")
        XCTAssertEqual(puts.count, 2)
        XCTAssertEqual(puts[1].body["signing_key"] as? String, first.body["signing_key"] as? String)
        XCTAssertNotNil(again.ownIdentityFingerprint)
    }

    func testAnIdentityAnotherDeviceMadeMeanwhileGrandfathersNothingThatSync() async throws {
        // Rule 3: on 409 `identity_exists` the stored identity is opened; grandfathering waits.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let row = try unsignedRow(vid, key: key, to: bob, epoch: 0)
        ScriptedServer.answer("PUT /api/account/identity", 409, #"{"error":"identity_exists","message":"x"}"#)
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, row], items: [own.item]),
                                        try syncBody(bob, vaults: [own.row, row], items: [own.item])])
        XCTAssertNotNil(repo.ownIdentityFingerprint, "the stored identity is used")
        for put in requests("PUT", "/api/account/key-pins") {
            let pins = try JSON.parse(try bob.account.openKeyPins(sealed: put.body["key_pins"] as? String ?? "", seq: UInt64(put.body["seq"] as? Int ?? 0)))
            XCTAssertNil(KeyPinsReader.field(pins.text, "grandfathered"), "nothing grandfathered on that sync")
        }
        XCTAssertNotEqual(repo.sharingNotice, SharingText.trustMemoryMissing)
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid })
    }

    func testUnknownServerFeaturesRunTheChecksButKeepNothing() async throws {
        // Rule 4: the server's config was never read: the checks run, nothing that keeps them on
        // for good is stored (no memory, no key pins, no identity).
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let memory = InMemorySharingMemory()
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, try unsignedRow(vid, key: key, to: bob, epoch: 0)],
                                                     items: [own.item])], memory: memory, features: nil, config: false, olderServers: true)
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid }, "checked")
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Mine"])
        XCTAssertTrue(memory.load("acc").isEmpty, "nothing kept")
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty)
        XCTAssertTrue(requests("PUT", "/api/account/identity").isEmpty)
        XCTAssertFalse(repo.signedSharingOn("acc"), "not sticky")
    }

    func testANewerListOfKnownKeysTheServerWithholdsKeepsTheDevicesOwn() async throws {
        // L-B: the server lists version 3 but sends none: like a rollback.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: s.id, keyKind: "sealed", currentJson: try s.key.epochPinJson(vaultId: s.id, keyEpoch: 0), rosterVersion: 1,
                                        rosterHash: try rosterHash(rosterJson: s.roster))
        let memory = try memory(bob, pins: pins, rosters: [s.id: s.roster])
        ScriptedServer.answer("GET /api/account/key-pins", 200, #"{"key_pins":null,"seq":3}"#)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)],
                                                     items: [own.item, try item("Bank", s.key, vault: s.id, id: s.itemId)], pinsSeq: 3)],
                                  memory: memory)
        XCTAssertEqual(repo.sharingNotice, SharingText.pinsWithheld)
        XCTAssertNotNil(repo.vault?.vaults.first { $0.id == s.id }, "the device's own list is used")
        XCTAssertEqual(memory.load("acc").serverBase, 1, "still on the version this device opened")
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty, "nothing written over a version it can't see")
    }

    func testADeviceWithoutItsOwnListWaitsForTheServersOne() async throws {
        // L-B: no list on the device, the server lists one but doesn't give it: shared vaults wait.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        ScriptedServer.answer("GET /api/account/key-pins", 200, #"{"key_pins":null,"seq":2}"#)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)],
                                                     items: [own.item, try item("Bank", s.key, vault: s.id, id: s.itemId)], pinsSeq: 2)])
        XCTAssertEqual(repo.vault?.refused.map(\.reason), [.admission("pins_unavailable")])
        XCTAssertEqual(repo.sharingNotice, SharingText.pinsUnavailable)
        XCTAssertTrue(repo.vault?.invitations.isEmpty ?? false, "not a consent either")
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty, "nothing grandfathered or written")
    }

    func testAMemoryTheKeychainCantReadIsNeitherEmptyNorOverwritten() async throws {
        // L-C: a failed read is "unknown": shared vaults refused, nothing grandfathered or written.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: s.id, keyKind: "sealed", currentJson: try s.key.epochPinJson(vaultId: s.id, keyEpoch: 0), rosterVersion: 1,
                                        rosterHash: try rosterHash(rosterJson: s.roster))
        let memory = try memory(bob, pins: pins, rosters: [s.id: s.roster])
        memory.failReads = true
        let body = try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)],
                                items: [own.item, try item("Bank", s.key, vault: s.id, id: s.itemId)], pinsSeq: 1)
        // L3: the account's own vaults are checked against the server's key pins (read-only), never against none.
        ScriptedServer.answer("GET /api/account/key-pins", 200, try text(["key_pins": try bob.account.sealKeyPins(pinsJson: pins, seq: 1), "seq": 1]))
        let repo = try await repo(bob, [body], memory: memory)
        XCTAssertEqual(repo.vault?.refused.map(\.reason), [.admission("memory_unreadable")])
        XCTAssertEqual(repo.vault?.entries.map(\.item.name), ["Mine"])
        XCTAssertEqual(repo.sharingNotice, SharingText.memoryUnreadable)
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty)
        XCTAssertTrue(requests("PUT", "/api/account/identity").isEmpty)
        XCTAssertTrue(repo.hasSignedHistory(s.id), "unknown counts as signed")
        memory.failReads = false
        let kept = memory.load("acc")
        XCTAssertEqual(kept.pinsSeq, 1)
        XCTAssertEqual(kept.rosters[s.id], s.roster, "nothing written over it")
        try await repo.sync()
        XCTAssertNotNil(repo.vault?.vaults.first { $0.id == s.id }, "readable again: used")
    }

    func testUnsentKeyPinsOfTheOtherProcessAreMergedNotLost() throws {
        // L-D: the AutoFill extension kept an unsent change (Alice pinned); the app then wrote the
        // server's next version (Carol pinned). Saving merges both instead of dropping one.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let carol = try person("carol@example.com")
        let now: Int64 = 1_700_000_000
        let withAlice = try pinSet(pinsJson: nil, identityJson: alice.pub, email: alice.email, verified: false, now: now)
        let withCarol = try pinSet(pinsJson: nil, identityJson: carol.pub, email: carol.email, verified: false, now: now)
        let memory = InMemorySharingMemory()
        var theirs = SharingMemoryRecord()
        theirs.pinsSeq = 2
        theirs.sealedPins = try bob.account.sealKeyPins(pinsJson: withAlice, seq: 2)
        theirs.uploaded = false
        memory.put("acc", theirs)
        var ours = SharingMemoryRecord()
        ours.pinsSeq = 2
        ours.sealedPins = try bob.account.sealKeyPins(pinsJson: withCarol, seq: 2)
        ours.uploaded = true
        XCTAssertTrue(memory.save("acc", ours, resolve: VaultRepository.pinsResolver(bob.account)))
        let stored = memory.load("acc")
        XCTAssertFalse(stored.uploaded, "the merge still has to reach the server")
        XCTAssertEqual(stored.pinsSeq, 3)
        let opened = try JSON.parse(try bob.account.openKeyPins(sealed: try XCTUnwrap(stored.sealedPins), seq: 3))
        XCTAssertEqual(Set(opened["pins"]?.array.map { $0.str("user_id") } ?? []), [alice.id, carol.id])
        // Both unsent: merged too.
        var mine = SharingMemoryRecord()
        mine.pinsSeq = 2
        mine.sealedPins = try bob.account.sealKeyPins(pinsJson: withAlice, seq: 2)
        mine.uploaded = false
        let other = InMemorySharingMemory()
        var theirs2 = SharingMemoryRecord()
        theirs2.pinsSeq = 2
        theirs2.sealedPins = try bob.account.sealKeyPins(pinsJson: withCarol, seq: 2)
        theirs2.uploaded = false
        other.put("acc", theirs2)
        other.save("acc", mine, resolve: VaultRepository.pinsResolver(bob.account))
        let both = other.load("acc")
        let opened2 = try JSON.parse(try bob.account.openKeyPins(sealed: try XCTUnwrap(both.sealedPins), seq: UInt64(both.pinsSeq)))
        XCTAssertEqual(Set(opened2["pins"]?.array.map { $0.str("user_id") } ?? []), [alice.id, carol.id])
        XCTAssertFalse(both.uploaded)
    }

    func testATombstoneWhoseWriteFailedIsWrittenAtTheNextSync() async throws {
        // Info: the server took the decline but the key pins couldn't be kept: retried.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let plainId = try newId()
        let plainKey = try alice.account.newVaultKey(vaultId: plainId).key
        let by: [String: Any] = ["id": alice.id, "email": alice.email, "name": "Alice", "public_key": alice.account.publicKey()]
        let unsigned: [String: Any] = ["vault_id": plainId, "role": "read", "wrapped_key": try plainKey.shareTo(vaultId: plainId, recipientPublicKey: bob.account.publicKey()),
                                       "meta": try plainKey.encryptMeta(vaultId: plainId, metaJson: #"{"name":"Planted"}"#), "invited_by": by,
                                       "key_epoch": 0, "share": NSNull(), "member_roster": NSNull(), "member_roster_seq": 0]
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        let memory = try memory(bob, pins: pins)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], invitations: [unsigned], pinsSeq: 1)], memory: memory)
        memory.failReads = true
        let writes = requests("PUT", "/api/account/key-pins").count
        try await repo.declineInvitation(plainId)
        XCTAssertEqual(requests("DELETE", "/api/vaults/\(plainId)/invitation").count, 1)
        XCTAssertEqual(requests("PUT", "/api/account/key-pins").count, writes)
        XCTAssertNil(try? writtenPins(bob)["left"]?[plainId])
        memory.failReads = false
        try await repo.sync()
        XCTAssertNotNil(try writtenPins(bob)["left"]?[plainId], "the tombstone is written now")
    }

    // MARK: Key replacement

    /// Alice (the app's account) owns a vault shared with Bob, with roster v1 the device trusts.
    private func ownerWorld() async throws -> (alice: Person, bob: Person, s: Shared, repo: VaultRepository, memory: InMemorySharingMemory) {
        let alice = try person("alice@example.com")
        let bob = try person("bob@example.com")
        let s = try shared(owner: alice, member: bob)
        let row: [String: Any] = ["id": s.id, "wrapped_key": s.wrappedForOwner, "key_kind": "account", "role": "owner", "key_epoch": 0, "seq": 1,
                                  "rotation_pending": 1, "meta": try s.key.encryptMeta(vaultId: s.id, metaJson: #"{"name":"Family"}"#),
                                  "share": NSNull(), "member_roster": s.roster, "member_roster_seq": 1]
        let memory = InMemorySharingMemory()
        var m = SharingMemoryRecord()
        m.rosters[s.id] = s.roster
        memory.put("acc", m)
        let repo = try await repo(alice, [try syncBody(alice, vaults: [row], items: [try item("Bank", s.key, vault: s.id, id: s.itemId, revision: 9)])],
                                  memory: memory)
        XCTAssertEqual(repo.vault?.vaults.first?.trust, .own)
        return (alice, bob, s, repo, memory)
    }

    private func membersAnswer(_ rows: [[String: Any]], _ s: Shared?, seq: Int = 1, epoch: Int = 0) throws -> String {
        try text(["members": rows, "key_epoch": epoch, "member_roster": s.map { $0.roster as Any } ?? NSNull(), "member_roster_seq": s == nil ? 0 : seq])
    }

    func testReplacingASharedVaultsKeySealsAndSignsForEveryMember() async throws {
        let (alice, bob, s, repo, memory) = try await ownerWorld()
        ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account"), bob.row("write", kind: "sealed")], s))
        let done = try await repo.rotateVaultKeys([s.id])
        XCTAssertEqual(done.rotated, [s.id])
        XCTAssertTrue(done.shared.isEmpty)
        let post = try XCTUnwrap(requests("POST", "/api/vaults/\(s.id)/rotate").first)
        XCTAssertEqual(post.body["key_epoch"] as? Int, 0)
        let keys = try XCTUnwrap(post.body["keys"] as? [[String: Any]])
        XCTAssertEqual(Set(keys.compactMap { $0["user_id"] as? String }), [alice.id, bob.id])
        let mine = try XCTUnwrap(keys.first { $0["user_id"] as? String == alice.id })
        XCTAssertEqual(mine["key_kind"] as? String, "account")
        XCTAssertNil(mine["signature"])
        let his = try XCTUnwrap(keys.first { $0["user_id"] as? String == bob.id })
        let sealed = try XCTUnwrap(his["wrapped_key"] as? String)
        // Bob's app: the new key opens, the share verifies at the new epoch, the roster follows v1
        // and commits to the key.
        _ = try verifyShare(vaultId: s.id, recipientJson: bob.pub, role: "write", keyEpoch: 1, sealedKey: sealed, signerJson: alice.pub,
                            signature: his["signature"] as? String ?? "")
        let newKey = try bob.account.openVaultKey(vaultId: s.id, wrapped: sealed, kind: "sealed", keyEpoch: 1, legacyAllowed: false)
        let roster = try XCTUnwrap(post.body["roster"] as? String)
        XCTAssertEqual(try verifyRosterChain(vaultId: s.id, trusted: s.roster, newer: [roster], latest: roster), roster)
        XCTAssertTrue(try newKey.matchesRoster(vaultId: s.id, rosterJson: roster))
        XCTAssertEqual(try rosterMemberRole(rosterJson: roster, identityJson: bob.pub), "write")
        XCTAssertEqual(SignedSharing.rosterVersion(roster), 2)
        let items = try XCTUnwrap(post.body["items"] as? [[String: Any]])
        XCTAssertEqual(items.map { ($0["revision"] as? NSNumber)?.int64Value }, [9])
        XCTAssertNoThrow(try newKey.decryptItem(encrypted: EncryptedItem(id: s.itemId, vaultId: s.id, key: items[0]["key"] as? String ?? "",
                                                                         data: items[0]["data"] as? String ?? "")))
        XCTAssertEqual(memory.load("acc").rosters[s.id], roster)
        // A later review showed nobody to compare (round 5 Info): Bob isn't pinned with an email
        // the user never saw.
        XCTAssertFalse(repo.knownPeople.contains { $0.email == "bob@example.com" })
        // The key this device gave the vault is recorded with the roster it signed (round 5).
        let recorded = try writtenPins(alice)
        XCTAssertEqual(recorded["epochs"]?[s.id]?["key_epoch"]?.number, 1)
        XCTAssertEqual(recorded["epochs"]?[s.id]?["roster_version_max"]?.number, 2)
        XCTAssertEqual(recorded["epochs"]?[s.id]?["roster_hash"]?.string, try rosterHash(rosterJson: roster))
    }

    func testMembersTheSignedRosterDoesntKnowStopTheReplacement() async throws {
        let (alice, bob, s, repo, _) = try await ownerWorld()
        let carol = try person("carol@example.com")
        ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200,
                              try membersAnswer([alice.row("owner", kind: "account"), bob.row("write", kind: "sealed"), carol.row("admin", kind: "sealed")], s))
        do {
            try await repo.rotateVaultKeys([s.id])
            XCTFail("the key was replaced for a member the roster doesn't list")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.membersDiffer(["carol@example.com"]))
        }
        ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account"), bob.row("admin", kind: "sealed")], s))
        do {
            try await repo.rotateVaultKeys([s.id])
            XCTFail("expected a stop")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.membersDiffer(["bob@example.com"]))
        }
        XCTAssertTrue(requests("POST", "/api/vaults/\(s.id)/rotate").isEmpty)
    }

    func testPeopleWhoLeftAreDroppedOnlyAfterTheUserConfirmsThemByUserId() async throws {
        // Review L2: the confirmation covers user ids, not the vault.
        let (alice, bob, s, repo, _) = try await ownerWorld()
        for _ in 0..<3 {
            ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account")], s))
        }
        let first = try await repo.rotateVaultKeys([s.id])
        XCTAssertEqual(first.confirm.map(\.userIds), [[bob.id]])
        XCTAssertEqual(first.confirm.first?.people, [SharingText.unknownMember])
        XCTAssertTrue(first.rotated.isEmpty)
        // Confirming someone else (or the vault as a whole) doesn't drop Bob.
        let wrong = try await repo.rotateVaultKeys([s.id], confirmed: [s.id: [alice.id]])
        XCTAssertEqual(wrong.confirm.count, 1)
        XCTAssertTrue(requests("POST", "/api/vaults/\(s.id)/rotate").isEmpty)
        let second = try await repo.rotateVaultKeys([s.id], confirmed: first.confirmedIds)
        XCTAssertEqual(second.rotated, [s.id])
        let post = try XCTUnwrap(requests("POST", "/api/vaults/\(s.id)/rotate").first)
        XCTAssertEqual((post.body["keys"] as? [[String: Any]])?.count, 1)
        let roster = try XCTUnwrap(post.body["roster"] as? String)
        XCTAssertEqual(SignedSharing.rosterMembers(roster), [alice.id])
        XCTAssertEqual(try verifyRosterChain(vaultId: s.id, trusted: s.roster, newer: [roster], latest: roster), roster)
    }

    func testTheServerRefusingTheMembersIsRetriedOnceThenNamed() async throws {
        let (alice, bob, s, repo, _) = try await ownerWorld()
        let carol = try person("carol@example.com")
        for _ in 0..<2 {
            ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account"), bob.row("write", kind: "sealed")], s))
            ScriptedServer.answer("POST /api/vaults/\(s.id)/rotate", 409,
                                  try text(["error": "members_changed", "message": "x", "key_epoch": 0, "unknown": [carol.id], "identity_changed": [],
                                            "role_changed": [], "missing": []]))
        }
        do {
            try await repo.rotateVaultKeys([s.id])
            XCTFail("expected members_changed")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.membersDiffer([SharingText.unknownMember]))
        }
        XCTAssertEqual(requests("POST", "/api/vaults/\(s.id)/rotate").count, 2)
        // A member the server names: their pinned email first, not the one the server lists now.
        try await repo.updatePins("acc", try XCTUnwrap(repo.sessions["acc"])) { p in
            try pinSet(pinsJson: p, identityJson: bob.pub, email: "bob@example.com", verified: false, now: 1)
        }
        var renamed = bob.row("write", kind: "sealed")
        renamed["email"] = "bob@elsewhere.example"
        ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account"), renamed], s))
        ScriptedServer.answer("POST /api/vaults/\(s.id)/rotate", 409,
                              try text(["error": "members_changed", "message": "x", "key_epoch": 0, "unknown": [], "identity_changed": [bob.id],
                                        "role_changed": [], "missing": []]))
        ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account"), renamed], s))
        ScriptedServer.answer("POST /api/vaults/\(s.id)/rotate", 409,
                              try text(["error": "members_changed", "message": "x", "key_epoch": 0, "unknown": [], "identity_changed": [bob.id],
                                        "role_changed": [], "missing": []]))
        do {
            try await repo.rotateVaultKeys([s.id])
            XCTFail("expected members_changed")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.membersDiffer(["bob@example.com"]))
        }
    }

    func testAMembersAnswerForAnotherStateThanTheVerifiedOneStops() async throws {
        // Review L1: the version and base epoch come from the verified state, not the server's numbers.
        let (alice, bob, s, repo, _) = try await ownerWorld()
        for _ in 0..<2 {
            ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200,
                                  try membersAnswer([alice.row("owner", kind: "account"), bob.row("write", kind: "sealed")], s, seq: 4))
        }
        do {
            try await repo.rotateVaultKeys([s.id])
            XCTFail("rotated on the server's roster number")
        } catch {}
        for _ in 0..<2 {
            ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200,
                                  try membersAnswer([alice.row("owner", kind: "account"), bob.row("write", kind: "sealed")], s, epoch: 3))
        }
        do {
            try await repo.rotateVaultKeys([s.id])
            XCTFail("rotated on the server's key epoch")
        } catch {}
        XCTAssertTrue(requests("POST", "/api/vaults/\(s.id)/rotate").isEmpty)
    }

    /// Alice's vault without a signed roster that the server says Mallory is a member of.
    private func unsignedOwnerWorld() async throws -> (alice: Person, mallory: Person, vaultId: String, repo: VaultRepository) {
        let alice = try person("alice@example.com")
        let mallory = try person("mallory@example.com")
        let own = try personal(alice)
        var row = own.row
        row["rotation_pending"] = 1
        let repo = try await repo(alice, [try syncBody(alice, vaults: [row], items: [own.item])])
        return (alice, mallory, row["id"] as? String ?? "", repo)
    }

    func testAVaultWithoutASignedRosterIsNeverSealedToMembersNobodyReviewed() async throws {
        // Review C1 / H4: no trusted roster, and the server lists an extra member.
        let (alice, mallory, vid, repo) = try await unsignedOwnerWorld()
        let rows = [alice.row("owner", kind: "account"), mallory.row("write", kind: "sealed")]
        for _ in 0..<2 { ScriptedServer.answer("GET /api/vaults/\(vid)/members", 200, try membersAnswer(rows, nil)) }
        let done = try await repo.rotateVaultKeys([vid])
        XCTAssertTrue(done.rotated.isEmpty)
        let review = try XCTUnwrap(done.review.first)
        XCTAssertTrue(review.review.first)
        XCTAssertEqual(review.review.members.map(\.userId).sorted(), [alice.id, mallory.id].sorted())
        let shown = try XCTUnwrap(review.review.members.first { $0.userId == mallory.id })
        XCTAssertEqual(shown.pin, "new")
        XCTAssertEqual(shown.fingerprint, mallory.signing.fingerprint())
        XCTAssertEqual(shown.shownEmail, "mallory@example.com")
        XCTAssertTrue(requests("POST", "/api/vaults/\(vid)/rotate").isEmpty, "nothing sealed without the review")
        // Emergency access (personal only): the same answer shows a shared vault: left alone.
        let personal = try await repo.rotateVaultKeys([vid], personalOnly: true)
        XCTAssertEqual(personal.shared.map(\.id), [vid])
        XCTAssertTrue(requests("POST", "/api/vaults/\(vid)/rotate").isEmpty)
        // The server adds Eve after the review: the confirmed digest no longer matches, shown again.
        let eve = try person("eve@example.com")
        ScriptedServer.answer("GET /api/vaults/\(vid)/members", 200, try membersAnswer(rows + [eve.row("read", kind: "sealed")], nil))
        let stale = try await repo.rotateVaultKeys([vid], reviewed: [vid: review.review.digest])
        XCTAssertEqual(stale.review.first?.review.members.count, 3)
        XCTAssertTrue(requests("POST", "/api/vaults/\(vid)/rotate").isEmpty)
        // The members the user confirmed: version 1, sealed and signed for exactly them. The server
        // now lists another email for Mallory: she is pinned with the one the review showed (L-F).
        var relabelled = mallory.row("write", kind: "sealed")
        relabelled["email"] = "mallory@evil.example"
        ScriptedServer.answer("GET /api/vaults/\(vid)/members", 200, try membersAnswer([alice.row("owner", kind: "account"), relabelled], nil))
        let confirmed = try await repo.rotateVaultKeys([vid], reviewed: [vid: review.review.digest])
        XCTAssertEqual(confirmed.rotated, [vid])
        let post = try XCTUnwrap(requests("POST", "/api/vaults/\(vid)/rotate").first)
        let roster = try XCTUnwrap(post.body["roster"] as? String)
        XCTAssertEqual(SignedSharing.rosterVersion(roster), 1)
        XCTAssertEqual(try verifyRosterChain(vaultId: vid, trusted: nil, newer: [roster], latest: roster), roster)
        XCTAssertEqual(Set((post.body["keys"] as? [[String: Any]])?.compactMap { $0["user_id"] as? String } ?? []), [alice.id, mallory.id])
        XCTAssertEqual(repo.knownPeople.map(\.email), ["mallory@example.com"], "pinned with the email the review showed")
    }

    func testAVaultOnlyTheUserIsInIsReplacedWithoutARoster() async throws {
        let (alice, _, vid, repo) = try await unsignedOwnerWorld()
        ScriptedServer.answer("GET /api/vaults/\(vid)/members", 200, try membersAnswer([alice.row("owner", kind: "account")], nil))
        let done = try await repo.rotateVaultKeys([vid], personalOnly: true)
        XCTAssertEqual(done.rotated, [vid])
        let post = try XCTUnwrap(requests("POST", "/api/vaults/\(vid)/rotate").first)
        XCTAssertNil(post.body["roster"], "no automatic version 1")
        XCTAssertEqual((post.body["keys"] as? [[String: Any]])?.count, 1)
    }

    func testEmergencyAccessLeavesASignedVaultOnlyTheUserIsIn() async throws {
        // Review M4: Alice's vault was shared before (a trusted roster listing Bob), Bob left.
        let (alice, _, s, repo, _) = try await ownerWorld()
        ScriptedServer.answer("GET /api/vaults/\(s.id)/members", 200, try membersAnswer([alice.row("owner", kind: "account")], s))
        XCTAssertTrue(repo.hasSignedHistory(s.id))
        let done = try await repo.rotateVaultKeys([s.id], personalOnly: true)
        XCTAssertEqual(done.shared.map(\.id), [s.id])
        XCTAssertTrue(requests("POST", "/api/vaults/\(s.id)/rotate").isEmpty)
    }

    // MARK: Round 4

    func testBeforeTheFirstSignedSyncUnsignedVaultsAreHeldNeutrallyAndNothingIsWritten() async throws {
        // Cross-client rule 2 (review M1 a): the server's config can't be read, so it hasn't shown
        // it signs: an unsigned shared vault is held ("still checking"), neither consent nor
        // declinable, and declining an invitation writes no tombstone.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let invId = try newId()
        let invKey = try alice.account.newVaultKey(vaultId: invId).key
        let by: [String: Any] = ["id": alice.id, "email": alice.email, "name": "Alice", "public_key": alice.account.publicKey()]
        let invitation: [String: Any] = ["vault_id": invId, "role": "read", "wrapped_key": try invKey.shareTo(vaultId: invId, recipientPublicKey: bob.account.publicKey()),
                                         "meta": try invKey.encryptMeta(vaultId: invId, metaJson: #"{"name":"Asked"}"#), "invited_by": by,
                                         "key_epoch": 0, "share": NSNull(), "member_roster": NSNull(), "member_roster_seq": 0]
        let memory = InMemorySharingMemory()
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, try unsignedRow(vid, key: key, to: bob, epoch: 0)],
                                                     items: [own.item], invitations: [invitation])], memory: memory, features: nil, config: false, olderServers: true)
        XCTAssertEqual(repo.vault?.refused.map(\.reason), [.checking])
        XCTAssertNil(repo.vault?.invitations.first { $0.vaultId == vid }, "not a consent: nothing to accept or decline")
        XCTAssertEqual(SharingText.refusedNotice(repo.vault?.refused ?? []), "A shared vault isn't shown until PassAuth finishes checking it.")
        try await repo.declineInvitation(invId)
        XCTAssertEqual(requests("DELETE", "/api/vaults/\(invId)/invitation").count, 1)
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty, "no tombstone before the server shows it signs")
        XCTAssertFalse(memory.load("acc").proven)
        XCTAssertFalse(repo.signedSharingOn("acc"), "not sticky")
    }

    func testAnUnansweredIdentityUploadHoldsUnsignedVaultsAndIsTriedAgainAtTheNextSync() async throws {
        // Review M1 b: the upload failed (5xx): the state is unknown, so the shared vault from
        // before is held, not offered for Decline; the next sync (same unlock) uploads again.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let row = try unsignedRow(vid, key: key, to: bob, epoch: 0)
        for _ in 0..<4 { ScriptedServer.answer("PUT /api/account/identity", 503, #"{"error":"unavailable","message":"x"}"#) }
        let memory = InMemorySharingMemory()
        let body = try syncBody(bob, identity: false, vaults: [own.row, row], items: [own.item])
        let repo = try await repo(bob, [body], memory: memory, earlier: body)
        XCTAssertEqual(repo.vault?.refused.first { $0.id == vid }?.reason, .checking)
        XCTAssertTrue(repo.vault?.invitations.isEmpty ?? false)
        ScriptedServer.answers["PUT /api/account/identity"] = nil
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true,"created":true}"#)
        try await repo.sync()
        let puts = requests("PUT", "/api/account/identity")
        XCTAssertGreaterThanOrEqual(puts.count, 2, "tried again at the next sync")
        XCTAssertEqual(puts.first?.body["signing_key"] as? String, puts.last?.body["signing_key"] as? String, "the same identity")
        XCTAssertTrue(try writtenPins(bob)["grandfathered"]?[vid] != nil)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == vid }?.trust, .notYetSigned)
    }

    func testAnIdentityMadeHereButGrandfatheredByAnotherDeviceLetsTheUserAcceptByKey() async throws {
        // Review M1 c: this device made the identity (the upload's answer was lost); another device
        // wrote the grandfathered list first (empty: it didn't make it). The shared vaults from
        // before can be accepted by the key shown, never declined.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let key = try alice.account.newVaultKey(vaultId: vid).key
        let row = try unsignedRow(vid, key: key, to: bob, epoch: 0)
        let memory = InMemorySharingMemory()
        var r = SharingMemoryRecord()
        r.pendingIdentity = bob.signing.identityHash()
        r.pendingRecord = bob.record
        r.candidates = [vid]
        memory.put("acc", r)
        var other = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        other = try pinsGrandfather(pinsJson: other, vaultsJson: "[]", createdIdentity: false)
        ScriptedServer.answer("GET /api/account/key-pins", 200, try text(["key_pins": try bob.account.sealKeyPins(pinsJson: other, seq: 1), "seq": 1]))
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row, row], items: [own.item], pinsSeq: 1)], memory: memory)
        let consent = try shownInvitation(repo, vid)
        XCTAssertEqual(consent.trust, .unsigned)
        XCTAssertTrue(consent.canAccept, "accepted by the key shown")
        XCTAssertFalse(consent.canDecline)
        XCTAssertEqual(repo.sharingNotice, SharingText.newDevice)
        try await repo.acceptInvitation(consent)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == vid }?.trust, .notYetSigned)
    }

    func testGrandfatheringUsesOnlyTheCandidatesRecordedWhenTheIdentityWasMade() async throws {
        // Review L2: the identity was made while the device knew [old]; a vault the server added
        // later (and that landed in this device's offline copy) isn't grandfathered by a later
        // unlock that finally gets the upload through.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let oldId = try newId(), plantedId = try newId()
        let old = try unsignedRow(oldId, key: try alice.account.newVaultKey(vaultId: oldId).key, to: bob, epoch: 0)
        let planted = try unsignedRow(plantedId, key: try alice.account.newVaultKey(vaultId: plantedId).key, to: bob, epoch: 0)
        let memory = InMemorySharingMemory()
        for _ in 0..<4 { ScriptedServer.answer("PUT /api/account/identity", 503, #"{"error":"unavailable","message":"x"}"#) }
        let before = try syncBody(bob, identity: false, vaults: [own.row, old], items: [own.item])
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, old, planted], items: [own.item])], memory: memory,
                                  earlier: before)
        XCTAssertEqual(Set(memory.load("acc").candidates ?? []), [own.row["id"] as? String ?? "", oldId])
        XCTAssertNil(repo.vault?.vaults.first { $0.id == plantedId })
        // The next unlock: the offline copy now has the planted vault too.
        await repo.lockActive()
        ScriptedServer.answers["PUT /api/account/identity"] = nil
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true,"created":true}"#)
        try await repo.unlock(password: password, secretKey: nil)
        try await repo.sync()
        let pins = try writtenPins(bob)
        // Round 5: grandfathered as {vault id: key id}.
        XCTAssertNotNil(pins["grandfathered"]?[oldId]?.string)
        XCTAssertNil(pins["grandfathered"]?[plantedId])
        let waiting = try shownInvitation(repo, plantedId)
        XCTAssertFalse(waiting.canDecline)
        XCTAssertEqual(repo.vault?.vaults.first { $0.id == oldId }?.trust, .notYetSigned)
    }

    func testAnUnreadableMemoryStillChecksOwnVaultsAgainstTheServersPins() async throws {
        // Review L3: an old personal key served again is refused even while the Keychain can't be
        // read (the server's key pins, opened read-only); without them the copy isn't used.
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        let vid = own.row["id"] as? String ?? ""
        let newer = try bob.account.newVaultKey(vaultId: vid).key
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: vid, keyKind: "sealed", currentJson: try newer.epochPinJson(vaultId: vid, keyEpoch: 1), rosterVersion: nil,
                                        rosterHash: nil)
        let memory = try memory(bob, pins: pins)
        memory.failReads = true
        ScriptedServer.answer("GET /api/account/key-pins", 200, try text(["key_pins": try bob.account.sealKeyPins(pinsJson: pins, seq: 1), "seq": 1]))
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], pinsSeq: 1)], memory: memory)
        XCTAssertEqual(repo.vault?.refused.map(\.reason), [.admission("older")], "the replayed old key")
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty)
        // The server's pins can't be had: the copy from the server isn't used (as offline).
        ScriptedServer.answer("GET /api/account/key-pins", 503, #"{"error":"unavailable","message":"x"}"#)
        await repo.lockActive()
        do {
            try await repo.unlock(password: password, secretKey: nil)
            try await repo.sync()
            XCTFail("used without key pins")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.memoryUnreadable)
        }
    }

    func testThisDevicesPinsAreMergedIntoEveryNewerServerCopy() async throws {
        // Cross-client rule 5: another device wrote version 2 without this device's tombstone; the
        // merge is written back although this device had nothing unsent.
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        let gone = try newId()
        var base = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        base = try pinsGrandfather(pinsJson: base, vaultsJson: "[]", createdIdentity: true)
        let mine = try pinsLeave(pinsJson: base, vaultId: gone, rosterVersion: 2, now: 1_700_000_000)
        let memory = try memory(bob, pins: mine)
        ScriptedServer.answer("GET /api/account/key-pins", 200, try text(["key_pins": try bob.account.sealKeyPins(pinsJson: base, seq: 2), "seq": 2]))
        _ = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], pinsSeq: 2)], memory: memory)
        let put = try XCTUnwrap(requests("PUT", "/api/account/key-pins").last, "the merge is written back")
        XCTAssertEqual(put.body["seq"] as? Int, 3)
        XCTAssertNotNil(try writtenPins(bob)["left"]?[gone])
    }

    func testWaitingTombstonesSurviveARestartButNeverTombstoneAUsableVault() async throws {
        // Info (persisted) and cross-client rule 3: a tombstone kept in the device memory by an
        // earlier run is written at the next sync, except for a vault this account uses.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        let gone = try newId()
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        pins = try pinSet(pinsJson: pins, identityJson: alice.pub, email: alice.email, verified: false, now: 1)
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: s.id, keyKind: "sealed", currentJson: try s.key.epochPinJson(vaultId: s.id, keyEpoch: 0), rosterVersion: 1,
                                        rosterHash: try rosterHash(rosterJson: s.roster))
        let memory = try memory(bob, pins: pins, rosters: [s.id: s.roster])
        var r = memory.load("acc")
        r.tombstones = [gone: 4]
        memory.put("acc", r)
        let body = try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)], items: [own.item], pinsSeq: 1)
        let repo = try await repo(bob, [body], memory: memory)
        XCTAssertNotNil(repo.vault?.vaults.first { $0.id == s.id }, "used")
        XCTAssertNotNil(try writtenPins(bob)["left"]?[gone])
        XCTAssertTrue((memory.load("acc").tombstones ?? [:]).isEmpty, "done")
        // A tombstone for the vault this account uses now (and a declined invitation for it) is dropped.
        var again = memory.load("acc")
        again.tombstones = [s.id: 1]
        memory.put("acc", again)
        try await repo.sync()
        XCTAssertNil(try writtenPins(bob)["left"]?[s.id])
        XCTAssertNotNil(repo.vault?.vaults.first { $0.id == s.id })
        let by: [String: Any] = ["id": alice.id, "email": alice.email, "name": "Alice", "public_key": alice.account.publicKey()]
        let dup: [String: Any] = ["vault_id": s.id, "role": "write", "wrapped_key": s.sealedForBob,
                                  "meta": try s.key.encryptMeta(vaultId: s.id, metaJson: #"{"name":"Family"}"#), "invited_by": by,
                                  "key_epoch": 0, "share": NSNull(), "member_roster": NSNull(), "member_roster_seq": 0]
        ScriptedServer.syncBodies = [try syncBody(bob, vaults: [own.row, try bobRow(s, by: alice)], items: [own.item], invitations: [dup],
                                                  pinsSeq: Int64(requests("PUT", "/api/account/key-pins").last?.body["seq"] as? Int ?? 1))]
        try await repo.sync()
        let writes = requests("PUT", "/api/account/key-pins").count
        try await repo.declineInvitation(s.id)
        XCTAssertEqual(requests("PUT", "/api/account/key-pins").count, writes, "the vault in use isn't tombstoned")
        XCTAssertNil(try writtenPins(bob)["left"]?[s.id])
    }

    func testTooManyKeyReplacementsAreSaidPlainly() async throws {
        let (alice, _, vid, repo) = try await unsignedOwnerWorld()
        ScriptedServer.answer("GET /api/vaults/\(vid)/members", 200, try membersAnswer([alice.row("owner", kind: "account")], nil))
        ScriptedServer.answer("POST /api/vaults/\(vid)/rotate", 429, #"{"error":"rate_limited","message":"x"}"#, headers: ["Retry-After": "600"])
        do {
            _ = try await repo.rotateVaultKeys([vid])
            XCTFail("replaced")
        } catch {
            XCTAssertEqual(errorMessage(error), SharingText.keyReplacementLimited(600))
        }
    }

    // MARK: Round 5

    /// A `/sync` answer's bundle with another `account_id`: never stored (iOS H); the account id an
    /// unlock authenticated is kept with the account.
    private func bundle(_ me: Person, accountId: String) throws -> String {
        var b = json(me.created.bundleJson) as? [String: Any] ?? [:]
        b["account_id"] = accountId
        return try text(b)
    }

    func testABundleWithAnotherAccountIdIsNeverStoredUnlockedOrLocked() async throws {
        let bob = try person("bob@example.com")
        let mallory = try person("mallory@example.com")
        let own = try personal(bob)
        let swapped = try bundle(bob, accountId: mallory.id)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], bundle: swapped)])
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.accountId, bob.id, "the id the unlock authenticated")
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.bundle, bob.created.bundleJson, "the synced bundle wasn't stored")
        // Locked: a background refresh with another account's bundle keeps nothing.
        await repo.lockActive()
        ScriptedServer.syncBodies = [try syncBody(bob, vaults: [own.row], items: [own.item], bundle: mallory.created.bundleJson)]
        try await repo.refreshCacheLocked(accountId: "acc")
        XCTAssertEqual(repo.store.get().file.accounts["acc"]?.bundle, bob.created.bundleJson)
        // The checks behind it (pure).
        XCTAssertTrue(VaultRepository.bundleMayBeStored(bob.created.bundleJson, account: bob.account, authenticatedId: bob.id))
        XCTAssertFalse(VaultRepository.bundleMayBeStored(swapped, account: bob.account, authenticatedId: bob.id))
        XCTAssertFalse(VaultRepository.bundleMayBeStored(mallory.created.bundleJson, account: bob.account, authenticatedId: nil))
        XCTAssertFalse(VaultRepository.bundleMayBeStored(mallory.created.bundleJson, account: nil, authenticatedId: bob.id))
        XCTAssertFalse(VaultRepository.bundleMayBeStored(bob.created.bundleJson, account: nil, authenticatedId: nil), "nothing before an unlock authenticated an id")
    }

    func testKeptSessionBytesOpenOnlyForTheAccountsOwnBundle() async throws {
        // iOS H: Face ID / "Never" / the macOS timed unlock restore under an authenticated id, and
        // only when the stored bundle is the account's own (`matches_bundle`).
        let bob = try person("bob@example.com")
        let mallory = try person("mallory@example.com")
        let bytes = bob.account.toSessionBytes()
        XCTAssertEqual(VaultRepository.restoreSession(bundle: bob.created.bundleJson, authenticatedId: bob.id, bytes: bytes)?.accountId, bob.id)
        XCTAssertEqual(VaultRepository.restoreSession(bundle: bob.created.bundleJson, authenticatedId: nil, bytes: bytes)?.accountId, bob.id)
        XCTAssertNil(VaultRepository.restoreSession(bundle: try bundle(bob, accountId: mallory.id), authenticatedId: nil, bytes: bytes),
                     "a bundle relabelled with another id")
        XCTAssertNil(VaultRepository.restoreSession(bundle: mallory.created.bundleJson, authenticatedId: nil, bytes: bytes), "another account's bundle")
        XCTAssertNil(VaultRepository.restoreSession(bundle: bob.created.bundleJson, authenticatedId: mallory.id, bytes: bytes),
                     "another id than the authenticated one")
        // Timeout "Never" after a restart: a stored bundle the server swapped stays locked.
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: bob.email)
            acc.bundle = try? self.bundle(bob, accountId: mallory.id)
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.file.settings.vaultTimeout = .never
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
            s.secrets.persistedKeys["acc"] = bytes.base64EncodedString()
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [ScriptedServer.self] })
        repo.sharingMemory = InMemorySharingMemory()
        let restored = await repo.restorePersisted()
        XCTAssertFalse(restored)
        XCTAssertNil(repo.vault)
    }

    func testAnotherUsersMemoryIsUnreadableAndTheOfflineCopyNeverStandsInOnceMemoryExists() async throws {
        // iOS H: a record of another user id on the same server is never taken for an empty one;
        // a record of this account (even without `seen`) means the offline copy isn't the earlier
        // copy, so a vault a background refresh put there isn't grandfathered.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let vid = try newId()
        let row = try unsignedRow(vid, key: try alice.account.newVaultKey(vaultId: vid).key, to: bob, epoch: 0)
        let memory = InMemorySharingMemory()
        var r = SharingMemoryRecord()
        r.userId = bob.id
        r.server = "https://fake.passauth.test"
        memory.put("acc", r)
        ScriptedServer.answer("PUT /api/account/identity", 200, #"{"ok":true,"created":true}"#)
        let earlier = try syncBody(bob, identity: false, vaults: [own.row, row], items: [own.item])
        let repo = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row, row], items: [own.item])], memory: memory, earlier: earlier)
        XCTAssertEqual(grandfatheredIds(try writtenPins(bob)), [], "nothing from the offline copy")
        XCTAssertNil(repo.vault?.vaults.first { $0.id == vid })
        // Another user id on this server: unreadable, shared vaults refused, nothing written over it.
        var other = SharingMemoryRecord()
        other.userId = alice.id
        other.server = "https://fake.passauth.test"
        other.signed = ["x"]
        XCTAssertTrue(other.owned(by: bob.id, server: "https://fake.passauth.test").unreadable)
    }

    func testASignInClearsAnotherAccountsMemoryUnderTheSameRecord() async throws {
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        let memory = InMemorySharingMemory()
        var r = SharingMemoryRecord()
        r.userId = alice.id
        r.server = "https://fake.passauth.test"
        r.signed = ["x"]
        memory.put("acc", r)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item])], memory: memory)
        // Unlock (not a sign-in) keeps it: unreadable for Bob.
        XCTAssertTrue(repo.loadMemory("acc", try XCTUnwrap(repo.sessions["acc"])).unreadable)
        repo.finishSession("acc", account: bob.account, try JSON.parse(try text(["bundle": json(bob.created.bundleJson), "email": bob.email,
                                                                                 "access_token": "A", "refresh_token": "R"])))
        XCTAssertEqual(memory.load("acc").userId, "", "cleared by a sign-in with the master password")
    }

    func testDecliningAnInvitationForAHeldVaultTheServerLeftOutNeverTombstonesIt() async throws {
        // iOS L: the server omits Bob's vault from this sync and lists an invitation under its id;
        // on a fresh unlock (nothing shown yet) declining it must not give the vault up.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let s = try shared(owner: alice, member: bob)
        let own = try personal(bob)
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: true)
        pins = try pinsRecordRotation(pinsJson: pins, vaultId: s.id, keyKind: "sealed", currentJson: try s.key.epochPinJson(vaultId: s.id, keyEpoch: 0),
                                      rosterVersion: 1, rosterHash: try rosterHash(rosterJson: s.roster))
        let by: [String: Any] = ["id": alice.id, "email": alice.email, "name": "Alice", "public_key": alice.account.publicKey()]
        let dup: [String: Any] = ["vault_id": s.id, "role": "write", "wrapped_key": s.sealedForBob,
                                  "meta": try s.key.encryptMeta(vaultId: s.id, metaJson: #"{"name":"Family"}"#), "invited_by": by,
                                  "key_epoch": 0, "share": NSNull(), "member_roster": NSNull(), "member_roster_seq": 0]
        let memory = try memory(bob, pins: pins, rosters: [s.id: s.roster])
        var r = memory.load("acc")
        r.proven = true
        memory.put("acc", r)
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], invitations: [dup], pinsSeq: 1)], memory: memory)
        let shown = try shownInvitation(repo, s.id)
        XCTAssertTrue(shown.canDecline, "an unsigned invitation can only be declined")
        try await repo.declineInvitation(s.id)
        XCTAssertEqual(requests("DELETE", "/api/vaults/\(s.id)/invitation").count, 1)
        for write in requests("PUT", "/api/account/key-pins") {
            let p = try JSON.parse(try bob.account.openKeyPins(sealed: write.body["key_pins"] as? String ?? "", seq: UInt64(write.body["seq"] as? Int ?? 0)))
            XCTAssertNil(p["left"]?[s.id], "a held vault is never tombstoned")
            XCTAssertNotNil(p["epochs"]?[s.id])
        }
        XCTAssertTrue((memory.load("acc").tombstones ?? [:]).isEmpty)
    }

    func testANewerServerCopyDifferingOnlyInPeopleIsntWrittenBack() async throws {
        // Web M1: with nothing unsent, a newer server copy wins for a person pinned with another
        // identity (`pins_merge_last_known`): no write-back, no loop between two devices.
        let bob = try person("bob@example.com")
        let alice = try person("alice@example.com")
        let own = try personal(bob)
        var base = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        base = try pinsGrandfather(pinsJson: base, vaultsJson: "[]", createdIdentity: true)
        let mine = try pinSet(pinsJson: base, identityJson: try alice.account.legacyIdentityJson(), email: alice.email, verified: true, now: 1)
        let theirs = try pinSet(pinsJson: base, identityJson: alice.pub, email: alice.email, verified: false, now: 2)
        let memory = try memory(bob, pins: mine)
        ScriptedServer.answer("GET /api/account/key-pins", 200, try text(["key_pins": try bob.account.sealKeyPins(pinsJson: theirs, seq: 2), "seq": 2]))
        _ = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], pinsSeq: 2)], memory: memory)
        // Whatever this sync writes (its own vault's pin), Alice stays as the server copy has her:
        // the device's stale, verified legacy pin never overwrites the newer decision.
        let alicePin = try XCTUnwrap(try writtenPins(bob)["pins"]?.array.first { $0.str("user_id") == alice.id })
        XCTAssertEqual(alicePin.str("identity"), alice.signing.identityHash())
        XCTAssertEqual(alicePin["verified"]?.bool, false)
        // The merge itself adds nothing to the server copy for people (no write-back loop).
        XCTAssertTrue(VaultRepository.samePins(try pinsMergeLastKnown(serverJson: theirs, lastKnownJson: mine), theirs))
    }

    func testANewerServerCopyWithAnotherOwnIdentityPausesAndMergesNothing() async throws {
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        var base = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        base = try pinsGrandfather(pinsJson: base, vaultsJson: "[]", createdIdentity: true)
        let fake = try person("fake@example.com")
        var theirs = try pinsSetOwnIdentity(pinsJson: nil, hash: fake.signing.identityHash())
        theirs = try pinsGrandfather(pinsJson: theirs, vaultsJson: "[]", createdIdentity: true)
        let memory = try memory(bob, pins: base)
        let before = memory.load("acc")
        ScriptedServer.answer("GET /api/account/key-pins", 200, try text(["key_pins": try bob.account.sealKeyPins(pinsJson: theirs, seq: 2), "seq": 2]))
        let repo = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], pinsSeq: 2)], memory: memory)
        XCTAssertTrue(requests("PUT", "/api/account/key-pins").isEmpty, "nothing written")
        let kept = memory.load("acc")
        XCTAssertGreaterThanOrEqual(kept.pinsSeq, before.pinsSeq)
        let opened = try JSON.parse(try bob.account.openKeyPins(sealed: try XCTUnwrap(kept.sealedPins), seq: UInt64(kept.pinsSeq)))
        XCTAssertEqual(opened["own_identity"]?.string, bob.signing.identityHash(), "the device's copy stays, nothing merged")
        XCTAssertEqual(repo.sharingNotice, SharingText.paused)
    }

    func testVaultsWaitingForConsentStayListedWhenASyncDoesntShowThem() async throws {
        // Info: `missing` shrinks only for vaults settled (accepted, used, tombstoned).
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        let waiting = try newId()
        var pins = try pinsSetOwnIdentity(pinsJson: nil, hash: bob.signing.identityHash())
        pins = try pinsGrandfather(pinsJson: pins, vaultsJson: "[]", createdIdentity: false)
        let memory = try memory(bob, pins: pins)
        var r = memory.load("acc")
        r.missing = [waiting]
        r.proven = true
        memory.put("acc", r)
        _ = try await repo(bob, [try syncBody(bob, vaults: [own.row], items: [own.item], pinsSeq: 1)], memory: memory)
        XCTAssertEqual(memory.load("acc").missing, [waiting])
    }

    func testAnIdentityUploadAnswered404DoesntProveTheServerSigns() async throws {
        // Info: `proven` only after an answer other than 404.
        let bob = try person("bob@example.com")
        let own = try personal(bob)
        ScriptedServer.answer("PUT /api/account/identity", 404, #"{"error":"not_found","message":"x"}"#)
        let memory = InMemorySharingMemory()
        _ = try await repo(bob, [try syncBody(bob, identity: false, vaults: [own.row], items: [own.item])], memory: memory)
        XCTAssertEqual(requests("PUT", "/api/account/identity").count, 1)
        XCTAssertFalse(memory.load("acc").proven)
    }

}
