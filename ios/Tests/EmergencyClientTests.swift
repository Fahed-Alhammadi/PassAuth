import PassAuthKit
import XCTest

/// The emergency client's roster flows against a fake server and a fake account (the core's
/// sealing is stood in for): every case of the web vault's `emergency-client.test.ts`.
@MainActor
final class EmergencyClientTests: XCTestCase {
    // MARK: Fakes

    private final class FakeKey: EmergencyKeyHandle {
        let grant: String
        let n: Int
        init(_ grant: String, _ n: Int) {
            self.grant = grant
            self.n = n
        }
        func sealFor(contactPublicKey: String, grantorId: String, grantId: String) throws -> String { "sealed:\(grant):\(n)" }
        func wrapVault(_ vaultId: String) throws -> String { "wrap:\(grant):\(n):\(vaultId)" }
    }

    private final class FakeAccount: EmergencyAccountKeys {
        var made = 0
        func newEmergencyKey(grantId: String) throws -> (key: EmergencyKeyHandle, wrapped: String) {
            made += 1
            return (FakeKey(grantId, made), "gk:\(grantId):\(made)")
        }
        func openEmergencyKey(grantId: String, wrapped: String) throws -> EmergencyKeyHandle {
            let parts = wrapped.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "gk", String(parts[1]) == grantId, let n = Int(parts[2]) else { throw UserError("decrypt_failed") }
            return FakeKey(grantId, n)
        }
        func sealRoster(_ json: String) throws -> String { "R:" + Data(json.utf8).base64EncodedString() }
        func openRoster(_ sealed: String) throws -> String {
            guard sealed.hasPrefix("R:"), let d = Data(base64Encoded: String(sealed.dropFirst(2))) else { throw UserError("decrypt_failed") }
            return String(decoding: d, as: UTF8.self)
        }
    }

    private final class Memory: RosterMemory {
        var store: [String: (Int64, String?)] = [:]
        func load(_ userId: String) -> (version: Int64, sealed: String?) { store[userId].map { ($0.0, $0.1) } ?? (0, nil) }
        func save(_ userId: String, version: Int64, sealed: String?) { store[userId] = (version, sealed) }
    }

    private final class Server {
        var grants: [[String: JSON]] = []
        var roster: String?
        var rosterSeq: Int64 = 0
        var fills: [String] = []
        var confirms = 0
        var confirmHook: ((String) throws -> Void)?

        func index(_ id: String) throws -> Int {
            guard let i = grants.firstIndex(where: { $0["id"]?.string == id }) else { throw ApiError(status: 404, code: "not_found", message: "not found") }
            return i
        }

        func handle(_ path: String, _ body: JSON?, _ method: String?) throws -> JSON {
            let m = method ?? (body == nil ? "GET" : "POST")
            if m == "GET" && path == "/emergency-access" {
                return ["as_grantor": .array(grants.map(JSON.object)), "as_grantee": [], "roster": roster.map(JSON.string) ?? .null, "roster_seq": .int(rosterSeq)]
            }
            if m == "PUT" && path == "/emergency-access/roster" {
                guard body?["seq"] == .int(rosterSeq + 1) else { throw ApiError(status: 409, code: "roster_changed", message: "changed") }
                roster = body?["roster"]?.string
                rosterSeq += 1
                return ["roster_seq": .int(rosterSeq)]
            }
            let parts = path.split(separator: "/").map(String.init)
            if parts.count == 3, parts[0] == "emergency-access", parts[2] == "confirm" {
                confirms += 1
                let id = parts[1]
                try confirmHook?(id)
                let i = try index(id)
                grants[i]["status"] = "confirmed"
                grants[i]["grantor_key"] = body?["grantor_key"] ?? .null
                grants[i]["missing_vaults"] = []
                return .object(grants[i])
            }
            if parts.count == 3, parts[0] == "emergency-access", parts[2] == "vault-keys" {
                let i = try index(parts[1])
                fills.append(parts[1])
                grants[i]["missing_vaults"] = []
                return .object(grants[i])
            }
            if path == "/vaults/v1/members" {
                return ["members": [["user_id": "me", "email": "me@example.com", "name": "Me", "role": "owner", "public_key": "pk-me"]]]
            }
            throw ApiError(status: 404, code: "not_found", message: "no fake for \(m) \(path)")
        }
    }

    private var server = Server()
    private var account = FakeAccount()
    private var memory = Memory()
    private var client: EmergencyClient!

    override func setUp() async throws {
        server = Server()
        account = FakeAccount()
        memory = Memory()
        let server = self.server
        let account = self.account
        client = EmergencyClient(EmergencyEnvironment(
            api: { path, body, method, _ in try server.handle(path, body, method) },
            keys: { account },
            me: { "me" },
            vaults: { [(vault: Emergency.OwnVault(id: "v1", role: .owner, keyKind: "account"), epoch: Int64(0))] },
            features: { [emergencyAccessFeature, emergencyVaultKeysFeature] },
            reauth: { password, _ in
                if password != "right" { throw UserError("That master password is wrong.") }
                return "reauth-token"
            },
            rotate: { _ in KeyReplacement() },
            sync: {},
            memory: memory,
            notice: { _ in }
        ))
    }

    private func grantJson(_ id: String, _ extra: [String: JSON] = [:]) -> [String: JSON] {
        var g: [String: JSON] = [
            "id": .string(id), "status": "approved", "wait_days": 7, "created_at": 1, "updated_at": 1,
            "requested_at": nil, "approved_at": nil, "auto_approve_at": nil,
            "grantor": ["id": "me", "email": "me@example.com", "name": "Me", "public_key": "pk-me"],
            "grantee": ["id": .string("u-\(id)"), "email": .string("\(id)@example.com"), "name": .string("Name \(id)"), "public_key": .string("pk-\(id)")],
            "key_version": 2, "grantor_key": .string("gk:\(id):100"), "reconfirm": false, "v1_exposed": false, "missing_vaults": ["v1"],
        ]
        for (k, v) in extra { g[k] = v }
        return g
    }

    private func grant(_ id: String, _ extra: [String: JSON] = [:]) -> Grant { Emergency.readGrant(.object(grantJson(id, extra)))! }

    private func sealRoster(_ version: Int64, _ accesses: [RosterEntry], removed: [RemovedEntry] = []) -> String {
        try! account.sealRoster(Emergency.rosterJson(Roster(version: version, accesses: accesses, removed: removed)))
    }

    private func serverRoster() -> Roster { Emergency.readRoster(try! account.openRoster(server.roster!))! }

    private func entry(_ id: String, _ name: String? = nil, grantorKey: String? = nil) -> RosterEntry {
        RosterEntry(id: id, contactKey: "pk-\(id)", grantorKeyHash: Emergency.sha256b64(grantorKey ?? "gk:\(id):100"),
                    email: name.map { _ in "\(id)@example.com" }, name: name)
    }

    private func assertThrows(_ text: String, file: StaticString = #filePath, line: UInt = #line, _ body: () async throws -> Void) async {
        do {
            try await body()
            XCTFail("expected an error containing \(text)", file: file, line: line)
        } catch {
            XCTAssertTrue(errorMessage(error).contains(text), "\(errorMessage(error))", file: file, line: line)
        }
    }

    // MARK: The roster, between the app and the server

    func testDropsAnAccessTheContactEndedForGood() async throws {
        server.grants = [grantJson("g1")]
        server.roster = sealRoster(1, [entry("g1", "Name g1")])
        server.rosterSeq = 1
        try await client.fill()
        XCTAssertEqual(server.fills, ["g1"])
        server.grants = []
        server.fills = []
        try await client.fill()
        XCTAssertEqual(serverRoster(), Roster(version: 2, accesses: [], removed: [RemovedEntry(id: "g1", grantorKeyHash: Emergency.sha256b64("gk:g1:100"))]))
        server.grants = [grantJson("g1")]
        try await client.fill()
        XCTAssertEqual(server.fills, [])
        let state = try await client.rosterState()
        XCTAssertEqual([state.removed.contains("g1"), state.confirmAgain.contains("g1")], [true, false])
        await assertThrows("was removed from your emergency contacts") { try await self.client.confirmAgain(self.grant("g1")) }
    }

    func testKeepsAContactTheGrantorRemovedOutEvenWhenTheServerListsThemAgain() async throws {
        server.grants = [grantJson("g1"), grantJson("g2")]
        server.roster = sealRoster(1, [entry("g1", "Name g1"), entry("g2", "Name g2")])
        server.rosterSeq = 1
        _ = try await client.removeContact(grant("g1"))
        XCTAssertEqual(serverRoster().removed, [RemovedEntry(id: "g1", grantorKeyHash: Emergency.sha256b64("gk:g1:100"))])
        XCTAssertEqual(serverRoster().accesses.map(\.id), ["g2"])
        server.grants = [grantJson("g1"), grantJson("g2", ["missing_vaults": []])]
        try await client.fill()
        XCTAssertEqual(server.fills, [])
        let removed = try await client.rosterState().removed
        XCTAssertTrue(removed.contains("g1"))
        await assertThrows("add them as a new contact") { try await self.client.confirmAgain(self.grant("g1")) }
        server.grants = [grantJson("g1", ["status": "accepted", "grantor_key": nil]), grantJson("g2", ["missing_vaults": []])]
        await assertThrows("add them as a new contact") { try await self.client.confirmContact(self.grant("g1", ["status": "accepted", "grantor_key": nil])) }
        XCTAssertEqual(server.confirms, 0)
    }

    func testPutsAnAccessBackWithConfirmAgainAndRefusesAKeyThisAccountDidntMake() async throws {
        server.grants = [grantJson("g1")]
        server.roster = sealRoster(2, [])
        server.rosterSeq = 2
        let g = grant("g1")
        let needs = try await client.rosterState().confirmAgain
        XCTAssertTrue(needs.contains("g1"))
        try await client.confirmAgain(g)
        XCTAssertEqual(serverRoster(), Roster(version: 3, accesses: [entry("g1", "Name g1")], removed: []))
        try await client.fill()
        XCTAssertEqual(server.fills, ["g1"])
        server.grants = [grantJson("g1", ["missing_vaults": []]),
                         grantJson("g2", ["grantee": ["id": "u-g2", "email": "g2@example.com", "name": "Name g2", "public_key": "pk-new"]])]
        await assertThrows("key changed") { try await self.client.confirmAgain(self.grant("g2")) }
        server.grants = [grantJson("g1", ["missing_vaults": []]), grantJson("g2", ["grantor_key": "gk:someone-else:1"])]
        await assertThrows("wasn't made by your account") { try await self.client.confirmAgain(self.grant("g2")) }
        XCTAssertEqual(serverRoster().accesses.map(\.id), ["g1"])
    }

    func testPointsTheRosterAtTheKeyAnAccessAlreadyHoldsWhenTheConfirmAnswerGotLost() async throws {
        let accepted = grantJson("g1", ["status": "accepted", "grantor_key": nil])
        server.grants = [accepted]
        let server = self.server
        server.confirmHook = { id in
            let i = try server.index(id)
            server.grants[i]["status"] = "confirmed"
            server.grants[i]["grantor_key"] = "gk:g1:99"
            server.grants[i]["missing_vaults"] = []
            throw ApiError(status: 409, code: "conflict", message: "this emergency contact is confirmed already")
        }
        try await client.confirmContact(Emergency.readGrant(.object(accepted))!)
        XCTAssertEqual(serverRoster().accesses, [entry("g1", "Name g1", grantorKey: "gk:g1:99")])
        server.confirmHook = nil
        let confirms = server.confirms
        try await client.confirmContact(Emergency.readGrant(.object(accepted))!)
        XCTAssertEqual(server.confirms, confirms)
        XCTAssertEqual(serverRoster().accesses, [entry("g1", "Name g1", grantorKey: "gk:g1:99")])
    }

    func testReviewsAnOlderServerListAgainstThisDevicesOwnAndWritesItForward() async throws {
        server.grants = [grantJson("g1"), grantJson("g2")]
        server.roster = sealRoster(5, [entry("g1", "Sam")])
        server.rosterSeq = 5
        var problem = try await client.rosterState().problem
        XCTAssertNil(problem)
        server.grants = [grantJson("g1"), grantJson("g2", ["grantee": ["id": "u-g2", "email": "mom@example.com", "name": "Mom", "public_key": "pk-g2"]])]
        server.roster = sealRoster(3, [entry("g1", "Sam"), entry("g2", "Eve"), entry("g4", "Ann")])
        server.rosterSeq = 3
        problem = try await client.rosterState().problem
        XCTAssertEqual(problem, .older)
        let list = try await client.loadServerRoster()
        XCTAssertEqual(list.entries.map(\.entry.id), ["g1", "g2"])
        XCTAssertEqual(list.entries.map(\.entry.name), ["Sam", "Eve"])
        XCTAssertEqual(list.entries.map(\.entry.email), ["g1@example.com", "g2@example.com"])
        XCTAssertEqual(list.entries.map(\.wouldReturn), [false, true])
        await assertThrows("master password") { try await self.client.useServerRoster(list, password: "wrong") }
        XCTAssertEqual(server.rosterSeq, 3)
        try await client.useServerRoster(list, password: "right")
        XCTAssertEqual(serverRoster().version, 6)
        XCTAssertEqual(serverRoster().accesses, [entry("g1", "Sam"), entry("g2", "Eve")])
        XCTAssertEqual(serverRoster().removed.map(\.id), ["g4"])
        problem = try await client.rosterState().problem
        XCTAssertNil(problem)
        server.roster = sealRoster(5, [entry("g1", "Sam")])
        problem = try await client.rosterState().problem
        XCTAssertEqual(problem, .older)
    }

    func testNeverWritesAContactTheUserWasntShown() async throws {
        server.grants = [grantJson("g1")]
        server.roster = sealRoster(5, [entry("g1", "Sam")])
        server.rosterSeq = 5
        _ = try await client.rosterState()
        server.roster = sealRoster(3, [entry("g1", "Sam"), entry("gc", "Carol")])
        server.rosterSeq = 3
        let list = try await client.loadServerRoster()
        XCTAssertEqual(list.entries.map(\.entry.id), ["g1"])
        server.grants = [grantJson("g1"), grantJson("gc")]
        try await client.useServerRoster(list, password: "right")
        XCTAssertEqual(serverRoster().accesses.map(\.id), ["g1"])
        XCTAssertEqual(serverRoster().removed.map(\.id), ["gc"])
        try await client.fill()
        XCTAssertFalse(server.fills.contains("gc"))
        let removed = try await client.rosterState().removed
        XCTAssertTrue(removed.contains("gc"))
    }

    func testStartsANewListWhenTheServersDoesntOpenKeepingWhoWasRemoved() async throws {
        server.grants = [grantJson("g1"), grantJson("g0")]
        server.roster = sealRoster(4, [entry("g1", "Name g1")], removed: [RemovedEntry(id: "g0", grantorKeyHash: "h-g0")])
        server.rosterSeq = 4
        var problem = try await client.rosterState().problem
        XCTAssertNil(problem)
        server.roster = "garbage written by someone else"
        server.rosterSeq = 5
        problem = try await client.rosterState().problem
        XCTAssertEqual(problem, .unreadable)
        try await client.fill()
        XCTAssertEqual(server.fills, [])
        await assertThrows("master password") { try await self.client.startNewRoster(password: "wrong") }
        try await client.startNewRoster(password: "right")
        XCTAssertEqual(serverRoster(), Roster(version: 5, accesses: [], removed: [RemovedEntry(id: "g0", grantorKeyHash: "h-g0")]))
        let state = try await client.rosterState()
        XCTAssertNil(state.problem)
        XCTAssertEqual([state.confirmAgain.contains("g1"), state.removed.contains("g0"), state.confirmAgain.contains("g0")], [true, true, false])
    }

    // MARK: Beyond the web's cases

    func testConfirmingWrapsOnlyPersonalVaultsAndSendsTheirKeyEpoch() async throws {
        var bodies: [JSON] = []
        let server = self.server
        server.grants = [grantJson("g1", ["status": "accepted", "grantor_key": nil, "missing_vaults": ["v1"]])]
        let account = self.account
        let spy = EmergencyClient(EmergencyEnvironment(
            api: { path, body, method, _ in
                if path.hasSuffix("/confirm"), let body { bodies.append(body) }
                return try server.handle(path, body, method)
            },
            keys: { account }, me: { "me" },
            vaults: { [(vault: Emergency.OwnVault(id: "v1", role: .owner, keyKind: "account"), epoch: Int64(4))] },
            features: { [emergencyAccessFeature, emergencyVaultKeysFeature] },
            reauth: { _, _ in "t" }, rotate: { _ in KeyReplacement() }, sync: {}, memory: memory, notice: { _ in }
        ))
        try await spy.confirmContact(grant("g1", ["status": "accepted", "grantor_key": nil]))
        XCTAssertEqual(bodies.count, 1)
        XCTAssertEqual(bodies[0]["sealed_key"], "sealed:g1:1")
        XCTAssertEqual(bodies[0]["grantor_key"], "gk:g1:1")
        XCTAssertEqual(bodies[0]["vault_keys"], [["vault_id": "v1", "wrapped_key": "wrap:g1:1:v1", "key_epoch": 4]])
        // A vault the server lists that this app sees as shared stops the confirmation.
        server.grants = [grantJson("g2", ["status": "accepted", "grantor_key": nil, "missing_vaults": ["v1", "v9"]])]
        await assertThrows("nothing was confirmed") { try await spy.confirmContact(self.grant("g2", ["status": "accepted", "grantor_key": nil])) }
    }

    private final class Box<T> {
        var value: T
        init(_ value: T) { self.value = value }
    }

    /// A fill asked for just as the running one finishes starts a run of its own (it doesn't
    /// join the run that has ended and miss its work).
    func testAFillAskedForAsTheLastOneEndsStillRuns() async throws {
        let runs = Box(0)
        let late = Box<Task<Void, Never>?>(nil)
        let box = Box<EmergencyClient?>(nil)
        let c = EmergencyClient(EmergencyEnvironment(
            api: { _, _, _, _ in [:] }, keys: { nil }, me: { "me" }, vaults: { [] },
            features: {
                runs.value += 1
                // The second call arrives while the first run is on its last step.
                if runs.value == 1 { late.value = Task { @MainActor in try? await box.value?.fill() } }
                return nil
            },
            reauth: { _, _ in "t" }, rotate: { _ in KeyReplacement() }, sync: {}, memory: memory, notice: { _ in }
        ))
        box.value = c
        try await c.fill()
        await late.value?.value
        XCTAssertEqual(runs.value, 2)
    }

    /// An operation keeps to the account it started on: once another account is active, its
    /// next step is refused instead of being sent for that account.
    func testAnAccountSwitchMidwayStopsTheOperation() async throws {
        server.grants = [grantJson("g1")]
        server.roster = sealRoster(1, [entry("g1", "Name g1")])
        server.rosterSeq = 1
        memory.store["me"] = (1, server.roster)
        let server = self.server
        let account = self.account
        let active = Box("acc-1")
        var sent: [String] = []
        let c = EmergencyClient(EmergencyEnvironment(
            api: { path, body, method, _ in
                sent.append("\(method ?? (body == nil ? "GET" : "POST")) \(path)")
                // Another account becomes active while the first step's answer is on its way.
                if path == "/emergency-access" { active.value = "acc-2" }
                return try server.handle(path, body, method)
            },
            keys: { account }, me: { "me" }, vaults: { [] },
            features: { [emergencyAccessFeature, emergencyVaultKeysFeature] },
            reauth: { _, _ in "t" }, rotate: { _ in KeyReplacement() }, sync: {}, memory: memory, notice: { _ in },
            account: { active.value }
        ))
        await assertThrows("Another account became active") { _ = try await c.removeContact(self.grant("g1")) }
        XCTAssertEqual(sent, ["GET /emergency-access"])
        XCTAssertEqual(server.rosterSeq, 1)
        // Started on the account now active, it goes through.
        let done = try await c.removeContact(grant("g1"))
        XCTAssertEqual(done, Removal(rotated: 0, failed: nil))
        XCTAssertEqual(server.rosterSeq, 2)
    }

    /// Removing a contact reports only the vaults whose keys were really replaced, and the shared
    /// ones left for the web vault or the desktop app.
    func testRemovalReportsWhatTheKeyReplacementDid() async throws {
        server.grants = [grantJson("g1")]
        server.roster = sealRoster(1, [entry("g1", "Name g1")])
        server.rosterSeq = 1
        memory.store["me"] = (1, server.roster)
        let server = self.server
        let account = self.account
        let c = EmergencyClient(EmergencyEnvironment(
            api: { path, body, method, _ in
                if method == "DELETE" && path == "/emergency-access/g1" { return ["rotation_pending": ["v1"]] }
                return try server.handle(path, body, method)
            },
            keys: { account }, me: { "me" },
            vaults: { [(vault: Emergency.OwnVault(id: "v1", role: .owner, keyKind: "account"), epoch: Int64(0))] },
            features: { [emergencyAccessFeature, emergencyVaultKeysFeature] },
            reauth: { _, _ in "t" },
            rotate: { ids in KeyReplacement(rotated: [], shared: ids.map { KeyReplacement.Shared(id: $0, name: "Family") }) },
            sync: {}, memory: memory, notice: { _ in }
        ))
        let done = try await c.removeContact(grant("g1"))
        XCTAssertEqual(done.rotated, 0)
        XCTAssertEqual(done.shared, "Family is shared, so replace its key in the web vault or the desktop app.")
    }

    func testOlderServersCantConfirmOrOpenVaults() async throws {
        let server = self.server
        let account = self.account
        let old = EmergencyClient(EmergencyEnvironment(
            api: { path, body, method, _ in try server.handle(path, body, method) },
            keys: { account }, me: { "me" }, vaults: { [] }, features: { [emergencyAccessFeature] },
            reauth: { _, _ in "t" }, rotate: { _ in KeyReplacement() }, sync: {}, memory: memory, notice: { _ in }
        ))
        await assertThrows("needs an update") { try await old.confirmContact(self.grant("g1", ["status": "accepted"])) }
        await assertThrows("needs an update") { _ = try await old.grantorVaultData("g1") }
    }
}
