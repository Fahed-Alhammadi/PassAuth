import PassAuthKit
import XCTest

/// Emergency access rules: every case of the web vault's `web/src/lib/emergency.test.ts`, with the
/// same inputs and expected results.
final class EmergencyTests: XCTestCase {
    private func raw(_ status: String, _ extra: [String: JSON] = [:]) -> JSON {
        var o: [String: JSON] = [
            "id": .string("grant-\(status)"), "status": .string(status), "wait_days": 7, "created_at": 100, "updated_at": 200,
            "requested_at": nil, "approved_at": nil, "auto_approve_at": nil,
            "grantor": ["id": "user-sam", "email": "sam@example.com", "name": "Sam Lee", "public_key": "pk-sam"],
            "grantee": ["id": "user-alex", "email": "alex@example.com", "name": "", "public_key": "pk-alex"],
        ]
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    private func grant(_ status: GrantStatus, _ extra: [String: JSON] = [:]) -> Grant {
        Emergency.readGrant(raw(status.rawValue, extra))!
    }

    private let when: (Int64) -> String = { "t\($0)" }

    // MARK: reading

    func testReadsBothLists() {
        let lists = Emergency.readGrants(["as_grantor": [raw("invited"), ["id": "x"]], "as_grantee": [raw("approved", ["approved_at": 300])]])
        XCTAssertEqual(lists.asGrantor.count, 1)
        let g = lists.asGrantor[0]
        XCTAssertEqual(g.id, "grant-invited")
        XCTAssertEqual(g.status, .invited)
        XCTAssertEqual(g.waitDays, 7)
        XCTAssertEqual(g.grantee.email, "alex@example.com")
        XCTAssertEqual(g.grantee.publicKey, "pk-alex")
        XCTAssertEqual(lists.asGrantee[0].status, .approved)
        XCTAssertEqual(lists.asGrantee[0].approvedAt, 300)
        XCTAssertEqual(Emergency.readGrants(nil), GrantLists(asGrantor: [], asGrantee: [], roster: nil, rosterSeq: nil))
    }

    func testCraftedNumbersDontCrash() throws {
        // Out-of-range waits and times are read without trapping; a wait is kept within 0…36500 days.
        let g = try XCTUnwrap(Emergency.readGrant(raw("approved", ["created_at": .double(-1e300), "auto_approve_at": .double(9.9e18),
                                                                    "key_version": .double(1e300)])))
        XCTAssertEqual(g.createdAt, 0)
        XCTAssertNil(g.autoApproveAt)
        XCTAssertNil(g.keyVersion)
        // A wait that isn't a usable number makes the entry malformed.
        XCTAssertNil(Emergency.readGrant(raw("approved", ["wait_days": .double(1e300)])))
        XCTAssertEqual(Emergency.readGrant(raw("approved", ["wait_days": .int(Int64.max)]))?.waitDays, 36_500)
        XCTAssertEqual(Emergency.readGrant(raw("approved", ["wait_days": .int(-5)]))?.waitDays, 0)
        // A compare-and-swap number the client adds 1 to: one it can't is treated as none.
        XCTAssertNil(Emergency.readGrants(try JSON.parse(#"{"as_grantor":[],"as_grantee":[],"roster_seq":1e300}"#)).rosterSeq)
        XCTAssertNil(Emergency.readGrants(try JSON.parse(#"{"as_grantor":[],"as_grantee":[],"roster_seq":9223372036854775807}"#)).rosterSeq)
        XCTAssertEqual(Emergency.readGrants(try JSON.parse(#"{"as_grantor":[],"as_grantee":[],"roster_seq":4}"#)).rosterSeq, 4)
    }

    func testLeavesOutUnknownStatusesAndEntriesWithoutPeople() {
        XCTAssertNil(Emergency.readGrant(raw("paused")))
        XCTAssertNil(Emergency.readGrant(raw("invited", ["grantor": nil])))
        XCTAssertNil(Emergency.readGrant(raw("invited", ["wait_days": "7"])))
    }

    func testNamesPeopleByNameElseEmail() {
        let g = grant(.invited)
        XCTAssertEqual(Emergency.personName(g.grantor), "Sam Lee")
        XCTAssertEqual(Emergency.personName(g.grantee), "alex@example.com")
        XCTAssertEqual(Emergency.personName(GrantPerson(id: "x", email: "", name: " ", publicKey: "")), "Someone")
    }

    // MARK: waiting period

    func testAcceptsWholeDaysFrom1To90() {
        XCTAssertTrue(Emergency.validWait(1))
        XCTAssertTrue(Emergency.validWait(90))
        XCTAssertFalse(Emergency.validWait(0))
        XCTAssertFalse(Emergency.validWait(91))
        XCTAssertFalse(Emergency.validWait(2.5))
        XCTAssertEqual(Emergency.daysText(1), "1 day")
        XCTAssertEqual(Emergency.daysText(30), "30 days")
    }

    // MARK: status in words

    func testTellsTheGrantorWhatEachStepMeans() {
        XCTAssertEqual(Emergency.grantorStatus(grant(.invited), when: when).text, "Waiting for alex@example.com to accept.")
        let accepted = Emergency.grantorStatus(grant(.accepted), when: when)
        XCTAssertEqual(accepted.label, "Confirm")
        XCTAssertEqual(accepted.tone, .warn)
        XCTAssertTrue(accepted.text.contains("Check their fingerprint"))
        XCTAssertTrue(Emergency.grantorStatus(grant(.confirmed), when: when).text.contains("You'd have 7 days to say no"))
        XCTAssertEqual(Emergency.grantorStatus(grant(.requested, ["requested_at": 1000, "auto_approve_at": 5000]), when: when).text,
                       "alex@example.com asked for access on t1000. Unless you reject it, they can view your personal vaults from t5000.")
        XCTAssertTrue(Emergency.grantorStatus(grant(.requested), when: when).text.contains("after 7 days"))
        let approved = Emergency.grantorStatus(grant(.approved, ["approved_at": 9]), when: when)
        XCTAssertEqual(approved.label, "Has access")
        XCTAssertEqual(approved.text, "alex@example.com can view your personal vaults since t9.")
        let again = Emergency.grantorStatus(grant(.accepted, ["reconfirm": true]), when: when)
        XCTAssertEqual(again.label, "Confirm again")
        XCTAssertEqual(again.text, "PassAuth now gives emergency contacts a key to your personal vaults only. Confirm alex@example.com again to give them access.")
        XCTAssertEqual(again.tone, .warn)
        XCTAssertTrue(Emergency.grantorActions(grant(.accepted, ["reconfirm": true])).contains(.confirm))
        XCTAssertTrue(Emergency.grantorStatus(grant(.rejected), when: when).text.contains("They can ask again"))
    }

    func testTellsTheContactWhatEachStepMeans() {
        XCTAssertTrue(Emergency.granteeStatus(grant(.invited), when: when).text.contains("Sam Lee named you as their emergency contact"))
        XCTAssertEqual(Emergency.granteeStatus(grant(.accepted), when: when).text, "Waiting for Sam Lee to confirm you.")
        XCTAssertTrue(Emergency.granteeStatus(grant(.confirmed), when: when).text.contains("Sam Lee is told at once and has 7 days to say no"))
        XCTAssertTrue(Emergency.granteeStatus(grant(.requested, ["auto_approve_at": 5000]), when: when).text.contains("you can view their vaults from t5000"))
        let approved = Emergency.granteeStatus(grant(.approved), when: when)
        XCTAssertEqual(approved.label, "Access granted")
        XCTAssertEqual(approved.tone, .ok)
        XCTAssertTrue(Emergency.granteeStatus(grant(.rejected), when: when).text.contains("You can ask again"))
    }

    // MARK: actions

    func testOffersTheGrantorWhatEachStepAllows() {
        XCTAssertEqual(Emergency.grantorActions(grant(.invited)), [.wait, .remove])
        XCTAssertEqual(Emergency.grantorActions(grant(.accepted)), [.confirm, .wait, .remove])
        XCTAssertEqual(Emergency.grantorActions(grant(.confirmed)), [.wait, .remove])
        XCTAssertEqual(Emergency.grantorActions(grant(.requested)), [.approve, .reject, .wait, .remove])
        XCTAssertEqual(Emergency.grantorActions(grant(.approved)), [.end, .wait, .remove])
        XCTAssertEqual(Emergency.grantorActions(grant(.rejected)), [.wait, .remove])
    }

    func testOffersTheContactWhatEachStepAllows() {
        XCTAssertEqual(Emergency.granteeActions(grant(.invited)), [.accept, .decline])
        XCTAssertEqual(Emergency.granteeActions(grant(.accepted)), [.remove])
        XCTAssertEqual(Emergency.granteeActions(grant(.confirmed)), [.request, .remove])
        XCTAssertEqual(Emergency.granteeActions(grant(.requested)), [.remove])
        XCTAssertEqual(Emergency.granteeActions(grant(.approved)), [.view, .remove])
        XCTAssertEqual(Emergency.granteeActions(grant(.rejected)), [.request, .remove])
    }

    func testCountsWhatWaitsForAnAnswer() {
        XCTAssertEqual(Emergency.needsAnswer(asGrantor: [grant(.accepted), grant(.requested), grant(.approved)], asGrantee: [grant(.invited), grant(.confirmed)]), 3)
        XCTAssertEqual(Emergency.needsAnswer(asGrantor: [], asGrantee: []), 0)
    }

    // MARK: what is said about the keys

    func testSaysWhatConfirmingGivesBeforeItIsDone() {
        XCTAssertEqual(Emergency.confirmMeaning("Alex"),
                       "Confirming gives Alex a key to your personal vaults. Once they get access (or at once, if your server is ever compromised), they can read everything in those vaults. Shared vaults and Sends stay out of reach. If you remove them, PassAuth changes the keys of those vaults, so they can't read anything you add afterwards, unless your server is later compromised.")
        XCTAssertTrue(Emergency.reconfirmText("Alex").contains("Confirm Alex again"))
    }

    func testSaysWhenRemovingAContactChangesKeysAndDeletesEarlierVersions() {
        XCTAssertEqual(Emergency.removalText(grant(.invited)), "alex@example.com can't ask for access any more.")
        XCTAssertEqual(Emergency.removalText(grant(.accepted)), "alex@example.com can't ask for access any more.")
        let confirmed = Emergency.removalText(grant(.confirmed))
        XCTAssertTrue(confirmed.contains("PassAuth changes the keys of your personal vaults"))
        XCTAssertTrue(confirmed.contains("deletes the earlier versions"))
        XCTAssertFalse(confirmed.contains("keep what they saw"))
        for status in [GrantStatus.requested, .approved, .rejected] {
            XCTAssertTrue(Emergency.removalText(grant(status)).contains("changes the keys"))
            XCTAssertTrue(Emergency.removalText(grant(status)).contains("keep what they saw"))
        }
    }

    // MARK: which vaults get the contact's key

    private let own = Emergency.OwnVault(id: "v1", role: .owner, keyKind: "account")

    func testTakesOnlyVaultsThisAppSeesAsPersonal() {
        let me = "user-sam"
        let alone = [me]
        XCTAssertTrue(Emergency.isPersonal(own, members: alone, me: me))
        XCTAssertFalse(Emergency.isPersonal(own, members: alone + ["user-alex"], me: me))
        XCTAssertFalse(Emergency.isPersonal(own, members: ["user-alex"], me: me))
        XCTAssertFalse(Emergency.isPersonal(own, members: [], me: me))
        XCTAssertFalse(Emergency.isPersonal(own, members: nil, me: me))
        XCTAssertFalse(Emergency.isPersonal(nil, members: alone, me: me))
        XCTAssertFalse(Emergency.isPersonal(Emergency.OwnVault(id: "v1", role: .admin, keyKind: "account"), members: alone, me: me))
        XCTAssertFalse(Emergency.isPersonal(Emergency.OwnVault(id: "v1", role: .owner, keyKind: "sealed"), members: alone, me: me))
        XCTAssertFalse(Emergency.isPersonal(own, members: alone, me: ""))
    }

    func testNeverWrapsAVaultTheServerListsButThisAppSeesAsShared() {
        let personal: Set = ["v1", "v2"]
        let r = Emergency.vaultsToWrap(["v1", "v3", "v2", "v1"]) { personal.contains($0) }
        XCTAssertEqual(r.wrap, ["v1", "v2"])
        XCTAssertEqual(r.refused, ["v3"])
        let empty = Emergency.vaultsToWrap([]) { _ in true }
        XCTAssertEqual(empty.wrap, [])
        XCTAssertEqual(empty.refused, [])
    }

    func testAddsWrapsOnlyForAccessesThatHoldKeysHaveThisAccountsKeyAndMissVaults() {
        func fill(_ status: GrantStatus, _ extra: [String: JSON]) -> Grant {
            var e: [String: JSON] = ["grantor_key": "gk", "missing_vaults": ["v1"], "key_version": 2]
            for (k, v) in extra { e[k] = v }
            return grant(status, e)
        }
        let todo = [
            fill(.confirmed, [:]), fill(.requested, [:]), fill(.approved, [:]), fill(.rejected, [:]), fill(.accepted, [:]), fill(.invited, [:]),
            fill(.approved, ["grantor_key": nil]), fill(.approved, ["missing_vaults": []]), fill(.approved, ["key_version": 3]),
        ]
        XCTAssertEqual(Emergency.accessesToFill(todo).map(\.status), [.confirmed, .requested, .approved, .rejected])
        XCTAssertFalse(Emergency.hasKeys(grant(.accepted)))
    }

    func testReadsWhatTheGrantorsListingAdds() {
        let g = grant(.confirmed, ["key_version": 2, "grantor_key": "gk", "reconfirm": false, "missing_vaults": ["v2", 5, "v2", ""]])
        XCTAssertEqual(g.keyVersion, 2)
        XCTAssertEqual(g.grantorKey, "gk")
        XCTAssertFalse(g.reconfirm)
        XCTAssertEqual(g.missingVaults, ["v2"])
        let plain = grant(.confirmed)
        XCTAssertNil(plain.keyVersion)
        XCTAssertNil(plain.grantorKey)
        XCTAssertFalse(plain.reconfirm)
        XCTAssertEqual(plain.missingVaults, [])
        XCTAssertFalse(grant(.accepted, ["reconfirm": "yes"]).reconfirm)
    }

    func testReadsWhichVaultsNeedNewKeysAfterARemoval() {
        XCTAssertEqual(Emergency.vaultsToRotate(["ok": true, "rotation_pending": ["v1", "v2"]]), ["v1", "v2"])
        XCTAssertEqual(Emergency.vaultsToRotate(["ok": true]), [])
        XCTAssertEqual(Emergency.vaultsToRotate(["rotation_pending": "v1"]), [])
        XCTAssertEqual(Emergency.vaultsToRotate(nil), [])
    }

    // MARK: the grantor's vault

    func testMapsRowsToWhatTheCoreDecrypts() throws {
        let data = try XCTUnwrap(Emergency.readGrantorVault([
            "grant": raw("approved"),
            "key_version": 2,
            "sealed_key": "sealed",
            "vaults": [["id": "v1", "meta": "m", "wrapped_key": "w", "key_epoch": 2], ["id": "v2"]],
            "items": [
                ["id": "i1", "vault_id": "v1", "item_key": "ik", "data": "d", "revision": 3, "deleted_at": nil, "created_at": 1, "updated_at": 2],
                ["id": "i2", "vault_id": "v1", "item_key": "ik2", "data": "d2", "revision": 4, "deleted_at": 50, "created_at": 1, "updated_at": 3],
                ["id": "i3", "vault_id": "v1", "data": "no key"],
            ],
        ]))
        XCTAssertEqual(data.sealedKey, "sealed")
        XCTAssertEqual(data.keyVersion, 2)
        XCTAssertEqual(data.vaults, [.init(id: "v1", meta: "m", wrappedKey: "w")])
        XCTAssertEqual(data.items, [
            .init(id: "i1", vaultId: "v1", key: "ik", data: "d", deletedAt: nil, updatedAt: 2),
            .init(id: "i2", vaultId: "v1", key: "ik2", data: "d2", deletedAt: 50, updatedAt: 3),
        ])
    }

    func testRefusesAnAnswerWithoutTheSealedKey() {
        XCTAssertNil(Emergency.readGrantorVault(["vaults": [], "items": []]))
        XCTAssertNil(Emergency.readGrantorVault(nil))
    }

    func testTellsAnswersFromServersBeforeEmergencyKeys() {
        XCTAssertNil(Emergency.readGrantorVault(["sealed_key": "s", "vaults": [], "items": []])!.keyVersion)
    }

    // MARK: contacts confirmed before emergency keys

    func testReadsTheFlagAndSaysWhatRemovingCantUndo() {
        XCTAssertTrue(grant(.approved, ["v1_exposed": true]).v1Exposed)
        XCTAssertFalse(grant(.approved).v1Exposed)
        let warning = Emergency.v1Warning("Alex")
        XCTAssertEqual(warning, "Alex was confirmed with an earlier version of PassAuth, which gave them your account key. Removing them can't take that back. If you no longer trust them, change the passwords that matter or move to a new account.")
        XCTAssertTrue(Emergency.confirmMeaning("Alex", v1Exposed: true).contains(warning))
        XCTAssertFalse(Emergency.confirmMeaning("Alex", v1Exposed: true).contains("can't read anything you add afterwards"))
        let removal = Emergency.removalText(grant(.approved, ["v1_exposed": true]))
        XCTAssertTrue(removal.contains("changes the keys of your personal vaults"))
        XCTAssertTrue(removal.contains(Emergency.v1Warning("alex@example.com")))
        XCTAssertFalse(removal.contains("can't read anything you add afterwards"))
        XCTAssertTrue(Emergency.removalText(grant(.accepted, ["v1_exposed": true, "reconfirm": true])).contains("gave them your account key"))
    }

    // MARK: the roster

    private func entry(_ id: String, _ contactKey: String? = nil, _ grantorKeyHash: String? = nil) -> RosterEntry {
        RosterEntry(id: id, contactKey: contactKey ?? "pk-\(id)", grantorKeyHash: grantorKeyHash ?? "h-\(id)")
    }

    private func roster(_ version: Int64, _ accesses: [RosterEntry], _ removed: [RemovedEntry] = []) -> Roster {
        Roster(version: version, accesses: accesses, removed: removed)
    }

    func testReadsAndWritesItsJSONAndRefusesAnythingMalformed() throws {
        let r = roster(3, [entry("g1"), entry("g2")], [RemovedEntry(id: "g0", grantorKeyHash: "h-g0")])
        XCTAssertEqual(Emergency.readRoster(Emergency.rosterJson(r)), r)
        XCTAssertEqual(try JSON.parse(Emergency.rosterJson(r)), [
            "version": 3,
            "accesses": [
                ["id": "g1", "contact_key": "pk-g1", "grantor_key_hash": "h-g1"],
                ["id": "g2", "contact_key": "pk-g2", "grantor_key_hash": "h-g2"],
            ],
            "removed": [["id": "g0", "grantor_key_hash": "h-g0"]],
        ])
        XCTAssertEqual(Emergency.readRoster(#"{"version":1,"accesses":[]}"#), roster(1, []))
        for bad in [
            "", "nonsense", "null", "[]",
            #"{"version":-1,"accesses":[]}"#,
            #"{"version":1.5,"accesses":[]}"#,
            #"{"version":1}"#,
            #"{"version":1,"accesses":[{"id":"g1"}]}"#,
            #"{"version":1,"accesses":[],"removed":{}}"#,
            #"{"version":1,"accesses":[],"removed":[{"id":"g1"}]}"#,
        ] {
            XCTAssertNil(Emergency.readRoster(bad), bad)
        }
    }

    func testGoesUpAVersionWithEveryChangePastWhatThisDeviceHasSeen() throws {
        let added = try XCTUnwrap(Emergency.nextRoster(Emergency.emptyRoster, seen: 0, .add(entry("g1"))))
        XCTAssertEqual(added, roster(1, [entry("g1")]))
        let replaced = try XCTUnwrap(Emergency.nextRoster(added, seen: 0, .add(entry("g1", "pk-new", "h-new"))))
        XCTAssertEqual(replaced, roster(2, [entry("g1", "pk-new", "h-new")]))
        XCTAssertEqual(try Emergency.nextRoster(replaced, seen: 0, .remove("g1")), roster(3, [], [RemovedEntry(id: "g1", grantorKeyHash: "h-new")]))
        XCTAssertEqual(try Emergency.nextRoster(added, seen: 9, .add(entry("g2")))?.version, 10)
        XCTAssertNil(try Emergency.nextRoster(added, seen: 0, .remove("g9")))
        XCTAssertEqual(try Emergency.nextRoster(added, seen: 0, .remove("g9", hash: "h-g9")), roster(2, [entry("g1")], [RemovedEntry(id: "g9", grantorKeyHash: "h-g9")]))
        XCTAssertNil(try Emergency.nextRoster(added, seen: 0, nil, listed: ["g1"]))
    }

    func testKeepsTheNameAndEmailTheGrantorConfirmedAndReadsEntriesFromBeforeWithoutThem() {
        let g = grant(.approved, ["id": "g1", "grantee": ["id": "u2", "email": "alex@example.com", "name": " Alex ", "public_key": "pk-listed"]])
        let e = Emergency.rosterEntry(g, checkedContactKey: "pk-checked", grantorKeyHash: "h-1")
        XCTAssertEqual(e, RosterEntry(id: "g1", contactKey: "pk-checked", grantorKeyHash: "h-1", email: "alex@example.com", name: "Alex"))
        XCTAssertEqual(Emergency.readRoster(Emergency.rosterJson(roster(1, [e])))?.accesses[0], e)
        XCTAssertNil(Emergency.readRoster(#"{"version":1,"accesses":[{"id":"g1","contact_key":"k","grantor_key_hash":"h","email":5}]}"#))
        XCTAssertEqual(Emergency.entryLabel(e), "Alex (alex@example.com)")
        XCTAssertEqual(Emergency.entryLabel(entry("g2")), "Unknown contact")
    }

    func testIsRefusedWhenOlderThanOneThisDeviceOpened() {
        XCTAssertTrue(Emergency.rosterIsOlder(roster(4, []), seen: 5))
        XCTAssertFalse(Emergency.rosterIsOlder(roster(5, []), seen: 5))
        XCTAssertFalse(Emergency.rosterIsOlder(roster(6, []), seen: 5))
        XCTAssertTrue(Emergency.rosterIsOlder(Emergency.emptyRoster, seen: 1))
        XCTAssertFalse(Emergency.rosterIsOlder(Emergency.emptyRoster, seen: 0))
    }

    func testNamesGrantorKeysByTheirSHA256InBase64url() {
        XCTAssertEqual(Emergency.sha256b64("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")
        XCTAssertEqual(Emergency.sha256b64(""), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU")
    }

    func testKeepsAtMost300RemovedAccessesTheNewestAndStaysUnderTheServersSizeLimit() throws {
        let many = (0..<310).map { i in RemovedEntry(id: "00000000-0000-4000-8000-" + String(format: "%012d", i), grantorKeyHash: String(repeating: "x", count: 43)) }
        var r = roster(1, [])
        for x in many { r = try XCTUnwrap(Emergency.nextRoster(r, seen: 0, .remove(x.id, hash: x.grantorKeyHash))) }
        XCTAssertLessThanOrEqual(r.removed.count, Emergency.maxRemoved)
        XCTAssertEqual(r.removed.last?.id, many.last?.id)
        XCTAssertFalse(r.removed.contains { $0.id == many[0].id })
        XCTAssertLessThanOrEqual(Emergency.sealedLength(r), Emergency.maxSealedRoster)
        let big = (0..<50).map { i in
            RosterEntry(id: "c\(i)", contactKey: "pk-c\(i)", grantorKeyHash: "h-c\(i)", email: String(repeating: "e", count: 240) + "@x.example", name: String(repeating: "N", count: 100))
        }
        var full = r
        full.accesses = big
        XCTAssertThrowsError(try Emergency.nextRoster(full, seen: 0, .remove("00000000-0000-4000-8000-999999999999", hash: String(repeating: "y", count: 43)))) {
            XCTAssertTrue($0 is RosterFullError)
        }
        var small = roster(1, [])
        small.accesses = big
        let roomy = try XCTUnwrap(Emergency.nextRoster(small, seen: 0, .remove("00000000-0000-4000-8000-999999999999", hash: String(repeating: "y", count: 43))))
        XCTAssertEqual(roomy.accesses.count, 50)
        XCTAssertLessThanOrEqual(Emergency.sealedLength(roomy), Emergency.maxSealedRoster)
    }

    func testKeepsNamesAndEmailsOnOneLineWithoutInvisibleCharactersAndBounded() {
        let padded = grant(.approved, ["id": "g1", "grantee": ["id": "u2", "email": .string(String(repeating: "\u{200B}", count: 10000) + "alex@example.com"),
                                                           "name": .string(String(repeating: "A", count: 500) + "\u{202E}"), "public_key": "pk"]])
        let e = Emergency.rosterEntry(padded, checkedContactKey: "pk", grantorKeyHash: "h-1")
        XCTAssertEqual(e.email, "alex@example.com")
        XCTAssertLessThanOrEqual((e.name ?? "").unicodeScalars.count, Emergency.maxName)
        let long = Emergency.rosterEntry(grant(.approved, ["id": "g2", "grantee": ["id": "u3", "email": .string(String(repeating: "e", count: 400)), "name": "B", "public_key": "pk"]]),
                                         checkedContactKey: "pk", grantorKeyHash: "h")
        XCTAssertLessThanOrEqual((long.email ?? "").unicodeScalars.count, Emergency.maxEmail)
    }

    func testKeepsThisDevicesOwnRemovedAccessesOverTheServersWhenTrimming() throws {
        let ids = (0..<Emergency.maxRemoved).map { RemovedEntry(id: "server-\($0)", grantorKeyHash: String(repeating: "h", count: 43)) }
        let server = roster(3, [], ids)
        let trusted = roster(5, [], [RemovedEntry(id: "mine", grantorKeyHash: String(repeating: "m", count: 43))])
        let forward = try Emergency.restoredRosterForward([], server: server, trusted: trusted, seen: 5, listedNow: [])
        XCTAssertTrue(forward.removed.contains { $0.id == "mine" })
        XCTAssertEqual(forward.removed.count, Emergency.maxRemoved)
    }

    func testIsReadFromTheListing() {
        let a = Emergency.readGrants(["as_grantor": [], "as_grantee": [], "roster": "c2VhbGVk", "roster_seq": 4])
        XCTAssertEqual(a.roster, "c2VhbGVk")
        XCTAssertEqual(a.rosterSeq, 4)
        let b = Emergency.readGrants(["as_grantor": [], "as_grantee": [], "roster": nil, "roster_seq": 0])
        XCTAssertNil(b.roster)
        XCTAssertEqual(b.rosterSeq, 0)
        let c = Emergency.readGrants(["as_grantor": [], "as_grantee": []])
        XCTAssertNil(c.roster)
        XCTAssertNil(c.rosterSeq)
        let d = Emergency.readGrants(["roster": 5, "roster_seq": -1])
        XCTAssertNil(d.roster)
        XCTAssertNil(d.rosterSeq)
    }

    // MARK: which accesses get more vault keys

    private func listed(_ id: String, _ extra: [String: JSON] = [:]) -> Grant {
        var e: [String: JSON] = ["id": .string(id), "grantor_key": .string("gk-\(id)"), "missing_vaults": ["v1"], "key_version": 2,
                                 "grantee": ["id": "user-alex", "email": "alex@example.com", "name": "", "public_key": "pk-alex"]]
        for (k, v) in extra { e[k] = v }
        return grant(.approved, e)
    }

    func testOnlyThoseInTheRosterWithTheSameContactKeyAndGrantorKeyAndNeverARemovedOne() {
        let hashes = ["gk-g1": "h-g1", "gk-g2": "h-g2", "gk-g3": "h-g3", "gk-g5": "h-g5"]
        let r = Roster(version: 2, accesses: [
            RosterEntry(id: "g1", contactKey: "pk-alex", grantorKeyHash: "h-g1"),
            RosterEntry(id: "g2", contactKey: "pk-alex", grantorKeyHash: "h-other"),
            RosterEntry(id: "g3", contactKey: "pk-someone-else", grantorKeyHash: "h-g3"),
            RosterEntry(id: "g5", contactKey: "pk-alex", grantorKeyHash: "h-g5"),
        ], removed: [RemovedEntry(id: "g6", grantorKeyHash: "h-g5")])
        let grants = [listed("g1"), listed("g2"), listed("g3"), listed("g4"), listed("g5")]
        XCTAssertEqual(Emergency.fillableAccesses(grants, r, hashes: hashes).map(\.id), ["g1"])
        XCTAssertEqual(Emergency.fillableAccesses(grants, Emergency.emptyRoster, hashes: hashes), [])
        XCTAssertEqual(Emergency.fillableAccesses([listed("g1", ["missing_vaults": []])], r, hashes: hashes), [])
        XCTAssertEqual(Emergency.fillableAccesses([listed("g1", ["status": "accepted"])], r, hashes: hashes), [])
    }

    // MARK: which vault keys a removal replaces

    func testOnlyTheVaultsTheServerNamesThatThisAppSeesAsPersonal() {
        let personal: Set = ["v1", "v3"]
        let answer: JSON = ["ok": true, "rotation_pending": ["v1", "v2", "v3", "v4"]]
        XCTAssertEqual(Emergency.vaultsToReKey(answer) { personal.contains($0) }, ["v1", "v3"])
        XCTAssertEqual(Emergency.vaultsToReKey(["ok": true]) { _ in true }, [])
        XCTAssertEqual(Emergency.vaultsToReKey(answer) { _ in false }, [])
    }

    // MARK: using the server's list after a restore

    private func e(_ id: String, _ contactKey: String? = nil, _ name: String? = nil) -> RosterEntry {
        RosterEntry(id: id, contactKey: contactKey ?? "pk-\(id)", grantorKeyHash: "h-\(id)", email: name.map { _ in "\(id)@example.com" }, name: name)
    }

    func testWritesExactlyWhatWasShownOneVersionAboveTheNewestThisDeviceSaw() throws {
        let seen: Int64 = 7
        let server = Roster(version: 4, accesses: [e("g1"), e("g9")], removed: [])
        XCTAssertTrue(Emergency.rosterIsOlder(server, seen: seen))
        let shown = Emergency.reviewRoster(server, trusted: nil, listed: ["g1"])
        let forward = try Emergency.restoredRosterForward(shown, server: server, trusted: nil, seen: seen, listedNow: ["g1", "g9"])
        XCTAssertEqual(forward, Roster(version: 8, accesses: [e("g1")], removed: [RemovedEntry(id: "g9", grantorKeyHash: "h-g9")]))
        for version: Int64 in [4, 5, 6, 7] {
            var r = server
            r.version = version
            XCTAssertTrue(Emergency.rosterIsOlder(r, seen: forward.version), "\(version)")
        }
        XCTAssertFalse(Emergency.rosterIsOlder(forward, seen: forward.version))
        XCTAssertEqual(try Emergency.restoredRosterForward(shown, server: server, trusted: nil, seen: seen, listedNow: []).accesses, [])
        XCTAssertEqual(try Emergency.restoredRosterForward([], server: Emergency.emptyRoster, trusted: nil, seen: seen, listedNow: []), Roster(version: 8, accesses: [], removed: []))
    }

    func testMarksWhoThisDevicesLastTrustedListDoesntHaveOrRemoved() throws {
        let trusted = Roster(version: 7, accesses: [e("g1", "pk-g1", "Sam")], removed: [RemovedEntry(id: "g5", grantorKeyHash: "h-g5")])
        let server = Roster(version: 4, accesses: [e("g1", "pk-g1", "Sam"), e("g2", "pk-g2", "Eve"), e("g3", "pk-other", "Max"), e("g4", "pk-g4", "Ann"), e("g5", "pk-g5", "Bo")], removed: [])
        let review = Emergency.reviewRoster(server, trusted: trusted, listed: ["g1", "g2", "g3", "g5"])
        XCTAssertEqual(review.map(\.entry.id), ["g1", "g2", "g3", "g5"])
        XCTAssertEqual(review.map(\.wouldReturn), [false, true, true, true])
        XCTAssertEqual(review.map(\.removed), [false, false, false, true])
        XCTAssertEqual(review.map { Emergency.entryLabel($0.entry) }, ["Sam (g1@example.com)", "Eve (g2@example.com)", "Max (g3@example.com)", "Bo (g5@example.com)"])
        let forward = try Emergency.restoredRosterForward(review, server: server, trusted: trusted, seen: 7, listedNow: ["g1", "g2", "g3", "g5"])
        XCTAssertEqual(forward.accesses.map(\.id), ["g1", "g2", "g3"])
        XCTAssertEqual(forward.removed.map(\.id).sorted(), ["g4", "g5"])
        XCTAssertEqual(Emergency.reviewRoster(server, trusted: nil, listed: ["g1"]).map(\.wouldReturn), [true])
    }

    func testStartsANewEmptyListAboveWhatThisDeviceSawKeepingWhatItRemoved() throws {
        let trusted = Roster(version: 7, accesses: [e("g1")], removed: [RemovedEntry(id: "g0", grantorKeyHash: "h-g0")])
        XCTAssertEqual(try Emergency.freshRoster(seen: 7), Roster(version: 8, accesses: [], removed: []))
        let fresh = try Emergency.freshRoster(seen: 7, trusted: trusted)
        XCTAssertEqual(fresh, Roster(version: 8, accesses: [], removed: [RemovedEntry(id: "g0", grantorKeyHash: "h-g0")]))
        XCTAssertTrue(Emergency.needsConfirmAgain(grant(.approved, ["id": "g1"]), fresh))
        XCTAssertFalse(Emergency.needsConfirmAgain(grant(.approved, ["id": "g0"]), fresh))
        XCTAssertFalse(Emergency.needsConfirmAgain(grant(.accepted, ["id": "g1"]), fresh))
        XCTAssertFalse(Emergency.needsConfirmAgain(grant(.approved, ["id": "g1"]), nil))
    }

    // MARK: accesses that ended or were removed

    private func listedGrant(_ id: String, _ extra: [String: JSON] = [:]) -> Grant {
        var x: [String: JSON] = ["id": .string(id), "grantor_key": .string("gk-\(id)"), "missing_vaults": ["v1"], "key_version": 2,
                                 "grantee": ["id": "u2", "email": "alex@example.com", "name": "Alex", "public_key": "pk-alex"]]
        for (k, v) in extra { x[k] = v }
        return grant(.approved, x)
    }

    private let endedHashes = ["gk-g1": "h-g1"]
    private let endedRoster = Roster(version: 3, accesses: [RosterEntry(id: "g1", contactKey: "pk-alex", grantorKeyHash: "h-g1")], removed: [])

    func testLeaveTheRosterForGoodWhenTheServerNoLongerListsThem() throws {
        XCTAssertEqual(Emergency.pruneRoster(endedRoster, listed: []), [])
        let pruned = try XCTUnwrap(Emergency.nextRoster(endedRoster, seen: 3, nil, listed: []))
        XCTAssertEqual(pruned, Roster(version: 4, accesses: [], removed: [RemovedEntry(id: "g1", grantorKeyHash: "h-g1")]))
        XCTAssertEqual(Emergency.fillableAccesses([listedGrant("g1")], pruned, hashes: endedHashes), [])
        XCTAssertFalse(Emergency.needsConfirmAgain(listedGrant("g1"), pruned, grantorKeyHash: "h-g1"))
        XCTAssertTrue(Emergency.isRemoved(pruned, "g1"))
        XCTAssertEqual(Emergency.removedText("Alex"), "Alex was removed from your emergency contacts. To give them access again, add them as a new contact.")
        XCTAssertNil(try Emergency.nextRoster(pruned, seen: 4, nil, listed: []))
        XCTAssertEqual(try Emergency.nextRoster(pruned, seen: 4, .add(RosterEntry(id: "g2", contactKey: "k", grantorKeyHash: "h-g2")), listed: ["g2"])?.removed, pruned.removed)
    }

    func testMissingWithoutBeingRemovedComeBackThroughConfirmAgain() throws {
        let lost = Roster(version: 4, accesses: [], removed: [])
        let g = listedGrant("g1")
        XCTAssertTrue(Emergency.needsConfirmAgain(g, lost, grantorKeyHash: "h-g1"))
        let back = try XCTUnwrap(Emergency.nextRoster(lost, seen: 4, .add(Emergency.rosterEntry(g, checkedContactKey: "pk-alex", grantorKeyHash: "h-g1")), listed: ["g1"]))
        XCTAssertEqual(back.version, 5)
        XCTAssertFalse(Emergency.needsConfirmAgain(g, back, grantorKeyHash: "h-g1"))
        XCTAssertEqual(Emergency.fillableAccesses([g], back, hashes: endedHashes).map(\.id), ["g1"])
    }
}
