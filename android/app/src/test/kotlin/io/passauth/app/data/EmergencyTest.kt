package io.passauth.app.data

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The emergency access rules ([Emergency]): every case of the web vault's `emergency.test.ts`,
 * with the same inputs and expected results.
 */
class EmergencyTest {
    private fun person(id: String, email: String, name: String, pk: String) = buildJsonObject {
        put("id", id); put("email", email); put("name", name); put("public_key", pk)
    }

    private fun raw(status: String, extra: Map<String, JsonElement> = emptyMap()): JsonObject = JsonObject(
        mapOf(
            "id" to JsonPrimitive("grant-$status"),
            "status" to JsonPrimitive(status),
            "wait_days" to JsonPrimitive(7),
            "created_at" to JsonPrimitive(100),
            "updated_at" to JsonPrimitive(200),
            "requested_at" to JsonNull,
            "approved_at" to JsonNull,
            "auto_approve_at" to JsonNull,
            "grantor" to person("user-sam", "sam@example.com", "Sam Lee", "pk-sam"),
            "grantee" to person("user-alex", "alex@example.com", "", "pk-alex"),
        ) + extra,
    )

    private fun grant(status: String, vararg extra: Pair<String, Any?>): Grant = Emergency.readGrant(raw(status, extra.associate { it.first to j(it.second) }))!!

    private fun j(v: Any?): JsonElement = when (v) {
        null -> JsonNull
        is JsonElement -> v
        is String -> JsonPrimitive(v)
        is Number -> JsonPrimitive(v)
        is Boolean -> JsonPrimitive(v)
        is List<*> -> buildJsonArray { v.forEach { add(j(it)) } }
        else -> error("unsupported $v")
    }

    private val whenText = { s: Long -> "t$s" }

    // ------------------------------------------------------------- reading

    @Test
    fun readsBothLists() {
        val lists = Emergency.readGrants(buildJsonObject {
            put("as_grantor", buildJsonArray { add(raw("invited")); add(buildJsonObject { put("id", "x") }) })
            put("as_grantee", buildJsonArray { add(raw("approved", mapOf("approved_at" to JsonPrimitive(300)))) })
        })
        assertEquals(1, lists.asGrantor.size)
        val g = lists.asGrantor[0]
        assertEquals("grant-invited", g.id)
        assertEquals(GrantStatus.Invited, g.status)
        assertEquals(7L, g.waitDays)
        assertEquals("alex@example.com", g.grantee.email)
        assertEquals("pk-alex", g.grantee.publicKey)
        assertEquals(GrantStatus.Approved, lists.asGrantee[0].status)
        assertEquals(300L, lists.asGrantee[0].approvedAt)
        assertEquals(GrantLists(emptyList(), emptyList(), null, null), Emergency.readGrants(JsonNull))
    }

    @Test
    fun leavesOutUnknownStatusesAndEntriesWithoutPeople() {
        assertNull(Emergency.readGrant(raw("paused")))
        assertNull(Emergency.readGrant(raw("invited", mapOf("grantor" to JsonNull))))
        assertNull(Emergency.readGrant(raw("invited", mapOf("wait_days" to JsonPrimitive("7")))))
    }

    @Test
    fun namesPeopleByNameElseEmail() {
        val g = grant("invited")
        assertEquals("Sam Lee", Emergency.personName(g.grantor))
        assertEquals("alex@example.com", Emergency.personName(g.grantee))
        assertEquals("Someone", Emergency.personName(GrantPerson("x", "", " ", "")))
    }

    @Test
    fun waitingPeriodAcceptsWholeDaysFrom1To90() {
        assertTrue(Emergency.validWait(1.0))
        assertTrue(Emergency.validWait(90.0))
        assertFalse(Emergency.validWait(0.0))
        assertFalse(Emergency.validWait(91.0))
        assertFalse(Emergency.validWait(2.5))
        assertEquals("1 day", Emergency.daysText(1))
        assertEquals("30 days", Emergency.daysText(30))
    }

    // ------------------------------------------------------ status in words

    @Test
    fun tellsTheGrantorWhatEachStepMeans() {
        assertEquals("Waiting for alex@example.com to accept.", Emergency.grantorStatus(grant("invited"), whenText).text)
        val accepted = Emergency.grantorStatus(grant("accepted"), whenText)
        assertEquals("Confirm", accepted.label)
        assertEquals(Tone.Warn, accepted.tone)
        assertTrue(accepted.text.contains("Check their fingerprint"))
        assertTrue(Emergency.grantorStatus(grant("confirmed"), whenText).text.contains("You'd have 7 days to say no"))
        assertEquals(
            "alex@example.com asked for access on t1000. Unless you reject it, they can view your personal vaults from t5000.",
            Emergency.grantorStatus(grant("requested", "requested_at" to 1000, "auto_approve_at" to 5000), whenText).text,
        )
        assertTrue(Emergency.grantorStatus(grant("requested"), whenText).text.contains("after 7 days"))
        val approved = Emergency.grantorStatus(grant("approved", "approved_at" to 9), whenText)
        assertEquals("Has access", approved.label)
        assertEquals("alex@example.com can view your personal vaults since t9.", approved.text)
        // Confirmed before emergency keys: confirm again.
        assertEquals(
            StatusText(
                "Confirm again",
                "PassAuth now gives emergency contacts a key to your personal vaults only. Confirm alex@example.com again to give them access.",
                Tone.Warn,
            ),
            Emergency.grantorStatus(grant("accepted", "reconfirm" to true), whenText),
        )
        assertTrue(GrantorAction.Confirm in Emergency.grantorActions(grant("accepted", "reconfirm" to true)))
        assertTrue(Emergency.grantorStatus(grant("rejected"), whenText).text.contains("They can ask again"))
    }

    @Test
    fun tellsTheContactWhatEachStepMeans() {
        assertTrue(Emergency.granteeStatus(grant("invited"), whenText).text.contains("Sam Lee named you as their emergency contact"))
        assertEquals("Waiting for Sam Lee to confirm you.", Emergency.granteeStatus(grant("accepted"), whenText).text)
        assertTrue(Emergency.granteeStatus(grant("confirmed"), whenText).text.contains("Sam Lee is told at once and has 7 days to say no"))
        assertTrue(Emergency.granteeStatus(grant("requested", "auto_approve_at" to 5000), whenText).text.contains("you can view their vaults from t5000"))
        val approved = Emergency.granteeStatus(grant("approved"), whenText)
        assertEquals("Access granted", approved.label)
        assertEquals(Tone.Ok, approved.tone)
        assertTrue(Emergency.granteeStatus(grant("rejected"), whenText).text.contains("You can ask again"))
    }

    // -------------------------------------------------------------- actions

    @Test
    fun offersTheGrantorWhatEachStepAllows() {
        assertEquals(listOf(GrantorAction.Wait, GrantorAction.Remove), Emergency.grantorActions(grant("invited")))
        assertEquals(listOf(GrantorAction.Confirm, GrantorAction.Wait, GrantorAction.Remove), Emergency.grantorActions(grant("accepted")))
        assertEquals(listOf(GrantorAction.Wait, GrantorAction.Remove), Emergency.grantorActions(grant("confirmed")))
        assertEquals(listOf(GrantorAction.Approve, GrantorAction.Reject, GrantorAction.Wait, GrantorAction.Remove), Emergency.grantorActions(grant("requested")))
        assertEquals(listOf(GrantorAction.End, GrantorAction.Wait, GrantorAction.Remove), Emergency.grantorActions(grant("approved")))
        assertEquals(listOf(GrantorAction.Wait, GrantorAction.Remove), Emergency.grantorActions(grant("rejected")))
    }

    @Test
    fun offersTheContactWhatEachStepAllows() {
        assertEquals(listOf(GranteeAction.Accept, GranteeAction.Decline), Emergency.granteeActions(grant("invited")))
        assertEquals(listOf(GranteeAction.Remove), Emergency.granteeActions(grant("accepted")))
        assertEquals(listOf(GranteeAction.Request, GranteeAction.Remove), Emergency.granteeActions(grant("confirmed")))
        assertEquals(listOf(GranteeAction.Remove), Emergency.granteeActions(grant("requested")))
        assertEquals(listOf(GranteeAction.View, GranteeAction.Remove), Emergency.granteeActions(grant("approved")))
        assertEquals(listOf(GranteeAction.Request, GranteeAction.Remove), Emergency.granteeActions(grant("rejected")))
    }

    @Test
    fun countsWhatWaitsForAnAnswer() {
        assertEquals(3, Emergency.needsAnswer(listOf(grant("accepted"), grant("requested"), grant("approved")), listOf(grant("invited"), grant("confirmed"))))
        assertEquals(0, Emergency.needsAnswer(emptyList(), emptyList()))
    }

    // ----------------------------------------------- what is said about keys

    @Test
    fun saysWhatConfirmingGivesBeforeItIsDone() {
        assertEquals(
            "Confirming gives Alex a key to your personal vaults. Once they get access (or at once, if your server is ever compromised), they can read everything in those vaults. Shared vaults and Sends stay out of reach. If you remove them, PassAuth changes the keys of those vaults, so they can't read anything you add afterwards, unless your server is later compromised.",
            Emergency.confirmMeaning("Alex"),
        )
        assertTrue(Emergency.reconfirmText("Alex").contains("Confirm Alex again"))
    }

    @Test
    fun saysWhenRemovingAContactChangesKeysAndDeletesEarlierVersions() {
        assertEquals("alex@example.com can't ask for access any more.", Emergency.removalText(grant("invited")))
        assertEquals("alex@example.com can't ask for access any more.", Emergency.removalText(grant("accepted")))
        val confirmed = Emergency.removalText(grant("confirmed"))
        assertTrue(confirmed.contains("PassAuth changes the keys of your personal vaults"))
        assertTrue(confirmed.contains("deletes the earlier versions"))
        assertFalse(confirmed.contains("keep what they saw"))
        for (status in listOf("requested", "approved", "rejected")) {
            assertTrue(Emergency.removalText(grant(status)).contains("changes the keys"))
            assertTrue(Emergency.removalText(grant(status)).contains("keep what they saw"))
        }
    }

    // ---------------------------------------- which vaults get the contact's key

    private val own = OwnVault("v1", Role.Owner, "account")
    private val me = "user-sam"
    private val alone = listOf(me)

    @Test
    fun takesOnlyVaultsThisAppSeesAsPersonal() {
        assertTrue(Emergency.isPersonal(own, alone, me))
        assertFalse(Emergency.isPersonal(own, alone + "user-alex", me))
        assertFalse(Emergency.isPersonal(own, listOf("user-alex"), me))
        assertFalse(Emergency.isPersonal(own, emptyList(), me))
        assertFalse(Emergency.isPersonal(own, null, me))
        assertFalse(Emergency.isPersonal(null, alone, me))
        assertFalse(Emergency.isPersonal(own.copy(role = Role.Admin), alone, me))
        assertFalse(Emergency.isPersonal(own.copy(kind = "sealed"), alone, me))
        assertFalse(Emergency.isPersonal(own, alone, ""))
    }

    @Test
    fun neverWrapsAVaultTheServerListsButThisAppSeesAsShared() {
        val personal = setOf("v1", "v2")
        assertEquals(listOf("v1", "v2") to listOf("v3"), Emergency.vaultsToWrap(listOf("v1", "v3", "v2", "v1")) { it in personal })
        assertEquals(emptyList<String>() to emptyList<String>(), Emergency.vaultsToWrap(emptyList()) { true })
    }

    @Test
    fun addsWrapsOnlyForAccessesThatHoldKeysHaveThisAccountsKeyAndMissVaults() {
        fun fill(status: String, vararg extra: Pair<String, Any?>) =
            grant(status, *(arrayOf<Pair<String, Any?>>("grantor_key" to "gk", "missing_vaults" to listOf("v1"), "key_version" to 2) + extra))
        val todo = listOf(
            fill("confirmed"),
            fill("requested"),
            fill("approved"),
            fill("rejected"),
            fill("accepted"),
            fill("invited"),
            fill("approved", "grantor_key" to null),
            fill("approved", "missing_vaults" to emptyList<String>()),
            fill("approved", "key_version" to 3),
        )
        assertEquals(
            listOf(GrantStatus.Confirmed, GrantStatus.Requested, GrantStatus.Approved, GrantStatus.Rejected),
            Emergency.accessesToFill(todo).map { it.status },
        )
        assertFalse(Emergency.hasKeys(grant("accepted")))
    }

    @Test
    fun readsWhatTheGrantorsListingAdds() {
        val g = grant("confirmed", "key_version" to 2, "grantor_key" to "gk", "reconfirm" to false, "missing_vaults" to listOf("v2", 5, "v2", ""))
        assertEquals(2L, g.keyVersion)
        assertEquals("gk", g.grantorKey)
        assertFalse(g.reconfirm)
        assertEquals(listOf("v2"), g.missingVaults)
        val bare = grant("confirmed")
        assertNull(bare.keyVersion)
        assertNull(bare.grantorKey)
        assertFalse(bare.reconfirm)
        assertEquals(emptyList<String>(), bare.missingVaults)
        assertFalse(grant("accepted", "reconfirm" to "yes").reconfirm)
    }

    @Test
    fun readsWhichVaultsNeedNewKeysAfterARemoval() {
        assertEquals(listOf("v1", "v2"), Emergency.vaultsToRotate(j(mapOf("ok" to true, "rotation_pending" to listOf("v1", "v2")))))
        assertEquals(emptyList<String>(), Emergency.vaultsToRotate(buildJsonObject { put("ok", true) }))
        assertEquals(emptyList<String>(), Emergency.vaultsToRotate(buildJsonObject { put("rotation_pending", "v1") }))
        assertEquals(emptyList<String>(), Emergency.vaultsToRotate(JsonNull))
    }

    private fun j(m: Map<String, Any?>): JsonElement = JsonObject(m.mapValues { j(it.value) })

    // ---------------------------------------------------- the grantor's vault

    @Test
    fun mapsRowsToWhatTheCoreDecrypts() {
        val data = Emergency.readGrantorVault(
            j(
                mapOf(
                    "grant" to raw("approved"),
                    "key_version" to 2,
                    "sealed_key" to "sealed",
                    "vaults" to listOf(j(mapOf("id" to "v1", "meta" to "m", "wrapped_key" to "w", "key_epoch" to 2)), j(mapOf("id" to "v2"))),
                    "items" to listOf(
                        j(mapOf("id" to "i1", "vault_id" to "v1", "item_key" to "ik", "data" to "d", "revision" to 3, "deleted_at" to null, "created_at" to 1, "updated_at" to 2)),
                        j(mapOf("id" to "i2", "vault_id" to "v1", "item_key" to "ik2", "data" to "d2", "revision" to 4, "deleted_at" to 50, "created_at" to 1, "updated_at" to 3)),
                        j(mapOf("id" to "i3", "vault_id" to "v1", "data" to "no key")),
                    ),
                ),
            ),
        )!!
        assertEquals("sealed", data.sealedKey)
        assertEquals(2L, data.keyVersion)
        assertEquals(listOf(GrantorVaultRow("v1", "m", "w", keyEpoch = 2)), data.vaults)
        // Every row as sent stays for the vault's manifest check, also one this app can't read.
        assertEquals(3, data.rawItems.size)
        val withManifest = Emergency.readGrantorVault(
            j(mapOf("sealed_key" to "s", "vaults" to listOf(j(mapOf("id" to "v1", "meta" to "m", "wrapped_key" to "w", "key_epoch" to 2, "manifest" to "sealed-text", "manifest_seq" to 5))), "items" to emptyList<Any>())),
        )!!
        assertEquals(GrantorVaultRow("v1", "m", "w", 2, "sealed-text", 5), withManifest.vaults.single())
        assertEquals(
            listOf(GrantorItemRow("i1", "v1", "ik", "d", null, 2), GrantorItemRow("i2", "v1", "ik2", "d2", 50, 3)),
            data.items,
        )
    }

    @Test
    fun refusesAnAnswerWithoutTheSealedKey() {
        assertNull(Emergency.readGrantorVault(j(mapOf("vaults" to emptyList<Any>(), "items" to emptyList<Any>()))))
        assertNull(Emergency.readGrantorVault(JsonNull))
    }

    @Test
    fun tellsAnswersFromServersBeforeEmergencyKeys() {
        assertNull(Emergency.readGrantorVault(j(mapOf("sealed_key" to "s", "vaults" to emptyList<Any>(), "items" to emptyList<Any>())))!!.keyVersion)
    }

    // ------------------------------------- contacts confirmed before emergency keys

    @Test
    fun readsTheV1FlagAndSaysWhatRemovingCantUndo() {
        assertTrue(grant("approved", "v1_exposed" to true).v1Exposed)
        assertFalse(grant("approved").v1Exposed)
        val warning = Emergency.v1Warning("Alex")
        assertEquals(
            "Alex was confirmed with an earlier version of PassAuth, which gave them your account key. Removing them can't take that back. If you no longer trust them, change the passwords that matter or move to a new account.",
            warning,
        )
        // No promise about what they can't read afterwards, in the confirm step or when removing.
        assertTrue(Emergency.confirmMeaning("Alex", true).contains(warning))
        assertFalse(Emergency.confirmMeaning("Alex", true).contains("can't read anything you add afterwards"))
        val removal = Emergency.removalText(grant("approved", "v1_exposed" to true))
        assertTrue(removal.contains("changes the keys of your personal vaults"))
        assertTrue(removal.contains(Emergency.v1Warning("alex@example.com")))
        assertFalse(removal.contains("can't read anything you add afterwards"))
        assertTrue(Emergency.removalText(grant("accepted", "v1_exposed" to true, "reconfirm" to true)).contains("gave them your account key"))
    }

    // ------------------------------------------------------------ the roster

    private fun entry(id: String, contactKey: String = "pk-$id", hash: String = "h-$id") = RosterEntry(id, contactKey, hash)
    private fun roster(version: Long, accesses: List<RosterEntry>, removed: List<RemovedEntry> = emptyList()) = Roster(version, accesses, removed)

    @Test
    fun readsAndWritesItsJsonAndRefusesAnythingMalformed() {
        val r = roster(3, listOf(entry("g1"), entry("g2")), listOf(RemovedEntry("g0", "h-g0")))
        assertEquals(r, Emergency.readRoster(Emergency.rosterJson(r)))
        assertEquals(
            AppJson.parseToJsonElement(
                """{"version":3,"accesses":[{"id":"g1","contact_key":"pk-g1","grantor_key_hash":"h-g1"},{"id":"g2","contact_key":"pk-g2","grantor_key_hash":"h-g2"}],"removed":[{"id":"g0","grantor_key_hash":"h-g0"}]}""",
            ),
            AppJson.parseToJsonElement(Emergency.rosterJson(r)),
        )
        // Rosters from before `removed` have none.
        assertEquals(roster(1, emptyList()), Emergency.readRoster("""{"version":1,"accesses":[]}"""))
        for (bad in listOf(
            "",
            "nonsense",
            "null",
            "[]",
            """{"version":-1,"accesses":[]}""",
            """{"version":1.5,"accesses":[]}""",
            """{"version":1}""",
            """{"version":1,"accesses":[{"id":"g1"}]}""",
            """{"version":1,"accesses":[],"removed":{}}""",
            """{"version":1,"accesses":[],"removed":[{"id":"g1"}]}""",
        )) {
            assertNull(bad, Emergency.readRoster(bad))
        }
    }

    @Test
    fun goesUpAVersionWithEveryChangePastWhatThisDeviceHasSeen() {
        val added = Emergency.nextRoster(Emergency.EMPTY_ROSTER, 0, Emergency.RosterChange.Add(entry("g1")))!!
        assertEquals(roster(1, listOf(entry("g1"))), added)
        val replaced = Emergency.nextRoster(added, 0, Emergency.RosterChange.Add(entry("g1", "pk-new", "h-new")))!!
        assertEquals(roster(2, listOf(entry("g1", "pk-new", "h-new"))), replaced)
        // Removing keeps the access as removed, with its key's hash.
        assertEquals(roster(3, emptyList(), listOf(RemovedEntry("g1", "h-new"))), Emergency.nextRoster(replaced, 0, Emergency.RosterChange.Remove("g1")))
        // A device that opened version 9 writes 10, whatever it read.
        assertEquals(10L, Emergency.nextRoster(added, 9, Emergency.RosterChange.Add(entry("g2")))!!.version)
        // Nothing to change, nothing to write; an access the roster doesn't have is removed only with its key's hash.
        assertNull(Emergency.nextRoster(added, 0, Emergency.RosterChange.Remove("g9")))
        assertEquals(
            roster(2, listOf(entry("g1")), listOf(RemovedEntry("g9", "h-g9"))),
            Emergency.nextRoster(added, 0, Emergency.RosterChange.Remove("g9", "h-g9")),
        )
        assertNull(Emergency.nextRoster(added, 0, null, setOf("g1")))
    }

    @Test
    fun keepsTheNameAndEmailTheGrantorConfirmedAndReadsEntriesFromBeforeWithoutThem() {
        val g = grant("approved", "id" to "g1", "grantee" to person("u2", "alex@example.com", " Alex ", "pk-listed"))
        val e = Emergency.rosterEntry(g, "pk-checked", "h-1")
        assertEquals(RosterEntry("g1", "pk-checked", "h-1", "alex@example.com", "Alex"), e)
        assertEquals(e, Emergency.readRoster(Emergency.rosterJson(roster(1, listOf(e))))!!.accesses[0])
        assertNull(Emergency.readRoster("""{"version":1,"accesses":[{"id":"g1","contact_key":"k","grantor_key_hash":"h","email":5}]}"""))
        assertEquals("Alex (alex@example.com)", Emergency.entryLabel(e))
        assertEquals("Unknown contact", Emergency.entryLabel(entry("g2")))
    }

    @Test
    fun isRefusedWhenOlderThanOneThisDeviceOpened() {
        assertTrue(Emergency.rosterIsOlder(roster(4, emptyList()), 5))
        assertFalse(Emergency.rosterIsOlder(roster(5, emptyList()), 5))
        assertFalse(Emergency.rosterIsOlder(roster(6, emptyList()), 5))
        // No roster at all after one was seen counts as older.
        assertTrue(Emergency.rosterIsOlder(Emergency.EMPTY_ROSTER, 1))
        assertFalse(Emergency.rosterIsOlder(Emergency.EMPTY_ROSTER, 0))
    }

    @Test
    fun namesGrantorKeysByTheirSha256InBase64url() {
        assertEquals("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", Emergency.sha256b64("abc"))
        assertEquals("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", Emergency.sha256b64(""))
    }

    @Test
    fun keepsAtMost300RemovedAccessesTheNewestAndStaysUnderTheServersSizeLimit() {
        val many = (0 until 310).map { i -> RemovedEntry("00000000-0000-4000-8000-${i.toString().padStart(12, '0')}", "x".repeat(43)) }
        var r = roster(1, emptyList())
        for (x in many) r = Emergency.nextRoster(r, 0, Emergency.RosterChange.Remove(x.id, x.grantorKeyHash))!!
        assertTrue(r.removed.size <= Emergency.MAX_REMOVED)
        assertEquals(many.last().id, r.removed.last().id)
        assertFalse(r.removed.any { it.id == many[0].id })
        assertTrue(Emergency.sealedLength(r) <= Emergency.MAX_SEALED_ROSTER)
        // A roster too large for the server is refused: removed entries are never dropped to make room.
        val big = (0 until 50).map { i -> RosterEntry("c$i", "pk-c$i", "h-c$i", "${"e".repeat(240)}@x.example", "N".repeat(100)) }
        assertThrows(RosterFullError::class.java) {
            Emergency.nextRoster(r.copy(accesses = big), 0, Emergency.RosterChange.Remove("00000000-0000-4000-8000-999999999999", "y".repeat(43)))
        }
        // Fewer removed accesses leave room for the same contacts.
        val roomy = Emergency.nextRoster(roster(1, emptyList()).copy(accesses = big), 0, Emergency.RosterChange.Remove("00000000-0000-4000-8000-999999999999", "y".repeat(43)))!!
        assertEquals(50, roomy.accesses.size)
        assertTrue(Emergency.sealedLength(roomy) <= Emergency.MAX_SEALED_ROSTER)
    }

    @Test
    fun keepsNamesAndEmailsOnOneLineWithoutInvisibleCharactersAndBounded() {
        val padded = grant(
            "approved",
            "id" to "g1",
            "grantee" to person("u2", "​".repeat(10000) + "alex@example.com", "A".repeat(500) + "‮", "pk"),
        )
        val e = Emergency.rosterEntry(padded, "pk", "h-1")
        assertEquals("alex@example.com", e.email)
        assertTrue(CleanText.length(e.name.orEmpty()) <= Emergency.MAX_NAME)
        val long = Emergency.rosterEntry(grant("approved", "id" to "g2", "grantee" to person("u3", "e".repeat(400), "B", "pk")), "pk", "h")
        assertTrue(CleanText.length(long.email.orEmpty()) <= Emergency.MAX_EMAIL)
    }

    @Test
    fun keepsThisDevicesOwnRemovedAccessesOverTheServersWhenTrimming() {
        fun ids(n: Int, p: String) = (0 until n).map { RemovedEntry("$p-$it", "h".repeat(43)) }
        val server = roster(3, emptyList(), ids(Emergency.MAX_REMOVED, "server"))
        val trusted = roster(5, emptyList(), listOf(RemovedEntry("mine", "m".repeat(43))))
        val forward = Emergency.restoredRosterForward(emptyList(), server, trusted, 5, emptySet())
        assertTrue(forward.removed.any { it.id == "mine" })
        assertEquals(Emergency.MAX_REMOVED, forward.removed.size)
    }

    @Test
    fun isReadFromTheListing() {
        val a = Emergency.readGrants(AppJson.parseToJsonElement("""{"as_grantor":[],"as_grantee":[],"roster":"c2VhbGVk","roster_seq":4}"""))
        assertEquals("c2VhbGVk", a.roster)
        assertEquals(4L, a.rosterSeq)
        val b = Emergency.readGrants(AppJson.parseToJsonElement("""{"as_grantor":[],"as_grantee":[],"roster":null,"roster_seq":0}"""))
        assertNull(b.roster)
        assertEquals(0L, b.rosterSeq)
        val c = Emergency.readGrants(AppJson.parseToJsonElement("""{"as_grantor":[],"as_grantee":[]}"""))
        assertNull(c.roster)
        assertNull(c.rosterSeq)
        val d = Emergency.readGrants(AppJson.parseToJsonElement("""{"roster":5,"roster_seq":-1}"""))
        assertNull(d.roster)
        assertNull(d.rosterSeq)
    }

    // -------------------------------------- which accesses get more vault keys

    private fun listed(id: String, vararg extra: Pair<String, Any?>) = grant(
        "approved",
        *(arrayOf<Pair<String, Any?>>(
            "id" to id, "grantor_key" to "gk-$id", "missing_vaults" to listOf("v1"), "key_version" to 2,
            "grantee" to person("user-alex", "alex@example.com", "", "pk-alex"),
        ) + extra),
    )

    @Test
    fun fillsOnlyThoseInTheRosterWithTheSameContactKeyAndGrantorKeyAndNeverARemovedOne() {
        val hashes = mapOf("gk-g1" to "h-g1", "gk-g2" to "h-g2", "gk-g3" to "h-g3", "gk-g5" to "h-g5")
        val r = Roster(
            2,
            listOf(
                RosterEntry("g1", "pk-alex", "h-g1"),
                RosterEntry("g2", "pk-alex", "h-other"),
                RosterEntry("g3", "pk-someone-else", "h-g3"),
                RosterEntry("g5", "pk-alex", "h-g5"),
            ),
            // g5's key was removed under another access: refused too.
            listOf(RemovedEntry("g6", "h-g5")),
        )
        val grants = listOf(listed("g1"), listed("g2"), listed("g3"), listed("g4"), listed("g5"))
        assertEquals(listOf("g1"), Emergency.fillableAccesses(grants, r, hashes).map { it.id })
        assertEquals(emptyList<Grant>(), Emergency.fillableAccesses(grants, Emergency.EMPTY_ROSTER, hashes))
        // Still only accesses that hold keys and miss vaults.
        assertEquals(emptyList<Grant>(), Emergency.fillableAccesses(listOf(listed("g1", "missing_vaults" to emptyList<String>())), r, hashes))
        assertEquals(emptyList<Grant>(), Emergency.fillableAccesses(listOf(listed("g1", "status" to "accepted")), r, hashes))
    }

    @Test
    fun aRemovalReplacesOnlyTheVaultsTheServerNamesThatThisAppSeesAsPersonal() {
        val personal = setOf("v1", "v3")
        val answer = j(mapOf("ok" to true, "rotation_pending" to listOf("v1", "v2", "v3", "v4")))
        assertEquals(listOf("v1", "v3"), Emergency.vaultsToReKey(answer) { it in personal })
        assertEquals(emptyList<String>(), Emergency.vaultsToReKey(buildJsonObject { put("ok", true) }) { true })
        assertEquals(emptyList<String>(), Emergency.vaultsToReKey(answer) { false })
    }

    // -------------------------------------------- using the server's list after a restore

    private fun e(id: String, contactKey: String = "pk-$id", name: String? = null) =
        RosterEntry(id, contactKey, "h-$id", name?.let { "$id@example.com" }, name)

    @Test
    fun writesExactlyWhatWasShownOneVersionAboveTheNewestThisDeviceSaw() {
        val seen = 7L
        val server = Roster(4, listOf(e("g1"), e("g9")), emptyList())
        assertTrue(Emergency.rosterIsOlder(server, seen))
        // g9 wasn't listed at the review, so it wasn't shown: it is kept as removed, never written as an access.
        val shown = Emergency.reviewRoster(server, null, setOf("g1"))
        val forward = Emergency.restoredRosterForward(shown, server, null, seen, setOf("g1", "g9"))
        assertEquals(Roster(8, listOf(e("g1")), listOf(RemovedEntry("g9", "h-g9"))), forward)
        // Remembered once stored: the restored version and every one in between are refused from then on.
        for (version in listOf(4L, 5L, 6L, 7L)) assertTrue("$version", Emergency.rosterIsOlder(server.copy(version = version), forward.version))
        assertFalse(Emergency.rosterIsOlder(forward, forward.version))
        // A shown entry the server no longer lists when writing is left out too; no roster on the server at all: empty.
        assertEquals(emptyList<RosterEntry>(), Emergency.restoredRosterForward(shown, server, null, seen, emptySet()).accesses)
        assertEquals(Roster(8, emptyList(), emptyList()), Emergency.restoredRosterForward(emptyList(), Emergency.EMPTY_ROSTER, null, seen, emptySet()))
    }

    @Test
    fun marksWhoThisDevicesLastTrustedListDoesntHaveOrRemovedWithNamesFromInsideTheList() {
        val trusted = Roster(7, listOf(e("g1", "pk-g1", "Sam")), listOf(RemovedEntry("g5", "h-g5")))
        // The server's (restored) list: g1 as before, g2 removed since, g3 with another key, g4 it no longer lists, g5 removed here.
        val server = Roster(
            4,
            listOf(e("g1", "pk-g1", "Sam"), e("g2", "pk-g2", "Eve"), e("g3", "pk-other", "Max"), e("g4", "pk-g4", "Ann"), e("g5", "pk-g5", "Bo")),
            emptyList(),
        )
        val review = Emergency.reviewRoster(server, trusted, setOf("g1", "g2", "g3", "g5"))
        assertEquals(
            listOf(Triple("g1", false, false), Triple("g2", true, false), Triple("g3", true, false), Triple("g5", true, true)),
            review.map { Triple(it.entry.id, it.wouldReturn, it.removed) },
        )
        // Names come from the list itself, never from the server's listing.
        assertEquals(
            listOf("Sam (g1@example.com)", "Eve (g2@example.com)", "Max (g3@example.com)", "Bo (g5@example.com)"),
            review.map { Emergency.entryLabel(it.entry) },
        )
        // What is written keeps g5 removed (this device's own removal wins) and g4 too (not shown).
        val forward = Emergency.restoredRosterForward(review, server, trusted, 7, setOf("g1", "g2", "g3", "g5"))
        assertEquals(listOf("g1", "g2", "g3"), forward.accesses.map { it.id })
        assertEquals(listOf("g4", "g5"), forward.removed.map { it.id }.sorted())
        // A device that keeps no list of its own marks everyone.
        assertEquals(listOf(true), Emergency.reviewRoster(server, null, setOf("g1")).map { it.wouldReturn })
    }

    @Test
    fun startsANewEmptyListAboveWhatThisDeviceSawKeepingWhatItRemoved() {
        val trusted = Roster(7, listOf(e("g1")), listOf(RemovedEntry("g0", "h-g0")))
        assertEquals(Roster(8, emptyList(), emptyList()), Emergency.freshRoster(7))
        val fresh = Emergency.freshRoster(7, trusted)
        assertEquals(Roster(8, emptyList(), listOf(RemovedEntry("g0", "h-g0"))), fresh)
        assertTrue(Emergency.needsConfirmAgain(grant("approved", "id" to "g1"), fresh))
        assertFalse(Emergency.needsConfirmAgain(grant("approved", "id" to "g0"), fresh))
        assertFalse(Emergency.needsConfirmAgain(grant("accepted", "id" to "g1"), fresh))
        // Not while the list can't be trusted (nothing to compare with).
        assertFalse(Emergency.needsConfirmAgain(grant("approved", "id" to "g1"), null))
    }

    // ------------------------------------------------ accesses that ended or were removed

    private fun listedGrant(id: String, vararg extra: Pair<String, Any?>) = grant(
        "approved",
        *(arrayOf<Pair<String, Any?>>(
            "id" to id, "grantor_key" to "gk-$id", "missing_vaults" to listOf("v1"), "key_version" to 2,
            "grantee" to person("u2", "alex@example.com", "Alex", "pk-alex"),
        ) + extra),
    )
    private val endedHashes = mapOf("gk-g1" to "h-g1")
    private val endedRoster = Roster(3, listOf(RosterEntry("g1", "pk-alex", "h-g1")), emptyList())

    @Test
    fun leaveTheRosterForGoodWhenTheServerNoLongerListsThem() {
        // The contact stepped down: the server lists nothing for g1, so the next write drops it and keeps it as removed.
        assertEquals(emptyList<RosterEntry>(), Emergency.pruneRoster(endedRoster, emptySet()))
        val pruned = Emergency.nextRoster(endedRoster, 3, null, emptySet())!!
        assertEquals(Roster(4, emptyList(), listOf(RemovedEntry("g1", "h-g1"))), pruned)
        // Later a server lists g1 again, with its old key: no wraps, and it can't come back through Confirm again.
        assertEquals(emptyList<Grant>(), Emergency.fillableAccesses(listOf(listedGrant("g1")), pruned, endedHashes))
        assertFalse(Emergency.needsConfirmAgain(listedGrant("g1"), pruned, "h-g1"))
        assertTrue(Emergency.isRemoved(pruned, "g1"))
        assertEquals(
            "Alex was removed from your emergency contacts. To give them access again, add them as a new contact.",
            Emergency.removedText("Alex"),
        )
        // Pruning again never drops what was removed.
        assertNull(Emergency.nextRoster(pruned, 4, null, emptySet()))
        assertEquals(pruned.removed, Emergency.nextRoster(pruned, 4, Emergency.RosterChange.Add(RosterEntry("g2", "k", "h-g2")), setOf("g2"))!!.removed)
    }

    @Test
    fun missingWithoutBeingRemovedComeBackThroughConfirmAgain() {
        val lost = Roster(4, emptyList(), emptyList())
        val g = listedGrant("g1")
        assertTrue(Emergency.needsConfirmAgain(g, lost, "h-g1"))
        val back = Emergency.nextRoster(lost, 4, Emergency.RosterChange.Add(Emergency.rosterEntry(g, "pk-alex", "h-g1")), setOf("g1"))!!
        assertEquals(5L, back.version)
        assertFalse(Emergency.needsConfirmAgain(g, back, "h-g1"))
        assertEquals(listOf("g1"), Emergency.fillableAccesses(listOf(g), back, endedHashes).map { it.id })
    }

    @Test
    fun rosterJsonKeepsAllFieldsInTheWebVaultsOrder() {
        val r = Roster(2, listOf(RosterEntry("g1", "k", "h", "a@example.com", "A")), listOf(RemovedEntry("g0", "")))
        assertEquals(
            """{"version":2,"accesses":[{"id":"g1","contact_key":"k","grantor_key_hash":"h","email":"a@example.com","name":"A"}],"removed":[{"id":"g0","grantor_key_hash":""}]}""",
            Emergency.rosterJson(r),
        )
        assertEquals(r, Emergency.readRoster(Emergency.rosterJson(r)))
        assertTrue(AppJson.parseToJsonElement(Emergency.rosterJson(r)).jsonObject.containsKey("removed"))
    }
}
