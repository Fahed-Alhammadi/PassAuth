package io.passauth.app.data

import java.util.Base64
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The emergency client's roster flows against a fake server and a fake account (the core's
 * sealing is stood in for: these tests are about what the app sends and refuses, not the
 * cryptography, which the core's own tests cover). Every case of the web vault's
 * `emergency-client.test.ts`, plus the removal and approval requests.
 */
class EmergencyClientTest {
    private class FakeKey(val grantId: String, val n: Int) : EmergencyKeyHandle {
        override fun sealFor(contactKey: String, grantorId: String, grantId: String) = "sealed:${this.grantId}:$n"
        override fun wrapVaultKey(vaultId: String) = "wrap:$grantId:$n:$vaultId"
        override fun openVaultKey(vaultId: String, wrapped: String): OpenedVaultKey = error("not used")
        override fun close() {}
    }

    private var made = 0
    private val account = object : EmergencyCrypto {
        override fun newEmergencyKey(grantId: String): NewEmergencyKeyHandle {
            val n = ++made
            return NewEmergencyKeyHandle("gk:$grantId:$n", FakeKey(grantId, n))
        }

        override fun openEmergencyKey(grantId: String, wrapped: String): EmergencyKeyHandle {
            val m = Regex("^gk:(.+):(\\d+)$").find(wrapped)
            if (m == null || m.groupValues[1] != grantId) throw io.passauth.core.CoreException.DecryptFailed("decrypt_failed")
            return FakeKey(grantId, m.groupValues[2].toInt())
        }

        override fun sealRoster(json: String) = "R:" + Base64.getEncoder().encodeToString(json.toByteArray())
        override fun openRoster(sealed: String): String {
            if (!sealed.startsWith("R:")) throw io.passauth.core.CoreException.DecryptFailed("decrypt_failed")
            return String(Base64.getDecoder().decode(sealed.substring(2)))
        }

        override fun openSealedEmergencyKey(grantorId: String, grantId: String, sealed: String): EmergencyKeyHandle = error("not used")
    }

    private class Server {
        var grants = mutableListOf<MutableMap<String, JsonElement>>()
        var roster: String? = null
        var rosterSeq = 0L
        val fills = mutableListOf<String>()
        var confirms = 0
        var confirmHook: ((String) -> Unit)? = null
        val deleted = mutableListOf<String>()
        var deleteAnswer: JsonElement = buildJsonObject { put("ok", true) }
        val calls = mutableListOf<Triple<String, String, Map<String, String>>>()

        fun grantAt(id: String) = grants.firstOrNull { it["id"]?.jsonPrimitive?.content == id } ?: throw ApiException(404, "not_found", "not found")
    }

    private val server = Server()
    private var seen = 0L
    private var trusted: String? = null
    private val rotated = mutableListOf<List<String>>()
    private val vaults = listOf(VaultInfo("v1", "Personal", Role.Owner, "account", keyEpoch = 0))

    /** The active account [EmergencyEnv.pin] answers with (a test switches it midway). */
    private var active = EmergencyAccount("record-1", "https://pa.example", "me")

    /** The account each request was made on. */
    private val callAccounts = mutableListOf<EmergencyAccount>()

    /** What replacing keys reports (null: every vault replaced). */
    private var rotateAnswer: RotationReport? = null

    /** Called on each request (a test switches account from here). */
    private var onCall: (suspend (String) -> Unit)? = null

    /** Vaults with a signed sharing history (a trusted roster listing others): never personal. */
    private val signedBefore = mutableSetOf<String>()

    private val env = object : EmergencyEnv {
        override suspend fun pin(): EmergencyAccount = active
        override suspend fun call(a: EmergencyAccount, path: String, body: JsonElement?, method: String, headers: Map<String, String>): JsonElement {
            server.calls += Triple(method, path, headers)
            callAccounts += a
            onCall?.invoke(path)
            if (method == "GET" && path == "/emergency-access") {
                return buildJsonObject {
                    put("as_grantor", JsonArray(server.grants.map { JsonObject(it.toMap()) }))
                    put("as_grantee", JsonArray(emptyList()))
                    put("roster", server.roster?.let(::JsonPrimitive) ?: JsonNull)
                    put("roster_seq", server.rosterSeq)
                }
            }
            if (method == "PUT" && path == "/emergency-access/roster") {
                val o = body!!.jsonObject
                if (o["seq"]!!.jsonPrimitive.content.toLong() != server.rosterSeq + 1) throw ApiException(409, "roster_changed", "changed")
                server.roster = o["roster"]!!.jsonPrimitive.content
                server.rosterSeq += 1
                return buildJsonObject { put("roster_seq", server.rosterSeq) }
            }
            Regex("^/emergency-access/([^/]+)/confirm$").find(path)?.let { m ->
                server.confirms++
                val id = java.net.URLDecoder.decode(m.groupValues[1], "UTF-8")
                server.confirmHook?.invoke(id)
                server.grantAt(id).putAll(mapOf("status" to JsonPrimitive("confirmed"), "grantor_key" to body!!.jsonObject["grantor_key"]!!, "missing_vaults" to JsonArray(emptyList())))
                return JsonObject(server.grantAt(id).toMap())
            }
            Regex("^/emergency-access/([^/]+)/vault-keys$").find(path)?.let { m ->
                val id = java.net.URLDecoder.decode(m.groupValues[1], "UTF-8")
                server.fills += id
                server.grantAt(id)["missing_vaults"] = JsonArray(emptyList())
                return JsonObject(server.grantAt(id).toMap())
            }
            Regex("^/emergency-access/([^/]+)(/approve|/reject|/accept|/request)?$").find(path)?.let { m ->
                val id = java.net.URLDecoder.decode(m.groupValues[1], "UTF-8")
                if (method == "DELETE") {
                    server.grantAt(id)
                    server.deleted += id
                    server.grants.removeAll { it["id"]?.jsonPrimitive?.content == id }
                    return server.deleteAnswer
                }
                return JsonObject(server.grantAt(id).toMap())
            }
            if (path == "/vaults/v1/members") {
                return AppJson.parseToJsonElement("""{"members":[{"user_id":"me","email":"me@example.com","name":"Me","role":"owner","public_key":"pk-me"}]}""")
            }
            throw ApiException(404, "not_found", "no fake for $method $path")
        }

        override suspend fun features(a: EmergencyAccount): List<String> = listOf("emergency_access", "emergency_vault_keys")
        override fun crypto(a: EmergencyAccount): EmergencyCrypto = account
        override fun unlocked(a: EmergencyAccount) = true
        override fun vaults(a: EmergencyAccount): List<VaultInfo> = this@EmergencyClientTest.vaults
        override suspend fun reauth(a: EmergencyAccount, password: String): String {
            if (password != "right") throw UserException("That master password is wrong.")
            return "reauth-token"
        }
        override suspend fun sharedBefore(a: EmergencyAccount, vaultId: String): Boolean = vaultId in signedBefore
        override suspend fun rotateVaultKeys(a: EmergencyAccount, ids: List<String>): RotationReport {
            rotated += ids
            return rotateAnswer ?: RotationReport(ids.size)
        }
        override suspend fun sync(a: EmergencyAccount) {}
        override fun setNotice(a: EmergencyAccount, text: String?) {}
        override suspend fun seenVersion(a: EmergencyAccount) = if (a.userId == "me") seen else 0
        override suspend fun trustedSealed(a: EmergencyAccount) = if (a.userId == "me") trusted else null
        override suspend fun remember(a: EmergencyAccount, version: Long, sealed: String?) {
            check(a.userId == "me") { "roster memory written for ${a.userId}" }
            seen = version
            trusted = sealed
        }
    }

    private val client = EmergencyClient(env)

    private fun grantJson(id: String, vararg extra: Pair<String, JsonElement>): MutableMap<String, JsonElement> = mutableMapOf(
        "id" to JsonPrimitive(id),
        "status" to JsonPrimitive("approved"),
        "wait_days" to JsonPrimitive(7),
        "created_at" to JsonPrimitive(1),
        "updated_at" to JsonPrimitive(1),
        "requested_at" to JsonNull,
        "approved_at" to JsonNull,
        "auto_approve_at" to JsonNull,
        "grantor" to person("me", "me@example.com", "Me", "pk-me"),
        "grantee" to person("u-$id", "$id@example.com", "Name $id", "pk-$id"),
        "key_version" to JsonPrimitive(2),
        "grantor_key" to JsonPrimitive("gk:$id:100"),
        "reconfirm" to JsonPrimitive(false),
        "v1_exposed" to JsonPrimitive(false),
        "missing_vaults" to buildJsonArray { add(JsonPrimitive("v1")) },
    ).apply { putAll(extra) }

    private fun person(id: String, email: String, name: String, pk: String) = buildJsonObject {
        put("id", id); put("email", email); put("name", name); put("public_key", pk)
    }

    private fun readGrant(m: Map<String, JsonElement>) = Emergency.readGrant(JsonObject(m))!!

    private fun sealRoster(version: Long, accesses: List<RosterEntry>, removed: List<RemovedEntry> = emptyList()) =
        account.sealRoster(Emergency.rosterJson(Roster(version, accesses, removed)))

    private fun serverRoster(): Roster = Emergency.readRoster(account.openRoster(server.roster!!))!!

    private fun entry(id: String, name: String? = null, grantorKey: String = "gk:$id:100") =
        RosterEntry(id, "pk-$id", Emergency.sha256b64(grantorKey), name?.let { "$id@example.com" }, name)

    private suspend fun expectFailure(contains: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            assertTrue("\"${e.message}\" should contain \"$contains\"", e.message.orEmpty().contains(contains))
            return
        }
        fail("expected a failure containing \"$contains\"")
    }

    @Before
    fun reset() {
        seen = 0
        trusted = null
    }

    @Test
    fun dropsAnAccessTheContactEndedForGood() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(1, listOf(entry("g1", "Name g1")))
        server.rosterSeq = 1
        client.fillEmergencyKeys()
        assertEquals(listOf("g1"), server.fills)
        // The contact stepped down: the server no longer lists the access, and the next fill takes it out of the roster.
        server.grants = mutableListOf()
        server.fills.clear()
        client.fillEmergencyKeys()
        val hash = Emergency.sha256b64("gk:g1:100")
        assertEquals(Roster(2, emptyList(), listOf(RemovedEntry("g1", hash))), serverRoster())
        // A server that lists it again, with its old key and vaults to wrap, gets nothing, and it can't be confirmed again.
        server.grants = mutableListOf(grantJson("g1"))
        client.fillEmergencyKeys()
        assertEquals(emptyList<String>(), server.fills)
        val state = client.rosterState()
        assertEquals(listOf(true, false), listOf("g1" in state.removed, "g1" in state.confirmAgain))
        expectFailure("was removed from your emergency contacts") { client.confirmAgain(readGrant(grantJson("g1"))) }
    }

    @Test
    fun keepsAContactTheGrantorRemovedOutEvenWhenTheServerListsThemAgain() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"), grantJson("g2"))
        server.roster = sealRoster(1, listOf(entry("g1", "Name g1"), entry("g2", "Name g2")))
        server.rosterSeq = 1
        client.removeContact(readGrant(grantJson("g1")))
        assertEquals(listOf(RemovedEntry("g1", Emergency.sha256b64("gk:g1:100"))), serverRoster().removed)
        assertEquals(listOf("g2"), serverRoster().accesses.map { it.id })
        // Re-listed (the server keeps the access after all): no fill, no Confirm again, no new confirmation.
        server.grants = mutableListOf(grantJson("g1"), grantJson("g2", "missing_vaults" to JsonArray(emptyList())))
        client.fillEmergencyKeys()
        assertEquals(emptyList<String>(), server.fills)
        assertTrue("g1" in client.rosterState().removed)
        expectFailure("add them as a new contact") { client.confirmAgain(readGrant(grantJson("g1"))) }
        val accepted = grantJson("g1", "status" to JsonPrimitive("accepted"), "grantor_key" to JsonNull)
        server.grants = mutableListOf(accepted, grantJson("g2", "missing_vaults" to JsonArray(emptyList())))
        expectFailure("add them as a new contact") { client.confirmContact(readGrant(accepted)) }
        assertEquals(0, server.confirms)
    }

    @Test
    fun putsAnAccessBackWithConfirmAgainAndRefusesAKeyThisAccountDidntMake() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(2, emptyList())
        server.rosterSeq = 2
        val g = readGrant(grantJson("g1"))
        assertTrue("g1" in client.rosterState().confirmAgain)
        client.confirmAgain(g)
        assertEquals(Roster(3, listOf(entry("g1", "Name g1")), emptyList()), serverRoster())
        client.fillEmergencyKeys()
        assertEquals(listOf("g1"), server.fills)
        // A contact key that changed since the user checked it, or a key not made by this account: refused.
        server.grants = mutableListOf(
            grantJson("g1", "missing_vaults" to JsonArray(emptyList())),
            grantJson("g2", "grantee" to person("u-g2", "g2@example.com", "Name g2", "pk-new")),
        )
        expectFailure("key changed") { client.confirmAgain(readGrant(grantJson("g2"))) }
        server.grants = mutableListOf(grantJson("g1", "missing_vaults" to JsonArray(emptyList())), grantJson("g2", "grantor_key" to JsonPrimitive("gk:someone-else:1")))
        expectFailure("wasn't made by your account") { client.confirmAgain(readGrant(grantJson("g2"))) }
        assertEquals(listOf("g1"), serverRoster().accesses.map { it.id })
    }

    @Test
    fun pointsTheRosterAtTheKeyAnAccessAlreadyHoldsWhenTheConfirmAnswerGotLost() = runBlocking {
        val accepted = grantJson("g1", "status" to JsonPrimitive("accepted"), "grantor_key" to JsonNull)
        server.grants = mutableListOf(accepted)
        // Another try (or another app) confirmed first: the server holds key 99 and refuses this one.
        server.confirmHook = { id ->
            server.grantAt(id).putAll(mapOf("status" to JsonPrimitive("confirmed"), "grantor_key" to JsonPrimitive("gk:g1:99"), "missing_vaults" to JsonArray(emptyList())))
            throw ApiException(409, "conflict", "this emergency contact is confirmed already")
        }
        client.confirmContact(readGrant(accepted))
        assertEquals(listOf(entry("g1", "Name g1", "gk:g1:99")), serverRoster().accesses)
        // Trying again from a page that still shows "accepted": no new key, no new confirmation.
        server.confirmHook = null
        val confirms = server.confirms
        client.confirmContact(readGrant(accepted))
        assertEquals(confirms, server.confirms)
        assertEquals(listOf(entry("g1", "Name g1", "gk:g1:99")), serverRoster().accesses)
    }

    @Test
    fun reviewsAnOlderServerListAgainstThisDevicesOwnAndWritesItForward() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"), grantJson("g2"))
        server.roster = sealRoster(5, listOf(entry("g1", "Sam")))
        server.rosterSeq = 5
        assertNull(client.rosterState().problem)
        // Restored to version 3: g1, g2 (removed since; the server's listing now calls them "Mom") and g4, which it no longer lists.
        server.grants = mutableListOf(grantJson("g1"), grantJson("g2", "grantee" to person("u-g2", "mom@example.com", "Mom", "pk-g2")))
        server.roster = sealRoster(3, listOf(entry("g1", "Sam"), entry("g2", "Eve"), entry("g4", "Ann")))
        server.rosterSeq = 3
        assertEquals("older", client.rosterState().problem)
        val list = client.loadServerRoster()
        assertEquals(
            listOf(listOf("g1", "Sam", "g1@example.com", false), listOf("g2", "Eve", "g2@example.com", true)),
            list.entries.map { listOf(it.entry.id, it.entry.name, it.entry.email, it.wouldReturn) },
        )
        // The master password first; then it is written one version above what this device saw, without g4.
        expectFailure("master password") { client.useServerRoster(list, "wrong") }
        assertEquals(3L, server.rosterSeq)
        client.useServerRoster(list, "right")
        assertEquals(6L, serverRoster().version)
        assertEquals(listOf(entry("g1", "Sam"), entry("g2", "Eve")), serverRoster().accesses)
        assertEquals(listOf("g4"), serverRoster().removed.map { it.id })
        assertNull(client.rosterState().problem)
        // A replay of a version in between is refused from then on.
        server.roster = sealRoster(5, listOf(entry("g1", "Sam")))
        assertEquals("older", client.rosterState().problem)
    }

    @Test
    fun neverWritesAContactTheUserWasntShown() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(5, listOf(entry("g1", "Sam")))
        server.rosterSeq = 5
        client.rosterState()
        // The restored list has C, but the server hides C's access while the dialog loads…
        server.roster = sealRoster(3, listOf(entry("g1", "Sam"), entry("gc", "Carol")))
        server.rosterSeq = 3
        val list = client.loadServerRoster()
        assertEquals(listOf("g1"), list.entries.map { it.entry.id })
        // …and lists it again when the list is written.
        server.grants = mutableListOf(grantJson("g1"), grantJson("gc"))
        client.useServerRoster(list, "right")
        assertEquals(listOf("g1"), serverRoster().accesses.map { it.id })
        assertEquals(listOf("gc"), serverRoster().removed.map { it.id })
        client.fillEmergencyKeys()
        assertFalse("gc" in server.fills)
        assertTrue("gc" in client.rosterState().removed)
    }

    @Test
    fun startsANewListWhenTheServersDoesntOpenKeepingWhoWasRemoved() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"), grantJson("g0"))
        server.roster = sealRoster(4, listOf(entry("g1", "Name g1")), listOf(RemovedEntry("g0", "h-g0")))
        server.rosterSeq = 4
        assertNull(client.rosterState().problem)
        server.roster = "garbage written by someone else"
        server.rosterSeq = 5
        assertEquals("unreadable", client.rosterState().problem)
        client.fillEmergencyKeys()
        assertEquals(emptyList<String>(), server.fills)
        expectFailure("master password") { client.startNewRoster("wrong") }
        client.startNewRoster("right")
        assertEquals(Roster(5, emptyList(), listOf(RemovedEntry("g0", "h-g0"))), serverRoster())
        val state = client.rosterState()
        assertNull(state.problem)
        assertEquals(listOf(true, true, false), listOf("g1" in state.confirmAgain, "g0" in state.removed, "g0" in state.confirmAgain))
    }

    // ------------------------------------------------------ beyond the web's cases

    @Test
    fun confirmsANewContactWithTheRosterFirstThenTheKeysForPersonalVaults() = runBlocking {
        val accepted = grantJson("g1", "status" to JsonPrimitive("accepted"), "grantor_key" to JsonNull)
        server.grants = mutableListOf(accepted)
        var rosterAtConfirm: Roster? = null
        server.confirmHook = { rosterAtConfirm = serverRoster() }
        val g = client.confirmContact(readGrant(accepted))
        assertEquals(GrantStatus.Confirmed, g.status)
        // The roster had the access (contact key, grantor key hash, name and email) before the server got the key.
        assertEquals(listOf(entry("g1", "Name g1", "gk:g1:1")), rosterAtConfirm!!.accesses)
        assertEquals(1, server.confirms)
    }

    @Test
    fun refusesToConfirmWhenAVaultTheServerListsIsntPersonalHere() = runBlocking {
        val accepted = grantJson("g1", "status" to JsonPrimitive("accepted"), "grantor_key" to JsonNull, "missing_vaults" to buildJsonArray { add(JsonPrimitive("v1")); add(JsonPrimitive("v-shared")) })
        server.grants = mutableListOf(accepted)
        expectFailure("couldn't check that every vault") { client.confirmContact(readGrant(accepted)) }
        assertEquals(0, server.confirms)
    }

    /** Review L5 / iOS M4: a vault the server says is this account's alone, but which was shared under a signed roster, isn't personal. */
    @Test
    fun aVaultWithASignedSharingHistoryIsNeverPersonal() = runBlocking {
        signedBefore += "v1"
        val accepted = grantJson("g1", "status" to JsonPrimitive("accepted"), "grantor_key" to JsonNull, "missing_vaults" to buildJsonArray { add(JsonPrimitive("v1")) })
        server.grants = mutableListOf(accepted)
        expectFailure("couldn't check that every vault") { client.confirmContact(readGrant(accepted)) }
        assertEquals(0, server.confirms)
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(1, listOf(entry("g1", "Name g1")))
        server.rosterSeq = 1
        server.deleteAnswer = AppJson.parseToJsonElement("""{"ok":true,"rotation_pending":["v1"]}""")
        assertEquals(Removal(0, null), client.removeContact(readGrant(grantJson("g1"))))
        assertTrue(rotated.isEmpty())
    }

    @Test
    fun removingAContactWhoHeldTheKeyReplacesOnlyPersonalVaultKeys() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(1, listOf(entry("g1", "Name g1")))
        server.rosterSeq = 1
        server.deleteAnswer = AppJson.parseToJsonElement("""{"ok":true,"rotation_pending":["v1","v-shared"]}""")
        val r = client.removeContact(readGrant(grantJson("g1")))
        assertEquals(Removal(1, null), r)
        assertEquals(listOf(listOf("v1")), rotated)
        assertEquals(listOf("g1"), server.deleted)
    }

    @Test
    fun approvingAndShorteningTheWaitSendTheReauthToken() = runBlocking {
        server.grants = mutableListOf(grantJson("g1", "status" to JsonPrimitive("requested")))
        client.approveGrant("g1", "right")
        assertEquals("reauth-token", server.calls.last().third["x-reauth-token"])
        expectFailure("master password") { client.approveGrant("g1", "wrong") }
        client.changeWait("g1", 3, "right")
        assertEquals(Triple("PUT", "/emergency-access/g1", mapOf("x-reauth-token" to "reauth-token")), server.calls.last())
        client.changeWait("g1", 30)
        assertEquals(emptyMap<String, String>(), server.calls.last().third)
    }

    @Test
    fun oneOperationStaysOnTheAccountItStartedOnWhenTheUserSwitchesMidway() = runBlocking {
        val accepted = grantJson("g1", "status" to JsonPrimitive("accepted"), "grantor_key" to JsonNull, "missing_vaults" to buildJsonArray { add(JsonPrimitive("v1")) })
        server.grants = mutableListOf(accepted)
        // Another account becomes active after the first request: the rest of the confirm must not follow it.
        onCall = { active = EmergencyAccount("record-2", "https://pa.example", "someone-else") }
        client.confirmContact(readGrant(accepted))
        onCall = null
        assertEquals(1, server.confirms)
        // The confirm's own requests (before the fill it starts afterwards) all went to the first account.
        val confirmIndex = server.calls.indexOfFirst { it.second.endsWith("/confirm") }
        assertTrue(callAccounts.subList(0, confirmIndex + 1).all { it.record == "record-1" && it.userId == "me" })
        assertTrue(seen > 0)
    }

    @Test
    fun removingReportsVaultsLeftForAnotherApp() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(1, listOf(entry("g1", "Name g1")))
        server.rosterSeq = 1
        server.deleteAnswer = AppJson.parseToJsonElement("""{"ok":true,"rotation_pending":["v1"]}""")
        rotateAnswer = RotationReport(0, unreadable = listOf("Personal"))
        val r = client.removeContact(readGrant(grantJson("g1")))
        assertEquals(0, r.rotated)
        assertTrue(r.leftover!!.contains("Personal"))
    }

    @Test
    fun aFillAskedForDuringARunRunsAgainAndBothCallersReturn() = runBlocking {
        server.grants = mutableListOf(grantJson("g1"))
        server.roster = sealRoster(1, listOf(entry("g1", "Name g1")))
        server.rosterSeq = 1
        var lists = 0
        var second: kotlinx.coroutines.Deferred<Unit>? = null
        onCall = { path ->
            if (path == "/emergency-access") {
                lists++
                if (lists == 1) {
                    second = async { client.fillEmergencyKeys() }
                    // Let the second caller ask while this run is in progress.
                    kotlinx.coroutines.yield()
                }
            }
        }
        client.fillEmergencyKeys()
        second!!.await()
        assertEquals("the fill ran again for the caller who joined", 2, lists)
        // A later fill starts a run of its own (the finished one doesn't swallow it).
        val before = lists
        client.fillEmergencyKeys()
        assertEquals(before + 1, lists)
    }
}
