package io.passauth.app.data

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Vault invitations (Invitations.kt): reading `/sync` leniently, keeping them with the copy through
 * full, delta and local changes, the wording, and answering them against a scripted server. The
 * same cases as the iOS `InvitationsTests` and the web vault's `invitations.test.ts`.
 */
class InvitationsTest {
    private val bundle = """"bundle":{"account_id":"acc","secret_key_enabled":false},"user":{"name":"Alex"}"""

    private fun invitationJson(vault: String, by: String? = """{"id":"u2","email":"sam@example.com","name":"Sam Lee","public_key":"pk"}""") =
        """{"vault_id":"$vault","role":"write","wrapped_key":"sealed-$vault","meta":"meta-$vault","invited_by":${by ?: "null"},"invited_at":1762000000}"""

    private fun answer(json: String): SyncResponse = DeltaSync.parse(json)!!

    private fun inv(name: String? = "Family", by: InvitedBy? = InvitedBy("u2", "sam@example.com", "Sam Lee", "pk"), role: String = "write", at: Long? = 1_762_000_000) =
        Invitation("v1", role, name, by, at)

    // ------------------------------------------------------------- reading

    @Test
    fun readsInvitationsAndDropsMalformedOnes() {
        val list = Invitations.read(
            AppJson.parseToJsonElement(
                "[" + listOf(
                    invitationJson("v1"),
                    invitationJson("v1"), // the same vault twice: counted once
                    """{"vault_id":"v2","role":"read","wrapped_key":"","meta":"m"}""", // no sealed key
                    """{"vault_id":"v3","role":"read","wrapped_key":"w","meta":7}""", // name not a string
                    """{"vault_id":"v4","wrapped_key":"w","meta":"m"}""", // no role
                    """{"role":"read","wrapped_key":"w","meta":"m"}""", // no vault
                    "\"text\"",
                    """{"vault_id":"v5","role":"owner-to-be","wrapped_key":"w","meta":"m","invited_by":{"email":"x@y.z"},"invited_at":"soon"}""",
                    invitationJson("v6", by = null),
                ).joinToString(",") + "]",
            ),
        )
        assertEquals(listOf("v1", "v5", "v6"), list.map { it.vaultId })
        val first = list[0]
        assertEquals(InvitedBy("u2", "sam@example.com", "Sam Lee", "pk"), first.invitedBy)
        assertEquals(1_762_000_000L, first.invitedAt)
        assertEquals("sealed-v1", first.wrappedKey)
        // An unknown role is kept (so it can be answered); invited_by without an id and a text date are dropped.
        assertEquals("owner-to-be", list[1].role)
        assertNull(list[1].invitedBy)
        assertNull(list[1].invitedAt)
        assertNull(list[2].invitedBy)
        // Servers without invitations: none.
        assertEquals(emptyList<SyncInvitation>(), Invitations.read(null))
        assertEquals(emptyList<SyncInvitation>(), Invitations.read(buildJsonObject { put("vault_id", "v1") }))
    }

    @Test
    fun aBadInvitationNeverMakesTheSyncUnreadable() {
        val r = answer("""{"revision":3,"cursor":"c",$bundle,"vaults":[],"items":[],"invitations":[{"vault_id":5},${invitationJson("v1")}]}""")
        val snap = SyncMerge.apply(r, null)!!
        assertEquals(listOf("v1"), snap.invitations.map { it.vaultId })
        // Not a list at all: no invitations, the vault still syncs.
        val odd = SyncMerge.apply(answer("""{"revision":3,$bundle,"vaults":[],"items":[],"invitations":{"v1":true}}"""), null)!!
        assertEquals(emptyList<SyncInvitation>(), odd.invitations)
    }

    // ---------------------------------------------------------------- merge

    @Test
    fun everyAnswerReplacesTheList() {
        val full = SyncMerge.apply(answer("""{"revision":3,"cursor":"c1",$bundle,"vaults":[],"items":[],"invitations":[${invitationJson("v1")},${invitationJson("v2")}]}"""), null)!!
        assertEquals(listOf("v1", "v2"), full.invitations.map { it.vaultId })
        // A delta lists them in full too: v1 accepted (gone), v3 new.
        val delta = SyncMerge.apply(
            answer("""{"delta":true,"revision":4,"cursor":"c2",$bundle,"vaults":[],"items":[],"deleted":[],"reset":[],"invitations":[${invitationJson("v2")},${invitationJson("v3")}]}"""),
            full,
        )!!
        assertEquals(listOf("v2", "v3"), delta.invitations.map { it.vaultId })
        // An answer without the list (a server without invitations) leaves none.
        val older = SyncMerge.apply(answer("""{"delta":true,"revision":5,"cursor":"c3",$bundle,"vaults":[],"items":[],"deleted":[],"reset":[]}"""), delta)!!
        assertEquals(emptyList<SyncInvitation>(), older.invitations)
    }

    @Test
    fun localChangesKeepTheListAndTheCopyStoresIt() {
        val vault = SyncVault("A", "m", "owner", "w", "account", null, 0, 3)
        val row = SyncItem("1", "A", "k", "d", 1)
        val snap = SyncSnapshot(10, "c1", null, buildJsonObject { put("account_id", "acc") }, listOf(vault), listOf(row), Invitations.read(AppJson.parseToJsonElement("[${invitationJson("v9")}]")))
        val next = SyncMerge.applyLocal(LocalChange.Put(SyncItem("2", "A", "k2", "d2", 2)), "A", 4, snap)!!
        assertEquals(snap.invitations, next.invitations)
        // The stored copy keeps them (and reads them back), and a copy from before them reads as none.
        val stored = SyncSnapshot.decode(next.encode())!!
        assertEquals(snap.invitations, stored.invitations)
        val old = SyncSnapshot.decode("""{"revision":10,"cursor":"c1","bundle":{"account_id":"acc"},"vaults":[],"items":[]}""")!!
        assertEquals(emptyList<SyncInvitation>(), old.invitations)
    }

    // ---------------------------------------------------------- opening

    @Test
    fun openedNamesAndInvitationsThatCantBeOpened() {
        val list = Invitations.read(AppJson.parseToJsonElement("[${invitationJson("v1")},${invitationJson("v2")},${invitationJson("v3")}]"))
        val opened = Invitations.open(list) { i ->
            when (i.vaultId) {
                "v1" -> "Family"
                "v2" -> null
                else -> error("can't open")
            }
        }
        assertEquals(listOf("Family", null, null), opened.map { it.name })
        assertEquals(listOf("v1", "v2", "v3"), opened.map { it.vaultId })
        assertEquals("write", opened[0].role)
        // The name from the decrypted meta: a non-blank name, else "Shared vault".
        assertEquals("Family", Invitations.nameOf(AppJson.parseToJsonElement("""{"name":"Family"}""")))
        assertEquals("Shared vault", Invitations.nameOf(AppJson.parseToJsonElement("""{"name":"  "}""")))
        assertEquals("Shared vault", Invitations.nameOf(AppJson.parseToJsonElement("""{"name":5}""")))
        assertEquals("Shared vault", Invitations.nameOf(AppJson.parseToJsonElement("\"x\"")))
        // The name cache is keyed by vault, sealed key and encrypted name.
        assertTrue(Invitations.cacheKey(list[0]) != Invitations.cacheKey(list[0].copy(meta = "renamed")))
    }

    // -------------------------------------------------------------- wording

    @Test
    fun wordingLikeTheWebVault() {
        val i = inv()
        assertEquals("Sam Lee (sam@example.com)", InvitationText.sharerName(i))
        assertEquals("Sam Lee", InvitationText.sharerShort(i))
        assertEquals("sam@example.com", InvitationText.sharerName(inv(by = InvitedBy("u2", "sam@example.com", " ", ""))))
        assertEquals("Someone on this server", InvitationText.sharerName(inv(by = InvitedBy("u2"))))
        assertEquals("Someone whose account was deleted", InvitationText.sharerName(inv(by = null)))
        assertEquals("the person who shared it", InvitationText.sharerShort(inv(by = null)))
        assertEquals("From Sam Lee (sam@example.com), DATE", InvitationText.fromLine(i) { "DATE" })
        assertEquals("From Sam Lee (sam@example.com)", InvitationText.fromLine(inv(at = null)) { "DATE" })
        assertEquals(listOf("Owner", "Admin", "Can edit", "Can view", "auditor"), listOf("owner", "admin", "write", "read", "auditor").map(InvitationText::roleLabel))
        assertEquals("Invitation that can't be opened", InvitationText.title(inv(name = null)))
        // The fingerprint is the one the server lists for the sharer: never presented as proof of who sent it.
        assertEquals("Fingerprint your server lists for sam@example.com", InvitationText.fingerprintLabel(i))
        assertEquals("Fingerprint your server lists for Sam", InvitationText.fingerprintLabel(inv(by = InvitedBy("u2", "", "Sam", ""))))
        assertEquals("Fingerprint your server lists for the person who shared it", InvitationText.fingerprintLabel(inv(by = InvitedBy("u2"))))
        assertEquals("Accept only invitations you expected.", InvitationText.EXPECTED)
        assertEquals("A vault shared with you appears in your apps only after you accept it.", InvitationText.INTRO)
        assertEquals(
            "Your account's keys can't open this invitation, so PassAuth can't show the vault's name. Decline it, then ask Sam Lee to share the vault again.",
            InvitationText.cantOpen(i),
        )
        assertEquals(
            "The account that shared this vault no longer exists. Accept only invitations you expected.",
            InvitationText.noFingerprint(inv(by = null)),
        )
        assertEquals(
            "Your server didn't list a key for Sam Lee, so PassAuth can't show a fingerprint. Accept only invitations you expected.",
            InvitationText.noFingerprint(i),
        )
        assertEquals("Accept \"Family\"?", InvitationText.acceptTitle(i))
        assertEquals("Shared by Sam Lee (sam@example.com)", InvitationText.acceptSubtitle(i))
        assertEquals(
            "The vault and its items appear in all your apps. You'll be able to view and edit its items. The people who manage it can add and change items in it.",
            InvitationText.acceptBody(i),
        )
        assertEquals(
            "The vault and its items appear in all your apps. The people who manage it can add and change items in it.",
            InvitationText.acceptBody(inv(role = "owner")),
        )
        assertEquals("You joined \"Family\".", InvitationText.joined(i))
        assertEquals("Family", InvitationText.declineSubtitle(i))
        assertEquals("From Someone whose account was deleted", InvitationText.declineSubtitle(inv(name = null, by = null)))
    }

    @Test
    fun noticeAndItsKey() {
        assertNull(InvitationText.notice(emptyList()))
        assertEquals(
            "Sam Lee invited you to the shared vault \"Family\". Nothing from it reaches your apps until you accept.",
            InvitationText.notice(listOf(inv())),
        )
        assertEquals(
            "Someone invited you to a shared vault. Nothing from it reaches your apps until you accept.",
            InvitationText.notice(listOf(inv(name = null, by = null))),
        )
        val two = listOf(inv(), inv().copy(vaultId = "v0"))
        assertEquals("You have 2 invitations to shared vaults. Nothing from them reaches your apps until you accept.", InvitationText.notice(two))
        assertEquals("See the invitation", InvitationText.noticeAction(listOf(inv())))
        assertEquals("See the invitations", InvitationText.noticeAction(two))
        // Order doesn't matter; a new invitation changes the key (a dismissed notice comes back).
        assertEquals("v0,v1", InvitationText.noticeKey(two))
        assertEquals("v0,v1", InvitationText.noticeKey(two.reversed()))
        assertTrue(InvitationText.noticeKey(two) != InvitationText.noticeKey(two + inv().copy(vaultId = "v2")))
    }

    // ------------------------------------------------- against a scripted server

    private class Server(val answers: Map<String, () -> JsonElement>) : SecurityTransport {
        val log = mutableListOf<String>()
        val authed = mutableListOf<Boolean>()
        override suspend fun call(path: String, body: JsonElement?, method: String, auth: Boolean, headers: Map<String, String>): JsonElement {
            log += "$method $path"
            authed += auth
            return (answers["$method $path"] ?: error("unexpected $method $path"))()
        }
    }

    private val notFound = { throw ApiException(404, "not_found", "not found") }

    @Test
    fun acceptThenSync() = runBlocking {
        var syncs = 0
        val server = Server(mapOf("POST /vaults/v1/invitation/accept" to { JsonObject(mapOf()) }))
        InvitationActions(server) { syncs++ }.accept("v1")
        assertEquals(listOf("POST /vaults/v1/invitation/accept"), server.log)
        assertEquals(listOf(true), server.authed)
        assertEquals("the vault arrives with the next sync", 1, syncs)
    }

    @Test
    fun acceptingAnInvitationThatIsGoneRefreshesAndSaysSo() {
        var syncs = 0
        val server = Server(mapOf("POST /vaults/v1/invitation/accept" to notFound))
        val e = assertThrows(UserException::class.java) { runBlocking { InvitationActions(server) { syncs++ }.accept("v1") } }
        assertEquals(InvitationText.NO_LONGER_OPEN, e.message)
        assertEquals(1, syncs)
        // A refresh that fails too doesn't hide why.
        val e2 = assertThrows(UserException::class.java) {
            runBlocking { InvitationActions(server) { throw UserException(UNREACHABLE) }.accept("v1") }
        }
        assertEquals(InvitationText.NO_LONGER_OPEN, e2.message)
        // Other errors stand, and nothing syncs.
        syncs = 0
        val denied = Server(mapOf("POST /vaults/v1/invitation/accept" to { throw ApiException(403, "forbidden", "no") }))
        assertThrows(ApiException::class.java) { runBlocking { InvitationActions(denied) { syncs++ }.accept("v1") } }
        assertEquals(0, syncs)
    }

    @Test
    fun declineAlreadyGoneIsFineAndSyncs() = runBlocking {
        var syncs = 0
        val gone = Server(mapOf("DELETE /vaults/v%201/invitation" to notFound))
        InvitationActions(gone) { syncs++ }.decline("v 1")
        assertEquals(listOf("DELETE /vaults/v%201/invitation"), gone.log)
        assertEquals(1, syncs)
        val ok = Server(mapOf("DELETE /vaults/v1/invitation" to { JsonObject(mapOf()) }))
        InvitationActions(ok) { syncs++ }.decline("v1")
        assertEquals(2, syncs)
    }
}
