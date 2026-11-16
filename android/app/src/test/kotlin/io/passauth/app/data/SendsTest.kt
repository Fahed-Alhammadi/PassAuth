package io.passauth.app.data

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Send ([Sends], [SendActions]): the owner-side cases of the web vault's `sends.test.ts`, and the requests against a fake server and the real core. */
class SendsTest {
    private val id = "AbCdEfGhIjKlMnOpQrSt_-"
    private val key = "k".repeat(40) + "_-A"

    @Test
    fun buildsTheLinkWithTheKeyAfterTheHash() {
        assertEquals("https://vault.example.com/send/$id#$key", Sends.link("https://vault.example.com", id, key))
        assertEquals("https://vault.example.com/send/$id#$key", Sends.link("https://vault.example.com/", id, key))
    }

    @Test
    fun hidesTheKeyWhenTheLinkIsShownNeverAnythingBeforeIt() {
        val link = Sends.link("https://vault.example.com", id, key)
        val masked = Sends.maskedLink(link)
        assertTrue(masked.startsWith("https://vault.example.com/send/$id#"))
        assertFalse(masked.contains(key))
        assertFalse(masked.contains(key.take(4)))
        assertEquals("https://vault.example.com/send/x", Sends.maskedLink("https://vault.example.com/send/x"))
    }

    @Test
    fun measuresTheEncryptedTextAsTheServerDoes() {
        // 1 version byte, 24-byte nonce, the text, 16-byte tag, in unpadded base64url.
        assertEquals(Math.ceil(41 * 4 / 3.0).toInt(), Sends.encryptedFieldLength(0))
        assertEquals(Math.ceil(46 * 4 / 3.0).toInt(), Sends.encryptedFieldLength(5))
        assertEquals(6, Sends.utf8Length("héllo"))
    }

    @Test
    fun knowsTheMostTextThatFits() {
        val max = Sends.maxTextBytes(Sends.DEFAULT_MAX_BYTES)
        assertTrue(Sends.encryptedFieldLength(max) <= Sends.DEFAULT_MAX_BYTES)
        assertTrue(Sends.encryptedFieldLength(max + 1) > Sends.DEFAULT_MAX_BYTES)
        assertEquals(0, Sends.maxTextBytes(10))
    }

    @Test
    fun readsTheLimitsFromApiConfigElseTheServersDefaults() {
        assertEquals(Sends.Limits(7, 2048), Sends.limits(AppJson.parseToJsonElement("""{"send_max_days":7,"send_max_bytes":2048}""")))
        assertEquals(Sends.Limits(30, Sends.DEFAULT_MAX_BYTES), Sends.limits(null))
        assertEquals(Sends.Limits(30, Sends.DEFAULT_MAX_BYTES), Sends.limits(AppJson.parseToJsonElement("""{"send_max_days":0,"send_max_bytes":"x"}""")))
    }

    @Test
    fun offersWhatTheServerAllowsAndItsLimit() {
        assertEquals(listOf("1 hour", "1 day", "2 days", "3 days", "7 days", "14 days", "30 days"), Sends.durationChoices(30).map { it.second })
        assertEquals(listOf("1 hour", "1 day", "2 days", "3 days", "7 days", "10 days"), Sends.durationChoices(10).map { it.second })
        assertEquals(listOf("1 hour", "1 day"), Sends.durationChoices(1).map { it.second })
        assertEquals(365 * 86400L to "365 days", Sends.durationChoices(365).last())
    }

    @Test
    fun deletesAfter7DaysByDefaultOrSoonerWhenTheServerSaysSo() {
        assertEquals(7 * 86400L, Sends.defaultDeletion(30))
        assertEquals(3 * 86400L, Sends.defaultDeletion(3))
    }

    private val raw = """{"id":"$id","path":"/send/$id","kind":"text","name":"enc-name","owner_key":"wrapped","size":100,"has_password":true,
        "access_salt":"sendpw-v1${'$'}m=131072,t=3,p=1${'$'}abc","max_views":5,"views":2,"expires_at":2000,"delete_at":3000,"disabled":false,
        "hide_email":true,"available":true,"created_at":100,"updated_at":200}"""

    @Test
    fun readsTheOwnersSends() {
        val s = Sends.read(AppJson.parseToJsonElement(raw))!!
        assertEquals(id, s.id)
        assertEquals("enc-name", s.name)
        assertEquals("wrapped", s.ownerKey)
        assertTrue(s.hasPassword)
        assertEquals(5L, s.maxViews)
        assertEquals(2L, s.views)
        assertEquals(2000L, s.expiresAt)
        assertEquals(3000L, s.deleteAt)
        assertTrue(s.hideEmail)
        assertNull(s.data)
        val withData = raw.replace("\"kind\"", "\"data\":\"enc-text\",\"kind\"")
        assertEquals("enc-text", Sends.read(AppJson.parseToJsonElement(withData))!!.data)
        assertEquals(1, Sends.readList(AppJson.parseToJsonElement("""{"sends":[$raw,{"id":"x"},null]}""")).size)
        assertEquals(emptyList<OwnedSend>(), Sends.readList(AppJson.parseToJsonElement("{}")))
    }

    @Test
    fun saysWhetherTheyCanBeOpened() {
        val s = Sends.read(AppJson.parseToJsonElement(raw))!!
        assertEquals(SendState.Available, Sends.state(s, 1000))
        assertEquals(SendState.Disabled, Sends.state(s.copy(disabled = true), 1000))
        assertEquals(SendState.Expired, Sends.state(s, 2000))
        assertEquals(SendState.UsedUp, Sends.state(s.copy(views = 5), 1000))
        assertEquals(SendState.Deleted, Sends.state(s, 3000))
        assertEquals(SendState.Unavailable, Sends.state(s.copy(available = false), 1000))
        assertEquals("Active", SendState.Available.label)
        assertEquals("Turned off", SendState.Disabled.label)
    }

    @Test
    fun countsViews() {
        assertEquals("Not opened yet", Sends.viewsText(0, null))
        assertEquals("Opened 1 time", Sends.viewsText(1, null))
        assertEquals("Opened 2 of 5 times", Sends.viewsText(2, 5))
        assertEquals("Opened 0 of 1 time", Sends.viewsText(0, 1))
    }

    private fun obj(vararg p: Pair<String, JsonElement>) = JsonObject(mapOf(*p))

    @Test
    fun sendsOnlyWhatChanged() {
        assertEquals(obj(), Sends.changesBody(SendChanges()))
        assertEquals(obj("name" to JsonPrimitive("n"), "disabled" to JsonPrimitive(true)), Sends.changesBody(SendChanges(name = "n", disabled = true)))
        assertEquals(
            obj("access_salt" to JsonPrimitive("s"), "access_verifier" to JsonPrimitive("v")),
            Sends.changesBody(SendChanges(password = SendPassword.Set("s", "v"))),
        )
        assertEquals(
            obj("access_verifier" to JsonNull, "max_views" to JsonNull, "expires_at" to JsonNull),
            Sends.changesBody(SendChanges(password = SendPassword.Remove, maxViews = Change(null), expiresAt = Change(null))),
        )
        assertEquals(
            obj("data" to JsonPrimitive("d"), "delete_at" to JsonPrimitive(5), "hide_email" to JsonPrimitive(false)),
            Sends.changesBody(SendChanges(deleteAt = 5, hideEmail = false, data = "d")),
        )
    }

    // ------------------------------------------- requests, with the real core

    /** A fake account key wrap around the core's real Send encryption. */
    private class Crypto : SendCrypto {
        var saltsMade = 0
        override fun newKey() = io.passauth.core.sendNewKey()
        override fun encrypt(key: String, field: String, plain: String) = io.passauth.core.sendEncrypt(key, field, plain)
        override fun decrypt(key: String, field: String, cipher: String) = io.passauth.core.sendDecrypt(key, field, cipher)
        override fun wrap(key: String) = "wrapped:$key"
        override fun unwrap(wrapped: String) = wrapped.removePrefix("wrapped:")
        override fun passwordSalt(): String {
            saltsMade++
            return "salt-$saltsMade"
        }
        override fun verifier(password: String, salt: String) = "v($password,$salt)"
    }

    @Test
    fun createsEncryptsAndEditsOnlyWhatChanged() = runBlocking {
        val crypto = Crypto()
        val calls = mutableListOf<Triple<String, String, JsonElement?>>()
        var stored: JsonObject? = null
        val transport = SecurityTransport { path, body, method, _, _ ->
            calls += Triple(method, path, body)
            when (method) {
                "POST" -> {
                    stored = JsonObject((body as JsonObject) + mapOf("id" to JsonPrimitive(id), "delete_at" to body["delete_at"]!!))
                    stored!!
                }
                "PUT" -> JsonObject(stored!! + (body as JsonObject))
                else -> JsonNull
            }
        }
        val actions = SendActions(transport) { crypto }
        val (send, sendKey) = actions.create(NewSend("Wi-Fi", "hunter2", "pw", 3, null, 5000, true))
        val body = calls[0].third as JsonObject
        assertEquals("text", (body["kind"] as JsonPrimitive).content)
        assertEquals("wrapped:$sendKey", (body["owner_key"] as JsonPrimitive).content)
        assertEquals("salt-1", (body["access_salt"] as JsonPrimitive).content)
        assertEquals("v(pw,salt-1)", (body["access_verifier"] as JsonPrimitive).content)
        assertEquals(JsonNull, body["expires_at"])
        assertEquals(JsonPrimitive(3), body["max_views"])
        // The server gets ciphertext only; the owner reads it back with the wrapped key.
        assertFalse(body.toString().contains("hunter2"))
        assertEquals("Wi-Fi", actions.nameOf(send))
        assertEquals("hunter2", actions.textOf(send.copy(data = (body["data"] as JsonPrimitive).content)))
        // A change sends only what changed, encrypted with the same key (the link has it).
        actions.update(send, SendEdit(text = "new text", password = "", disabled = true))
        val change = calls[1].third as JsonObject
        assertEquals(setOf("data", "access_verifier", "disabled"), change.keys)
        assertEquals(JsonNull, change["access_verifier"])
        assertEquals("new text", io.passauth.core.sendDecrypt(sendKey, "data", (change["data"] as JsonPrimitive).content))
        assertEquals("PUT", calls[1].first)
        assertEquals("/sends/$id", calls[1].second)
    }

    @Test
    fun aSendMadeWithAnotherAccountKeyHasNoName() {
        val actions = SendActions({ _, _, _, _, _ -> JsonNull }) { Crypto() }
        val s = OwnedSend(id, "not-a-ciphertext", "wrapped:" + io.passauth.core.sendNewKey(), deleteAt = 1)
        assertNull(actions.nameOf(s))
    }

    @Test
    fun anAlreadyDeletedSendCountsAsDeleted() = runBlocking {
        val actions = SendActions({ _, _, _, _, _ -> throw ApiException(404, "not_found", "gone") }) { Crypto() }
        actions.delete(id)
    }
}
