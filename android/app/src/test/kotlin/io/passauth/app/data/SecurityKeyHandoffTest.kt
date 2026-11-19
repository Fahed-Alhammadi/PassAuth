package io.passauth.app.data

import io.passauth.app.data.SecurityKeyHandoff.Callback
import io.passauth.app.data.SecurityKeyHandoff.b64urlDecode
import io.passauth.app.data.SecurityKeyHandoff.b64urlEncode
import io.passauth.app.ui.auth.twoStepChoices
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Two-step sign-in with a security key through the server's key page (SecurityKeyHandoff.kt). */
class SecurityKeyHandoffTest {
    private val challenge = ByteArray(32) { (it * 7 + 1).toByte() }
    private val challengeB64 = b64urlEncode(challenge)
    private val state = "AAECAwQFBgcICQoLDA0ODw"
    private val server = "https://vault.example.com"

    private fun options(rpId: String = "vault.example.com", c: String = challengeB64) = AppJson.parseToJsonElement(
        """{"publicKey":{"challenge":"$c","timeout":60000,"rpId":"$rpId","allowCredentials":[{"type":"public-key","id":"AQID"}],"userVerification":"preferred"}}""",
    ).jsonObject

    private fun credential(c: ByteArray = challenge, type: String = "webauthn.get"): String {
        val clientData = b64urlEncode("""{"type":"$type","challenge":"${b64urlEncode(c)}","origin":"https://vault.example.com"}""".toByteArray())
        return """{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"$clientData","authenticatorData":"AA","signature":"AA","userHandle":null},"clientExtensionResults":{}}"""
    }

    private fun callback(fragment: String) = "passauth://two-step-key#$fragment"
    private fun withCredential(json: String, s: String = state) = callback("v=1&state=$s&credential=${b64urlEncode(json.toByteArray())}")
    private fun cancelled(s: String = state) = callback("v=1&state=$s&error=cancelled")

    // ------------------------------------------------------------ the URL the app opens

    @Test
    fun keyPageUrlCarriesTheOptionsInTheFragment() {
        val r = SecurityKeyHandoff.request(options(), "https://vault.example.com/two-step/key", server, state)
        assertNotNull(r)
        assertArrayEquals(challenge, r!!.challenge)
        assertEquals(state, r.state)
        val (page, fragment) = r.url.split('#', limit = 2)
        assertEquals("https://vault.example.com/two-step/key", page)
        val parts = fragment.split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
        assertEquals(setOf("v", "options", "return", "state"), parts.keys)
        assertEquals(state, parts["state"])
        assertEquals("1", parts["v"])
        assertEquals("app", parts["return"])
        val sent = AppJson.parseToJsonElement(b64urlDecode(parts["options"]!!)!!.decodeToString())
        assertEquals(options(), sent)
        // base64url without padding: nothing in the fragment needs escaping.
        assertTrue(Regex("[A-Za-z0-9_-]+").matches(parts["options"]!!))
    }

    @Test
    fun keyPageMustBeHttpsOnTheRelyingPartysHost() {
        val o = options()
        assertNotNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://VAULT.example.com/two-step/key"))
        assertNotNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://vault.example.com:8443/pa/two-step/key"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "http://vault.example.com/two-step/key"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://evil.example.com/two-step/key"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://sub.vault.example.com/two-step/key"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://vault.example.com.evil.net/two-step/key"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://user@vault.example.com/two-step/key"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://vault.example.com/two-step/key#x"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "https://vault.example.com/two-step/key?next=x"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = "javascript:alert(1)"))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = null))
        assertNull(SecurityKeyHandoff.request(o, server = server, keyPage = ""))
        // Pinned to the server the app signs in to (host only, any case, ports ignored).
        assertNotNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", "https://VAULT.example.com:8443/"))
        assertNotNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", "http://vault.example.com:8080"))
        assertNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", "https://other.example.com"))
        assertNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", "https://example.com"))
        assertNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", ""))
        // A state that isn't 22–64 base64url characters opens nothing.
        assertNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", server, "short"))
        assertNull(SecurityKeyHandoff.request(o, "https://vault.example.com/two-step/key", server, "AAECAwQFBgcICQoLDA0OD+"))
        // Options without a relying party or challenge are never opened.
        assertNull(SecurityKeyHandoff.request(options(rpId = ""), "https://vault.example.com/two-step/key", server))
        assertNull(SecurityKeyHandoff.request(options(c = ""), "https://vault.example.com/two-step/key", server))
        assertNull(SecurityKeyHandoff.request(JsonObject(emptyMap()), "https://vault.example.com/two-step/key", server))
    }

    @Test
    fun bareOptionsObjectIsReadToo() {
        val bare = options()["publicKey"]!!.jsonObject
        val r = SecurityKeyHandoff.request(bare, "https://vault.example.com/two-step/key", server)
        assertNotNull(r)
        assertArrayEquals(challenge, r!!.challenge)
    }

    @Test
    fun eachHandOffGetsA16ByteRandomState() {
        val a = SecurityKeyHandoff.newState()
        assertEquals(22, a.length)
        assertTrue(SecurityKeyHandoff.validState(a))
        assertEquals(16, b64urlDecode(a)!!.size)
        assertTrue(a != SecurityKeyHandoff.newState())
        val r1 = SecurityKeyHandoff.request(options(), "https://vault.example.com/two-step/key", server)!!
        val r2 = SecurityKeyHandoff.request(options(), "https://vault.example.com/two-step/key", server)!!
        assertTrue(r1.state != r2.state)
        assertTrue(r1.url.endsWith("&state=${r1.state}"))
    }

    // ------------------------------------------------------------ the callback

    @Test
    fun credentialForTheOpenedChallengeIsAccepted() {
        val r = SecurityKeyHandoff.parseCallback(withCredential(credential()), challenge, state)
        assertTrue(r is Callback.Credential)
        assertEquals(AppJson.parseToJsonElement(credential()), (r as Callback.Credential).json)
    }

    @Test
    fun anotherChallengeOrCeremonyIsIgnored() {
        val other = challenge.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertSame(Callback.Invalid, SecurityKeyHandoff.parseCallback(withCredential(credential(other)), challenge, state))
        assertSame(Callback.Invalid, SecurityKeyHandoff.parseCallback(withCredential(credential(type = "webauthn.create")), challenge, state))
        assertSame(Callback.Invalid, SecurityKeyHandoff.parseCallback(withCredential(credential()), ByteArray(0), state))
        assertSame(Callback.Invalid, SecurityKeyHandoff.parseCallback(withCredential("""{"response":{}}"""), challenge, state))
        assertSame(Callback.Invalid, SecurityKeyHandoff.parseCallback(withCredential("not json"), challenge, state))
    }

    @Test
    fun cancelIsAnError() {
        assertSame(Callback.Cancelled, SecurityKeyHandoff.parseCallback(cancelled(), challenge, state))
    }

    @Test
    fun malformedCallbacksAreIgnored() {
        val cred = b64urlEncode(credential().toByteArray())
        listOf(
            null,
            "",
            "passauth://two-step-key",
            "passauth://two-step-key#",
            "passauth://two-step-key#credential=$cred",
            "passauth://two-step-key#v=2&credential=$cred",
            "passauth://two-step-key#v=1&credential=$cred&error=cancelled",
            "passauth://two-step-key#v=1&v=1&credential=$cred",
            "passauth://two-step-key#v=1&credential=$cred&credential=$cred",
            "passauth://two-step-key#v=1&credential=not+base64!",
            "passauth://other#v=1&credential=$cred",
            "passauth://two-step-key/x#v=1&credential=$cred",
            "https://two-step-key#v=1&credential=$cred",
            "otpauth://two-step-key#v=1&credential=$cred",
        ).forEach { assertSame(it, Callback.Invalid, SecurityKeyHandoff.parseCallback(it, challenge, state)) }
    }

    // ------------------------------------------------------------ waiting

    @Test
    fun aCallbackFinishesTheWaitOnceAndOnlyWhileWaiting() = runBlocking {
        val w = SecurityKeyHandoff.Waiter()
        assertFalse("nothing waits", w.deliver(withCredential(credential())))
        val p = w.begin(challenge, state)
        assertTrue(w.waiting())
        assertFalse("another challenge is ignored", w.deliver(withCredential(credential(ByteArray(32)))))
        assertTrue(w.waiting())
        assertTrue(w.deliver(withCredential(credential())))
        assertFalse("only once", w.deliver(withCredential(credential())))
        assertFalse(w.waiting())
        assertTrue(p.await() is Callback.Credential)
    }

    @Test
    fun cancellingAndRestartingEndTheEarlierWait() = runBlocking {
        val w = SecurityKeyHandoff.Waiter()
        val first = w.begin(challenge, state)
        val second = w.begin(ByteArray(32) { 9 }, "BBECAwQFBgcICQoLDA0ODw")
        assertSame(Callback.Cancelled, first.await())
        // The first start's callback no longer counts.
        assertFalse(w.deliver(withCredential(credential())))
        w.cancel(first) // stale: doesn't touch the second wait
        assertTrue(w.waiting())
        w.cancel(second)
        assertFalse(w.waiting())
        assertSame(Callback.Cancelled, second.await())
        assertFalse(w.deliver(withCredential(credential(ByteArray(32) { 9 }))))
        assertFalse(w.deliver(withCredential(credential(ByteArray(32) { 9 }), "BBECAwQFBgcICQoLDA0ODw")))
    }

    @Test
    fun cancelFromThePageEndsTheWait() = runBlocking {
        val w = SecurityKeyHandoff.Waiter()
        val p = w.begin(challenge, state)
        assertFalse("another state", w.deliver(cancelled("BBECAwQFBgcICQoLDA0ODw")))
        assertFalse("no state", w.deliver(callback("v=1&error=cancelled")))
        assertTrue(w.waiting())
        assertTrue(w.deliver(cancelled()))
        assertSame(Callback.Cancelled, p.await())
    }

    // ------------------------------------------------------------ method list

    @Test
    fun securityKeysAreOfferedOnlyWithTheKeyPage() {
        assertEquals(listOf("totp", "recovery"), twoStepChoices(listOf("totp", "passkey", "recovery"), keyPage = false))
        assertEquals(listOf("totp", "passkey", "recovery"), twoStepChoices(listOf("totp", "passkey", "recovery"), keyPage = true))
        assertEquals(listOf("passkey"), twoStepChoices(listOf("passkey"), keyPage = true))
        assertEquals(listOf("totp"), twoStepChoices(listOf("passkey"), keyPage = false))
        assertEquals(listOf("totp"), twoStepChoices(listOf("duo"), keyPage = true))
    }
}
