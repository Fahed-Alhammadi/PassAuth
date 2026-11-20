package io.passauth.app.push

import io.passauth.app.data.ApiException
import io.passauth.app.data.SecurityTransport
import io.passauth.app.ui.permissions.Access
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Sign-in request notifications: token rules, the registration requests, gating on the server's
 * `push` feature, the vault card and Settings switch rules and the notification payload (as the
 * iPhone app's PushTests).
 */
class PushTest {
    private val token1 = "f" + "A1b2_C3d-4:".repeat(15)
    private val token2 = "e" + "Z9y8_X7w-6:".repeat(15)

    @Test
    fun tokenValidationMatchesTheServer() {
        assertTrue(PushRules.validToken(token1))
        assertTrue(PushRules.validToken("a".repeat(100)))
        assertTrue(PushRules.validToken("a".repeat(512)))
        assertFalse(PushRules.validToken("a".repeat(99)))
        assertFalse(PushRules.validToken("a".repeat(513)))
        assertFalse(PushRules.validToken("a".repeat(99) + " "))
        assertFalse(PushRules.validToken("a".repeat(99) + "/"))
        assertFalse(PushRules.validToken(null))
    }

    @Test
    fun registerBody() {
        assertEquals(
            JsonObject(mapOf("platform" to JsonPrimitive("fcm"), "token" to JsonPrimitive(token1), "environment" to JsonPrimitive("production"))),
            PushRules.registerBody(token1),
        )
        assertEquals("/account/push", PushRules.PATH)
    }

    @Test
    fun featureGate() {
        assertTrue(PushRules.offered(listOf("login_with_device", "push")))
        assertFalse(PushRules.offered(listOf("login_with_device")))
        assertFalse(PushRules.offered(emptyList()))
        assertFalse(PushRules.offered(null))
    }

    @Test
    fun activeOfferAndSwitch() {
        assertTrue(PushRules.active(available = true, enabled = true, granted = true))
        assertFalse(PushRules.active(available = false, enabled = true, granted = true))
        assertFalse(PushRules.active(available = true, enabled = false, granted = true))
        assertFalse(PushRules.active(available = true, enabled = true, granted = false))

        assertTrue(PushRules.showOffer(available = true, permission = Access.NotAsked, dismissed = false, offered = true))
        assertFalse(PushRules.showOffer(available = false, permission = Access.NotAsked, dismissed = false, offered = true))
        assertFalse(PushRules.showOffer(available = true, permission = Access.NotAsked, dismissed = true, offered = true))
        assertFalse(PushRules.showOffer(available = true, permission = Access.NotAsked, dismissed = false, offered = false))
        assertFalse(PushRules.showOffer(available = true, permission = Access.On, dismissed = false, offered = true))
        assertFalse(PushRules.showOffer(available = true, permission = Access.Off, dismissed = false, offered = true))
        assertFalse(PushRules.showOffer(available = true, permission = Access.Blocked, dismissed = false, offered = true))

        assertTrue(PushRules.switchOn(enabled = true, permission = Access.On))
        assertFalse(PushRules.switchOn(enabled = false, permission = Access.On))
        assertFalse(PushRules.switchOn(enabled = true, permission = Access.Blocked))

        assertEquals(PushRules.Toggle.Enable, PushRules.toggle(true, Access.On))
        assertEquals(PushRules.Toggle.RequestPermission, PushRules.toggle(true, Access.NotAsked))
        assertEquals(PushRules.Toggle.RequestPermission, PushRules.toggle(true, Access.Off))
        assertEquals(PushRules.Toggle.OpenSettings, PushRules.toggle(true, Access.Blocked))
        assertEquals(PushRules.Toggle.Disable, PushRules.toggle(false, Access.On))
        assertEquals(PushRules.Toggle.Disable, PushRules.toggle(false, Access.Blocked))
    }

    @Test
    fun notificationPayload() {
        val shown = PushNotice.forMessage(mapOf("kind" to "auth_request"))
        assertEquals(PushNotice.Content("sign_in_requests", "Sign-in request", "Someone wants to sign in to your PassAuth account on a new device. Open PassAuth to review."), shown)
        // The relay may add fields later: still shown, with the same fixed words.
        assertEquals(shown, PushNotice.forMessage(mapOf("kind" to "auth_request", "v" to "2")))
        assertNull(PushNotice.forMessage(mapOf("kind" to "other")))
        assertNull(PushNotice.forMessage(emptyMap()))
        assertNull(PushNotice.forMessage(mapOf("passauth" to "auth_request")))
        assertEquals("Sign-in requests", PushNotice.CHANNEL_NAME)
    }

    // ------------------------------------------------------------ client

    private class Sent(val path: String, val body: JsonElement?, val method: String, val auth: Boolean)

    @Test
    fun clientSendsPutAndDelete() = runBlocking {
        val sent = mutableListOf<Sent>()
        val client = PushClient { path, body, method, auth, _ ->
            sent += Sent(path, body, method, auth)
            JsonNull
        }
        client.register(token1)
        client.unregister()
        assertEquals(listOf("PUT", "DELETE"), sent.map { it.method })
        assertTrue(sent.all { it.path == "/account/push" && it.auth })
        assertEquals(PushRules.registerBody(token1), sent[0].body)
        assertNull(sent[1].body)
    }

    @Test
    fun clientPassesTheServersRefusalOn() = runBlocking {
        val client = PushClient(SecurityTransport { _, _, _, _, _ -> throw ApiException(409, "push_disabled", "push notifications are turned off on this server") })
        try {
            client.register(token1)
            fail("expected the 409")
        } catch (e: ApiException) {
            assertEquals(409, e.status)
            assertEquals("push_disabled", e.code)
        }
    }

    // ------------------------------------------------------------ registrar

    private data class Call(val account: String, val method: String, val body: JsonElement?)

    private class Fake {
        val sent = mutableListOf<Call>()
        val features = mutableMapOf<String, List<String>?>()
        val failing = mutableSetOf<String>()
    }

    private fun registrar(fake: Fake) = PushRegistrar(
        send = { id, method, body ->
            fake.sent += Call(id, method, body)
            if (id in fake.failing) throw ApiException(409, "push_disabled", "off")
        },
        features = { id -> fake.features[id] },
    )

    @Test
    fun registersOnlyWithServersOfferingPushOncePerToken() = runBlocking {
        val fake = Fake()
        fake.features += mapOf("a" to listOf("push"), "b" to listOf("login_with_device"), "c" to null)
        val r = registrar(fake)
        r.sync(token1, listOf("a", "b", "c"))
        assertEquals(listOf(Call("a", "PUT", PushRules.registerBody(token1))), fake.sent)
        assertEquals(mapOf("a" to token1), r.registered)
        // Again with the same token (app back on screen): nothing new.
        r.sync(token1, listOf("a", "b", "c"))
        assertEquals(1, fake.sent.size)
        // The admin turned push on for b's server.
        fake.features["b"] = listOf("push")
        r.sync(token1, listOf("a", "b", "c"))
        assertEquals(listOf("a", "b"), fake.sent.map { it.account })
    }

    @Test
    fun newTokenRegistersAgain() = runBlocking {
        val fake = Fake()
        fake.features["a"] = listOf("push")
        val r = registrar(fake)
        r.sync(token1, listOf("a"))
        r.sync(token2, listOf("a"))
        assertEquals(listOf(PushRules.registerBody(token1), PushRules.registerBody(token2)), fake.sent.map { it.body })
        assertEquals(mapOf("a" to token2), r.registered)
    }

    @Test
    fun noTokenOrInvalidTokenSendsNothing() = runBlocking {
        val fake = Fake()
        fake.features["a"] = listOf("push")
        val r = registrar(fake)
        r.sync(null, listOf("a"))
        r.sync("abc", listOf("a"))
        assertTrue(fake.sent.isEmpty())
    }

    @Test
    fun failureIsRetriedAndSignedOutAccountsAreForgotten() = runBlocking {
        val fake = Fake()
        fake.features["a"] = listOf("push")
        fake.failing += "a"
        val r = registrar(fake)
        r.sync(token1, listOf("a"))
        assertEquals(emptyMap<String, String>(), r.registered)
        fake.failing.clear()
        r.sync(token1, listOf("a"))
        assertEquals(mapOf("a" to token1), r.registered)
        // Signed out elsewhere (session ended): forgotten, so the next sign-in registers again.
        r.sync(token1, emptyList())
        assertEquals(emptyMap<String, String>(), r.registered)
        r.sync(token1, listOf("a"))
        assertEquals(3, fake.sent.count { it.method == "PUT" })
    }

    @Test
    fun unregisterSendsDeleteAndForgets() = runBlocking {
        val fake = Fake()
        fake.features += mapOf("a" to listOf("push"), "b" to listOf("push"))
        val r = registrar(fake)
        r.sync(token1, listOf("a", "b"))
        r.unregister(listOf("a"))
        assertEquals(Call("a", "DELETE", null), fake.sent.last())
        assertEquals(mapOf("b" to token1), r.registered)
        // A failing DELETE (offline, push turned off) is fine: best effort.
        fake.failing += "b"
        r.unregister(listOf("b"))
        assertEquals("DELETE", fake.sent.last().method)
        assertEquals(emptyMap<String, String>(), r.registered)
        // Forget without a request (never registered in this run).
        r.forget("a")
        assertEquals(4, fake.sent.size)
    }

    @Test
    fun unregisterDoesNotWaitForASlowServer() = runBlocking {
        val r = PushRegistrar(send = { _, _, _ -> delay(30_000) }, features = { listOf("push") })
        val start = System.nanoTime()
        r.unregister(listOf("a", "b"), timeoutMs = 200)
        assertTrue((System.nanoTime() - start) / 1_000_000 < 5_000)
    }
}
