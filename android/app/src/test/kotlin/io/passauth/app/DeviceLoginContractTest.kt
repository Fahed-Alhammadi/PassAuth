package io.passauth.app

import io.passauth.app.data.ApiDeviceLoginTransport
import io.passauth.app.data.AppJson
import io.passauth.app.data.ApprovalCrypto
import io.passauth.app.data.AuthRequestApi
import io.passauth.app.data.DeviceApprovals
import io.passauth.app.data.DeviceLogin
import io.passauth.app.data.DeviceLoginFlow
import io.passauth.app.data.DeviceLoginPoll
import io.passauth.app.data.PreparedApproval
import io.passauth.app.data.SecurityTransport
import io.passauth.app.data.UserException
import io.passauth.app.data.str
import io.passauth.core.LoginApproval
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
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
 * Sign in with another device against a scripted server (crates/server/src/auth_requests.rs):
 * the paths, methods, session use and headers of the new device's and the approving app's requests.
 */
class DeviceLoginContractTest {
    private data class Req(val method: String, val path: String, val body: JsonElement?, val auth: Boolean, val headers: Map<String, String>)

    /** Answers by "METHOD path" (in order for repeated ones), records every request. */
    private class ScriptedServer(vararg script: Pair<String, (Req) -> JsonElement>) : SecurityTransport {
        val log = mutableListOf<Req>()
        private val answers = script.toMutableList()
        override suspend fun call(path: String, body: JsonElement?, method: String, auth: Boolean, headers: Map<String, String>): JsonElement {
            val r = Req(method, path, body, auth, headers)
            log += r
            val i = answers.indexOfFirst { it.first == "$method $path" }
            check(i >= 0) { "unexpected $method $path" }
            return answers.removeAt(i).second(r)
        }
    }

    private fun obj(json: String) = AppJson.parseToJsonElement(json).jsonObject

    private val device = buildJsonObject { put("id", "dev-1"); put("name", "PassAuth for Android (Pixel)"); put("kind", "mobile") }

    @Test
    fun theNewDeviceAsksWithoutASessionAndPollsWithTheCodeInAHeader() = runBlocking {
        val server = ScriptedServer(
            "POST /auth/requests" to { r ->
                val b = r.body!!.jsonObject
                assertEquals("alex@example.com", b.str("email"))
                assertEquals("PUB", b.str("public_key"))
                assertEquals("dev-1", b.str("device_id"))
                assertEquals("mobile", b.str("device_kind"))
                obj("""{"id":"7f6c1d1e-0000-4000-8000-000000000001","fingerprint_phrase":"never shown","expires_at":1000900}""")
            },
            "GET /auth/requests/7f6c1d1e-0000-4000-8000-000000000001" to { _ -> obj("""{"status":"pending"}""") },
            "GET /auth/requests/7f6c1d1e-0000-4000-8000-000000000001" to { _ ->
                obj("""{"status":"approved","sealed_key":"SK","access_token":"a","refresh_token":"r","user_id":"u","email":"alex@example.com","bundle":{"account_id":"u"}}""")
            },
        )
        val flow = DeviceLoginFlow(ApiDeviceLoginTransport(server), { 1_000_000 }, { })
        val code = DeviceLogin.accessCode()
        val started = flow.start("alex@example.com", "PUB", code, device, null)
        val result = flow.await(started.id, code, started.expiresAt)
        assertTrue(result is DeviceLoginPoll.Approved)
        assertEquals("SK", (result as DeviceLoginPoll.Approved).session.str("sealed_key"))
        // No request of the new device uses a session.
        assertTrue(server.log.none { it.auth })
        // The code goes in X-PassAuth-Access-Code on every poll, never in the URL or a body.
        val polls = server.log.filter { it.method == "GET" }
        assertEquals(2, polls.size)
        assertTrue(polls.all { it.headers == mapOf("X-PassAuth-Access-Code" to code) && it.body == null && code !in it.path })
        assertEquals(code, server.log.first().body!!.jsonObject.str("access_code"))
    }

    @Test
    fun aRequestIdThatIsntOneNeverReachesAPath() = runBlocking {
        val server = ScriptedServer("POST /auth/requests" to { _ -> obj("""{"id":"../../account","expires_at":1000900}""") })
        val e = assertThrows(UserException::class.java) { runBlocking { DeviceLoginFlow(ApiDeviceLoginTransport(server)).start("a@x", "P", "C", device, null) } }
        assertEquals(DeviceLogin.GONE, e.message)
        assertEquals(1, server.log.size)
    }

    @Test
    fun theApprovingAppListsAndAnswersWithItsSession() = runBlocking {
        val id = "7f6c1d1e-0000-4000-8000-000000000002"
        val server = ScriptedServer(
            "GET /account/auth-requests" to { _ ->
                obj(
                    """{"requests":[{"id":"$id","public_key":"PUB","fingerprint_phrase":"server words","challenge":"CH","device_name":"Pixel 9",
                    |"device_kind":"mobile","client":"android/0.7.0","ip":null,"created_at":999900,"expires_at":1000800}]}""".trimMargin(),
                )
            },
            "POST /account/auth-requests/$id" to { r ->
                assertEquals(obj("""{"approve":true,"sealed_key":"SEALED","proof":"PROOF"}"""), r.body)
                obj("""{"id":"$id","status":"approved"}""")
            },
            "POST /account/auth-requests/$id" to { r ->
                assertEquals(obj("""{"approve":false}"""), r.body)
                obj("""{"id":"$id","status":"denied"}""")
            },
        )
        val requests = AuthRequestApi(server)
        val listed = requests.list(1_000_000)
        assertEquals(listOf(id), listed.map { it.id })
        assertNull(listed.single().ip)
        val crypto = object : ApprovalCrypto {
            override fun approve(publicKey: String, requestId: String, chosenPhrase: String, secretKey: String?): LoginApproval {
                assertEquals("PUB" to id, publicKey to requestId)
                assertEquals("the picked words", chosenPhrase)
                assertEquals("PA1-KEPT", secretKey)
                return LoginApproval("SEALED", "123456")
            }

            override fun proof(challenge: String, requestId: String): String {
                assertEquals("CH" to id, challenge to requestId)
                return "PROOF"
            }
        }
        val approval = DeviceApprovals.prepare(listed.single(), "the picked words", crypto, "PA1-KEPT") as PreparedApproval.Approve
        // The code is shown on this device only: it never goes to the server.
        assertEquals("123456", approval.code)
        requests.answer(listed.single(), approval.body)
        requests.answer(listed.single(), DeviceApprovals.DENY)
        assertTrue(server.log.none { it.body.toString().contains("123456") })
        // Every request of the approving app uses its session.
        assertTrue(server.log.all { it.auth })
        assertFalse(server.log.any { it.headers.isNotEmpty() })
    }
}
