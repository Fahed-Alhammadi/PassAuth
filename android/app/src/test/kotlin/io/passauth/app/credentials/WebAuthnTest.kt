package io.passauth.app.credentials

import io.passauth.app.data.AppJson
import io.passauth.app.data.ItemCodec
import io.passauth.app.data.Passkey
import java.security.MessageDigest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class WebAuthnTest {
    private val userId = B64Url.encode("user-1".toByteArray())
    private val createJson = """
        {"rp":{"id":"webauthn.io","name":"WebAuthn.io"},
         "user":{"id":"$userId","name":"alice","displayName":"Alice"},
         "challenge":"Y2hhbGxlbmdl",
         "pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
         "excludeCredentials":[{"type":"public-key","id":"AAEC"}],
         "authenticatorSelection":{"residentKey":"required","userVerification":"preferred"},
         "extensions":{"credProps":true}}
    """.trimIndent()

    private fun pk(id: String, rp: String = "webauthn.io", discoverable: Boolean = true, alg: Int = -7) =
        Passkey(credentialId = id, rpId = rp, algorithm = alg, discoverable = discoverable)

    @Test
    fun base64url() {
        assertEquals("AAEC_w", B64Url.encode(byteArrayOf(0, 1, 2, -1)))
        assertArrayEquals(byteArrayOf(0, 1, 2, -1), B64Url.decode("AAEC_w=="))
        assertEquals("AAEC_w", B64Url.canonical("AAEC_w=="))
        assertNull(B64Url.canonical("AAE+"))
        assertNull(B64Url.canonical("A"))
    }

    @Test
    fun parsesCreationOptions() {
        val o = WebAuthn.parseCreate(createJson)
        assertEquals("webauthn.io", o.rpId)
        assertEquals("WebAuthn.io", o.rpName)
        assertEquals(userId, o.userId)
        assertEquals("alice", o.userName)
        assertEquals("Alice", o.userDisplayName)
        assertEquals("Y2hhbGxlbmdl", o.challenge)
        assertEquals(listOf(-8, -7, -257), o.algorithms)
        assertEquals(setOf("AAEC"), o.excludeCredentials)
        assertTrue(o.credProps)
        assertTrue(WebAuthn.supports(o))
        assertFalse(WebAuthn.supports(o.copy(algorithms = listOf(-257))))
        assertTrue(WebAuthn.supports(o.copy(algorithms = emptyList(), defaultAlgorithms = true)))
        assertFalse(WebAuthn.supports(o.copy(attachment = "cross-platform")))
    }

    @Test
    fun rejectsMalformedOptions() {
        assertThrows(WebAuthnException::class.java) { WebAuthn.parseCreate("""{"rp":{"name":"x"},"user":{"id":"","name":"a"},"challenge":"AA","pubKeyCredParams":[]}""") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.parseCreate("""{"rp":{"name":"x"},"user":{"id":"AA","name":"a"},"challenge":"A+","pubKeyCredParams":[]}""") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.parseGet("not json") }
    }

    @Test
    fun rpIdMustFitTheOrigin() {
        assertEquals("webauthn.io", WebAuthn.effectiveRpId(null, "https://webauthn.io"))
        assertEquals("example.com", WebAuthn.effectiveRpId("example.com", "https://login.example.com"))
        assertEquals("example.com", WebAuthn.effectiveRpId("Example.COM", "https://login.example.com:8443"))
        assertEquals("localhost", WebAuthn.effectiveRpId(null, "http://localhost:8080"))
        assertThrows(WebAuthnException::class.java) { WebAuthn.effectiveRpId("evil.com", "https://example.com") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.effectiveRpId("com", "https://example.com") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.effectiveRpId("co.uk", "https://example.co.uk") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.effectiveRpId(null, "http://example.com") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.effectiveRpId(null, "https://10.0.0.1") }
        assertThrows(WebAuthnException::class.java) { WebAuthn.effectiveRpId(null, "android:apk-key-hash:abc") }
        assertEquals("example.com", WebAuthn.appRpId("example.com"))
        assertThrows(WebAuthnException::class.java) { WebAuthn.appRpId(null) }
        assertThrows(WebAuthnException::class.java) { WebAuthn.appRpId("https://example.com") }
    }

    @Test
    fun appOriginIsTheCertificateHash() {
        val hash = MessageDigest.getInstance("SHA-256").digest("cert".toByteArray())
        val origin = WebAuthn.appOrigin(hash)
        assertTrue(origin.startsWith("android:apk-key-hash:"))
        assertEquals(B64Url.encode(hash), origin.removePrefix("android:apk-key-hash:"))
        assertFalse(origin.contains('=') || origin.contains('+') || origin.contains('/'))
        assertTrue(WebAuthn.isAppOrigin(origin))
    }

    @Test
    fun matchingAndExcludedPasskeys() {
        val all = listOf(pk("AAEC"), pk("BBBB", discoverable = false), pk("CCCC", rp = "other.io"), pk("DDDD", alg = -257))
        val discover = WebAuthn.parseGet("""{"challenge":"AA","rpId":"webauthn.io"}""")
        assertEquals(listOf("AAEC"), WebAuthn.matching(discover, "webauthn.io", all).map { it.credentialId })
        val listed = WebAuthn.parseGet("""{"challenge":"AA","allowCredentials":[{"type":"public-key","id":"BBBB"},{"type":"public-key","id":"CCCC"}]}""")
        assertTrue(listed.requireListed)
        assertEquals(listOf("BBBB"), WebAuthn.matching(listed, "webauthn.io", all).map { it.credentialId })
        val o = WebAuthn.parseCreate(createJson)
        assertTrue(WebAuthn.excludedExists(o, "webauthn.io", all))
        assertFalse(WebAuthn.excludedExists(o, "other.io", all))
    }

    @Test
    fun storedPasskeyHasTheExtensionFormat() {
        val o = WebAuthn.parseCreate(createJson)
        val p = WebAuthn.passkeyRecord(o, "webauthn.io", byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6), 1_700_000_000)
        val json = AppJson.parseToJsonElement(ItemCodec.encode(io.passauth.app.data.Item(login = io.passauth.app.data.Login(passkeys = listOf(p)))))
            .jsonObject["login"]!!.jsonObject["passkeys"]!!.jsonArray[0].jsonObject
        assertEquals(
            setOf("credential_id", "rp_id", "rp_name", "user_handle", "user_name", "user_display_name", "algorithm", "private_key", "counter", "discoverable", "created_at"),
            json.keys,
        )
        assertEquals("AQID", json["credential_id"]!!.jsonPrimitive.content)
        assertEquals("BAUG", json["private_key"]!!.jsonPrimitive.content)
        assertEquals(userId, json["user_handle"]!!.jsonPrimitive.content)
        assertEquals("alice", json["user_name"]!!.jsonPrimitive.content)
        assertEquals("Alice", json["user_display_name"]!!.jsonPrimitive.content)
        assertEquals("WebAuthn.io", json["rp_name"]!!.jsonPrimitive.content)
        assertEquals(-7, json["algorithm"]!!.jsonPrimitive.int)
        assertEquals(0, json["counter"]!!.jsonPrimitive.int)
        assertEquals("true", json["discoverable"]!!.jsonPrimitive.content)
    }

    @Test
    fun registrationResponseJson() {
        val cdj = """{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://webauthn.io","crossOrigin":false}"""
        val r = AppJson.parseToJsonElement(
            WebAuthn.registrationResponse(byteArrayOf(1, 2, 3), cdj, byteArrayOf(9), byteArrayOf(8), byteArrayOf(7), credProps = true),
        ).jsonObject
        assertEquals("AQID", r["id"]!!.jsonPrimitive.content)
        assertEquals("AQID", r["rawId"]!!.jsonPrimitive.content)
        assertEquals("public-key", r["type"]!!.jsonPrimitive.content)
        assertEquals("platform", r["authenticatorAttachment"]!!.jsonPrimitive.content)
        val resp = r["response"]!!.jsonObject
        assertEquals(cdj, String(B64Url.decode(resp["clientDataJSON"]!!.jsonPrimitive.content)))
        assertEquals("CQ", resp["attestationObject"]!!.jsonPrimitive.content)
        assertEquals("CA", resp["authenticatorData"]!!.jsonPrimitive.content)
        assertEquals("Bw", resp["publicKey"]!!.jsonPrimitive.content)
        assertEquals(-7, resp["publicKeyAlgorithm"]!!.jsonPrimitive.int)
        assertEquals(listOf("internal", "hybrid"), resp["transports"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("true", r["clientExtensionResults"]!!.jsonObject["credProps"]!!.jsonObject["rk"]!!.jsonPrimitive.content)
    }

    @Test
    fun authenticationResponseJson() {
        val p = pk("AAEC==").copy(userHandle = userId)
        val cdj = """{"type":"webauthn.get","challenge":"AA","origin":"android:apk-key-hash:xyz","crossOrigin":false}"""
        val r = AppJson.parseToJsonElement(WebAuthn.authenticationResponse(p, cdj, byteArrayOf(1), byteArrayOf(2))).jsonObject
        assertEquals("AAEC", r["id"]!!.jsonPrimitive.content)
        val resp = r["response"]!!.jsonObject
        assertEquals("AQ", resp["authenticatorData"]!!.jsonPrimitive.content)
        assertEquals("Ag", resp["signature"]!!.jsonPrimitive.content)
        assertEquals(userId, resp["userHandle"]!!.jsonPrimitive.content)
        assertEquals(cdj, String(B64Url.decode(resp["clientDataJSON"]!!.jsonPrimitive.content)))
        assertEquals(JsonObject(emptyMap()), r["clientExtensionResults"])
        val noHandle = AppJson.parseToJsonElement(WebAuthn.authenticationResponse(pk("AAEC"), cdj, byteArrayOf(1), byteArrayOf(2))).jsonObject
        assertNull(noHandle["response"]!!.jsonObject["userHandle"])
    }
}
