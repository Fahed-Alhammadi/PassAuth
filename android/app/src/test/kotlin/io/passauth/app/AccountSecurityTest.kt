package io.passauth.app

import io.passauth.app.data.AccountData
import io.passauth.app.data.AccountSecurity
import io.passauth.app.data.ApiException
import io.passauth.app.data.AppJson
import io.passauth.app.data.KdfMinimums
import io.passauth.app.data.KeyChange
import io.passauth.app.data.LoginProof
import io.passauth.app.data.MasterPasswordRules
import io.passauth.app.data.QrDecoder
import io.passauth.app.data.QrEncoder
import io.passauth.app.data.Rewrapped
import io.passauth.app.data.Sealed
import io.passauth.app.data.SecretKeyChoice
import io.passauth.app.data.SecurityCrypto
import io.passauth.app.data.SecurityTransport
import io.passauth.app.data.SessionInfo
import io.passauth.app.data.SessionText
import io.passauth.app.data.ShowOnce
import io.passauth.app.data.Stored
import io.passauth.app.data.Tokens
import io.passauth.app.data.TotpSetup
import io.passauth.app.data.TwoFactor
import io.passauth.app.data.UserException
import io.passauth.app.data.afterKeyChange
import io.passauth.app.data.securityErrorMessage
import io.passauth.app.data.str
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Account security request sequences against a fake server (crates/server/src/account.rs). */
class AccountSecurityTest {
    private data class Req(val method: String, val path: String, val body: JsonElement?, val auth: Boolean, val headers: Map<String, String>)

    /** A scripted server: answers by "METHOD path", records every request. */
    private class FakeServer(val answers: MutableMap<String, (Req) -> JsonElement>) : SecurityTransport {
        val log = mutableListOf<Req>()
        override suspend fun call(path: String, body: JsonElement?, method: String, auth: Boolean, headers: Map<String, String>): JsonElement {
            val r = Req(method, path, body, auth, headers)
            log += r
            val answer = answers["$method $path"] ?: error("unexpected $method $path")
            return answer(r)
        }
        val paths get() = log.map { "${it.method} ${it.path}" }
    }

    private class FakeCrypto(val rightPassword: String = "current password") : SecurityCrypto {
        var loginPassword: String? = null
        var rewrapArgs: List<Any?>? = null
        var closed = 0

        override fun loginProof(password: String, secretKey: String?, prelogin: JsonObject): LoginProof {
            loginPassword = password
            return object : LoginProof {
                override val message = "ke1"
                override fun finish(serverMessage: String): String {
                    assertEquals("ke2", serverMessage)
                    if (password != rightPassword) throw UserException("Wrong master password or Secret Key.")
                    return "ke3"
                }
                override fun close() { closed++ }
            }
        }

        var rewrapKdf: KdfMinimums? = null

        override fun rewrap(bundleJson: String, newPassword: String, withSecretKey: Boolean, existingSecretKey: String?, kdf: KdfMinimums?): Rewrapped {
            rewrapArgs = listOf(newPassword, withSecretKey, existingSecretKey)
            rewrapKdf = kdf
            return object : Rewrapped {
                override val bundleJson = """{"account_id":"acc","secret_key_enabled":$withSecretKey,"wrapped_account_key":"new"}"""
                override val secretKey = if (withSecretKey && existingSecretKey == null) "A1-NEWKEY" else null
                override fun registerStart() = "reg1"
                override fun registerFinish(serverMessage: String): String {
                    assertEquals("reg2", serverMessage)
                    return "upload"
                }
                override fun close() { closed++ }
            }
        }
    }

    private val device = buildJsonObject { put("id", "dev"); put("kind", "mobile") }
    private fun bundle(sk: Boolean) = """{"account_id":"acc","secret_key_enabled":$sk,"wrapped_account_key":"old"}"""

    private fun reauthAnswers(skRequired: Boolean = false): MutableMap<String, (Req) -> JsonElement> = mutableMapOf(
        "POST /auth/prelogin" to { _ -> buildJsonObject { put("account_id", "acc"); put("secret_key_required", skRequired); put("kdf", JsonObject(emptyMap())) } },
        "POST /auth/login/start" to { _ -> buildJsonObject { put("login_id", "L1"); put("message", "ke2") } },
        "POST /auth/login/finish" to { r ->
            assertEquals("reauth", r.body!!.jsonObject.str("purpose"))
            buildJsonObject { put("reauth_token", "RT") }
        },
    )

    @Test
    fun changePasswordRunsTheWebVaultSequence() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("POST /account/keys/start") { r ->
                    assertEquals("reg1", r.body!!.jsonObject.str("message"))
                    buildJsonObject { put("message", "reg2") }
                }
                put("POST /account/keys/finish") { r ->
                    val b = r.body!!.jsonObject
                    assertEquals("upload", b.str("upload"))
                    assertEquals("new", (b["bundle"] as JsonObject).str("wrapped_account_key"))
                    buildJsonObject { put("ok", true) }
                }
            },
        )
        val crypto = FakeCrypto()
        val change = AccountSecurity(server, crypto, device)
            .changeKeys("a@example.com", bundle(false), "current password", "new password!", SecretKeyChoice.Keep, null)

        assertEquals(
            listOf("POST /auth/prelogin", "POST /auth/login/start", "POST /auth/login/finish", "POST /account/keys/start", "POST /account/keys/finish"),
            server.paths,
        )
        // Prelogin and login/start are anonymous; the reauth login and key change use the session.
        assertEquals(listOf(false, false, true, true, true), server.log.map { it.auth })
        assertEquals("RT", server.log.last().headers[AccountSecurity.REAUTH_HEADER])
        assertTrue(server.log.dropLast(1).none { it.headers.containsKey(AccountSecurity.REAUTH_HEADER) })
        assertEquals("current password", crypto.loginPassword)
        assertEquals(listOf("new password!", false, null), crypto.rewrapArgs)
        assertNull("no policy: the core's own settings", crypto.rewrapKdf)
        assertEquals(KeyChange(change.bundleJson, false, null), change)
        assertEquals(2, crypto.closed) // login proof and rewrap handles released
    }

    /** A `kdf` policy violation is fixed by new keys with the server's minimums, with the same password. */
    @Test
    fun newKeysFollowTheServersMinimums() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("POST /account/keys/start") { _ -> buildJsonObject { put("message", "reg2") } }
                put("POST /account/keys/finish") { _ -> buildJsonObject { put("ok", true) } }
            },
        )
        val crypto = FakeCrypto()
        AccountSecurity(server, crypto, device)
            .changeKeys("a@example.com", bundle(false), "current password", "current password", SecretKeyChoice.Keep, null, KdfMinimums(256, 4))
        assertEquals(listOf("current password", false, null), crypto.rewrapArgs)
        assertEquals(KdfMinimums(256, 4), crypto.rewrapKdf)
        assertEquals("POST /account/keys/finish", server.paths.last())
    }

    @Test
    fun secretKeyChoices() = runBlocking {
        fun server() = FakeServer(
            reauthAnswers(skRequired = true).apply {
                put("POST /account/keys/start") { _ -> buildJsonObject { put("message", "reg2") } }
                put("POST /account/keys/finish") { _ -> buildJsonObject { put("ok", true) } }
            },
        )
        // On + keep: same key, nothing new to show.
        var crypto = FakeCrypto()
        var change = AccountSecurity(server(), crypto, device).changeKeys("a@x", bundle(true), "current password", "n", SecretKeyChoice.Keep, "A1-OLD")
        assertEquals(listOf("n", true, "A1-OLD"), crypto.rewrapArgs)
        assertNull(change.secretKey)
        // On + turn off.
        crypto = FakeCrypto()
        change = AccountSecurity(server(), crypto, device).changeKeys("a@x", bundle(true), "current password", "n", SecretKeyChoice.TurnOff, "A1-OLD")
        assertEquals(listOf("n", false, null), crypto.rewrapArgs)
        assertFalse(change.secretKeyEnabled)
        // Off + turn on: a new key, shown once.
        crypto = FakeCrypto()
        val off = FakeServer(
            reauthAnswers(skRequired = false).apply {
                put("POST /account/keys/start") { _ -> buildJsonObject { put("message", "reg2") } }
                put("POST /account/keys/finish") { _ -> buildJsonObject { put("ok", true) } }
            },
        )
        change = AccountSecurity(off, crypto, device).changeKeys("a@x", bundle(false), "current password", "n", SecretKeyChoice.TurnOn, null)
        assertEquals(listOf("n", true, null), crypto.rewrapArgs)
        assertEquals("A1-NEWKEY", change.secretKey)
    }

    @Test
    fun reauthNeedsTheSecretKeyWhenTheServerRequiresIt() = runBlocking {
        val server = FakeServer(reauthAnswers(skRequired = true))
        try {
            AccountSecurity(server, FakeCrypto(), device).changeKeys("a@x", bundle(true), "current password", "n", SecretKeyChoice.Keep, null)
            fail("expected secret_key_required")
        } catch (e: UserException) {
            assertEquals("secret_key_required", e.message)
        }
        assertEquals(listOf("POST /auth/prelogin"), server.paths)
    }

    @Test
    fun wrongCurrentPasswordStopsBeforeAnyChange() = runBlocking {
        val server = FakeServer(reauthAnswers())
        val crypto = FakeCrypto()
        try {
            AccountSecurity(server, crypto, device).changeKeys("a@x", bundle(false), "wrong", "n", SecretKeyChoice.Keep, null)
            fail("expected wrong password")
        } catch (e: UserException) {
            assertEquals("Wrong master password or Secret Key.", e.message)
        }
        assertEquals(listOf("POST /auth/prelogin", "POST /auth/login/start"), server.paths)
        assertNull(crypto.rewrapArgs)
        assertEquals(1, crypto.closed)
    }

    @Test
    fun keysFinishRejectedKeepsNothing() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("POST /account/keys/start") { _ -> buildJsonObject { put("message", "reg2") } }
                put("POST /account/keys/finish") { _ -> throw ApiException(403, "forbidden", "reauth_required") }
            },
        )
        val crypto = FakeCrypto()
        try {
            AccountSecurity(server, crypto, device).changeKeys("a@x", bundle(false), "current password", "n", SecretKeyChoice.TurnOn, null)
            fail("expected an error")
        } catch (e: ApiException) {
            assertEquals("Your confirmation expired. Enter your master password again.", securityErrorMessage(e))
        }
        assertEquals(2, crypto.closed)
    }

    @Test
    fun totpSetupAndEnableAfterReauth() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("POST /account/2fa/totp/setup") { r ->
                    assertNull(r.body)
                    buildJsonObject { put("secret", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"); put("uri", "otpauth://totp/PassAuth:a%40x?secret=JBSW&issuer=PassAuth") }
                }
                put("POST /account/2fa/totp/enable") { r ->
                    assertEquals("123456", r.body!!.jsonObject.str("code"))
                    // Servers refuse it without a fresh confirmation of the master password.
                    assertEquals("RT", r.headers[AccountSecurity.REAUTH_HEADER])
                    AppJson.parseToJsonElement("""{"recovery_codes":["aaaa-bbbb","cccc-dddd"]}""")
                }
            },
        )
        val crypto = FakeCrypto()
        val sec = AccountSecurity(server, crypto, device)
        val setup = sec.totpSetup()
        assertEquals("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP", setup.grouped)
        assertFalse(setup.toString().contains("JBSW")) // never in logs
        // A wrong-length code is refused locally, before any request (and before asking for a confirmation).
        try {
            sec.totpEnable("12345", "a@x", "current password", null)
            fail("expected a local error")
        } catch (e: UserException) {
            assertEquals("Enter the 6-digit code from your authenticator app.", e.message)
        }
        assertEquals(1, server.log.size)
        assertEquals(listOf("aaaa-bbbb", "cccc-dddd"), sec.totpEnable(" 123 456 ", "a@x", "current password", null))
        // The master password first (a reauth sign-in), then the enable with its token.
        assertEquals(
            listOf("POST /account/2fa/totp/setup", "POST /auth/prelogin", "POST /auth/login/start", "POST /auth/login/finish", "POST /account/2fa/totp/enable"),
            server.paths,
        )
        assertEquals("current password", crypto.loginPassword)
        assertTrue(server.log.filter { it.path.startsWith("/account/") }.all { it.auth && it.method == "POST" })
    }

    @Test
    fun aWrongMasterPasswordTurnsNothingOn() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("POST /account/2fa/email/enable") { _ -> fail("enabled without a confirmation"); JsonObject(emptyMap()) }
            },
        )
        val sec = AccountSecurity(server, FakeCrypto(), device)
        try {
            sec.emailEnable("654321", "a@x", "wrong password", null)
            fail("expected the wrong password to stop it")
        } catch (e: UserException) {
            assertEquals("Wrong master password or Secret Key.", e.message)
        }
        assertFalse(server.paths.contains("POST /account/2fa/email/enable"))
    }

    @Test
    fun laterMethodsReturnNoRecoveryCodes() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("POST /account/2fa/email/setup") { _ -> buildJsonObject { put("sent", true) } }
                put("POST /account/2fa/email/enable") { r ->
                    assertEquals("RT", r.headers[AccountSecurity.REAUTH_HEADER])
                    AppJson.parseToJsonElement("""{"recovery_codes":null}""")
                }
            },
        )
        val sec = AccountSecurity(server, FakeCrypto(), device)
        sec.emailSetup()
        assertNull(sec.emailEnable("654321", "a@x", "current password", null))
    }

    @Test
    fun wrongCodeAndRateLimitWording() {
        assertEquals(
            "That code didn't work. Enter the code that's showing now and try again.",
            securityErrorMessage(ApiException(400, "bad_request", "invalid code")),
        )
        assertEquals("Too many attempts, try again later.", securityErrorMessage(ApiException(429, "rate_limited", "too many requests, try again later")))
        assertNull(securityErrorMessage(UserException("Can't reach your PassAuth server.")))
    }

    @Test
    fun disableAndRegenerateNeedReauth() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("DELETE /account/2fa/totp") { r ->
                    assertEquals("RT", r.headers[AccountSecurity.REAUTH_HEADER])
                    buildJsonObject { put("ok", true) }
                }
                put("POST /account/2fa/recovery") { r ->
                    assertEquals("RT", r.headers[AccountSecurity.REAUTH_HEADER])
                    AppJson.parseToJsonElement("""{"recovery_codes":["x1","x2"]}""")
                }
            },
        )
        val sec = AccountSecurity(server, FakeCrypto(), device)
        sec.disable(TwoFactor.TOTP, "a@x", "current password", null)
        assertEquals(listOf("POST /auth/prelogin", "POST /auth/login/start", "POST /auth/login/finish", "DELETE /account/2fa/totp"), server.paths)
        server.log.clear()
        assertEquals(listOf("x1", "x2"), sec.regenerateRecoveryCodes("a@x", "current password", null))
        assertEquals("POST /account/2fa/recovery", server.paths.last())
        // Wrong password: nothing is turned off.
        server.log.clear()
        try {
            sec.disable(TwoFactor.EMAIL, "a@x", "wrong", null)
            fail("expected wrong password")
        } catch (_: UserException) {
        }
        assertTrue(server.paths.none { it.startsWith("DELETE") })
    }

    @Test
    fun statusFromAccount() = runBlocking {
        val server = FakeServer(
            mutableMapOf(
                "GET /account" to { _ ->
                    AppJson.parseToJsonElement(
                        """{"email":"a@x","two_factor":["totp"],"recovery_codes_left":7,"email_enabled":false,"secret_key_enabled":true}""",
                    )
                },
            ),
        )
        val s = AccountSecurity(server, FakeCrypto(), device).status()
        assertTrue(s.totpOn)
        assertFalse(s.emailOn)
        assertTrue(s.isLast(TwoFactor.TOTP))
        assertEquals(7, s.recoveryCodesLeft)
        assertFalse(s.emailAvailable)
        assertTrue(s.secretKeyEnabled)
    }

    @Test
    fun securityKeysListedAndRemovedAfterReauth() = runBlocking {
        val server = FakeServer(
            reauthAnswers().apply {
                put("GET /account") { _ ->
                    AppJson.parseToJsonElement(
                        """{"email":"a@x","two_factor":["passkey"],"recovery_codes_left":10,"passkeys":[""" +
                            """{"id":"k1","name":"YubiKey","created_at":1762000000,"last_used_at":null},""" +
                            """{"id":"k 2","name":"Laptop","created_at":1762000100,"last_used_at":1762100000}]}""",
                    )
                }
                put("DELETE /account/2fa/passkey/k%202") { r ->
                    assertEquals("RT", r.headers[AccountSecurity.REAUTH_HEADER])
                    buildJsonObject { put("ok", true) }
                }
            },
        )
        val sec = AccountSecurity(server, FakeCrypto(), device)
        val s = sec.status()
        assertEquals(listOf("k1", "k 2"), s.securityKeys.map { it.id })
        assertEquals(null, s.securityKeys[0].lastUsedAt)
        assertEquals(1762100000L, s.securityKeys[1].lastUsedAt)
        assertTrue(s.anyOn)
        assertFalse(s.isLastKey())
        assertTrue(s.copy(securityKeys = s.securityKeys.take(1)).isLastKey())
        assertFalse(s.copy(securityKeys = s.securityKeys.take(1), providers = listOf("passkey", "totp")).isLastKey())

        server.log.clear()
        sec.removeSecurityKey("k 2", "a@x", "current password", null)
        assertEquals(listOf("POST /auth/prelogin", "POST /auth/login/start", "POST /auth/login/finish", "DELETE /account/2fa/passkey/k%202"), server.paths)
        // Wrong password: nothing is removed.
        server.log.clear()
        try {
            sec.removeSecurityKey("k1", "a@x", "wrong", null)
            fail("expected wrong password")
        } catch (_: UserException) {
        }
        assertTrue(server.paths.none { it.startsWith("DELETE") })
    }

    private val sessionsJson = """{"current":"s1","sessions":[""" +
        """{"id":"s1","device_id":"d1","device_name":"PassAuth for Android (Pixel 9)","device_kind":"mobile","client":"android/0.6.0","created_at":1762000000,"last_used":1762100000},""" +
        """{"id":"s 2","device_id":"d2","device_name":"Chrome on macOS","device_kind":"extension","client":"extension/0.6.0","created_at":1762000000,"last_used":1762000500},""" +
        """{"id":"s3","device_id":"d3","device_name":"","device_kind":"web","client":null,"created_at":1762000000,"last_used":1762000600}]}"""

    @Test
    fun sessionsListedWithTheirAppAndSignedOut() = runBlocking {
        val server = FakeServer(
            mutableMapOf(
                "GET /account/sessions" to { _ -> AppJson.parseToJsonElement(sessionsJson) },
                "GET /config" to { r ->
                    assertFalse("the feature check needs no session", r.auth)
                    AppJson.parseToJsonElement("""{"name":"PassAuth","api":2,"features":["key_epoch","revoke_others"]}""")
                },
                "DELETE /account/sessions/s%202" to { _ -> buildJsonObject { put("ok", true) } },
                "POST /account/sessions/revoke-others" to { _ -> buildJsonObject { put("ok", true); put("revoked", 2) } },
            ),
        )
        val sec = AccountSecurity(server, FakeCrypto(), device)
        val list = sec.sessions()
        assertEquals(listOf("s1", "s 2", "s3"), list.sessions.map { it.id })
        assertEquals(listOf(true, false, false), list.sessions.map { it.current })
        assertEquals(listOf("s 2", "s3"), list.others.map { it.id })
        assertTrue(list.canRevokeOthers)
        assertEquals(listOf("Android app 0.6.0", "Chrome extension 0.6.0", "Web vault"), list.sessions.map(SessionText::app))
        assertNull(list.sessions[2].client)

        server.log.clear()
        sec.revokeSession("s 2")
        assertEquals(2, sec.revokeOtherSessions())
        assertEquals(listOf("DELETE /account/sessions/s%202", "POST /account/sessions/revoke-others"), server.paths)
        assertTrue(server.log.all { it.auth && it.body == null && it.headers.isEmpty() })
        // Each session's device; forgetting needs the server's feature.
        assertEquals(listOf("d1", "d2", "d3"), list.sessions.map { it.deviceId })
        assertFalse(list.canForget)
    }

    @Test
    fun forgetADeviceWhereTheServerHasIt() = runBlocking {
        val twoOnD2 = sessionsJson.replace(""""device_id":"d3"""", """"device_id":"d2"""")
        val server = FakeServer(
            mutableMapOf(
                "GET /account/sessions" to { _ -> AppJson.parseToJsonElement(twoOnD2) },
                "GET /config" to { _ -> AppJson.parseToJsonElement("""{"name":"PassAuth","features":["revoke_others","forget_device"]}""") },
                "POST /account/devices/d%202/forget" to { _ -> AppJson.parseToJsonElement("""{"ok":true,"signed_out":2,"current":false}""") },
                "POST /account/devices/d1/forget" to { _ -> AppJson.parseToJsonElement("""{"ok":true,"signed_out":1,"current":true}""") },
            ),
        )
        val sec = AccountSecurity(server, FakeCrypto(), device)
        val list = sec.sessions()
        assertTrue(list.canForget)
        assertEquals(2, list.sessionsOn("d2"))
        assertEquals(1, list.sessionsOn("d1"))
        assertTrue(list.isThisDevice("d1"))
        assertFalse(list.isThisDevice("d2"))
        assertFalse(list.isThisDevice(""))

        server.log.clear()
        assertEquals(io.passauth.app.data.ForgetResult(2, current = false), sec.forgetDevice("d 2"))
        // This device: the server signed this session out; the app only signs out locally (no /auth/logout).
        assertEquals(io.passauth.app.data.ForgetResult(1, current = true), sec.forgetDevice("d1"))
        assertEquals(listOf("POST /account/devices/d%202/forget", "POST /account/devices/d1/forget"), server.paths)
        assertTrue(server.log.all { it.auth && it.body == null && it.headers.isEmpty() })
    }

    @Test
    fun forgettingThisDeviceDropsItsRememberedTwoStep() {
        val s = Stored(
            activeId = "1",
            accounts = mapOf(
                "1" to AccountData(server = "https://p.example", email = "A@x.io", tokens = Tokens("a", "r")),
                "2" to AccountData(server = "https://q.example", email = "a@x.io", tokens = Tokens("a", "r")),
            ),
            rememberTokens = mapOf("https://p.example|a@x.io" to "rem", "https://q.example|a@x.io" to "keep"),
        )
        // Only this server's token: the same email on another server keeps its own.
        assertEquals(mapOf("https://q.example|a@x.io" to "keep"), s.withoutRememberToken("1").rememberTokens)
        assertEquals(s, s.withoutRememberToken("9"))
    }

    @Test
    fun forgetWording() {
        assertEquals(
            "Signing a device out ends its session there. It needs your master password to sign in again." +
                " Forgetting a device also ends its other sessions and makes its next sign-in count as a new device, so a remembered device has to use two-step login again.",
            SessionText.intro(canForget = true),
        )
        assertEquals("Signing a device out ends its session there. It needs your master password to sign in again.", SessionText.intro(canForget = false))
        assertEquals(
            "Its 2 sessions are signed out at once. The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it.",
            SessionText.forgetBody(2, thisDevice = false),
        )
        assertEquals(
            "Its session is signed out at once. The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it." +
                " This is the device you're using, so you're signed out here too.",
            SessionText.forgetBody(1, thisDevice = true),
        )
        assertEquals("Forget and sign out", SessionText.forgetAction(true))
        assertEquals("Forget device", SessionText.forgetAction(false))
        assertEquals("Laptop forgotten.", SessionText.forgotten("Laptop"))
        assertEquals("Device forgotten.", SessionText.forgotten(""))
        assertEquals("This device was forgotten and signed out.", SessionText.FORGOTTEN_HERE)
    }

    @Test
    fun signOutOthersOnlyWhereTheServerHasIt() = runBlocking {
        // An older server: no `revoke_others` in its features, or no features at all.
        for (config in listOf("""{"name":"PassAuth","features":["key_epoch"]}""", """{"name":"PassAuth"}""")) {
            val server = FakeServer(
                mutableMapOf(
                    "GET /account/sessions" to { _ -> AppJson.parseToJsonElement(sessionsJson) },
                    "GET /config" to { _ -> AppJson.parseToJsonElement(config) },
                ),
            )
            assertFalse(config, AccountSecurity(server, FakeCrypto(), device).sessions().canRevokeOthers)
        }
        // The check failing doesn't fail the list.
        val failing = FakeServer(mutableMapOf("GET /account/sessions" to { _ -> AppJson.parseToJsonElement(sessionsJson) }))
        val list = AccountSecurity(failing, FakeCrypto(), device).sessions()
        assertEquals(3, list.sessions.size)
        assertFalse(list.canRevokeOthers)
    }

    @Test
    fun sessionWordingLikeTheWebVault() {
        assertEquals("Chrome extension 0.6.0", SessionText.client("extension/0.6.0"))
        assertEquals("Desktop app 0.7.0", SessionText.client("desktop/0.7.0"))
        assertEquals("Web", SessionText.client("web/0.9.0"))
        assertEquals("iPhone app 0.6.0", SessionText.client("ios/0.6.0"))
        assertEquals("Android app 0.6.1", SessionText.client("android/0.6.1"))
        assertEquals("Mac AutoFill 0.7.0", SessionText.client("macos-autofill/0.7.0"))
        assertEquals("Command line", SessionText.client("cli/unknown"))
        assertEquals("Desktop app", SessionText.client("desktop"))
        // Unknown names as sent (first letter capitalised), with a version that looks like one.
        assertEquals("Mytool 1.2", SessionText.client("MyTool/1.2"))
        assertEquals("Password-sync 2.0-beta", SessionText.client("password_sync/2.0-beta"))
        assertNull(SessionText.client(null))
        assertNull(SessionText.client("  "))
        assertEquals("Mobile app", SessionText.kind("mobile"))
        assertEquals("Browser extension", SessionText.kind("extension"))
        assertEquals("Tv", SessionText.kind("tv"))
        val s = SessionInfo("x", "Laptop", "desktop", null, createdAt = 1_000, lastUsed = 1_000, current = false)
        assertEquals("Desktop app", SessionText.app(s))
        val now = 1_000_000L
        assertEquals("Just now", SessionText.ago(now - 30, nowMs = now * 1000))
        assertEquals("5 min ago", SessionText.ago(now - 300, nowMs = now * 1000))
        assertEquals("1 hour ago", SessionText.ago(now - 3_700, nowMs = now * 1000))
        assertEquals("3 hours ago", SessionText.ago(now - 3 * 3_600, nowMs = now * 1000))
        assertEquals("2 days ago", SessionText.ago(now - 2 * 86_400, nowMs = now * 1000))
        assertTrue(SessionText.detail(s.copy(current = true)).endsWith(" · in use now"))
        assertTrue(SessionText.detail(s.copy(lastUsed = now - 300), nowMs = now * 1000).endsWith(" · last used 5 min ago"))
        assertTrue(SessionText.detail(s.copy(lastUsed = now), nowMs = now * 1000).endsWith(" · last used just now"))
        assertEquals("2 other sessions signed out.", SessionText.revokedOthers(2))
        assertEquals("1 other session signed out.", SessionText.revokedOthers(1))
        assertEquals("Other sessions signed out.", SessionText.revokedOthers(null))
    }

    @Test
    fun shownOnceNeedsConfirmation() {
        var once = ShowOnce(listOf("a", "b"))
        assertFalse(once.mayClose())
        once = once.confirmSaved(true)
        assertTrue(once.mayClose())
        once = once.confirmSaved(false)
        assertFalse(once.mayClose())
        assertFalse(ShowOnce("A1-SECRET").toString().contains("SECRET"))
    }

    @Test
    fun masterPasswordRules() {
        assertEquals(MasterPasswordRules.Strength.Weak, MasterPasswordRules.strength(49.9))
        assertEquals(MasterPasswordRules.Strength.Fair, MasterPasswordRules.strength(50.0))
        assertEquals(MasterPasswordRules.Strength.Good, MasterPasswordRules.strength(65.0))
        assertEquals(MasterPasswordRules.Strength.Strong, MasterPasswordRules.strength(80.0))
        val p = { current: String, next: String, confirm: String, bits: Double, weak: Boolean -> MasterPasswordRules.problem(current, next, confirm, bits, weak) }
        assertEquals("Enter your current master password.", p("", "long enough pw", "long enough pw", 90.0, false))
        assertEquals("Use at least 10 characters for your new master password.", p("c", "short", "short", 90.0, false))
        assertTrue(p("c", "long enough pw", "long enough px", 90.0, false)!!.startsWith("The new passwords don't match"))
        assertEquals(MasterPasswordRules.WEAK_MESSAGE, p("c", "aaaaaaaaaa", "aaaaaaaaaa", 20.0, false))
        assertNull(p("c", "aaaaaaaaaa", "aaaaaaaaaa", 20.0, true)) // submitted again: allowed
        assertNull(p("c", "correct horse battery", "correct horse battery", 70.0, false))
    }

    @Test
    fun localStateAfterKeyChange() {
        val bio = Sealed("iv", "sealed")
        val s = Stored(
            activeId = "1",
            accounts = mapOf(
                "1" to AccountData(server = "https://p.example", email = "A@x.io", tokens = Tokens("a", "r"), bundle = "old", biometric = bio, persistedKeys = "keys"),
                "2" to AccountData(server = "https://q.example", email = "b@x.io"),
            ),
            rememberTokens = mapOf("https://p.example|a@x.io" to "rem", "https://q.example|b@x.io" to "keep"),
            secretKeys = mapOf("a@x.io" to "A1-OLD", "b@x.io" to "B1"),
        )
        // New Secret Key: replaces the stored one; the remember token is gone; unlock material stays.
        val on = s.afterKeyChange("1", KeyChange("new", true, "A1-NEW"))
        assertEquals("new", on.accounts["1"]!!.bundle)
        assertEquals("A1-NEW", on.secretKeys["a@x.io"])
        assertEquals(mapOf("https://q.example|b@x.io" to "keep"), on.rememberTokens)
        assertEquals(bio, on.accounts["1"]!!.biometric)
        assertEquals("keys", on.accounts["1"]!!.persistedKeys)
        assertEquals(Tokens("a", "r"), on.accounts["1"]!!.tokens)
        assertEquals(s.accounts["2"], on.accounts["2"])
        // Kept: unchanged. Turned off: removed.
        assertEquals("A1-OLD", s.afterKeyChange("1", KeyChange("new", true, null)).secretKeys["a@x.io"])
        assertNull(s.afterKeyChange("1", KeyChange("new", false, null)).secretKeys["a@x.io"])
        assertEquals("B1", s.afterKeyChange("1", KeyChange("new", false, null)).secretKeys["b@x.io"])
        // Same email on another server keeps its key.
        val shared = s.copy(accounts = s.accounts + ("3" to AccountData(server = "https://r.example", email = "a@x.io")))
        assertEquals("A1-OLD", shared.afterKeyChange("1", KeyChange("new", false, null)).secretKeys["a@x.io"])
        // A removed account: nothing changes.
        assertEquals(s, s.afterKeyChange("9", KeyChange("new", false, null)))
    }

    @Test
    fun setupQrCodeDecodesToTheUri() {
        val uri = "otpauth://totp/PassAuth:alex%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=PassAuth&algorithm=SHA1&digits=6&period=30"
        val m = QrEncoder.encode(uri)
        val scale = 4
        val w = m.size * scale
        val pixels = ByteArray(w * w) { i ->
            val x = (i % w) / scale
            val y = (i / w) / scale
            if (m[x, y]) 0 else 255.toByte()
        }
        assertEquals(uri, QrDecoder().decode(pixels, w, w))
    }

    @Test
    fun codesAndRecoveryText() {
        assertTrue(TwoFactor.validTotp("123 456"))
        assertFalse(TwoFactor.validTotp("12345a"))
        assertFalse(TwoFactor.validTotp("1234567"))
        assertEquals("PassAuth recovery codes\nhttps://p.example\n\nEach code works once.\n\nx1\nx2\n", TwoFactor.recoveryText("https://p.example", listOf("x1", "x2")))
        assertEquals("TotpSetup(…)", TotpSetup("S", "u").toString())
    }
}
