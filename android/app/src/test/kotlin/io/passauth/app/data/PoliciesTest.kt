package io.passauth.app.data

import io.passauth.app.ui.errorMessage
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Account policies (Policies.kt): reading `/api/config`, the master password minimum, the vault
 * timeout limit and lowering, export, violations and their notices, policy errors and the two-step
 * gate. The same cases as the iOS `PoliciesTests` and the web vault's `policies.test.ts`.
 */
class PoliciesTest {
    private fun config(json: String) = ServerConfig.parse(AppJson.parseToJsonElement(json).jsonObject)

    private val allPolicies = """{"name":"PassAuth","api":2,"signups_allowed":false,"features":["delta_sync","policies","forget_device"],"policies":{
        "require_two_step":true,"require_secret_key":true,"min_kdf_memory_mib":256,"min_kdf_iterations":4,
        "master_password_min_length":14,"max_vault_timeout_minutes":45,"disable_export":true}}"""

    @Test
    fun readsThePoliciesOfServersThatHaveThem() {
        val c = config(allPolicies)
        assertEquals(false, c.signupsAllowed)
        assertEquals(listOf("delta_sync", "policies", "forget_device"), c.features)
        assertEquals(Policies(true, true, 256, 4, 14, 45, true), c.policies)
        // Nothing sent: defaults, which change nothing.
        assertNull(config("""{"name":"PassAuth"}""").signupsAllowed)
        assertEquals(Policies(), config("""{"name":"PassAuth","features":["policies"]}""").policies)
    }

    @Test
    fun oddValuesFallBackOrAreClamped() {
        val p = PolicyRules.read(
            AppJson.parseToJsonElement(
                """{"require_two_step":"true","require_secret_key":1,"min_kdf_memory_mib":5000,"min_kdf_iterations":2.5,
                "master_password_min_length":4,"max_vault_timeout_minutes":-5,"disable_export":null}""",
            ),
        )
        assertFalse("only a real true counts", p.requireTwoStep)
        assertFalse(p.requireSecretKey)
        assertEquals(1024, p.minKdfMemoryMib)
        assertEquals("a fraction is ignored", 3, p.minKdfIterations)
        assertEquals("never below the apps' own minimum", 10, p.masterPasswordMinLength)
        assertEquals(0, p.maxVaultTimeoutMinutes)
        assertFalse(p.disableExport)
        assertEquals(43_200, PolicyRules.read(AppJson.parseToJsonElement("""{"max_vault_timeout_minutes":99999999}""")).maxVaultTimeoutMinutes)
        assertEquals(60, PolicyRules.read(AppJson.parseToJsonElement("""{"max_vault_timeout_minutes":60.0}""")).maxVaultTimeoutMinutes)
        assertEquals(Policies(), PolicyRules.read(AppJson.parseToJsonElement("[1]")))
    }

    @Test
    fun masterPasswordMinimumAndExport() {
        assertEquals(10, PolicyRules.minPasswordLength(null))
        assertEquals(10, PolicyRules.minPasswordLength(Policies()))
        assertEquals(14, PolicyRules.minPasswordLength(Policies(masterPasswordMinLength = 14)))
        assertEquals("Use at least 14 characters for your new master password.", MasterPasswordRules.problem("c", "twelve chars", "twelve chars", 90.0, false, minLength = 14))
        assertNull(MasterPasswordRules.problem("c", "fourteen chars", "fourteen chars", 90.0, false, minLength = 14))
        // A policy below the apps' own minimum changes nothing.
        assertEquals("Use at least 10 characters for your new master password.", MasterPasswordRules.problem("c", "short", "short", 90.0, false, minLength = 4))
        assertTrue(PolicyRules.exportAllowed(null))
        assertTrue(PolicyRules.exportAllowed(Policies()))
        assertFalse(PolicyRules.exportAllowed(Policies(disableExport = true)))
    }

    @Test
    fun vaultTimeoutLimit() {
        // No limit: every choice.
        assertEquals(VaultTimeout.entries, PolicyRules.timeoutOptions(0))
        assertTrue(PolicyRules.timeoutWithin(VaultTimeout.Never, 0))
        // 45 minutes: up to 30 minutes; "On app restart" and "Never" have no time, so they're above any limit.
        assertEquals(
            listOf(VaultTimeout.Immediately, VaultTimeout.Min1, VaultTimeout.Min5, VaultTimeout.Min15, VaultTimeout.Min30),
            PolicyRules.timeoutOptions(45),
        )
        assertTrue(PolicyRules.timeoutWithin(VaultTimeout.Hour1, 60))
        assertFalse(PolicyRules.timeoutWithin(VaultTimeout.Hour4, 60))
        assertFalse(PolicyRules.timeoutWithin(VaultTimeout.Restart, 43_200))
        assertTrue(PolicyRules.timeoutWithin(VaultTimeout.Immediately, 1))
        // A saved choice above the limit is lowered to the longest one within it.
        assertEquals(VaultTimeout.Min30, PolicyRules.clampTimeout(VaultTimeout.Never, 45))
        assertEquals(VaultTimeout.Hour1, PolicyRules.clampTimeout(VaultTimeout.Hour4, 239))
        assertEquals(VaultTimeout.Min1, PolicyRules.clampTimeout(VaultTimeout.Restart, 1))
        assertEquals(VaultTimeout.Min5, PolicyRules.clampTimeout(VaultTimeout.Min5, 45))
        assertEquals(VaultTimeout.Never, PolicyRules.clampTimeout(VaultTimeout.Never, 0))
    }

    @Test
    fun theStrictestSignedInAccountSetsTheLimit() {
        val s = Stored(
            accounts = mapOf(
                "a" to AccountData(server = "https://a", email = "a@x", tokens = Tokens("t", "r"), policies = Policies(maxVaultTimeoutMinutes = 240)),
                "b" to AccountData(server = "https://b", email = "b@x", tokens = Tokens("t", "r"), policies = Policies(maxVaultTimeoutMinutes = 30)),
                // Signed out: its server's limit doesn't apply any more.
                "c" to AccountData(server = "https://c", email = "c@x", policies = Policies(maxVaultTimeoutMinutes = 5)),
                "d" to AccountData(server = "https://d", email = "d@x", tokens = Tokens("t", "r")),
            ),
        )
        assertEquals(30, s.timeoutLimit)
        assertEquals(0, Stored().timeoutLimit)
        assertEquals(0, PolicyRules.timeoutLimit(listOf(null, Policies())))
        // Old stored settings and accounts read without the new fields.
        val settings = AppJson.decodeFromString(Settings.serializer(), """{"vaultTimeout":"never"}""")
        assertFalse(settings.vaultTimeoutLowered)
        assertNull(AppJson.decodeFromString(AccountData.serializer(), """{"server":"https://a","email":"a@x"}""").policies)
    }

    @Test
    fun limitWording() {
        assertEquals("45 minutes", PolicyRules.minutesLabel(45))
        assertEquals("1 minute", PolicyRules.minutesLabel(1))
        assertEquals("1 hour", PolicyRules.minutesLabel(60))
        assertEquals("4 hours", PolicyRules.minutesLabel(240))
        assertEquals("90 minutes", PolicyRules.minutesLabel(90))
        assertEquals("1 day", PolicyRules.minutesLabel(1440))
        assertEquals("30 days", PolicyRules.minutesLabel(43_200))
        assertEquals("Your server allows at most 45 minutes before the vault locks.", PolicyRules.limitNote(45))
        assertEquals("Your previous choice was longer, so it was lowered to 30 minutes.", PolicyRules.loweredNote(VaultTimeout.Min30))
    }

    @Test
    fun violationsAndTheirNotices() {
        val account = AppJson.parseToJsonElement("""{"email":"a@x","policy_violations":["kdf","bogus","two_step","kdf","secret_key"]}""").jsonObject
        val v = PolicyRules.readViolations(account["policy_violations"])
        assertEquals(listOf(Violation.TwoStep, Violation.SecretKey, Violation.Kdf), v)
        assertEquals(emptyList<Violation>(), PolicyRules.readViolations(null))
        assertEquals(emptyList<Violation>(), PolicyRules.readViolations(AppJson.parseToJsonElement("\"two_step\"")))
        assertEquals("two_step,secret_key,kdf", PolicyRules.violationsKey(v))

        val notices = PolicyRules.notices(v)
        assertEquals(
            listOf(
                PolicyNotice(Violation.TwoStep, "Your server requires two-step login.", "Set up two-step login", PolicyFix.TwoStep),
                PolicyNotice(Violation.SecretKey, "Your server asks you to turn on a Secret Key.", "Turn on a Secret Key", PolicyFix.ChangePassword),
                // New keys always meet the minimums now (the core makes them), so this is always fixable.
                PolicyNotice(
                    Violation.Kdf,
                    "Your server asks you to update your account's encryption settings. Change your master password to update them. You can keep the same password.",
                    "Change master password",
                    PolicyFix.ChangePassword,
                ),
            ),
            notices,
        )
    }

    @Test
    fun keyDerivationMinimumsForNewKeys() {
        assertEquals(KdfMinimums(256, 5), PolicyRules.kdfMinimums(Policies(minKdfMemoryMib = 256, minKdfIterations = 5)))
        val withPolicies = ServerConfig(signupsAllowed = true, features = listOf("policies"), policies = Policies(minKdfMemoryMib = 512))
        assertEquals(KdfMinimums(512, 3), PolicyRules.kdfMinimums(withPolicies))
        assertNull(PolicyRules.kdfMinimums(null as ServerConfig?))
    }

    @Test
    fun theApiVersionIsReadAndKeptWithTheAccount() {
        assertEquals(2, config("""{"name":"PassAuth","api":2,"features":["icons"]}""").api)
        assertEquals(1, config("""{"api":1}""").api)
        // None sent, or anything that isn't a number, counts as none.
        assertNull(config("""{"name":"PassAuth","features":[]}""").api)
        assertNull(config("""{"api":"2"}""").api)
        assertNull(config("""{"api":null}""").api)
        assertNull(config("""{"api":true}""").api)
        // Stored files from before keep working (no `api`), and it round-trips.
        assertNull(AppJson.decodeFromString(AccountData.serializer(), """{"server":"https://a","features":["icons"],"featuresAt":5}""").api)
        val kept = AccountData(server = "https://a", features = listOf("icons"), api = 2)
        assertEquals(kept, AppJson.decodeFromString(AccountData.serializer(), AppJson.encodeToString(AccountData.serializer(), kept)))
    }

    /** The web vault's `siteIconsShown`: the user's setting and the server's icon service together. */
    @Test
    fun websiteIconsFollowTheSettingAndTheServer() {
        assertFalse("the user turned them off", SiteIcons.shown(false, 2, listOf("icons")))
        assertTrue("config not known yet: the setting decides", SiteIcons.shown(true, null, null))
        assertTrue("a list kept without its API version: the setting decides", SiteIcons.shown(true, null, emptyList()))
        assertTrue("API 2 with the icon service", SiteIcons.shown(true, 2, listOf("delta_sync", "icons")))
        assertFalse("API 2 without it: the service is off", SiteIcons.shown(true, 2, listOf("delta_sync")))
        assertFalse("a later API without it", SiteIcons.shown(true, 3, emptyList()))
    }

    @Test
    fun policyErrorsInPlainWords() {
        val sk = failedResponse(400, """{"error":"secret_key_required","message":"this server requires a Secret Key: turn on \"Use a Secret Key\""}""", null)
        assertEquals("Your server requires a Secret Key. Turn on \"Use a Secret Key\" and try again.", errorMessage(sk))
        val kdf = failedResponse(400, """{"error":"kdf_too_weak","message":"this server requires stronger key derivation"}""", null)
        assertEquals("Your server's encryption settings have changed. Try again.", errorMessage(kdf))
        val gate = failedResponse(403, """{"error":"two_step_required","message":"this server requires two-step login: turn it on in Settings → Two-step login"}""", null)
        assertEquals("Your server requires two-step login. Set it up to continue.", errorMessage(gate))
        // The app's own "enter your Secret Key" is unchanged.
        assertEquals("This account uses a Secret Key. Enter it from your Emergency Kit.", errorMessage(UserException(VaultRepository.SECRET_KEY_REQUIRED)))
        assertNull(PolicyRules.errorMessage(ApiException(400, "bad_request", "nope")))
    }

    @Test
    fun twoStepGateDecisions() {
        val gate = failedResponse(403, """{"error":"two_step_required","message":"x"}""", null)
        assertTrue(TwoStepGate.blocks(gate))
        assertFalse(TwoStepGate.blocks(ApiException(403, "forbidden", "x")))
        assertFalse(TwoStepGate.blocks(ApiException(400, "two_step_required", "x")))
        assertFalse(TwoStepGate.blocks(UserException("two_step_required")))
        assertEquals(TwoStepGate.Next.Sync, TwoStepGate.afterSetup(keysInMemory = true))
        assertEquals(TwoStepGate.Next.Unlock, TwoStepGate.afterSetup(keysInMemory = false))
        // The gate replaces the vault and the unlock screen of a signed-in account, nothing else.
        assertTrue(TwoStepGate.shows(Status.Unlocked, gated = true))
        assertTrue(TwoStepGate.shows(Status.Locked, gated = true))
        assertFalse(TwoStepGate.shows(Status.LoggedOut, gated = true))
        assertFalse(TwoStepGate.shows(Status.Unlocked, gated = false))
        // No live sync while gated (the socket would be refused, in a loop).
        assertTrue(TwoStepGate.liveSyncAllowed(Status.Unlocked, gated = false))
        assertFalse(TwoStepGate.liveSyncAllowed(Status.Unlocked, gated = true))
        assertEquals(
            "Set up a second step for a@x.io to open your vault. It's asked for after your master password when you sign in on a new device, so a stolen password isn't enough.",
            TwoStepGate.intro("a@x.io"),
        )
    }

    /** `/sync` answering "set up two-step login first" is that error, not "the answer couldn't be read". */
    @Test
    fun syncRefusedForTwoStepIsTheGateNotAnUnreadableAnswer() {
        val e = assertThrows(ApiException::class.java) {
            runBlocking {
                DeltaSync.fetch(null, delta = true, trashSummary = true) { _ ->
                    throw failedResponse(403, """{"error":"two_step_required","message":"this server requires two-step login"}""", null)
                }
            }
        }
        assertTrue(TwoStepGate.blocks(e))
        // The same for a locked account's background refresh.
        val cached = SyncSnapshot(1, "c1", null, JsonObject(emptyMap()), emptyList(), emptyList())
        val e2 = assertThrows(ApiException::class.java) {
            runBlocking {
                DeltaSync.refresh(cached, delta = true, trashSummary = true) { _ -> throw failedResponse(403, """{"error":"two_step_required","message":"x"}""", null) }
            }
        }
        assertTrue(TwoStepGate.blocks(e2))
    }
}
