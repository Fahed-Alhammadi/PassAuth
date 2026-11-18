package io.passauth.app

import io.passauth.app.autofill.SaveRule
import io.passauth.app.credentials.PasskeyTargets
import io.passauth.app.credentials.WebAuthn
import io.passauth.app.credentials.WebAuthnException
import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.Role
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultData
import io.passauth.app.data.VaultInfo
import io.passauth.core.EncryptedItem
import io.passauth.core.matchesUrl
import io.passauth.core.normalizeHost
import io.passauth.core.publicSuffix
import io.passauth.core.publicSuffixListVersion
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The golden vectors every client checks (testdata/vectors.json, generated from the Rust core's
 * WASM build by testdata/generate-vectors.mjs): host names, public suffixes and base domains,
 * website matching, the downgrade rule, refused patterns, the save rule, passkey "Save in"
 * targets and RP ID checks. This app calls the same core through UniFFI (the host build, see
 * build.gradle.kts), so every case must come out the same; each section goes through the app's
 * own wrapper where there is one (UrlMatcher, SaveRule, PasskeyTargets, WebAuthn).
 */
class GoldenVectorsTest {
    private val vectors: JsonObject by lazy {
        // Gradle runs unit tests in android/app; the file is at the repository root.
        val file = generateSequence(File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
            .map { File(it, "testdata/vectors.json") }.firstOrNull { it.isFile }
        requireNotNull(file) { "testdata/vectors.json not found" }
        Json.parseToJsonElement(file.readText()).jsonObject
    }

    private fun cases(name: String): List<JsonObject> = vectors[name]!!.jsonArray.map { it.jsonObject }
    private fun JsonObject.s(key: String): String = this[key]!!.jsonPrimitive.content
    private fun JsonObject.sOrNull(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull
    private fun JsonObject.b(key: String): Boolean = this[key]!!.jsonPrimitive.boolean

    /** The app's match type for a vector's string; null for one the app's items can't hold (sent to the core as is). */
    private fun match(s: String): UrlMatch? = UrlMatch.entries.firstOrNull { it.wire == s }

    private fun check(failures: MutableList<String>, what: String, want: Any?, got: Any?) {
        if (want != got) failures += "$what: got $got, want $want"
    }

    @Test
    fun vectorsAreThere() {
        // A broken path would make every check below pass on an empty list.
        assertEquals(2, vectors["version"]?.jsonPrimitive?.content?.toInt())
        for (name in listOf("normalizeHost", "baseDomain", "publicSuffix", "urlMatch", "downgrade", "regexError", "savePlan", "passkeyTargets", "rpId")) {
            if ((vectors[name] as? JsonArray).isNullOrEmpty()) fail("no $name vectors")
        }
    }

    @Test
    fun theSameSuffixList() {
        assertEquals("vectors.json was made with another Public Suffix List", vectors.s("publicSuffixList"), publicSuffixListVersion())
    }

    @Test
    fun hostsAndSites() {
        val failures = mutableListOf<String>()
        for (c in cases("normalizeHost")) check(failures, "normalizeHost(${c.s("host")})", c.sOrNull("expected"), normalizeHost(c.s("host")))
        for (c in cases("baseDomain")) check(failures, "baseDomain(${c.s("host")})", c.s("expected"), UrlMatcher.baseDomain(c.s("host")))
        for (c in cases("publicSuffix")) check(failures, "publicSuffix(${c.s("host")})", c.s("expected"), publicSuffix(c.s("host")))
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun urlMatching() {
        val failures = mutableListOf<String>()
        for (c in cases("urlMatch")) {
            // `allowRegex` false: a login in a vault somebody shared (its regular expressions never count).
            val allowRegex = c.b("allowRegex")
            val m = match(c.s("match"))
            val d = match(c.s("defaultMatch"))
            val got = if (m != null && d != null) {
                UrlMatcher.matches(c.s("page"), LoginUrl(c.s("url"), m), d, allowRegex)
            } else {
                matchesUrl(c.s("page"), c.s("url"), c.s("match"), c.s("defaultMatch"), allowRegex)
            }
            check(failures, "${c.s("match")}/${c.s("defaultMatch")} ${if (allowRegex) "own" else "shared"} ${c.s("page")} vs ${c.s("url")} (${c.s("note")})", c.b("expected"), got)
            // The same through matchesAny (one call for a login's websites).
            if (m != null && d != null) {
                val any = UrlMatcher.matchesAny(c.s("page"), Login(urls = listOf(LoginUrl(c.s("url"), m))), d, allowRegex)
                check(failures, "matchesAny ${c.s("page")} vs ${c.s("url")} (${c.s("note")})", c.b("expected"), any)
            }
        }
        if (cases("urlMatch").none { !it.b("allowRegex") }) failures += "no shared-vault urlMatch cases"
        for (c in cases("downgrade")) {
            val got = UrlMatcher.downgrade(c.s("page"), LoginUrl(c.s("url"), match(c.s("match"))!!))
            check(failures, "downgrade ${c.s("page")} vs ${c.s("url")} (${c.s("note")})", c.b("expected"), got)
        }
        for (c in cases("regexError")) check(failures, "regexError ${c.s("pattern").take(40)}", c.sOrNull("expected"), UrlMatcher.regexError(c.s("pattern")))
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    private fun candidate(o: JsonObject) = SaveRule.Candidate(
        id = o.s("id"),
        name = o.s("name"),
        username = o.s("username"),
        password = o.s("password"),
        writable = o.b("writable"),
        personal = o.b("personal"),
        vault = o.sOrNull("vault").orEmpty(),
    )

    @Test
    fun savePlan() {
        val failures = mutableListOf<String>()
        for (c in cases("savePlan")) {
            val list = c["candidates"]!!.jsonArray.map { candidate(it.jsonObject) }
            val user = c.s("typedUser")
            val password = c.s("password")
            val want = c["expected"]!!.jsonObject
            val plan = SaveRule.plan(list, user, password)
            val got = when (plan) {
                SaveRule.Plan.Nothing -> "none"
                SaveRule.Plan.New -> "create"
                is SaveRule.Plan.Update -> "update ${plan.reason.name.lowercase()} ${plan.id}"
            }
            val wanted = when (want.s("action")) {
                "update" -> "update ${want.s("reason")} ${want.s("target")}"
                else -> want.s("action")
            }
            if (got != wanted) {
                failures += "${c.s("name")}: got $got, want $wanted"
                continue
            }
            if (plan == SaveRule.Plan.Nothing) continue
            // "Save in": the targets in order, a shared one labelled with its vault ("Shared vault" without a name).
            val targets = SaveRule.targets(list, user, password).map { t -> t.id to if (t.personal) null else t.vault.ifEmpty { "Shared vault" } }
            val wantTargets = want["targets"]!!.jsonArray.map { it.jsonObject.s("id") to it.jsonObject.sOrNull("vault") }
            if (targets != wantTargets) failures += "${c.s("name")}: targets $targets, want $wantTargets"
            // Only what was offered is accepted as a choice; "New login" always.
            for (cand in list) {
                val accepted = SaveRule.planFor(list, cand.id, user, password) != null
                if (accepted != wantTargets.any { it.first == cand.id }) failures += "${c.s("name")}: choice ${cand.id} accepted=$accepted"
            }
            if (SaveRule.planFor(list, null, user, password) != SaveRule.Plan.New) failures += "${c.s("name")}: New login refused"
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun passkeyTargets() {
        val failures = mutableListOf<String>()
        for (c in cases("passkeyTargets")) {
            val logins = c["logins"]!!.jsonArray.map { it.jsonObject }
            fun vaultId(o: JsonObject) = when {
                o.b("personal") -> "personal"
                o.b("writable") -> "shared-${o.s("vault")}"
                else -> "ro-${o.s("vault")}"
            }
            val vaults = listOf(VaultInfo("personal", "Personal", Role.Owner)) + logins.filter { !it.b("personal") }.map {
                VaultInfo(vaultId(it), it.s("vault"), if (it.b("writable")) Role.Write else Role.Read, keyKind = "sealed")
            }.distinctBy { it.id }
            val entries = logins.map { o ->
                val id = o.s("id")
                Entry(
                    id = id,
                    item = Item(name = o.s("name"), login = Login(username = o.s("username"), password = "pw", urls = o["urls"]!!.jsonArray.map { LoginUrl(it.jsonPrimitive.content, UrlMatch.Default) })),
                    vaultId = vaultId(o),
                    revision = 1,
                    enc = EncryptedItem(id = id, vaultId = vaultId(o), key = "", data = ""),
                )
            }
            val vault = VaultData(entries = entries, vaults = vaults)
            val targets = PasskeyTargets.saveTargets(vault, c.s("host"), c.s("rpId"), c.s("userName"), c.s("displayName"))
            val got = targets.map { t -> Triple(t.id, t.preferred, vault.vaults.first { it.id == t.entry.vaultId }.takeIf { !it.personal }?.name) }
            val wanted = c["expected"]!!.jsonArray.map { it.jsonObject }.map { Triple(it.s("id"), it.b("preferred"), it.sOrNull("vault")) }
            if (got != wanted) failures += "${c.s("name")}: got $got, want $wanted"
            check(failures, "${c.s("name")}: default", c.s("expectedDefault"), PasskeyTargets.defaultTarget(targets))
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun rpIds() {
        val failures = mutableListOf<String>()
        for (c in cases("rpId")) {
            val requested = c["requested"].takeIf { it != JsonNull }?.jsonPrimitive?.content
            val want: JsonElement = c["expected"]!!
            val what = "${c.s("origin")} / $requested (${c.s("note")})"
            try {
                val got = WebAuthn.effectiveRpId(requested, c.s("origin"))
                check(failures, what, want.takeIf { it != JsonNull }?.jsonPrimitive?.content, got)
            } catch (e: WebAuthnException) {
                if (want != JsonNull) failures += "$what: refused (${e.message}), want ${want.jsonPrimitive.content}"
                check(failures, "$what: kind", WebAuthnException.Kind.Security, e.kind)
                check(failures, "$what: message", c.sOrNull("message"), e.message)
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** Send v2: one Argon2id run gives the server's verifier and the content key; the v2 field opens with it (and not without). */
    @Test
    fun sendV2() {
        val v = vectors["sendV2"]!!.jsonObject
        val keys = io.passauth.core.sendPasswordKeys(v.s("password"), v.s("salt"), v.s("key"))
        assertEquals(v.s("verifier"), keys.verifier)
        assertEquals(v.s("contentKey"), keys.contentKey)
        assertEquals(v.s("verifier"), io.passauth.core.sendPasswordVerifier(v.s("password"), v.s("salt")))
        assertEquals(2, io.passauth.core.sendFieldVersion(v.s("data")).toInt())
        assertEquals(v.s("text"), io.passauth.core.sendOpen(v.s("key"), keys.contentKey, "data", v.s("data")))
        try {
            io.passauth.core.sendOpen(v.s("key"), null, "data", v.s("data"))
            fail("a v2 field opened without its content key")
        } catch (_: io.passauth.core.CoreException.PasswordRequired) {
        }
    }

    /** The item edit counter: the rollback rule ([io.passauth.core.itemRevCheck]) and the chain of writes. */
    @Test
    fun itemRev() {
        val v = vectors["itemRev"]!!.jsonObject
        val failures = mutableListOf<String>()
        val checks = v["checks"]!!.jsonArray.map { it.jsonObject }
        assertTrue(checks.size >= 5)
        for (c in checks) {
            val remembered = (c["remembered"] as? JsonPrimitive)?.contentOrNull?.toULong()
            val served = c.s("served").toULong()
            check(failures, "itemRevCheck($remembered, $served)", c.s("expected"), io.passauth.core.itemRevCheck(remembered, served))
        }
        // The chain through this app's own model (ItemCodec keeps `rev`): encrypt (1), update (2),
        // update with an item of rev 0 (3), restore of the first version (4), move to another vault (5).
        val account = alice()
        val vault = account.newVaultKey("v1").key
        val other = account.newVaultKey("v2").key
        fun rev(k: io.passauth.core.VaultKey, e: EncryptedItem) = io.passauth.app.data.ItemCodec.decode(k.decryptItem(e)).rev
        val item = Item(name = "Mail")
        val e1 = vault.encryptItem(io.passauth.app.data.ItemCodec.encode(item), "i1", "v1")
        val first = io.passauth.app.data.ItemCodec.decode(vault.decryptItem(e1))
        val e2 = vault.updateItem(e1, io.passauth.app.data.ItemCodec.encode(first.copy(name = "Mail 2")))
        val e3 = vault.updateItem(e2, io.passauth.app.data.ItemCodec.encode(item.copy(name = "Old app")))
        val e4 = vault.updateItem(e3, io.passauth.app.data.ItemCodec.encode(first))
        val e5 = other.encryptItem(vault.decryptItem(e4), "i1", "v2")
        val chain = listOf(rev(vault, e1), rev(vault, e2), rev(vault, e3), rev(vault, e4), rev(other, e5))
        check(failures, "rev chain", v["chain"]!!.jsonArray.map { it.jsonPrimitive.content.toLong() }, chain)
        // The editor's copy keeps `rev` but a rev alone never makes two items differ in what the user sees.
        check(failures, "rev kept through the model", 2L, io.passauth.app.data.ItemCodec.decode(io.passauth.app.data.ItemCodec.encode(io.passauth.app.data.ItemCodec.decode(vault.decryptItem(e2)))).rev)
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** Account wraps v2: bound to the epoch given; a v1 wrap is opened only where the pins allow it. */
    @Test
    fun boundAccountWraps() {
        val account = alice()
        val made = account.newVaultKeyBound("v1", 3u)
        assertTrue(io.passauth.core.accountWrapIsBound(made.wrapped))
        account.openVaultKey("v1", made.wrapped, "account", 3u, false).close()
        try {
            account.openVaultKey("v1", made.wrapped, "account", 2u, true)
            fail("a v2 wrap opened at another epoch")
        } catch (_: io.passauth.core.CoreException) {
        }
        val rewrapped = made.key.wrapForBound(account, "v1", 4u)
        assertTrue(io.passauth.core.accountWrapIsBound(rewrapped))
        val legacy = made.key.wrapFor(account, "v1")
        assertTrue(!io.passauth.core.accountWrapIsBound(legacy))
        // The app's own reading of the server's hint: only a JSON true.
        assertTrue(io.passauth.app.data.SignedSharing.accountWrapsV2(Json.parseToJsonElement("""{"account_wraps_v2":true}""")))
        for (no in listOf("""{"account_wraps_v2":"true"}""", """{"account_wraps_v2":1}""", "{}", "null")) {
            assertTrue(no, !io.passauth.app.data.SignedSharing.accountWrapsV2(Json.parseToJsonElement(no)))
        }
    }

    /** The vectors' account "alice" (signed sharing section), opened from its session bytes. */
    private fun alice(): io.passauth.core.Account {
        val a = vectors["signedSharing"]!!.jsonObject["accounts"]!!.jsonArray.map { it.jsonObject }.first { it.s("name") == "alice" }
        return io.passauth.core.accountFromSessionBytes(a.s("id"), java.util.Base64.getUrlDecoder().decode(a.s("sessionBytes")))
    }
}
