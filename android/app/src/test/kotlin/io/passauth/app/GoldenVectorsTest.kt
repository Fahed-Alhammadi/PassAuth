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
        // Counters at and beyond what every client can count (2^53 − 1): the core reads them clamped
        // and an update never fails, so one planted number can't jam an item; this app's model takes them.
        val limits = v["limits"]!!.jsonObject
        val owner = io.passauth.core.accountFromSessionBytes(limits.s("accountId"), java.util.Base64.getUrlDecoder().decode(limits.s("sessionBytes")))
        val limitKey = owner.openVaultKey(limits.s("vaultId"), limits.s("wrappedKey"), "account", limits.s("keyEpoch").toULong(), false)
        val top = limits.s("top").toLong()
        val planted = limits["items"]!!.jsonArray.map { it.jsonObject }
        assertTrue(planted.size >= 5)
        for (i in planted) {
            val e = i["encrypted"]!!.jsonObject
            val enc = EncryptedItem(e.s("id"), e.s("vault_id"), e.s("key"), e.s("data"))
            val read = io.passauth.app.data.ItemCodec.decode(limitKey.decryptItem(enc))
            check(failures, "rev ${i.s("rev")} reads", i.s("reads").toLong(), read.rev)
            val updated = limitKey.updateItem(enc, io.passauth.app.data.ItemCodec.encode(read))
            check(failures, "rev ${i.s("rev")} writes", minOf(i.s("writes").toLong(), top), rev(limitKey, updated))
        }
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

    /**
     * Vault manifests: every verdict of `manifestVerify` (with and without device memory and the
     * manifest log), the link of every manifest, every kind of write through `manifestNext`, and
     * `manifestStart` (first manifest, baseline, key replacement), with the fixture's account and
     * its two wrapped vault keys. Each row list also goes through the app's own row builder
     * ([io.passauth.app.data.Manifests.rows] over its sync rows) and must come out the same.
     */
    @Test
    fun vaultManifests() {
        val failures = mutableListOf<String>()
        val v = vectors["vaultManifest"]!!.jsonObject
        val vaultId = v.s("vaultId")
        val account = io.passauth.core.accountFromSessionBytes(v.s("accountId"), java.util.Base64.getUrlDecoder().decode(v.s("sessionBytes")))
        val rotated = v["rotated"]!!.jsonObject
        val keys = mapOf(
            "main" to account.openVaultKey(vaultId, v.s("wrappedKey"), "account", v.s("keyEpoch").toULong(), false),
            "rotated" to account.openVaultKey(vaultId, rotated.s("wrappedKey"), "account", rotated.s("keyEpoch").toULong(), false),
        )
        val items = v["items"]!!.jsonObject
        val manifests = v["manifests"]!!.jsonObject
        fun long(o: JsonObject, k: String): Long? = (o[k] as? JsonPrimitive)?.takeIf { !it.isString }?.contentOrNull?.toLong()
        fun obj(o: JsonObject, k: String): JsonObject? = o[k] as? JsonObject

        /** The rows as this app holds them (its sync rows): `id`, `deleted_at` and the data or its hash, nothing else. */
        fun appRows(rows: JsonArray): String = io.passauth.app.data.Manifests.rows(
            rows.map { it.jsonObject }.map { r ->
                io.passauth.app.data.SyncItem(
                    r.s("id"), r.sOrNull("vault_id") ?: vaultId, null, r.sOrNull("data"), long(r, "revision"), long(r, "deleted_at"),
                    dataSha256 = r.sOrNull("data_sha256"),
                )
            },
        )
        fun same(a: io.passauth.core.ManifestCheck, e: JsonObject) =
            a.status == e.s("status") && a.version == e.s("version").toULong() && a.link == e.sOrNull("link") &&
                a.live == e.s("live").toULong() && a.trashed == e.s("trashed").toULong()

        // Every manifest's link is what the core's `manifestLink` gives for its row.
        for ((name, m) in manifests) {
            val row = m.jsonObject
            val link = row.sOrNull("link") ?: continue
            check(failures, "link of $name", link, io.passauth.core.manifestLink(row.s("manifest_seq").toULong(), row.s("manifest_prev"), row.s("manifest")))
        }

        val checks = v["checks"]!!.jsonArray.map { it.jsonObject }
        assertTrue(checks.size >= 40)
        val seen = mutableSetOf<String>()
        for (c in checks) {
            val row = manifests[c.s("manifest")]!!.jsonObject
            val key = keys.getValue(c.s("key"))
            val epoch = c.s("keyEpoch").toULong()
            val rows = items[c.s("items")]!!.jsonArray
            val remembered = obj(c, "remembered")
            val log = (c["log"] as? JsonArray)?.toString()
            val expected = c["expected"]!!.jsonObject
            seen += expected.s("status")
            for (mine in listOf(false, true)) {
                val got = key.manifestVerify(
                    vaultId, epoch, row.s("manifest_seq").toULong(), row.sOrNull("manifest_prev"), row.sOrNull("manifest"),
                    remembered?.s("version")?.toULong(), remembered?.sOrNull("link"), log, if (mine) appRows(rows) else rows.toString(),
                )
                if (!same(got, expected)) failures += "check ${c.s("name")} (app rows: $mine): got $got, want $expected"
            }
        }
        assertEquals(setOf("none", "ok", "rollback", "mismatch", "incomplete", "need_log"), seen)

        // Round 2: `manifestAccept` (the check behind "Use the server's copy"): the served head against the served rows, nothing remembered.
        val accepts = v["accepts"]!!.jsonArray.map { it.jsonObject }
        assertTrue(accepts.size >= 4)
        val acceptSeen = mutableSetOf<String>()
        for (c in accepts) {
            val row = manifests[c.s("manifest")]!!.jsonObject
            val rows = items[c.s("items")]!!.jsonArray
            val expected = c["expected"]!!.jsonObject
            acceptSeen += expected.s("status")
            for (mine in listOf(false, true)) {
                val got = keys.getValue(c.s("key")).manifestAccept(
                    vaultId, c.s("keyEpoch").toULong(), row.s("manifest_seq").toULong(), row.sOrNull("manifest_prev"), row.sOrNull("manifest"),
                    if (mine) appRows(rows) else rows.toString(),
                )
                if (!same(got, expected)) failures += "accept ${c.s("name")} (app rows: $mine): got $got, want $expected"
            }
            // The app's own wrapper gives the same verdict, with a mark only for "ok".
            val header = io.passauth.app.data.SyncVault(
                vaultId, keyEpoch = c.s("keyEpoch").toLong(), manifest = row.sOrNull("manifest"), manifestSeq = row.s("manifest_seq").toLong(), manifestPrev = row.sOrNull("manifest_prev"),
            )
            val appItems = rows.map { it.jsonObject }.map { r ->
                io.passauth.app.data.SyncItem(r.s("id"), vaultId, null, r.sOrNull("data"), long(r, "revision"), long(r, "deleted_at"), dataSha256 = r.sOrNull("data_sha256"))
            }
            val wrapped = io.passauth.app.data.Manifests.accept(keys.getValue(c.s("key")), header, appItems)
            check(failures, "app accept ${c.s("name")}", expected.s("status"), wrapped.status)
            check(failures, "app accept mark ${c.s("name")}", expected.sOrNull("link").takeIf { expected.s("status") == "ok" }, wrapped.mark?.link)
        }
        assertTrue("$acceptSeen", acceptSeen.containsAll(setOf("ok", "mismatch")))

        // Rows every entry point refuses (a `deleted_at` that is no time, …).
        val current = manifests["current"]!!.jsonObject
        val main = keys.getValue("main")
        val mainEpoch = v.s("keyEpoch").toULong()
        val malformed = v["malformed"]!!.jsonArray.map { it.jsonObject }
        assertTrue(malformed.size >= 5)
        for ((n, m) in malformed.withIndex()) {
            val rows = m["items"].toString()
            try {
                main.manifestVerify(vaultId, mainEpoch, current.s("manifest_seq").toULong(), current.s("manifest_prev"), current.s("manifest"), null, null, null, rows)
                failures += "malformed $n: verify took it"
            } catch (_: io.passauth.core.CoreException) {
            }
            try {
                main.manifestStart(vaultId, mainEpoch, 1u, null, rows)
                failures += "malformed $n: start took it"
            } catch (_: io.passauth.core.CoreException) {
            }
            try {
                main.manifestAccept(vaultId, mainEpoch, current.s("manifest_seq").toULong(), current.s("manifest_prev"), current.s("manifest"), rows)
                failures += "malformed $n: accept took it"
            } catch (_: io.passauth.core.CoreException) {
            }
        }

        // Round 2: memories the core refuses (version 0, the all-zero link): never handed to it by the app.
        val badMemories = v["badMemories"]!!.jsonArray.map { it.jsonObject }
        assertTrue(badMemories.isNotEmpty())
        for ((n, m) in badMemories.withIndex()) {
            try {
                main.manifestVerify(
                    vaultId, mainEpoch, current.s("manifest_seq").toULong(), current.s("manifest_prev"), current.s("manifest"),
                    m.s("version").toULong(), m.sOrNull("link"), null, items["full"]!!.jsonArray.toString(),
                )
                failures += "bad memory $n: verify took it"
            } catch (_: io.passauth.core.CoreException) {
            }
            val asStored = """{"v":{"version":${m["version"]},"link":${m["link"]}}}"""
            if (io.passauth.app.data.Manifests.marks(io.passauth.app.data.Manifests.decodeMemory(asStored)).isNotEmpty()) failures += "bad memory $n: the app would remember it"
        }

        val writes = v["writes"]!!.jsonArray.map { it.jsonObject }
        assertTrue(writes.size >= 7)
        val version = current.s("manifest_seq").toULong()
        for (w in writes) {
            val expected = w["expected"]!!.jsonObject
            for (mine in listOf(false, true)) {
                val removed = if (mine) appRows(w["removed"]!!.jsonArray) else w["removed"].toString()
                val added = if (mine) appRows(w["added"]!!.jsonArray) else w["added"].toString()
                val next = main.manifestNext(vaultId, mainEpoch, version, current.s("manifest_prev"), current.s("manifest"), removed, added)
                check(failures, "write ${w.s("name")} seq (app rows: $mine)", expected.s("seq").toULong(), next.seq)
                check(failures, "write ${w.s("name")} prev (app rows: $mine)", expected.s("prev"), next.prev)
                check(failures, "write ${w.s("name")} names the current manifest", current.s("link"), next.prev)
                val after = main.manifestVerify(vaultId, mainEpoch, next.seq, next.prev, next.sealed, version, current.s("link"), null, w["after"].toString())
                check(failures, "write ${w.s("name")} verifies (app rows: $mine)", "ok", after.status)
                check(failures, "write ${w.s("name")} link", next.link, after.link)
                check(failures, "write ${w.s("name")} live", expected.s("live").toULong(), after.live)
                check(failures, "write ${w.s("name")} trashed", expected.s("trashed").toULong(), after.trashed)
            }
        }

        val starts = v["starts"]!!.jsonArray.map { it.jsonObject }
        assertTrue(starts.size >= 3)
        for (st in starts) {
            val key = keys.getValue(st.s("key"))
            val epoch = st.s("keyEpoch").toULong()
            val rows = items[st.s("items")]!!.jsonArray
            val expected = st["expected"]!!.jsonObject
            val remembered = obj(st, "remembered")
            for (mine in listOf(false, true)) {
                val text = if (mine) appRows(rows) else rows.toString()
                val made = key.manifestStart(vaultId, epoch, st.s("version").toULong(), st.sOrNull("prev"), text)
                check(failures, "start ${st.s("name")} seq", expected.s("seq").toULong(), made.seq)
                check(failures, "start ${st.s("name")} prev", expected.s("prev"), made.prev)
                val after = key.manifestVerify(vaultId, epoch, made.seq, made.prev, made.sealed, remembered?.s("version")?.toULong(), remembered?.sOrNull("link"), null, text)
                check(failures, "start ${st.s("name")} verifies (app rows: $mine)", "ok", after.status)
                check(failures, "start ${st.s("name")} link", made.link, after.link)
            }
        }
        // The data hash the app keeps for rows without data is the core's.
        for (t in v["terms"]!!.jsonArray.map { it.jsonObject }) {
            val row = items["full"]!!.jsonArray.map { it.jsonObject }.first { it.s("id") == t.s("id") }
            check(failures, "data hash of ${t.s("id")}", t.s("dataSha256"), io.passauth.core.manifestDataHash(row.s("data")))
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** The vectors' account "alice" (signed sharing section), opened from its session bytes. */
    private fun alice(): io.passauth.core.Account {
        val a = vectors["signedSharing"]!!.jsonObject["accounts"]!!.jsonArray.map { it.jsonObject }.first { it.s("name") == "alice" }
        return io.passauth.core.accountFromSessionBytes(a.s("id"), java.util.Base64.getUrlDecoder().decode(a.s("sessionBytes")))
    }
}
