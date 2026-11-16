package io.passauth.app

import io.passauth.app.data.SignedSharing
import io.passauth.core.Account
import io.passauth.core.CoreException
import io.passauth.core.SigningIdentity
import io.passauth.core.VaultKey
import io.passauth.core.accountFromSessionBytes
import io.passauth.core.compareMembers
import io.passauth.core.epochCheck
import io.passauth.core.mergePins
import io.passauth.core.normalizeEmail
import io.passauth.core.pinCheck
import io.passauth.core.pinSet
import io.passauth.core.pinsAdmit
import io.passauth.core.pinsCheckOwnIdentity
import io.passauth.core.pinsEpochCheck
import io.passauth.core.pinsGrandfather
import io.passauth.core.pinsLeave
import io.passauth.core.pinsLegacyWrapAllowed
import io.passauth.core.pinsObserve
import io.passauth.core.pinsSetEpoch
import io.passauth.core.pinsSetOwnIdentity
import io.passauth.core.rosterHash
import io.passauth.core.rosterHead
import io.passauth.core.rosterMemberRole
import io.passauth.core.rosterReview
import io.passauth.core.rosterSignerRole
import io.passauth.core.verifyIdentity
import io.passauth.core.verifyRosterChain
import io.passauth.core.verifyShare
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

/**
 * The `signedSharing` golden vectors (testdata/vectors.json, made from the Rust core's WASM build by
 * testdata/generate-vectors.mjs and cross-checked there independently of the core): identities with
 * their X25519 cross-signatures and fingerprints, share signatures, member rosters (byte-exact,
 * signed again through the core's review), key commitments and key ids, account wraps, roster
 * chains and heads, member comparisons and roles, reviews, key pins, epoch pins, admissions,
 * tombstones, grandfathering and the own identity. The app calls the same core through UniFFI, so
 * every case must come out the same; the fingerprint of a pinned identity goes through the app's own
 * [SignedSharing.fingerprintOfHash].
 */
class SignedSharingVectorsTest {
    companion object {
        private lateinit var v: JsonObject
        private val accounts = mutableMapOf<String, Account>()
        private val signers = mutableMapOf<String, SigningIdentity>()
        private lateinit var vaultKey: VaultKey
        private lateinit var secondKey: VaultKey

        @JvmStatic
        @BeforeClass
        fun load() {
            val file = generateSequence(File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
                .map { File(it, "testdata/vectors.json") }.firstOrNull { it.isFile }
            requireNotNull(file) { "testdata/vectors.json not found" }
            v = Json.parseToJsonElement(file.readText()).jsonObject["signedSharing"]!!.jsonObject
            for (a in v["accounts"]!!.jsonArray.map { it.jsonObject }) {
                val name = a.s("name")
                val account = accountFromSessionBytes(a.s("id"), unb64(a.s("sessionBytes")))
                accounts[name] = account
                signers[name] = account.openSigningIdentity(a["record"]!!.toString())
            }
            val vault = v["vault"]!!.jsonObject
            vaultKey = accounts["alice"]!!.openVaultKey(vault.s("id"), vault.s("wrappedKeyV2"), "account", 0u, false)
            secondKey = accounts["alice"]!!.openVaultKey(vault.s("id"), vault.s("secondKeyV2"), "account", 0u, false)
        }

        @JvmStatic
        @AfterClass
        fun free() {
            vaultKey.destroy()
            secondKey.destroy()
            signers.values.forEach { it.destroy() }
            accounts.values.forEach { it.destroy() }
        }

        private fun unb64(s: String) = java.util.Base64.getUrlDecoder().decode(s)
        private fun JsonObject.s(key: String): String = this[key]!!.jsonPrimitive.content
        private fun JsonObject.sOrNull(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull
    }

    private val vaultId get() = v["vault"]!!.jsonObject.s("id")
    private fun cases(name: String): List<JsonObject> = v[name]!!.jsonArray.map { it.jsonObject }
    private fun full(name: String) = signers[name]!!.publicIdentityJson()
    private fun legacy(name: String) = accounts[name]!!.legacyIdentityJson()
    private fun who(name: String, isLegacy: Boolean) = if (isLegacy) legacy(name) else full(name)
    private fun roster(name: String) = cases("rosters").first { it.s("name") == name }.s("json")
    private fun rosterOrNull(name: String?) = name?.let(::roster)
    private fun rosterName(json: String) = cases("rosters").firstOrNull { it.s("json") == json }?.s("name") ?: json

    /** `[name, role, legacy?, email?]` member inputs as the core reads them (identity fields, role, the server's email). */
    private fun members(list: JsonArray, withEmail: Boolean = true): String = JsonArray(
        list.map { m ->
            val a = m.jsonArray
            val legacyFlag = (a.getOrNull(2) as? JsonPrimitive)?.booleanOrNull == true
            val id = Json.parseToJsonElement(who(a[0].jsonPrimitive.content, legacyFlag)).jsonObject
            val email = (a.getOrNull(3) as? JsonPrimitive)?.contentOrNull
            JsonObject(id + ("role" to a[1]) + (if (withEmail && email != null) mapOf("email" to JsonPrimitive(email)) else emptyMap()))
        },
    ).toString()

    private fun identityOf(pair: JsonArray) = who(pair[0].jsonPrimitive.content, pair[1].jsonPrimitive.boolean)

    /** The core's error code, as the vectors write it ("malformed" for malformed input). */
    private fun code(e: CoreException): String = when (e) {
        is CoreException.BadSignature -> "bad_signature"
        is CoreException.Rollback -> "rollback"
        is CoreException.RosterForked -> "roster_forked"
        is CoreException.RosterUnauthorized -> "roster_unauthorized"
        is CoreException.IdentityMismatch -> "identity_mismatch"
        is CoreException.TooLarge -> "too_large"
        is CoreException.ReviewMismatch -> "review_mismatch"
        is CoreException.DecryptFailed -> "decrypt_failed"
        else -> "malformed"
    }

    private fun expectedCode(error: String) = if (error.startsWith("malformed")) "malformed" else error

    private fun check(failures: MutableList<String>, what: String, want: Any?, got: Any?) {
        if (want != got) failures += "$what: got $got, want $want"
    }

    /** [f]'s result against the case's `expected`, or its error against `error`. */
    private fun expect(failures: MutableList<String>, what: String, c: JsonObject, f: () -> Any?) {
        try {
            val got = f()
            if (c.containsKey("error")) failures += "$what: got $got, want error ${c.s("error")}"
            else check(failures, what, c["expected"], got)
        } catch (e: CoreException) {
            if (c.containsKey("error")) check(failures, what, expectedCode(c.s("error")), code(e))
            else failures += "$what: error ${code(e)}, want ${c["expected"]}"
        }
    }

    private fun json(s: String): JsonElement = Json.parseToJsonElement(s)
    private fun str(s: String?): JsonElement = s?.let { JsonPrimitive(it) } ?: JsonNull

    @Test
    fun vectorsAreThere() {
        for (name in listOf("accounts", "identities", "shares", "rosters", "commitments", "chains", "heads", "memberDiffs", "rosterRoles", "pinChecks", "reviews", "epochChecks", "pinsEpochChecks", "admissions", "legacyWraps", "openings", "observations", "emails")) {
            assertTrue("no $name vectors", (v[name] as? JsonArray)?.isNotEmpty() == true)
        }
    }

    @Test
    fun identities() {
        val failures = mutableListOf<String>()
        for (c in cases("identities")) {
            val name = c.s("name")
            val pub = c["publicIdentity"]!!.jsonObject
            check(failures, "$name public identity", pub, json(full(name)))
            check(failures, "$name legacy identity", c["legacyIdentity"], json(legacy(name)))
            val info = json(verifyIdentity(pub.toString())).jsonObject
            check(failures, "$name hash", c.s("hash"), info.s("hash"))
            check(failures, "$name legacy hash", c.s("legacyHash"), info.s("legacy_hash"))
            check(failures, "$name fingerprint", c.s("fingerprint"), info.s("fingerprint"))
            check(failures, "$name own fingerprint", c.s("fingerprint"), signers[name]!!.fingerprint())
            check(failures, "$name identity hash", c.s("hash"), signers[name]!!.identityHash())
            check(failures, "$name fingerprintOfHash", c.s("fingerprint"), SignedSharing.fingerprintOfHash(c.s("hash")))
            check(failures, "$name legacy verify", c.s("legacyHash"), json(verifyIdentity(legacy(name))).jsonObject.s("hash"))
            // Without its X25519 cross-signature an identity doesn't verify.
            val stripped = JsonObject(pub + ("x25519_signature" to JsonNull))
            check(failures, "$name without cross-signature", true, runCatching { verifyIdentity(stripped.toString()) }.isFailure)
        }
        // Someone else's X25519 key paired with another signing key (the forged "upgrade"): refused.
        check(failures, "forged upgrade", "bad_signature", try {
            verifyIdentity(v["forgedUpgrade"].toString())
            null
        } catch (e: CoreException) {
            code(e)
        })
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun shareSignatures() {
        val failures = mutableListOf<String>()
        for (c in cases("shares")) {
            val to = who(c.s("recipient"), c["recipientLegacy"]!!.jsonPrimitive.boolean)
            val epoch = c["keyEpoch"]!!.jsonPrimitive.long.toULong()
            val what = "${c.s("signer")}→${c.s("recipient")} ${c.s("role")}@${c.s("keyEpoch")}"
            val sig = signers[c.s("signer")]!!.signShare(c.s("vaultId"), to, c.s("role"), epoch, c.s("sealedKey"))
            check(failures, "$what signature", c.s("signature"), sig)
            val ok = runCatching { verifyShare(c.s("vaultId"), to, c.s("role"), epoch, c.s("sealedKey"), full(c.s("signer")), c.s("signature")) }
            check(failures, "$what verifies", true, ok.isSuccess)
            val other = if (c.s("role") == "read") "write" else "read"
            check(failures, "$what other role", true, runCatching { verifyShare(c.s("vaultId"), to, other, epoch, c.s("sealedKey"), full(c.s("signer")), c.s("signature")) }.exceptionOrNull() is CoreException.BadSignature)
            check(failures, "$what other epoch", true, runCatching { verifyShare(c.s("vaultId"), to, c.s("role"), epoch + 1u, c.s("sealedKey"), full(c.s("signer")), c.s("signature")) }.exceptionOrNull() is CoreException.BadSignature)
            // A legacy signer signs nothing.
            check(failures, "$what legacy signer", true, runCatching { verifyShare(c.s("vaultId"), to, c.s("role"), epoch, c.s("sealedKey"), legacy(c.s("signer")), c.s("signature")) }.isFailure)
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun rostersKeysAndOpenings() {
        val failures = mutableListOf<String>()
        for (c in cases("rosters")) {
            if (c["rogue"]!!.jsonPrimitive.boolean) continue
            val previous = c.sOrNull("previous")?.let(::roster)
            val list = members(c["members"]!!.jsonArray)
            val signer = signers[c.s("signer")]!!
            val digest = json(rosterReview(vaultId, previous, signer.publicIdentityJson(), list, null)).jsonObject.s("digest")
            val text = signer.signRoster(vaultKey, vaultId, previous, c["keyEpoch"]!!.jsonPrimitive.long.toULong(), list, digest)
            check(failures, "roster ${c.s("name")}", c.s("json"), text)
            check(failures, "roster ${c.s("name")} matches the key", true, vaultKey.matchesRoster(vaultId, text))
            check(failures, "roster ${c.s("name")} of another vault", false, runCatching { vaultKey.matchesRoster("00000000-0000-4000-8000-0000000000ff", text) }.getOrDefault(false))
            check(failures, "roster ${c.s("name")} epoch", c["keyEpoch"]!!.jsonPrimitive.long, SignedSharing.rosterEpoch(text))
            check(failures, "roster ${c.s("name")} version", c["version"]!!.jsonPrimitive.long, SignedSharing.rosterVersion(text))
            check(failures, "roster ${c.s("name")} hash", c.s("hash"), rosterHash(text))
            // Another digest than the reviewed list's: review_mismatch.
            check(failures, "roster ${c.s("name")} unreviewed", true, runCatching { signer.signRoster(vaultKey, vaultId, previous, c["keyEpoch"]!!.jsonPrimitive.long.toULong(), list, "AAAA") }.exceptionOrNull() is CoreException.ReviewMismatch)
        }
        for (c in cases("commitments")) {
            check(failures, "commitment @${c.s("keyEpoch")}", c.s("commitment"), vaultKey.commitment(vaultId, c["keyEpoch"]!!.jsonPrimitive.long.toULong()))
        }
        val ids = v["keyIds"]!!.jsonObject
        check(failures, "key id", ids.s("first"), vaultKey.keyId(vaultId))
        check(failures, "second key id", ids.s("second"), secondKey.keyId(vaultId))
        val vault = v["vault"]!!.jsonObject
        for (c in cases("openings")) {
            expect(failures, "opening ${c.s("wrap")}@${c.s("keyEpoch")} legacy=${c["legacyAllowed"]}", c) {
                val k = accounts["alice"]!!.openVaultKey(vaultId, vault.s(c.s("wrap")), "account", c["keyEpoch"]!!.jsonPrimitive.long.toULong(), c["legacyAllowed"]!!.jsonPrimitive.boolean)
                try {
                    JsonPrimitive(k.keyId(vaultId))
                } finally {
                    k.destroy()
                }
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun chainsAndHeads() {
        val failures = mutableListOf<String>()
        for (c in cases("chains")) {
            val newer = c["newer"]!!.jsonArray.map { roster(it.jsonPrimitive.content) }
            expect(failures, "chain ${c.sOrNull("trusted")} + ${c["newer"]} → ${c.sOrNull("latest")}", c) {
                JsonPrimitive(rosterName(verifyRosterChain(c.s("vault"), rosterOrNull(c.sOrNull("trusted")), newer, roster(c.s("latest")))))
            }
        }
        for (c in cases("heads")) {
            expect(failures, "head ${c.sOrNull("remembered")} / ${c.sOrNull("latest")}", c) {
                json(rosterHead(c.s("vault"), rosterOrNull(c.sOrNull("remembered")), rosterOrNull(c.sOrNull("latest"))))
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun membersRolesAndReviews() {
        val failures = mutableListOf<String>()
        for (c in cases("memberDiffs")) {
            check(failures, "members ${c["members"]}", c["expected"], json(compareMembers(roster(c.s("roster")), members(c["members"]!!.jsonArray, withEmail = false))))
        }
        for (c in cases("rosterRoles")) {
            val id = identityOf(c["identity"]!!.jsonArray)
            check(failures, "member role of ${c["identity"]} in ${c.s("roster")}", c.sOrNull("member"), rosterMemberRole(roster(c.s("roster")), id))
            check(failures, "signer role of ${c["identity"]} in ${c.s("roster")}", c.sOrNull("signer"), rosterSignerRole(roster(c.s("roster")), id))
        }
        val pins = v["keyPins"]!!.toString()
        for (c in cases("reviews")) {
            val got = json(rosterReview(vaultId, rosterOrNull(c.sOrNull("previous")), full(c.s("signer")), members(c["members"]!!.jsonArray), pins))
            check(failures, "review ${c.s("name")}", c["expected"], got)
            // The app's view of it.
            val shown = SignedSharing.parseReview(got.toString(), "Team")
            check(failures, "review ${c.s("name")} digest", c["expected"]!!.jsonObject.sOrNull("digest") ?: "", shown.digest)
            check(failures, "review ${c.s("name")} members", c["expected"]!!.jsonObject["members"]!!.jsonArray.size, shown.members.size)
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun keyPinsEpochsAndAdmissions() {
        val failures = mutableListOf<String>()
        val pins = v["keyPins"]!!.toString()
        // The pins rebuilt through the app's calls.
        val rebuilt = pinSet(pinSet(null, full("bob"), "bob@example.com", true, 1000), legacy("carol"), "carol@example.com", false, 1000)
        check(failures, "rebuilt pins", json(pins), json(rebuilt))
        for (c in cases("pinChecks")) {
            check(failures, "pin check ${c["identity"]} ${c.sOrNull("email")}", c.s("expected"), pinCheck(pins, identityOf(c["identity"]!!.jsonArray), c.sOrNull("email")))
        }
        val people = SignedSharing.people(pins)
        check(failures, "people", listOf("bob@example.com", "carol@example.com"), people.map { it.email })
        val bob = cases("identities").first { it.s("name") == "bob" }
        check(failures, "bob's pinned fingerprint", bob.s("fingerprint"), people.first { it.email == "bob@example.com" }.fingerprint)
        for (c in cases("epochChecks")) {
            val pinned = c["pinned"]?.takeIf { it !is JsonNull }?.toString()
            check(failures, "epoch check ${c["pinned"]} / ${c["current"]}", c.s("expected"), epochCheck(pinned, c["current"].toString()))
        }
        val withEpoch = pinsSetEpoch(pins, vaultId, vaultKey.epochPinJson(vaultId, 1u), 2u)
        check(failures, "pins with epoch", v["keyPinsWithEpoch"], json(withEpoch))
        for (c in cases("pinsEpochChecks")) {
            val rv = (c["rosterVersion"] as? JsonPrimitive)?.longOrNull?.toULong()
            check(failures, "pins epoch check ${c["current"]} @${c["rosterVersion"]}", c.s("expected"), pinsEpochCheck(withEpoch, vaultId, c["current"].toString(), rv))
        }
        val raised = pinsSetEpoch(withEpoch, vaultId, secondKey.epochPinJson(vaultId, 2u), 3u)
        check(failures, "raised", v["keyPinsRaised"], json(raised))
        val otherDevice = pinsSetEpoch(null, vaultId, secondKey.epochPinJson(vaultId, 2u), null)
        check(failures, "merged epochs", v["mergedEpochs"], json(mergePins(withEpoch, otherDevice)).jsonObject["epochs"])
        val left = pinsLeave(raised, vaultId, 3u, 2000)
        check(failures, "left", v["keyPinsLeft"], json(left))
        val grandfathered = pinsGrandfather(pins, listOf(vaultId), true)
        check(failures, "grandfathered", v["keyPinsGrandfathered"], json(grandfathered))
        check(failures, "needs grandfathering", true, SignedSharing.needsGrandfathering(pins))
        check(failures, "grandfathered once", false, SignedSharing.needsGrandfathering(grandfathered))
        // Trust memory missing: an identity this unlock didn't create grandfathers nothing.
        val withheld = pinsGrandfather(pins, listOf(vaultId), false)
        check(failures, "withheld", v["keyPinsWithheld"], json(withheld))
        val unsigned = pinsSetEpoch(grandfathered, vaultId, vaultKey.epochPinJson(vaultId, 1u), null)
        check(failures, "unsigned", v["keyPinsUnsigned"], json(unsigned))
        val v3 = cases("rosters").first { it.s("name") == "v3" }
        val observation = """{"vault_id":"$vaultId","key_kind":"sealed","key":${vaultKey.epochPinJson(vaultId, 1u)},"roster_version":3,"roster_hash":"${v3.s("hash")}","signed_share":true,"paused":false}"""
        val rosterMax = json(pinsObserve(withEpoch, observation)).jsonObject["pins"].toString()
        check(failures, "roster max", v["keyPinsRosterMax"], json(rosterMax))
        val sets = mapOf(
            "none" to null, "withEpoch" to withEpoch, "raised" to raised, "left" to left, "grandfathered" to grandfathered,
            "withheld" to withheld, "unsigned" to unsigned, "rosterMax" to rosterMax,
        )
        for (c in cases("admissions")) {
            check(failures, "admission ${c.s("pins")} ${c["observation"]}", c["expected"], json(pinsAdmit(sets.getValue(c.s("pins")), c["observation"].toString())))
        }
        // Observations chained over a sync's rows, from the grandfathered pins.
        var step: String = grandfathered
        for (c in cases("observations")) {
            val observed = json(pinsObserve(step, c["observation"].toString()))
            check(failures, "observation ${c["observation"]}", c["expected"], observed)
            step = observed.jsonObject["pins"].toString()
        }
        for (c in cases("emails")) {
            check(failures, "email ${c.s("email")}", c.s("expected"), normalizeEmail(c.s("email")))
            check(failures, "shown email ${c.s("email")}", c.s("expected"), SignedSharing.normalized(c.s("email")))
        }
        for (c in cases("legacyWraps")) {
            check(failures, "legacy wrap ${c.s("pins")}", c["expected"]!!.jsonPrimitive.boolean, pinsLegacyWrapAllowed(sets.getValue(c.s("pins")), vaultId))
        }
        val own = v["ownIdentity"]!!.jsonObject
        check(failures, "own hash", own.s("hash"), signers["alice"]!!.identityHash())
        val withOwn = pinsSetOwnIdentity(pins, own.s("hash"))
        check(failures, "with own", own["pins"], json(withOwn))
        check(failures, "own identity read back", own.s("hash"), SignedSharing.ownIdentityOf(withOwn))
        for (c in own["checks"]!!.jsonArray.map { it.jsonObject }) {
            val p = if (c.s("pins") == "withOwn") withOwn else null
            check(failures, "own check ${c.s("pins")} ${c.sOrNull("listed")}", c.s("expected"), pinsCheckOwnIdentity(p, c.sOrNull("listed")))
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }
}
