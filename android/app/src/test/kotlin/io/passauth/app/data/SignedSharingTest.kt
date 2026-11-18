package io.passauth.app.data

import io.passauth.core.Account
import io.passauth.core.SigningIdentity
import io.passauth.core.VaultKey
import io.passauth.core.accountFromSessionBytes
import io.passauth.core.newId
import io.passauth.core.rosterReview
import java.io.File
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Signed sharing, the app's side ([SharingSession], [RotationRules]), with the real core and the
 * vectors' fixed accounts (alice owns the vault and shares it with bob; carol is a third person).
 * The server is a fake ([FakeSharingApi]) and this phone's memory a variable. Each review finding
 * (Android H1–H3, M1–M2, L1–L5, Info; the client parts of the core review; iOS M3/M4) has a test.
 */
class SignedSharingTest {
    private class Fixture(val name: String, val id: String, val account: Account, val record: String, val identity: SigningIdentity) {
        val public: String get() = identity.publicIdentityJson()
        val hash: String get() = identity.identityHash()
        fun row(role: String, email: String = "$name@example.com"): JsonObject =
            JsonObject(Json.parseToJsonElement(public).jsonObject + mapOf("role" to JsonPrimitive(role), "email" to JsonPrimitive(email), "name" to JsonPrimitive(name)))
    }

    private class FakeSharingApi : SharingApi {
        val identities = mutableListOf<String>()
        var putIdentityError: Exception? = null
        var current: JsonElement? = null
        var pins: String? = null
        var pinsSeq = 0L
        var puts = 0
        val rosters = mutableMapOf<String, MutableList<String>>()
        val asked = mutableListOf<Long>()
        var offline = false
        var endless: String? = null

        /** The upload lands but its answer is lost. */
        var loseIdentityAnswer = false
        var getPinsError: Exception? = null
        var putPinsError: Exception? = null

        override suspend fun putIdentity(recordJson: String): Boolean {
            putIdentityError?.let { throw it }
            identities += recordJson
            if (loseIdentityAnswer) throw java.io.IOException("answer lost")
            return true
        }

        override suspend fun currentIdentity(): JsonElement? = current

        override suspend fun getKeyPins(): Pair<String?, Long> {
            getPinsError?.let { throw it }
            return pins to pinsSeq
        }

        override suspend fun putKeyPins(sealed: String, seq: Long) {
            putPinsError?.let { throw it }
            if (seq != pinsSeq + 1) throw ApiException(409, "key_pins_changed", "changed")
            pins = sealed
            pinsSeq = seq
            puts++
        }

        /** What `GET /vaults/{id}/members` says ([SharingApi.stillMember]). */
        var member: Boolean? = null

        override suspend fun stillMember(vaultId: String): Boolean? = member

        override suspend fun rosters(vaultId: String, after: Long): Pair<List<String>, Boolean> {
            if (offline) throw UserException(UNREACHABLE)
            asked += after
            endless?.let { return listOf(it) to true }
            val all = rosters[vaultId].orEmpty()
            return all.filter { SignedSharing.rosterVersion(it)!! > after } to false
        }
    }

    private class Memory : SigningMemoryStore {
        var m = SigningMemory()
        override suspend fun read() = m
        override suspend fun write(transform: (SigningMemory) -> SigningMemory) {
            m = transform(m)
        }
    }

    private lateinit var alice: Fixture
    private lateinit var bob: Fixture
    private lateinit var carol: Fixture
    private lateinit var vaultId: String
    private lateinit var key: VaultKey
    private val api = FakeSharingApi()
    private val memory = Memory()
    private val opened = mutableListOf<AutoCloseable>()

    @Before
    fun setUp() {
        val file = generateSequence(File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
            .map { File(it, "testdata/vectors.json") }.first { it.isFile }
        val v = Json.parseToJsonElement(file.readText()).jsonObject["signedSharing"]!!.jsonObject
        val fixtures = v["accounts"]!!.jsonArray.map { it.jsonObject }.associate { a ->
            val name = a["name"]!!.jsonPrimitive.content
            val id = a["id"]!!.jsonPrimitive.content
            val account = accountFromSessionBytes(id, java.util.Base64.getUrlDecoder().decode(a["sessionBytes"]!!.jsonPrimitive.content))
            val record = a["record"]!!.toString()
            name to Fixture(name, id, account, record, account.openSigningIdentity(record))
        }
        alice = fixtures.getValue("alice")
        bob = fixtures.getValue("bob")
        carol = fixtures.getValue("carol")
        val vault = v["vault"]!!.jsonObject
        vaultId = vault["id"]!!.jsonPrimitive.content
        key = alice.account.openVaultKey(vaultId, vault["wrappedKey"]!!.jsonPrimitive.content, "account", 0u, true)
    }

    @After
    fun tearDown() {
        opened.forEach { it.close() }
        key.destroy()
        for (f in listOf(alice, bob, carol)) {
            f.identity.destroy()
            f.account.destroy()
        }
    }

    /** [earlier]: the vaults this phone showed as usable before the unlock (the grandfathering candidates). */
    private fun session(f: Fixture, now: Long = 1000, earlier: Set<String> = setOf(vaultId)): SharingSession =
        SharingSession(f.account, api, memory, { now }, earlier).also { opened += it }

    private fun user(f: Fixture, pinsSeq: Long = api.pinsSeq, identity: JsonElement = Json.parseToJsonElement(f.record)): JsonObject = buildJsonObject {
        put("id", f.id)
        put("identity", identity)
        put("key_pins_seq", pinsSeq)
    }

    private fun members(vararg rows: JsonObject) = JsonArray(rows.toList()).toString()

    /** A roster after [previous] (or version 1) at [epoch] listing [members], signed by [by] through the core's review. */
    private fun roster(epoch: Long, vararg members: JsonObject, previous: String? = null, by: Fixture = alice, k: VaultKey = key): String {
        val list = members(*members)
        val digest = SignedSharing.text(SignedSharing.obj(rosterReview(vaultId, previous, by.public, list, null)), "digest")!!
        return by.identity.signRoster(k, vaultId, previous, epoch.toULong(), list, digest)
    }

    private fun shareOf(signature: String, by: Fixture, email: String = "${by.name}@example.com", deleted: Boolean = false): JsonObject = buildJsonObject {
        put("signature", signature)
        put("signer", JsonObject(Json.parseToJsonElement(by.public).jsonObject + mapOf("email" to JsonPrimitive(email), "name" to JsonPrimitive(by.name))))
        put("signer_deleted", deleted)
    }

    /** Bob's row of the vault: the key sealed to him and signed by [by] at [epoch] with [role]. */
    private fun bobsVault(role: String = "write", epoch: Long = 0, rosterText: String? = null, by: Fixture = alice, signed: Boolean = true, k: VaultKey = key, email: String = "${by.name}@example.com"): SyncVault {
        val share = by.identity.sealAndSignShare(k, vaultId, bob.public, role, epoch.toULong())
        return SyncVault(
            vaultId, role = role, wrappedKey = share.sealedKey, keyKind = "sealed", keyEpoch = epoch,
            share = if (signed) shareOf(share.signature, by, email) else null,
            memberRoster = rosterText, memberRosterSeq = rosterText?.let { SignedSharing.rosterVersion(it) } ?: 0,
        )
    }

    /** An unsigned share from before (sealed without a signature). */
    private fun legacyVault(epoch: Long = 0) = SyncVault(vaultId, role = "write", wrappedKey = key.shareTo(vaultId, bob.account.publicKey()), keyKind = "sealed", keyEpoch = epoch)

    private suspend fun check(s: SharingSession, f: Fixture, v: SyncVault, online: Boolean = true): VaultCheck =
        s.checkVault(v, { legacy -> f.account.openVaultKey(v.id, v.wrappedKey, v.keyKind, (v.keyEpoch ?: 0).toULong(), legacy) }, { "Team" }, online)

    /** Bob's session after accepting the vault [v] (the consent of a vault the account never accepted). */
    private suspend fun accepted(v: SyncVault): SharingSession {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val c = check(s, bob, v) as VaultCheck.Consent
        assertTrue(c.vault.acceptable)
        s.acceptConsent(c.vault)
        return s
    }

    // ----------------------------------------------------------- identity, pins

    @Test
    fun anAccountWithoutIdentityMakesAndUploadsOne() = runBlocking {
        val s = session(bob)
        assertEquals(bob.id, s.me)
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertEquals(1, api.identities.size)
        assertNotNull(s.fingerprint)
        assertTrue(s.canSign)
        // Its identity is remembered: on this phone and in the key pins.
        assertEquals(s.fingerprint, SignedSharing.fingerprintOfHash(memory.m.ownIdentity!!))
        assertEquals(memory.m.ownIdentity, SignedSharing.ownIdentityOf(s.pins))
        // Offline it doesn't try (and checks with the legacy identity meanwhile).
        val offline = SharingSession(carol.account, api, Memory()).also { opened += it }
        offline.refresh(buildJsonObject { put("identity", JsonNull) }, online = false)
        assertEquals(1, api.identities.size)
        assertNull(offline.fingerprint)
        assertEquals(Json.parseToJsonElement(carol.account.legacyIdentityJson()), Json.parseToJsonElement(offline.myIdentityJson))
    }

    @Test
    fun anIdentityMadeElsewhereMeanwhileIsOpened() = runBlocking {
        api.putIdentityError = ApiException(409, "identity_exists", "exists")
        api.current = Json.parseToJsonElement(bob.record)
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertEquals(bob.identity.fingerprint(), s.fingerprint)
        assertFalse(s.paused)
    }

    /** Me = the core-authenticated account: a sync naming another account is refused. */
    @Test
    fun aSyncOfAnotherAccountIsRefused() = runBlocking {
        val s = session(bob)
        try {
            s.refresh(user(alice, 0), online = true)
            fail("another account's sync was used")
        } catch (_: WrongAccountException) {
        }
        assertNull(s.fingerprint)
    }

    /** H1: paused refuses every sealed (shared) row, a planted one too; the account's own vaults keep their key checks. */
    @Test
    fun anotherAccountsIdentityPausesSharingAndRefusesEverySharedVault() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, Json.parseToJsonElement(alice.record)), online = true)
        assertTrue(s.paused)
        assertFalse(s.canSign)
        assertNull(s.fingerprint)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        // A properly signed share, a planted unsigned one: both refused, nothing opened or remembered.
        assertEquals(VaultCheck.Refused(SignedSharing.PAUSED), check(s, bob, bobsVault(rosterText = r)))
        assertEquals(VaultCheck.Refused(SignedSharing.PAUSED), check(s, bob, legacyVault()))
        assertTrue(api.asked.isEmpty())
        assertTrue(memory.m.rosters.isEmpty())
        // Bob's own vault is still used, its key epoch pinned.
        val own = SyncVault(vaultId, role = "owner", wrappedKey = key.wrapFor(bob.account, vaultId), keyKind = "account", keyEpoch = 0)
        assertEquals(VaultCheck.Ok(VaultTrust.Own), check(s, bob, own))
        assertNotNull(SignedSharing.epochOf(s.pins, vaultId))
        // Invitations neither.
        val inv = invitation(rosterText = r)
        assertEquals(InvitationTrust.Refused(SignedSharing.PAUSED), s.checkInvitation(inv, opener, online = true))
        // Nothing is signed.
        try {
            s.planRotation(vaultId, "Team", null, listOf(bob.row("owner")), null)
            fail("signed while paused")
        } catch (e: UserException) {
            assertEquals(SignedSharing.PAUSED, e.message)
        }
    }

    /** Info/L4: the own identity is remembered; none or a malformed one listed later pauses instead of making another. */
    @Test
    fun theOwnIdentityIsRememberedSoNoneOrAMalformedOneLaterPauses() = runBlocking {
        session(bob).refresh(user(bob, 0), online = true)
        assertEquals(bob.hash, memory.m.ownIdentity)
        val none = session(bob)
        none.refresh(user(bob, 0, JsonNull), online = true)
        assertTrue(none.paused)
        assertTrue(api.identities.isEmpty())
        val malformed = session(bob)
        malformed.refresh(user(bob, 0, JsonPrimitive("x")), online = true)
        assertTrue(malformed.paused)
        // The right one again: not paused.
        val back = session(bob)
        back.refresh(user(bob, 0), online = true)
        assertFalse(back.paused)
    }

    @Test
    fun keyPinsAreWrittenByCompareAndSwapAndMerged() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        // Another device wrote version 1 meanwhile (carol pinned): merged, written as 2.
        val other = io.passauth.core.pinSet(null, carol.public, "carol@example.com", true, 5)
        api.pins = bob.account.sealKeyPins(other, 1u)
        api.pinsSeq = 1
        s.savePins()
        assertEquals(2L, api.pinsSeq)
        val stored = Json.parseToJsonElement(bob.account.openKeyPins(api.pins!!, 2u)).jsonObject
        assertEquals(setOf(carol.id), stored["pins"]!!.jsonArray.map { it.jsonObject["user_id"]!!.jsonPrimitive.content }.toSet())
        assertEquals(bob.hash, stored["own_identity"]!!.jsonPrimitive.content)
        assertEquals(2L, memory.m.pinsSeq)
        // Nothing new: nothing written.
        s.savePins()
        assertEquals(2L, api.pinsSeq)
    }

    @Test
    fun olderKeyPinsFromTheServerAreARollback() = runBlocking {
        val pins = io.passauth.core.pinSet(null, alice.public, "alice@example.com", false, 5)
        memory.m = SigningMemory(pinsSeq = 3, pinsSealed = bob.account.sealKeyPins(pins, 3u))
        api.pins = bob.account.sealKeyPins(io.passauth.core.pinSet(null, carol.public, "carol@example.com", false, 5), 2u)
        api.pinsSeq = 2
        val s = session(bob)
        s.refresh(user(bob, 2), online = true)
        assertEquals(SignedSharing.PINS_ROLLED_BACK, s.pinsProblem)
        // The phone's copy is used, and nothing is written.
        assertEquals(listOf("alice@example.com"), SignedSharing.people(s.pins).map { it.email })
        assertTrue(s.markVerified(alice.id, alice.hash))
        s.savePins()
        assertEquals(2L, api.pinsSeq)
        assertEquals(0, api.puts)
    }

    @Test
    fun keyPinsSealedWithAnotherKeyAreRefused() = runBlocking {
        api.pins = alice.account.sealKeyPins(io.passauth.core.pinSet(null, carol.public, "carol@example.com", false, 5), 1u)
        api.pinsSeq = 1
        val s = session(bob)
        s.refresh(user(bob, 1), online = true)
        assertEquals(SignedSharing.PINS_UNREADABLE, s.pinsProblem)
    }

    // ------------------------------------------------------------- vaults

    /** Core H2: a signed vault the account never accepted is held for consent; accepting pins it. */
    @Test
    fun aNeverAcceptedSignedVaultNeedsConsentThenIsTrusted() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val v = bobsVault(rosterText = r)
        val c = (check(s, bob, v) as VaultCheck.Consent).vault
        assertEquals("Team", c.name)
        assertEquals("alice@example.com", c.signer!!.email)
        assertEquals(PinState.New, c.signer!!.pin)
        assertFalse(c.rejoin)
        // Nothing pinned or remembered before the user accepts.
        assertTrue(memory.m.rosters.isEmpty())
        assertTrue(SignedSharing.people(s.pins).isEmpty())
        assertNull(SignedSharing.epochOf(s.pins, vaultId))
        s.acceptConsent(c)
        assertEquals(r, memory.m.rosters[vaultId])
        assertEquals(listOf(alice.id), SignedSharing.people(s.pins).map { it.userId })
        val trust = (check(s, bob, v) as VaultCheck.Ok).trust as VaultTrust.Signed
        assertEquals("alice@example.com", trust.signer.email)
        assertEquals(alice.identity.fingerprint(), trust.signer.fingerprint)
        assertFalse(trust.signer.verified)
        // The second sync: the same roster, no fetch needed (works offline too).
        api.rosters.clear()
        assertTrue(check(s, bob, v, online = false) is VaultCheck.Ok)
        // L3: "Mark as verified" marks only the identity that was shown.
        assertFalse(s.markVerified(alice.id, carol.hash))
        assertTrue(s.markVerified(alice.id, alice.hash))
        assertTrue((((check(s, bob, v) as VaultCheck.Ok).trust as VaultTrust.Signed).signer.verified))
    }

    /** Core H2: an unsigned vault planted after the first signed sync is held for consent and can't be accepted. */
    @Test
    fun aPlantedUnsignedVaultCantBeAccepted() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(emptyList(), online = true)
        val c = (check(s, bob, legacyVault()) as VaultCheck.Consent).vault
        assertFalse(c.acceptable)
        try {
            s.acceptConsent(c)
            fail("an unsigned vault was accepted")
        } catch (e: UserException) {
            assertEquals(SignedSharing.CONSENT_UNSIGNED, e.message)
        }
    }

    /** Grandfathering: only when this unlock made the identity; then the shares from before are "Not yet signed", until a roster was seen. */
    @Test
    fun theFirstSignedSyncGrandfathersTheSharesFromBefore() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
        assertEquals("Not yet signed", SignedSharing.label(VaultTrust.NotYetSigned))
        // A roster this phone trusted, then an unsigned share (or no roster at all): refused.
        memory.m = memory.m.copy(rosters = mapOf(vaultId to roster(0, alice.row("owner"), bob.row("write"))))
        assertTrue(check(s, bob, legacyVault()) is VaultCheck.Refused)
    }

    /** An account that had an identity but no key pins: nothing grandfathered, every shared vault needs consent. */
    @Test
    fun anExistingIdentityWithoutKeyPinsGrandfathersNothing() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(s.memoryMissing)
        // An empty list is written (once): nothing grandfathered.
        assertFalse(SignedSharing.needsGrandfathering(s.pins))
        val c = (check(s, bob, legacyVault()) as VaultCheck.Consent).vault
        // In this state only, the user may accept an unsigned vault ("Not yet signed").
        assertTrue(c.unsignedAllowed && c.acceptable)
        s.acceptConsent(c)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
    }

    /** Round 3: an unsigned key replacement of an accepted, never-signed vault is held for consent ("replaced"), never silently used. */
    @Test
    fun anUnsignedKeyReplacementNeedsConsent() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
        val other = alice.account.newVaultKey(vaultId)
        try {
            val replaced = SyncVault(vaultId, role = "write", wrappedKey = other.key.shareTo(vaultId, bob.account.publicKey()), keyKind = "sealed", keyEpoch = 1)
            val c = (check(s, bob, replaced) as VaultCheck.Consent).vault
            assertTrue(c.replaced)
            assertTrue(c.acceptable)
            s.acceptConsent(c)
            assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, replaced))
        } finally {
            other.destroy()
        }
    }

    @Test
    fun forgedOrMismatchedSharesAreRefusedAndNothingIsRemembered() = runBlocking {
        val r = roster(0, alice.row("owner"), bob.row("write"), carol.row("read"))
        api.rosters[vaultId] = mutableListOf(r)
        val signed = bobsVault(rosterText = r)
        val s = accepted(signed)
        val pinsBefore = s.pins
        // Another role than signed.
        assertTrue(check(s, bob, signed.copy(role = "admin")) is VaultCheck.Refused)
        // Signed by carol, who is only a reader in the roster.
        assertTrue(check(s, bob, bobsVault(rosterText = r, by = carol)) is VaultCheck.Refused)
        // A server-made share without signature next to a roster.
        assertTrue(check(s, bob, bobsVault(rosterText = r, signed = false)) is VaultCheck.Refused)
        // A signed share with the roster stripped.
        assertTrue(check(s, bob, bobsVault(rosterText = null)) is VaultCheck.Refused)
        // The roster's epoch isn't the vault's.
        assertTrue(check(s, bob, bobsVault(rosterText = r, epoch = 1)) is VaultCheck.Refused)
        // A roster that isn't a chain from the remembered one (version 1 again, other members): forked.
        assertTrue(check(s, bob, bobsVault(rosterText = roster(0, alice.row("owner"), bob.row("admin")))) is VaultCheck.Refused)
        // A newer roster whose share is signed by a reader: refused, and the newer roster isn't remembered (core L2).
        val r2 = roster(0, alice.row("owner"), bob.row("write"), carol.row("read"), previous = r)
        api.rosters[vaultId]!! += r2
        assertTrue(check(s, bob, bobsVault(rosterText = r2, by = carol)) is VaultCheck.Refused)
        assertEquals(r, memory.m.rosters[vaultId])
        assertEquals(pinsBefore, s.pins)
        // A key that isn't the roster's.
        val otherKey = alice.account.newVaultKey(vaultId)
        try {
            assertTrue(check(s, bob, bobsVault(rosterText = r, k = otherKey.key)) is VaultCheck.Refused)
        } finally {
            otherKey.destroy()
        }
        // The valid newer one is taken.
        assertTrue(check(s, bob, bobsVault(rosterText = r2)) is VaultCheck.Ok)
        assertEquals(r2, memory.m.rosters[vaultId])
    }

    /** Core H3: an older key, or the pinned key relabelled with a higher epoch, is refused; a new key is pinned and the old one retired. */
    @Test
    fun olderOrRelabelledKeysAreRefusedAndANewerOnePinned() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        fun own(k: VaultKey, epoch: Long) = SyncVault(vaultId, role = "owner", wrappedKey = k.wrapFor(alice.account, vaultId), keyKind = "account", keyEpoch = epoch)
        assertEquals(VaultCheck.Ok(VaultTrust.Own), check(s, alice, own(key, 1)))
        assertEquals(VaultCheck.Ok(VaultTrust.Own), check(s, alice, own(key, 1)))
        assertTrue(check(s, alice, own(key, 2)) is VaultCheck.Refused)
        val other = alice.account.newVaultKey(vaultId)
        try {
            assertEquals(VaultCheck.Ok(VaultTrust.Own), check(s, alice, own(other.key, 2)))
            assertTrue(check(s, alice, own(key, 1)) is VaultCheck.Refused)
            assertTrue(check(s, alice, own(key, 3)) is VaultCheck.Refused)
            assertTrue(check(s, alice, own(other.key, 1)) is VaultCheck.Refused)
        } finally {
            other.destroy()
        }
        // No key epoch: refused.
        assertTrue(check(s, alice, own(key, 1).copy(keyEpoch = null)) is VaultCheck.Refused)
    }

    /** L2: a signer whose keys changed stops the vault; only "Trust the new key" of the identity shown clears it. */
    @Test
    fun aSignerWithChangedKeysStopsTheVaultUntilTrusted() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val impostor = accountFromSessionBytes(alice.id, ByteArray(64) { 7 })
        val fake = impostor.newSigningIdentity()
        try {
            val pins = io.passauth.core.pinSet(null, fake.identity.publicIdentityJson(), "alice@example.com", true, 1)
            api.pins = bob.account.sealKeyPins(pins, 1u)
            api.pinsSeq = 1
            s.refresh(user(bob, 1), online = true)
            val r = roster(0, alice.row("owner"), bob.row("write"))
            api.rosters[vaultId] = mutableListOf(r)
            val v = bobsVault(rosterText = r)
            val refused = check(s, bob, v) as VaultCheck.Refused
            assertTrue(refused.reason.startsWith(SignedSharing.keysChanged("alice@example.com")))
            assertEquals(listOf(alice.id), s.changed.map { it.userId })
            assertEquals(alice.identity.fingerprint(), s.changed[0].fingerprint)
            // Still listed after other checks of the same sync.
            check(s, bob, legacyVault())
            assertEquals(listOf(alice.id), s.changed.map { it.userId })
            // Another identity than the one shown: not trusted.
            val shown = s.changed[0]
            assertFalse(s.trustNewKey(shown.copy(identityHash = carol.hash), compared = true))
            assertTrue(s.trustNewKey(shown, compared = true))
            assertTrue(s.changed.isEmpty())
            val c = (check(s, bob, v) as VaultCheck.Consent).vault
            assertTrue(c.signer!!.verified)
        } finally {
            fake.identity.destroy()
            impostor.destroy()
        }
    }

    /** A server-made account with a pinned person's email stops like a changed key. */
    @Test
    fun aNewAccountWithAKnownEmailIsAnEmailConflict() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val pins = io.passauth.core.pinSet(null, alice.public, "alice@example.com", true, 1)
        api.pins = bob.account.sealKeyPins(pins, 1u)
        api.pinsSeq = 1
        s.refresh(user(bob, 1), online = true)
        // Carol's account poses as alice@example.com.
        val r = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(r)
        assertTrue(check(s, bob, bobsVault(rosterText = r, by = carol, email = "alice@example.com")) is VaultCheck.Refused)
        val c = s.changed.single()
        assertTrue(c.conflict)
        assertEquals(SignedSharing.emailConflict("alice@example.com"), c.text)
    }

    @Test
    fun withoutTheServerANewerRosterCantBeChecked() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = false)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        val v = bobsVault(rosterText = r)
        assertEquals(VaultCheck.Refused(SignedSharing.UNCHECKED), check(s, bob, v, online = false))
        api.rosters[vaultId] = mutableListOf(r)
        api.offline = true
        assertEquals(VaultCheck.Refused(SignedSharing.UNCHECKED), check(s, bob, v))
        api.offline = false
        assertTrue(check(s, bob, v) is VaultCheck.Consent)
    }

    /** At most 10 pages / 1000 versions and 16 MiB of roster text per vault and sync. */
    @Test
    fun rosterHistoryIsCapped() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.endless = r
        assertEquals(VaultCheck.Refused(SignedSharing.TOO_MANY_CHANGES), check(s, bob, bobsVault(rosterText = r)))
        assertEquals(10, api.asked.size)
        api.endless = "x".repeat(17 * 1024 * 1024)
        api.asked.clear()
        assertEquals(VaultCheck.Refused(SignedSharing.TOO_MANY_CHANGES), check(s, bob, bobsVault(rosterText = r)))
        assertEquals(1, api.asked.size)
    }

    /** Tombstones: a left vault comes back only through consent with a newer roster. */
    @Test
    fun aLeftVaultIsRefusedUntilSharedAgain() = runBlocking {
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val v = bobsVault(rosterText = r)
        val s = accepted(v)
        s.leave(vaultId)
        val refused = check(s, bob, v) as VaultCheck.Refused
        assertEquals(SignedSharing.refusedReason("left"), refused.reason)
        val r2 = roster(0, alice.row("owner"), bob.row("write"), carol.row("read"), previous = r)
        api.rosters[vaultId]!! += r2
        val c = (check(s, bob, bobsVault(rosterText = r2)) as VaultCheck.Consent).vault
        assertTrue(c.rejoin)
    }

    // ---------------------------------------------------------- invitations

    private fun invitation(role: String = "write", rosterText: String?, signed: Boolean = true, by: Fixture = alice, email: String = "${by.name}@example.com"): SyncInvitation {
        val share = by.identity.sealAndSignShare(key, vaultId, bob.public, role, 0u)
        return SyncInvitation(
            vaultId, role, share.sealedKey, key.encryptMeta(vaultId, """{"name":"Team"}"""),
            InvitedBy(by.id, email, by.name, Json.parseToJsonElement(by.public).jsonObject["public_key"]!!.jsonPrimitive.content),
            keyEpoch = 0, share = if (signed) shareOf(share.signature, by, email) else null, memberRoster = rosterText,
        )
    }

    private val opener: (SyncInvitation) -> VaultKey? = { i -> runCatching { bob.account.openVaultKey(i.vaultId, i.wrappedKey, "sealed", 0u, false) }.getOrNull() }

    @Test
    fun invitationsMustBeSignedAndCheckedBeforeAccepting() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        assertEquals(InvitationTrust.Unsigned, s.checkInvitation(invitation(rosterText = null, signed = false), opener, online = true))
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val t = s.checkInvitation(invitation(rosterText = r), opener, online = true) as InvitationTrust.Signed
        assertEquals("alice@example.com", t.signer.email)
        assertEquals(PinState.New, t.signer.pin)
        assertEquals(alice.identity.fingerprint(), t.signer.fingerprint)
        // Nothing is pinned or remembered before accepting (the signer only on accept).
        assertTrue(memory.m.rosters.isEmpty())
        assertTrue(SignedSharing.people(s.pins).isEmpty())
        s.prepareAccept(vaultId, t)
        assertEquals(r, memory.m.rosters[vaultId])
        assertEquals(listOf(alice.id), SignedSharing.people(s.pins).map { it.userId })
        // The vault then arrives and checks against what was accepted.
        assertTrue(check(s, bob, bobsVault(rosterText = r), online = false) is VaultCheck.Ok)
        val shown = Invitation(vaultId, "write", "Team", null, null)
        assertFalse(shown.copy(trust = InvitationTrust.Unsigned).acceptable)
        assertTrue(shown.copy(trust = t).acceptable)
    }

    /** Info: an invitation's chain is checked from the remembered roster when there is one. */
    @Test
    fun anInvitationsChainStartsAtTheRememberedRoster() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        val r2 = roster(0, alice.row("owner"), bob.row("write"), carol.row("read"), previous = r)
        memory.m = memory.m.copy(rosters = mapOf(vaultId to r))
        api.rosters[vaultId] = mutableListOf(r, r2)
        assertTrue(s.checkInvitation(invitation(rosterText = r2), opener, online = true) is InvitationTrust.Signed)
        assertEquals(listOf(1L), api.asked)
        // The server's latest forks from the remembered one (another version 2): refused.
        memory.m = memory.m.copy(rosters = mapOf(vaultId to roster(0, alice.row("owner"), bob.row("read"), previous = r)))
        val fresh = session(bob).also { it.refresh(user(bob, 0), online = true) }
        assertTrue(fresh.checkInvitation(invitation(rosterText = r2), opener, online = true) is InvitationTrust.Refused)
    }

    @Test
    fun invitationsWhoseRosterGivesAnotherRoleOrSignerAreRefused() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("read"))
        api.rosters[vaultId] = mutableListOf(r)
        assertTrue(s.checkInvitation(invitation(rosterText = r), opener, online = true) is InvitationTrust.Refused)
        val r2 = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(r2)
        assertTrue(s.checkInvitation(invitation(rosterText = r2, by = alice), opener, online = true) is InvitationTrust.Refused)
        // Without a roster at all.
        assertTrue(s.checkInvitation(invitation(rosterText = null), opener, online = true) is InvitationTrust.Refused)
    }

    /** M1 + M2: the pinned email first, the server's other one only as "listed by your server as …", cleaned; never "Verified" next to it. */
    @Test
    fun theServersNamesAreNeverShownAsVerified() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val pins = io.passauth.core.pinSet(null, alice.public, "alice@example.com", true, 1)
        api.pins = bob.account.sealKeyPins(pins, 1u)
        api.pinsSeq = 1
        s.refresh(user(bob, 1), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val t = s.checkInvitation(invitation(rosterText = r, email = "boss@‮evil.example\nX"), opener, online = true) as InvitationTrust.Signed
        assertEquals("alice@example.com", t.signer.email)
        // Round 4: the core's normalized form drops invisible and control characters (no line break left to fold).
        assertEquals("boss@evil.examplex", t.signer.listedEmail)
        assertTrue(t.signer.verified)
        val line = SignedSharing.signerLine(t.signer, false)
        assertEquals("Signed by alice@example.com (listed by your server as boss@evil.examplex)", line)
        assertFalse(line.contains("Verified"))
        // Invitations read from the server are cleaned too.
        val read = Invitations.read(
            buildJsonArray {
                add(buildJsonObject {
                    put("vault_id", "v"); put("role", "read"); put("wrapped_key", "k"); put("meta", "m")
                    put("invited_by", buildJsonObject { put("id", "u"); put("email", "a​@b.c\n"); put("name", "Eve‮") })
                })
            },
        ).single()
        assertEquals("a@b.c", read.invitedBy!!.email)
        assertEquals("Eve", read.invitedBy!!.name)
    }

    // ---------------------------------------------------------- key replacement

    private fun stranger(): Triple<Account, io.passauth.core.NewSigningIdentity, JsonObject> {
        val a = accountFromSessionBytes(newId(), ByteArray(64) { 9 })
        val made = a.newSigningIdentity()
        val row = JsonObject(Json.parseToJsonElement(made.identity.publicIdentityJson()).jsonObject + mapOf("role" to JsonPrimitive("read"), "email" to JsonPrimitive("mallory@example.com")))
        return Triple(a, made, row)
    }

    /** H3/core H4: without a trusted roster, nobody the server lists is sealed to before the user reviewed exactly that list. */
    @Test
    fun aRotationWithoutARosterNeedsTheReviewOfEveryMember() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        val (a, made, mallory) = stranger()
        try {
            val honest = listOf(alice.row("owner"), bob.row("write"))
            val planted = honest + mallory
            val review = (s.planRotation(vaultId, "Team", null, planted, null) as RotationPlan.NeedsReview).review
            assertTrue(review.first)
            assertEquals(1L, review.version)
            assertEquals(setOf("alice@example.com", "bob@example.com", "mallory@example.com"), review.members.map { it.email }.toSet())
            assertTrue(review.members.first { it.email == "mallory@example.com" }.fingerprint.isNotEmpty())
            assertEquals(PinState.New, review.members.first { it.email == "bob@example.com" }.pin)
            // The user saw the honest list; the server now adds mallory: shown again, nothing signed.
            val honestReview = (s.planRotation(vaultId, "Team", null, honest, null) as RotationPlan.NeedsReview).review
            assertTrue(s.planRotation(vaultId, "Team", null, planted, ReviewApproval(honestReview.digest, emptySet())) is RotationPlan.NeedsReview)
            // Nothing pinned by planning.
            assertTrue(SignedSharing.people(s.pins).isEmpty())
            // Confirmed exactly: go ahead, bob to pin.
            val ready = s.planRotation(vaultId, "Team", null, honest, ReviewApproval(honestReview.digest, emptySet())) as RotationPlan.Ready
            assertEquals(listOf(bob.id), ready.newPins.map { Json.parseToJsonElement(it.first).jsonObject["user_id"]!!.jsonPrimitive.content })
            // A roster signed for another list than reviewed is refused by the core.
            val newKey = alice.account.newVaultKey(vaultId)
            try {
                try {
                    s.signRoster(newKey.key, vaultId, ready, 1, planted)
                    fail("signed another list than reviewed")
                } catch (e: UserException) {
                    assertEquals(SignedSharing.CHANGED_JUST_NOW, e.message)
                }
                val text = s.signRoster(newKey.key, vaultId, ready, 1, honest)
                assertEquals(1L, SignedSharing.rosterVersion(text))
            } finally {
                newKey.destroy()
            }
        } finally {
            made.identity.destroy()
            a.destroy()
        }
    }

    @Test
    fun aRotationWithATrustedRosterChecksTheMembersAndConfirmsMissingOnesById() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"), carol.row("read"))
        val rows = listOf(alice.row("owner"), bob.row("write"), carol.row("read"))
        // The vault's current key is pinned (as a sync does).
        val own = SyncVault(vaultId, role = "owner", wrappedKey = key.wrapFor(alice.account, vaultId), keyKind = "account", keyEpoch = 0)
        assertEquals(VaultCheck.Ok(VaultTrust.Own), check(s, alice, own))
        // The same members: no review needed.
        val ready = s.planRotation(vaultId, "Team", r, rows, null) as RotationPlan.Ready
        assertEquals(r, ready.trusted)
        // Carol left: confirmed per user id.
        val left = listOf(alice.row("owner"), bob.row("write"))
        val review = (s.planRotation(vaultId, "Team", r, left, null) as RotationPlan.NeedsReview).review
        assertEquals(listOf(carol.id), review.missing.map { it.userId })
        assertTrue(s.planRotation(vaultId, "Team", r, left, ReviewApproval(review.digest, setOf(bob.id))) is RotationPlan.NeedsReview)
        val go = s.planRotation(vaultId, "Team", r, left, ReviewApproval(review.digest, setOf(carol.id))) as RotationPlan.Ready
        // Someone the roster doesn't list, or another role: stop, naming them.
        val (a, made, mallory) = stranger()
        try {
            try {
                s.planRotation(vaultId, "Team", r, rows + mallory, ReviewApproval(review.digest, setOf(carol.id)))
                fail("an unknown member was accepted")
            } catch (e: UserException) {
                assertEquals(SignedSharing.membersDiffer(listOf("mallory@example.com")), e.message)
            }
        } finally {
            made.identity.destroy()
            a.destroy()
        }
        try {
            s.planRotation(vaultId, "Team", r, listOf(alice.row("owner"), bob.row("admin"), carol.row("read")), null)
            fail("a changed role was accepted")
        } catch (e: UserException) {
            assertTrue(e.message!!.contains("bob@example.com"))
        }
        // The shares and roster it then signs check out for the members; the new key is pinned.
        val newKey = alice.account.newVaultKey(vaultId)
        try {
            val share = s.sealAndSign(newKey.key, vaultId, bob.row("write"), 1)
            val next = s.signRoster(newKey.key, vaultId, go, 1, left)
            io.passauth.core.verifyShare(vaultId, bob.public, "write", 1u, share.sealedKey, alice.public, share.signature)
            assertEquals(next, io.passauth.core.verifyRosterChain(vaultId, r, listOf(next), next))
            s.rememberRotation(vaultId, next, newKey.key.epochPinJson(vaultId, 1u), go.newPins)
            assertEquals(next, memory.m.rosters[vaultId])
            assertEquals("same", io.passauth.core.pinsEpochCheck(s.pins, vaultId, newKey.key.epochPinJson(vaultId, 1u), 2u))
            // The old key is retired.
            assertEquals("older", io.passauth.core.pinsEpochCheck(s.pins, vaultId, key.epochPinJson(vaultId, 5u), 2u))
        } finally {
            newKey.destroy()
        }
    }

    @Test
    fun aRotationStopsForAMemberWhoseKeysChanged() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        val pins = io.passauth.core.pinSet(null, bob.public, "bob@example.com", true, 1)
        api.pins = alice.account.sealKeyPins(pins, 1u)
        api.pinsSeq = 1
        s.refresh(user(alice, 1), online = true)
        val impostor = accountFromSessionBytes(bob.id, ByteArray(64) { 5 })
        val fake = impostor.newSigningIdentity()
        try {
            val swapped = JsonObject(Json.parseToJsonElement(fake.identity.publicIdentityJson()).jsonObject + mapOf("role" to JsonPrimitive("write"), "email" to JsonPrimitive("bob@example.com")))
            try {
                s.planRotation(vaultId, "Team", null, listOf(alice.row("owner"), swapped), null)
                fail("a changed identity was accepted")
            } catch (e: UserException) {
                assertEquals(SignedSharing.keysChanged("bob@example.com"), e.message)
            }
            assertEquals(listOf(bob.id), s.changed.map { it.userId })
        } finally {
            fake.identity.destroy()
            impostor.destroy()
        }
    }

    /** H2 + L1: a rotation re-encrypts only the state the sync verified, and signs whenever a roster is remembered. */
    @Test
    fun aRotationIgnoresAnUnverifiedSyncAndSignsWhenARosterIsRemembered() {
        val r = roster(0, alice.row("owner"), bob.row("write"))
        val verified = SyncVault(vaultId, role = "owner", wrappedKey = "w1", keyKind = "account", keyEpoch = 0, memberRoster = r, memberRosterSeq = 1)
        assertEquals(RotationRules.Base.Ok, RotationRules.checkBase(verified, 0, verified, true, r, 1, r))
        // The /sync the items come from serves another key (or epoch): never re-encrypted from.
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 0, verified.copy(wrappedKey = "planted"), true, r, 1, r))
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 0, verified.copy(keyEpoch = 1), true, r, 1, r))
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 0, null, true, r, 1, r))
        // The members answer is of another key epoch.
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 1, verified, true, r, 1, r))
        // The server's roster isn't the trusted one (newer, hidden, or another).
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 0, verified, true, r, 2, r))
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 0, verified, true, r, 0, null))
        assertEquals(RotationRules.Base.Retry, RotationRules.checkBase(verified, 0, verified, true, null, 1, r))
        // L1: the server hides the roster and says the account is alone: still signed (the roster is remembered).
        assertTrue(RotationRules.mustSign(r, 0, null, alone = true))
        assertFalse(RotationRules.mustSign(null, 0, null, alone = true))
        assertTrue(RotationRules.mustSign(null, 0, null, alone = false))
    }

    // ---------------------------------------------------------- the rest

    /** L5 + iOS M4: a vault with a signed history isn't personal for emergency access. */
    @Test
    fun aVaultSharedUnderASignedRosterIsNotPersonal() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        assertFalse(s.sharedBefore(vaultId))
        memory.m = memory.m.copy(rosters = mapOf(vaultId to roster(0, alice.row("owner"))))
        assertFalse(s.sharedBefore(vaultId))
        memory.m = memory.m.copy(rosters = mapOf(vaultId to roster(0, alice.row("owner"), bob.row("write"))))
        assertTrue(s.sharedBefore(vaultId))
        memory.m = SigningMemory(signed = setOf(vaultId))
        assertTrue(s.sharedBefore(vaultId))
        val own = OwnVault(vaultId, Role.Owner, "account")
        assertTrue(Emergency.isPersonal(own, listOf(alice.id), alice.id, sharedBefore = false))
        assertFalse(Emergency.isPersonal(own, listOf(alice.id), alice.id, sharedBefore = true))
    }

    /** iOS M3: trust memory writes merge, never overwrite. */
    @Test
    fun memoryWritesMerge() {
        val r1 = roster(0, alice.row("owner"), bob.row("write"))
        val r2 = roster(0, alice.row("owner"), bob.row("write"), carol.row("read"), previous = r1)
        val mine = SigningMemory(pinsSeq = 4, pinsSealed = "s4", rosters = mapOf("v" to r2, "w" to r1), signed = setOf("v"), ownIdentity = "me")
        val stale = SigningMemory(pinsSeq = 3, pinsSealed = "s3", rosters = mapOf("v" to r1, "x" to r1), signed = setOf("x"), ownIdentity = "other")
        val merged = mine.merge(stale)
        assertEquals(4L, merged.pinsSeq)
        assertEquals("s4", merged.pinsSealed)
        assertEquals(mapOf("v" to r2, "w" to r1, "x" to r1), merged.rosters)
        assertEquals(setOf("v", "x"), merged.signed)
        assertEquals("me", merged.ownIdentity)
        assertEquals(5L, merged.merge(SigningMemory(pinsSeq = 5, pinsSealed = "s5")).pinsSeq)
    }

    @Test
    fun syncRowsAndInvitationsKeepTheirSignatures() {
        val r = roster(0, alice.row("owner"), bob.row("write"))
        val inv = invitation(rosterText = r)
        val answer = buildJsonObject {
            put("revision", 3)
            put("vaults", buildJsonArray { add(AppJson.encodeToJsonElement(SyncVault.serializer(), bobsVault(rosterText = r))) })
            put("items", buildJsonArray {})
            put("invitations", buildJsonArray {
                add(buildJsonObject {
                    put("vault_id", inv.vaultId); put("role", inv.role); put("wrapped_key", inv.wrappedKey); put("meta", inv.meta)
                    put("invited_by", buildJsonObject {
                        put("id", alice.id); put("email", "alice@example.com"); put("name", "alice"); put("public_key", inv.invitedBy!!.publicKey)
                        put("signing_key", "sk"); put("identity_signature", "sig")
                    })
                    put("key_epoch", 0); put("share", inv.share!!); put("member_roster", r); put("member_roster_seq", 1)
                })
            })
        }
        val snap = SyncSnapshot.decode(answer.toString())!!
        val v = snap.vaults.single()
        assertEquals(r, v.memberRoster)
        assertEquals(1L, v.memberRosterSeq)
        assertTrue(v.share is JsonObject)
        val i = snap.invitations.single()
        assertEquals(0L, i.keyEpoch)
        assertEquals(r, i.memberRoster)
        assertEquals(inv.share, i.share)
        assertEquals("sk", i.invitedBy!!.signingKey)
        assertEquals(snap, SyncSnapshot.decode(snap.encode()))
    }

    @Test
    fun memoryIsPerAccountAndGoesWithTheAccount() {
        val st = Stored()
            .updatingSigning("https://a", "u1") { it.copy(rosters = mapOf("v" to "r")) }
            .updatingSigning("https://a", "u2") { it.copy(pinsSeq = 4) }
        assertEquals(mapOf("v" to "r"), st.signingMemory("https://a", "u1").rosters)
        assertEquals(4L, st.signingMemory("https://a", "u2").pinsSeq)
        assertTrue(st.signingMemory("https://b", "u1").isEmpty)
        assertFalse(st.withoutRecord("x").signingMemory("https://a", "u1").isEmpty)
        assertTrue(st.forgettingRoster("https://a", "u1").signingMemory("https://a", "u1").isEmpty)
        assertEquals(4L, st.forgettingRoster("https://a", "u1").signingMemory("https://a", "u2").pinsSeq)
        assertEquals(st, AppJson.decodeFromString(Stored.serializer(), AppJson.encodeToString(Stored.serializer(), st)))
    }

    @Test
    fun markVerifiedOnlyChangesThatPinOfThatIdentity() {
        val pins = io.passauth.core.pinSet(io.passauth.core.pinSet(null, alice.public, "alice@example.com", false, 1), carol.public, "carol@example.com", false, 1)
        val next = SignedSharing.markVerified(pins, alice.id, alice.hash)!!
        assertEquals(mapOf("alice@example.com" to true, "carol@example.com" to false), SignedSharing.people(next).associate { it.email to it.verified })
        assertEquals("match", io.passauth.core.pinCheck(next, alice.public, null))
        assertNull(SignedSharing.markVerified(pins, alice.id, carol.hash))
        assertNull(SignedSharing.markVerified(pins, "nobody", alice.hash))
        assertNull(SignedSharing.fingerprintOfHash("short"))
    }

    @Test
    fun theStatusNoticeKeyChangesWithNewWarnings() {
        val a = SharingStatus(enabled = true)
        val b = a.copy(refused = listOf(RefusedVault("v", "Team", SignedSharing.REFUSED)))
        val c = b.copy(changed = listOf(IdentityChange("u", "e", null, "F", "h", "{}", false, "e")))
        val d = c.copy(consent = listOf(ConsentVault("w", "Other", "read", false, null, false)))
        assertEquals(4, setOf(a.noticeKey, b.noticeKey, c.noticeKey, d.noticeKey).size)
        val review = MemberReview(vaultId, "Team", 1, true, emptyList(), emptyList(), "d")
        assertEquals(RotationReport.reviewText(listOf("Team")), RotationReport(0, reviews = listOf(review)).leftover)
    }

    // ------------------------------------------------- final re-review (Android + cross-client)

    /** The JSON object of [key] in the key pins (`left`, `epochs`). */
    private fun pinsPart(s: SharingSession, key: String, vault: String = vaultId): JsonObject? =
        (SignedSharing.obj(s.pins!!)?.get(key) as? JsonObject)?.get(vault) as? JsonObject

    /** H (TOCTOU): accepting a consent binds to the check shown; the server swapping the signer meanwhile is refused. */
    @Test
    fun acceptingAConsentBindsToTheCheckShown() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val rA = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(rA)
        s.beginChecks()
        val a = (check(s, bob, bobsVault(rosterText = rA)) as VaultCheck.Consent).vault
        assertEquals("alice@example.com", a.signer!!.email)
        // The server swaps in carol as signer (her own roster) while the sheet shows alice.
        val rB = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(rB)
        s.beginChecks()
        val b = (check(s, bob, bobsVault(rosterText = rB, by = carol)) as VaultCheck.Consent).vault
        assertEquals("carol@example.com", b.signer!!.email)
        assertTrue(a.token != b.token)
        try {
            s.acceptConsent(a)
            fail("accepted what the sheet no longer shows")
        } catch (e: UserException) {
            assertEquals(SignedSharing.CHANGED_JUST_NOW, e.message)
        }
        // Nothing pinned or remembered.
        assertTrue(SignedSharing.people(s.pins).isEmpty())
        assertNull(SignedSharing.epochOf(s.pins, vaultId))
        assertTrue(memory.m.rosters.isEmpty())
        // What is shown now can be accepted.
        s.acceptConsent(b)
        assertEquals(listOf(carol.id), SignedSharing.people(s.pins).map { it.userId })
    }

    /** H (TOCTOU): an invitation is accepted only as the last check showed it. */
    @Test
    fun acceptingAnInvitationBindsToTheCheckShown() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val rA = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(rA)
        val a = s.checkInvitation(invitation(rosterText = rA), opener, online = true) as InvitationTrust.Signed
        val rB = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(rB)
        val b = s.checkInvitation(invitation(rosterText = rB, by = carol), opener, online = true) as InvitationTrust.Signed
        try {
            s.prepareAccept(vaultId, a)
            fail("accepted what the sheet no longer shows")
        } catch (e: UserException) {
            assertEquals(SignedSharing.CHANGED_JUST_NOW, e.message)
        }
        assertTrue(SignedSharing.people(s.pins).isEmpty())
        assertTrue(memory.m.rosters.isEmpty())
        // The repository's check of the listed invitation against the sheet's.
        val shownA = Invitation(vaultId, "write", "Team", null, null, a)
        val nowB = shownA.copy(trust = b)
        assertFalse(Invitations.sameAsShown(nowB, shownA))
        assertFalse(Invitations.sameAsShown(null, shownA))
        assertTrue(Invitations.sameAsShown(shownA.copy(), shownA))
        s.prepareAccept(vaultId, b)
        assertEquals(listOf(carol.id), SignedSharing.people(s.pins).map { it.userId })
    }

    /** M: a signed invitation's headings name the checked signer; the server's invited_by only as "listed by your server as …". */
    @Test
    fun signedInvitationHeadingsNameTheCheckedSigner() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val t = s.checkInvitation(invitation(rosterText = r), opener, online = true) as InvitationTrust.Signed
        val inv = Invitation(vaultId, "write", "Team", InvitedBy("someone-else", "Boss@Corp.example", "The Boss"), 0, t)
        assertEquals("alice@example.com (listed by your server as boss@corp.example)", InvitationText.sharerName(inv))
        assertEquals("alice@example.com", InvitationText.sharerShort(inv))
        assertTrue(InvitationText.fromLine(inv) { "d" }.startsWith("From alice@example.com"))
        assertFalse(InvitationText.acceptSubtitle(inv).contains("The Boss"))
        // The same email listed: no note.
        assertEquals("alice@example.com", InvitationText.sharerName(inv.copy(invitedBy = InvitedBy(alice.id, "ALICE@example.com", "Alice"))))
    }

    /**
     * Grandfathering rule 1: a fresh phone (no earlier offline copy) grandfathers nothing, even when
     * this unlock made the identity; its unsigned shared vaults then wait for consent, accepted by the
     * key id shown (final review L: a genuine share is never stuck), and never declined.
     */
    @Test
    fun aFreshPhoneGrandfathersNothing() = runBlocking {
        val s = session(bob, earlier = emptySet())
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertEquals(1, api.identities.size)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertFalse(SignedSharing.needsGrandfathering(s.pins))
        assertTrue(SignedSharing.grandfathered(s.pins).isEmpty())
        s.beginChecks()
        val c = (check(s, bob, legacyVault()) as VaultCheck.Consent).vault
        assertTrue(c.unsignedAllowed && c.acceptable)
        assertFalse(c.declinable)
        assertEquals(key.keyId(vaultId), c.keyId)
        assertEquals(SigningMemory.MISSING_DEVICE, s.missingWhy())
        s.acceptConsent(c)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
        // Accepted: no longer waiting.
        assertTrue(memory.m.missing.orEmpty().isEmpty())
    }

    /** Grandfathering rule 2: a failed identity upload writes nothing; the next sync tries again. */
    @Test
    fun aFailedIdentityUploadGrandfathersNothingUntilItWorks() = runBlocking {
        val s = session(bob)
        api.putIdentityError = java.io.IOException("offline")
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertNull(s.fingerprint)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(SignedSharing.needsGrandfathering(s.pins))
        s.savePins()
        assertEquals(0, api.puts)
        // A server error (5xx): the same, and tried again.
        api.putIdentityError = ApiException(503, "unavailable", "unavailable")
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(SignedSharing.needsGrandfathering(s.pins))
        api.putIdentityError = null
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertNotNull(s.fingerprint)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
    }

    /** Lead B: an upload whose answer was lost counts as made here once the server lists that identity. */
    @Test
    fun aLostUploadAnswerStillCountsAsMadeHere() = runBlocking {
        val s = session(bob)
        api.loseIdentityAnswer = true
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertNull(s.fingerprint)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(SignedSharing.needsGrandfathering(s.pins))
        // The next sync lists the record that landed: opened, and made here.
        val landed = Json.parseToJsonElement(api.identities.single())
        s.refresh(user(bob, 0, landed), online = true)
        assertNotNull(s.fingerprint)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
        // On another phone (no memory of it) the same record is not made here: nothing grandfathered.
        val other = SharingSession(bob.account, FakeSharingApi(), Memory()).also { opened += it }
        other.refresh(user(bob, 0, landed), online = true)
        other.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue((check(other, bob, legacyVault()) as VaultCheck.Consent).vault.let { !it.acceptable || it.unsignedAllowed })
    }

    /** Lead B: `identity_exists` with someone else's record skips grandfathering at that sync. */
    @Test
    fun identityExistsSkipsGrandfatheringOnce() = runBlocking {
        api.putIdentityError = ApiException(409, "identity_exists", "exists")
        api.current = Json.parseToJsonElement(bob.record)
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertNotNull(s.fingerprint)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(SignedSharing.needsGrandfathering(s.pins))
        // The next sync: known, not made here → an empty list.
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertFalse(SignedSharing.needsGrandfathering(s.pins))
        assertTrue(check(s, bob, legacyVault()) is VaultCheck.Consent)
    }

    /** L: key pins that can't be fetched on a fresh phone are "offline", not "trust memory missing". */
    @Test
    fun keyPinsThatCantBeFetchedAreOffline() = runBlocking {
        api.getPinsError = java.io.IOException("offline")
        val s = session(bob)
        s.refresh(user(bob, 3), online = true)
        assertTrue(s.pinsUnreachable)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertFalse(s.memoryMissing)
        assertTrue(SignedSharing.needsGrandfathering(s.pins))
        assertEquals(VaultCheck.Refused(SignedSharing.UNCHECKED), check(s, bob, legacyVault()))
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        assertEquals(VaultCheck.Refused(SignedSharing.UNCHECKED), check(s, bob, bobsVault(rosterText = r)))
        s.savePins()
        assertEquals(0, api.puts)
        // Reachable again: normal.
        api.getPinsError = null
        api.pinsSeq = 0
        s.refresh(user(bob, 0), online = true)
        assertFalse(s.pinsUnreachable)
        assertTrue(check(s, bob, bobsVault(rosterText = r)) is VaultCheck.Consent)
    }

    /** Round 5 M2: a declined invitation's tombstone is at roster version 0, never the version the server's chain chose. */
    @Test
    fun aDeclinedInvitationIsTombstonedAtVersionZero() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r1 = roster(0, alice.row("owner"), bob.row("read"))
        val r2 = roster(0, alice.row("owner"), bob.row("write"), previous = r1)
        api.rosters[vaultId] = mutableListOf(r1, r2)
        val t = s.checkInvitation(invitation(rosterText = r2), opener, online = true) as InvitationTrust.Signed
        assertEquals(2L, t.rosterVersion)
        assertTrue(t.declinable)
        s.declineInvitation(vaultId, t, rows = emptySet())
        assertEquals(0L, SignedSharing.number(pinsPart(s, "left"), "roster_version"))
    }

    /** Round 5 M2: declining a consent row (a vault row of this sync) never tombstones it; the account only leaves it on the server. */
    @Test
    fun aDeclinedConsentRowIsNeverTombstoned() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r1 = roster(0, alice.row("owner"), bob.row("read"))
        val r2 = roster(0, alice.row("owner"), bob.row("write"), previous = r1)
        api.rosters[vaultId] = mutableListOf(r1, r2)
        s.beginChecks()
        val c = (check(s, bob, bobsVault(rosterText = r2)) as VaultCheck.Consent).vault
        assertTrue(c.declinable)
        s.declineConsent(c)
        assertNull(pinsPart(s, "left"))
    }

    /** L: pins are written before the server is told; a failed write leaves them as before. */
    @Test
    fun acceptingWritesThePinsFirstAndRollsBackOnFailure() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        s.savePins()
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        s.beginChecks()
        val c = (check(s, bob, bobsVault(rosterText = r)) as VaultCheck.Consent).vault
        val before = s.pins
        api.putPinsError = java.io.IOException("offline")
        try {
            s.acceptConsent(c)
            fail("accepted without saving the pins")
        } catch (e: UserException) {
            assertEquals(SignedSharing.PINS_NOT_SAVED, e.message)
        }
        assertEquals(before, s.pins)
        assertNull(SignedSharing.epochOf(s.pins, vaultId))
        assertTrue(memory.m.rosters.isEmpty())
        // Invitations the same.
        val t = s.checkInvitation(invitation(rosterText = r), opener, online = true) as InvitationTrust.Signed
        try {
            s.prepareAccept(vaultId, t)
            fail("accepted without saving the pins")
        } catch (e: UserException) {
            assertEquals(SignedSharing.PINS_NOT_SAVED, e.message)
        }
        assertEquals(before, s.pins)
        assertTrue(memory.m.rosters.isEmpty())
        // Reachable: saved first, then remembered.
        api.putPinsError = null
        val puts = api.puts
        s.acceptConsent(c)
        assertEquals(puts + 1, api.puts)
        assertNotNull(SignedSharing.epochOf(bob.account.openKeyPins(api.pins!!, api.pinsSeq.toULong()), vaultId))
        assertEquals(r, memory.m.rosters[vaultId])
    }

    /** L: every email shown is normalized like the key pins compare it. */
    @Test
    fun shownEmailsAreNormalized() {
        assertEquals("alice@example.com" to null, SignedSharing.emails("Alice@EXAMPLE.com", "ALICE@example.com"))
        assertEquals("alice@example.com" to "bob@example.com", SignedSharing.emails("alice@example.com", "Bob@Example.COM"))
        assertEquals("bob@example.com" to null, SignedSharing.emails(null, " Bob@Example.COM "))
    }

    /** L: an accepted shared vault a verified sync no longer lists gets a tombstone (the server can't bring the old copy back). */
    @Test
    fun anAcceptedVaultThatDisappearsIsTombstoned() = runBlocking {
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val v = bobsVault(rosterText = r)
        val s = accepted(v)
        // Offline, or not a shared vault of the copy before: nothing.
        s.tombstoneRemoved(emptySet(), setOf(vaultId), online = false)
        s.tombstoneRemoved(emptySet(), emptySet(), online = true)
        assertNull(pinsPart(s, "left"))
        // Still listed: nothing.
        s.tombstoneRemoved(setOf(vaultId), setOf(vaultId), online = true)
        assertNull(pinsPart(s, "left"))
        // Rule 3: one sync that omits it isn't enough (the server answers its members: still there) ...
        s.tombstoneRemoved(emptySet(), setOf(vaultId), online = true)
        assertNull(pinsPart(s, "left"))
        assertEquals(mapOf(vaultId to 1), memory.m.absent)
        // ... the second verified sync in a row that doesn't list it is.
        s.tombstoneRemoved(emptySet(), emptySet(), online = true)
        assertEquals(1L, SignedSharing.number(pinsPart(s, "left"), "roster_version"))
        assertTrue(memory.m.absent.isEmpty())
        assertEquals(VaultCheck.Refused(SignedSharing.refusedReason("left")), check(s, bob, v))
    }

    /** Info + L-F: "Trust the new key" of a second account with a known email needs the compared tick, and pins the email shown. */
    @Test
    fun trustingAnEmailConflictNeedsTheComparedTickAndPinsTheEmailShown() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        api.pins = bob.account.sealKeyPins(io.passauth.core.pinSet(null, alice.public, "alice@example.com", true, 1), 1u)
        api.pinsSeq = 1
        s.refresh(user(bob, 1), online = true)
        val r = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(r)
        check(s, bob, bobsVault(rosterText = r, by = carol, email = "Alice@Example.com"))
        val c = s.changed.single()
        assertTrue(c.conflict)
        assertEquals("alice@example.com", c.pinShown)
        try {
            s.trustNewKey(c, compared = false)
            fail("trusted without comparing")
        } catch (e: UserException) {
            assertEquals(SignedSharing.COMPARE_FIRST, e.message)
        }
        // The server lists another email meanwhile: not the change shown.
        assertFalse(s.trustNewKey(c.copy(pinEmail = "other@example.com"), compared = true))
        assertTrue(s.trustNewKey(c, compared = true))
        assertEquals("alice@example.com", SignedSharing.people(s.pins).first { it.userId == carol.id }.email)
    }

    /** L-F: after a first-time review, members are pinned with the emails the review showed, not a later members answer's. */
    @Test
    fun aReviewPinsTheEmailsItShowed() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        val shown = listOf(alice.row("owner"), bob.row("write"))
        val review = (s.planRotation(vaultId, "Team", null, shown, null) as RotationPlan.NeedsReview).review
        assertEquals(mapOf(bob.id to "bob@example.com"), review.emailsToPin())
        // The second members answer lists another email for bob (same id, identity and role: same digest).
        val later = listOf(alice.row("owner"), bob.row("write", email = "bob@evil.example"))
        val ready = s.planRotation(vaultId, "Team", null, later, ReviewApproval(review.digest, emptySet(), review.emailsToPin())) as RotationPlan.Ready
        assertEquals(listOf("bob@example.com"), ready.newPins.map { it.second })
    }

    /** Lead (iOS 2): while the trust memory is missing, consents can't be declined (a server could push the user out of real vaults). */
    @Test
    fun consentsCantBeDeclinedWhileTheTrustMemoryIsMissing() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(s.memoryMissing)
        s.beginChecks()
        val c = (check(s, bob, legacyVault()) as VaultCheck.Consent).vault
        try {
            s.declineConsent(c)
            fail("declined while the trust memory is missing")
        } catch (e: UserException) {
            assertEquals(SignedSharing.NO_DECLINE_NOW, e.message)
        }
        assertNull(pinsPart(s, "left"))
    }

    /** Extension L3: the record uploaded is kept for the copy, so an offline unlock opens it instead of pausing. */
    @Test
    fun theUploadedRecordOpensOffline() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        val rec = s.uploadedRecord!!
        // Offline later, the copy without it pauses; with it (as the repository stores it) it opens.
        val without = session(bob)
        without.refresh(user(bob, 0, JsonNull), online = false)
        assertTrue(without.paused)
        val with = session(bob)
        with.refresh(user(bob, 0, Json.parseToJsonElement(rec)), online = false)
        assertFalse(with.paused)
        assertEquals(s.fingerprint, with.fingerprint)
    }

    /** Memory that holds only lists of generated identity hashes is empty (the checks themselves are always on: `ServerSupport`). */
    @Test
    fun memoryWithOnlyGeneratedIdentitiesIsEmpty() {
        assertTrue(SigningMemory(generated = listOf("x")).isEmpty)
    }

    /** Info: memory is keyed by the normalized server address; memory kept under another spelling is read and moved. */
    @Test
    fun memoryKeysUseTheNormalizedServer() {
        val m = SigningMemory(pinsSeq = 4)
        val st = Stored().updatingSigning("https://Vault.Example.com/", "u1") { m }
        assertEquals(4L, st.signingMemory("https://vault.example.com", "u1").pinsSeq)
        assertEquals(4L, st.signingMemory("https://vault.example.com:443", "u1").pinsSeq)
        // Written by an earlier version under the raw spelling: still read, then moved on write.
        val legacy = Stored(signing = mapOf("https://Vault.Example.com|u1" to SigningMemory(pinsSeq = 2)))
        assertEquals(2L, legacy.signingMemory("https://Vault.Example.com", "u1").pinsSeq)
        val moved = legacy.updatingSigning("https://Vault.Example.com", "u1") { it.copy(pinsSeq = 3) }
        assertEquals(setOf("https://vault.example.com|u1"), moved.signing.keys)
    }


    // ------------------------------------------------- round 4 (core API + cross-client rules)

    private fun pinEmail(s: SharingSession, userId: String) = SignedSharing.text(SignedSharing.pinOf(s.pins, userId), "email")

    /** Round 4 I1: accepting uses `pins_accept`: the roster's version and hash are remembered with the key. */
    @Test
    fun acceptingRemembersTheRosterHashThroughPinsAccept() = runBlocking {
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val s = accepted(bobsVault(rosterText = r))
        val e = pinsPart(s, "epochs")!!
        assertEquals(io.passauth.core.rosterHash(r), SignedSharing.text(e, "roster_hash"))
        assertEquals(1L, SignedSharing.number(e, "roster_version_max"))
        // An invitation the same.
        val t = session(bob)
        t.refresh(user(bob, api.pinsSeq), online = true)
        memory.m = memory.m.copy(rosters = emptyMap())
        val v2 = "00000000-0000-4000-8000-0000000000f2"
        assertNull(SignedSharing.epochOf(t.pins, v2))
    }

    /** Round 4 (puppet chain): a chain re-signed from version 1 without the roster the account last trusted is refused (`chain_hashes`). */
    @Test
    fun aChainWithoutTheRosterTheAccountTrustedIsForked() = runBlocking {
        val r1 = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r1)
        val s = accepted(bobsVault(rosterText = r1))
        // This phone forgets the roster (a device with no memory of it); the key pins remember version 1 and its hash.
        memory.m = memory.m.copy(rosters = emptyMap())
        val p1 = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        val p2 = roster(0, carol.row("owner"), bob.row("read"), previous = p1, by = carol)
        api.rosters[vaultId] = mutableListOf(p1, p2)
        val forked = SignedSharing.refusedReason("roster_forked")
        assertEquals(VaultCheck.Refused(forked), check(s, bob, bobsVault(role = "read", rosterText = p2, by = carol)))
        assertEquals(InvitationTrust.Refused(forked), s.checkInvitation(invitation(role = "read", rosterText = p2, by = carol), opener, online = true))
        assertTrue(memory.m.rosters.isEmpty())
        // The real chain (r1, then a version 2 by alice) is taken.
        val r2 = roster(0, alice.row("owner"), bob.row("read"), previous = r1)
        api.rosters[vaultId] = mutableListOf(r1, r2)
        assertTrue(check(s, bob, bobsVault(role = "read", rosterText = r2)) is VaultCheck.Ok)
    }

    /** Round 4: an own vault served as shared with a new key (signed) is a consent that says so, naming the signer only as listed by the server. */
    @Test
    fun anOwnVaultWithANewSignedKeyIsAConsentThatSaysSo() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val own = SyncVault(vaultId, role = "owner", wrappedKey = key.wrapFor(bob.account, vaultId), keyKind = "account", keyEpoch = 0)
        assertEquals(VaultCheck.Ok(VaultTrust.Own), check(s, bob, own))
        val other = alice.account.newVaultKey(vaultId)
        try {
            val r = roster(1, alice.row("owner"), bob.row("write"), k = other.key)
            api.rosters[vaultId] = mutableListOf(r)
            s.beginChecks()
            val c = (check(s, bob, bobsVault(epoch = 1, rosterText = r, k = other.key)) as VaultCheck.Consent).vault
            assertTrue(c.own && c.replaced && c.acceptable)
            assertFalse(c.declinable)
            val text = SignedSharing.consentText(c)
            assertTrue(text, text.startsWith("Team was your own vault. Your server now says someone else gave you a new key for it."))
            assertTrue(text, text.contains("replaced and signed by someone listed by your server as alice@example.com for the first time"))
            try {
                s.declineConsent(c)
                fail("declined a replaced key")
            } catch (e: UserException) {
                assertEquals(SignedSharing.CANT_DECLINE, e.message)
            }
        } finally {
            other.destroy()
        }
        // Unsigned replaced key: its own wording and the key id shown.
        val unsigned = ConsentVault(vaultId, "Team", "write", false, null, false, replaced = true, keyId = "k")
        assertTrue(SignedSharing.consentText(unsigned).startsWith("The key of Team was replaced by an app that doesn't sign yet."))
        assertTrue(unsigned.acceptable && !unsigned.declinable)
    }

    /** Rule 1: an unsigned vault held for consent never offers Decline; one that can't be accepted asks for the owner's signature. */
    @Test
    fun unsignedConsentsAreNeverDeclined() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(emptyList(), online = true)
        s.beginChecks()
        val c = (check(s, bob, legacyVault()) as VaultCheck.Consent).vault
        assertFalse(c.declinable || c.acceptable)
        assertEquals("It isn't signed, so PassAuth keeps it locked. Ask the vault's owner to sign this vault.", SignedSharing.unsignedConsentNote(c, null))
        try {
            s.declineConsent(c)
            fail("declined an unsigned vault")
        } catch (e: UserException) {
            assertEquals(SignedSharing.CANT_DECLINE, e.message)
        }
        assertNull(pinsPart(s, "left"))
    }

    /** Rule 3: the server saying the vault is gone (404 for its members) confirms a removal at once; a made-up invitation carrying a vault in use doesn't tombstone it. */
    @Test
    fun removalsAreConfirmedAndFakeInvitationsDontTombstone() = runBlocking {
        // Only a 404 confirms; a 403 (policy, two-step, reauth) never does.
        assertTrue(SignedSharing.removalConfirmed(ApiException(404, "not_found", "gone")))
        assertFalse(SignedSharing.removalConfirmed(ApiException(403, "two_step_required", "two-step")))
        assertFalse(SignedSharing.removalConfirmed(ApiException(403, "reauth_required", "reauth")))
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val s = accepted(bobsVault(rosterText = r))
        // Declining an invitation for the vault in use: no tombstone (usable, or accepted and still listed).
        s.declineInvitation(vaultId, InvitationTrust.Unsigned, rows = setOf(vaultId))
        s.declineInvitation(vaultId, InvitationTrust.Unsigned, rows = emptySet())
        assertNull(pinsPart(s, "left"))
        // A 403 for its members (can't be told: null) after one sync that omitted it: no tombstone yet.
        api.member = null
        s.tombstoneRemoved(emptySet(), setOf(vaultId), online = true)
        assertNull(pinsPart(s, "left"))
        // Listed again (the absence starts over), then gone on the server (404): tombstoned after one sync.
        s.tombstoneRemoved(setOf(vaultId), setOf(vaultId), online = true)
        api.member = false
        s.tombstoneRemoved(emptySet(), setOf(vaultId), online = true)
        assertEquals(1L, SignedSharing.number(pinsPart(s, "left"), "roster_version"))
        // A declined invitation of a vault not in use and not a row: tombstoned at version 0 (round 5 M2).
        val t = SharingSession(alice.account, FakeSharingApi(), Memory()).also { opened += it }
        t.refresh(user(alice, 0), online = true)
        t.declineInvitation(vaultId, InvitationTrust.Unsigned, rows = setOf(vaultId))
        assertNull(pinsPart(t, "left"))
        t.declineInvitation(vaultId, InvitationTrust.Unsigned, rows = emptySet())
        assertEquals(0L, SignedSharing.number(pinsPart(t, "left"), "roster_version"))
    }

    /** Rule 4 + one email form: accepting binds the email shown, and pins exactly that, normalized. */
    @Test
    fun acceptingBindsAndPinsTheEmailShown() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        s.beginChecks()
        val a = (check(s, bob, bobsVault(rosterText = r, email = " Alice@EXAMPLE.com. ")) as VaultCheck.Consent).vault
        assertEquals("alice@example.com", a.signer!!.email)
        // The server lists another email for the same signer while the sheet shows the first.
        s.beginChecks()
        val b = (check(s, bob, bobsVault(rosterText = r, email = "mallory@example.com")) as VaultCheck.Consent).vault
        assertTrue(a.token != b.token)
        try {
            s.acceptConsent(a)
            fail("accepted under an email no longer shown")
        } catch (e: UserException) {
            assertEquals(SignedSharing.CHANGED_JUST_NOW, e.message)
        }
        assertNull(SignedSharing.pinOf(s.pins, alice.id))
        s.beginChecks()
        val c = (check(s, bob, bobsVault(rosterText = r, email = " Alice@EXAMPLE.com. ")) as VaultCheck.Consent).vault
        s.acceptConsent(c)
        assertEquals("alice@example.com", pinEmail(s, alice.id))
    }

    /** Rule 4: an upgraded pin (legacy → signing identity, same X25519 key) keeps the pinned email and its verified mark. */
    @Test
    fun anUpgradedPinKeepsItsEmailAndVerifiedMark() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        api.pins = bob.account.sealKeyPins(io.passauth.core.pinSet(null, carol.account.legacyIdentityJson(), "carol@example.com", true, 1), 1u)
        api.pinsSeq = 1
        s.refresh(user(bob, 1), online = true)
        val r = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(r)
        s.beginChecks()
        val c = (check(s, bob, bobsVault(rosterText = r, by = carol, email = "carol@new.example")) as VaultCheck.Consent).vault
        assertEquals(PinState.Upgraded, c.signer!!.pin)
        assertEquals("carol@example.com", c.signer!!.email)
        assertEquals("carol@new.example", c.signer!!.listedEmail)
        s.acceptConsent(c)
        val pin = SignedSharing.pinOf(s.pins, carol.id)!!
        assertEquals("carol@example.com", SignedSharing.text(pin, "email"))
        assertTrue(SignedSharing.flag(pin, "verified"))
        assertEquals(carol.hash, SignedSharing.text(pin, "identity"))
        // A key replacement's review the same.
        val api2 = FakeSharingApi()
        val a = SharingSession(alice.account, api2, Memory()).also { opened += it }
        a.refresh(user(alice, 0), online = true)
        api2.pins = alice.account.sealKeyPins(io.passauth.core.pinSet(null, carol.account.legacyIdentityJson(), "carol@example.com", true, 1), 1u)
        api2.pinsSeq = 1
        a.refresh(user(alice, 1), online = true)
        val rows = listOf(alice.row("owner"), carol.row("write", email = "carol@new.example"))
        val review = (a.planRotation(vaultId, "Team", null, rows, null) as RotationPlan.NeedsReview).review
        assertEquals(PinState.Upgraded, review.members.first { it.userId == carol.id }.pin)
        val ready = a.planRotation(vaultId, "Team", null, rows, ReviewApproval(review.digest, emptySet(), review.emailsToPin())) as RotationPlan.Ready
        assertEquals(Triple(rows[1].toString(), "carol@example.com", true), ready.newPins.single())
    }

    /** Rule 5: this phone's last-known pins are merged into a newer server copy (another device wrote it without them) and written back. */
    @Test
    fun aNewerServerCopyGetsThisPhonesPinsMergedIn() = runBlocking {
        val first = session(bob)
        first.refresh(user(bob, 0), online = true)
        first.leave(vaultId)
        first.savePins()
        assertEquals(1L, api.pinsSeq)
        // Another device wrote version 2 without the tombstone.
        val theirs = io.passauth.core.pinsSetOwnIdentity(io.passauth.core.pinSet(null, carol.public, "carol@example.com", false, 5), bob.hash)
        api.pins = bob.account.sealKeyPins(theirs, 2u)
        api.pinsSeq = 2
        val s = session(bob)
        s.refresh(user(bob, 2), online = true)
        assertEquals(0L, SignedSharing.number(pinsPart(s, "left"), "roster_version"))
        assertEquals(listOf(carol.id), SignedSharing.people(s.pins).map { it.userId })
        s.savePins()
        assertEquals(3L, api.pinsSeq)
        val stored = bob.account.openKeyPins(api.pins!!, 3u)
        assertNotNull(SignedSharing.obj(stored)!!["left"]!!.jsonObject[vaultId])
        // Nothing new to add: nothing written.
        val again = session(bob)
        again.refresh(user(bob, 3), online = true)
        again.savePins()
        assertEquals(3L, api.pinsSeq)
    }

    /** Round 4: a key replacement the server refuses for its hourly limit (429) says so plainly. */
    @Test
    fun aRateLimitedKeyReplacementSaysSo() {
        assertEquals(
            "This vault's key was replaced too often in the last hour. Try again later. (Too many attempts. Try again in 2 minutes.)",
            SignedSharing.keyReplacementLimited(ApiException(429, "rate_limited", "Too many requests", retryAfter = 120)),
        )
        assertEquals(SignedSharing.TOO_MANY_KEY_REPLACEMENTS, SignedSharing.keyReplacementLimited(ApiException(429, "rate_limited", "Too many requests")))
        assertNull(SignedSharing.keyReplacementLimited(ApiException(409, "vault_key_changed", "changed")))
    }

    /** Rule 6: a generated identity hash counts as made here only if no own identity was known when the unlock began. */
    @Test
    fun aGeneratedHashDoesntMakeEveryLaterUnlockTheCreator() = runBlocking {
        memory.m = SigningMemory(ownIdentity = bob.hash, generated = listOf(bob.hash))
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertFalse(SignedSharing.needsGrandfathering(s.pins))
        assertTrue(SignedSharing.grandfathered(s.pins).isEmpty())
    }

    /** Rule 6: the grandfathering candidates are recorded once, when the identity is first made; cleared once the pins hold the identity and the list. */
    @Test
    fun grandfatheringCandidatesAreRecordedOnce() = runBlocking {
        api.loseIdentityAnswer = true
        val a = session(bob, earlier = setOf(vaultId))
        a.refresh(user(bob, 0, JsonNull), online = true)
        assertEquals(setOf(vaultId), memory.m.candidates)
        val landed = Json.parseToJsonElement(api.identities.single())
        api.loseIdentityAnswer = false
        // The next unlock: the vault was held meanwhile, so it isn't among its usable ones; the candidates still count.
        val b = session(bob, earlier = emptySet())
        b.refresh(user(bob, 0, landed), online = true)
        b.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertEquals(setOf(vaultId), SignedSharing.grandfathered(b.pins))
        b.savePins()
        assertTrue(memory.m.generated.isEmpty())
        assertNull(memory.m.candidates)
    }

    /** Rule 7: unreadable trust memory never runs with no pins: shared vaults refused, own vaults checked against the server's pins, nothing replaced. */
    @Test
    fun unreadableTrustMemoryRefusesSharedVaultsAndKeepsOwnChecks() = runBlocking {
        memory.m = SigningMemory(pinsSeq = 3, pinsSealed = alice.account.sealKeyPins(io.passauth.core.pinSet(null, carol.public, "carol@example.com", false, 5), 3u))
        api.pins = bob.account.sealKeyPins(io.passauth.core.pinsRecordRotation(null, vaultId, "account", key.epochPinJson(vaultId, 1u), null, null), 2u)
        api.pinsSeq = 2
        val s = session(bob)
        s.refresh(user(bob, 2), online = true)
        assertTrue(s.memoryUnreadable)
        assertEquals(SignedSharing.PINS_ROLLED_BACK, s.pinsProblem)
        assertEquals(VaultCheck.Refused(SignedSharing.MEMORY_UNREADABLE), check(s, bob, legacyVault()))
        val own = SyncVault(vaultId, role = "owner", wrappedKey = key.wrapFor(bob.account, vaultId), keyKind = "account", keyEpoch = 0)
        assertEquals(VaultCheck.Refused(SignedSharing.refusedReason("older")), check(s, bob, own))
        assertTrue(check(s, bob, own.copy(keyEpoch = 1)) is VaultCheck.Ok)
        try {
            s.planRotation(vaultId, "Team", null, listOf(bob.row("owner")), null)
            fail("replaced a key without trust memory")
        } catch (e: UserException) {
            assertEquals(SignedSharing.MEMORY_UNREADABLE, e.message)
        }
        try {
            s.savePins()
            fail("wrote pins without trust memory")
        } catch (e: UserException) {
            assertEquals(SignedSharing.MEMORY_UNREADABLE, e.message)
        }
        // Offline the same: shared vaults refused.
        val off = session(bob)
        off.refresh(user(bob, 2), online = false)
        assertTrue(off.memoryUnreadable)
        assertEquals(VaultCheck.Refused(SignedSharing.MEMORY_UNREADABLE), check(off, bob, legacyVault(), online = false))
    }

    /** Final review M: a cache-first unlock (offline first) doesn't make the trust memory "missing" once the server has the pins. */
    @Test
    fun aCacheFirstUnlockIsntTrustMemoryMissing() = runBlocking {
        val theirs = io.passauth.core.pinsGrandfather(io.passauth.core.pinsSetOwnIdentity(null, bob.hash), "[]", false)
        api.pins = bob.account.sealKeyPins(theirs, 1u)
        api.pinsSeq = 1
        val s = session(bob, earlier = emptySet())
        s.refresh(user(bob, 1), online = false)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = false)
        s.refresh(user(bob, 1), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertFalse(s.memoryMissing)
        s.beginChecks()
        assertFalse((check(s, bob, legacyVault()) as VaultCheck.Consent).vault.unsignedAllowed)
        // The server really has none: missing, also after an offline start.
        val other = SharingSession(bob.account, FakeSharingApi(), Memory()).also { opened += it }
        other.refresh(user(bob, 0), online = false)
        other.refresh(user(bob, 0), online = true)
        other.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(other.memoryMissing)
    }

    /** Rule 2 (iOS M1): before this phone finished the account's first signed sync an unsigned vault is held neutrally; the identity upload is retried every sync. */
    @Test
    fun unsignedVaultsAreHeldUntilTheFirstSignedSyncAndTheUploadIsRetried() = runBlocking {
        val s = session(bob)
        api.putIdentityError = ApiException(429, "rate_limited", "Too many requests")
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        s.beginChecks()
        assertEquals(VaultCheck.Held(SignedSharing.STILL_CHECKING), check(s, bob, legacyVault()))
        assertFalse(s.firstSignedSyncDone)
        // The next sync (same unlock) tries the upload again.
        api.putIdentityError = null
        s.refresh(user(bob, 0, JsonNull), online = true)
        assertEquals(1, api.identities.size)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertTrue(s.firstSignedSyncDone)
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
        // 404 (the server doesn't sign): not retried.
        val c = SharingSession(carol.account, api, Memory()).also { opened += it }
        val carolUser = buildJsonObject { put("id", carol.id); put("identity", JsonNull); put("key_pins_seq", 0) }
        api.putIdentityError = ApiException(404, "not_found", "Not found")
        c.refresh(carolUser, online = true)
        api.putIdentityError = null
        c.refresh(carolUser, online = true)
        assertEquals(1, api.identities.size)
    }

    /** Final review Info: a changed identity no row of a later sync shows any more is dropped. */
    @Test
    fun staleIdentityChangesAreDropped() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        api.pins = bob.account.sealKeyPins(io.passauth.core.pinSet(null, alice.public, "alice@example.com", true, 1), 1u)
        api.pinsSeq = 1
        s.refresh(user(bob, 1), online = true)
        val r = roster(0, carol.row("owner"), bob.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(r)
        repeat(2) {
            s.beginChecks()
            check(s, bob, bobsVault(rosterText = r, by = carol, email = "alice@example.com"))
            s.endChecks()
            assertEquals(1, s.changed.size)
        }
        s.beginChecks()
        s.endChecks()
        assertTrue(s.changed.isEmpty())
    }

    // ------------------------------------------------------------- round 5

    /** The account's own vault row at [epoch] with [k] (an `account` wrap). */
    private fun ownVault(f: Fixture, k: VaultKey = key, epoch: Long = 0) =
        SyncVault(vaultId, role = "owner", wrappedKey = k.wrapFor(f.account, vaultId), keyKind = "account", keyEpoch = epoch)

    /**
     * Round 5 Android H: a key replacement's pins whose write failed are kept on this phone as unsent,
     * survive a lock, are merged on top of the server's older copy (the old key stays refused) and are
     * cleared only after a write succeeded.
     */
    @Test
    fun unsentPinsSurviveAFailedWriteAndALock() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        s.beginChecks()
        assertTrue(check(s, alice, ownVault(alice)) is VaultCheck.Ok)
        s.savePins()
        assertEquals(1L, api.pinsSeq)
        assertNull(memory.m.unsentSealed)
        val made = alice.account.newVaultKey(vaultId)
        try {
            api.putPinsError = ApiException(500, "server_error", "down")
            s.rememberRotation(vaultId, null, made.key.epochPinJson(vaultId, 1u), emptyList())
            // Kept on this phone at once, before any write.
            assertNotNull(memory.m.unsentSealed)
            try {
                s.savePins()
                fail("the write didn't fail")
            } catch (_: ApiException) {
            }
            assertEquals(1L, api.pinsSeq)
            assertNotNull(memory.m.unsentSealed)
            // Locked and unlocked: the server still serves the old pins, and the old key (v1 wrap) again.
            val t = session(alice)
            t.refresh(user(alice, 1), online = true)
            t.beginChecks()
            assertEquals(VaultCheck.Refused(SignedSharing.refusedReason("older")), check(t, alice, ownVault(alice)))
            assertTrue(check(t, alice, ownVault(alice, made.key, 1)) is VaultCheck.Ok)
            // The server's copy never replaced the unsent one.
            assertNotNull(memory.m.unsentSealed)
            api.putPinsError = null
            t.savePins()
            assertEquals(2L, api.pinsSeq)
            assertNull(memory.m.unsentSealed)
            val stored = alice.account.openKeyPins(api.pins!!, 2u)
            assertEquals(1L, SignedSharing.number(SignedSharing.epochOf(stored, vaultId), "key_epoch"))
        } finally {
            made.destroy()
        }
    }

    /** Round 5 Android H: an accept whose pins can't be written leaves nothing unsent (nothing was accepted). */
    @Test
    fun aFailedAcceptLeavesNothingUnsent() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0), online = true)
        s.savePins()
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        s.beginChecks()
        val c = (check(s, bob, bobsVault(rosterText = r)) as VaultCheck.Consent).vault
        api.putPinsError = ApiException(500, "server_error", "down")
        try {
            s.acceptConsent(c)
            fail("accepted without saving the pins")
        } catch (_: ApiException) {
        }
        assertNull(memory.m.unsentSealed)
        assertNull(SignedSharing.epochOf(s.pins, vaultId))
    }

    /** Round 5 L: a sync without `user.key_pins_seq` still fetches the key pins (and is offline when they can't be). */
    @Test
    fun aSyncWithoutKeyPinsSeqStillFetchesThePins() = runBlocking {
        val withLeft = io.passauth.core.pinsSetOwnIdentity(io.passauth.core.pinsLeave(null, vaultId, 0u, 5), bob.hash)
        api.pins = bob.account.sealKeyPins(withLeft, 2u)
        api.pinsSeq = 2
        val noSeq = buildJsonObject {
            put("id", bob.id)
            put("identity", Json.parseToJsonElement(bob.record))
        }
        val s = session(bob)
        s.refresh(noSeq, online = true)
        assertNotNull(pinsPart(s, "left"))
        assertFalse(s.pinsUnreachable)
        // Unreachable with no version named: offline (nothing written, unadmitted shared vaults unchecked).
        val api2 = FakeSharingApi().apply { getPinsError = java.io.IOException("down") }
        val t = SharingSession(bob.account, api2, Memory()).also { opened += it }
        t.refresh(noSeq, online = true)
        assertTrue(t.pinsUnreachable)
    }

    /** Round 5 M (Android): an invitation for a vault the account has is held; a signed newer key there needs consent and can't be declined. */
    @Test
    fun invitationsForAVaultTheAccountHasAreHeld() = runBlocking {
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val s = accepted(bobsVault(rosterText = r))
        // The same key again, as an invitation: held (refused), and declining it never tombstones the vault.
        assertEquals(InvitationTrust.Refused(SignedSharing.refusedReason("held")), s.checkInvitation(invitation(rosterText = r), opener, online = true))
        s.declineInvitation(vaultId, InvitationTrust.Unsigned, rows = emptySet())
        assertNull(pinsPart(s, "left"))
        assertNotNull(SignedSharing.epochOf(s.pins, vaultId))
        // A signed newer key on a vault with signed history: consent `held`, no Decline.
        val made = alice.account.newVaultKey(vaultId)
        try {
            val r2 = roster(1, alice.row("owner"), bob.row("write"), previous = r, k = made.key)
            api.rosters[vaultId]!! += r2
            val share = alice.identity.sealAndSignShare(made.key, vaultId, bob.public, "write", 1u)
            val inv = SyncInvitation(
                vaultId, "write", share.sealedKey, made.key.encryptMeta(vaultId, """{"name":"Team"}"""),
                InvitedBy(alice.id, "alice@example.com", "alice", Json.parseToJsonElement(alice.public).jsonObject["public_key"]!!.jsonPrimitive.content),
                keyEpoch = 1, share = shareOf(share.signature, alice), memberRoster = r2,
            )
            val t = s.checkInvitation(inv, opener, online = true) as InvitationTrust.Signed
            assertTrue(t.held)
            assertFalse(t.declinable)
            assertFalse(Invitation(vaultId, "write", "Team", null, null, t).declinable)
            assertTrue(SignedSharing.invitationNote(t, "Team")!!.contains("which you already have"))
            try {
                s.declineInvitation(vaultId, t, rows = emptySet())
                fail("a held invitation was declined")
            } catch (e: UserException) {
                assertEquals(SignedSharing.NOT_DECLINABLE, e.message)
            }
            assertNull(pinsPart(s, "left"))
            // Accepting it passes the same observation (`invitation: true`) to `pins_accept`.
            s.prepareAccept(vaultId, t)
            assertEquals(1L, SignedSharing.number(SignedSharing.epochOf(s.pins, vaultId), "key_epoch"))
        } finally {
            made.destroy()
        }
    }

    /** Round 5 M (Android): an invitation naming the account's own vault is refused outright. */
    @Test
    fun anInvitationForTheAccountsOwnVaultIsRefused() = runBlocking {
        val s = session(alice)
        s.refresh(user(alice, 0), online = true)
        s.beginChecks()
        assertTrue(check(s, alice, ownVault(alice)) is VaultCheck.Ok)
        val r = roster(0, carol.row("owner"), alice.row("write"), by = carol)
        api.rosters[vaultId] = mutableListOf(r)
        val share = carol.identity.sealAndSignShare(key, vaultId, alice.public, "write", 0u)
        val inv = SyncInvitation(
            vaultId, "write", share.sealedKey, key.encryptMeta(vaultId, """{"name":"Mine"}"""),
            InvitedBy(carol.id, "carol@example.com", "carol", Json.parseToJsonElement(carol.public).jsonObject["public_key"]!!.jsonPrimitive.content),
            keyEpoch = 0, share = shareOf(share.signature, carol), memberRoster = r,
        )
        val aliceOpener: (SyncInvitation) -> VaultKey? = { i -> runCatching { alice.account.openVaultKey(i.vaultId, i.wrappedKey, "sealed", 0u, false) }.getOrNull() }
        assertEquals(InvitationTrust.Refused(SignedSharing.refusedReason("own_vault")), s.checkInvitation(inv, aliceOpener, online = true))
    }

    /** Round 5 M/M2: a vault from before signed for the first time at the same key needs consent, names its signer and can't be declined. */
    @Test
    fun aFirstSignatureNeedsConsentWithoutDecline() = runBlocking {
        val unsigned = io.passauth.core.pinsSetOwnIdentity(io.passauth.core.pinsRecordRotation(null, vaultId, "sealed", key.epochPinJson(vaultId, 0u), null, null), bob.hash)
        api.pins = bob.account.sealKeyPins(unsigned, 1u)
        api.pinsSeq = 1
        val r = roster(0, alice.row("owner"), bob.row("write"))
        api.rosters[vaultId] = mutableListOf(r)
        val s = session(bob)
        s.refresh(user(bob, 1), online = true)
        s.beginChecks()
        val c = (check(s, bob, bobsVault(rosterText = r)) as VaultCheck.Consent).vault
        assertTrue(c.firstSigned)
        assertFalse(c.declinable)
        assertTrue(SignedSharing.consentText(c).contains("is signed for the first time, by"))
        try {
            s.declineConsent(c)
            fail("a first signature was declined")
        } catch (e: UserException) {
            assertEquals(SignedSharing.CANT_DECLINE, e.message)
        }
        s.acceptConsent(c)
        assertEquals(1L, SignedSharing.number(SignedSharing.epochOf(s.pins, vaultId), "signed_since"))
    }

    /** Round 5 M1: a newer server copy that differs from this phone's last-known pins only in a person pin is used as it is (no write, no loop). */
    @Test
    fun aNewerServerCopyWinsForAPersonPinnedAgain() = runBlocking {
        val lastKnown = io.passauth.core.pinsSetOwnIdentity(io.passauth.core.pinSet(null, carol.account.legacyIdentityJson(), "carol@example.com", true, 5), bob.hash)
        val newer = io.passauth.core.pinsSetOwnIdentity(io.passauth.core.pinSet(null, carol.public, "carol@example.com", false, 9), bob.hash)
        memory.m = SigningMemory(pinsSeq = 1, pinsSealed = bob.account.sealKeyPins(lastKnown, 1u), ownIdentity = bob.hash)
        api.pins = bob.account.sealKeyPins(newer, 2u)
        api.pinsSeq = 2
        val s = session(bob)
        s.refresh(user(bob, 2), online = true)
        assertEquals(carol.hash, SignedSharing.text(SignedSharing.pinOf(s.pins, carol.id), "identity"))
        s.savePins()
        assertEquals(0, api.puts)
        assertNull(memory.m.unsentSealed)
    }

    /** Round 5: unsent pins remembering another own identity than the server's: nothing merged or written, sharing paused. */
    @Test
    fun anotherOwnIdentityInUnsentPinsPausesSharing() = runBlocking {
        val elsewhere = io.passauth.core.pinsSetOwnIdentity(null, carol.hash)
        val server = io.passauth.core.pinsSetOwnIdentity(null, bob.hash)
        api.pins = bob.account.sealKeyPins(server, 1u)
        api.pinsSeq = 1
        memory.m = SigningMemory(pinsSeq = 1, pinsSealed = bob.account.sealKeyPins(server, 1u), unsentSealed = bob.account.sealKeyPins(elsewhere, 1u), unsentSeq = 1)
        val s = session(bob)
        s.refresh(user(bob, 1), online = true)
        assertTrue(s.paused)
        assertEquals(SignedSharing.PAUSED, s.pinsProblem)
        s.savePins()
        assertEquals(0, api.puts)
        assertEquals(bob.hash, SignedSharing.ownIdentityOf(s.pins))
    }

    /** Round 5 Info: before the key pins are loaded no shared vault is used and nothing is written. */
    @Test
    fun withoutLoadedPinsSharedVaultsWaitAndNothingIsWritten() = runBlocking {
        val s = session(bob)
        s.beginChecks()
        assertEquals(VaultCheck.Refused(SignedSharing.UNCHECKED), check(s, bob, legacyVault()))
        assertTrue(check(s, bob, ownVault(bob)) is VaultCheck.Ok)
        s.savePins()
        assertEquals(0, api.puts)
        assertNull(memory.m.unsentSealed)
        try {
            s.requireReadyToReplace()
            fail("a key replacement was allowed without pins")
        } catch (e: UserException) {
            assertEquals(SignedSharing.PINS_UNSENT, e.message)
        }
    }

    /** Round 5: grandfathering binds each vault to the key it has now; a planted key under that id needs consent. */
    @Test
    fun grandfatheringBindsTheKey() = runBlocking {
        val s = session(bob)
        s.refresh(user(bob, 0, JsonNull), online = true)
        s.grandfather(listOf(vaultId to key.keyId(vaultId)), online = true)
        assertEquals(key.keyId(vaultId), (SignedSharing.obj(s.pins!!)!!["grandfathered"] as JsonObject)[vaultId]!!.jsonPrimitive.content)
        val planted = alice.account.newVaultKey(vaultId)
        try {
            val v = SyncVault(vaultId, role = "write", wrappedKey = planted.key.shareTo(vaultId, bob.account.publicKey()), keyKind = "sealed", keyEpoch = 0)
            assertTrue(check(s, bob, v) is VaultCheck.Consent)
        } finally {
            planted.destroy()
        }
        assertEquals(VaultCheck.Ok(VaultTrust.NotYetSigned), check(s, bob, legacyVault()))
    }

    /** Round 5 (iOS H, every client): a session is restored only under its own bundle, and only the account's own bundle is stored. */
    @Test
    fun sessionsRestoreOnlyUnderTheirOwnBundle() {
        val a = io.passauth.core.createAccount(newId(), "correct horse battery", false)
        val b = io.passauth.core.createAccount(newId(), "correct horse battery", false)
        try {
            val bytes = a.account.toSessionBytes()
            val restored = AccountBundles.restore(a.bundleJson, bytes)
            assertNotNull(restored)
            restored!!.destroy()
            // The server swapped in another account's bundle (another id): refused, the master password is asked.
            assertNull(AccountBundles.restore(b.bundleJson, bytes))
            // The same id, another account's keys: refused too.
            val forged = JsonObject(Json.parseToJsonElement(b.bundleJson).jsonObject + ("account_id" to JsonPrimitive(Stored.bundleUserId(a.bundleJson)!!))).toString()
            assertNull(AccountBundles.restore(forged, bytes))
            // Stored: unlocked, only its own; locked, only the same account id.
            assertEquals(a.bundleJson, AccountBundles.toStore(a.account, null, a.bundleJson))
            assertEquals(a.bundleJson, AccountBundles.toStore(a.account, a.bundleJson, b.bundleJson))
            assertEquals(a.bundleJson, AccountBundles.toStore(a.account, a.bundleJson, forged))
            assertEquals(a.bundleJson, AccountBundles.toStore(null, a.bundleJson, b.bundleJson))
            assertEquals(forged, AccountBundles.toStore(null, a.bundleJson, forged))
            assertNull(AccountBundles.toStore(null, null, b.bundleJson))
        } finally {
            for (n in listOf(a, b)) {
                n.account.destroy()
                n.master.destroy()
            }
        }
    }
}
