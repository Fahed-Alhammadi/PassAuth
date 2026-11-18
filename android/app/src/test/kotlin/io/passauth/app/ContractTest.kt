package io.passauth.app

import io.passauth.app.data.ApiException
import io.passauth.app.data.CLIENT_HEADER
import io.passauth.app.data.CLIENT_ID
import io.passauth.app.data.ConflictException
import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.ItemWrites
import io.passauth.app.data.Login
import io.passauth.app.data.failedResponse
import io.passauth.app.data.retryAfterSeconds
import io.passauth.app.data.securityErrorMessage
import io.passauth.app.data.serverRequest
import io.passauth.app.data.tooManyAttemptsMessage
import io.passauth.app.data.waitText
import io.passauth.app.ui.errorMessage
import io.passauth.core.EncryptedItem
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The client side of API contract v2 (2026-11-15): `X-PassAuth-Client` on every request to the
 * server, error codes before message texts, and item writes ([ItemWrites]): the vault key epoch,
 * one re-encrypted retry after `vault_key_changed`, and a create keeping its item id.
 */
class ContractTest {
    private val keyChanged = ApiException(409, "vault_key_changed", "the vault's key was replaced; sync and try again")
    private val revisionConflict = ApiException(409, "revision_conflict", "item changed on another device; sync and retry")

    private fun entry(id: String = "i1", password: String = "pw-1", revision: Long = 3, vault: String = "v1") = Entry(
        id = id,
        item = Item(name = "Shop", login = Login(username = "alice", password = password)),
        vaultId = vault,
        revision = revision,
        enc = EncryptedItem(id = id, vaultId = vault, key = "k$revision", data = "d$revision"),
    )

    @Test
    fun clientHeaderOnServerRequests() {
        assertTrue(CLIENT_ID, Regex("android/\\d+\\.\\d+\\.\\d+").matches(CLIENT_ID))
        assertEquals("X-PassAuth-Client", CLIENT_HEADER)
        assertEquals(CLIENT_ID, serverRequest("https://pass.example.com/api/config").build().header(CLIENT_HEADER))
    }

    @Test
    fun errorCodesBeforeMessages() {
        // API v2 code, and the message text older servers put the reason in.
        assertTrue(ApiException(403, "reauth_required", "anything").hasCode("reauth_required"))
        assertTrue(ApiException(403, "forbidden", "reauth_required").hasCode("reauth_required"))
        assertFalse(ApiException(403, "forbidden", "nope").hasCode("reauth_required"))
        assertTrue(ApiException(400, "bad_request", "Invalid code").hasCode("invalid_code", "invalid code"))
        val expired = "Your confirmation expired. Enter your master password again."
        assertEquals(expired, securityErrorMessage(ApiException(403, "reauth_required", "reauth_required")))
        assertEquals(expired, securityErrorMessage(ApiException(403, "forbidden", "reauth_required")))
        val wrong = "That code didn't work. Enter the code that's showing now and try again."
        assertEquals(wrong, securityErrorMessage(ApiException(400, "invalid_code", "the code is wrong")))
        assertEquals(wrong, securityErrorMessage(ApiException(400, "bad_request", "invalid code")))
        assertEquals("The setup expired. Cancel and start setup again.", securityErrorMessage(ApiException(400, "expired", "start setup first")))
        assertEquals(
            "The authenticator app is already on. Turn it off first to set it up again.",
            securityErrorMessage(ApiException(409, "already_enabled", "authenticator app already enabled")),
        )
        assertNull(securityErrorMessage(ApiException(400, "bad_request", "something else")))
    }

    /** A 429 says when to retry (`Retry-After`); sign-in, unlock and two-step steps show it. */
    @Test
    fun rateLimitsSayWhenToTryAgain() {
        val limited = failedResponse(429, """{"error":"rate_limited","message":"too many requests"}""", "120")
        assertTrue(limited.isRateLimited)
        assertEquals(120L, limited.retryAfter)
        assertEquals("Too many attempts. Try again in 2 minutes.", errorMessage(limited))
        assertEquals("Too many attempts. Try again in 2 minutes.", securityErrorMessage(limited))
        assertEquals("Too many attempts. Try again in 45 seconds.", errorMessage(failedResponse(429, "", "45")))
        assertEquals("Too many attempts. Try again in 60 minutes.", securityErrorMessage(failedResponse(429, """{"error":"rate_limited","message":"x"}""", "3600")))
        // A proxy's own 429 page is still a rate limit, not "not a PassAuth server".
        val proxy = failedResponse(429, "<html>Too Many Requests</html>", "30")
        assertEquals("rate_limited", proxy.code)
        assertEquals("Too many attempts. Try again in 30 seconds.", errorMessage(proxy))
        // Without Retry-After: the general wording.
        assertNull(tooManyAttemptsMessage(failedResponse(429, "", null)))
        assertEquals("Too many attempts. Wait a moment and try again.", errorMessage(failedResponse(429, "", null)))
        assertEquals("Too many attempts, try again later.", securityErrorMessage(failedResponse(429, "", "soon")))
        // Retry-After only counts on a 429; other errors are as before.
        assertNull(failedResponse(503, """{"error":"internal","message":"down"}""", "10").retryAfter)
        assertEquals("not_passauth", failedResponse(502, "<html>Bad gateway</html>", null).code)
        assertEquals("invalid_code", failedResponse(400, """{"error":"invalid_code","message":"wrong"}""", null).code)
    }

    @Test
    fun retryAfterAndWaitWords() {
        assertEquals(120L, retryAfterSeconds("120"))
        assertEquals(7L, retryAfterSeconds(" 7 "))
        assertNull(retryAfterSeconds(null))
        assertNull(retryAfterSeconds(""))
        assertNull(retryAfterSeconds("soon"))
        // An HTTP date: the seconds until then (rounded up), never negative.
        val at = java.time.ZonedDateTime.parse("2026-11-15T10:00:00Z").toInstant().toEpochMilli()
        assertEquals(90L, retryAfterSeconds("Sun, 15 Nov 2026 10:01:30 GMT", nowMs = at))
        assertEquals(1L, retryAfterSeconds("Sun, 15 Nov 2026 10:00:01 GMT", nowMs = at + 500))
        assertEquals(0L, retryAfterSeconds("Sun, 15 Nov 2026 09:59:00 GMT", nowMs = at))
        assertEquals("a moment", waitText(1))
        assertEquals("45 seconds", waitText(45))
        assertEquals("89 seconds", waitText(89))
        assertEquals("2 minutes", waitText(90))
        assertEquals("2 minutes", waitText(120))
        assertEquals("3 minutes", waitText(121))
        assertEquals("60 minutes", waitText(3600))
    }

    @Test
    fun bodiesCarryTheKeyEpochWhenKnown() {
        val enc = EncryptedItem(id = "i1", vaultId = "v1", key = "k", data = "d")
        val withEpoch = ItemWrites.body(enc, keyEpoch = 4, revision = 9)
        assertEquals(4, withEpoch["key_epoch"]!!.jsonPrimitive.long)
        assertEquals(9, withEpoch["revision"]!!.jsonPrimitive.long)
        assertEquals("v1", withEpoch["vault_id"]!!.jsonPrimitive.content)
        // An older server sent no epoch: none goes back.
        val old = ItemWrites.body(enc, keyEpoch = null)
        assertNull(old["key_epoch"])
        assertNull(old["revision"])
    }

    @Test
    fun createRetriesOnceAfterAKeyChange() = runBlocking {
        var sends = 0
        var syncs = 0
        val created = ItemWrites.create(
            send = { if (++sends == 1) throw keyChanged },
            resync = { syncs++ },
            updateEarlierAttempt = { error("not expected") },
        )
        assertEquals(ItemWrites.Created.New, created)
        assertEquals(2, sends)
        assertEquals(1, syncs)

        // Only once: a second key change is reported.
        sends = 0
        val e = assertThrows(ApiException::class.java) {
            runBlocking { ItemWrites.create(send = { sends++; throw keyChanged }, resync = {}, updateEarlierAttempt = { false }) }
        }
        assertEquals("vault_key_changed", e.code)
        assertEquals(2, sends)
    }

    @Test
    fun createWhoseEarlierAttemptGotThroughUpdatesThatItem() = runBlocking {
        for (answer in listOf(ApiException(409, "item_exists", "item id already exists"), ApiException(409, "conflict", "item id already exists"))) {
            var updated = 0
            val created = ItemWrites.create(send = { throw answer }, resync = { error("not expected") }, updateEarlierAttempt = { updated++; true })
            assertEquals(ItemWrites.Created.UpdatedEarlierAttempt, created)
            assertEquals(1, updated)
        }
        // Not in the vault after all: the error stands.
        assertThrows(ApiException::class.java) {
            runBlocking { ItemWrites.create(send = { throw ApiException(409, "item_exists", "x") }, resync = {}, updateEarlierAttempt = { false }) }
        }
        // Any other error isn't retried.
        var sends = 0
        assertThrows(ApiException::class.java) {
            runBlocking { ItemWrites.create(send = { sends++; throw ApiException(400, "bad_request", "ids must be UUIDs") }, resync = { error("no") }, updateEarlierAttempt = { false }) }
        }
        assertEquals(1, sends)
    }

    @Test
    fun updateRetriesWithTheResyncedItem() = runBlocking {
        val base = entry()
        val sent = mutableListOf<Entry>()
        // The rotation re-encrypted the unchanged item: new revision and key wrapping.
        val rotated = entry(revision = 4)
        ItemWrites.update(base, send = { e -> sent += e; if (sent.size == 1) throw keyChanged }, resync = { rotated })
        assertEquals(listOf(3L, 4L), sent.map { it.revision })
        assertEquals("k4", sent.last().enc.key)
    }

    @Test
    fun updateAfterAKeyChangeOnAChangedItemIsAConflict() {
        var sends = 0
        assertThrows(ConflictException::class.java) {
            runBlocking { ItemWrites.update(entry(), send = { sends++; throw keyChanged }, resync = { entry(password = "changed elsewhere", revision = 4) }) }
        }
        assertEquals("nothing sent on top of the other change", 1, sends)
        // Gone meanwhile: said so (there is nothing to save over). Moved to another vault: a conflict.
        val gone = assertThrows(io.passauth.app.data.UserException::class.java) { runBlocking { ItemWrites.update(entry(), send = { throw keyChanged }, resync = { null }) } }
        assertEquals("This item was deleted on another device.", gone.message)
        assertThrows(ConflictException::class.java) {
            runBlocking { ItemWrites.update(entry(), send = { throw keyChanged }, resync = { entry(vault = "v2", revision = 4) }) }
        }
    }

    @Test
    fun updateConflictsAndRepeatedKeyChanges() {
        // A stale revision is the usual conflict.
        assertThrows(ConflictException::class.java) { runBlocking { ItemWrites.update(entry(), send = { throw revisionConflict }, resync = { error("no") }) } }
        // A key change on the retry too is reported as such.
        val e = assertThrows(ApiException::class.java) {
            runBlocking { ItemWrites.update(entry(), send = { throw keyChanged }, resync = { entry(revision = 4) }) }
        }
        assertEquals("vault_key_changed", e.code)
        // Other errors pass through.
        assertThrows(ApiException::class.java) {
            runBlocking { ItemWrites.update(entry(), send = { throw ApiException(403, "forbidden", "no write access") }, resync = { error("no") }) }
        }
    }
}
