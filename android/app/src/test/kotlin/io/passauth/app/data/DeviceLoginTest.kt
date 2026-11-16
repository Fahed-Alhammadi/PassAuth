package io.passauth.app.data

import io.passauth.core.CoreException
import io.passauth.core.LoginApproval
import io.passauth.core.LoginRequestKey
import io.passauth.core.accountFromSessionBytes
import io.passauth.core.loginPhrase
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

private fun obj(json: String) = AppJson.parseToJsonElement(json).jsonObject

/** Sign in with another device: the new device's request and wait, and the approving app's side (DeviceLogin.kt). */
class DeviceLoginTest {
    // ------------------------------------------------------------ the new device

    @Test
    fun accessCodesAre256RandomBitsInBase64url() {
        val a = DeviceLogin.accessCode()
        assertEquals(43, a.length)
        assertTrue(a, Regex("[A-Za-z0-9_-]{43}").matches(a))
        assertNotEquals(a, DeviceLogin.accessCode())
    }

    @Test
    fun pollDelaysGrowToTenSeconds() {
        assertEquals(listOf(2L, 2L, 2L, 3L, 3L, 4L, 5L, 6L, 8L, 10L, 10L), (0..10).map(DeviceLogin::pollDelay))
    }

    @Test
    fun countdown() {
        assertEquals("15:00", DeviceLogin.countdown(1_000_900, 1_000_000))
        assertEquals("14:59", DeviceLogin.countdown(1_000_899, 1_000_000))
        assertEquals("0:05", DeviceLogin.countdown(1_000_005, 1_000_000))
        assertEquals("0:00", DeviceLogin.countdown(999_000, 1_000_000))
        assertEquals("Expires in 1:30", DeviceLogin.expiresIn(1_000_090, 1_000_000))
    }

    private val device = buildJsonObject { put("id", "dev-1"); put("name", "PassAuth for Android (Pixel)"); put("kind", "mobile") }

    @Test
    fun theRequestCarriesTheKeyTheCodeAndTheDevice() {
        val b = DeviceLogin.requestBody(" alex@example.com ", "PUB", "CODE", device, "REMEMBER")
        assertEquals(
            buildJsonObject {
                put("email", "alex@example.com")
                put("public_key", "PUB")
                put("access_code", "CODE")
                put("device_id", "dev-1")
                put("device_name", "PassAuth for Android (Pixel)")
                put("device_kind", "mobile")
                put("remember_token", "REMEMBER")
            },
            b,
        )
        assertFalse("no remember token: left out", "remember_token" in DeviceLogin.requestBody("a@x", "P", "C", device, null))
    }

    /** A scripted server for the new device: answers in order, records every call. */
    private class FakeServer(vararg polls: () -> JsonObject) : DeviceLoginTransport {
        val created = mutableListOf<JsonObject>()
        val polled = mutableListOf<Pair<String, String>>()
        private val answers = ArrayDeque(polls.toList())
        var createAnswer: () -> JsonObject = { obj("""{"id":"req-1","fingerprint_phrase":"server words","expires_at":1000900}""") }

        override suspend fun create(body: JsonObject): JsonObject {
            created += body
            return createAnswer()
        }

        override suspend fun poll(id: String, accessCode: String): JsonObject {
            polled += id to accessCode
            return (answers.removeFirstOrNull() ?: error("polled too often"))()
        }
    }

    /** A clock that moves only when the flow sleeps. */
    private class Clock(var now: Long = 1_000_000) {
        val slept = mutableListOf<Long>()
        suspend fun sleep(seconds: Long) {
            slept += seconds
            now += seconds
        }
    }

    private fun flow(server: FakeServer, clock: Clock) = DeviceLoginFlow(server, { clock.now }, clock::sleep)

    @Test
    fun startSendsTheRequestAndKeepsOnlyTheIdAndExpiry() = runBlocking {
        val server = FakeServer()
        val started = flow(server, Clock()).start("alex@example.com", "PUB", "CODE", device, null)
        assertEquals(DeviceLoginFlow.Started("req-1", 1_000_900), started)
        assertEquals("PUB", server.created.single().str("public_key"))
        // Refused while the admin turned the feature off.
        server.createAnswer = { throw ApiException(403, "login_with_device_disabled", "turned off") }
        val e = assertThrows(UserException::class.java) { runBlocking { flow(server, Clock()).start("a@x", "P", "C", device, null) } }
        assertEquals(DeviceLogin.DISABLED, e.message)
        // Rate limits and other errors are the caller's to word.
        server.createAnswer = { throw ApiException(429, "rate_limited", "slow down", 60) }
        assertThrows(ApiException::class.java) { runBlocking { flow(server, Clock()).start("a@x", "P", "C", device, null) } }
        Unit
    }

    @Test
    fun waitsWithGrowingDelaysUntilApproved() = runBlocking {
        val session = """{"status":"approved","sealed_key":"SK","access_token":"a","refresh_token":"r","user_id":"u","email":"alex@example.com","bundle":{}}"""
        val server = FakeServer({ obj("""{"status":"pending"}""") }, { obj("""{"status":"pending"}""") }, { obj(session) })
        val clock = Clock()
        val result = flow(server, clock).await("req-1", "CODE", 1_000_900)
        assertEquals(DeviceLoginPoll.Approved(obj(session)), result)
        assertEquals(listOf(2L, 2L, 2L), clock.slept)
        // The access code goes with each poll (as a header, see VaultRepository), never in the id.
        assertEquals(listOf("req-1" to "CODE", "req-1" to "CODE", "req-1" to "CODE"), server.polled)
    }

    @Test
    fun twoStepLoginComesFirstWhenTheAccountHasIt() = runBlocking {
        val server = FakeServer({ obj("""{"status":"approved","two_factor_required":true,"two_factor_token":"T","providers":["totp","recovery"]}""") })
        assertEquals(DeviceLoginPoll.TwoFactor("T", listOf("totp", "recovery")), flow(server, Clock()).await("req-1", "CODE", 1_000_900))
    }

    @Test
    fun endingsSayWhatHappened() = runBlocking {
        fun ending(answer: () -> JsonObject) = runBlocking { flow(FakeServer(answer), Clock()).await("req-1", "CODE", 1_000_900) }
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.DENIED), ending { obj("""{"status":"denied"}""") })
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.EXPIRED), ending { obj("""{"status":"expired"}""") })
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.USED), ending { obj("""{"status":"used"}""") })
        // A wrong code and an unknown request look the same: 404.
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.GONE), ending { throw ApiException(404, "not_found", "not found") })
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.DISABLED), ending { throw ApiException(403, "login_with_device_disabled", "off") })
        // The account itself was refused (disabled, unverified): the app's usual message, from the caller.
        val e = assertThrows(ApiException::class.java) { ending { throw ApiException(403, "account_disabled", "this account is disabled") } }
        assertEquals("account_disabled", e.code)
        Unit
    }

    @Test
    fun rateLimitsNetworkAndServerErrorsDontEndTheWait() = runBlocking {
        val server = FakeServer(
            { throw ApiException(429, "rate_limited", "slow down", 7) },
            { throw ApiException(429, "rate_limited", "slow down") },
            { throw UserException(UNREACHABLE) },
            { throw ApiException(502, "not_passauth", "bad gateway") },
            { obj("""{"status":"something new"}""") },
            { obj("""{"status":"denied"}""") },
        )
        val clock = Clock()
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.DENIED), flow(server, clock).await("req-1", "CODE", 1_000_900))
        // 2 → 429: its Retry-After (7) → 2 → 429 without one: 10 → 2 → … the usual delays go on.
        assertEquals(listOf(2L, 7L, 2L, 10L, 2L, 3L, 3L, 4L), clock.slept)
        assertEquals(6, server.polled.size)
    }

    @Test
    fun givesUpOnceTheRequestIsPastItsTime() = runBlocking {
        val pending = { obj("""{"status":"pending"}""") }
        val server = FakeServer(*Array(500) { pending })
        val clock = Clock()
        val expiresAt = 1_000_100L
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.EXPIRED), flow(server, clock).await("req-1", "CODE", expiresAt))
        assertTrue("stopped within the grace", clock.now in (expiresAt + DeviceLogin.EXPIRY_GRACE + 1)..(expiresAt + DeviceLogin.EXPIRY_GRACE + DeviceLogin.MAX_DELAY))
        assertTrue(server.polled.size < 30)
    }

    @Test
    fun theDeadlineIsNeverMoreThanFifteenMinutesAfterTheRequestWasMade() {
        val madeAt = 1_000_000L
        assertEquals(madeAt + 900, DeviceLogin.deadline(madeAt + 900, madeAt, madeAt))
        assertEquals(madeAt + 300, DeviceLogin.deadline(madeAt + 300, madeAt, madeAt))
        // Years ahead, already past, or not said: 15 minutes.
        assertEquals(madeAt + 900, DeviceLogin.deadline(4_102_444_800, madeAt, madeAt))
        assertEquals(madeAt + 900, DeviceLogin.deadline(madeAt - 10, madeAt, madeAt))
        assertEquals(madeAt + 900, DeviceLogin.deadline(null, madeAt, madeAt))
        // Read as time left when the answer came, still capped from when the request was made.
        assertEquals(madeAt + 600, DeviceLogin.deadline(madeAt + 600, madeAt, madeAt + 2))
        assertEquals(madeAt + 900, DeviceLogin.deadline(madeAt + 1_000, madeAt, madeAt + 5))
    }

    @Test
    fun aServerCantKeepTheNewDeviceWaiting() = runBlocking {
        val clock = Clock()
        val madeAt = clock.now
        for (answer in listOf("""{"id":"req-1","expires_at":4102444800}""", """{"id":"req-1","expires_at":1}""", """{"id":"req-1"}""", """{"id":"req-1","expires_at":"4102444800"}""")) {
            val server = FakeServer().apply { createAnswer = { obj(answer) } }
            assertEquals(answer, madeAt + DeviceLogin.LIFETIME, flow(server, clock).start("a@x", "P", "C", device, null).expiresAt)
        }
        // A server that says "pending" for ever: the wait ends 15 + 1 minutes after the request was made.
        val server = FakeServer(*Array(1000) { { obj("""{"status":"pending"}""") } }).apply { createAnswer = { obj("""{"id":"req-1","expires_at":4102444800}""") } }
        val started = flow(server, clock).start("a@x", "P", "C", device, null)
        assertEquals(DeviceLoginPoll.Ended(DeviceLogin.EXPIRED), flow(server, clock).await(started.id, "C", started.expiresAt))
        assertTrue("stopped by 16 minutes", clock.now <= madeAt + 16 * 60 + DeviceLogin.MAX_DELAY)
        assertTrue("not before 16 minutes", clock.now > madeAt + 16 * 60)
    }

    // ------------------------------------------- the new device: the approval's code

    @Test
    fun theCodeWording() {
        assertEquals("That code doesn't match. 2 tries left.", DeviceLogin.wrongCode(2))
        assertEquals("That code doesn't match. 1 try left.", DeviceLogin.wrongCode(1))
        assertEquals("Enter the 6-digit code shown on your other device.", DeviceLogin.CODE_PROMPT)
        assertEquals(
            "Too many wrong codes, so this sign-in was stopped. If you didn't approve it on your other device, change your master password.",
            DeviceLogin.TOO_MANY_CODES,
        )
    }

    @Test
    fun aReceivedSecretKeyIsKeptOnlyForTheTypedEmailAndNeverOverAnother() {
        val kept = mapOf("other@example.com" to "PA1-OTHER")
        // The account the server signed in is the one typed here (case and spaces don't matter): kept under the typed email.
        assertEquals(kept + ("alex@example.com" to "PA1-NEW"), DeviceLogin.keepSecretKey(kept, "PA1-NEW", " Alex@Example.com ", "alex@example.com"))
        // The server signed in another account: nothing kept.
        assertEquals(kept, DeviceLogin.keepSecretKey(kept, "PA1-NEW", "alex@example.com", "other@example.com"))
        assertEquals(kept, DeviceLogin.keepSecretKey(kept, "PA1-NEW", "alex@example.com", ""))
        // A different key already kept for that email stays.
        assertEquals(kept, DeviceLogin.keepSecretKey(kept, "PA1-NEW", "other@example.com", "other@example.com"))
        // The same key again, or none at all: unchanged.
        assertEquals(kept, DeviceLogin.keepSecretKey(kept, "PA1-OTHER", "other@example.com", "other@example.com"))
        assertEquals(kept, DeviceLogin.keepSecretKey(kept, null, "alex@example.com", "alex@example.com"))
        assertEquals(kept, DeviceLogin.keepSecretKey(kept, "PA1-NEW", " ", ""))
    }

    // ------------------------------------------------------------ the approving app

    private fun listed(vararg entries: String) = obj("""{"requests":[${entries.joinToString(",")}]}""")

    private val requestJson = """{"id":"r-1","public_key":"PUB","fingerprint_phrase":"server words","challenge":"CH","device_name":"Pixel 9",
        |"device_kind":"mobile","client":"android/0.7.0","ip":"203.0.113.9","created_at":999880,"expires_at":1000780}""".trimMargin()

    @Test
    fun requestsAreReadLenientlyNewestFirst() {
        val now = 1_000_000L
        val list = DeviceApprovals.parse(
            listed(
                """{"id":"old","public_key":"P","challenge":"C","device_name":"Old","device_kind":"web","created_at":999000,"expires_at":1000100}""",
                requestJson,
                """{"id":"gone","public_key":"P","challenge":"C","created_at":999000,"expires_at":999999}""",
                """{"id":"no-key","challenge":"C","expires_at":1000500}""",
                """{"id":"no-challenge","public_key":"P","expires_at":1000500}""",
                """{"id":"../x","public_key":"P","challenge":"C","expires_at":1000500}""",
                """{"id":"strings","public_key":"P","challenge":"C","expires_at":"1000500"}""",
                "42",
            ),
            now,
        )
        assertEquals(listOf("r-1", "old"), list.map { it.id })
        assertEquals(AuthRequest("r-1", "PUB", "CH", "Pixel 9", "mobile", "android/0.7.0", "203.0.113.9", 999_880, 1_000_780), list[0])
        assertNull("no client or address: none shown", list[1].client ?: list[1].ip)
        assertEquals(emptyList<AuthRequest>(), DeviceApprovals.parse(null, now))
        assertEquals(emptyList<AuthRequest>(), DeviceApprovals.parse(obj("""{"requests":"x"}"""), now))
    }

    @Test
    fun theSheetsWording() {
        val r = DeviceApprovals.parse(listed(requestJson), 1_000_000).single()
        assertEquals("A device is asking to sign in to alex@example.com.", DeviceApprovals.body("alex@example.com"))
        assertEquals("Device (as it calls itself)", DeviceApprovals.DEVICE)
        assertEquals("Pixel 9", DeviceApprovals.device(r))
        assertEquals("No name given", DeviceApprovals.device(r.copy(deviceName = " ")))
        assertEquals("Android app 0.7.0", DeviceApprovals.app(r))
        assertEquals("Mobile app", DeviceApprovals.app(r.copy(client = null)))
        assertEquals("203.0.113.9", DeviceApprovals.address(r))
        assertNull(DeviceApprovals.address(r.copy(ip = null)))
        assertEquals("Which words does the new device show?", DeviceApprovals.QUESTION)
        assertEquals("123 456", DeviceApprovals.groupedCode("123456"))
        assertEquals("Just now", DeviceApprovals.requested(1_000_000, 1_000_059))
        assertEquals("1 minute ago", DeviceApprovals.requested(1_000_000, 1_000_060))
        assertEquals("3 minutes ago", DeviceApprovals.requested(1_000_000, 1_000_200))
        assertEquals("2 hours ago", DeviceApprovals.requested(1_000_000, 1_007_200))
        assertEquals("Just now", DeviceApprovals.requested(1_000_100, 1_000_000))
    }

    @Test
    fun claimedTextIsCleanedAndCutShort() {
        // Bidi overrides and isolates, marks, zero-width and control characters go; breaks become spaces.
        assertEquals("invoiceexe.pdf", ShownText.clean("invoice‮exe.pdf", 64))
        assertEquals("ab", ShownText.clean("a​b⁦⁩﻿‎‏\u0000\u001F‪‬", 64))
        assertEquals("Your MacBook PassAuth check", ShownText.clean("  Your MacBook\n\tPassAuth check  ", 64))
        assertEquals("", ShownText.clean(" ‮​ ", 64))
        assertEquals("", ShownText.clean(null, 64))
        // At most 64 characters (code points), with an ellipsis; an emoji is never cut in half.
        assertEquals("x".repeat(63) + "…", ShownText.clean("x".repeat(100), 64))
        assertEquals("x".repeat(64), ShownText.clean("x".repeat(64), 64))
        assertEquals("😀".repeat(63) + "…", ShownText.clean("😀".repeat(70), 64))
        // The sheet's claims go through it.
        val r = AuthRequest("r", "P", "C", "Your MacBook‮ – PassAuth security check" + "!".repeat(100), "evil⁦kind", null, "203.0.113.9\n‮", 0, 1)
        val device = DeviceApprovals.device(r)
        assertEquals(64, device.codePointCount(0, device.length))
        assertTrue(device.startsWith("Your MacBook – PassAuth security check!"))
        assertTrue(device.endsWith("…"))
        assertEquals("No name given", DeviceApprovals.device(r.copy(deviceName = "‮​")))
        assertEquals("Evilkind", DeviceApprovals.app(r))
        assertEquals("Chrome extension 0.6.0", DeviceApprovals.app(r.copy(client = "extension/0.6.0")))
        assertEquals("203.0.113.9", DeviceApprovals.address(r))
        assertNull(DeviceApprovals.address(r.copy(ip = "​")))
    }

    /** The approving app's crypto, faked: the words of key "PUB" are "right words". */
    private class FakeApproval : ApprovalCrypto {
        val calls = mutableListOf<String>()
        override fun approve(publicKey: String, requestId: String, chosenPhrase: String, secretKey: String?): LoginApproval {
            calls += "approve $publicKey $requestId $chosenPhrase $secretKey"
            if (chosenPhrase != "right words") throw CoreException.PhraseMismatch("phrase_mismatch")
            return LoginApproval("SEALED", "123456")
        }

        override fun proof(challenge: String, requestId: String): String {
            calls += "proof $challenge $requestId"
            return "PROOF"
        }
    }

    @Test
    fun approvingNeedsTheRequestsWordsAndGivesTheCode() {
        val r = DeviceApprovals.parse(listed(requestJson), 1_000_000).single()
        val crypto = FakeApproval()
        val ok = DeviceApprovals.prepare(r, "right words", crypto, "PA1-SECRET")
        assertEquals(
            PreparedApproval.Approve(buildJsonObject { put("approve", true); put("sealed_key", "SEALED"); put("proof", "PROOF") }, "123456"),
            ok,
        )
        assertEquals(listOf("approve PUB r-1 right words PA1-SECRET", "proof CH r-1"), crypto.calls)
        assertFalse("the code isn't logged", ok.toString().contains("123456"))
        // Other words: nothing is sealed or proven.
        val wrong = FakeApproval()
        assertEquals(PreparedApproval.Mismatch, DeviceApprovals.prepare(r, "other words", wrong, "PA1-SECRET"))
        assertEquals(listOf("approve PUB r-1 other words PA1-SECRET"), wrong.calls)
        assertEquals(buildJsonObject { put("approve", false) }, DeviceApprovals.DENY)
    }

    @Test
    fun refusedAnswersInPlainWords() {
        assertEquals("This request was already answered on another device.", DeviceApprovals.errorMessage(ApiException(409, "conflict", "already answered")))
        assertEquals("This request expired.", DeviceApprovals.errorMessage(ApiException(400, "expired", "this sign-in request expired")))
        assertEquals("This request is no longer there.", DeviceApprovals.errorMessage(ApiException(404, "not_found", "not found")))
        assertEquals(DeviceApprovals.UNCHECKED, DeviceApprovals.errorMessage(CoreException.DecryptFailed("decrypt_failed")))
        assertNull(DeviceApprovals.errorMessage(ApiException(400, "bad_request", "nope")))
        assertNull(DeviceApprovals.errorMessage(UserException(UNREACHABLE)))
    }

    // --------------------------------------------- the approving app's frozen queue

    private val now = 1_000_000L

    private fun req(id: String, key: String = "K-$id", challenge: String = "C-$id", createdAt: Long = 999_990, expiresAt: Long = now + 600) =
        AuthRequest(id, key, challenge, "Device $id", "web", null, null, createdAt, expiresAt)

    /** Freezes with fixed words (the inbox asks the core). */
    private val freeze = { r: AuthRequest -> ShownRequest(r, listOf("one ${r.id}", "two ${r.id}", "three ${r.id}")) }

    private fun ApprovalQueue.list(vararg r: AuthRequest, account: String = "acc") = listed(account, r.toList(), now).let { it.copy(queue = it.queue.next(now, freeze)) }

    private fun QueueStep.next() = queue.next(now, freeze)

    @Test
    fun theShownRequestIsFrozenAndNeverReplacedByANewerOne() {
        val a = req("a")
        var q = ApprovalQueue().list(a).queue
        assertEquals(a, q.shown?.request)
        assertEquals(listOf("one a", "two a", "three a"), q.shown?.choices)
        // A newer request waits in line: the one on screen stays, frozen.
        val b = req("b", createdAt = 999_995)
        q = q.list(b, a).queue
        assertEquals(a, q.shown?.request)
        assertEquals(listOf("b", "a"), q.requests.map { it.id })
        // The same request listed with another name: still the frozen copy.
        q = q.list(b, a.copy(deviceName = "Renamed", client = "web/1")).queue
        assertEquals("Device a", q.shown?.request?.deviceName)
        assertNull(q.shown?.request?.client)
        // Put off: the next one in line comes up, frozen as it is now; the put-off one doesn't come back.
        q = q.putOff("a").next()
        assertEquals(b, q.shown?.request)
        q = q.list(b, a).queue
        assertEquals(b, q.shown?.request)
        assertEquals(listOf("b"), q.requests.map { it.id })
        // Expired while waiting in line: never shown.
        assertNull(ApprovalQueue().list(req("c", expiresAt = now)).queue.shown)
    }

    @Test
    fun theSameKeyWithAResealedChallengeKeepsTheSheet() {
        // The server seals the challenge again for every listing: other text, the same value inside.
        val a = req("a")
        var q = ApprovalQueue().list(a).queue
        for (n in 1..3) {
            val step = q.list(a.copy(challenge = "C-a-resealed-$n", deviceName = "Renamed $n"))
            assertNull(step.note)
            assertNull(step.queue.closed)
            q = step.queue
        }
        // Still the request as it was frozen: its first challenge is the one the proof opens.
        assertEquals(a, q.shown?.request)
        assertEquals("C-a", q.shown?.request?.challenge)
    }

    @Test
    fun aListingThatChangesTheShownRequestClosesIt() {
        val a = req("a")
        val changed = a.copy(publicKey = "K-server")
        run {
            val step = ApprovalQueue().list(a).queue.list(changed, req("b"))
            assertNull("closed, not updated in place", step.queue.shown)
            assertEquals(Closed.Changed, step.queue.closed)
            assertNull(step.note)
            // Nothing else comes up until the note was read; then the next one, never the changed one.
            assertNull(step.queue.list(changed, req("b")).queue.shown)
            val after = step.queue.closedRead().next()
            assertEquals("b", after.shown?.request?.id)
            assertNull(after.putOff("b").next().list(changed).queue.shown)
        }
        // Dropped from the listing before its time: closed the same way.
        val gone = ApprovalQueue().list(a).queue.list(req("b"))
        assertEquals(Closed.Changed, gone.queue.closed)
        assertNull(gone.queue.shown)
        // Dropped because its time ran out: an ordinary note instead.
        val late = ApprovalQueue().list(req("x", expiresAt = now)).queue.copy(shown = ShownRequest(req("x", expiresAt = now), emptyList()))
        val expired = late.listed("acc", emptyList(), now)
        assertNull(expired.queue.closed)
        assertEquals(DeviceApprovals.EXPIRED, expired.note)
    }

    @Test
    fun answersHereAndElsewhere() {
        val a = req("a")
        val b = req("b", createdAt = 999_000)
        val q = ApprovalQueue().list(a, b).queue
        // Answered on another device: the sheet closes with a note, the next one comes up.
        val elsewhere = q.answeredElsewhere("a")
        assertEquals(DeviceApprovals.ANSWERED_ELSEWHERE, elsewhere.note)
        assertEquals("b", elsewhere.next().shown?.request?.id)
        // Being answered here: listings and the live message leave it on screen.
        val sending = q.answering("a", Answering.Approve)!!
        assertNull("only once", sending.answering("a", Answering.Deny))
        assertNull("only the shown one", q.answering("b", Answering.Approve))
        assertEquals(a, sending.list(b).queue.shown?.request)
        assertEquals(a, sending.answeredElsewhere("a").queue.shown?.request)
        // Approved here: the code stays (also through listings without it and this app's own answer coming back) until Done.
        var done = sending.approved("a", "123456").next()
        assertEquals("123456", done.shown?.code)
        done = done.list(b).queue
        done = done.answeredElsewhere("a").next()
        assertEquals("123456", done.shown?.code)
        assertEquals("b", done.done("a").next().shown?.request?.id)
        // Denied here (or the answer failed): the sheet closes.
        assertEquals("b", sending.finished("a", DeviceApprovals.DENIED).next().shown?.request?.id)
        // An answer that never left: the sheet is as it was.
        assertNull(sending.notAnswered("a").queue.shown?.answering)
        // Answered (here or elsewhere): a stale listing that still has it never brings it back; a failed answer's does.
        fun relisted(after: ApprovalQueue) = after.putOff("b").next().list(a).queue.shown?.request
        assertNull(relisted(done.done("a").next()))
        assertNull(relisted(sending.finished("a", DeviceApprovals.DENIED).queue))
        assertNull(relisted(q.answeredElsewhere("a").queue))
        assertEquals(a, relisted(sending.finished("a", answered = false).queue))
        // The shown request's time ran out on screen.
        val late = ApprovalQueue().list(req("x", expiresAt = now + 1)).queue
        assertNull(late.expired("x", now).note)
        assertEquals(DeviceApprovals.EXPIRED, late.expired("x", now + 1).note)
    }

    @Test
    fun anotherAccountsListingStartsAfresh() {
        val q = ApprovalQueue().list(req("a")).queue.answering("a", Answering.Approve)!!.approved("a", "123456").queue
        val other = q.list(req("b"), account = "acc-2").queue
        assertEquals("acc-2", other.account)
        assertEquals("b", other.shown?.request?.id)
        assertNull(ApprovalQueue().list(req("a")).queue.clear().next().shown)
    }

    /** The repository, faked: one listing at a time, and what was answered with which words. */
    private class FakeSource(var listing: AuthRequestListing?) : AuthRequestSource {
        val answers = mutableListOf<String>()
        var fail: Exception? = null
        override suspend fun list() = listing
        override suspend fun approve(account: String, request: AuthRequest, chosenPhrase: String): String? {
            fail?.let { throw it }
            answers += "approve $account ${request.id} ${request.publicKey} ${request.challenge} $chosenPhrase"
            return if (chosenPhrase == "one ${request.id}") "654321" else null
        }

        override suspend fun deny(account: String, request: AuthRequest) {
            fail?.let { throw it }
            answers += "deny $account ${request.id}"
        }
    }

    @Test
    fun theInboxAnswersFromTheFrozenCopy() = runBlocking {
        val a = req("a")
        val source = FakeSource(AuthRequestListing("acc", listOf(a)))
        val inbox = AuthRequestInbox(source, { now }) { key -> listOf("one ${key.removePrefix("K-")}", "two", "three") }
        val notes = mutableListOf<InboxNotice>()
        val watching = launch(start = CoroutineStart.UNDISPATCHED) { inbox.notices.collect { notes += it } }
        inbox.refresh()
        assertEquals(a, inbox.shown?.request)
        // Re-listed with the challenge sealed again: the same sheet.
        source.listing = AuthRequestListing("acc", listOf(a.copy(challenge = "C-a-resealed")))
        inbox.refresh()
        assertEquals(a, inbox.shown?.request)
        assertNull(inbox.queue.value.closed)
        // The server swaps the key after the words were shown: the sheet closes, and nothing can approve it.
        source.listing = AuthRequestListing("acc", listOf(a.copy(publicKey = "K-server")))
        inbox.refresh()
        assertEquals(Closed.Changed, inbox.queue.value.closed)
        inbox.approve("a", "one a")
        assertEquals(emptyList<String>(), source.answers)
        inbox.closedRead()
        // A new request: the request's own words approve with the frozen key, and the code shows until Done.
        val b = req("b")
        source.listing = AuthRequestListing("acc", listOf(b))
        inbox.refresh()
        source.listing = AuthRequestListing("acc", listOf(b.copy(challenge = "C-b-resealed")))
        inbox.refresh()
        inbox.approve("b", "not offered")
        inbox.approve("b", "one b")
        // The frozen key and challenge go into the approval, never a newer listing's.
        assertEquals(listOf("approve acc b K-b C-b one b"), source.answers)
        assertEquals("654321", inbox.shown?.code)
        source.listing = AuthRequestListing("acc", emptyList())
        inbox.refresh()
        inbox.answered("b")
        assertEquals("654321", inbox.shown?.code)
        inbox.done("b")
        assertNull(inbox.shown)
        // Other words deny it, and say so before anything else comes up.
        val c = req("c")
        source.listing = AuthRequestListing("acc", listOf(c, req("c2", createdAt = 999_000)))
        inbox.refresh()
        inbox.approve("c", "two")
        assertEquals("approve acc c K-c C-c two", source.answers.last())
        assertNull(inbox.shown)
        assertEquals(Closed.Mismatch, inbox.queue.value.closed)
        inbox.closedRead()
        assertEquals("c2", inbox.shown?.request?.id)
        inbox.putOff("c2")
        // "None of these", and an answer that fails: the sheet closes either way.
        val d = req("d")
        source.listing = AuthRequestListing("acc", listOf(d))
        inbox.refresh()
        inbox.deny("d")
        assertEquals("deny acc d", source.answers.last())
        source.listing = AuthRequestListing("acc", listOf(req("e")))
        inbox.refresh()
        source.fail = ApiException(409, "conflict", "already answered")
        inbox.approve("e", "one e")
        assertNull(inbox.shown)
        // Locked or no feature: nothing.
        source.listing = null
        inbox.refresh()
        assertNull(inbox.queue.value.account)
        yield()
        assertEquals(
            listOf<InboxNotice>(
                InboxNotice.Text(DeviceApprovals.DENIED),
                InboxNotice.Failed(source.fail!!),
            ),
            notes,
        )
        watching.cancel()
    }

    // ------------------------------------------------------------ with the real core

    /**
     * The Rust core end to end (crates/core/src/device_login.rs): the approving app approves only
     * with the request key's own words and gets the code; the new device opens the approval, but
     * nothing of it is usable before that code.
     */
    @Test
    fun anApprovalIsUsableOnlyWithItsCode() {
        val bytes = ByteArray(64).also(SecureRandom()::nextBytes)
        val account = accountFromSessionBytes("acc-1", bytes)
        val key = LoginRequestKey.generate()
        try {
            // Both screens' words come from the key each holds; the approving app offers three, one of them right.
            assertEquals(key.phrase(), loginPhrase(key.publicKey()))
            assertEquals(5, key.phrase().split(" ").size)
            val choices = DeviceApprovals.choices(key.publicKey())
            assertEquals(3, choices.size)
            assertEquals(1, choices.count { it == key.phrase() })
            val crypto = AccountApprovalCrypto(account)
            // Other words: refused by the core.
            val decoy = choices.first { it != key.phrase() }
            assertThrows(CoreException.PhraseMismatch::class.java) { crypto.approve(key.publicKey(), "req-1", decoy, null) }
            assertEquals(PreparedApproval.Mismatch, DeviceApprovals.prepare(AuthRequest("req-1", key.publicKey(), "CH", "", "", null, null, 0, 1), decoy, crypto, null))
            val secretKey = "PA1-AEBAGB-AFAYDQ-QCIKBM-GA2DQP-CA"
            val approval = crypto.approve(key.publicKey(), "req-1", key.phrase(), secretKey)
            assertTrue(approval.code, Regex("[0-9]{6}").matches(approval.code))
            // Bound to the account and the request; another device's key can't open it.
            assertThrows(CoreException::class.java) { key.open(approval.sealed, "acc-2", "req-1") }
            assertThrows(CoreException::class.java) { key.open(approval.sealed, "acc-1", "req-2") }
            LoginRequestKey.generate().use { other -> assertThrows(CoreException::class.java) { other.open(approval.sealed, "acc-1", "req-1") } }
            key.open(approval.sealed, "acc-1", "req-1").use { approved ->
                assertEquals("acc-1", approved.accountId())
                // Nothing before the code.
                assertFalse(approved.isConfirmed())
                assertThrows(CoreException.NotConfirmed::class.java) { approved.secretKey() }
                assertThrows(CoreException.NotConfirmed::class.java) { approved.unlock(FAKE_BUNDLE) }
                // Not six digits: not counted.
                assertEquals(CodeCheck.NotACode(DeviceLogin.CODE_PROMPT), DeviceLogin.check(approved, "12345"))
                assertEquals(3, approved.attemptsLeft().toInt())
                assertEquals(CodeCheck.Wrong(DeviceLogin.wrongCode(2)), DeviceLogin.check(approved, otherCode(approval.code)))
                // The right code, as typed with a space: confirmed.
                assertEquals(CodeCheck.Confirmed, DeviceLogin.check(approved, approval.code.take(3) + " " + approval.code.drop(3)))
                assertTrue(approved.isConfirmed())
                assertEquals(secretKey, approved.secretKey())
                // Past the gate: a bundle that doesn't open now fails as a bundle, not as "not confirmed".
                val e = assertThrows(CoreException::class.java) { approved.unlock(FAKE_BUNDLE) }
                assertFalse(e is CoreException.NotConfirmed)
            }
            // Without a Secret Key on the approving app, none comes.
            val bare = crypto.approve(key.publicKey(), "req-1", key.phrase(), null)
            key.open(bare.sealed, "acc-1", "req-1").use {
                assertEquals(CodeCheck.Confirmed, DeviceLogin.check(it, bare.code))
                assertNull(it.secretKey())
            }
            // A malformed key gives no words (the sheet then offers only None of these / Not now).
            assertThrows(CoreException::class.java) { loginPhrase("not a key") }
            assertEquals(emptyList<String>(), DeviceApprovals.choices("not a key"))
        } finally {
            key.destroy()
            account.destroy()
        }
    }

    @Test
    fun threeWrongCodesStopTheSignInForGood() {
        val account = accountFromSessionBytes("acc-1", ByteArray(64).also(SecureRandom()::nextBytes))
        val key = LoginRequestKey.generate()
        try {
            val approval = AccountApprovalCrypto(account).approve(key.publicKey(), "req-1", key.phrase(), "PA1-AEBAGB-AFAYDQ-QCIKBM-GA2DQP-CA")
            key.open(approval.sealed, "acc-1", "req-1").use { approved ->
                val wrong = otherCode(approval.code)
                assertEquals(CodeCheck.Wrong(DeviceLogin.wrongCode(2)), DeviceLogin.check(approved, wrong))
                assertEquals(CodeCheck.Wrong(DeviceLogin.wrongCode(1)), DeviceLogin.check(approved, wrong))
                assertEquals(CodeCheck.Stopped(DeviceLogin.TOO_MANY_CODES), DeviceLogin.check(approved, wrong))
                // Even the right code is refused now, and nothing can be read.
                assertEquals(CodeCheck.Stopped(DeviceLogin.TOO_MANY_CODES), DeviceLogin.check(approved, approval.code))
                assertFalse(approved.isConfirmed())
                assertEquals(0, approved.attemptsLeft().toInt())
                assertThrows(CoreException.NotConfirmed::class.java) { approved.secretKey() }
            }
        } finally {
            key.destroy()
            account.destroy()
        }
    }

    /** An account bundle that reads (so unlocking gets to the code check) but doesn't open with any key. */
    private val FAKE_BUNDLE = """{"account_id":"acc-1","kdf":{"memory_kib":65536,"iterations":3,"parallelism":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA"},""" +
        """"secret_key_enabled":false,"wrapped_account_key":"AAAA","public_key":"AAAA","wrapped_private_key":"AAAA"}"""

    /** A six-digit code that isn't [code]. */
    private fun otherCode(code: String) = ((code.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
}
