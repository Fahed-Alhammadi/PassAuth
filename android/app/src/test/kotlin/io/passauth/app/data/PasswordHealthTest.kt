package io.passauth.app.data

import io.passauth.core.EncryptedItem
import java.io.IOException
import java.net.ServerSocket
import java.util.Collections
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Password health (PasswordHealth.kt, HealthSession.kt), the same cases as the web vault's
 * `health.test.ts` and the iOS `PasswordHealthTests`: the weak threshold, reuse groups, what's left
 * out, range answers, the breach check's requests, limits and failures, and the session dropping
 * everything when the vault closes.
 */
class PasswordHealthTest {
    // ------------------------------------------------------------------ helpers

    private data class TestEntry(val id: String, val password: String?, val trashed: Boolean = false)

    private var nextId = 0
    private fun login(password: String?, trashed: Boolean = false) = TestEntry("item-${++nextId}", password, trashed)

    private fun analyze(entries: List<TestEntry>, bits: (String) -> Double) =
        PasswordHealth.analyze(entries, bits, { it.id }, { it.password }, { it.trashed })

    /** Strength estimate stub: bits per password, 100 for anything not listed. */
    private fun bitsFrom(table: Map<String, Double>): (String) -> Double = { table[it] ?: 100.0 }

    /** A 40-character uppercase hex hash from a 5-character prefix and a suffix seed. */
    private fun hash(prefix: String, seed: String) = (prefix + seed.repeat(35)).take(40).uppercase()

    /** Digest stub: fixed hashes per password, so tests choose which passwords share a prefix. */
    private fun digestFrom(table: Map<String, String>): (String) -> String = { table[it] ?: error("no hash for $it") }

    /** [count] padding lines (count 0), as Have I Been Pwned adds them. */
    private fun padding(count: Int, seed: Int = 0) = (0 until count).map { (seed * 1000 + it).toString(16).uppercase().padStart(35, 'F') + ":0" }

    private fun prefixOf(url: String) = url.removePrefix(PwnedPasswords.RANGE_URL)

    /** A stubbed range API: answers each prefix after [delayMs], records every URL and the most requests in flight. */
    private class StubNet(private val delayMs: () -> Long = { 0 }, var answer: (String) -> Any) {
        val urls: MutableList<String> = Collections.synchronizedList(mutableListOf())
        private val inFlight = AtomicInteger()
        val most = AtomicInteger()
        val prefixes get() = urls.map { it.removePrefix(PwnedPasswords.RANGE_URL) }

        val fetch: suspend (String) -> RangeAnswer = { url ->
            urls += url
            most.accumulateAndGet(inFlight.incrementAndGet(), ::maxOf)
            try {
                val wait = delayMs()
                if (wait > 0) delay(wait)
                when (val reply = answer(url.removePrefix(PwnedPasswords.RANGE_URL))) {
                    is String -> RangeAnswer(200, reply)
                    is RangeAnswer -> reply
                    is Throwable -> throw reply
                    else -> error("unexpected reply $reply")
                }
            } finally {
                inFlight.decrementAndGet()
            }
        }
    }

    private fun failure(block: suspend () -> Unit): BreachCheckException = runBlocking {
        try {
            block()
            fail("Expected the check to fail")
            error("unreachable")
        } catch (e: BreachCheckException) {
            e
        }
    }

    // ------------------------------------------------------------------ weak

    @Test
    fun oneThresholdOf50Bits() {
        assertEquals(50.0, PasswordHealth.WEAK_BITS, 0.0)
        assertEquals(MasterPasswordRules.WEAK_BITS, PasswordHealth.WEAK_BITS, 0.0)
        assertTrue(PasswordHealth.isWeak("short") { 49.99 })
        assertFalse(PasswordHealth.isWeak("longer") { 50.0 })
        assertFalse(PasswordHealth.isWeak("longest") { 80.0 })
    }

    @Test
    fun emptyPasswordIsNeverWeak() {
        var asked = false
        assertFalse(PasswordHealth.isWeak("") { asked = true; 0.0 })
        assertFalse(asked)
    }

    @Test
    fun reportsLoginsBelowTheThreshold() {
        val weak = login("abc")
        val edge = login("edge")
        val strong = login("strong")
        val report = analyze(listOf(weak, edge, strong), bitsFrom(mapOf("abc" to 15.0, "edge" to PasswordHealth.WEAK_BITS, "strong" to 90.0)))
        assertEquals(listOf(weak), report.weak)
        assertEquals(listOf(weak, edge, strong), report.logins)
    }

    // ------------------------------------------------------------------ reuse

    @Test
    fun groupsIdenticalPasswordsLargestFirst() {
        val a1 = login("same-a")
        val b1 = login("same-b")
        val a2 = login("same-a")
        val b2 = login("same-b")
        val a3 = login("same-a")
        val alone = login("only-once")
        val report = analyze(listOf(a1, b1, a2, b2, a3, alone), bitsFrom(emptyMap()))
        assertEquals(listOf(listOf(a1, a2, a3), listOf(b1, b2)), report.reused)
        assertEquals(2, report.reuseCount[a1.id])
        assertEquals(1, report.reuseCount[b2.id])
        assertNull(report.reuseCount[alone.id])
    }

    @Test
    fun groupsOfTheSameSizeKeepVaultOrder() {
        val c1 = login("c")
        val d1 = login("d")
        val c2 = login("c")
        val d2 = login("d")
        assertEquals(listOf(listOf(c1, c2), listOf(d1, d2)), analyze(listOf(c1, d1, c2, d2), bitsFrom(emptyMap())).reused)
    }

    @Test
    fun comparesPasswordsExactly() {
        val report = analyze(listOf(login("Secret"), login("secret"), login("secret "), login(" secret"), login("caf\u00E9"), login("cafe\u0301")), bitsFrom(emptyMap()))
        assertTrue(report.reused.isEmpty())
    }

    @Test
    fun skipsEmptyPasswordsTrashAndOtherItems() {
        val empty1 = login("")
        val empty2 = login("")
        val kept = login("shared-password")
        val trashed = login("shared-password", trashed = true)
        val note = login(null)
        val report = analyze(listOf(empty1, empty2, kept, trashed, note), bitsFrom(mapOf("" to 0.0)))
        assertTrue(report.reused.isEmpty())
        assertEquals(listOf(kept), report.logins)
        assertTrue(report.weak.isEmpty())
        assertTrue(analyze(listOf(login("abc", trashed = true)), bitsFrom(mapOf("abc" to 10.0))).weak.isEmpty())
    }

    @Test
    fun vaultEntriesWithoutALoginAreLeftOut() {
        fun entry(id: String, item: Item) = Entry(id, item, "v1", 1, EncryptedItem(id, "v1", "", ""))
        val a = entry("a", Item(name = "A", login = Login(password = "pw")))
        val b = entry("b", Item(name = "B", login = Login(password = "pw")))
        val note = entry("n", Item(name = "Note", notes = "pw"))
        val report = PasswordHealth.analyze(listOf(a, note, b)) { 10.0 }
        assertEquals(listOf("a", "b"), report.logins.map { it.id })
        assertEquals(listOf("a", "b"), report.weak.map { it.id })
        assertEquals(mapOf("a" to 1, "b" to 1), report.reuseCount)
    }

    // ------------------------------------------------------------------ ranges

    @Test
    fun readsSuffixCountLinesAndLeavesPaddingOut() {
        val body = (listOf("0018A45C4D1DEF81644B54AB7F969B88D65:1", "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2") + padding(3)).joinToString("\r\n")
        assertEquals(mapOf("0018A45C4D1DEF81644B54AB7F969B88D65" to 1, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC" to 2), PwnedPasswords.parseRange(body))
    }

    @Test
    fun acceptsLowercaseHexPlainNewlinesAndBlankLines() {
        assertEquals(12, PwnedPasswords.parseRange("\n0018a45c4d1def81644b54ab7f969b88d65:12\n\n")?.get("0018A45C4D1DEF81644B54AB7F969B88D65"))
        // A byte order mark and spaces around a line, as JavaScript's trim() removes them.
        assertEquals(3, PwnedPasswords.parseRange("\uFEFF0018A45C4D1DEF81644B54AB7F969B88D65:3 \r\n")?.get("0018A45C4D1DEF81644B54AB7F969B88D65"))
    }

    @Test
    fun ignoresLinesOfTheWrongShape() {
        val range = PwnedPasswords.parseRange(
            listOf(
                "SHORT:1",
                "0018A45C4D1DEF81644B54AB7F969B88D65",
                "ZZ18A45C4D1DEF81644B54AB7F969B88D65:3",
                "0018A45C4D1DEF81644B54AB7F969B88D65:",
                "0018A45C4D1DEF81644B54AB7F969B88D65:1:2",
                "0018A45C4D1DEF81644B54AB7F969B88D65 :5",
                "0018A45C4D1DEF81644B54AB7F969B88D65:-5",
                "0018A45C4D1DEF81644B54AB7F969B88D65A:5",
                "0018A45C4D1DEF81644B54AB7F969B88D65:\u0663",
                "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:4",
            ).joinToString("\n"),
        )
        assertEquals(setOf("00D4F6E8FA6EECAD2A3AA415EEC418D38EC"), range?.keys)
    }

    @Test
    fun keepsTheLargestCountAndHugeCounts() {
        val range = PwnedPasswords.parseRange(
            listOf(
                "0018A45C4D1DEF81644B54AB7F969B88D65:2", "0018a45c4d1def81644b54ab7f969b88d65:9", "0018A45C4D1DEF81644B54AB7F969B88D65:0",
                "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:99999999999999999999999999",
            ).joinToString("\r\n"),
        )
        assertEquals(9, range?.get("0018A45C4D1DEF81644B54AB7F969B88D65"))
        assertEquals(Int.MAX_VALUE, range?.get("00D4F6E8FA6EECAD2A3AA415EEC418D38EC"))
    }

    @Test
    fun anAnswerWithoutARangeLineIsNoAnswer() {
        assertNull(PwnedPasswords.parseRange("<!doctype html><title>Sign in to this network</title>"))
        assertNull(PwnedPasswords.parseRange(""))
        assertNull(PwnedPasswords.parseRange("{\"error\":\"rate limited\"}"))
        // Only padding is still a real answer: nothing found.
        assertEquals(0, PwnedPasswords.parseRange(padding(2).joinToString("\r\n"))?.size)
    }

    // ------------------------------------------------------------------ breach check

    @Test
    fun hashesWithSha1() {
        assertEquals("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", PwnedPasswords.sha1Hex("password"))
        assertEquals("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", PwnedPasswords.sha1Hex(""))
        assertTrue(Regex("^[0-9A-F]{40}$").matches(PwnedPasswords.sha1Hex("pässwörd")))
        assertFalse(PwnedPasswords.sha1Hex("caf\u00E9") == PwnedPasswords.sha1Hex("cafe\u0301"))
    }

    @Test
    fun sendsOnlyTheFirst5CharactersAndMatchesTheSuffix() = runBlocking {
        val suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        val net = StubNet { (padding(5) + "$suffix:3861" + padding(5, 1)).joinToString("\r\n") }
        val result = BreachChecker(net.fetch).check(listOf("password"))
        assertEquals(3861, result["password"])
        assertEquals(listOf("${PwnedPasswords.RANGE_URL}5BAA6"), net.urls)
        assertFalse(net.urls.single().contains(suffix))
    }

    @Test
    fun theRequestIsPlainAndPadded() {
        val r = PwnedPasswords.request("${PwnedPasswords.RANGE_URL}5BAA6")
        assertEquals("GET", r.method)
        assertNull(r.body)
        assertEquals("true", r.header("Add-Padding"))
        assertNull(r.header("Authorization"))
        assertNull(r.header(CLIENT_HEADER))
        assertNull(r.header("Cookie"))
        assertEquals("https://api.pwnedpasswords.com/range/5BAA6", r.url.toString())
    }

    @Test
    fun theClientDropsTheServerClientsCookiesCacheAndInterceptors() {
        val base = OkHttpClient.Builder()
            .addInterceptor(Interceptor { it.proceed(it.request().newBuilder().header(CLIENT_HEADER, "android/test").build()) })
            .addNetworkInterceptor(Interceptor { it.proceed(it.request()) })
            .followRedirects(false)
            .build()
        val client = PwnedPasswords.client(base)
        assertTrue(client.interceptors.isEmpty())
        assertTrue(client.networkInterceptors.isEmpty())
        assertEquals(okhttp3.CookieJar.NO_COOKIES, client.cookieJar)
        assertNull(client.cache)
        assertEquals(PwnedPasswords.TIMEOUT_MS.toInt(), client.callTimeoutMillis)
        assertFalse(client.followSslRedirects)
        // The server client itself is unchanged.
        assertEquals(1, base.interceptors.size)
    }

    /** The real fetcher against a local server: the request as it is sent. */
    @Test
    fun fetcherSendsNoCookiesTokensOrClientHeader() = runBlocking {
        val server = ServerSocket(0)
        val received = Collections.synchronizedList(mutableListOf<String>())
        val body = (padding(3) + "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42").joinToString("\r\n")
        val worker = thread {
            server.accept().use { socket ->
                val input = socket.getInputStream().bufferedReader()
                while (true) {
                    val line = input.readLine() ?: break
                    if (line.isEmpty()) break
                    received += line
                }
                val bytes = body.toByteArray()
                socket.getOutputStream().apply {
                    write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${bytes.size}\r\nSet-Cookie: track=1\r\nConnection: close\r\n\r\n".toByteArray())
                    write(bytes)
                    flush()
                }
            }
        }
        try {
            val client = PwnedPasswords.client(OkHttpClient.Builder().callTimeout(5, TimeUnit.SECONDS).build())
            val answer = PwnedPasswords.fetcher(client)("http://127.0.0.1:${server.localPort}/range/5BAA6")
            assertEquals(200, answer.status)
            assertEquals(42, PwnedPasswords.parseRange(answer.body)?.get("1E4C9B93F3F0682250B6CF8331B7EE68FD8"))
        } finally {
            worker.join(5_000)
            server.close()
        }
        assertEquals("GET /range/5BAA6 HTTP/1.1", received.first())
        val headers = received.drop(1).associate { it.substringBefore(':').trim().lowercase() to it.substringAfter(':').trim() }
        assertEquals("true", headers["add-padding"])
        assertNull(headers["cookie"])
        assertNull(headers["authorization"])
        assertNull(headers[CLIENT_HEADER.lowercase()])
    }

    @Test
    fun reports0ForMissingAndPaddedPasswords() = runBlocking {
        val digest = digestFrom(mapOf("listed" to hash("ABCDE", "1"), "padded" to hash("ABCDE", "2"), "missing" to hash("ABCDE", "3")))
        val net = StubNet { (listOf("${"1".repeat(35)}:7", "${"2".repeat(35)}:0") + padding(3)).joinToString("\r\n") }
        val result = BreachChecker(net.fetch, digest = digest).check(listOf("listed", "padded", "missing"))
        assertEquals(mapOf("listed" to 7, "padded" to 0, "missing" to 0), result)
    }

    @Test
    fun requestsEachPrefixOnceAndKeepsAnswersUntilCleared() = runBlocking {
        val digest = digestFrom(mapOf("one" to hash("AAAAA", "1"), "two" to hash("AAAAA", "2"), "three" to hash("BBBBB", "3")))
        val net = StubNet { prefix -> if (prefix == "AAAAA") "${"2".repeat(35)}:5" else padding(4).joinToString("\r\n") }
        val checker = BreachChecker(net.fetch, digest = digest)

        val first = checker.check(listOf("one", "two", "", "three", "one", "two"))
        assertEquals(listOf("AAAAA", "BBBBB"), net.prefixes.sorted())
        assertEquals(mapOf("one" to 0, "two" to 5, "three" to 0), first)

        val again = checker.check(listOf("two", "three"))
        assertEquals(2, net.urls.size)
        assertEquals(mapOf("two" to 5, "three" to 0), again)

        checker.clear()
        checker.check(listOf("three"))
        assertEquals(3, net.urls.size)
        assertEquals("BBBBB", net.prefixes.last())
    }

    @Test
    fun checksNothingWithoutPasswords() = runBlocking {
        val net = StubNet { "" }
        val progress = mutableListOf<Pair<Int, Int>>()
        val result = BreachChecker(net.fetch).check(listOf("", "")) { d, t -> progress += d to t }
        assertTrue(result.isEmpty())
        assertTrue(net.urls.isEmpty())
        assertEquals(listOf(0 to 0), progress)
    }

    @Test
    fun runsAtMost6RequestsAtATime() = runBlocking {
        val table = (0 until 40).associate { "p$it" to hash("%05X".format(it), "C") }
        val net = StubNet(delayMs = { (1L..4L).random() }) { padding(3).joinToString("\r\n") }
        val checker = BreachChecker(net.fetch, digest = digestFrom(table))
        val names = table.keys.toList()
        // Two overlapping checks share the same limit.
        listOf(async { checker.check(names.take(25)) }, async { checker.check(names.drop(25)) }).awaitAll()
        assertEquals(6, PwnedPasswords.PARALLEL)
        assertEquals(PwnedPasswords.PARALLEL, net.most.get())
        assertEquals(40, net.prefixes.toSet().size)
        assertEquals(40, net.urls.size)
    }

    @Test
    fun honoursALowerLimit() = runBlocking {
        val table = (0 until 8).associate { "p$it" to hash("0000$it", "D") }
        val net = StubNet(delayMs = { 2 }) { padding(1).joinToString("\n") }
        BreachChecker(net.fetch, parallel = 2, digest = digestFrom(table)).check(table.keys)
        assertEquals(2, net.most.get())
        assertEquals(8, net.urls.size)
    }

    @Test
    fun reportsProgressInDistinctPasswords() = runBlocking {
        val digest = digestFrom(mapOf("a" to hash("11111", "1"), "b" to hash("11111", "2"), "c" to hash("22222", "3")))
        val net = StubNet { padding(2).joinToString("\r\n") }
        val progress = mutableListOf<Pair<Int, Int>>()
        BreachChecker(net.fetch, digest = digest).check(listOf("a", "b", "c", "a")) { d, t -> progress += d to t }
        assertEquals(0 to 3, progress.first())
        assertEquals(3 to 3, progress.last())
        assertEquals(progress.map { it.first }.sorted(), progress.map { it.first })
    }

    @Test
    fun failsWithTheHttpStatusAndDoesntKeepTheFailedPrefix() {
        val net = StubNet { RangeAnswer(503, "busy") }
        val checker = BreachChecker(net.fetch)
        val e = failure { checker.check(listOf("password")) }
        assertEquals(BreachCheckException.Reason.Http, e.reason)
        assertEquals(503, e.status)

        net.answer = { padding(2).joinToString("\r\n") }
        assertEquals(0, runBlocking { checker.check(listOf("password")) }["password"])
        assertEquals(2, net.urls.size)
    }

    @Test
    fun noAnswerIsANetworkFailure() {
        val io = failure { BreachChecker(StubNet { IOException("connection refused") }.fetch).check(listOf("password")) }
        assertEquals(BreachCheckException.Reason.Network, io.reason)
        assertTrue(io.cause is IOException)
        val other = failure { BreachChecker(StubNet { IllegalStateException("broken") }.fetch).check(listOf("password")) }
        assertEquals(BreachCheckException.Reason.Network, other.reason)
        val okHttpTimeout = failure { BreachChecker(StubNet { java.io.InterruptedIOException("timeout") }.fetch).check(listOf("password")) }
        assertEquals(BreachCheckException.Reason.Timeout, okHttpTimeout.reason)
    }

    @Test
    fun anAnswerThatIsntARangeListIsInvalid() {
        val e = failure { BreachChecker(StubNet { "<html>Sign in to continue</html>" }.fetch).check(listOf("password")) }
        assertEquals(BreachCheckException.Reason.Invalid, e.reason)
    }

    @Test
    fun givesUpOnARequestAfterTheTimeout() {
        val started = System.nanoTime()
        val e = failure { BreachChecker(StubNet(delayMs = { 30_000 }) { "" }.fetch, timeoutMs = 20).check(listOf("password")) }
        assertEquals(BreachCheckException.Reason.Timeout, e.reason)
        assertTrue(System.nanoTime() - started < 5_000_000_000)
    }

    @Test
    fun skipsTheRemainingRequestsAfterTheFirstFailure() {
        val table = (0 until 6).associate { "p$it" to hash("9999$it", "E") }
        val net = StubNet(delayMs = { 1 }) { RangeAnswer(429, "") }
        val e = failure { BreachChecker(net.fetch, parallel = 1, digest = digestFrom(table)).check(table.keys) }
        assertEquals(BreachCheckException.Reason.Http, e.reason)
        assertEquals(429, e.status)
        Thread.sleep(20)
        assertEquals(1, net.urls.size)
    }

    @Test
    fun clearStopsARunningCheck() = runBlocking {
        val table = (0 until 12).associate { "p$it" to hash("7%04X".format(it), "F") }
        val net = StubNet(delayMs = { 200 }) { padding(1).joinToString("\n") }
        val checker = BreachChecker(net.fetch, digest = digestFrom(table))
        val running = async { runCatching { checker.check(table.keys) } }
        while (net.urls.size < PwnedPasswords.PARALLEL) delay(5)
        checker.clear()
        val outcome = withTimeout(1_000) { running.await() }
        assertEquals(BreachCheckException.Reason.Stopped, (outcome.exceptionOrNull() as? BreachCheckException)?.reason)
        delay(250)
        // Only the first slots were ever sent; the queued prefixes never went out.
        assertEquals(PwnedPasswords.PARALLEL, net.urls.size)
    }

    // ------------------------------------------------------------------ wording

    @Test
    fun failureMessages() {
        assertEquals("Have I Been Pwned is busy. Wait a minute, then try again.", HealthText.explain(BreachCheckException(BreachCheckException.Reason.Http, 429)))
        assertEquals("Have I Been Pwned couldn't answer (error 503). Try again later.", HealthText.explain(BreachCheckException(BreachCheckException.Reason.Http, 503)))
        assertEquals(HealthText.UNREACHABLE, HealthText.explain(BreachCheckException(BreachCheckException.Reason.Network)))
        assertEquals(HealthText.TIMEOUT, HealthText.explain(BreachCheckException(BreachCheckException.Reason.Timeout)))
        assertEquals(HealthText.INVALID, HealthText.explain(BreachCheckException(BreachCheckException.Reason.Invalid)))
        assertEquals("The check stopped. Try again.", HealthText.explain(BreachCheckException(BreachCheckException.Reason.Stopped)))
        assertEquals("The check stopped. Try again.", HealthText.explain(IllegalStateException()))
        assertEquals("This server doesn't allow checking passwords against Have I Been Pwned.", HealthText.NOT_ALLOWED)
    }

    @Test
    fun notesAndAnnouncements() {
        assertEquals("Used in 1 other login", HealthText.usedIn(1))
        assertEquals("Used in 2 other logins", HealthText.usedIn(2))
        assertEquals("Seen 1 time", HealthText.timesSeen(1))
        assertEquals("Seen 12 times", HealthText.timesSeen(12))
        assertEquals("Starting the check.", HealthText.progress(0, 0))
        assertEquals("Checking 10 passwords, 0% done.", HealthText.progress(0, 10))
        assertEquals("Checking 10 passwords, 25% done.", HealthText.progress(3, 10))
        assertEquals("Checking 10 passwords, 50% done.", HealthText.progress(7, 10))
        assertEquals("Checking 10 passwords, 100% done.", HealthText.progress(10, 10))
        assertEquals("Checking 1 password, 100% done.", HealthText.progress(1, 1))
        assertEquals("Check finished. No exposed passwords found.", HealthText.finished(0))
        assertEquals("Check finished. 1 login uses a password found in data breaches.", HealthText.finished(1))
        assertEquals("Check finished. 3 logins use passwords found in data breaches.", HealthText.finished(3))
    }

    // ------------------------------------------------------------------ session

    /** The repository's side: the vault, the server's features, and closing the vault. */
    private class FakeSource(var features: List<String>?) : HealthSource {
        override val vault = MutableStateFlow<VaultData?>(null)
        var asked = 0
        override suspend fun serverFeatures(): List<String>? {
            asked++
            return features
        }

        override var onVaultClosed: (() -> Unit)? = null

        fun close() {
            vault.value = null
            onVaultClosed?.invoke()
        }
    }

    private fun vaultOf(vararg logins: Pair<String, String>): VaultData {
        val entries = logins.map { (id, password) -> Entry(id, Item(name = id, login = Login(password = password)), "v1", 1, EncryptedItem(id, "v1", "", "")) }
        return VaultData(entries, listOf(VaultInfo("v1", "Personal", Role.Owner)))
    }

    private val weakTable = mapOf("password" to 30.0)

    private suspend fun HealthSession.settled(): HealthSession.State =
        withTimeout(5_000) { state.first { it.status != HealthSession.Status.Checking } }

    @Test
    fun sessionFindsBreachedPasswordsAndClosingTheVaultDropsEverything() = runBlocking {
        val source = FakeSource(listOf("delta_sync", PasswordHealth.BREACH_CHECK_FEATURE))
        source.vault.value = vaultOf("shop" to "password", "mail" to "password", "bank" to "cT7#qLm2!vXr9\$Wz4@Hs")
        val net = StubNet { prefix -> if (prefix == "5BAA6") "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861" else "${"F".repeat(35)}:0" }
        val health = HealthSession(source, BreachChecker(net.fetch), this, bits = bitsFrom(weakTable))
        val report = health.report(source.vault.value!!)
        assertEquals(3, report.logins.size)
        assertEquals(listOf(2), report.reused.map { it.size })
        assertEquals(listOf("shop", "mail"), report.weak.map { it.id })
        assertTrue(report === health.report(source.vault.value!!.copy(offline = true)))

        health.check()
        val done = health.settled()
        assertEquals(HealthSession.Status.Done, done.status)
        assertEquals(HealthSession.Availability.On, done.availability)
        assertEquals(3861, done.results?.get("password"))
        assertEquals(0, done.results?.get("cT7#qLm2!vXr9\$Wz4@Hs"))
        assertNotNull(done.checkedAt)
        assertEquals(2, net.urls.size)

        source.close()
        assertEquals(HealthSession.State(), health.state.value)
        assertNull(health.state.value.results)
    }

    @Test
    fun serverWithoutTheFeatureSendsNothing() = runBlocking {
        val source = FakeSource(listOf("delta_sync"))
        source.vault.value = vaultOf("shop" to "password")
        val net = StubNet { "" }
        val health = HealthSession(source, BreachChecker(net.fetch), this, bits = bitsFrom(weakTable))
        health.loadAvailability()
        assertEquals(HealthSession.Availability.Off, health.state.value.availability)
        // Asked again at the check: the admin may have switched it off since the page opened.
        health.check()
        val after = health.settled()
        assertEquals(HealthSession.Status.Idle, after.status)
        assertEquals(HealthSession.Availability.Off, after.availability)
        assertNull(after.error)
        assertNull(after.results)
        assertEquals(2, source.asked)
        assertTrue(net.urls.isEmpty())
    }

    @Test
    fun unreadableSettingsSayWhy() = runBlocking {
        val source = FakeSource(null)
        source.vault.value = vaultOf("shop" to "password")
        val net = StubNet { "" }
        val health = HealthSession(source, BreachChecker(net.fetch), this, bits = bitsFrom(weakTable))
        health.loadAvailability()
        assertEquals(HealthSession.Availability.Unknown, health.state.value.availability)
        health.check()
        assertEquals(HealthText.NO_CONFIG, health.settled().error)
        assertTrue(net.urls.isEmpty())
    }

    @Test
    fun closingTheVaultDuringACheckStopsIt() = runBlocking {
        val source = FakeSource(listOf(PasswordHealth.BREACH_CHECK_FEATURE))
        source.vault.value = vaultOf("shop" to "password", "bank" to "other")
        val net = StubNet(delayMs = { 5_000 }) { "${"F".repeat(35)}:0" }
        val health = HealthSession(source, BreachChecker(net.fetch), this, bits = bitsFrom(weakTable))
        health.check()
        withTimeout(2_000) { while (net.urls.isEmpty()) delay(5) }
        assertEquals(HealthSession.Status.Checking, health.state.value.status)
        source.close()
        assertEquals(HealthSession.Status.Idle, health.state.value.status)
        delay(100)
        // The stopped check comes back neither as a failure nor as a result.
        assertEquals(HealthSession.State(), health.state.value)
    }

    @Test
    fun onlyOneCheckAtATime() = runBlocking {
        val source = FakeSource(listOf(PasswordHealth.BREACH_CHECK_FEATURE))
        source.vault.value = vaultOf("shop" to "password")
        val net = StubNet(delayMs = { 50 }) { "${"F".repeat(35)}:0" }
        val health = HealthSession(source, BreachChecker(net.fetch), this, bits = bitsFrom(weakTable))
        health.check()
        health.check()
        assertEquals(HealthSession.Status.Done, health.settled().status)
        assertEquals(1, source.asked)
        assertEquals(1, net.urls.size)
    }
}
