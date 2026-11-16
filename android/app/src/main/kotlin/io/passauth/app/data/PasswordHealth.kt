package io.passauth.app.data

import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.job
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.OkHttpClient
import okhttp3.Request

/*
 * Password health (Settings → Password health and the notes on an item's page): weak, reused and
 * exposed passwords among the logins the user can read. The web vault's `web/src/lib/health.ts`,
 * with the same rules, threshold, limits and wording; iOS: `ios/Shared/PasswordHealth.swift`.
 * Pure: callers pass the strength estimate (the core's `estimateBits`) and the network
 * ([PwnedPasswords.fetcher]). Decrypted passwords stay in memory: reuse is found by comparing them
 * in place, and the breach check sends only the first 5 hex characters of each password's SHA-1
 * hash to Have I Been Pwned's range API (k-anonymity, padded answers), never a full hash or a password.
 */

object PasswordHealth {
    /**
     * Bits, as estimated by the core's `estimateBits`, below which a password is weak ("easy to
     * guess"): the one threshold of the strength meter, the master password checks, the generator
     * and password health, as in the web vault (`WEAK_BITS`), the extension and iOS.
     */
    const val WEAK_BITS = MasterPasswordRules.WEAK_BITS

    /** The `/api/config` feature of servers whose admin allows the breach check. */
    const val BREACH_CHECK_FEATURE = "breach_check"

    /** Weak: set, and estimated below [WEAK_BITS]. */
    fun isWeak(password: String, estimateBits: (String) -> Double): Boolean =
        password.isNotEmpty() && estimateBits(password) < WEAK_BITS

    /**
     * Weak and reused passwords among [entries] (every vault the user can read). Items in the
     * trash, items that aren't logins ([password] null) and logins without a password are left
     * out. Passwords are compared exactly as they are, in memory.
     */
    fun <T> analyze(
        entries: List<T>,
        estimateBits: (String) -> Double,
        id: (T) -> String,
        password: (T) -> String?,
        trashed: (T) -> Boolean = { false },
    ): HealthReport<T> {
        val logins = mutableListOf<T>()
        val weak = mutableListOf<T>()
        val byPassword = LinkedHashMap<String, MutableList<T>>()
        for (e in entries) {
            val p = password(e)
            if (trashed(e) || p.isNullOrEmpty()) continue
            logins += e
            if (isWeak(p, estimateBits)) weak += e
            byPassword.getOrPut(p) { mutableListOf() } += e
        }
        // Largest first (a stable sort: groups of the same size stay in vault order).
        val reused = byPassword.values.filter { it.size > 1 }.sortedByDescending { it.size }
        val reuseCount = HashMap<String, Int>()
        for (group in reused) for (e in group) reuseCount[id(e)] = group.size - 1
        return HealthReport(logins, weak, reused, reuseCount)
    }

    /** The report for the active account's vault (its entries are never in the trash). */
    fun analyze(entries: List<Entry>, estimateBits: (String) -> Double): HealthReport<Entry> =
        analyze(entries, estimateBits, { it.id }, { it.item.login?.password })
}

/** Weak and reused passwords among the logins of every vault the user can read. */
class HealthReport<T>(
    /** Logins with a password that aren't in the trash: everything the report covers, in vault order. */
    val logins: List<T>,
    /** Logins whose password is weak. */
    val weak: List<T>,
    /** Logins that share one password, in groups of 2 or more, the largest group first. */
    val reused: List<List<T>>,
    /** For each login in [reused] (by id): how many other logins use the same password. */
    val reuseCount: Map<String, Int>,
)

/** Have I Been Pwned's Pwned Passwords range API. */
object PwnedPasswords {
    const val ORIGIN = "https://api.pwnedpasswords.com"

    /** GET this + the first 5 hex characters (uppercase) of a password's SHA-1 hash. */
    const val RANGE_URL = "$ORIGIN/range/"

    /** Range requests running at the same time, at most. */
    const val PARALLEL = 6

    /** Per request, from when it is sent until its answer has been read. */
    const val TIMEOUT_MS = 15_000L

    /**
     * One range request: padded answers (800 to 1,000 lines, so their size says nothing about the
     * prefix). Built here, never with [serverRequest]: no `X-PassAuth-Client`, no tokens.
     */
    fun request(url: String): Request = Request.Builder().url(url).header("Add-Padding", "true").get().build()

    /**
     * The breach check's client: [base]'s connections and settings without its cookie jar, cache,
     * authenticators or interceptors, and the request timeout.
     */
    fun client(base: OkHttpClient): OkHttpClient = base.newBuilder()
        .apply {
            interceptors().clear()
            networkInterceptors().clear()
        }
        .cookieJar(CookieJar.NO_COOKIES)
        .cache(null)
        .authenticator(Authenticator.NONE)
        .followRedirects(true)
        .followSslRedirects(false)
        .callTimeout(TIMEOUT_MS, TimeUnit.MILLISECONDS)
        .build()

    /** Sends range requests with [client]. */
    fun fetcher(client: OkHttpClient): suspend (String) -> RangeAnswer = { url ->
        client.newCall(request(url)).await().use { r -> RangeAnswer(r.code, withContext(Dispatchers.IO) { r.body.string() }) }
    }

    /** Uppercase hex SHA-1 of the text's UTF-8 bytes. */
    fun sha1Hex(text: String): String {
        val digits = "0123456789ABCDEF"
        val out = StringBuilder(40)
        for (b in MessageDigest.getInstance("SHA-1").digest(text.toByteArray(Charsets.UTF_8))) {
            val v = b.toInt() and 0xFF
            out.append(digits[v ushr 4]).append(digits[v and 0x0F])
        }
        return out.toString()
    }

    private val RANGE_LINE = Regex("^([0-9A-F]{35}):(\\d+)$")

    /**
     * A range answer (`SUFFIX:COUNT` lines): hash suffix → times seen. Padding lines (count 0) are
     * left out. Null when no line has that shape, so a page that isn't a range answer (a network's
     * sign-in page) never reads as "not found".
     */
    fun parseRange(body: String): Map<String, Int>? {
        val seen = HashMap<String, Int>()
        var lines = 0
        for (line in body.split('\n')) {
            // As JavaScript's trim(): white space, line breaks and the byte order mark.
            val m = RANGE_LINE.matchEntire(line.trim { it.isWhitespace() || it == '\uFEFF' }.uppercase()) ?: continue
            lines++
            // Only digits: a count too large for Int is still "seen".
            val count = m.groupValues[2].toIntOrNull() ?: Int.MAX_VALUE
            if (count > 0) seen[m.groupValues[1]] = maxOf(count, seen[m.groupValues[1]] ?: 0)
        }
        return if (lines > 0) seen else null
    }
}

/** An answer from the range API (or a stub in tests). */
data class RangeAnswer(val status: Int, val body: String)

/** Why a breach check stopped; [status] for [Reason.Http]. */
class BreachCheckException(val reason: Reason, val status: Int? = null, cause: Throwable? = null) :
    Exception(if (status != null) "$reason (HTTP $status)" else reason.name, cause) {
    enum class Reason {
        /** No answer at all (offline, DNS, TLS, a blocking VPN). */
        Network,

        /** No answer within [PwnedPasswords.TIMEOUT_MS]. */
        Timeout,

        /** An answer with an HTTP error status (429: rate limited). */
        Http,

        /** An answer that isn't a range list (e.g. a network's sign-in page). */
        Invalid,

        /** [BreachChecker.clear] (the vault locked or signed out). */
        Stopped,
    }
}

/**
 * Checks passwords against Have I Been Pwned through [fetch] ([PwnedPasswords.fetcher], or a stub
 * in tests; it gets the full range URL). Answers per prefix are kept (in memory) for later checks
 * until [clear]. Thread-safe.
 */
class BreachChecker(
    private val fetch: suspend (url: String) -> RangeAnswer,
    parallel: Int = PwnedPasswords.PARALLEL,
    private val timeoutMs: Long = PwnedPasswords.TIMEOUT_MS,
    private val digest: (String) -> String = PwnedPasswords::sha1Hex,
) {
    /** Requests at the same time, at most, across checks; a finished one hands its slot to the next. */
    private val slots = Semaphore(parallel.coerceAtLeast(1))
    private val lock = Any()

    /** Answers per prefix: hash suffix → times seen. */
    private var ranges = HashMap<String, Map<String, Int>>()

    /** Bumped by [clear]: work started before it is dropped. */
    private var generation = 0
    private val checks = HashSet<Job>()

    private class Run(val distinct: List<String>, val hashes: List<String>, val onProgress: ((Int, Int) -> Unit)?) {
        val failed = AtomicBoolean(false)
        val done = AtomicInteger(0)
        val seen = ConcurrentHashMap<String, Int>()
    }

    private fun stopped(gen: Int) = synchronized(lock) { gen != generation }

    /**
     * How often each distinct, non-empty password appears in known data breaches (0: not found).
     * Passwords that share a prefix share one request, kept answers are reused, and at most
     * `parallel` requests run at a time. [onProgress] counts distinct passwords. The first failed
     * request fails the check with its [BreachCheckException]; the check's requests that haven't
     * started yet are then skipped. [clear] stops it with [BreachCheckException.Reason.Stopped].
     */
    suspend fun check(passwords: Iterable<String>, onProgress: ((done: Int, total: Int) -> Unit)? = null): Map<String, Int> {
        val gen = synchronized(lock) { generation }
        return try {
            coroutineScope {
                val job = coroutineContext.job
                synchronized(lock) {
                    if (gen != generation) throw BreachCheckException(BreachCheckException.Reason.Stopped)
                    checks += job
                }
                try {
                    run(passwords, gen, onProgress)
                } finally {
                    synchronized(lock) { checks -= job }
                }
            }
        } catch (e: CancellationException) {
            // Cancelled by clear(): a stopped check. Otherwise the caller itself was cancelled.
            if (stopped(gen)) throw BreachCheckException(BreachCheckException.Reason.Stopped)
            throw e
        }
    }

    /** Stop every check in progress (each fails with Stopped) and forget the kept answers. */
    fun clear() {
        val running = synchronized(lock) {
            generation++
            ranges = HashMap()
            checks.toList()
        }
        running.forEach { it.cancel(CancellationException("The breach check was stopped.")) }
    }

    private suspend fun run(passwords: Iterable<String>, gen: Int, onProgress: ((Int, Int) -> Unit)?): Map<String, Int> = coroutineScope {
        val distinct = LinkedHashSet<String>().apply { for (p in passwords) if (p.isNotEmpty()) add(p) }.toList()
        val hashes = withContext(Dispatchers.Default) { distinct.map { digest(it).uppercase() } }
        if (stopped(gen)) throw BreachCheckException(BreachCheckException.Reason.Stopped)
        val byPrefix = LinkedHashMap<String, MutableList<Int>>()
        hashes.forEachIndexed { i, hash -> byPrefix.getOrPut(hash.take(5)) { mutableListOf() } += i }
        val run = Run(distinct, hashes, onProgress)
        onProgress?.invoke(0, distinct.size)
        byPrefix.map { (prefix, members) -> async { lookUp(prefix, members, gen, run) } }.awaitAll()
        HashMap(run.seen)
    }

    /** The passwords [members] (of `run.distinct`) that share [prefix]. */
    private suspend fun lookUp(prefix: String, members: List<Int>, gen: Int, run: Run) {
        val found = synchronized(lock) { if (gen == generation) ranges[prefix] else null } ?: request(prefix, gen, run)
        for (i in members) run.seen[run.distinct[i]] = found[run.hashes[i].substring(5)] ?: 0
        val done = run.done.addAndGet(members.size)
        if (!run.failed.get()) run.onProgress?.invoke(done, run.distinct.size)
    }

    /** Waits for a free slot. Not sent when the checker was cleared or the check has already failed. */
    private suspend fun request(prefix: String, gen: Int, run: Run): Map<String, Int> = slots.withPermit {
        try {
            if (stopped(gen) || run.failed.get()) throw BreachCheckException(BreachCheckException.Reason.Stopped)
            val found = send(PwnedPasswords.RANGE_URL + prefix)
            synchronized(lock) { if (gen == generation) ranges[prefix] = found }
            found
        } catch (e: Throwable) {
            // Marked before the slot is handed on, so the check's next request already sees it.
            run.failed.set(true)
            throw e
        }
    }

    private suspend fun send(url: String): Map<String, Int> {
        val answer = try {
            withTimeoutOrNull(timeoutMs) { fetch(url) } ?: throw BreachCheckException(BreachCheckException.Reason.Timeout)
        } catch (e: CancellationException) {
            throw e
        } catch (e: BreachCheckException) {
            throw e
        } catch (e: java.io.InterruptedIOException) {
            // OkHttp's own call timeout.
            throw BreachCheckException(BreachCheckException.Reason.Timeout, cause = e)
        } catch (e: IOException) {
            throw BreachCheckException(BreachCheckException.Reason.Network, cause = e)
        } catch (e: Exception) {
            throw BreachCheckException(BreachCheckException.Reason.Network, cause = e)
        }
        if (answer.status !in 200..299) throw BreachCheckException(BreachCheckException.Reason.Http, answer.status)
        return withContext(Dispatchers.Default) { PwnedPasswords.parseRange(answer.body) }
            ?: throw BreachCheckException(BreachCheckException.Reason.Invalid)
    }
}

/** The web vault's wording for password health. */
object HealthText {
    const val NOT_ALLOWED = "This server doesn't allow checking passwords against Have I Been Pwned."
    const val NO_CONFIG = "Couldn't load your server's settings. Check your connection, then try again."
    const val UNAVAILABLE = "Couldn't load your server's settings, so the breach check isn't available right now. Check your connection, then try again."
    const val UNREACHABLE = "Couldn't reach Have I Been Pwned. Check your connection or VPN, then try again."
    const val TIMEOUT = "Have I Been Pwned didn't answer in time. Try again in a moment."
    const val BUSY = "Have I Been Pwned is busy. Wait a minute, then try again."
    const val INVALID = "The answer didn't come from Have I Been Pwned. If this network shows a sign-in page, sign in there first, then try again."
    const val STOPPED = "The check stopped. Try again."

    /** What the check sends, next to its button. */
    const val PRIVACY = "The first 5 characters of each password's SHA-1 hash go to Have I Been Pwned; your passwords never leave this device."

    /** Why a check stopped, in plain words. */
    fun explain(e: Throwable): String {
        if (e !is BreachCheckException) return STOPPED
        return when (e.reason) {
            BreachCheckException.Reason.Network -> UNREACHABLE
            BreachCheckException.Reason.Timeout -> TIMEOUT
            BreachCheckException.Reason.Http -> if (e.status == 429) BUSY else "Have I Been Pwned couldn't answer (error ${e.status}). Try again later."
            BreachCheckException.Reason.Invalid -> INVALID
            BreachCheckException.Reason.Stopped -> STOPPED
        }
    }

    /** "1 login", "2,048 logins". */
    fun count(n: Int, one: String, many: String) = "${java.text.NumberFormat.getIntegerInstance().format(n)} ${if (n == 1) one else many}"

    /** "Seen 3,861 times". */
    fun timesSeen(n: Int) = "Seen ${count(n, "time", "times")}"

    /** "Used in 2 other logins". */
    fun usedIn(others: Int) = "Used in $others other ${if (others == 1) "login" else "logins"}"

    /** Screen reader progress in steps of a quarter, not after every request. */
    fun progress(done: Int, total: Int): String =
        if (total <= 0) "Starting the check." else "Checking ${count(total, "password", "passwords")}, ${minOf(done * 4 / total, 4) * 25}% done."

    /** Read out when a check finishes. */
    fun finished(exposed: Int): String =
        if (exposed > 0) "Check finished. ${count(exposed, "login uses a password", "logins use passwords")} found in data breaches."
        else "Check finished. No exposed passwords found."
}
