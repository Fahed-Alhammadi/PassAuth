package io.passauth.app.data

import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/**
 * An error response from the server (`{ "error": code, "message": …, "request_id": … }`).
 * [retryAfter]: seconds to wait before trying again, from a 429's `Retry-After` (null when it
 * didn't say). [requestId]: the server's id for the request (it names it in the server's log),
 * shown as a reference with errors the app has no wording for ([ServerErrors]).
 */
class ApiException(
    val status: Int,
    val code: String,
    message: String,
    val retryAfter: Long? = null,
    val requestId: String? = null,
    /** The error answer's JSON body (its extra fields, e.g. `members_changed`'s lists); null when there was none. */
    val body: JsonObject? = null,
) : Exception(message) {
    /** The server (or a proxy in front of it) refused because of too many requests. */
    val isRateLimited: Boolean get() = status == 429 || code == "rate_limited"

    /**
     * Is this the server's [reason]? Servers since API v2 put it in `error`; older ones answer
     * some of them with a generic code and the reason as the message
     * (`{"error":"forbidden","message":"reauth_required"}`), or only with a message text
     * ([fallback], compared without case).
     */
    fun hasCode(reason: String, fallback: String? = null): Boolean =
        code == reason || message == reason || (fallback != null && message.orEmpty().equals(fallback, ignoreCase = true))
}

/**
 * "Too many attempts. Try again in 30 seconds." for a rate-limited request that said when to
 * retry (`Retry-After`), worded as the extension does; null otherwise (callers keep their own
 * text for a limit without a time).
 */
fun tooManyAttemptsMessage(e: ApiException): String? {
    val s = e.retryAfter?.takeIf { e.isRateLimited && it > 0 } ?: return null
    return "Too many attempts. Try again in ${waitText(s)}."
}

/** A wait in plain words, never shorter than the real one: "a moment" (a second), "45 seconds" (under a minute and a half), else whole minutes rounded up. */
fun waitText(seconds: Long): String = when {
    seconds <= 1 -> "a moment"
    seconds < 90 -> "$seconds seconds"
    else -> "${(seconds + 59) / 60} minutes"
}

/** Seconds from a `Retry-After` header: a number of seconds, or an HTTP date (RFC 9110); null if absent or unreadable. */
fun retryAfterSeconds(value: String?, nowMs: Long = System.currentTimeMillis()): Long? {
    val v = value?.trim()?.takeIf { it.isNotEmpty() } ?: return null
    if (v.all { it in '0'..'9' }) return v.toLongOrNull()
    val at = runCatching { java.time.ZonedDateTime.parse(v, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME) }.getOrNull() ?: return null
    val ms = at.toInstant().toEpochMilli() - nowMs
    return if (ms <= 0) 0 else (ms + 999) / 1000
}

/** Sent with every request to a PassAuth server (API v2): which app and version is asking. */
const val CLIENT_HEADER = "X-PassAuth-Client"

/** `android/<version>` (debug builds without their "-debug" suffix). */
val CLIENT_ID: String = "android/" + io.passauth.app.BuildConfig.VERSION_NAME.removeSuffix("-debug").ifEmpty { "0" }

/** A request to a PassAuth server, with [CLIENT_HEADER]. Never for other hosts (asset links). */
fun serverRequest(url: String): Request.Builder = Request.Builder().url(url).header(CLIENT_HEADER, CLIENT_ID)

/** A user-facing error from the app itself (shown as is). */
open class UserException(message: String) : Exception(message)

/** An item update was rejected because the item changed elsewhere (HTTP 409 on a revision check). */
class ConflictException : UserException("This item was changed on another device.")

/** Outcome of a refresh-token rotation. Only [Rejected] ends the session. */
enum class RefreshResult { Refreshed, Rejected, Unavailable }

/** Classifies a refresh response status: the server only rejects a refresh token with 400/401/403. */
fun refreshOutcome(status: Int): RefreshResult = when {
    status in 200..299 -> RefreshResult.Refreshed
    status == 400 || status == 401 || status == 403 -> RefreshResult.Rejected
    else -> RefreshResult.Unavailable
}

/**
 * HTTP client for PassAuth servers: bearer auth, refresh-token rotation on 401
 * and per-account pinning (a request always uses the server and tokens of the
 * account it was started for, even if the user switches accounts meanwhile).
 */
class ApiClient(private val store: SecureStore) {
    val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    /** Called when an account's session can't be refreshed (it is signed out). */
    var onSessionLost: suspend (accountId: String) -> Unit = {}

    private val refreshing = ConcurrentHashMap<String, CompletableDeferred<RefreshResult>>()
    private val jsonType = "application/json".toMediaType()

    suspend fun call(
        accountId: String,
        path: String,
        body: JsonElement? = null,
        method: String = if (body == null) "GET" else "POST",
        auth: Boolean = true,
        headers: Map<String, String> = emptyMap(),
    ): JsonElement = gate(accountId, auth) { parse(respond(accountId, path, body, method, auth, headers)) }

    /**
     * Like [call] for a large GET response kept as text (`/sync`, which is cached as is):
     * the body isn't parsed here, so it's parsed only once, by the caller, off the main thread.
     */
    suspend fun callText(accountId: String, path: String): String = gate(accountId, true) {
        val res = respond(accountId, path, null, "GET", true, emptyMap())
        if (!res.isSuccessful) parse(res) // throws the server's error
        withContext(Dispatchers.IO) { res.use { it.body.string() } }
    }

    /**
     * Called when the server refuses a signed-in request of an account because it requires
     * two-step login and the account has no method yet (403 `two_step_required`, [TwoStepGate]).
     */
    var onTwoStepRequired: suspend (accountId: String) -> Unit = {}

    /** Runs a request; a "set up two-step login first" answer is reported to [onTwoStepRequired], then thrown as usual. */
    private suspend inline fun <T> gate(accountId: String, auth: Boolean, block: () -> T): T = try {
        block()
    } catch (e: ApiException) {
        if (auth && TwoStepGate.blocks(e)) onTwoStepRequired(accountId)
        throw e
    }

    private suspend fun respond(
        accountId: String,
        path: String,
        body: JsonElement?,
        method: String,
        auth: Boolean,
        headers: Map<String, String>,
    ): Response = respondWith(accountId, path, method, auth, headers) {
        body?.toString()?.toRequestBody(jsonType) ?: if (method == "GET") null else ByteArray(0).toRequestBody()
    }

    /**
     * `PUT` a stream of exactly [length] bytes that [write] produces (an attachment's encrypted
     * file), on account [accountId]'s session. After a 401 the session is renewed and [write] runs
     * again. A failure inside [write] reaches the caller as a [BodyFailure].
     */
    suspend fun upload(accountId: String, path: String, length: Long, write: (java.io.OutputStream) -> Unit): JsonElement = gate(accountId, true) {
        val type = "application/octet-stream".toMediaType()
        parse(
            respondWith(accountId, path, "PUT", true, emptyMap()) {
                object : okhttp3.RequestBody() {
                    override fun contentType() = type
                    override fun contentLength() = length

                    // The stream is made once per request (a renewed session builds a new one): OkHttp must never send it again itself.
                    override fun isOneShot() = true
                    override fun writeTo(sink: okio.BufferedSink) {
                        try {
                            write(sink.outputStream())
                        } catch (e: IOException) {
                            throw e
                        } catch (e: Throwable) {
                            // Anything else would escape OkHttp's call thread.
                            throw BodyFailure(e)
                        }
                    }
                }
            },
        )
    }

    /** `GET` a raw answer (an attachment's file) on account [accountId]'s session; the caller reads and closes it. */
    suspend fun download(accountId: String, path: String): Response = gate(accountId, true) {
        respondWith(accountId, path, "GET", true, emptyMap()) { null }
    }

    /** Throws the server's error for a failed raw answer (and closes it). */
    suspend fun fail(res: Response): Nothing {
        parse(res)
        throw ApiException(res.code, "error", "Request failed (${res.code})")
    }

    private suspend fun respondWith(
        accountId: String,
        path: String,
        method: String,
        auth: Boolean,
        headers: Map<String, String>,
        makeBody: () -> okhttp3.RequestBody?,
    ): Response {
        suspend fun send(): Response {
            val a = store.get().accounts[accountId]
            val server = a?.server?.takeIf { it.isNotEmpty() } ?: throw UserException("Set your PassAuth server address first.")
            val req = serverRequest("$server/api$path")
                .method(method, makeBody())
                .apply { if (auth && a.tokens != null) header("Authorization", "Bearer ${a.tokens.access}") }
                .apply { headers.forEach { (k, v) -> header(k, v) } }
                .build()
            return execute(req)
        }

        var res = send()
        if (res.code == 401 && auth) {
            res.close()
            when (refresh(accountId)) {
                RefreshResult.Refreshed -> res = send()
                RefreshResult.Rejected -> {
                    store.updateAccount(accountId) { it.copy(tokens = null) }
                    onSessionLost(accountId)
                    throw ApiException(401, "unauthorized", "Your session ended. Sign in again.")
                }
                // Network error, 5xx or 429: keep the tokens, the next request retries.
                RefreshResult.Unavailable -> throw UserException(UNREACHABLE)
            }
        }
        return res
    }

    /** Request against a server URL directly (server setup check). */
    suspend fun get(url: String): Response = execute(serverRequest(url).build())

    private suspend fun refresh(accountId: String): RefreshResult {
        val mine = CompletableDeferred<RefreshResult>()
        val running = refreshing.putIfAbsent(accountId, mine)
        if (running != null) return running.await()
        val result = try {
            val a = store.get().accounts[accountId]
            val tokens = a?.tokens
            if (a == null || tokens == null) {
                RefreshResult.Rejected
            } else {
                val body = buildJsonObject { put("refresh_token", tokens.refresh) }
                val res = execute(
                    serverRequest("${a.server}/api/auth/refresh")
                        .post(body.toString().toRequestBody(jsonType)).build(),
                )
                when (val outcome = refreshOutcome(res.code)) {
                    RefreshResult.Refreshed -> {
                        val j = parse(res).jsonObject
                        store.updateAccount(accountId) {
                            it.copy(tokens = Tokens(j.str("access_token"), j.str("refresh_token")))
                        }
                        outcome
                    }
                    else -> {
                        res.close()
                        outcome
                    }
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Don't sign anyone out because this caller was cancelled; waiters retry later.
            refreshing.remove(accountId)
            mine.complete(RefreshResult.Unavailable)
            throw e
        } catch (_: Exception) {
            RefreshResult.Unavailable
        } finally {
            refreshing.remove(accountId)
        }
        mine.complete(result)
        return result
    }

    /** Best-effort sign-out with an account's own server and token. */
    suspend fun logoutRemote(server: String, tokens: Tokens?) {
        if (server.isEmpty() || tokens == null) return
        runCatching {
            execute(
                serverRequest("$server/api/auth/logout")
                    .header("Authorization", "Bearer ${tokens.access}")
                    .post(ByteArray(0).toRequestBody()).build(),
            ).close()
        }
    }

    private suspend fun execute(req: Request): Response = try {
        http.newCall(req).await()
    } catch (e: BodyFailure) {
        throw e.cause ?: e
    } catch (e: IOException) {
        // A failure while sending a body that the app made (an upload) keeps its own reason.
        (e.cause as? BodyFailure)?.let { throw it.cause ?: it }
        throw UserException(UNREACHABLE)
    }

    private suspend fun parse(res: Response): JsonElement = withContext(Dispatchers.IO) {
        res.use {
            val text = it.body.string()
            if (!it.isSuccessful) throw failedResponse(it.code, text, it.header("Retry-After"), it.header("x-request-id"))
            try {
                if (text.isEmpty()) JsonNull else AppJson.parseToJsonElement(text)
            } catch (_: Exception) {
                throw ApiException(it.code, "not_passauth", "That address doesn't look like a PassAuth server.")
            }
        }
    }
}

/**
 * The error for a failed response: the server's `error` code and message, with a 429's
 * `Retry-After` ([retryAfterHeader]) and the request's id (the body's `request_id`, else the
 * `x-request-id` header). A body that isn't JSON means another server answered, except for a 429,
 * which is a rate limit whoever sent it (a proxy in front of PassAuth).
 */
fun failedResponse(status: Int, body: String, retryAfterHeader: String?, requestIdHeader: String? = null): ApiException {
    val retryAfter = if (status == 429) retryAfterSeconds(retryAfterHeader) else null
    val json = try {
        if (body.isEmpty()) JsonNull else AppJson.parseToJsonElement(body)
    } catch (_: Exception) {
        return if (status == 429) ApiException(429, "rate_limited", "Too many requests", retryAfter)
        else ApiException(status, "not_passauth", "That address doesn't look like a PassAuth server.")
    }
    val o = json as? JsonObject
    fun text(key: String) = (o?.get(key) as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
    return ApiException(
        status,
        text("error") ?: "error",
        text("message") ?: "Request failed ($status)",
        retryAfter,
        text("request_id") ?: requestIdHeader,
        o,
    )
}

const val UNREACHABLE = "Can't reach your PassAuth server. Check the server address and your connection."

/** Sends the call and waits for its response; cancelling the coroutine cancels the call. */
internal suspend fun Call.await(): Response = suspendCancellableCoroutine { cont ->
    enqueue(object : Callback {
        override fun onResponse(call: Call, response: Response) = cont.resume(response) { _, r, _ -> r.close() }
        override fun onFailure(call: Call, e: IOException) {
            if (!cont.isCancelled) cont.resumeWith(Result.failure(e))
        }
    })
    cont.invokeOnCancellation { runCatching { cancel() } }
}

fun JsonObject.str(key: String): String = this[key]?.jsonPrimitive?.contentOrNull ?: ""
fun JsonObject.strOrNull(key: String): String? = (this[key] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
fun JsonObject.bool(key: String): Boolean = this[key]?.jsonPrimitive?.contentOrNull == "true"
fun JsonObject.long(key: String): Long = this[key]?.jsonPrimitive?.contentOrNull?.toLongOrNull() ?: 0
