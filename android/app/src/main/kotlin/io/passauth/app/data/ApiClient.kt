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

/** An error response from the server (`{ "error": code, "message": … }`). */
class ApiException(val status: Int, val code: String, message: String) : Exception(message)

/** A user-facing error from the app itself (shown as is). */
class UserException(message: String) : Exception(message)

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

    private val refreshing = ConcurrentHashMap<String, CompletableDeferred<Boolean>>()
    private val jsonType = "application/json".toMediaType()

    suspend fun call(
        accountId: String,
        path: String,
        body: JsonElement? = null,
        method: String = if (body == null) "GET" else "POST",
        auth: Boolean = true,
        headers: Map<String, String> = emptyMap(),
    ): JsonElement {
        suspend fun send(): Response {
            val a = store.get().accounts[accountId]
            val server = a?.server?.takeIf { it.isNotEmpty() } ?: throw UserException("Set your PassAuth server address first.")
            val req = Request.Builder()
                .url("$server/api$path")
                .method(method, body?.toString()?.toRequestBody(jsonType) ?: if (method == "GET") null else ByteArray(0).toRequestBody())
                .apply { if (auth && a.tokens != null) header("Authorization", "Bearer ${a.tokens.access}") }
                .apply { headers.forEach { (k, v) -> header(k, v) } }
                .build()
            return execute(req)
        }

        var res = send()
        if (res.code == 401 && auth) {
            res.close()
            if (refresh(accountId)) {
                res = send()
            } else {
                store.updateAccount(accountId) { it.copy(tokens = null) }
                onSessionLost(accountId)
                throw ApiException(401, "unauthorized", "Your session ended. Sign in again.")
            }
        }
        return parse(res)
    }

    /** Request against a server URL directly (server setup check). */
    suspend fun get(url: String): Response = execute(Request.Builder().url(url).build())

    private suspend fun refresh(accountId: String): Boolean {
        val mine = CompletableDeferred<Boolean>()
        val running = refreshing.putIfAbsent(accountId, mine)
        if (running != null) return running.await()
        val ok = try {
            val a = store.get().accounts[accountId]
            val tokens = a?.tokens
            if (a == null || tokens == null) {
                false
            } else {
                val body = buildJsonObject { put("refresh_token", tokens.refresh) }
                val res = execute(
                    Request.Builder().url("${a.server}/api/auth/refresh")
                        .post(body.toString().toRequestBody(jsonType)).build(),
                )
                if (!res.isSuccessful) {
                    res.close()
                    false
                } else {
                    val j = parse(res).jsonObject
                    store.updateAccount(accountId) {
                        it.copy(tokens = Tokens(j.str("access_token"), j.str("refresh_token")))
                    }
                    true
                }
            }
        } catch (_: Exception) {
            false
        } finally {
            refreshing.remove(accountId)
        }
        mine.complete(ok)
        return ok
    }

    /** Best-effort sign-out with an account's own server and token. */
    suspend fun logoutRemote(server: String, tokens: Tokens?) {
        if (server.isEmpty() || tokens == null) return
        runCatching {
            execute(
                Request.Builder().url("$server/api/auth/logout")
                    .header("Authorization", "Bearer ${tokens.access}")
                    .post(ByteArray(0).toRequestBody()).build(),
            ).close()
        }
    }

    private suspend fun execute(req: Request): Response = try {
        http.newCall(req).await()
    } catch (e: IOException) {
        throw UserException("Can't reach your PassAuth server. Check the server address and your connection.")
    }

    private suspend fun parse(res: Response): JsonElement = withContext(Dispatchers.IO) {
        res.use {
            val text = it.body.string()
            val json = try {
                if (text.isEmpty()) JsonNull else AppJson.parseToJsonElement(text)
            } catch (_: Exception) {
                throw ApiException(it.code, "not_passauth", "That address doesn't look like a PassAuth server.")
            }
            if (!it.isSuccessful) {
                val o = json as? JsonObject
                throw ApiException(
                    it.code,
                    o?.get("error")?.jsonPrimitive?.contentOrNull ?: "error",
                    o?.get("message")?.jsonPrimitive?.contentOrNull ?: "Request failed (${it.code})",
                )
            }
            json
        }
    }
}

private suspend fun Call.await(): Response = suspendCancellableCoroutine { cont ->
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
