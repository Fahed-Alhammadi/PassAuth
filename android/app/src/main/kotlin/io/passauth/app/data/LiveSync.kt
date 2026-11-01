package io.passauth.app.data

import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

/** A message from the server's live sync socket (`GET /api/ws`, see the server's `ws.rs`). */
sealed interface LiveMessage {
    /** The account's data changed; [revision] is the new sync revision. */
    data class Sync(val revision: Long) : LiveMessage

    /** Sessions of this account were ended on the server (password change, admin, deletion). */
    data object Logout : LiveMessage
}

/** What the app does about a [LiveMessage]. */
enum class LiveAction { Ignore, Sync, CheckSession }

/** The pure parts of live sync (unit-tested). */
object LiveSyncProtocol {
    fun parse(text: String): LiveMessage? = runCatching {
        val o = AppJson.parseToJsonElement(text).jsonObject
        when (o.str("type")) {
            "sync" -> o["revision"]?.jsonPrimitive?.longOrNull?.let { LiveMessage.Sync(it) }
            "logout" -> LiveMessage.Logout
            else -> null
        }
    }.getOrNull()

    /**
     * A sync message refreshes the vault only when its revision is newer than the
     * one on screen (our own saves also send one, after we already re-synced).
     * A logout message makes the app check its session: an ended one signs the
     * account out through the normal refresh-token path; a live one (e.g. another
     * device's sessions were ended) is left alone.
     */
    fun action(msg: LiveMessage?, currentRevision: Long?): LiveAction = when (msg) {
        null -> LiveAction.Ignore
        is LiveMessage.Sync -> if (currentRevision != null && msg.revision > currentRevision) LiveAction.Sync else LiveAction.Ignore
        LiveMessage.Logout -> LiveAction.CheckSession
    }

    /** `ws(s)://server/api/ws?access_token=…` (browsers can't send headers on sockets; the server accepts the query). */
    fun socketUrl(server: String, accessToken: String): String {
        val base = when {
            server.startsWith("https://") -> "wss://" + server.removePrefix("https://")
            server.startsWith("http://") -> "ws://" + server.removePrefix("http://")
            else -> server
        }
        return "$base/api/ws?access_token=" + URLEncoder.encode(accessToken, Charsets.UTF_8)
    }

    /** Reconnect delay: 1 s, 2 s, 4 s … up to a minute, plus up to 20% jitter. */
    fun backoffMillis(attempt: Int, jitter: Double = 0.0): Long {
        val base = (1_000L shl attempt.coerceIn(0, 6)).coerceAtMost(60_000L)
        return base + (base * jitter.coerceIn(0.0, 1.0) * 0.2).toLong()
    }
}

/**
 * Live sync while the app is on screen: a WebSocket to the active account's
 * server, connected only while [run] is running (MainActivity started) and the
 * active account is unlocked. A newer revision refreshes the vault without
 * pull-to-refresh. Reconnects with backoff; each reconnect first goes through
 * the normal API (which refreshes an expired access token and catches up).
 */
class LiveSync(private val repo: VaultRepository, private val store: SecureStore, http: OkHttpClient) {
    private val client = http.newBuilder().pingInterval(25, TimeUnit.SECONDS).build()

    suspend fun run() {
        repo.state.map { s -> if (s.status == Status.Unlocked) s.activeId else null }
            .distinctUntilChanged()
            .collectLatest { id -> if (id != null) connectLoop(id) }
    }

    private suspend fun connectLoop(id: String) {
        var attempt = 0
        while (currentCoroutineContext().isActive) {
            if (session(id)) attempt = 0
            delay(LiveSyncProtocol.backoffMillis(attempt++, Math.random()))
            runCatching { repo.refreshIfStale() }
        }
    }

    private sealed interface Event {
        data object Opened : Event
        data class Message(val msg: LiveMessage) : Event
    }

    /** One connection; returns when it closes (true if it had opened). */
    private suspend fun session(id: String): Boolean {
        val a = store.get().accounts[id] ?: return false
        val tokens = a.tokens ?: return false
        val events = Channel<Event>(Channel.UNLIMITED)
        val request = Request.Builder().url(LiveSyncProtocol.socketUrl(a.server, tokens.access)).build()
        val socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                events.trySend(Event.Opened)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                LiveSyncProtocol.parse(text)?.let { events.trySend(Event.Message(it)) }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                events.close()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                response?.close()
                events.close()
            }
        })
        var opened = false
        try {
            for (e in events) {
                when (e) {
                    // Catch up on anything missed while disconnected.
                    Event.Opened -> { opened = true; runCatching { repo.refreshIfStale() } }
                    is Event.Message -> when (LiveSyncProtocol.action(e.msg, repo.vault.value?.revision)) {
                        LiveAction.Sync -> runCatching { repo.sync() }
                        LiveAction.CheckSession -> runCatching { repo.checkSession() }
                        LiveAction.Ignore -> {}
                    }
                }
            }
        } finally {
            socket.cancel()
        }
        return opened
    }
}
