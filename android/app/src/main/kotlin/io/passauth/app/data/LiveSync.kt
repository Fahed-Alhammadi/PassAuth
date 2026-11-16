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
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

/** A message from the server's live sync socket (`GET /api/ws`, see the server's `ws.rs`). */
sealed interface LiveMessage {
    /** The first message on a socket: the live-sync [origin] of this session (`origin` of the sync messages its own writes cause). */
    data class Hello(val origin: String) : LiveMessage

    /**
     * The account's data changed: the new sync [revision], the new number of each vault written
     * ([vaults]: null from older servers; empty for profile or account changes) and the session
     * that wrote ([origin]: null for the server's own changes and for notices from several
     * sessions merged into one).
     */
    data class Sync(val revision: Long, val vaults: Map<String, Long>? = null, val origin: String? = null) : LiveMessage

    /** Sessions of this account were ended on the server (password change, admin, deletion). */
    data object Logout : LiveMessage

    /** A new device asks to sign in to the account ([id]: the request). */
    data class AuthRequest(val id: String) : LiveMessage

    /** Sign-in request [id] was answered (on any device) or ended. */
    data class AuthRequestAnswered(val id: String) : LiveMessage

    /**
     * The admin now requires two-step login and the account has no method yet: the server closes
     * the socket next (1008 `two_step_required`) and refuses everything but setting a method up.
     */
    data object TwoStepRequired : LiveMessage
}

/** What the app does about a [LiveMessage]. */
enum class LiveAction {
    Ignore, Sync, CheckSession,

    /** List the sign-in requests waiting for an answer ([AuthRequestInbox.refresh]). */
    ListAuthRequests,

    /** Drop the answered request ([AuthRequestInbox.answered]). */
    AuthRequestAnswered,

    /** Show the two-step gate and stop live sync for the account (no reconnecting: the server would refuse, in a loop). */
    TwoStepRequired,
}

/** The pure parts of live sync (unit-tested). */
object LiveSyncProtocol {
    /** The close code and reason a server ends the socket with once the account must set up two-step login. */
    const val POLICY_CLOSE = 1008
    const val TWO_STEP_REASON = "two_step_required"

    fun parse(text: String): LiveMessage? = runCatching {
        val o = AppJson.parseToJsonElement(text).jsonObject
        when (o.str("type")) {
            "hello" -> o.strOrNull("origin")?.let { LiveMessage.Hello(it) }
            "sync" -> o["revision"]?.jsonPrimitive?.longOrNull?.let { LiveMessage.Sync(it, DeltaSync.vaultNumbers(o["vaults"]), o.strOrNull("origin")) }
            "logout" -> LiveMessage.Logout
            "auth_request" -> o.strOrNull("id")?.takeIf { it.isNotEmpty() }?.let { LiveMessage.AuthRequest(it) }
            "auth_request_answered" -> o.strOrNull("id")?.takeIf { it.isNotEmpty() }?.let { LiveMessage.AuthRequestAnswered(it) }
            "two_step_required" -> LiveMessage.TwoStepRequired
            else -> null
        }
    }.getOrNull()

    /** Whether a close of the socket means "set up two-step login first" (then it isn't reopened). */
    fun closedForTwoStep(code: Int, reason: String?): Boolean = code == POLICY_CLOSE && reason == TWO_STEP_REASON

    /**
     * A sync message refreshes the copy only when it has something the copy lacks
     * ([SyncDecision.onLiveSync]: a vault number newer than the copy's, or no vault numbers at
     * all for a profile or account change; older servers: a newer revision), whichever session
     * wrote it: this device's own saves are already in the copy. [have]: the open copy's
     * position, null while locked. A logout message makes the app check its session: an ended
     * one signs the account out through the normal refresh-token path; a live one (e.g. another
     * device's sessions were ended) is left alone.
     */
    fun action(msg: LiveMessage?, have: SyncPosition?): LiveAction = when (msg) {
        null, is LiveMessage.Hello -> LiveAction.Ignore
        is LiveMessage.Sync -> if (SyncDecision.onLiveSync(msg.revision, msg.vaults, have)) LiveAction.Sync else LiveAction.Ignore
        LiveMessage.Logout -> LiveAction.CheckSession
        is LiveMessage.AuthRequest -> LiveAction.ListAuthRequests
        is LiveMessage.AuthRequestAnswered -> LiveAction.AuthRequestAnswered
        LiveMessage.TwoStepRequired -> LiveAction.TwoStepRequired
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
 * active account is unlocked. A change the copy doesn't have yet (a newer vault
 * number, or a profile change) refreshes the vault without pull-to-refresh,
 * through the repository's sync queue (one sync running, one waiting), with delta
 * sync where the server has it. Reconnects with backoff; each reconnect first goes
 * through the normal API (which refreshes an expired access token and catches up).
 */
class LiveSync(private val repo: VaultRepository, private val store: SecureStore, http: OkHttpClient, private val inbox: AuthRequestInbox) {
    private val client = http.newBuilder().pingInterval(25, TimeUnit.SECONDS).build()

    /**
     * This socket session's live-sync origin (its `hello`). Not used to skip messages: processes
     * sharing a session share it, so the vault numbers decide instead.
     */
    @Volatile
    var origin: String? = null
        private set

    suspend fun run() {
        // Not while the server requires two-step login first: it refuses the socket too, and the reconnects would loop.
        repo.state.map { s -> if (TwoStepGate.liveSyncAllowed(s.status, s.twoStepRequired)) s.activeId else null }
            .distinctUntilChanged()
            .collectLatest { id -> if (id != null) connectLoop(id) }
    }

    private suspend fun connectLoop(id: String) {
        var attempt = 0
        while (currentCoroutineContext().isActive) {
            when (session(id)) {
                End.Opened -> attempt = 0
                End.Failed -> Unit
                // The two-step gate is up for the account ([run] stops this loop with it): no reconnecting.
                End.TwoStepRequired -> return
            }
            delay(LiveSyncProtocol.backoffMillis(attempt++, Math.random()))
            runCatching { repo.refreshIfStale() }
        }
    }

    private sealed interface Event {
        data object Opened : Event
        data class Message(val msg: LiveMessage) : Event

        /** The server closed the socket because the account must set up two-step login first. */
        data object TwoStepRequired : Event
    }

    /** How a connection ended. */
    private enum class End { Opened, Failed, TwoStepRequired }

    /** One connection; returns when it closes. */
    private suspend fun session(id: String): End {
        val a = store.get().accounts[id] ?: return End.Failed
        val tokens = a.tokens ?: return End.Failed
        val events = Channel<Event>(Channel.UNLIMITED)
        val request = serverRequest(LiveSyncProtocol.socketUrl(a.server, tokens.access)).build()
        val socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                events.trySend(Event.Opened)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                when (val msg = LiveSyncProtocol.parse(text)) {
                    null -> {}
                    is LiveMessage.Hello -> origin = msg.origin
                    else -> events.trySend(Event.Message(msg))
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                if (LiveSyncProtocol.closedForTwoStep(code, reason)) events.trySend(Event.TwoStepRequired)
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
                    // Catch up on anything missed while disconnected, sign-in requests from new devices too.
                    Event.Opened -> {
                        opened = true
                        runCatching { repo.refreshIfStale() }
                        runCatching { inbox.refresh() }
                    }
                    Event.TwoStepRequired -> {
                        twoStepRequired(id)
                        return End.TwoStepRequired
                    }
                    is Event.Message -> when (LiveSyncProtocol.action(e.msg, repo.syncPosition)) {
                        LiveAction.Sync -> runCatching { repo.sync() }
                        LiveAction.CheckSession -> runCatching { repo.checkSession() }
                        LiveAction.ListAuthRequests -> runCatching { inbox.refresh() }
                        LiveAction.AuthRequestAnswered -> (e.msg as? LiveMessage.AuthRequestAnswered)?.let { inbox.answered(it.id) }
                        LiveAction.TwoStepRequired -> {
                            twoStepRequired(id)
                            return End.TwoStepRequired
                        }
                        LiveAction.Ignore -> {}
                    }
                }
            }
        } finally {
            socket.cancel()
        }
        return if (opened) End.Opened else End.Failed
    }

    /** The account must set up two-step login first: the app shows its gate (as after a 403 `two_step_required`). */
    private fun twoStepRequired(id: String) {
        inbox.clear()
        repo.markTwoStepRequired(id)
    }
}
