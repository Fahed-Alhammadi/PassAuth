package io.passauth.app.push

import io.passauth.app.data.SecurityTransport
import io.passauth.app.ui.permissions.Access
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/*
 * Sign-in request notifications (as in the iPhone app): when a new device asks to sign in to an
 * account, its server asks the PassAuth push relay to wake this phone (FCM, a data-only message
 * `{"kind":"auth_request"}`). The app posts a notification with fixed text and no account data;
 * tapping it opens PassAuth, which asks the server for its open requests as usual (unlock first if
 * needed) and shows the existing sign-in request sheet. The approval protocol is unchanged. Every
 * signed-in account registers this phone's token with its own server, and only while that server
 * lists the `push` feature (`PUT /api/account/push`, `DELETE` before signing out).
 */

/** Pure rules (unit-tested). */
object PushRules {
    /** `/api/config` `features` entry of servers that send sign-in request notifications. */
    const val FEATURE = "push"

    /** Below `/api`. */
    const val PATH = "/account/push"
    const val PLATFORM = "fcm"

    /** FCM has one environment. */
    const val ENVIRONMENT = "production"

    /** What the server accepts as an FCM registration token: 100 to 512 of A–Z a–z 0–9 _ - :. */
    fun validToken(token: String?): Boolean =
        token != null && token.length in 100..512 && token.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-' || it == ':' }

    /** `PUT /api/account/push` body. */
    fun registerBody(token: String): JsonObject = JsonObject(
        mapOf("platform" to JsonPrimitive(PLATFORM), "token" to JsonPrimitive(token), "environment" to JsonPrimitive(ENVIRONMENT)),
    )

    /** Whether a server with these `/api/config` features takes registrations (unknown: no). */
    fun offered(features: List<String>?): Boolean = features?.contains(FEATURE) == true

    /**
     * Whether this phone registers its token: notifications can work here ([available]: Firebase
     * set up in this build and Google Play services present), the Settings switch is on and Android
     * lets PassAuth post notifications.
     */
    fun active(available: Boolean, enabled: Boolean, granted: Boolean): Boolean = available && enabled && granted

    /**
     * The one-time vault card: only while notifications can work here, Android hasn't asked yet,
     * it wasn't dismissed, and the account's server sends these notifications.
     */
    fun showOffer(available: Boolean, permission: Access, dismissed: Boolean, offered: Boolean): Boolean =
        available && permission == Access.NotAsked && !dismissed && offered

    /** The Settings switch: on while wanted and allowed by Android. */
    fun switchOn(enabled: Boolean, permission: Access): Boolean = enabled && permission == Access.On

    /** What turning the Settings switch on or off does. */
    enum class Toggle { Enable, RequestPermission, OpenSettings, Disable }

    fun toggle(on: Boolean, permission: Access): Toggle = when {
        !on -> Toggle.Disable
        permission == Access.On -> Toggle.Enable
        // Denied for good: only Android's app settings can allow it again.
        permission == Access.Blocked -> Toggle.OpenSettings
        else -> Toggle.RequestPermission
    }

    /** An FCM message's data is the relay's sign-in request one (`{"kind":"auth_request"}`). */
    fun isSignInRequest(data: Map<String, String>): Boolean = data["kind"] == "auth_request"
}

/** The notification PassAuth posts for a sign-in request: fixed words, never account data. */
object PushNotice {
    const val CHANNEL_ID = "sign_in_requests"
    const val CHANNEL_NAME = "Sign-in requests"
    const val CHANNEL_DESCRIPTION = "When a new device asks to sign in to your PassAuth account."
    const val TITLE = "Sign-in request"
    const val BODY = "Someone wants to sign in to your PassAuth account on a new device. Open PassAuth to review."

    /** One notification at a time: a newer request replaces the one shown. */
    const val NOTIFICATION_ID = 7301

    /** The tap's intent extra: ask for the open sign-in requests. */
    const val EXTRA_SIGN_IN_REQUEST = "io.passauth.app.SIGN_IN_REQUEST"

    data class Content(val channel: String, val title: String, val body: String)

    /** What to post for a received message's data; null when it isn't one PassAuth shows. */
    fun forMessage(data: Map<String, String>): Content? =
        if (PushRules.isSignInRequest(data)) Content(CHANNEL_ID, TITLE, BODY) else null
}

/** `PUT` / `DELETE /api/account/push` on one account's session. */
class PushClient(private val api: SecurityTransport) {
    /** Registers [token] for this session (204); a 409 `push_disabled` or 400 comes back as the [io.passauth.app.data.ApiException]. */
    suspend fun register(token: String) = send("PUT", PushRules.registerBody(token))

    /** This session's server forgets the token (204). */
    suspend fun unregister() = send("DELETE", null)

    /** [PushRegistrar]'s requests: `PUT` with the registration body, `DELETE` without one. */
    suspend fun send(method: String, body: JsonElement?) {
        api.call(PushRules.PATH, body, method, true, emptyMap())
    }
}

/**
 * Keeps this phone's token registered with every signed-in account's server (each its own), once
 * per token and session in this app run. The network and `/api/config` are injected (tests).
 */
class PushRegistrar(
    /** One request to an account's server: method (PUT/DELETE) and body for [PushRules.PATH]. */
    private val send: suspend (accountId: String, method: String, body: JsonElement?) -> Unit,
    /** The account's server's `/api/config` `features` (null: unknown). */
    private val features: suspend (accountId: String) -> List<String>?,
) {
    private val lock = Mutex()
    private val _registered = HashMap<String, String>()

    /** Account id → the token it was registered with in this run. */
    val registered: Map<String, String> get() = synchronized(_registered) { _registered.toMap() }

    /**
     * Register [token] with each of [signedIn] not registered with it yet; accounts no longer
     * signed in are forgotten (their server dropped the row with the session). One pass at a time.
     */
    suspend fun sync(token: String?, signedIn: List<String>) = lock.withLock {
        synchronized(_registered) { _registered.keys.retainAll(signedIn.toSet()) }
        if (token == null || !PushRules.validToken(token)) return@withLock
        for (id in signedIn) {
            if (registered[id] == token) continue
            if (!PushRules.offered(features(id))) continue
            try {
                send(id, "PUT", PushRules.registerBody(token))
                synchronized(_registered) { _registered[id] = token }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Offline, signed out meanwhile, push turned off by the admin (409): try at the next start.
            }
        }
    }

    /** Sign-out (or switched off): remove this session's row (best effort, at most [timeoutMs]). */
    suspend fun unregister(ids: List<String>, timeoutMs: Long = 3_000) {
        synchronized(_registered) { ids.forEach { _registered.remove(it) } }
        withTimeoutOrNull(timeoutMs) {
            coroutineScope {
                ids.map { id ->
                    async {
                        try {
                            send(id, "DELETE", null)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (_: Exception) {
                            // Offline: the server also drops the row with the session.
                        }
                    }
                }.awaitAll()
            }
        }
    }

    /** The account's next sign-in registers again. */
    fun forget(id: String) {
        synchronized(_registered) { _registered.remove(id) }
    }
}
