package io.passauth.app.data

import java.net.URI
import java.net.URLDecoder
import java.util.Base64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Two-step sign-in with a security key or passkey through the server's key page.
 *
 * The app can't run WebAuthn for a self-hosted server's relying party, so after
 * `POST /auth/2fa/passkey/start` it opens the server's `key_page` in the browser
 * with the request options in the URL fragment (`v=1&options=…&return=app&state=…`). The page
 * returns to `passauth://two-step-key#v=1&state=…&credential=…` (or `…#v=1&state=…&error=cancelled`),
 * and the app sends the credential to `/auth/2fa/passkey/finish` with its own
 * two-factor token, which never leaves the app.
 *
 * A callback is accepted only while the app waits for one, only once, and only when its
 * `clientDataJSON.challenge` is the challenge of the options this app opened.
 */
object SecurityKeyHandoff {
    /** `/api/config` feature: the server has the key page. */
    const val FEATURE = "two_step_key_page"
    const val SCHEME = "passauth"
    const val HOST = "two-step-key"

    const val METHOD = "Security key or passkey"
    const val BUTTON = "Use security key"
    const val EXPLAIN = "PassAuth opens your server's page in the browser. Touch your security key or use your passkey there."
    const val WAITING = "Waiting for your security key…"
    const val MISMATCH = "This server's address for security keys doesn't match. Use another method."
    const val NO_BROWSER = "No browser is installed that can open your server's page. Use another method."
    const val NEVER_ASKS = "PassAuth never asks for your master password or Secret Key in the browser."

    /** A fresh `state` for one hand-off: 16 bytes from the CSPRNG, base64url (22 characters). */
    fun newState(): String = b64urlEncode(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })

    /** A `state` the page may echo: 22–64 base64url characters. */
    fun validState(s: String?): Boolean = s != null && Regex("[A-Za-z0-9_-]{22,64}").matches(s)

    /** What the app opens: the key page URL with the options and [state] in its fragment, and the challenge it expects back. */
    class Request(val url: String, val challenge: ByteArray, val state: String)

    /**
     * The URL to open for the start answer, or null when it must not be opened: the key page
     * isn't an `https:` address whose host is exactly the options' `rpId` AND the host of
     * [server] (the server the app is signing in to; ports aren't compared), or the options
     * have no challenge.
     */
    fun request(options: JsonObject, keyPage: String?, server: String, state: String = newState()): Request? {
        if (!validState(state)) return null
        val serverHost = runCatching { URI(server).host }.getOrNull()?.takeIf { it.isNotEmpty() } ?: return null
        // `{publicKey: {…}}` as webauthn-rs answers; a bare options object is read the same way.
        val pk = options["publicKey"] as? JsonObject ?: options.takeIf { "challenge" in it } ?: return null
        val rpId = (pk["rpId"] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotEmpty() } ?: return null
        val challenge = (pk["challenge"] as? JsonPrimitive)?.contentOrNull?.let(::b64urlDecode)?.takeIf { it.isNotEmpty() } ?: return null
        val page = keyPage?.takeIf { it.isNotEmpty() } ?: return null
        val uri = runCatching { URI(page) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true)) return null
        if (uri.rawUserInfo != null || uri.rawFragment != null || uri.rawQuery != null) return null
        val host = uri.host ?: return null
        if (!host.equals(rpId, ignoreCase = true) || !host.equals(serverHost, ignoreCase = true)) return null
        val fragment = "v=1&options=${b64urlEncode(options.toString().toByteArray())}&return=app&state=$state"
        return Request("$page#$fragment", challenge, state)
    }

    sealed interface Callback {
        /** The assertion JSON to send to `/finish` as `credential`. */
        class Credential(val json: JsonObject) : Callback
        /** The user cancelled on the page or closed the browser. */
        data object Cancelled : Callback
        /** Not ours (another scheme or path, wrong version or state, malformed, or another challenge): ignored. */
        data object Invalid : Callback
    }

    /**
     * Read a `passauth://two-step-key#v=1&state=…&(credential=…|error=cancelled)` callback: only one
     * echoing [state] (the hand-off's own) counts, a credential only for [expected] (the challenge of
     * the options this app opened), and only the exact `error=cancelled` is a cancel.
     */
    fun parseCallback(url: String?, expected: ByteArray, state: String): Callback {
        if (!validState(state)) return Callback.Invalid
        if (url == null) return Callback.Invalid
        val uri = runCatching { URI(url) }.getOrNull() ?: return Callback.Invalid
        if (!uri.scheme.equals(SCHEME, ignoreCase = true) || !uri.host.equals(HOST, ignoreCase = true)) return Callback.Invalid
        if (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/") return Callback.Invalid
        val params = fragmentParams(uri.rawFragment ?: return Callback.Invalid) ?: return Callback.Invalid
        if (params["v"] != "1") return Callback.Invalid
        val echoed = params["state"]
        if (!validState(echoed) || !java.security.MessageDigest.isEqual(echoed!!.toByteArray(), state.toByteArray())) return Callback.Invalid
        val credential = params["credential"]
        val error = params["error"]
        if ((credential == null) == (error == null)) return Callback.Invalid
        if (error != null) return if (error == "cancelled") Callback.Cancelled else Callback.Invalid
        val json = b64urlDecode(credential!!)?.let { bytes ->
            runCatching { AppJson.parseToJsonElement(bytes.decodeToString()) as? JsonObject }.getOrNull()
        } ?: return Callback.Invalid
        if (!challengeMatches(json, expected)) return Callback.Invalid
        return Callback.Credential(json)
    }

    /** Whether the assertion's `response.clientDataJSON` is a `webauthn.get` for [expected]. */
    fun challengeMatches(credential: JsonObject, expected: ByteArray): Boolean {
        val response = credential["response"] as? JsonObject ?: return false
        val clientData = (response["clientDataJSON"] as? JsonPrimitive)?.contentOrNull?.let(::b64urlDecode) ?: return false
        val data = runCatching { AppJson.parseToJsonElement(clientData.decodeToString()) as? JsonObject }.getOrNull() ?: return false
        if ((data["type"] as? JsonPrimitive)?.contentOrNull != "webauthn.get") return false
        val got = (data["challenge"] as? JsonPrimitive)?.contentOrNull?.let(::b64urlDecode) ?: return false
        return expected.isNotEmpty() && java.security.MessageDigest.isEqual(got, expected)
    }

    /** `a=b&c=d` → map; null when a key repeats or a pair has no `=`. */
    private fun fragmentParams(fragment: String): Map<String, String>? {
        val out = HashMap<String, String>()
        for (part in fragment.split('&')) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            if (eq <= 0) return null
            val key = part.substring(0, eq)
            val value = runCatching { URLDecoder.decode(part.substring(eq + 1), Charsets.UTF_8) }.getOrNull() ?: return null
            if (out.put(key, value) != null) return null
        }
        return out
    }

    fun b64urlEncode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun b64urlDecode(s: String): ByteArray? =
        if (!Regex("[A-Za-z0-9_-]*={0,2}").matches(s)) null else runCatching { Base64.getUrlDecoder().decode(s) }.getOrNull()

    /** The app-wide waiter: the receiving activity and the Auth Tab result both deliver here. */
    val waiter = Waiter()

    /** One pending hand-off at a time; a callback finishes it once. */
    class Waiter {
        class Pending internal constructor(internal val challenge: ByteArray, internal val state: String) {
            internal val result = CompletableDeferred<Callback>()
            suspend fun await(): Callback = result.await()
        }

        private var pending: Pending? = null

        /** Start waiting for the options with [challenge], opened with [state]; an earlier wait ends as cancelled. */
        @Synchronized
        fun begin(challenge: ByteArray, state: String): Pending {
            pending?.result?.complete(Callback.Cancelled)
            return Pending(challenge.copyOf(), state).also { pending = it }
        }

        /** Whether something waits now. */
        @Synchronized
        fun waiting(): Boolean = pending != null

        /**
         * A callback URL arrived: true when it finished the wait. Ignored (false) when nothing waits,
         * or when it isn't a valid callback for the challenge being waited for.
         */
        @Synchronized
        fun deliver(url: String?): Boolean {
            val p = pending ?: return false
            val r = parseCallback(url, p.challenge, p.state)
            if (r is Callback.Invalid) return false
            pending = null
            return p.result.complete(r)
        }

        /** Stop waiting for [p] (Cancel, the browser was closed, the screen went away). */
        @Synchronized
        fun cancel(p: Pending) {
            if (pending === p) pending = null
            p.result.complete(Callback.Cancelled)
        }
    }
}
