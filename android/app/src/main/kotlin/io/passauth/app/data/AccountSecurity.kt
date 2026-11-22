package io.passauth.app.data

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/*
 * Account security settings (the web vault's Settings → Security and Two-step login):
 * master password / Secret Key change and two-step login methods. The request
 * sequence lives here, apart from the Rust core and OkHttp, so JVM tests can run it
 * against a fake server; VaultRepository supplies the real transport and crypto and
 * updates what this device keeps afterwards.
 */

/** Signed-in requests of one account (ApiClient pinned to an account id). */
fun interface SecurityTransport {
    suspend fun call(path: String, body: JsonElement?, method: String, auth: Boolean, headers: Map<String, String>): JsonElement
}

/** An OPAQUE login in progress: [message] goes to `/auth/login/start`, [finish] answers the server. */
interface LoginProof : AutoCloseable {
    val message: String

    /** Throws [UserException] when the password (or Secret Key) is wrong. */
    fun finish(serverMessage: String): String
}

/** A re-wrapped account bundle plus the OPAQUE registration for the new password. */
interface Rewrapped : AutoCloseable {
    val bundleJson: String

    /** A newly created Secret Key, shown once; null when none was created. */
    val secretKey: String?

    /** The registration request for `/account/keys/start`. */
    fun registerStart(): String

    /** The upload for `/account/keys/finish`, from the server's answer to [registerStart]. */
    fun registerFinish(serverMessage: String): String
}

/** The Rust core's part (Argon2id, OPAQUE, re-wrapping); faked in tests. */
interface SecurityCrypto {
    fun loginProof(password: String, secretKey: String?, prelogin: JsonObject): LoginProof

    /** New account keys for [newPassword], made to meet [kdf] (the server's minimums; null: the core's defaults). */
    fun rewrap(bundleJson: String, newPassword: String, withSecretKey: Boolean, existingSecretKey: String?, kdf: KdfMinimums?): Rewrapped
}

/** What to do with the Secret Key when the master password changes. */
enum class SecretKeyChoice {
    Keep, TurnOn, TurnOff;

    fun enabledAfter(currentlyOn: Boolean): Boolean = when (this) {
        Keep -> currentlyOn
        TurnOn -> true
        TurnOff -> false
    }
}

/**
 * 403 `quota_exceeded`: the save would take the vault's owner past the server's item or storage
 * limit (only growth is refused; editing, trashing and deleting always work).
 */
const val QUOTA_EXCEEDED_MESSAGE = "You've reached this server's storage limit. Delete items or ask the server's admin."

/**
 * The account's storage as `GET /api/account` reports it: items and bytes (encrypted item keys
 * and data, trash included) in the vaults it owns, and the server admin's limits (0 = none).
 */
data class AccountUsage(val itemCount: Long, val storageBytes: Long, val maxItems: Long, val maxStorageBytes: Long) {
    /** The server limits items or storage: only then is the usage shown. */
    val limited: Boolean get() = maxItems > 0 || maxStorageBytes > 0

    /** "120 of 500 items"; null without an item limit. */
    val itemsLine: String? get() = if (maxItems > 0) "$itemCount of $maxItems ${if (maxItems == 1L) "item" else "items"}" else null

    /** "1.2 MB of 50 MB"; null without a storage limit. */
    val storageLine: String? get() = if (maxStorageBytes > 0) "${bytes(storageBytes)} of ${bytes(maxStorageBytes)}" else null

    /** Share of each limit used (0…1), for a bar; null without that limit. */
    val itemsUsed: Float? get() = if (maxItems > 0) (itemCount.toFloat() / maxItems).coerceAtMost(1f) else null
    val storageUsed: Float? get() = if (maxStorageBytes > 0) (storageBytes.toFloat() / maxStorageBytes).coerceAtMost(1f) else null

    /** A limit is reached: new items (or bigger ones) are refused until something is deleted. */
    val full: Boolean get() = (maxItems > 0 && itemCount >= maxItems) || (maxStorageBytes > 0 && storageBytes >= maxStorageBytes)

    companion object {
        /** Absent fields (older servers) read as 0: no usage, no limit. */
        fun parse(o: JsonObject): AccountUsage {
            val usage = o["usage"] as? JsonObject ?: JsonObject(emptyMap())
            val limits = o["limits"] as? JsonObject ?: JsonObject(emptyMap())
            return AccountUsage(
                usage.long("item_count").coerceAtLeast(0),
                usage.long("storage_bytes").coerceAtLeast(0),
                limits.long("max_items").coerceAtLeast(0),
                limits.long("max_storage_bytes").coerceAtLeast(0),
            )
        }

        /**
         * Sizes in binary units as the admin page sets them ("50 MB" = 50 MiB): bytes, KB, MB, GB,
         * one decimal below 10 when it isn't whole (the iOS app's `AccountUsage.bytes`).
         */
        fun bytes(n: Long): String {
            if (n < 1024) return "$n ${if (n == 1L) "byte" else "bytes"}"
            val units = listOf("KB", "MB", "GB", "TB")
            var value = n / 1024.0
            var unit = 0
            while (value >= 1024 && unit < units.size - 1) {
                value /= 1024
                unit++
            }
            val rounded = Math.round(value * 10) / 10.0
            val text = if (rounded < 10 && rounded != Math.rint(rounded)) String.format(java.util.Locale.ROOT, "%.1f", rounded) else Math.round(value).toString()
            return "$text ${units[unit]}"
        }
    }
}

/** A security key / passkey registered for two-step login (added in the web vault). */
data class SecurityKeyInfo(val id: String, val name: String, val createdAt: Long, val lastUsedAt: Long?)

/** GET /api/account, the parts these settings use. */
data class SecurityStatus(
    val email: String,
    val providers: List<String>,
    val recoveryCodesLeft: Int,
    /** The server can send email (email codes are possible). */
    val emailAvailable: Boolean,
    val secretKeyEnabled: Boolean,
    val securityKeys: List<SecurityKeyInfo> = emptyList(),
) {
    val totpOn: Boolean get() = TwoFactor.TOTP in providers
    val emailOn: Boolean get() = TwoFactor.EMAIL in providers
    val anyOn: Boolean get() = providers.isNotEmpty()

    /** Turning [provider] off leaves no method: recovery codes go too. */
    fun isLast(provider: String) = providers == listOf(provider)

    /** Removing a key now turns two-step login off: it's the only key and no other method is on. */
    fun isLastKey() = securityKeys.size == 1 && providers == listOf(TwoFactor.PASSKEY)
}

/** Authenticator setup from the server: the secret (base32) and its `otpauth://` URI. */
data class TotpSetup(val secret: String, val uri: String) {
    /** The setup key in groups of four, for typing into an app. */
    val grouped: String get() = secret.chunked(4).joinToString(" ")

    override fun toString() = "TotpSetup(…)"
}

/** Result of a password / Secret Key change. [secretKey] is new and shown once. */
data class KeyChange(val bundleJson: String, val secretKeyEnabled: Boolean, val secretKey: String?) {
    override fun toString() = "KeyChange(secretKeyEnabled=$secretKeyEnabled, newSecretKey=${secretKey != null})"
}

object TwoFactor {
    const val TOTP = "totp"
    const val EMAIL = "email"
    const val PASSKEY = "passkey"

    /** Codes as typed: spaces and dashes are dropped, like the web vault. */
    fun cleanCode(code: String) = code.filterNot { it.isWhitespace() || it == '-' }

    /** A six-digit authenticator code. */
    fun validTotp(code: String) = cleanCode(code).let { it.length == 6 && it.all(Char::isDigit) }

    fun recoveryText(server: String, codes: List<String>) =
        "PassAuth recovery codes\n$server\n\nEach code works once.\n\n${codes.joinToString("\n")}\n"
}

/**
 * Something shown only once (new Secret Key, recovery codes): it can't be closed
 * (back, outside tap, Done) until the user confirms they saved it.
 */
data class ShowOnce<T>(val value: T, val saved: Boolean = false) {
    fun confirmSaved(on: Boolean) = copy(saved = on)

    /** Whether a close request (back, outside tap, Done) may close it. */
    fun mayClose(): Boolean = saved

    override fun toString() = "ShowOnce(saved=$saved)"
}

/** Master password rules of the web vault (Register / Change master password). */
object MasterPasswordRules {
    const val MIN_LENGTH = 10
    const val WEAK_BITS = 50.0
    const val WEAK_MESSAGE = "This password is easy to guess. Choose a longer one, or select Change master password again to use it anyway."

    enum class Strength(val label: String, val level: Int) { Weak("Weak", 1), Fair("Fair", 2), Good("Good", 3), Strong("Strong", 4) }

    fun strength(bits: Double): Strength = when {
        bits < WEAK_BITS -> Strength.Weak
        bits < 65 -> Strength.Fair
        bits < 80 -> Strength.Good
        else -> Strength.Strong
    }

    /**
     * The problem with a new master password, or null. A weak one is refused once
     * ([weakConfirmed] false) and accepted when the user submits it again. [minLength]: the
     * server's policy ([PolicyRules.minPasswordLength]), never below [MIN_LENGTH].
     */
    fun problem(current: String, next: String, confirm: String, bits: Double, weakConfirmed: Boolean, minLength: Int = MIN_LENGTH): String? = when {
        current.isEmpty() -> "Enter your current master password."
        next.length < maxOf(MIN_LENGTH, minLength) -> tooShort(minLength)
        next != confirm -> "The new passwords don't match. Type the same password in both fields."
        bits < WEAK_BITS && !weakConfirmed -> WEAK_MESSAGE
        else -> null
    }

    fun tooShort(minLength: Int) = "Use at least ${maxOf(MIN_LENGTH, minLength)} characters for your new master password."
}

/**
 * User-facing wording for errors of these settings (the web vault's `friendlyError`): the
 * server's `error` code first (API v2), the message text of older servers second.
 */
fun securityErrorMessage(e: Throwable): String? = when {
    e !is ApiException -> null
    e.isRateLimited -> tooManyAttemptsMessage(e) ?: "Too many attempts, try again later."
    e.hasCode("invalid_code", "invalid code") -> "That code didn't work. Enter the code that's showing now and try again."
    e.hasCode("expired", "start setup first") -> "The setup expired. Cancel and start setup again."
    e.hasCode("reauth_required") -> "Your confirmation expired. Enter your master password again."
    e.message == "email is not configured on this server" -> "This server isn't set up to send email, so email codes aren't available."
    e.status == 409 && (e.hasCode("already_enabled") || e.message.orEmpty().startsWith("authenticator app already enabled")) ->
        "The authenticator app is already on. Turn it off first to set it up again."
    else -> null
}

/** One signed-in session of the account (`GET /account/sessions`). */
data class SessionInfo(
    val id: String,
    val deviceName: String,
    /** The device's kind as it signed in: `web`, `extension`, `desktop`, `mobile`, `cli`. */
    val deviceKind: String,
    /** The app that signed in (`X-PassAuth-Client`, e.g. `android/0.6.0`); null from older servers and sessions. */
    val client: String?,
    /** Unix seconds. */
    val createdAt: Long,
    val lastUsed: Long,
    /** This app's own session (signing it out is "Log out"). */
    val current: Boolean,
    /** The device the session belongs to (a device can hold several sessions); "" when the server didn't say. */
    val deviceId: String = "",
)

/**
 * The account's sessions (most recently used first), whether the server signs out all the others in
 * one request ([canRevokeOthers]) and forgets a device ([canForget], feature `forget_device`).
 */
data class SessionList(val sessions: List<SessionInfo>, val canRevokeOthers: Boolean, val canForget: Boolean = false) {
    /** The sessions other than this app's. */
    val others: List<SessionInfo> get() = sessions.filter { !it.current }

    /** How many listed sessions [deviceId] holds. */
    fun sessionsOn(deviceId: String): Int = sessions.count { it.deviceId == deviceId }

    /** Whether [deviceId] is the device this app signed in as (one of its sessions is this app's). */
    fun isThisDevice(deviceId: String): Boolean = deviceId.isNotEmpty() && sessions.any { it.deviceId == deviceId && it.current }
}

/** What forgetting a device did: how many sessions ended, and whether this app's own was one of them. */
data class ForgetResult(val signedOut: Int, val current: Boolean)

/** Session wording, as the web vault's Sessions tab (pure, unit-tested). */
object SessionText {
    /** Apps by the name they send in `X-PassAuth-Client` (`<name>/<version>`); false: the version is left out. */
    private val CLIENTS = mapOf(
        "web" to ("Web" to false),
        "desktop" to ("Desktop app" to true),
        "extension" to ("Chrome extension" to true),
        "chrome" to ("Chrome extension" to true),
        "chrome-extension" to ("Chrome extension" to true),
        "ios" to ("iPhone app" to true),
        "iphone" to ("iPhone app" to true),
        "ipad" to ("iPad app" to true),
        "ios-autofill" to ("iPhone AutoFill" to true),
        "android" to ("Android app" to true),
        "macos-autofill" to ("Mac AutoFill" to true),
        "mac-autofill" to ("Mac AutoFill" to true),
        "cli" to ("Command line" to true),
    )
    private val VERSION = Regex("^[0-9][A-Za-z0-9_.+-]{0,31}$")
    private val SPACES = Regex("[\\s_]+")

    /**
     * The app in plain words: "desktop/0.7.0" → "Desktop app 0.7.0", "web/0.9.0" → "Web",
     * "android/0.6.0" → "Android app 0.6.0"; an unknown name as sent (first letter capitalised)
     * with its version; null when the session has no client (older servers).
     */
    fun client(raw: String?): String? {
        val text = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val name = text.substringBefore('/').lowercase(java.util.Locale.ROOT).replace(SPACES, "-")
        val version = if ('/' in text) text.substringAfter('/').trim() else ""
        val shown = version.takeIf { VERSION.matches(it) }.orEmpty()
        val known = CLIENTS[name]
        if (known == null) {
            val label = name.take(40).ifEmpty { return null }
            return label.replaceFirstChar { it.uppercase() } + if (shown.isEmpty()) "" else " $shown"
        }
        return if (known.second && shown.isNotEmpty()) "${known.first} $shown" else known.first
    }

    /** The device kind, for sessions without a client. */
    fun kind(kind: String): String = when (kind) {
        "web" -> "Web vault"
        "extension" -> "Browser extension"
        "cli" -> "Command line"
        "desktop" -> "Desktop app"
        "mobile" -> "Mobile app"
        "" -> "Unknown app"
        else -> kind.replaceFirstChar { it.uppercase() }
    }

    /** The app of a session: its client, else its device kind. */
    fun app(s: SessionInfo): String = client(s.client) ?: kind(s.deviceKind)

    private fun day(ts: Long): String = java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(ts * 1000))

    /** "Just now", "5 min ago", "3 hours ago", "2 days ago", else the date. */
    fun ago(ts: Long, nowMs: Long = System.currentTimeMillis()): String {
        val s = maxOf(0L, nowMs / 1000 - ts)
        return when {
            s < 60 -> "Just now"
            s < 3600 -> "${s / 60} min ago"
            s < 86_400 -> (s / 3600).let { h -> "$h hour${if (h == 1L) "" else "s"} ago" }
            s < 30 * 86_400 -> (s / 86_400).let { d -> "$d day${if (d == 1L) "" else "s"} ago" }
            else -> day(ts)
        }
    }

    /** The line under a session's app: "Signed in 12 Nov 2026 · last used 5 min ago" ("in use now" for this app's session). */
    fun detail(s: SessionInfo, nowMs: Long = System.currentTimeMillis()): String {
        val signedIn = "Signed in ${day(s.createdAt)}"
        if (s.current) return "$signedIn · in use now"
        val used = ago(s.lastUsed, nowMs)
        return "$signedIn · last used ${if (used == "Just now") "just now" else used}"
    }

    /** The notice after signing the others out ("2 other sessions signed out."). */
    fun revokedOthers(n: Int?): String =
        if (n == null) "Other sessions signed out." else "$n other ${if (n == 1) "session" else "sessions"} signed out."

    const val INTRO = "Signing a device out ends its session there. It needs your master password to sign in again."
    const val FORGET_INTRO = " Forgetting a device also ends its other sessions and makes its next sign-in count as a new device, " +
        "so a remembered device has to use two-step login again."
    const val FORGOTTEN_HERE = "This device was forgotten and signed out."

    /** The page's intro; servers with `forget_device` explain forgetting too. */
    fun intro(canForget: Boolean) = if (canForget) INTRO + FORGET_INTRO else INTRO

    /** The body of "Forget this device?": [sessions] = how many listed sessions the device holds. */
    fun forgetBody(sessions: Int, thisDevice: Boolean): String =
        (if (sessions > 1) "Its $sessions sessions are signed out at once." else "Its session is signed out at once.") +
            " The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it." +
            (if (thisDevice) " This is the device you're using, so you're signed out here too." else "")

    fun forgetAction(thisDevice: Boolean) = if (thisDevice) "Forget and sign out" else "Forget device"

    /** The notice after forgetting another device. */
    fun forgotten(deviceName: String) = "${deviceName.ifEmpty { "Device" }} forgotten."
}

class AccountSecurity(
    private val api: SecurityTransport,
    private val crypto: SecurityCrypto,
    private val device: JsonObject,
) {
    private suspend fun post(path: String, body: JsonElement? = null, headers: Map<String, String> = emptyMap()) =
        api.call(path, body, "POST", true, headers)

    /**
     * A fresh proof of the master password: an OPAQUE login with `purpose: "reauth"`
     * on the signed-in session. The token allows one sensitive request (five minutes).
     */
    suspend fun reauth(email: String, password: String, secretKey: String?): String {
        val pre = api.call("/auth/prelogin", buildJsonObject { put("email", email) }, "POST", false, emptyMap()).jsonObject
        val skRequired = pre.bool("secret_key_required")
        if (skRequired && secretKey == null) throw UserException(VaultRepository.SECRET_KEY_REQUIRED)
        crypto.loginProof(password, if (skRequired) secretKey else null, pre).use { proof ->
            val resp = api.call(
                "/auth/login/start",
                buildJsonObject { put("email", email); put("message", proof.message) },
                "POST", false, emptyMap(),
            ).jsonObject
            val fin = proof.finish(resp.str("message"))
            val result = post(
                "/auth/login/finish",
                buildJsonObject {
                    put("login_id", resp.str("login_id"))
                    put("message", fin)
                    put("device", device)
                    put("purpose", "reauth")
                },
            ).jsonObject
            return result.strOrNull("reauth_token") ?: throw UserException("Your server didn't confirm the master password. Try again.")
        }
    }

    /**
     * Change the master password and/or the Secret Key setting (the web vault's
     * `changeKeys`): reauth → rewrap → keys/start → OPAQUE registration → keys/finish.
     * The server keeps this session and signs out every other one.
     * [secretKey] is the current Secret Key (typed, or this device's copy): kept when
     * the Secret Key stays on; without one a new key is created. [kdf]: the server's minimums
     * for new keys (its policy, read just before), so the new keys always meet them; the same
     * password with new settings is how a `kdf` policy violation is fixed.
     */
    suspend fun changeKeys(
        email: String,
        bundleJson: String,
        currentPassword: String,
        newPassword: String,
        choice: SecretKeyChoice,
        secretKey: String?,
        kdf: KdfMinimums? = null,
    ): KeyChange {
        val currentlyOn = AppJson.parseToJsonElement(bundleJson).jsonObject.bool("secret_key_enabled")
        val withSecretKey = choice.enabledAfter(currentlyOn)
        val token = reauth(email, currentPassword, secretKey)
        // Keep the same Secret Key only when it stays on; turning it on (again) makes a new one.
        val existing = secretKey.takeIf { currentlyOn && choice == SecretKeyChoice.Keep }
        crypto.rewrap(bundleJson, newPassword, withSecretKey, existing, kdf).use { next ->
            val start = post("/account/keys/start", buildJsonObject { put("message", next.registerStart()) }).jsonObject
            val upload = next.registerFinish(start.str("message"))
            post(
                "/account/keys/finish",
                buildJsonObject {
                    put("upload", upload)
                    put("bundle", AppJson.parseToJsonElement(next.bundleJson))
                },
                mapOf(REAUTH_HEADER to token),
            )
            return KeyChange(next.bundleJson, withSecretKey, next.secretKey)
        }
    }

    suspend fun status(): SecurityStatus {
        val o = api.call("/account", null, "GET", true, emptyMap()).jsonObject
        return SecurityStatus(
            email = o.str("email"),
            providers = (o["two_factor"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull },
            recoveryCodesLeft = o.long("recovery_codes_left").toInt(),
            emailAvailable = o.bool("email_enabled"),
            secretKeyEnabled = o.bool("secret_key_enabled"),
            securityKeys = (o["passkeys"] as? JsonArray).orEmpty().mapNotNull { e ->
                val k = e as? JsonObject ?: return@mapNotNull null
                val id = k.str("id").ifEmpty { return@mapNotNull null }
                SecurityKeyInfo(id, k.str("name"), k.long("created_at"), k.long("last_used_at").takeIf { it > 0 })
            },
        )
    }

    /** Items and storage against the server's limits (`GET /account`). */
    suspend fun usage(): AccountUsage = AccountUsage.parse(api.call("/account", null, "GET", true, emptyMap()).jsonObject)

    suspend fun totpSetup(): TotpSetup {
        val o = post("/account/2fa/totp/setup").jsonObject
        return TotpSetup(o.str("secret"), o.str("uri"))
    }

    /**
     * Turns the authenticator on, after re-authentication (servers answer 403 `reauth_required`
     * without it, so a stolen session alone can't add its own second step; older servers ignore the
     * header); the first method returns recovery codes (shown once). A malformed code is refused
     * before anything is sent.
     */
    suspend fun totpEnable(code: String, email: String, password: String, secretKey: String?): List<String>? {
        val c = TwoFactor.cleanCode(code)
        if (!TwoFactor.validTotp(c)) throw UserException("Enter the 6-digit code from your authenticator app.")
        val token = reauth(email, password, secretKey)
        return recoveryCodes(post("/account/2fa/totp/enable", buildJsonObject { put("code", c) }, mapOf(REAUTH_HEADER to token)))
    }

    suspend fun emailSetup() {
        post("/account/2fa/email/setup")
    }

    /** Turns email codes on, after re-authentication (as [totpEnable]). */
    suspend fun emailEnable(code: String, email: String, password: String, secretKey: String?): List<String>? {
        val c = TwoFactor.cleanCode(code)
        if (c.isEmpty()) throw UserException("Enter the code from the email we sent you.")
        val token = reauth(email, password, secretKey)
        return recoveryCodes(post("/account/2fa/email/enable", buildJsonObject { put("code", c) }, mapOf(REAUTH_HEADER to token)))
    }

    /** New recovery codes (the old ones stop working), after re-authentication. */
    suspend fun regenerateRecoveryCodes(email: String, password: String, secretKey: String?): List<String> {
        val token = reauth(email, password, secretKey)
        return recoveryCodes(post("/account/2fa/recovery", headers = mapOf(REAUTH_HEADER to token)))
            ?: throw UserException("Your server didn't send new recovery codes. Try again.")
    }

    /** Turn off one method, after re-authentication. */
    suspend fun disable(provider: String, email: String, password: String, secretKey: String?) {
        require(provider == TwoFactor.TOTP || provider == TwoFactor.EMAIL)
        val token = reauth(email, password, secretKey)
        api.call("/account/2fa/$provider", null, "DELETE", true, mapOf(REAUTH_HEADER to token))
    }

    /** Remove a two-step login security key, after re-authentication. */
    suspend fun removeSecurityKey(keyId: String, email: String, password: String, secretKey: String?) {
        val token = reauth(email, password, secretKey)
        api.call("/account/2fa/passkey/${urlPart(keyId)}", null, "DELETE", true, mapOf(REAUTH_HEADER to token))
    }

    /**
     * The account's sessions; the server's `features` (`GET /config`) say whether all the others
     * can be signed out in one request (an older server or a failed check just hides that).
     */
    suspend fun sessions(): SessionList {
        val o = api.call("/account/sessions", null, "GET", true, emptyMap()).jsonObject
        val features = try {
            ((api.call("/config", null, "GET", false, emptyMap()) as? JsonObject)?.get("features") as? JsonArray).orEmpty()
                .mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            emptyList()
        }
        val current = o.str("current")
        val list = (o["sessions"] as? JsonArray).orEmpty().mapNotNull { e ->
            val r = e as? JsonObject ?: return@mapNotNull null
            val id = r.str("id").ifEmpty { return@mapNotNull null }
            SessionInfo(
                id = id,
                deviceName = r.str("device_name"),
                deviceKind = r.str("device_kind"),
                client = r.strOrNull("client")?.trim()?.ifEmpty { null },
                createdAt = r.long("created_at"),
                lastUsed = r.long("last_used"),
                current = id == current,
                deviceId = r.str("device_id"),
            )
        }
        return SessionList(list, canRevokeOthers = "revoke_others" in features, canForget = FORGET_DEVICE in features)
    }

    /**
     * Forget a device (servers with `forget_device`): every session it holds ends at once and its
     * next sign-in counts as a new device (two-step login again, new-device email).
     * [ForgetResult.current]: this app's own session was one of them, so it is signed out too.
     */
    suspend fun forgetDevice(deviceId: String): ForgetResult {
        val r = post("/account/devices/${urlPart(deviceId)}/forget") as? JsonObject
        return ForgetResult(
            signedOut = (r?.get("signed_out") as? JsonPrimitive)?.contentOrNull?.toIntOrNull() ?: 0,
            current = r?.bool("current") == true,
        )
    }

    /** Sign out one of the account's other sessions (this app's own is "Log out"). */
    suspend fun revokeSession(sessionId: String) {
        api.call("/account/sessions/${urlPart(sessionId)}", null, "DELETE", true, emptyMap())
    }

    /** Sign out every other session of the account at once; this one stays. Returns how many, when the server says. */
    suspend fun revokeOtherSessions(): Int? {
        val r = api.call("/account/sessions/revoke-others", null, "POST", true, emptyMap()) as? JsonObject
        return (r?.get("revoked") as? JsonPrimitive)?.contentOrNull?.toIntOrNull()
    }

    private fun recoveryCodes(r: JsonElement): List<String>? =
        ((r as? JsonObject)?.get("recovery_codes") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.takeIf { it.isNotEmpty() }

    companion object {
        const val REAUTH_HEADER = "x-reauth-token"

        /** The `/api/config` feature of servers that forget a device (`POST /account/devices/{id}/forget`). */
        const val FORGET_DEVICE = "forget_device"
    }
}

/**
 * This device's records after a successful password / Secret Key change of account [id]:
 * - the new bundle (so the next master-password unlock, here and in the autofill and
 *   passkey services, uses the new password),
 * - the stored Secret Key: the new one, or removed when it was turned off,
 * - the two-step "remember this device" token removed (the server forgot all of them).
 * Biometric unlock and "never" keys stay: they hold the account key itself, which a
 * re-wrap doesn't change.
 */
fun Stored.afterKeyChange(id: String, change: KeyChange): Stored {
    val a = accounts[id] ?: return this
    val email = a.email.lowercase()
    // Secret Keys are kept per email: another server's account with this email may still need it.
    val sharedEmail = accounts.any { (k, v) -> k != id && v.email.equals(email, ignoreCase = true) }
    val keys = when {
        change.secretKey != null -> secretKeys + (email to change.secretKey)
        !change.secretKeyEnabled && !sharedEmail -> secretKeys - email
        else -> secretKeys
    }
    return copy(
        accounts = accounts + (id to a.copy(bundle = change.bundleJson)),
        secretKeys = keys,
        rememberTokens = rememberTokens - "${a.server}|$email",
    )
}

private fun JsonArray?.orEmpty(): List<JsonElement> = this ?: emptyList()
