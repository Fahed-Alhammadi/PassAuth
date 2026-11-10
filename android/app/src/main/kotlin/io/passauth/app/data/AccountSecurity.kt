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
    fun rewrap(bundleJson: String, newPassword: String, withSecretKey: Boolean, existingSecretKey: String?): Rewrapped
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
     * ([weakConfirmed] false) and accepted when the user submits it again.
     */
    fun problem(current: String, next: String, confirm: String, bits: Double, weakConfirmed: Boolean): String? = when {
        current.isEmpty() -> "Enter your current master password."
        next.length < MIN_LENGTH -> "Use at least $MIN_LENGTH characters for your new master password."
        next != confirm -> "The new passwords don't match. Type the same password in both fields."
        bits < WEAK_BITS && !weakConfirmed -> WEAK_MESSAGE
        else -> null
    }
}

/** User-facing wording for errors of these settings (the web vault's `friendlyError`). */
fun securityErrorMessage(e: Throwable): String? = when {
    e is ApiException && e.status == 429 -> "Too many attempts, try again later."
    e is ApiException && e.message == "invalid code" -> "That code didn't work. Enter the code that's showing now and try again."
    e is ApiException && e.message == "start setup first" -> "The setup expired. Cancel and start setup again."
    e is ApiException && e.message == "reauth_required" -> "Your confirmation expired. Enter your master password again."
    e is ApiException && e.message == "email is not configured on this server" ->
        "This server isn't set up to send email, so email codes aren't available."
    e is ApiException && e.status == 409 && e.message.orEmpty().startsWith("authenticator app already enabled") ->
        "The authenticator app is already on. Turn it off first to set it up again."
    else -> null
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
     * the Secret Key stays on; without one a new key is created.
     */
    suspend fun changeKeys(
        email: String,
        bundleJson: String,
        currentPassword: String,
        newPassword: String,
        choice: SecretKeyChoice,
        secretKey: String?,
    ): KeyChange {
        val currentlyOn = AppJson.parseToJsonElement(bundleJson).jsonObject.bool("secret_key_enabled")
        val withSecretKey = choice.enabledAfter(currentlyOn)
        val token = reauth(email, currentPassword, secretKey)
        // Keep the same Secret Key only when it stays on; turning it on (again) makes a new one.
        val existing = secretKey.takeIf { currentlyOn && choice == SecretKeyChoice.Keep }
        crypto.rewrap(bundleJson, newPassword, withSecretKey, existing).use { next ->
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

    suspend fun totpSetup(): TotpSetup {
        val o = post("/account/2fa/totp/setup").jsonObject
        return TotpSetup(o.str("secret"), o.str("uri"))
    }

    /** Turns the authenticator on; the first method returns recovery codes (shown once). */
    suspend fun totpEnable(code: String): List<String>? {
        val c = TwoFactor.cleanCode(code)
        if (!TwoFactor.validTotp(c)) throw UserException("Enter the 6-digit code from your authenticator app.")
        return recoveryCodes(post("/account/2fa/totp/enable", buildJsonObject { put("code", c) }))
    }

    suspend fun emailSetup() {
        post("/account/2fa/email/setup")
    }

    suspend fun emailEnable(code: String): List<String>? {
        val c = TwoFactor.cleanCode(code)
        if (c.isEmpty()) throw UserException("Enter the code from the email we sent you.")
        return recoveryCodes(post("/account/2fa/email/enable", buildJsonObject { put("code", c) }))
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
        api.call("/account/2fa/passkey/${java.net.URLEncoder.encode(keyId, "UTF-8").replace("+", "%20")}", null, "DELETE", true, mapOf(REAUTH_HEADER to token))
    }

    private fun recoveryCodes(r: JsonElement): List<String>? =
        ((r as? JsonObject)?.get("recovery_codes") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.takeIf { it.isNotEmpty() }

    companion object {
        const val REAUTH_HEADER = "x-reauth-token"
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
