package io.passauth.app.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull

/*
 * Account policies set by the server's admin (`GET /api/config` `policies`, and `GET /account` `policy_violations` for what an account still has
 * to change; the server side is `crates/server/src/policies.rs`), and what the app does with them.
 *
 * Enforced by the server: two-step login (403 `two_step_required` on everything but setting a
 * method up, reading the account and signing out), a Secret Key and the key-derivation minimums
 * for new account keys (400 `secret_key_required` / `kdf_too_weak`). Applied by the app: the
 * master password length, the longest vault timeout and export. A value the server doesn't send
 * has its default, which changes nothing. Mirrors the web vault's
 * `policies.ts` and the iOS app's `Shared/Policies.swift`; pure, JVM-tested in PoliciesTest.
 */

/** The server's account policies (defaults: no policy). Kept with each account. */
@Serializable
data class Policies(
    /** Every account must use two-step login. */
    val requireTwoStep: Boolean = false,
    /** New account keys (registration, master password or Secret Key change) must use a Secret Key. */
    val requireSecretKey: Boolean = false,
    /** Least Argon2id memory (MiB) and passes for new account keys. */
    val minKdfMemoryMib: Int = PolicyRules.DEFAULT_KDF_MEMORY_MIB,
    val minKdfIterations: Int = PolicyRules.DEFAULT_KDF_ITERATIONS,
    /** Shortest master password the apps accept for a new one; never below [MasterPasswordRules.MIN_LENGTH]. */
    val masterPasswordMinLength: Int = MasterPasswordRules.MIN_LENGTH,
    /** Longest vault timeout the apps offer, in minutes; 0 = no limit. */
    val maxVaultTimeoutMinutes: Int = 0,
    /** The apps don't offer exporting the vault. */
    val disableExport: Boolean = false,
)

/** What an account still has to change for the server's policies (`GET /account` `policy_violations`). */
enum class Violation(val wire: String) { TwoStep("two_step"), SecretKey("secret_key"), Kdf("kdf") }

/** Where the app fixes a violation. */
enum class PolicyFix { TwoStep, ChangePassword }

/** One line of the policy notice, with the place that fixes it when this app can. */
data class PolicyNotice(val violation: Violation, val text: String, val action: String? = null, val fix: PolicyFix? = null)

/**
 * A server's minimums for new account keys (`policies.min_kdf_memory_mib` / `min_kdf_iterations`),
 * handed to the core's `createAccountWithKdf` / `Account.rewrapWithKdf`, which make keys with
 * memory = max(128 MiB, minimum) and passes = max(3, minimum).
 */
data class KdfMinimums(val memoryMib: Int, val iterations: Int)

/**
 * `GET /api/config` as the app reads it: sign-ups, features, the API version ([api]: null when the
 * server sent no number) and policies.
 */
data class ServerConfig(
    val signupsAllowed: Boolean?,
    val features: List<String>,
    val policies: Policies,
    val api: Int? = null,
    /** `/api/config` `limits` as sent (Send and attachment sizes are read from it). */
    val limits: JsonObject? = null,
) {
    /** `limits.max_import_items`: how many items one batch request may name; null when the server doesn't say. */
    val maxImportItems: Int?
        get() = (limits?.get("max_import_items") as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() && it >= 1 }?.toInt()

    companion object {
        fun parse(o: JsonObject): ServerConfig {
            val features = (o["features"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            return ServerConfig(
                signupsAllowed = (o["signups_allowed"] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull,
                features = features,
                policies = PolicyRules.read(o["policies"]),
                api = (o["api"] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() }?.toInt(),
                limits = o["limits"] as? JsonObject,
            )
        }
    }
}

/**
 * Whether website icons (`/api/icons/<host>`) are shown and asked for: the user's setting and the
 * server's icon service together (the web vault's `siteIconsShown`). Servers list the service as
 * the feature `icons` (only while it is on); before the account's config is known (no feature
 * list, or one kept without its API version) the setting alone decides (a missing icon just shows
 * the letter).
 */
object SiteIcons {
    const val FEATURE = "icons"

    fun shown(wanted: Boolean, api: Int?, features: List<String>?): Boolean {
        if (!wanted) return false
        if (features == null || api == null) return true
        return FEATURE in features
    }
}

object PolicyRules {
    const val DEFAULT_KDF_MEMORY_MIB = 64
    const val DEFAULT_KDF_ITERATIONS = 3

    /** The server's ceiling for `max_vault_timeout_minutes` (30 days). */
    private const val MAX_TIMEOUT_MINUTES = 43_200

    /** A whole number from the server, kept within [min]..[max]; anything else (missing, text, a fraction) is [fallback]. */
    private fun whole(v: JsonElement?, min: Int, max: Int, fallback: Int): Int {
        val p = v as? JsonPrimitive ?: return fallback
        if (p.isString) return fallback
        val d = p.doubleOrNull ?: return fallback
        if (!d.isFinite() || d != kotlin.math.floor(d)) return fallback
        return d.coerceIn(min.toDouble(), max.toDouble()).toInt()
    }

    private fun flag(v: JsonElement?) = (v as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull == true

    /** The server's `policies` object, with the defaults for a value it didn't send (or sent in another shape). */
    fun read(value: JsonElement?): Policies {
        val p = value as? JsonObject ?: return Policies()
        val d = Policies()
        return Policies(
            requireTwoStep = flag(p["require_two_step"]),
            requireSecretKey = flag(p["require_secret_key"]),
            minKdfMemoryMib = whole(p["min_kdf_memory_mib"], d.minKdfMemoryMib, 1024, d.minKdfMemoryMib),
            minKdfIterations = whole(p["min_kdf_iterations"], d.minKdfIterations, 20, d.minKdfIterations),
            masterPasswordMinLength = whole(p["master_password_min_length"], MasterPasswordRules.MIN_LENGTH, 128, MasterPasswordRules.MIN_LENGTH),
            maxVaultTimeoutMinutes = whole(p["max_vault_timeout_minutes"], 0, MAX_TIMEOUT_MINUTES, 0),
            disableExport = flag(p["disable_export"]),
        )
    }

    /** Characters a new master password needs: the server's minimum, never below the apps' own. */
    fun minPasswordLength(p: Policies?): Int = maxOf(MasterPasswordRules.MIN_LENGTH, p?.masterPasswordMinLength ?: 0)

    /** Whether the app offers exporting the vault (the server's admin can turn it off). */
    fun exportAllowed(p: Policies?): Boolean = p?.disableExport != true

    /** The minimums new account keys must meet (the policy is clamped to the core's 64–1024 MiB and 3–20 passes when read). */
    fun kdfMinimums(p: Policies): KdfMinimums = KdfMinimums(p.minKdfMemoryMib, p.minKdfIterations)

    /** The minimums from a server's config; null without the `policies` feature (the core's defaults then). */
    fun kdfMinimums(config: ServerConfig?): KdfMinimums? = config?.policies?.let(::kdfMinimums)

    // ---------------------------------------------------------- vault timeout

    /**
     * The longest vault timeout the device may use: the strictest positive limit among the
     * signed-in accounts' servers (the timeout locks every account at once); 0 = no limit.
     */
    fun timeoutLimit(policies: List<Policies?>): Int = policies.mapNotNull { it?.maxVaultTimeoutMinutes?.takeIf { m -> m > 0 } }.minOrNull() ?: 0

    /** Whether [value] locks the vault within [maxMinutes] of inactivity (0 = no limit: every choice does). */
    fun timeoutWithin(value: VaultTimeout, maxMinutes: Int): Boolean {
        if (maxMinutes <= 0 || value == VaultTimeout.Immediately) return true
        val m = value.minutes ?: return false
        return m <= maxMinutes
    }

    /** The choices to offer under the limit, short to long. */
    fun timeoutOptions(maxMinutes: Int): List<VaultTimeout> = VaultTimeout.entries.filter { timeoutWithin(it, maxMinutes) }

    /** The choice that applies: [value], or the longest choice within the limit when it is above it. */
    fun clampTimeout(value: VaultTimeout, maxMinutes: Int): VaultTimeout {
        if (timeoutWithin(value, maxMinutes)) return value
        return timeoutOptions(maxMinutes).maxByOrNull { it.minutes ?: 0 } ?: VaultTimeout.Immediately
    }

    /** "45 minutes", "1 hour", "4 hours", "30 days": a limit in words. */
    fun minutesLabel(minutes: Int): String {
        fun plural(n: Int, unit: String) = "$n $unit${if (n == 1) "" else "s"}"
        return when {
            minutes >= 1440 && minutes % 1440 == 0 -> plural(minutes / 1440, "day")
            minutes >= 60 && minutes % 60 == 0 -> plural(minutes / 60, "hour")
            else -> plural(minutes, "minute")
        }
    }

    fun limitNote(maxMinutes: Int) = "Your server allows at most ${minutesLabel(maxMinutes)} before the vault locks."

    fun loweredNote(value: VaultTimeout) = "Your previous choice was longer, so it was lowered to ${value.label}."

    // -------------------------------------------------------------- violations

    /** The known violations in a fixed order; unknown or repeated entries (and servers without the list) give none. */
    fun readViolations(value: JsonElement?): List<Violation> {
        val list = (value as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }?.toSet() ?: return emptyList()
        return Violation.entries.filter { it.wire in list }
    }

    /** The notice lines for an account's violations, each with the place that fixes it. */
    fun notices(violations: List<Violation>): List<PolicyNotice> = violations.map { v ->
        when (v) {
            Violation.TwoStep -> PolicyNotice(v, "Your server requires two-step login.", "Set up two-step login", PolicyFix.TwoStep)
            Violation.SecretKey -> PolicyNotice(v, "Your server asks you to turn on a Secret Key.", "Turn on a Secret Key", PolicyFix.ChangePassword)
            // New keys always meet the server's minimums (the core makes them), so a password change fixes it.
            Violation.Kdf -> PolicyNotice(v, KDF_NOTICE, "Change master password", PolicyFix.ChangePassword)
        }
    }

    /** Identifies a set of violations, so a dismissed notice comes back when the set changes. */
    fun violationsKey(violations: List<Violation>): String = violations.joinToString(",") { it.wire }

    // ------------------------------------------------------------------ errors

    const val SECRET_KEY_REQUIRED_MESSAGE = "Your server requires a Secret Key. Turn on \"Use a Secret Key\" and try again."
    const val KDF_NOTICE =
        "Your server asks you to update your account's encryption settings. Change your master password to update them. You can keep the same password."
    const val KDF_SAME_PASSWORD_NOTE =
        "Your server asks for new encryption settings. Changing your master password applies them: you can enter your current password again as the new one."
    const val KDF_TOO_WEAK_MESSAGE = "Your server's encryption settings have changed. Try again."
    const val TWO_STEP_REQUIRED_MESSAGE = "Your server requires two-step login. Set it up to continue."
    const val SECRET_KEY_POLICY_NOTE = "Your server requires a Secret Key."
    const val EXPORT_OFF_NOTE = "Exporting is turned off by your server's admin."
    const val EXPORT_OFF_PAGE = "Your server's admin turned off exporting the vault."

    /** The plain message for a policy error answer, or null for any other error. */
    fun errorMessage(e: Throwable): String? = when {
        e !is ApiException -> null
        e.status == 400 && e.hasCode("secret_key_required") -> SECRET_KEY_REQUIRED_MESSAGE
        e.status == 400 && e.hasCode("kdf_too_weak") -> KDF_TOO_WEAK_MESSAGE
        TwoStepGate.blocks(e) -> TWO_STEP_REQUIRED_MESSAGE
        else -> null
    }
}

/**
 * The server requires two-step login and the account has none: every request but setting a method
 * up, reading the account and signing out answers 403 `two_step_required`, the live-sync socket
 * too. The app then shows a screen that only sets a method up or signs out (pure, unit-tested).
 */
object TwoStepGate {
    const val CODE = "two_step_required"

    /** Whether an answer is the server's "set up two-step login first". */
    fun blocks(e: Throwable): Boolean = e is ApiException && e.status == 403 && e.hasCode(CODE)

    /** What follows "Continue" once a method is on. */
    enum class Next {
        /** The account keys are in memory (the gate came up at sign-in, unlock or while the vault was open): sync and open the vault. */
        Sync,

        /** No keys in memory (the account was locked): leave the gate and ask to unlock. */
        Unlock,
    }

    fun afterSetup(keysInMemory: Boolean): Next = if (keysInMemory) Next.Sync else Next.Unlock

    /** The gate replaces the vault and the unlock screen of a signed-in account. */
    fun shows(status: Status, gated: Boolean): Boolean = gated && (status == Status.Unlocked || status == Status.Locked)

    /** Live sync runs only for an unlocked account the server lets in (the socket would be refused, in a loop). */
    fun liveSyncAllowed(status: Status, gated: Boolean): Boolean = status == Status.Unlocked && !gated

    const val TITLE = "Your server requires two-step login"
    const val HINT = "You get recovery codes with your first method. Keep them somewhere safe: they let you sign in if you lose it."
    const val DONE_TITLE = "Two-step login is on"
    const val DONE_TEXT = "Your vault can open now."

    fun intro(email: String): String =
        (if (email.isNotBlank()) "Set up a second step for $email to open your vault. " else "Set up a second step to open your vault. ") +
            "It's asked for after your master password when you sign in on a new device, so a stolen password isn't enough."
}
