package io.passauth.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

const val MAX_ACCOUNTS = 5

/** Vault timeout, like the extension's (minutes of inactivity, or a special trigger). */
@Serializable
enum class VaultTimeout(val label: String, val minutes: Int?) {
    @SerialName("immediately") Immediately("Immediately", 0),
    @SerialName("1") Min1("1 minute", 1),
    @SerialName("5") Min5("5 minutes", 5),
    @SerialName("15") Min15("15 minutes", 15),
    @SerialName("30") Min30("30 minutes", 30),
    @SerialName("60") Hour1("1 hour", 60),
    @SerialName("240") Hour4("4 hours", 240),
    @SerialName("restart") Restart("On app restart", null),
    @SerialName("never") Never("Never", null),
}

@Serializable
enum class TimeoutAction {
    @SerialName("lock") Lock,
    @SerialName("logout") Logout,
}

@Serializable
enum class ThemeMode {
    @SerialName("system") System,
    @SerialName("light") Light,
    @SerialName("dark") Dark,
}

/** App settings (shared by all accounts), mirroring the extension's `Settings`. */
@Serializable
data class Settings(
    val vaultTimeout: VaultTimeout = VaultTimeout.Min15,
    val timeoutAction: TimeoutAction = TimeoutAction.Lock,
    val autoCopyTotp: Boolean = true,
    /** Seconds; 0 = never. */
    val clearClipboard: Int = 30,
    val showIcons: Boolean = true,
    /** Resolves a website's "default" match; never [UrlMatch.Default] itself. */
    val defaultMatch: UrlMatch = UrlMatch.Domain,
    val theme: ThemeMode = ThemeMode.System,
    /** Offer to save new logins and update changed passwords (autofill save prompt). */
    val askToSave: Boolean = true,
    /**
     * Never offer to save on these: a website's base domain ("example.com") or an
     * app as `androidapp://<package>`. Like the extension's never-save list.
     */
    val neverSave: List<String> = emptyList(),
)

@Serializable
data class Tokens(val access: String, val refresh: String)

/** AES-GCM ciphertext from the Android Keystore (base64). */
@Serializable
data class Sealed(val iv: String, val data: String)

@Serializable
data class AccountData(
    val server: String = "",
    val email: String = "",
    /** Profile name, for the account initials. */
    val name: String = "",
    val tokens: Tokens? = null,
    val lastSync: Long = 0,
    /** The account bundle (encrypted keys) from the server, as JSON. */
    val bundle: String? = null,
    /** `Account.toSessionBytes()` wrapped by a biometric-bound Keystore key. */
    val biometric: Sealed? = null,
    /** Unlocked keys (base64), only while the vault timeout is "never". */
    val persistedKeys: String? = null,
)

/**
 * First-launch "Set up PassAuth" (permissions) screen, shared by all accounts.
 * [cameraAsked] tells "not asked yet" from "denied for good" (Android reports
 * neither as needing a rationale). [offerBiometric]: the user chose fingerprint /
 * face unlock there, so it's offered once after the next sign-in or unlock.
 */
@Serializable
data class Onboarding(
    val permissionsShown: Boolean = false,
    val cameraAsked: Boolean = false,
    val offerBiometric: Boolean = false,
)

/** Everything the app keeps on disk; the whole file is encrypted with a Keystore key. */
@Serializable
data class Stored(
    val deviceId: String = "",
    val activeId: String = "",
    val accounts: Map<String, AccountData> = emptyMap(),
    /** Two-step "remember this device" tokens, keyed `server|email`. */
    val rememberTokens: Map<String, String> = emptyMap(),
    /** Secret Keys typed at sign-in, keyed by `email`. */
    val secretKeys: Map<String, String> = emptyMap(),
    val settings: Settings = Settings(),
    val onboarding: Onboarding = Onboarding(),
) {
    val active: AccountData? get() = accounts[activeId]

    /**
     * Show the permissions screen: only on a first launch (never shown, and no server
     * connected yet — people who already use the app find it in Settings → Permissions).
     */
    val showPermissionsIntro: Boolean
        get() = !onboarding.permissionsShown && accounts.values.none { it.server.isNotEmpty() }
}
