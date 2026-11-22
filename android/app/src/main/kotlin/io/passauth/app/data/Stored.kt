package io.passauth.app.data

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

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
    /**
     * Minutes between background refreshes of the encrypted offline copy (0 = off).
     * One of [BACKGROUND_SYNC_OPTIONS]; older stored settings lack the key and get the default.
     */
    val backgroundSyncMinutes: Int = BACKGROUND_SYNC_DEFAULT,
    /**
     * The server's longest vault timeout (`max_vault_timeout_minutes`) made PassAuth lower
     * [vaultTimeout]; Settings says so until the user picks a timeout again.
     */
    val vaultTimeoutLowered: Boolean = false,
    /**
     * Sign-in request notifications are wanted (Settings → Account security). They also need
     * Android's notifications permission; on by default, so allowing it turns them on.
     */
    val signInNotifications: Boolean = true,
)

const val BACKGROUND_SYNC_DEFAULT = 120

/** Background sync choices (minutes; 0 = off) with their labels. */
val BACKGROUND_SYNC_OPTIONS: List<Pair<Int, String>> = listOf(
    0 to "Off",
    30 to "Every 30 minutes",
    60 to "Every hour",
    120 to "Every 2 hours",
    360 to "Every 6 hours",
    720 to "Every 12 hours",
)

@Serializable
data class Tokens(val access: String, val refresh: String)

/** AES-GCM ciphertext from the Android Keystore (base64). */
@Serializable
data class Sealed(val iv: String, val data: String)

@OptIn(ExperimentalSerializationApi::class)
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
    /** The server's `/api/config` `features` when last asked ([featuresAt], epoch ms); null until then. */
    val features: List<String>? = null,
    val featuresAt: Long = 0,
    /** The server's API version (`/api/config` `api`) asked with [features]; null until then. */
    val api: Int? = null,
    /** The server's account policies when last asked (with [features]); null until then. */
    val policies: Policies? = null,
    /** The server's `limits.max_import_items` asked with [features] (how many items one batch request may name); null until then. */
    val maxImportItems: Int? = null,
    /** How many offline changes wait on this device (the list itself is sealed with the account key); shown before they'd be lost. */
    val pendingChanges: Int = 0,
    /**
     * Before [Stored.rosters]: the roster memory kept in the record (so a log out or another account
     * on the record lost or inherited it). Only read to move it there once ([Stored.migrated]).
     */
    @EncodeDefault(EncodeDefault.Mode.NEVER) val rosterSeen: Long = 0,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val rosterTrusted: String? = null,
)

/**
 * Emergency access: this device's memory of one account's contact roster. [seen] is the highest
 * version it has opened (0: none; never goes down), [trusted] the last roster it trusted, sealed as
 * the server keeps it (null: none).
 */
@Serializable
data class RosterMemory(val seen: Long = 0, val trusted: String? = null)

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
    /** Android was asked for the notifications permission (tells "not asked" from "denied for good"). */
    val notificationsAsked: Boolean = false,
    /** The vault card offering sign-in request notifications was dismissed (device-wide, kept). */
    val pushOfferDismissed: Boolean = false,
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
    /**
     * Emergency access roster memory by account, keyed [rosterKey] (server and the account's user
     * id): outside the account records, so a log out, signing in again or another account on the
     * same record neither loses nor inherits it (the web vault's `pa.roster.<userId>`).
     */
    val rosters: Map<String, RosterMemory> = emptyMap(),
    /**
     * Signed sharing memory by account, keyed [rosterKey] like [rosters] (untouched by log out; gone
     * with the account): the highest key-pins version opened here and the rosters trusted per vault.
     */
    val signing: Map<String, SigningMemory> = emptyMap(),
) {
    val active: AccountData? get() = accounts[activeId]

    /** The roster memory of user [userId] on [server] (none yet: version 0). */
    fun roster(server: String, userId: String): RosterMemory = rosters[rosterKey(server, userId)] ?: rosters[rawKey(server, userId)] ?: RosterMemory()

    /** Remember a roster this device trusts for user [userId] on [server]: never below the version it already opened. */
    fun rememberingRoster(server: String, userId: String, version: Long, sealed: String?): Stored {
        if (server.isEmpty() || userId.isEmpty() || version < roster(server, userId).seen) return this
        return copy(rosters = rosters - rawKey(server, userId) + (rosterKey(server, userId) to RosterMemory(version, sealed)))
    }

    /** Without the roster and signed-sharing memory of user [userId] on [server] (the account was deleted). */
    fun forgettingRoster(server: String, userId: String): Stored =
        copy(rosters = rosters - rosterKey(server, userId) - rawKey(server, userId), signing = signing - rosterKey(server, userId) - rawKey(server, userId))

    /** The signed-sharing memory of user [userId] on [server] (none yet: empty). */
    fun signingMemory(server: String, userId: String): SigningMemory {
        val canonical = signing[rosterKey(server, userId)]
        val raw = rawKey(server, userId).takeIf { it != rosterKey(server, userId) }?.let { signing[it] }
        // Memory kept under the address as it was typed before (Info): merged in, never lost.
        return when {
            canonical == null -> raw ?: SigningMemory()
            raw == null -> canonical
            else -> canonical.merge(raw)
        }
    }

    /** [transform] applied to the signed-sharing memory of user [userId] on [server]. */
    fun updatingSigning(server: String, userId: String, transform: (SigningMemory) -> SigningMemory): Stored {
        if (server.isEmpty() || userId.isEmpty()) return this
        return copy(signing = signing - rawKey(server, userId) + (rosterKey(server, userId) to transform(signingMemory(server, userId))))
    }

    /**
     * Roster memory still kept in account records (before [rosters]) moved out once: to the user id
     * of the record's current account (its bundle's `account_id`), or dropped when that's unknown.
     */
    fun migrated(): Stored {
        if (accounts.values.none { it.rosterSeen != 0L || it.rosterTrusted != null }) return this
        var out = rosters
        val records = accounts.mapValues { (_, a) ->
            if (a.rosterSeen == 0L && a.rosterTrusted == null) return@mapValues a
            val uid = bundleUserId(a.bundle)
            if (uid != null && a.server.isNotEmpty()) {
                val key = rosterKey(a.server, uid)
                if (a.rosterSeen >= (out[key]?.seen ?: 0)) out = out + (key to RosterMemory(a.rosterSeen, a.rosterTrusted))
            }
            a.copy(rosterSeen = 0, rosterTrusted = null)
        }
        return copy(accounts = records, rosters = out)
    }

    /**
     * Show the permissions screen: only on a first launch (never shown, and no server
     * connected yet). Later changes go through Android's settings.
     */
    val showPermissionsIntro: Boolean
        get() = !onboarding.permissionsShown && accounts.values.none { it.server.isNotEmpty() }

    /** The longest vault timeout the signed-in accounts' servers allow (the strictest; 0 = no limit). */
    val timeoutLimit: Int
        get() = PolicyRules.timeoutLimit(accounts.values.filter { it.tokens != null }.map { it.policies })

    /**
     * Account [id]'s two-step "remember this device" token removed (the server forgot it: the
     * device was forgotten, or the keys changed).
     */
    fun withoutRememberToken(id: String): Stored {
        val a = accounts[id] ?: return this
        return copy(rememberTokens = rememberTokens - "${a.server}|${a.email.lowercase()}")
    }

    /**
     * A sign-in on record [id]: its account's email, tokens and bundle, the other records of the same
     * account ([dupes]) dropped. Roster memory ([rosters]) is the account's, not the record's: untouched.
     */
    fun signedIn(id: String, email: String, tokens: Tokens, bundle: String, dupes: Set<String>): Stored {
        val a = (accounts[id] ?: AccountData()).copy(email = email, tokens = tokens, bundle = bundle, biometric = null, persistedKeys = null)
        return copy(activeId = id, accounts = accounts - dupes + (id to a))
    }

    /** Record [id] removed (log out with other accounts listed); the next signed-in one becomes active. [rosters] stay. */
    fun withoutRecord(id: String): Stored {
        val rest = accounts - id
        val next = if (activeId == id) rest.entries.firstOrNull { it.value.tokens != null }?.key ?: rest.keys.firstOrNull() ?: "" else activeId
        return copy(accounts = rest, activeId = next)
    }

    /** Record [id] signed out but kept (the last account: the sign-in screen remembers server and email). [rosters] stay. */
    fun signedOutRecord(id: String): Stored {
        val a = accounts[id] ?: return this
        return copy(accounts = accounts + (id to a.copy(tokens = null, biometric = null, bundle = null, lastSync = 0, pendingChanges = 0)))
    }

    companion object {
        /** Memory keys use the server address normalized (scheme and host in lower case, no default port or trailing slash), so another spelling of it keeps its memory. */
        fun rosterKey(server: String, userId: String) = "${serverKey(server)}|$userId"

        /** The key as earlier versions wrote it (the address as stored), read and replaced on write. */
        internal fun rawKey(server: String, userId: String) = "$server|$userId"

        internal fun serverKey(server: String): String =
            runCatching { VaultRepository.normalizeServer(server) }.getOrNull() ?: server.trim().trimEnd('/')

        /** The user id (`account_id`) of an account bundle; null when there's none or it can't be read. */
        fun bundleUserId(bundle: String?): String? = bundle?.let {
            runCatching { ((AppJson.parseToJsonElement(it) as? JsonObject)?.get("account_id") as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.getOrNull()
        }?.takeIf { it.isNotEmpty() }
    }
}
