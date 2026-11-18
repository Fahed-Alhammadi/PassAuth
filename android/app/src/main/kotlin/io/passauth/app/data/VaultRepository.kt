package io.passauth.app.data

import android.os.Build
import androidx.compose.ui.graphics.ImageBitmap
import io.passauth.core.Account
import io.passauth.core.ApprovedLogin
import io.passauth.core.CoreException
import io.passauth.core.EncryptedItem
import io.passauth.core.LoginRequestKey
import io.passauth.core.MasterKeys
import io.passauth.core.VaultKey
import io.passauth.core.createAccountWithKdf
import io.passauth.core.deriveMasterKeys
import io.passauth.core.itemRevCheck
import io.passauth.core.newId
import io.passauth.core.opaqueLoginFinish
import io.passauth.core.opaqueLoginStart
import io.passauth.core.opaqueRegisterFinish
import io.passauth.core.opaqueRegisterStart
import java.util.UUID
import javax.crypto.Cipher
import kotlin.io.encoding.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.getAndUpdate
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

enum class Status { Setup, LoggedOut, Locked, Unlocked }

data class AccountSummary(
    val id: String,
    val email: String,
    val name: String,
    val server: String,
    val status: Status,
    /** The account's profile picture kept on this device; null: initials. */
    val avatar: ImageBitmap? = null,
)

/** What the UI needs to know about accounts and settings (no secrets). */
data class AppState(
    val loaded: Boolean = false,
    val status: Status = Status.Setup,
    val activeId: String = "",
    /** Signed-in (or signed-out but remembered) accounts on this device. */
    val accounts: List<AccountSummary> = emptyList(),
    val name: String = "",
    val server: String = "",
    val email: String = "",
    val secretKeyRequired: Boolean = false,
    val secretKeyStored: Boolean = false,
    val biometricEnabled: Boolean = false,
    val settings: Settings = Settings(),
    val lastSync: Long = 0,
    val onboarding: Onboarding = Onboarding(),
    val showPermissionsIntro: Boolean = false,
    /**
     * The active account's server requires two-step login and the account has none yet (403
     * `two_step_required`): the app shows only the setup screen ([TwoStepGate]). Memory only.
     */
    val twoStepRequired: Boolean = false,
    /** The active account's server's policies (defaults when unknown or from servers without them). */
    val policies: Policies = Policies(),
    /** The longest vault timeout the signed-in accounts' servers allow (minutes; 0 = no limit). */
    val timeoutLimit: Int = 0,
    /** Website icons are shown: the user's setting and the active account's server's icon service ([SiteIcons]). */
    val showSiteIcons: Boolean = true,
    /** The active account's profile picture kept on this device; null: initials. */
    val avatar: ImageBitmap? = null,
    /** The active account's server keeps profile pictures (`/api/config` feature [AvatarRules.FEATURE]). */
    val avatarAvailable: Boolean = false,
)

/** A decrypted item of the active account. */
data class Entry(
    val id: String,
    val item: Item,
    val vaultId: String,
    val revision: Long,
    val enc: EncryptedItem,
)

enum class Role { Owner, Admin, Write, Read }

/**
 * A vault the active account can open. [keyKind] is `account` for a vault key
 * wrapped with this account's own key (only this account can have made it) and
 * `sealed` for a key someone shared with it.
 */
data class VaultInfo(
    val id: String,
    val name: String,
    val role: Role,
    val keyKind: String = KEY_KIND_ACCOUNT,
    /**
     * The epoch of the vault key this device holds, from `/sync` (API v2: goes up by one with
     * every key replacement); null from older servers. Writes encrypted under that key carry it
     * (`key_epoch`), so the server refuses them once the key was replaced ([ItemWrites]).
     */
    val keyEpoch: Long? = null,
    /** The server asks for a new key of this vault (`rotation_pending`: a member or an emergency contact who held it left). */
    val rotationPending: Boolean = false,
    /** How far its key was checked (signed sharing); [VaultTrust.Unchecked] on servers without it. */
    val trust: VaultTrust = VaultTrust.Unchecked,
    /** How its items stand against the vault's manifest ([Manifests]); [ManifestState.Unresolved]: warned, no writes. */
    val manifest: ManifestState = ManifestState.None,
) {
    val personal: Boolean get() = keyKind == KEY_KIND_ACCOUNT

    companion object {
        const val KEY_KIND_ACCOUNT = "account"

        /**
         * Where new items go when the user didn't pick a vault (autofill saves, passkeys,
         * the editor's default): the account's own vault, never a vault someone else shared,
         * so another user (or the server) can't make itself the place new logins land.
         */
        fun defaultSaveVault(vaults: List<VaultInfo>): VaultInfo? =
            vaults.firstOrNull { it.personal && it.role == Role.Owner } ?: vaults.firstOrNull { it.personal && it.role != Role.Read }
    }
}

/**
 * What replacing vault keys did: [rotated] vaults got a new key; [shared] (names) are shared with
 * other people, so this app can't replace their keys; [unreadable] (names) were left as they are
 * because their name didn't decrypt (a new key would lose it).
 */
data class RotationReport(
    val rotated: Int,
    val shared: List<String> = emptyList(),
    val unreadable: List<String> = emptyList(),
    /**
     * Vaults whose new key waits for the user to review its members (the first signed member list:
     * every member's fingerprint; or people the signed list names but the server no longer lists).
     */
    val reviews: List<MemberReview> = emptyList(),
) {
    /** What's left for the user, in words; null when every vault got its new key. */
    val leftover: String?
        get() {
            val parts = mutableListOf<String>()
            if (shared.isNotEmpty()) parts += sharedText(shared)
            if (reviews.isNotEmpty()) parts += reviewText(reviews.map { it.vaultName })
            if (unreadable.isNotEmpty()) {
                parts += "The name of ${names(unreadable)} couldn't be decrypted on this phone, so ${if (unreadable.size == 1) "its key wasn't" else "their keys weren't"} " +
                    "replaced: a new key would lose the name. Sync and try again, or replace ${if (unreadable.size == 1) "it" else "them"} in the web vault."
            }
            return parts.takeIf { it.isNotEmpty() }?.joinToString(" ")
        }

    companion object {
        val NONE = RotationReport(0)

        private fun names(list: List<String>) = if (list.size == 1) list[0] else list.dropLast(1).joinToString(", ") + " and " + list.last()

        /** Why vaults shared with others get their new keys elsewhere (servers without signed sharing, or sharing paused). */
        fun sharedText(shared: List<String>): String =
            if (shared.size == 1) "${shared[0]} is shared, so replace its key in the web vault or the desktop app."
            else "${names(shared)} are shared, so replace their keys in the web vault or the desktop app."

        /** Vaults whose members the user checks first (Settings → Emergency access → Replace keys). */
        fun reviewText(vaults: List<String>): String =
            "Check who can open ${names(vaults)} before ${if (vaults.size == 1) "its key is" else "their keys are"} replaced: open Replace keys again."
    }
}

/** The unlocked vault of the active account. */
data class VaultData(
    val entries: List<Entry> = emptyList(),
    val vaults: List<VaultInfo> = emptyList(),
    val revision: Long = 0,
    /** Shown from the on-device copy because the server couldn't be reached. */
    val offline: Boolean = false,
    /** Vaults shared with the account and waiting for it to accept or decline (servers with `vault_invitations`). */
    val invitations: List<Invitation> = emptyList(),
    /** Items the server sent in an older version than this phone saw ([ItemRevs]): shown with a warning. */
    val rolledBack: Set<String> = emptySet(),
    /** For some of [rolledBack] this phone kept the newer copy it had (instead of the one served). */
    val keptNewer: Boolean = false,
    /** Why the server isn't asked ([ServerSupport.UPDATE_SERVER]) while the copy on this phone is shown; null: it just couldn't be reached. */
    val syncProblem: String? = null,
) {
    /** Vaults whose items don't match the vault's manifest ([Manifests.WARNING]): shown, never written to. */
    val unresolved: List<VaultInfo> get() = vaults.filter { it.manifest == ManifestState.Unresolved }

    /** The sync-level notice about [rolledBack], or null. */
    val rollbackNotice: String? get() = ItemRevs.notice(rolledBack, keptNewer)

    val folders: List<String> get() = entries.mapNotNull { it.item.folder?.takeIf(String::isNotEmpty) }.distinct().sorted()
    fun get(id: String) = entries.firstOrNull { it.id == id }
    fun vaultName(id: String) = vaults.firstOrNull { it.id == id }?.name ?: "Vault"
    fun canWrite(e: Entry) = vaults.firstOrNull { it.id == e.vaultId }?.role != Role.Read

    /**
     * Is [e] in the account's own vault, and editable? Only such logins may become the default
     * place a typed login or a new passkey is saved: anyone on the server can share a vault with
     * this account and put a login for a site in it.
     */
    fun isOwn(e: Entry) = vaults.firstOrNull { it.id == e.vaultId }?.let { it.personal && it.role != Role.Read } == true

    /**
     * Is [e] in one of the account's own vaults (key wrapped with its own key), whatever the role?
     * Only such logins' regular-expression websites are used for matching (`AutofillMatcher`);
     * a login whose vault is unknown counts as somebody else's.
     */
    fun isPersonal(e: Entry) = vaults.firstOrNull { it.id == e.vaultId }?.personal == true
    val writable: List<VaultInfo> get() = vaults.filter { it.role != Role.Read }
    val defaultVault: VaultInfo? get() = VaultInfo.defaultSaveVault(vaults)
}

sealed interface LoginResult {
    data object Done : LoginResult
    data class TwoFactor(val token: String, val providers: List<String>) : LoginResult

    /** A device sign-in was approved: the code the approving app shows comes next ([VaultRepository.deviceCode]). */
    data object CodeNeeded : LoginResult
}

data class Registered(val secretKey: String?, val emailVerificationRequired: Boolean)

/**
 * A sign-in this device asked another device to approve ([VaultRepository.beginDeviceLogin]),
 * for account record [record]. Its key never leaves memory (it can't be saved), so the request
 * ends with the process; [close] drops it.
 */
class DeviceLoginRequest internal constructor(
    val record: String,
    val id: String,
    val email: String,
    /** The five words this device shows, from its own key. */
    val phrase: String,
    /** Unix seconds, this device's clock: never more than 15 minutes after the request was made ([DeviceLogin.deadline]). */
    val expiresAt: Long,
    internal val accessCode: String,
    internal val key: LoginRequestKey,
) : AutoCloseable {
    override fun close() = key.destroy()

    override fun toString() = "DeviceLoginRequest($id)"
}

/**
 * An approved device sign-in waiting for the code the approving app shows
 * ([VaultRepository.confirmDeviceCode]): the account key that came with it stays inside [approved]
 * (Rust), and nothing is unlocked, signed in or stored before the code is confirmed. [email] is the
 * one typed on this device; [session] the server's sign-in answer (tokens, bundle).
 */
class DeviceCodeRequest internal constructor(
    val record: String,
    val email: String,
    internal val approved: ApprovedLogin,
    internal val session: JsonObject,
    internal val bundle: String,
    /** "Remember this device" from two-step login (key and token): kept only once the code is confirmed. */
    internal val rememberToken: Pair<String, String>?,
) : AutoCloseable {
    override fun close() = approved.destroy()

    override fun toString() = "DeviceCodeRequest($record)"
}

/** Unlocked keys of one account, in memory only (Rust handles); [sharing]: its signed sharing (servers with it). */
private class Session(val accountId: String, val account: Account) {
    var sharing: SharingSession? = null

    /**
     * From before this unlock (read when the session opened): [earlierVaults], the vaults this phone
     * last showed as usable ([SigningMemory.usable]: checked "ok", or shown while the server didn't
     * sign; never rows a locked background refresh wrote into the copy), the only ones that may be
     * grandfathered (rule 6); [earlierShared], the shared (sealed) rows of the offline copy, whose
     * removal a verified sync may confirm.
     */
    var earlierVaults: Set<String> = emptySet()
    var earlierShared: Set<String> = emptySet()

    fun close() {
        sharing?.close()
        sharing = null
        account.destroy()
    }
}

/**
 * The app's single source of truth for accounts, unlock state and the
 * decrypted vault. Mirrors the extension's background `vault.ts`.
 *
 * Phase 2 (autofill and passkey provider) runs in the same process and reads
 * the unlocked vault through [vault], [loginsFor] and [passkeysFor].
 */
class VaultRepository(
    private val store: SecureStore,
    private val api: ApiClient,
    private val scope: CoroutineScope,
) : HealthSource {
    private val mutex = Mutex()
    private val sessions = mutableMapOf<String, Session>()
    private val sessionIds = MutableStateFlow<Set<String>>(emptySet())
    private var vaultKeys = mapOf<String, VaultKey>()

    /** The vault headers [vaultKeys] were opened from (a changed header opens the key again). */
    private var vaultHeaders = mapOf<String, SyncVault>()

    /**
     * The active account's copy behind [vault] (account id, ciphertext with cursor and vault
     * numbers): the base of the next delta sync and of local changes after this device's writes.
     */
    private var copy: Pair<String, SyncSnapshot>? = null

    /** The remembered item edit counters of one account ([ItemRevs]; stored with its offline copy). */
    private var itemRevs: Pair<String, Map<String, Long>>? = null

    /** The last manifest (version and link) this phone checked or wrote of each vault of one account ([Manifests]; stored with its offline copy). */
    private var manifestMemory: Pair<String, Map<String, ManifestMark>>? = null

    /** When this phone first saw each trashed item of one account in the trash ([TrashSeen]; stored with its offline copy). */
    private var trashSeen: Pair<String, Map<String, Long>>? = null

    /** The vault number ("<account>|<vault>" → `seq`) at which a first manifest or an old-trash purge was last tried: once per vault and number. */
    private val upkeepTried = mutableMapOf<String, Long>()

    /** How each vault of the copy shown stands against its manifest. */
    private var manifestStates = mapOf<String, ManifestState>()

    /** Public syncs: one in flight, one waiting ([SyncQueue]). */
    private val syncQueue = SyncQueue(scope)
    private val _vault = MutableStateFlow<VaultData?>(null)
    private var pendingMaster: MasterKeys? = null
    private var pendingRemember = ""

    /** A device sign-in waiting for two-step login: [verifyTwoFactor] finishes it with this key. */
    private var pendingDeviceLogin: DeviceLoginRequest? = null

    private val _deviceLogin = MutableStateFlow<DeviceLoginRequest?>(null)

    /** The sign-in request waiting for another device's approval (the sign-in screen shows its words). */
    val deviceLogin: StateFlow<DeviceLoginRequest?> = _deviceLogin.asStateFlow()

    private val _deviceCode = MutableStateFlow<DeviceCodeRequest?>(null)

    /** An approved device sign-in waiting for the approving app's code (the sign-in screen asks for it). */
    val deviceCode: StateFlow<DeviceCodeRequest?> = _deviceCode.asStateFlow()

    /** The active account's decrypted vault; null while locked. */
    override val vault: StateFlow<VaultData?> = _vault.asStateFlow()

    /** Accounts whose server answered 403 `two_step_required` (no two-step method while one is required); memory only. */
    private val gated = MutableStateFlow<Set<String>>(emptySet())

    /** Each signed-in account's `policy_violations` (`GET /account`), asked after sign-in and unlock; memory only. */
    private val _violations = MutableStateFlow<Map<String, List<Violation>>>(emptyMap())
    val violations: StateFlow<Map<String, List<Violation>>> = _violations.asStateFlow()

    /** Notices the user dismissed (by key: a new invitation or another violation shows its notice again); memory only. */
    private val _dismissed = MutableStateFlow<Set<String>>(emptySet())
    val dismissed: StateFlow<Set<String>> = _dismissed.asStateFlow()

    fun dismissNotice(key: String) = _dismissed.update { it + key }

    /** Vault names read from invitations, by [Invitations.cacheKey] (null: it couldn't be opened). */
    private var invitationNames = mapOf<String, String?>()

    /**
     * Called whenever the decrypted vault is dropped (lock, log out, switching or adding an
     * account): what the app derived from it for this session (password health) goes too.
     */
    override var onVaultClosed: (() -> Unit)? = null

    /** Profile pictures kept on this device, decoded, by account record id. */
    private val _avatars = MutableStateFlow<Map<String, ImageBitmap>>(emptyMap())

    val state: StateFlow<AppState> = combine(store.data, sessionIds, gated, _avatars) { s, open, g, pics -> toState(s, open, g, pics) }
        .stateIn(scope, SharingStarted.Eagerly, AppState())

    init {
        // Runs later: the request that noticed it may hold the lock.
        api.onSessionLost = { id -> scope.launch { mutex.withLock { closeSession(id) } } }
        // The server requires two-step login first: the app shows only the setup screen for that account.
        api.onTwoStepRequired = { id -> gated.update { it + id } }
        // Pictures kept on this device: read for the listed records; files of records gone are deleted.
        scope.launch(Dispatchers.IO) {
            store.data.map { it.accounts.keys }.distinctUntilChanged().collect { ids ->
                runCatching { store.avatars.prune(ids) }
                val known = _avatars.value
                val loaded = ids.filter { it !in known }.mapNotNull { id ->
                    store.avatars.read(id)?.let { e -> AvatarImage.decode(e.jpeg) }?.let { id to it }
                }.toMap()
                _avatars.update { cur -> cur.filterKeys { it in ids } + loaded }
            }
        }
    }

    private fun statusOf(id: String, a: AccountData?, open: Set<String>) = when {
        a == null || a.server.isEmpty() -> Status.Setup
        a.tokens == null -> Status.LoggedOut
        id in open -> Status.Unlocked
        else -> Status.Locked
    }

    private fun toState(s: Stored, open: Set<String>, gate: Set<String>, pics: Map<String, ImageBitmap>): AppState {
        val a = s.active
        return AppState(
            loaded = true,
            status = statusOf(s.activeId, a, open),
            activeId = s.activeId,
            accounts = s.accounts.filter { (_, v) -> v.server.isNotEmpty() && v.email.isNotEmpty() }
                .map { (id, v) -> AccountSummary(id, v.email, v.name, v.server, statusOf(id, v, open), pics[id]) },
            name = a?.name.orEmpty(),
            server = a?.server.orEmpty(),
            email = a?.email.orEmpty(),
            secretKeyRequired = a?.bundle?.let { AppJson.parseToJsonElement(it).jsonObject.bool("secret_key_enabled") } ?: false,
            secretKeyStored = a != null && s.secretKeys.containsKey(a.email.lowercase()),
            biometricEnabled = a?.biometric != null,
            settings = s.settings,
            lastSync = a?.lastSync ?: 0,
            onboarding = s.onboarding,
            showPermissionsIntro = s.showPermissionsIntro,
            twoStepRequired = a?.tokens != null && s.activeId in gate,
            policies = a?.policies ?: Policies(),
            timeoutLimit = s.timeoutLimit,
            showSiteIcons = SiteIcons.shown(s.settings.showIcons, a?.api, a?.features),
            avatar = pics[s.activeId],
            avatarAvailable = a?.features?.contains(AvatarRules.FEATURE) == true,
        )
    }

    private suspend fun activeId() = store.get().activeId

    // ------------------------------------------------------------- server

    /** Connect the active account record (created if needed) to a server. */
    suspend fun setServer(url: String) {
        val origin = normalizeServer(url)
        val res = try {
            api.get("$origin/api/config")
        } catch (e: UserException) {
            throw UserException("No PassAuth server answered at that address.")
        }
        val config = res.use { r ->
            if (!r.isSuccessful) return@use null
            runCatching { AppJson.parseToJsonElement(r.body.string()).jsonObject.takeIf { it.str("name") == "PassAuth" } }.getOrNull()
        }?.let { ServerConfig.parse(it) } ?: throw UserException("No PassAuth server answered at that address.")
        // A server that doesn't sign shares is never connected to ([ServerSupport]).
        if (!ServerSupport.supported(config.features)) throw ServerTooOldException()
        mutex.withLock {
            val s = store.get()
            closeSession(s.activeId)
            // A device sign-in in progress was for the old server.
            cancelDeviceLogin()
            dropPendingDeviceLogin()
            store.update { st ->
                val id = st.activeId.takeIf { st.accounts.containsKey(it) } ?: UUID.randomUUID().toString()
                val a = st.accounts[id] ?: AccountData()
                st.copy(
                    activeId = id,
                    accounts = st.accounts + (
                        id to a.copy(
                            server = origin, tokens = null, bundle = null,
                            features = config.features, featuresAt = System.currentTimeMillis(), api = config.api,
                            policies = config.policies.takeIf { PolicyRules.FEATURE in config.features },
                            maxImportItems = config.maxImportItems,
                        )
                    ),
                )
            }
        }
    }

    /** The active record's server's `/api/config` (sign-ups, features, policies), asked now; null if it couldn't be read. */
    suspend fun publicConfig(): ServerConfig? {
        val server = store.get().active?.server?.takeIf { it.isNotEmpty() } ?: return null
        return fetchConfig(server)
    }

    /** `GET <server>/api/config`, read off the main thread; null when it fails or isn't a PassAuth answer. */
    private suspend fun fetchConfig(server: String): ServerConfig? = try {
        api.get("$server/api/config").use { r ->
            if (!r.isSuccessful) return@use null
            val o = withContext(Dispatchers.IO) { AppJson.parseToJsonElement(r.body.string()) } as? JsonObject ?: return@use null
            ServerConfig.parse(o)
        }
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }

    /**
     * Ask account [id]'s server for its features and policies now and keep them with the account;
     * a longer vault timeout than its policy allows is then lowered ([enforceTimeoutPolicy], run
     * afterwards: this may be called inside a sync, holding the lock that settings changes take).
     */
    private suspend fun refreshConfig(id: String): ServerConfig? {
        val server = store.get().accounts[id]?.server?.takeIf { it.isNotEmpty() } ?: return null
        val config = fetchConfig(server) ?: return null
        store.updateAccount(id) {
            it.copy(
                features = config.features,
                featuresAt = System.currentTimeMillis(),
                api = config.api,
                policies = config.policies.takeIf { PolicyRules.FEATURE in config.features },
                maxImportItems = config.maxImportItems,
            )
        }
        scope.launch {
            try {
                enforceTimeoutPolicy()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
            }
        }
        return config
    }

    /**
     * Part S, before a sync of account [id] is asked for or used: its server must be known to sign
     * shares ([ServerSupport]). The list kept is trusted for a while; one that is old, unknown or
     * without the feature is asked for again now. [ServerTooOldException] when the server's own
     * answer lacks it; a config that can't be read now is not a refusal (decided at the next one)
     * while a list is kept from before; with none kept it is "can't connect".
     */
    private suspend fun requireSupportedServer(id: String) {
        val a = store.get().accounts[id]?.takeIf { it.server.isNotEmpty() } ?: return
        val now = System.currentTimeMillis()
        val kept = a.features
        val fresh = kept != null && now >= a.featuresAt && now - a.featuresAt < FEATURES_MAX_AGE_MS
        if (fresh && ServerSupport.supported(kept.orEmpty())) return
        // The server can't say now: a list kept from before decides (offline use goes on). With nothing
        // kept, nothing is known about this server, and nothing is asked of it or taken from it: a
        // server could otherwise dodge the check by breaking its own `/api/config`.
        val features = ServerSupport.decide(refreshConfig(id)?.features, kept)
        if (!ServerSupport.supported(features)) throw ServerTooOldException()
    }

    /**
     * Part S at sign-in and sign-up: asked now. A server that can't be asked goes on only with a
     * list kept from before that has the feature (the request that follows fails by itself when the
     * server is unreachable); with nothing kept it is "can't connect".
     */
    private suspend fun requireSupportedServerNow(id: String) {
        // No server set yet: the request that follows says so.
        if (store.get().accounts[id]?.server.isNullOrEmpty()) return
        val features = ServerSupport.decide(refreshConfig(id)?.features, store.get().accounts[id]?.takeIf { it.server.isNotEmpty() }?.features)
        if (!ServerSupport.supported(features)) throw ServerTooOldException()
    }

    // -------------------------------------------------------------- login

    private suspend fun deviceInfo() = buildJsonObject {
        put("id", store.get().deviceId)
        put("name", "PassAuth for Android (${Build.MODEL})")
        put("kind", "mobile")
    }

    suspend fun login(email: String, password: String, secretKey: String?): LoginResult = mutex.withLock {
        // A password sign-in replaces any device sign-in in progress.
        dropPendingDeviceLogin()
        val s = store.get()
        val id = s.activeId
        val key = email.trim().lowercase()
        val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[key]
        requireSupportedServerNow(id)
        val pre = api.call(id, "/auth/prelogin", body = buildJsonObject { put("email", email.trim()) }, auth = false).jsonObject
        val skRequired = pre.bool("secret_key_required")
        if (skRequired && sk == null) throw UserException(SECRET_KEY_REQUIRED)
        val master = core {
            deriveMasterKeys(password, if (skRequired) sk else null, pre.str("account_id"), pre["kdf"].toString(), skRequired)
        }
        try {
            val start = core { opaqueLoginStart(master) }
            val resp = api.call(
                id, "/auth/login/start", auth = false,
                body = buildJsonObject { put("email", email.trim()); put("message", start.message) },
            ).jsonObject
            val fin = try {
                core { opaqueLoginFinish(start.state, master, resp.str("message")) }
            } catch (_: CoreException) {
                throw UserException("Wrong email, master password or Secret Key.")
            }
            val rememberKey = "${s.active?.server}|$key"
            val result = api.call(
                id, "/auth/login/finish", auth = false,
                body = buildJsonObject {
                    put("login_id", resp.str("login_id"))
                    put("message", fin)
                    put("device", deviceInfo())
                    s.rememberTokens[rememberKey]?.let { put("remember_token", it) }
                },
            ).jsonObject
            if (sk != null && skRequired) store.update { it.copy(secretKeys = it.secretKeys + (key to sk)) }
            if (result.bool("two_factor_required")) {
                pendingMaster?.destroy()
                pendingMaster = master
                pendingRemember = rememberKey
                return@withLock LoginResult.TwoFactor(
                    result.str("two_factor_token"),
                    result["providers"]?.jsonArray?.map { it.toString().trim('"') }.orEmpty(),
                )
            }
            finishLogin(id, master, result)
            master.destroy()
        } catch (e: Exception) {
            if (pendingMaster !== master) master.destroy()
            throw e
        }
        syncOrGate()
        refreshPoliciesLater(id)
        LoginResult.Done
    }

    suspend fun verifyTwoFactor(token: String, provider: String, code: String, remember: Boolean) {
        mutex.withLock {
            val device = pendingDeviceLogin
            val id = device?.record ?: activeId()
            val result = api.call(
                id, "/auth/2fa/verify", auth = false,
                body = buildJsonObject {
                    put("two_factor_token", token)
                    put("provider", provider)
                    put("code", code.trim().replace(" ", ""))
                    put("remember", remember)
                },
            ).jsonObject
            if (device != null) {
                // An approved device sign-in: the answer carries the sealed account key with the session.
                // The approving app's code comes next; "remember this device" is kept only once it is confirmed.
                pendingDeviceLogin = null
                try {
                    openDeviceApproval(device, result, result.strOrNull("remember_token")?.let { pendingRemember to it })
                } finally {
                    device.close()
                }
                return@withLock
            }
            val master = pendingMaster ?: throw UserException("Sign-in expired. Start again.")
            pendingMaster = null
            try {
                result.strOrNull("remember_token")?.let { t ->
                    store.update { it.copy(rememberTokens = it.rememberTokens + (pendingRemember to t)) }
                }
                finishLogin(id, master, result)
            } finally {
                master.destroy()
            }
            syncOrGate()
            refreshPoliciesLater(id)
        }
    }

    /** Two-step login was left ("Back"): the sign-in waiting for it (its keys) leaves memory. */
    suspend fun cancelTwoFactor() = mutex.withLock {
        pendingMaster?.destroy()
        pendingMaster = null
        dropPendingDeviceLogin()
    }

    /** A device sign-in waiting for two-step login or for the approving app's code leaves memory (its session is signed out). */
    private fun dropPendingDeviceLogin() {
        pendingDeviceLogin?.close()
        pendingDeviceLogin = null
        _deviceCode.value?.let { dropDeviceCode(it) }
    }

    suspend fun sendTwoFactorEmail(token: String) {
        api.call(activeId(), "/auth/2fa/email", body = buildJsonObject { put("two_factor_token", token) }, auth = false)
    }

    private suspend fun finishLogin(id: String, master: MasterKeys, result: JsonObject) {
        val bundle = result["bundle"].toString()
        finishSession(id, result, bundle, core { master.unlock(bundle) })
    }

    /** A sign-in's session answer with its account unlocked: kept and opened the same way for every kind of sign-in. */
    private suspend fun finishSession(id: String, result: JsonObject, bundle: String, account: Account) {
        val email = result.str("email")
        val before = store.get()
        val server = before.accounts[id]?.server
        // Signing in again to an account that is already listed replaces the old record.
        val dupes = before.accounts.filter { (k, v) -> k != id && v.server == server && v.email.equals(email, true) }.keys
        dupes.forEach { closeSession(it); deleteLocalCopy(it); Keystore.deleteBiometricKey(it) }
        store.update { s -> s.signedIn(id, email, Tokens(result.str("access_token"), result.str("refresh_token")), bundle, dupes) }
        Keystore.deleteBiometricKey(id)
        openSession(id, Session(bundleAccountId(bundle), account))
    }

    /** Create an account on the active record's server (the web vault's Register). */
    suspend fun register(email: String, name: String, password: String, withSecretKey: Boolean): Registered = mutex.withLock {
        val id = activeId()
        requireSupportedServerNow(id)
        // The server's minimums for new keys (its policy), asked again now.
        val kdf = PolicyRules.kdfMinimums(publicConfig())
        val init = api.call(id, "/auth/register/init", body = buildJsonObject { put("email", email.trim()) }, auth = false).jsonObject
        val created = core {
            createAccountWithKdf(init.str("account_id"), password, withSecretKey, kdf?.memoryMib?.toUInt(), kdf?.iterations?.toUInt())
        }
        try {
            val start = core { opaqueRegisterStart(created.master) }
            val resp = api.call(
                id, "/auth/register/start", auth = false,
                body = buildJsonObject { put("registration_id", init.str("registration_id")); put("message", start.message) },
            ).jsonObject
            val upload = core { opaqueRegisterFinish(start.state, created.master, resp.str("message")) }
            val vaultId = core { newId() }
            val nv = core { created.account.newVaultKey(vaultId) }
            val meta = try {
                core { nv.key.encryptMeta(vaultId, """{"name":"Personal"}""") }
            } finally {
                nv.key.destroy()
            }
            val done = api.call(
                id, "/auth/register/finish", auth = false,
                body = buildJsonObject {
                    put("registration_id", init.str("registration_id"))
                    put("upload", upload)
                    put("bundle", AppJson.parseToJsonElement(created.bundleJson))
                    put("name", name.trim())
                    put("vault", buildJsonObject { put("id", vaultId); put("meta", meta); put("wrapped_key", nv.wrapped) })
                },
            ).jsonObject
            created.secretKey?.let { sk -> store.update { it.copy(secretKeys = it.secretKeys + (email.trim().lowercase() to sk)) } }
            Registered(created.secretKey, done.bool("email_verification_required"))
        } finally {
            created.destroy()
        }
    }

    // ---------------------------------------- sign in with another device

    /** The new device's requests to account record [record]'s server (no session; the access code in a header). */
    private fun deviceLoginFlow(record: String) = DeviceLoginFlow(ApiDeviceLoginTransport(securityTransport(record)))

    /** Whether the active record's server lets a device sign in with another device's approval (`/api/config` `features`). */
    suspend fun deviceLoginAvailable(): Boolean = publicConfig()?.features?.contains(DeviceLogin.FEATURE) == true

    /**
     * Ask the active record's server to let this device sign in to [email] once another device of
     * the account approves: a key made for this request only (its words are shown, never the
     * server's), a random access code kept here, this device's name and its "remember this
     * device" token. The request is [deviceLogin] until [awaitDeviceLogin] ends it or the user
     * cancels ([cancelDeviceLogin]); a new one replaces an older one.
     */
    suspend fun beginDeviceLogin(email: String): DeviceLoginRequest {
        val s = store.get()
        val id = s.activeId
        val mail = email.trim()
        if (mail.isEmpty()) throw UserException("Enter your email address.")
        requireSupportedServerNow(id)
        val key = core { LoginRequestKey.generate() }
        try {
            val code = DeviceLogin.accessCode()
            val remember = s.rememberTokens["${s.accounts[id]?.server}|${mail.lowercase()}"]
            val started = deviceLoginFlow(id).start(mail, key.publicKey(), code, deviceInfo(), remember)
            val request = DeviceLoginRequest(id, started.id, mail, key.phrase(), started.expiresAt, code, key)
            _deviceLogin.getAndUpdate { request }?.close()
            return request
        } catch (e: Exception) {
            key.destroy()
            throw e
        }
    }

    /**
     * Wait for the other device's answer (polling). Approved: the code the approving app shows
     * comes next ([LoginResult.CodeNeeded], [deviceCode], [confirmDeviceCode]), or two-step login
     * first ([LoginResult.TwoFactor], finished by [verifyTwoFactor]). Denied, expired and the like
     * end with a [UserException] that says so. Cancelling the coroutine keeps the request
     * ([deviceLogin]) so a new screen (rotation) can wait again.
     */
    suspend fun awaitDeviceLogin(request: DeviceLoginRequest): LoginResult {
        val outcome = try {
            deviceLoginFlow(request.record).await(request.id, request.accessCode, request.expiresAt)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            endDeviceLogin(request)
            throw e
        }
        return when (outcome) {
            is DeviceLoginPoll.Approved -> try {
                mutex.withLock { openDeviceApproval(request, outcome.session, null) }
                LoginResult.CodeNeeded
            } finally {
                endDeviceLogin(request)
            }
            is DeviceLoginPoll.TwoFactor -> {
                mutex.withLock {
                    pendingMaster?.destroy()
                    pendingMaster = null
                    if (pendingDeviceLogin !== request) dropPendingDeviceLogin()
                    pendingDeviceLogin = request
                    pendingRemember = "${store.get().accounts[request.record]?.server}|${request.email.lowercase()}"
                }
                // Handed over to two-step login: no longer the request the sign-in screen waits for.
                _deviceLogin.compareAndSet(request, null)
                LoginResult.TwoFactor(outcome.token, outcome.providers)
            }
            is DeviceLoginPoll.Ended -> {
                endDeviceLogin(request)
                throw UserException(outcome.message)
            }
            DeviceLoginPoll.Pending -> error("a request ended while pending")
        }
    }

    /** Stop waiting ("Cancel"): the key leaves memory and the request expires on the server unanswered. */
    fun cancelDeviceLogin() {
        _deviceLogin.getAndUpdate { null }?.close()
    }

    private fun endDeviceLogin(request: DeviceLoginRequest) {
        _deviceLogin.compareAndSet(request, null)
        request.close()
    }

    /**
     * An approved request's session answer: the account key sealed to this request's key (bound to
     * the account and the request) opens into an approval that unlocks nothing yet: the code the
     * approving app shows comes first ([deviceCode], [confirmDeviceCode]). Anything that doesn't
     * open (another key, account or request, or changed) signs nobody in, and the session the server
     * opened for it is signed out again.
     */
    private suspend fun openDeviceApproval(request: DeviceLoginRequest, result: JsonObject, remember: Pair<String, String>?) {
        val bundle = result["bundle"]?.takeIf { it is JsonObject }?.toString()
        val sealed = result.strOrNull("sealed_key")
        val user = result.strOrNull("user_id")
        val approved = if (bundle == null || sealed == null || user == null) {
            null
        } else {
            try {
                core { request.key.open(sealed, user, request.id) }
            } catch (_: CoreException) {
                null
            }
        }
        if (bundle == null || approved == null) {
            signOutLater(request.record, result)
            throw UserException(DeviceLogin.UNVERIFIED)
        }
        val pending = DeviceCodeRequest(request.record, request.email, approved, result, bundle, remember)
        _deviceCode.getAndUpdate { pending }?.let { if (it !== pending) dropDeviceCode(it) }
    }

    /**
     * Check the code the approving app shows ([DeviceLogin.check]). Right: the approval unlocks the
     * account (no master password), a Secret Key that came with it is kept only for the email typed
     * here ([DeviceLogin.keepSecretKey]), and the session is stored like any sign-in's. The third
     * wrong code stops the sign-in: its session is signed out (best effort) and its keys dropped.
     */
    suspend fun confirmDeviceCode(pending: DeviceCodeRequest, code: String): CodeCheck = mutex.withLock {
        if (_deviceCode.value !== pending) throw UserException(DeviceLogin.GONE)
        val check = core { DeviceLogin.check(pending.approved, code) }
        when (check) {
            CodeCheck.Confirmed -> {
                _deviceCode.compareAndSet(pending, null)
                try {
                    val account = try {
                        core { pending.approved.unlock(pending.bundle) }
                    } catch (_: CoreException) {
                        signOutLater(pending.record, pending.session)
                        throw UserException(DeviceLogin.UNVERIFIED)
                    }
                    val secretKey = try {
                        core { pending.approved.secretKey() }
                    } catch (_: CoreException) {
                        account.destroy()
                        signOutLater(pending.record, pending.session)
                        throw UserException(DeviceLogin.UNVERIFIED)
                    }
                    store.update { it.copy(secretKeys = DeviceLogin.keepSecretKey(it.secretKeys, secretKey, pending.email, pending.session.str("email"))) }
                    pending.rememberToken?.let { (key, token) -> store.update { it.copy(rememberTokens = it.rememberTokens + (key to token)) } }
                    finishSession(pending.record, pending.session, pending.bundle, account)
                } finally {
                    pending.close()
                }
                syncOrGate()
                refreshPoliciesLater(pending.record)
            }
            is CodeCheck.Stopped -> dropDeviceCode(pending)
            is CodeCheck.Wrong, is CodeCheck.NotACode -> Unit
        }
        check
    }

    /** Leave the code step ("Cancel"): the approval's keys leave memory and its session is signed out. */
    fun cancelDeviceCode() {
        _deviceCode.value?.let { dropDeviceCode(it) }
    }

    /** Drop an approval waiting for its code, and sign out the session that came with it. */
    private fun dropDeviceCode(pending: DeviceCodeRequest) {
        _deviceCode.compareAndSet(pending, null)
        pending.close()
        signOutLater(pending.record, pending.session)
    }

    /** Best effort, in the background: end the session a server opened for a device sign-in that won't be used. */
    private fun signOutLater(record: String, session: JsonObject) {
        val access = session.strOrNull("access_token")?.takeIf { it.isNotEmpty() } ?: return
        val refresh = session.str("refresh_token")
        scope.launch {
            val server = store.get().accounts[record]?.server.orEmpty()
            api.logoutRemote(server, Tokens(access, refresh))
        }
    }

    // ------------------------------------------------------------- unlock

    suspend fun unlock(password: String, secretKey: String?) {
        mutex.withLock {
            val s = store.get()
            val id = s.activeId
            val a = s.active ?: throw UserException("Sign in first.")
            val fetched = a.bundle == null
            val bundle = a.bundle ?: api.call(id, "/sync").jsonObject["bundle"].toString()
            val b = AppJson.parseToJsonElement(bundle).jsonObject
            val skEnabled = b.bool("secret_key_enabled")
            val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
            if (skEnabled && sk == null) throw UserException(SECRET_KEY_REQUIRED)
            val account = core {
                val master = deriveMasterKeys(password, sk, b.str("account_id"), b["kdf"].toString(), skEnabled)
                try {
                    master.unlock(bundle)
                } catch (_: CoreException) {
                    throw UserException("Wrong master password or Secret Key.")
                } finally {
                    master.destroy()
                }
            }
            if (sk != null && secretKey?.isNotBlank() == true) {
                store.update { it.copy(secretKeys = it.secretKeys + (a.email.lowercase() to sk)) }
            }
            // A bundle fetched now is kept only once it opened under the master password (its account id authenticated).
            if (fetched) store.updateAccount(id) { it.copy(bundle = bundle) }
            openSession(id, Session(b.str("account_id"), account))
            syncOrGate(fallbackToCache = true, cacheFirst = true)
            refreshPoliciesLater(id)
        }
    }

    /** Session bytes to protect with a biometric key (enable biometric unlock). */
    suspend fun enableBiometric(cipher: Cipher) = mutex.withLock {
        val id = activeId()
        val session = sessions[id] ?: throw UserException("Unlock your vault first.")
        val bytes = session.account.toSessionBytes()
        val sealed = try {
            Keystore.seal(cipher, bytes)
        } finally {
            bytes.fill(0)
        }
        store.updateAccount(id) { it.copy(biometric = sealed) }
    }

    suspend fun disableBiometric() {
        val id = activeId()
        Keystore.deleteBiometricKey(id)
        store.updateAccount(id) { it.copy(biometric = null) }
    }

    suspend fun biometricBlob(): Pair<String, Sealed>? = store.get().let { s -> s.active?.biometric?.let { s.activeId to it } }

    suspend fun unlockWithBiometric(cipher: Cipher) {
        mutex.withLock {
            val s = store.get()
            val id = s.activeId
            val a = s.active ?: throw UserException("Sign in first.")
            val sealed = a.biometric ?: throw UserException("Biometric unlock is off.")
            val bundle = a.bundle ?: throw UserException("Unlock with your master password.")
            val bytes = Keystore.open(cipher, sealed)
            val account = try {
                core { AccountBundles.restore(bundle, bytes) }
            } finally {
                bytes.fill(0)
            } ?: throw UserException("Unlock with your master password.")
            openSession(id, Session(bundleAccountId(bundle), account))
            syncOrGate(fallbackToCache = true, cacheFirst = true)
            refreshPoliciesLater(id)
        }
    }

    /** Vault timeout "never": restore keys kept on disk after the app restarts. */
    suspend fun restorePersisted(): Boolean {
        // A server's longest vault timeout may rule "never" out: lower it first (that wipes the kept keys).
        enforceTimeoutPolicy()
        return restoreLocked()
    }

    private suspend fun restoreLocked(): Boolean = mutex.withLock {
        val s = store.get()
        if (s.settings.vaultTimeout != VaultTimeout.Never) return@withLock false
        var restored = false
        for ((id, a) in s.accounts) {
            val keys = a.persistedKeys ?: continue
            val bundle = a.bundle ?: continue
            if (a.tokens == null || sessions.containsKey(id)) continue
            runCatching {
                val bytes = Base64.decode(keys)
                // Only a session whose stored bundle is its own (round 5 iOS H): else the master password is asked.
                val account = try {
                    core { AccountBundles.restore(bundle, bytes) }
                } finally {
                    bytes.fill(0)
                } ?: return@runCatching
                openSession(id, Session(bundleAccountId(bundle), account))
                restored = true
            }
        }
        if (restored && sessions.containsKey(s.activeId)) {
            syncOrGate(fallbackToCache = true, cacheFirst = true)
            refreshPoliciesLater(s.activeId)
        }
        restored
    }

    private suspend fun openSession(id: String, session: Session) {
        // The copy this phone kept from an earlier session (none on a fresh install or a re-added account).
        runCatching { readSnapshot(id) }.getOrNull()?.let { earlier ->
            session.earlierShared = earlier.vaults.filter { it.keyKind == "sealed" }.map { it.id }.toSet()
        }
        val server = store.get().accounts[id]?.server.orEmpty()
        session.earlierVaults = store.get().signingMemory(server, session.accountId).usable.orEmpty()
        sessions.remove(id)?.close()
        sessions[id] = session
        sessionIds.value = sessions.keys.toSet()
        persistForNever(id)
    }

    private suspend fun persistForNever(id: String) {
        val s = store.get()
        val session = sessions[id] ?: return
        if (s.settings.vaultTimeout != VaultTimeout.Never) return
        val bytes = session.account.toSessionBytes()
        store.updateAccount(id) { it.copy(persistedKeys = Base64.encode(bytes)) }
        bytes.fill(0)
    }

    private suspend fun closeSession(id: String) {
        sessions.remove(id)?.close()
        sessionIds.value = sessions.keys.toSet()
        store.updateAccount(id) { it.copy(persistedKeys = null) }
        if (id == store.get().activeId) unloadVault()
    }

    private fun unloadVault() {
        vaultKeys.values.forEach { it.destroy() }
        vaultKeys = emptyMap()
        vaultHeaders = emptyMap()
        invitationNames = emptyMap()
        manifestStates = emptyMap()
        copy = null
        _vault.value = null
        _sharing.value = SharingStatus()
        keysSignature = null
        _emergencyNotice.value = null
        onVaultClosed?.invoke()
    }

    // ------------------------------------------------------ lock / logout

    /** Lock the active account. */
    suspend fun lock() = mutex.withLock { closeSession(activeId()) }

    /** Vault timeout: lock every account. */
    suspend fun lockAll() = mutex.withLock {
        sessions.keys.toList().forEach { closeSession(it) }
        unloadVault()
    }

    /** Vault timeout with the "log out" action: sign every account out (they stay listed). */
    suspend fun logoutAll() {
        lockAll()
        val s = store.get()
        for ((id, a) in s.accounts) {
            if (a.tokens == null) continue
            api.logoutRemote(a.server, a.tokens)
            store.updateAccount(id) { it.copy(tokens = null, biometric = null) }
            Keystore.deleteBiometricKey(id)
            deleteLocalCopy(id)
            forgetSessionState(id)
        }
    }

    /** Log out of the active account and remove it from this device; the next one becomes active. */
    suspend fun logout() = mutex.withLock {
        val s = store.get()
        s.active?.let { api.logoutRemote(it.server, it.tokens) }
        signOutLocally(s.activeId)
    }

    /**
     * Log out of account [id] on this device only (its session already ended on the server):
     * keys, offline copy and biometric unlock go; the account is removed from the device, or the
     * last one stays as a signed-out record so the sign-in screen remembers the server and email.
     */
    private suspend fun signOutLocally(id: String) {
        val s = store.get()
        closeSession(id)
        pendingMaster?.destroy()
        pendingMaster = null
        Keystore.deleteBiometricKey(id)
        deleteLocalCopy(id)
        forgetSessionState(id)
        val listed = s.accounts.filterValues { it.server.isNotEmpty() && it.email.isNotEmpty() }
        if (listed.size > 1 || !listed.containsKey(id)) {
            removeAccount(id)
        } else {
            store.update { it.signedOutRecord(id) }
        }
    }

    /** What this app knew about account [id]'s session in memory: the two-step gate and its policy violations. */
    private fun forgetSessionState(id: String) {
        gated.update { it - id }
        _violations.update { it - id }
    }

    private suspend fun removeAccount(id: String) {
        store.update { it.withoutRecord(id) }
        if (sessions.containsKey(activeId())) syncLocked(fallbackToCache = true)
    }

    suspend fun switchAccount(id: String) = mutex.withLock {
        val s = store.get()
        if (s.accounts[id]?.server.isNullOrEmpty()) throw UserException("That account isn't on this device any more.")
        if (id == s.activeId) return@withLock
        unloadVault()
        // Drop an unfinished "add account" record.
        val unfinished = s.active?.let { !isListed(it) } ?: false
        store.update { st -> st.copy(activeId = id, accounts = if (unfinished) st.accounts - st.activeId else st.accounts) }
        if (sessions.containsKey(id)) syncLocked(fallbackToCache = true, cacheFirst = true)
    }

    private fun isListed(a: AccountData) = a.server.isNotEmpty() && a.email.isNotEmpty()

    /** Start adding an account: an empty record becomes active until it's signed in or cancelled. */
    suspend fun addAccount() = mutex.withLock {
        val s = store.get()
        if (s.accounts.values.count(::isListed) >= MAX_ACCOUNTS) {
            throw UserException("PassAuth supports up to $MAX_ACCOUNTS accounts. Log out of one first.")
        }
        unloadVault()
        val id = UUID.randomUUID().toString()
        store.update { st ->
            val kept = st.accounts.filter { (_, a) -> a.server.isNotEmpty() && (a.email.isNotEmpty() || a.tokens != null) }
            st.copy(accounts = kept + (id to AccountData()), activeId = id)
        }
    }

    /** Leave an unfinished "add account" and go back to [to]. */
    suspend fun cancelAddAccount(to: String) {
        mutex.withLock {
            val s = store.get()
            if (s.active?.tokens == null && s.accounts[to] != null) {
                store.update { it.copy(accounts = it.accounts - it.activeId, activeId = to) }
            }
        }
        if (sessions.containsKey(to)) mutex.withLock { syncLocked(fallbackToCache = true) }
    }

    // ----------------------------------------------------------- settings

    suspend fun updateOnboarding(transform: (Onboarding) -> Onboarding) {
        store.update { it.copy(onboarding = transform(it.onboarding)) }
    }

    suspend fun updateSettings(transform: (Settings) -> Settings) {
        val before = store.get().settings
        val after = store.update { it.copy(settings = transform(it.settings)) }.settings
        if (before.vaultTimeout != after.vaultTimeout) {
            mutex.withLock {
                if (after.vaultTimeout == VaultTimeout.Never) {
                    sessions.keys.forEach { persistForNever(it) }
                } else {
                    store.update { s -> s.copy(accounts = s.accounts.mapValues { it.value.copy(persistedKeys = null) }) }
                }
            }
        }
    }

    // --------------------------------------------------------------- sync

    /**
     * Sync the active account (pull to refresh, live sync, the editor's conflict choice). One sync
     * runs at a time and at most one waits: a request made while one is waiting joins it.
     */
    suspend fun sync() = syncQueue.run { mutex.withLock { syncLocked(upkeep = true) } }

    /** Where the open copy is (revision and vault numbers); null while locked. */
    val syncPosition: SyncPosition?
        get() {
            val v = _vault.value ?: return null
            return copy?.second?.position ?: SyncPosition(v.revision, null)
        }

    /**
     * Re-sync if the server has something the copy lacks (cheap `/sync/revision` check: the
     * revision and, with delta sync, every vault's number; [SyncDecision.isStale]), or to leave
     * the offline copy.
     */
    suspend fun refreshIfStale() {
        val current = _vault.value ?: return
        val have = syncPosition ?: return
        val id = activeId()
        val j = runCatching { api.call(id, "/sync/revision").jsonObject }.getOrNull() ?: return
        gated.update { it - id }
        val r = (j["revision"] as? JsonPrimitive)?.longOrNull ?: return
        if (SyncDecision.isStale(r, DeltaSync.vaultNumbers(j["vaults"]), have) || current.offline) sync()
    }

    /** Ask the server whether this session still exists: an ended one signs the account out (refresh fails). */
    suspend fun checkSession() = refreshIfStale()

    /** Result of [refreshAllCaches]: accounts whose copy was checked, and how many the server couldn't be reached for. */
    data class CacheRefreshOutcome(val refreshed: Int = 0, val networkFailures: Int = 0)

    /**
     * Background sync: bring every signed-in account's encrypted offline copy up to
     * date. The active account, if unlocked, gets a normal sync; every other account
     * gets [refreshCacheLocked] (ciphertext only, nothing decrypted or kept in memory).
     */
    suspend fun refreshAllCaches(): CacheRefreshOutcome {
        var outcome = CacheRefreshOutcome()
        val s = store.get()
        for ((id, a) in s.accounts) {
            if (a.tokens == null || a.server.isEmpty()) continue
            try {
                // A background worker never starts manifests or deletes old trash ([manifestUpkeep]).
                if (id == s.activeId && sessions.containsKey(id)) syncQueue.run { mutex.withLock { syncLocked() } } else refreshCacheLocked(id)
                outcome = outcome.copy(refreshed = outcome.refreshed + 1)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: ServerTooOldException) {
                // Nothing is asked of a server that doesn't sign shares; trying again wouldn't change it.
            } catch (_: ApiException) {
                // Server answered (e.g. the session ended → signed out by ApiClient): nothing to retry.
            } catch (_: Exception) {
                outcome = outcome.copy(networkFailures = outcome.networkFailures + 1)
            }
        }
        return outcome
    }

    /**
     * Refresh one account's offline copy without unlocking it, through the usual client (token
     * refresh and 401 handling unchanged). Nothing is decrypted: with delta sync `/sync/revision`
     * decides and only the changes are fetched and merged into the copy; otherwise the whole
     * `/sync` replaces it. Only a valid sync answer (with the account bundle) at least as new as
     * the copy is written ([DeltaSync.refresh]): never downgrades, never an unparseable body.
     */
    private suspend fun refreshCacheLocked(id: String) {
        requireSupportedServer(id)
        val cached = readSnapshot(id)
        val delta = deltaSyncEnabled(id)
        val result = DeltaSync.refresh(cached, delta, TRASH_SUMMARY) { path -> api.callText(id, path) }
        if (store.get().accounts[id]?.tokens == null) return // signed out meanwhile
        gated.update { it - id }
        when (result) {
            DeltaSync.CacheRefresh.Keep -> return
            DeltaSync.CacheRefresh.Current -> store.updateAccount(id) { it.copy(lastSync = System.currentTimeMillis()) }
            is DeltaSync.CacheRefresh.Write -> {
                // Nothing is decrypted here: the versions replaced are held for the next unlocked sync's rollback check.
                val next = ItemRevs.withHeld(result.snapshot, cached)
                val text = core { next.encode() }
                mutex.withLock {
                    // Unlocked and shown meanwhile: its own sync writes the copy.
                    if (sessions.containsKey(id) && activeId() == id) return@withLock
                    withContext(Dispatchers.IO) { store.writeCache(id, text) }
                    // Locked: a bundle naming another account than the one kept is never stored (round 5 iOS H);
                    // an unlocked (inactive) session checks it is the account's own.
                    val unlocked = sessions[id]?.account
                    store.updateAccount(id) {
                        it.copy(
                            lastSync = System.currentTimeMillis(),
                            name = (next.user as? JsonObject)?.strOrNull("name") ?: it.name,
                            bundle = AccountBundles.toStore(unlocked, it.bundle, next.bundle?.toString()),
                        )
                    }
                }
            }
        }
    }

    /**
     * Fetch and decrypt the active account's vault. With [fallbackToCache] an
     * unreachable server shows the on-device copy (offline). With [cacheFirst]
     * the on-device copy is shown straight away and the server is asked in the
     * background, so unlocking doesn't wait for a slow or unreachable server.
     *
     * With delta sync the server sends only what changed since the copy's cursor; the merged
     * copy is decrypted incrementally ([decryptVault]) and stored with its new cursor in one
     * write, so a failed or interrupted sync leaves the previous copy and cursor.
     */
    private suspend fun syncLocked(fallbackToCache: Boolean = false, cacheFirst: Boolean = false, upkeep: Boolean = false) {
        val id = activeId()
        val session = sessions[id] ?: return
        if (cacheFirst) {
            val cached = readSnapshot(id)
            if (cached != null && runCatching { show(id, session, cached, offline = false, mode = CopyStore.None) }.isSuccess) {
                scope.launch { backgroundSync(id, session) }
                return
            }
        }
        // The server couldn't be asked, or its answer couldn't be checked: the copy on this phone, when asked for.
        suspend fun unreached(e: Exception) {
            val cached = if (fallbackToCache) readSnapshot(id) else null
            val problem = (e as? ServerTooOldException)?.message
            if (cached == null) {
                if (fallbackToCache && e !is ApiException) {
                    copy = null
                    manifestStates = emptyMap()
                    _vault.value = VaultData(offline = true, syncProblem = problem)
                    return
                }
                throw e
            }
            show(id, session, cached, offline = true, mode = CopyStore.None)
            if (problem != null && sessions[id] === session) _vault.value = _vault.value?.copy(syncProblem = problem)
        }
        val next = try {
            fetchSnapshot(id).also { gated.update { g -> g - id } }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // An answer that isn't a vault is an error, not "offline".
            if (e is UserException && e.message == DeltaSync.unreadable().message) throw e
            return unreached(e)
        }
        val shown = try {
            showAnswer(id, session, next)
        } catch (e: ManifestLogUnavailable) {
            // The answer can't be checked now: as if the server hadn't answered (the copy shown and its state stay).
            return unreached(e.cause as? Exception ?: e)
        }
        if (upkeep) manifestUpkeep(id, session, shown.serverTime, shown.trashDays)
    }

    /**
     * A copy made from the server's answer that doesn't pass its manifests yet isn't a whole answer
     * (a delta on this phone's copy): everything is asked for once, and that answer decides.
     */
    private class NeedsWholeAnswer : Exception()

    /**
     * [next] (the copy after a server answer) checked, shown and stored; returns the answer shown.
     * A warning comes from the server's whole answer alone: when a delta on this phone's copy
     * doesn't pass a vault's manifest (or holds rows that can't be counted), everything is fetched
     * once and judged as sent. [ManifestLogUnavailable] when the server can't be asked for what the
     * check needs: nothing was taken, the copy shown before and its state stay.
     */
    private suspend fun showAnswer(id: String, session: Session, next: SyncSnapshot): SyncSnapshot {
        try {
            show(id, session, next, offline = false, mode = CopyStore.Synced)
            return next
        } catch (_: NeedsWholeAnswer) {
            return showWholeAnswer(id, session)
        }
    }

    /** Everything the server has for account [id], fetched now, checked as one whole answer, shown and stored. */
    private suspend fun showWholeAnswer(id: String, session: Session): SyncSnapshot {
        val full = try {
            DeltaSync.fetch(null, false, TRASH_SUMMARY) { path -> api.callText(id, path) }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            if (e is UserException && e.message == DeltaSync.unreadable().message) throw e
            throw ManifestLogUnavailable(e)
        }
        show(id, session, full, offline = false, mode = CopyStore.Synced)
        return full
    }

    /** The server sync after a cache-first unlock; an unreachable server leaves the copy marked offline. */
    private suspend fun backgroundSync(id: String, session: Session) = mutex.withLock {
        if (sessions[id] !== session || activeId() != id) return@withLock
        try {
            syncLocked(upkeep = true)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            if (sessions[id] === session && activeId() == id) _vault.value = _vault.value?.copy(offline = true, syncProblem = (e as? ServerTooOldException)?.message)
        }
    }

    /** The account's copy after asking the server: since the copy's cursor when the server does delta sync, else everything. */
    private suspend fun fetchSnapshot(id: String): SyncSnapshot {
        requireSupportedServer(id)
        val base = copy?.takeIf { it.first == id }?.second ?: readSnapshot(id)
        val delta = deltaSyncEnabled(id)
        return DeltaSync.fetch(base, delta, TRASH_SUMMARY) { path -> api.callText(id, path) }
    }

    /** The account's copy on this device (null if missing or unreadable). */
    private suspend fun readSnapshot(id: String): SyncSnapshot? {
        val text = withContext(Dispatchers.IO) { store.readCache(id) } ?: return null
        return core { SyncSnapshot.decode(text) }
    }

    /**
     * The active account's server's `/api/config` `features`, asked now (password health follows
     * the admin's breach-check switch as it is) and kept with the account; null when the settings
     * couldn't be loaded.
     */
    override suspend fun serverFeatures(): List<String>? = refreshConfig(activeId())?.features

    /**
     * Whether the account's server does delta sync (`/api/config` `features` has `delta_sync`),
     * asked at most every 6 hours and kept with the account. A list gone stale is harmless: a
     * server without the feature ignores `since` and answers in full. Unknown → no.
     */
    private suspend fun deltaSyncEnabled(id: String): Boolean {
        val a = store.get().accounts[id]?.takeIf { it.server.isNotEmpty() } ?: return false
        val now = System.currentTimeMillis()
        val known = a.features
        if (known != null && now >= a.featuresAt && now - a.featuresAt < FEATURES_MAX_AGE_MS) return DeltaSync.FEATURE in known
        val config = refreshConfig(id) ?: return DeltaSync.FEATURE in known.orEmpty()
        return DeltaSync.FEATURE in config.features
    }

    /** What [show] keeps of a copy besides showing it. */
    private enum class CopyStore { None, LocalChange, Synced }

    /**
     * Decrypt [snap] (only what changed since the copy shown now) and show it. [CopyStore.Synced]:
     * fresh from the server, stored as the offline copy with the time of the sync, the profile
     * name and the bundle; [CopyStore.LocalChange]: this device's write applied to the copy, stored too.
     *
     * Vault manifests ([Manifests.judge]): a copy made from the server's answer is checked before
     * anything of it is kept. [NeedsWholeAnswer] when it is a delta that doesn't pass (the caller
     * asks for everything, [showAnswer]); [ManifestLogUnavailable] when the check needs the vault's
     * log and the server can't be asked. In both cases nothing was stored, shown or remembered.
     */
    private suspend fun show(
        id: String,
        session: Session,
        snap: SyncSnapshot,
        offline: Boolean,
        mode: CopyStore,
        /** [CopyStore.LocalChange]: the vaults whose manifest this device just wrote (the copy carries it), with what to remember of each. */
        written: Map<String, ManifestMark> = emptyMap(),
        /** [CopyStore.LocalChange]: items this device just deleted for good. */
        purged: Set<String> = emptySet(),
    ) {
        if (sessions[id] !== session) return
        // Only the server's whole answer, exactly as sent, raises a vault's warning.
        val whole = snap.whole && mode == CopyStore.Synced
        // Signed sharing: every vault and invitation checked before anything of it is used.
        val shownBefore = copy?.takeIf { it.first == id }?.second?.vaults?.filter { it.keyKind == "sealed" }?.map { it.id }?.toSet()
        val checks = verifySharing(id, session, snap, online = !offline && mode != CopyStore.None, sharedBefore = shownBefore ?: session.earlierShared, fromServer = !offline && mode == CopyStore.Synced)
        if (sessions[id] !== session) return
        // An identity uploaded at this sync goes into the copy kept, so an offline unlock later opens it (instead of pausing).
        @Suppress("NAME_SHADOWING")
        val served = (checks?.identityRecord?.let { withIdentity(snap, it) } ?: snap).let { s -> checks?.pinsSeq?.takeIf { mode == CopyStore.Synced }?.let { withPinsSeq(s, it) } ?: s }
        val previous = if (copy?.first == id) _vault.value?.let { Opened(it, vaultKeys, vaultHeaders, emptyList()) } else null
        val names = if (copy?.first == id) invitationNames else emptyMap()
        // Rollback check: what this phone remembers, and the copies it has to compare with (the copy
        // shown, else the stored one, and the versions a locked refresh held or that wait for an item
        // the server stopped sending). Memory that can't be read now: nothing is remembered from this
        // copy and nothing written (the copies this phone has are still compared).
        val revs = itemRevsOf(id)
        val priorCopy = copy?.takeIf { it.first == id }?.second ?: if (mode == CopyStore.Synced) readSnapshot(id) else null
        val priors = (priorCopy?.items.orEmpty() + priorCopy?.held.orEmpty() + served.held).groupBy { it.id }
        val opened = core { decryptVault(session.account, served, previous, names, checks, revs.orEmpty(), priors) }
        if (sessions[id] !== session) {
            opened.fresh.forEach { it.destroy() }
            return
        }
        // Vault manifests: the items exactly as the server sent them (one answer, applied) against each
        // vault's record; after this device's own write the copy carries the manifest it made.
        val before = if (copy?.first == id) manifestStates else emptyMap()
        val memory = manifestMemoryOf(id)
        var remember: Map<String, ManifestMark> = written
        val states: Map<String, ManifestState> = when {
            mode == CopyStore.LocalChange -> opened.keys.keys.associateWith { vid -> if (vid in written) ManifestState.Ok else before[vid] ?: ManifestState.None }
            // What this phone remembers can't be read now: nothing is checked against "nothing remembered"
            // (and nothing is written over it). A warning that stands stays; every other vault is unchecked
            // until a sync can check it (never an earlier "ok" over rows that weren't checked), so nothing is
            // written, started or purged meanwhile.
            memory == null -> opened.keys.keys.associateWith { vid -> if (before[vid] == ManifestState.Unresolved) ManifestState.Unresolved else ManifestState.Unchecked }
            else -> {
                val judged = try {
                    withContext(Dispatchers.Default) {
                        Manifests.judge(
                            served.vaults, served.items, opened.keys, memory, whole, opened.hidden,
                            log = if (mode == CopyStore.Synced) { vid, after -> manifestLog(id, vid, after) } else null,
                        )
                    }
                } catch (e: Throwable) {
                    opened.fresh.forEach { it.destroy() }
                    throw e
                }
                // A vault whose warning already stands (raised by a whole answer) keeps it while it doesn't pass;
                // any other that doesn't pass is decided by the server's whole answer, asked for now.
                if (mode == CopyStore.Synced && !whole && judged.undecided.any { before[it] != ManifestState.Unresolved }) {
                    opened.fresh.forEach { it.destroy() }
                    throw NeedsWholeAnswer()
                }
                remember = judged.remember
                judged.states.mapValues { (vid, state) -> if (vid in judged.undecided && before[vid] == ManifestState.Unresolved) ManifestState.Unresolved else state }
            }
        }
        // Items gone for certain: deleted for good by this phone, or absent from a vault whose manifest passed for this answer.
        val forget = purged + if (mode == CopyStore.Synced) ItemRevs.gone(priorCopy, served, states) else emptySet()
        // The copy kept: newer copies in place of older versions served; held versions checked now;
        // kept newer copies of items the server stopped sending (without that being certain) wait.
        @Suppress("NAME_SHADOWING")
        val snap = ItemRevs.keepRows(served, opened.keptRows).let { kept ->
            kept.copy(held = ItemRevs.waiting(priorCopy ?: served, kept, forget), serverTime = null, trashDays = null, whole = false)
        }
        if (mode != CopyStore.None) {
            val text = core { snap.encode() }
            withContext(Dispatchers.IO) { store.writeCache(id, text) }
            if (mode == CopyStore.Synced) {
                store.updateAccount(id) {
                    it.copy(
                        lastSync = System.currentTimeMillis(),
                        name = (snap.user as? JsonObject)?.strOrNull("name") ?: it.name,
                        // Only the unlocked account's own bundle is stored (round 5 iOS H).
                        bundle = AccountBundles.toStore(session.account, it.bundle, snap.bundle?.toString()),
                    )
                }
                val avatarSeq = ((snap.user as? JsonObject)?.get("avatar_seq") as? JsonPrimitive)?.contentOrNull?.toLongOrNull()
                if (avatarSeq != null) scope.launch { refreshAvatar(id, session, avatarSeq) }
            }
            rememberTrashSeen(id, snap.items)
        }
        // Remembered only now: together with the stored copy that carries it (never ahead of it).
        if (revs != null) rememberRevs(id, revs, opened.revUpdates, forget, snap.items.map { it.id }.toSet())
        rememberManifests(id, remember)
        // Keys of vaults gone or opened again are freed; kept ones live on in the new map.
        val kept = opened.keys.values
        vaultKeys.values.filter { old -> kept.none { it === old } }.forEach { it.destroy() }
        vaultKeys = opened.keys
        vaultHeaders = opened.headers
        invitationNames = opened.invitationNames
        copy = id to snap
        manifestStates = states
        _vault.value = opened.data.copy(offline = offline, vaults = opened.data.vaults.map { it.copy(manifest = states[it.id] ?: ManifestState.None) })
        rememberUsable(id, session, opened.data.vaults.map { it.id }.toSet(), checks)
        if (!offline) vaultKeysMaybeChanged(id, opened.data.vaults)
    }

    /** Vault [vaultId]'s manifest log after version [after] ([Manifests.fetchLog]). */
    private suspend fun manifestLog(id: String, vaultId: String, after: Long): String? =
        Manifests.fetchLog(after) { from -> api.call(id, Manifests.logPath(vaultId, from)) }

    /**
     * Account [id]'s remembered item edit counters (read from the phone once per account and kept);
     * null while the file can't be read (not the same as empty: nothing is written over it).
     */
    private suspend fun itemRevsOf(id: String): Map<String, Long>? {
        itemRevs?.takeIf { it.first == id }?.let { return it.second }
        val m = when (val r = withContext(Dispatchers.IO) { store.revs(id).read() }) {
            SealedFile.Read.Unreadable -> return null
            SealedFile.Read.Missing -> emptyMap()
            is SealedFile.Read.Text -> ItemRevs.decode(r.text)
        }
        itemRevs = id to m
        return m
    }

    /**
     * [updates] remembered (never lowered); [forget]: items gone for certain ([ItemRevs.gone]);
     * [present]: the copy's items (kept first when the memory is full). Written only when changed.
     */
    private suspend fun rememberRevs(id: String, memory: Map<String, Long>, updates: Map<String, Long>, forget: Set<String>, present: Set<String>) {
        val next = ItemRevs.merged(memory, updates, forget, present)
        if (next == memory) return
        val text = ItemRevs.encode(next)
        if (withContext(Dispatchers.IO) { store.revs(id).write { text } }) itemRevs = id to next
    }

    /**
     * What account [id] remembers of its vaults' manifests (read from the phone once per account
     * and kept); null while the file can't be read: no vault is checked against "nothing".
     */
    private suspend fun manifestMemoryOf(id: String): Map<String, ManifestMark>? {
        manifestMemory?.takeIf { it.first == id }?.let { return it.second }
        val m = when (val r = withContext(Dispatchers.IO) { store.manifests(id).read() }) {
            SealedFile.Read.Unreadable -> return null
            SealedFile.Read.Missing -> emptyMap()
            is SealedFile.Read.Text -> Manifests.decodeMemory(r.text)
        }
        manifestMemory = id to m
        return m
    }

    /** [updates] remembered (the higher version wins, merged with what the file holds). Written only when something went up, never over a file that can't be read. */
    private suspend fun rememberManifests(id: String, updates: Map<String, ManifestMark>) {
        if (updates.isEmpty()) return
        val memory = manifestMemoryOf(id) ?: return
        if (Manifests.merged(memory, updates) == memory) return
        val stored = withContext(Dispatchers.IO) {
            var out = memory
            val done = store.manifests(id).write { text ->
                out = Manifests.merged(Manifests.merged(Manifests.decodeMemory(text), memory), updates)
                Manifests.encodeMemory(out)
            }
            out.takeIf { done }
        } ?: return
        manifestMemory = id to stored
    }

    /** When account [id] first saw each trashed item in the trash; null while the file can't be read (no old trash is deleted then). */
    private suspend fun trashSeenOf(id: String): Map<String, Long>? {
        trashSeen?.takeIf { it.first == id }?.let { return it.second }
        val m = when (val r = withContext(Dispatchers.IO) { store.trashSeen(id).read() }) {
            SealedFile.Read.Unreadable -> return null
            SealedFile.Read.Missing -> emptyMap()
            is SealedFile.Read.Text -> TrashSeen.decode(r.text)
        }
        trashSeen = id to m
        return m
    }

    /** The trash times brought up to the copy's [rows] ([TrashSeen.updated]), by this phone's clock. Written only when changed. */
    private suspend fun rememberTrashSeen(id: String, rows: List<SyncItem>) {
        val memory = trashSeenOf(id) ?: return
        val next = TrashSeen.updated(memory, rows, now())
        if (next == memory) return
        val text = TrashSeen.encode(next)
        if (withContext(Dispatchers.IO) { store.trashSeen(id).write { text } }) trashSeen = id to next
    }

    /**
     * The vaults just shown as usable, kept per account ([SigningMemory.usable]) as the next unlock's
     * "earlier copy" (rule 6): every vault shown while the server doesn't sign, else the ones checked
     * "ok" — only once this phone finished the account's first signed sync (a vault held meanwhile
     * mustn't drop out of the list).
     */
    private suspend fun rememberUsable(id: String, session: Session, shown: Set<String>, checks: SharingChecks?) {
        if (checks != null && session.sharing?.firstSignedSyncDone != true) return
        val server = store.get().accounts[id]?.server.orEmpty()
        val me = session.sharing?.me ?: session.accountId
        if (store.get().signingMemory(server, me).usable == shown) return
        store.update { st -> st.updatingSigning(server, me) { it.copy(usable = shown) } }
    }

    /**
     * After a write the server already has the change: a failed follow-up sync must not
     * report the save as failed (a retry would duplicate it). The next revision check syncs.
     */
    private suspend fun syncAfterWrite() {
        try {
            syncLocked()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            _vault.value = _vault.value?.copy(offline = true, syncProblem = (e as? ServerTooOldException)?.message)
        }
    }

    /**
     * After this device's write into [vaultId] ([answer]: the server's reply, with `vault_seq` on
     * servers with delta sync): when it is the vault's next number nothing else changed there, so
     * [change] is applied to the copy without asking the server; when the copy already has it
     * nothing is done; otherwise (other writes too, a move, an older server) the copy is synced,
     * as before every write.
     */
    private suspend fun afterWrite(vaultId: String, answer: JsonElement?, change: LocalChange?, sent: ManifestEntry? = null) {
        val id = activeId()
        val c = copy?.takeIf { it.first == id }
        val session = sessions[id]
        // With a manifest sent, the copy takes the write only when the answer names exactly that version.
        if (change == null || c == null || session == null || !Manifests.mayApplyLocally(sent, answer)) return syncAfterWrite()
        val known = c.second.vaults.firstOrNull { it.id == vaultId }?.seq
        val seq = ((answer as? JsonObject)?.get("vault_seq") as? JsonPrimitive)?.longOrNull
        // The copy with this write (the vault at [number]), stored, and only then the manifest it carried
        // remembered: what this phone remembers is never ahead of the copy it holds.
        suspend fun apply(number: Long): Boolean {
            val next = SyncMerge.applyLocal(change, vaultId, number, c.second, sent) ?: return false
            return try {
                show(
                    id, session, next, offline = false, mode = CopyStore.LocalChange,
                    written = listOfNotNull(sent).associate { it.vaultId to it.mark },
                    purged = (change as? LocalChange.PurgeAll)?.ids.orEmpty(),
                )
                true
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
        }
        when (SyncDecision.afterWrite(known, seq).takeUnless { it == SyncDecision.AfterWrite.Nothing && sent != null } ?: SyncDecision.AfterWrite.Sync) {
            SyncDecision.AfterWrite.Nothing -> return
            SyncDecision.AfterWrite.ApplyLocally -> if (seq == null || !apply(seq)) syncAfterWrite()
            SyncDecision.AfterWrite.Sync -> {
                // The server stored exactly the manifest sent, so the vault's items are the copy's with this
                // write, whatever else was written there (a name, sharing, files): taken under the vault's old
                // number, so the sync that follows still brings the rest, and a write the server took is
                // remembered even when that sync fails.
                if (sent != null && known != null) apply(known)
                syncAfterWrite()
            }
        }
    }

    // ------------------------------------------------------ vault manifests

    private fun urlPart(s: String) = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    /** The header of vault [vaultId] in the active account's copy. */
    private suspend fun copyVault(vaultId: String): SyncVault? = copy?.takeIf { it.first == activeId() }?.second?.vaults?.firstOrNull { it.id == vaultId }

    /**
     * The row of an item as the copy holds it, for the manifest of a write that changes or removes
     * it. Missing from a vault with a manifest: the copy is behind what the caller holds, so the
     * write syncs first ([ItemWrites.StaleCopy]); null for a vault without one (nothing is needed).
     */
    private suspend fun rowForWrite(itemId: String, vaultId: String): SyncItem? {
        val c = copy?.takeIf { it.first == activeId() }?.second
        c?.items?.firstOrNull { it.id == itemId && it.vaultId == vaultId }?.let { return it }
        if (c == null || (c.vaults.firstOrNull { it.id == vaultId }?.manifestSeq ?: 0) > 0) throw ItemWrites.StaleCopy()
        return null
    }

    /**
     * The manifest entry a write into [vaultId] carries ([Manifests.next]): null for a vault without
     * a manifest; [Manifests.HELD] for one whose warning isn't resolved. A copy that couldn't be
     * checked yet (shown from this phone before the server answered) is synced first.
     */
    private suspend fun manifestEntry(vaultId: String, removed: List<SyncItem>, added: List<SyncItem>): ManifestEntry? {
        val v = copyVault(vaultId) ?: return null
        val state = manifestStates[vaultId]
        // Not checked against the server's answer yet: the sync first. Unless what this phone remembers
        // can't be read (a sync can't check it either): held, like a vault with a warning.
        if (state == ManifestState.Unchecked) throw if (manifestMemoryOf(activeId()) == null) UserException(Manifests.HELD) else ItemWrites.StaleCopy()
        val key = vaultKeys[vaultId] ?: throw UserException("Vault not found.")
        return core { Manifests.next(key, v, state, removed, added) }
    }

    /**
     * After a foreground sync, once per answer and never retried (the next sync decides again): a
     * vault without a manifest gets its first one when the server says every member's apps keep
     * them ([Manifests.mayStart]); in a vault with one, trash older than the server's retention is
     * deleted for good ([Manifests.dueTrash]: the server no longer does that by itself there).
     * Only for vaults the account can write to; failures are ignored.
     */
    private suspend fun manifestUpkeep(id: String, session: Session, serverTime: Long?, trashDays: Long?) {
        val account = store.get().accounts[id] ?: return
        if (account.features?.contains(Manifests.FEATURE) != true) return
        // Nothing is started or deleted while this phone can't read what it remembers.
        if (manifestMemoryOf(id) == null) return
        // Trashed rows this phone kept from before manifests carry no hash, and a delta never sends them
        // again: before a first manifest can be started here, everything is fetched once in full.
        try {
            val c = copy?.takeIf { it.first == id }?.second ?: return
            val roles = _vault.value?.vaults.orEmpty().associate { it.id to it.role }
            val blocked = c.vaults.any { v ->
                (v.manifestSeq ?: 0) == 0L && v.manifestOk == true && roles[v.id].let { it != null && it != Role.Read } &&
                    manifestStates[v.id] == ManifestState.None && c.items.any { it.vaultId == v.id && !Manifests.countable(it) }
            }
            if (blocked) showWholeAnswer(id, session)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            return
        }
        val vaultIds = copy?.takeIf { it.first == id }?.second?.vaults?.map { it.id } ?: return
        for (vid in vaultIds) {
            try {
                if (sessions[id] !== session || activeId() != id || _vault.value?.offline != false) return
                val c = copy?.takeIf { it.first == id }?.second ?: return
                val v = c.vaults.firstOrNull { it.id == vid } ?: continue
                val key = vaultKeys[vid] ?: continue
                val role = _vault.value?.vaults?.firstOrNull { it.id == vid }?.role ?: continue
                if (role == Role.Read) continue
                val rows = c.items.filter { it.vaultId == vid }
                val state = manifestStates[vid]
                // One attempt per vault and vault number: not again at every sync while nothing changed.
                val tried = "$id|$vid"
                val number = v.seq ?: continue
                if (upkeepTried[tried] == number) continue
                val memory = manifestMemoryOf(id) ?: return
                if (Manifests.mayStart(v, state, role, true, memory[vid], rows, _vault.value?.rolledBack.orEmpty())) {
                    val (body, entry) = core { Manifests.startBody(key, v, 1, rows) } ?: continue
                    upkeepTried[tried] = number
                    val answer = api.call(id, "/vaults/${urlPart(vid)}/manifest", body, "PUT")
                    afterWrite(vid, answer, LocalChange.ManifestOnly, entry)
                } else if (state == ManifestState.Ok && (v.manifestSeq ?: 0) > 0) {
                    // Only what this phone has itself watched in the trash for the retention ([TrashSeen]); one chunk per sync.
                    val seen = trashSeenOf(id) ?: continue
                    val due = Manifests.dueTrash(rows, serverTime, trashDays, seen, now()).take(Manifests.purgeChunk(account.maxImportItems))
                    if (due.isEmpty()) continue
                    val entry = core { Manifests.next(key, v, state, due, emptyList()) } ?: continue
                    upkeepTried[tried] = number
                    val answer = api.call(id, "/vaults/${urlPart(vid)}/trash/purge", Manifests.purgeBody(due, entry))
                    afterWrite(vid, answer, LocalChange.PurgeAll(due.map { it.id }.toSet()), entry)
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // One attempt: another device probably did it; the next sync shows.
            }
        }
    }

    /**
     * "Use the server's copy" of vault [vaultId] ([Manifests.CONFIRM_BODY], after the user confirmed):
     * the vault is fetched in full, and a new manifest for exactly what the server sent is written
     * as a version above the vault's and above everything this phone remembers. Only for a vault
     * whose warning is showing, by an account that can write to it.
     */
    suspend fun useServerCopy(vaultId: String) = mutex.withLock {
        val id = activeId()
        val session = sessions[id] ?: throw UserException("Your vault is locked.")
        repeat(Manifests.ATTEMPTS) { attempt ->
            requireSupportedServer(id)
            // Exactly what the server sends now: everything, not a delta on this phone's copy.
            try {
                showWholeAnswer(id, session)
            } catch (e: ManifestLogUnavailable) {
                throw e.cause as? Exception ?: e
            }
            if (sessions[id] !== session || activeId() != id) throw UserException("Your vault is locked.")
            // Resolved by this sync (or the vault is gone): nothing to accept.
            if (manifestStates[vaultId] != ManifestState.Unresolved) return@withLock
            val v = copyVault(vaultId) ?: return@withLock
            val role = _vault.value?.vaults?.firstOrNull { it.id == vaultId }?.role
            if (role == null || role == Role.Read) throw UserException(Manifests.READERS)
            val key = vaultKeys[vaultId] ?: throw UserException("Vault not found.")
            val rows = copy?.second?.items.orEmpty().filter { it.vaultId == vaultId }
            // Above everything this phone remembers: without that memory no version can be chosen.
            val memory = manifestMemoryOf(id) ?: throw DeltaSync.unreadable()
            val seq = Manifests.baselineSeq(v.manifestSeq, memory[vaultId]?.version)
            val (body, entry) = try {
                core { Manifests.startBody(key, v, seq, rows) }
            } catch (_: CoreException) {
                null
            } ?: throw DeltaSync.unreadable()
            try {
                val answer = api.call(id, "/vaults/${urlPart(vaultId)}/manifest", body, "PUT")
                afterWrite(vaultId, answer, LocalChange.ManifestOnly, entry)
                return@withLock
            } catch (e: ApiException) {
                when {
                    Manifests.isNotReady(e) -> throw UserException(Manifests.NOT_READY)
                    Manifests.isConflict(e) && attempt < Manifests.ATTEMPTS - 1 -> return@repeat
                    Manifests.isConflict(e) -> throw UserException(Manifests.CHANGED_ELSEWHERE)
                    else -> throw e
                }
            }
        }
    }

    /**
     * What one decryption produced, kept so the next one decrypts only what changed. [fresh]: keys
     * opened by it; [invitationNames]: the vault names read from invitations ([Invitations.cacheKey]).
     */
    private class Opened(
        val data: VaultData,
        val keys: Map<String, VaultKey>,
        val headers: Map<String, SyncVault>,
        val fresh: List<VaultKey>,
        val invitationNames: Map<String, String?> = emptyMap(),
        /** Item edit counters seen newer than remembered ([ItemRevs]). */
        val revUpdates: Map<String, Long> = emptyMap(),
        /** Rows of newer copies kept instead of an older version served (by item id). */
        val keptRows: Map<String, SyncItem> = emptyMap(),
        /** Opened vaults with a live item that doesn't open: behind a manifest that counts it, an item is being hidden. */
        val hidden: Set<String> = emptySet(),
    )

    /**
     * Decrypt a copy, reusing what [previous] already opened: a vault key whose header (wrapping,
     * kind, epoch) is unchanged, the vault's name while its `meta` is too, and items whose
     * ciphertext is the same in a vault whose key was kept. A vault key that can't be opened
     * (rotated) is skipped with its items, and so is an undecryptable item; trashed items aren't
     * shown (the app has no trash view; with `trash=summary` they have no data anyway).
     */
    private fun decryptVault(
        account: Account,
        snap: SyncSnapshot,
        previous: Opened?,
        previousNames: Map<String, String?>,
        checks: SharingChecks? = null,
        revs: Map<String, Long> = emptyMap(),
        priors: Map<String, List<SyncItem>> = emptyMap(),
    ): Opened {
        val keys = mutableMapOf<String, VaultKey>()
        val headers = mutableMapOf<String, SyncVault>()
        val kept = mutableSetOf<String>()
        val fresh = mutableListOf<VaultKey>()
        val vaults = mutableListOf<VaultInfo>()
        val oldNames = previous?.data?.vaults.orEmpty().associate { it.id to it.name }
        for (v in snap.vaults) {
            // With signed sharing only a vault that passed is opened: one refused, held for consent or
            // unopened is never shown, filled or saved to.
            val check = checks?.vaults?.get(v.id)
            if (checks != null && check !is VaultCheck.Ok) continue
            val old = previous?.headers?.get(v.id)
            val oldKey = previous?.keys?.get(v.id)
            var name: String? = null
            val key = if (old != null && oldKey != null && old.sameKey(v)) {
                kept += v.id
                if (old.meta == v.meta) name = oldNames[v.id]
                oldKey
            } else {
                try {
                    val legacy = checks?.legacyAllowed?.invoke(v.id, v.keyEpoch) ?: true
                    account.openVaultKey(v.id, v.wrappedKey, v.keyKind.ifEmpty { VaultInfo.KEY_KIND_ACCOUNT }, (v.keyEpoch ?: 0).toULong(), legacy).also { fresh += it }
                } catch (_: CoreException) {
                    continue // vault key unavailable (rotated); skip
                }
            }
            val shown = name ?: runCatching { AppJson.parseToJsonElement(key.decryptMeta(v.id, v.meta)).jsonObject.str("name") }
                .getOrNull()?.takeIf { it.isNotEmpty() } ?: "Vault"
            val role = when (v.role) {
                "owner" -> Role.Owner
                "admin" -> Role.Admin
                "write" -> Role.Write
                else -> Role.Read
            }
            keys[v.id] = key
            headers[v.id] = v
            val trust = (check as? VaultCheck.Ok)?.trust ?: VaultTrust.Unchecked
            vaults += VaultInfo(v.id, shown, role, v.keyKind.ifEmpty { VaultInfo.KEY_KIND_ACCOUNT }, v.keyEpoch, v.rotationPending == 1L, trust)
        }
        val before = previous?.data?.entries.orEmpty().associateBy { it.id }
        val entries = mutableListOf<Entry>()
        val revUpdates = mutableMapOf<String, Long>()
        val keptRows = mutableMapOf<String, SyncItem>()
        val rolledBack = mutableSetOf<String>()
        val hidden = mutableSetOf<String>()
        var keptNewer = false
        // A copy this phone has of an item (shown before, or held by a locked refresh), decrypted only when needed.
        fun priorOf(row: SyncItem): Pair<SyncItem, Item>? = priors[row.id].orEmpty()
            .filter { it.deletedAt == null && it.itemKey != null && it.data != null && it.data != row.data }
            .mapNotNull { p ->
                val k = keys[p.vaultId] ?: return@mapNotNull null
                val o = before[p.id]?.takeIf { it.enc.data == p.data && it.enc.key == p.itemKey }?.item
                    ?: runCatching { ItemCodec.decode(k.decryptItem(EncryptedItem(p.id, p.vaultId, p.itemKey!!, p.data!!))) }.getOrNull()
                o?.let { p to it }
            }
            .maxByOrNull { it.second.rev }
        for (row in snap.items) {
            if (row.deletedAt != null) continue
            val key = keys[row.vaultId] ?: continue
            val enc = EncryptedItem(row.id, row.vaultId, row.itemKey ?: continue, row.data ?: continue)
            val old = before[row.id]
            val item = if (row.vaultId in kept && old != null && old.vaultId == row.vaultId && old.enc.key == enc.key && old.enc.data == enc.data) {
                old.item
            } else {
                try {
                    ItemCodec.decode(key.decryptItem(enc))
                } catch (_: Exception) {
                    // An item that doesn't open isn't shown; its vault's manifest still counts it ([Manifests.judge]).
                    hidden += row.vaultId
                    continue
                }
            }
            // A newer copy this phone kept in place of an older version served stays marked for as long
            // as the row is that copy: until it is saved again, or the server sends that version or a newer one.
            if (ItemRevs.isKept(row)) {
                rolledBack += row.id
                keptNewer = true
            }
            // Rollback check ([ItemRevs]): the copy this phone had is read only for an item never
            // remembered (a copy from before) or one served older than remembered.
            val remembered = revs[row.id]
            val check = { r: Long?, served: Long -> itemRevCheck(r?.toULong(), served.toULong()) }
            var prior: Pair<SyncItem, Item>? = null
            var verdict = ItemRevs.judge(remembered, item.rev, null, check)
            if (remembered == null || verdict is ItemRevs.Verdict.Rollback) {
                prior = priorOf(row)
                if (prior != null) verdict = ItemRevs.judge(remembered, item.rev, prior.second.rev, check)
            }
            when (val v = verdict) {
                is ItemRevs.Verdict.Accept -> v.remember?.let { revUpdates[row.id] = it }
                is ItemRevs.Verdict.Rollback -> {
                    rolledBack += row.id
                    val p = prior
                    // Only a copy from the same vault can stand in for the row (its data is that vault's, and so is its manifest).
                    if (v.keepPrior && p != null && p.first.vaultId == row.vaultId) {
                        // The newer copy stays (shown, filled, stored) in the served row's place: with the
                        // server's revision, so editing it saves over the older version the server has, and
                        // with the hash of the data the server holds, which is what the vault's manifest records.
                        keptNewer = true
                        keptRows[row.id] = ItemRevs.keptRow(p.first, row, Manifests.serverHash(row))
                        val pe = EncryptedItem(p.first.id, p.first.vaultId, p.first.itemKey!!, p.first.data!!)
                        entries += Entry(pe.id, p.second, pe.vaultId, row.revision ?: 0, pe)
                        continue
                    }
                }
            }
            entries += Entry(enc.id, item, enc.vaultId, row.revision ?: 0, enc)
        }
        entries.sortWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.item.name })
        // Invitations: each sealed key is opened only to read the vault's name, then destroyed.
        val names = mutableMapOf<String, String?>()
        val invitations = Invitations.open(snap.invitations) { inv ->
            val key = Invitations.cacheKey(inv)
            val name = if (previousNames.containsKey(key)) previousNames[key] else invitationName(account, inv)
            names[key] = name
            name
        }.map { inv -> checks?.invitations?.get(inv.vaultId)?.let { inv.copy(trust = it) } ?: inv }
        return Opened(
            VaultData(entries, vaults, snap.revision, invitations = invitations, rolledBack = rolledBack, keptNewer = keptNewer),
            keys, headers, fresh, names, revUpdates, keptRows, hidden,
        )
    }

    // ------------------------------------------------------- signed sharing

    /**
     * What signed sharing said about a sync's vaults and invitations (by vault id); [legacyAllowed]:
     * whether an `account` wrap of a vault may be a v1 wrap (the key pins' rule).
     */
    private class SharingChecks(
        val vaults: Map<String, VaultCheck>,
        val invitations: Map<String, InvitationTrust>,
        val legacyAllowed: (String, Long?) -> Boolean,
        /** The identity record this session uploaded, for a copy whose `user.identity` is still null. */
        val identityRecord: String? = null,
        /** The key pins version this session wrote at this sync, for a copy whose `user.key_pins_seq` was read before the write. */
        val pinsSeq: Long? = null,
    )

    /** [snap] with [record] as `user.identity` when it lists none (the sync answer was read before the upload). */
    private fun withIdentity(snap: SyncSnapshot, record: String): SyncSnapshot {
        val user = snap.user as? JsonObject ?: return snap
        if (user["identity"].let { it != null && it !is kotlinx.serialization.json.JsonNull }) return snap
        val parsed = runCatching { AppJson.parseToJsonElement(record) }.getOrNull() ?: return snap
        return snap.copy(user = JsonObject(user + ("identity" to parsed)))
    }

    /**
     * [snap] with `user.key_pins_seq` raised to [seq], the version this phone wrote at this sync (the
     * answer was read before the write). The copy kept then agrees with what the server holds, so
     * this phone's own next change applied to it (which checks the copy again, [show]) doesn't take
     * the older number in the copy for the server sending an older list of known keys.
     */
    private fun withPinsSeq(snap: SyncSnapshot, seq: Long): SyncSnapshot {
        val user = snap.user as? JsonObject ?: return snap
        if ((SignedSharing.number(user, "key_pins_seq") ?: 0) >= seq) return snap
        return snap.copy(user = JsonObject(user + ("key_pins_seq" to JsonPrimitive(seq))))
    }

    private val _sharing = MutableStateFlow(SharingStatus())

    /** Signed sharing of the active account (own fingerprint, refused vaults, changed identities, pinned people, vaults to consent to). */
    val sharing: StateFlow<SharingStatus> = _sharing.asStateFlow()

    /**
     * Whether account [id] checks signed sharing: always. This app only uses servers that sign
     * shares ([ServerSupport]), so the checks never wait for the server's `/api/config` to say so
     * (a server that breaks or changes its feature list can't switch them off, on a new phone
     * either); a server that then sends nothing signed gets its shared vaults refused.
     */
    @Suppress("UNUSED_PARAMETER")
    private fun signedSharingOn(id: String, session: Session, online: Boolean, snap: SyncSnapshot? = null): Boolean = true

    /** The signed sharing of [session] (made once per unlock, on account [id]'s requests and this phone's memory). */
    private suspend fun sharingFor(id: String, session: Session): SharingSession {
        session.sharing?.let { return it }
        val server = store.get().accounts[id]?.server.orEmpty()
        fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
        val api = object : SharingApi {
            override suspend fun putIdentity(recordJson: String): Boolean {
                val answer = api.call(id, "/account/identity", AppJson.parseToJsonElement(recordJson), "PUT") as? JsonObject
                return (answer?.get("created") as? JsonPrimitive)?.content == "true"
            }

            override suspend fun currentIdentity(): JsonElement? =
                ((AppJson.parseToJsonElement(api.callText(id, "/sync")) as? JsonObject)?.get("user") as? JsonObject)?.get("identity")

            override suspend fun getKeyPins(): Pair<String?, Long> {
                val o = api.call(id, "/account/key-pins") as? JsonObject ?: throw UserException(EmergencyClient.UNEXPECTED)
                return SignedSharing.text(o, "key_pins") to (SignedSharing.number(o, "seq") ?: throw UserException(EmergencyClient.UNEXPECTED))
            }

            override suspend fun putKeyPins(sealed: String, seq: Long) {
                api.call(id, "/account/key-pins", buildJsonObject { put("key_pins", sealed); put("seq", seq) }, "PUT")
            }

            override suspend fun rosters(vaultId: String, after: Long): Pair<List<String>, Boolean> {
                val o = api.call(id, "/vaults/${enc(vaultId)}/rosters?after=$after") as? JsonObject
                    ?: throw ApiException(200, "malformed", EmergencyClient.UNEXPECTED)
                val list = (o["rosters"] as? kotlinx.serialization.json.JsonArray)?.map { r ->
                    (r as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw ApiException(200, "malformed", EmergencyClient.UNEXPECTED)
                } ?: throw ApiException(200, "malformed", EmergencyClient.UNEXPECTED)
                return list to ((o["more"] as? JsonPrimitive)?.content == "true")
            }

            override suspend fun stillMember(vaultId: String): Boolean? = try {
                api.call(id, "/vaults/${enc(vaultId)}/members")
                true
            } catch (e: ApiException) {
                if (SignedSharing.removalConfirmed(e)) false else null
            }
        }
        // Memory is keyed by the server and the account id the core authenticated (never the server's word).
        var made: SharingSession? = null
        val memoryStore = object : SigningMemoryStore {
            override suspend fun read(): SigningMemory = store.get().signingMemory(server, made!!.me)
            override suspend fun write(transform: (SigningMemory) -> SigningMemory) {
                store.update { it.updatingSigning(server, made!!.me, transform) }
            }
        }
        made = SharingSession(session.account, api, memoryStore, earlier = session.earlierVaults)
        session.sharing = made
        return made
    }

    /** The (cleaned) name of a vault row, read with its key only for this; "Shared vault" when it can't be. */
    private fun rowName(account: Account, v: SyncVault, legacyAllowed: Boolean): String {
        val name = runCatching {
            val key = account.openVaultKey(v.id, v.wrappedKey, v.keyKind.ifEmpty { VaultInfo.KEY_KIND_ACCOUNT }, (v.keyEpoch ?: 0).toULong(), legacyAllowed)
            try {
                Invitations.nameOf(AppJson.parseToJsonElement(key.decryptMeta(v.id, v.meta)))
            } finally {
                key.destroy()
            }
        }.getOrNull()
        return SignedSharing.cleanName(name).ifEmpty { Invitations.UNNAMED }
    }

    /**
     * Signed sharing for a copy about to be shown: the account named must be this one, its identity
     * and key pins brought up to date ([online]: from the server; else this phone's copies, and newer
     * rosters can't be fetched), the vaults of the first signed sync grandfathered, every vault's key
     * and every invitation checked, new pins written. Null when the account's server doesn't sign
     * shares (nothing is checked, as before).
     */
    private suspend fun verifySharing(id: String, session: Session, snap: SyncSnapshot, online: Boolean, sharedBefore: Set<String>, fromServer: Boolean): SharingChecks? {
        if (!signedSharingOn(id, session, online, snap)) {
            if (id == activeId()) _sharing.value = SharingStatus()
            return null
        }
        return withContext(Dispatchers.Default) {
            val sh = sharingFor(id, session)
            try {
                sh.refresh(snap.user, online)
            } catch (e: WrongAccountException) {
                throw e
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // Identity or pins not reachable now: checked with what this phone has.
            }
            // Only the unsigned shared vaults present now that this phone's copy from an earlier session had (signed ones are
            // checked on their own), each with the key id of the key it has now (round 5); one whose key doesn't open isn't kept.
            sh.grandfather(
                snap.vaults.filter { it.keyKind == "sealed" && (it.share == null || it.share is kotlinx.serialization.json.JsonNull) }.mapNotNull { v ->
                    runCatching {
                        val k = session.account.openVaultKey(v.id, v.wrappedKey, "sealed", (v.keyEpoch ?: 0).toULong(), false)
                        try {
                            v.id to k.keyId(v.id)
                        } finally {
                            k.destroy()
                        }
                    }.getOrNull()
                },
                online,
            )
            sh.beginChecks()
            val vaults = mutableMapOf<String, VaultCheck>()
            val names = mutableMapOf<String, String>()
            for (v in snap.vaults) {
                val kind = v.keyKind.ifEmpty { VaultInfo.KEY_KIND_ACCOUNT }
                val check = sh.checkVault(
                    v,
                    open = { legacy -> session.account.openVaultKey(v.id, v.wrappedKey, kind, (v.keyEpoch ?: 0).toULong(), legacy) },
                    nameOf = { rowName(session.account, v, sh.legacyAllowed(v.id, v.keyEpoch)) },
                    online = online,
                )
                vaults[v.id] = check
                if (check is VaultCheck.Refused || check is VaultCheck.Held) names[v.id] = rowName(session.account, v, sh.legacyAllowed(v.id, v.keyEpoch))
            }
            val invitations = mutableMapOf<String, InvitationTrust>()
            for (inv in snap.invitations) {
                invitations[inv.vaultId] = sh.checkInvitation(
                    inv,
                    { i -> runCatching { session.account.openVaultKey(i.vaultId, i.wrappedKey, "sealed", 0u, false) }.getOrNull() },
                    online,
                )
            }
            sh.endChecks()
            // Accepted shared vaults a sync from the server no longer lists: tombstoned once that is confirmed
            // (the server says it's gone, or two such syncs in a row), so the server can't bring the old copy back.
            sh.tombstoneRemoved(snap.vaults.map { it.id }.toSet(), sharedBefore, fromServer)
            if (online) savePinsQuietly(sh)
            if (sessions[id] === session && id == activeId()) publishSharing(sh, vaults, names, sh.missingWhy())
            SharingChecks(vaults, invitations, { vid, epoch -> sh.legacyAllowed(vid, epoch) }, sh.uploadedRecord, sh.serverPinsSeq.takeIf { online })
        }
    }

    /** Write changed key pins; a failure leaves them for the next sync. */
    private suspend fun savePinsQuietly(sh: SharingSession) {
        try {
            sh.savePins()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
        }
    }

    private fun publishSharing(sh: SharingSession, vaults: Map<String, VaultCheck>? = null, names: Map<String, String> = emptyMap(), missingWhy: String? = _sharing.value.missingWhy) {
        val before = _sharing.value
        val refused = vaults?.mapNotNull { (vid, c) -> (c as? VaultCheck.Refused)?.let { RefusedVault(vid, names[vid] ?: Invitations.UNNAMED, it.reason) } } ?: before.refused
        val checking = vaults?.mapNotNull { (vid, c) -> (c as? VaultCheck.Held)?.let { RefusedVault(vid, names[vid] ?: Invitations.UNNAMED, it.reason) } } ?: before.checking
        val consent = vaults?.mapNotNull { (_, c) -> (c as? VaultCheck.Consent)?.vault } ?: before.consent
        val problem = sh.pinsProblem ?: SignedSharing.MEMORY_UNREADABLE.takeIf { sh.memoryUnreadable }
        _sharing.value = SharingStatus(true, sh.fingerprint, sh.paused, problem, refused, sh.changed, SignedSharing.people(sh.pins), consent, sh.memoryMissing, missingWhy, checking)
    }

    /** Signed sharing of the active, unlocked account; a [UserException] otherwise. */
    private fun activeSharing(): SharingSession {
        val (_, session) = unlockedAccount()
        return session.sharing ?: throw UserException("Sync your vault first.")
    }

    /** "Mark as verified": the user compared [userId]'s identity fingerprint of [identityHash] (the one shown) with them. */
    suspend fun markVerified(userId: String, identityHash: String) = mutex.withLock {
        val sh = activeSharing()
        if (!sh.markVerified(userId, identityHash)) throw UserException("Their keys changed since this fingerprint was shown. Compare it again.")
        try {
            sh.savePins()
        } finally {
            publishSharing(sh)
        }
    }

    /** "Trust the new key" of the change [shown] in the sheet (its identity and the email it pins; [compared]: the user compared the new fingerprint with them); the vault syncs again. */
    suspend fun trustNewKey(shown: IdentityChange, compared: Boolean) {
        mutex.withLock {
            val sh = activeSharing()
            if (!sh.trustNewKey(shown, compared)) throw UserException("Their keys changed again since this fingerprint was shown. Compare it again.")
            try {
                sh.savePins()
            } finally {
                publishSharing(sh)
            }
        }
        syncAfterAnswer()
    }

    /**
     * Accept a shared vault held for consent (the account never accepted it) exactly as [shown] (the
     * sheet's; a vault checked differently since is refused): its key and roster become what this
     * phone trusts, its signer is pinned (written to the server first), and the vault syncs again.
     */
    suspend fun acceptConsent(shown: ConsentVault) {
        mutex.withLock {
            activeSharing().acceptConsent(shown)
        }
        syncAfterAnswer()
    }

    /**
     * Decline a shared vault held for consent: a tombstone in the key pins (it never comes back unless
     * shared again with a newer signed member list), and the account leaves it on the server.
     */
    suspend fun declineConsent(shown: ConsentVault) {
        val vaultId = shown.vaultId
        val (id, me) = mutex.withLock {
            val sh = activeSharing()
            // Exactly the vault the sheet showed, and only a signed one naming its signer (rule 1).
            sh.declineConsent(shown)
            sh.savePins()
            activeId() to sh.me
        }
        try {
            api.call(id, "/vaults/${java.net.URLEncoder.encode(vaultId, "UTF-8")}/members/${java.net.URLEncoder.encode(me, "UTF-8")}", method = "DELETE")
        } catch (e: ApiException) {
            // Already gone, or the server won't let this account leave (it stays refused here).
            if (e.status !in setOf(400, 403, 404, 409)) throw e
        }
        syncAfterAnswer()
    }

    /** This phone can replace the keys of vaults shared with others (signed sharing is on and the account can sign). */
    fun canReplaceSharedKeys(): Boolean = sessions[state.value.activeId]?.sharing?.canSign == true && _sharing.value.enabled

    /** The vault name of an invitation, read with its sealed key (never kept); null when the account can't open it. */
    private fun invitationName(account: Account, inv: SyncInvitation): String? {
        val key = try {
            account.openVaultKey(inv.vaultId, inv.wrappedKey, "sealed", 0u, false)
        } catch (_: Exception) {
            return null
        }
        return try {
            Invitations.nameOf(AppJson.parseToJsonElement(key.decryptMeta(inv.vaultId, inv.meta)))
        } catch (_: Exception) {
            null
        } finally {
            key.destroy()
        }
    }

    // -------------------------------------------------------------- items

    private fun now() = System.currentTimeMillis() / 1000

    private fun writableVault(v: VaultData): VaultInfo =
        v.defaultVault ?: throw UserException("Your own vault isn't available. Choose a vault to save to.")

    private fun requireVault() = _vault.value ?: throw UserException("Your vault is locked.")

    private suspend fun requireOnline(v: VaultData) {
        // Part S: nothing is written to a server whose known config doesn't list signed sharing.
        store.get().active?.features?.let { if (!ServerSupport.supported(it)) throw ServerTooOldException() }
        if (v.offline) throw UserException("You're offline. Changes can be saved once PassAuth reaches your server.")
    }

    /**
     * Create an item. [id] keeps the item's id across the caller's retries (an editor or a save
     * sheet whose first attempt failed or timed out), so a create that did reach the server
     * isn't saved twice. Key epoch, the retry after a key change and an id that already exists:
     * see [ItemWrites].
     */
    suspend fun createItem(item: Item, vaultId: String?, id: String? = null): String = mutex.withLock { createLocked(item, vaultId, id) }

    private suspend fun createLocked(item: Item, vaultId: String?, requested: String?): String {
        requireOnline(requireVault())
        val t = now()
        val id = requested ?: core { newId() }
        val stamped = item.copy(createdAt = t, updatedAt = t)
        val json = ItemCodec.encode(stamped)
        var targetId = ""
        var sent: EncryptedItem? = null
        var manifest: ManifestEntry? = null
        var answer: JsonElement? = null
        val created = ItemWrites.create(
            send = {
                val v = requireVault()
                val target = vaultId?.let { want -> v.vaults.firstOrNull { it.id == want } } ?: writableVault(v)
                val key = vaultKeys[target.id] ?: throw UserException("Vault not found.")
                targetId = target.id
                val enc = core { key.encryptItem(json, id, target.id) }
                // A vault with a manifest: the write carries its next one, counting the new item.
                val m = manifestEntry(target.id, emptyList(), listOf(SyncItem(id, target.id, enc.key, enc.data)))
                answer = api.call(activeId(), "/items", body = ItemWrites.body(enc, target.keyEpoch, manifests = listOfNotNull(m)))
                sent = enc
                manifest = m
            },
            resync = { syncLocked() },
            updateEarlierAttempt = {
                syncLocked()
                val landed = _vault.value?.get(id)?.takeIf { it.vaultId == targetId }
                if (landed != null) updateLocked(landed, stamped.copy(createdAt = landed.item.createdAt), landed.vaultId)
                landed != null
            },
        )
        if (created == ItemWrites.Created.New) {
            val enc = sent
            val change = if (enc == null) null else ItemWrites.revision(answer)?.let { rev -> LocalChange.Put(SyncItem(id, targetId, enc.key, enc.data, rev, null, t, t)) }
            afterWrite(targetId, answer, change, manifest)
        }
        return id
    }

    /**
     * Save changes to an item; with another [targetVaultId] the item also moves to that vault
     * (re-encrypted with its key under the same id), like the web vault's `updateItem`. Throws
     * [ConflictException] when the item changed on the server since [entry] was read. Key epoch
     * and the retry after a key change: see [ItemWrites].
     */
    suspend fun updateItem(entry: Entry, item: Item, targetVaultId: String = entry.vaultId) {
        mutex.withLock { updateLocked(entry, item, targetVaultId) }
    }

    /**
     * "Add this site to a login": [url] (a page origin or `androidapp://<package>`) becomes one
     * more website of the login [entry], with match "default"; nothing else changes. Saved like any
     * edit ([updateItem]: refused for a view-only vault, [ConflictException] on a newer version).
     */
    suspend fun addWebsite(entry: Entry, url: String) {
        val login = entry.item.login ?: throw UserException("Login not found.")
        updateItem(entry, entry.item.copy(login = login.copy(urls = login.urls + LoginUrl(url, UrlMatch.Default))))
    }

    private suspend fun updateLocked(base: Entry, item: Item, targetVaultId: String) {
        requireOnline(requireVault())
        val t = now()
        var next = item.copy(updatedAt = t)
        val old = base.item.login?.password
        val newPassword = next.login?.password
        if (next.login != null && !old.isNullOrEmpty() && old != newPassword && next.passwordHistory == base.item.passwordHistory) {
            next = next.copy(passwordHistory = (listOf(PasswordChange(old, t)) + next.passwordHistory).take(20))
        }
        val json = ItemCodec.encode(next)
        var sent: EncryptedItem? = null
        var moved = false
        var manifest: ManifestEntry? = null
        var answer: JsonElement? = null
        ItemWrites.update(
            base,
            send = { entry ->
                val v = requireVault()
                val vault = v.vaults.firstOrNull { it.id == entry.vaultId } ?: throw UserException("Vault not found.")
                if (vault.role == Role.Read) throw UserException("You can only view items in this vault.")
                val target = v.vaults.firstOrNull { it.id == targetVaultId } ?: throw UserException("Vault not found.")
                if (target.role == Role.Read) throw UserException("You can't add items to ${target.name}.")
                val key = vaultKeys[target.id] ?: throw UserException("Vault not found.")
                val enc = core { if (target.id == entry.vaultId) key.updateItem(entry.enc, json) else key.encryptItem(json, entry.id, target.id) }
                // Vault manifests: the row as the copy holds it leaves, the row as sent arrives; a move
                // takes it out of one vault's manifest and puts it (re-encrypted) into the other's.
                val before = rowForWrite(entry.id, entry.vaultId)
                val after = SyncItem(entry.id, target.id, enc.key, enc.data, deletedAt = before?.deletedAt)
                val manifests = if (target.id == entry.vaultId) {
                    listOfNotNull(manifestEntry(target.id, listOfNotNull(before), listOf(after)))
                } else {
                    listOfNotNull(manifestEntry(entry.vaultId, listOfNotNull(before), emptyList()), manifestEntry(target.id, emptyList(), listOf(after)))
                }
                answer = api.call(activeId(), "/items/${entry.id}", body = ItemWrites.body(enc, target.keyEpoch, entry.revision, manifests), method = "PUT")
                sent = enc
                moved = target.id != entry.vaultId
                manifest = manifests.singleOrNull()
            },
            resync = {
                syncLocked()
                _vault.value?.get(base.id)
            },
        )
        // A move also changed the vault it left (its number isn't in the answer): sync.
        val enc = sent
        val change = if (moved || enc == null) null else ItemWrites.revision(answer)?.let { rev -> LocalChange.Put(SyncItem(base.id, targetVaultId, enc.key, enc.data, rev, updatedAt = t)) }
        afterWrite(targetVaultId, answer, change, if (moved) null else manifest)
    }

    /** Move an item to another vault the user can write to. */
    suspend fun moveItem(entry: Entry, vaultId: String) {
        if (vaultId == entry.vaultId) return
        updateItem(entry, entry.item, vaultId)
    }

    suspend fun setFavorite(entry: Entry, favorite: Boolean) = updateItem(entry, entry.item.copy(favorite = favorite))

    suspend fun trashItem(entry: Entry) {
        mutex.withLock {
            var current: Entry? = entry
            var answer: JsonElement? = null
            var manifest: ManifestEntry? = null
            var hash: String? = null
            var at = now()
            ItemWrites.place(
                send = {
                    val v = requireVault()
                    requireOnline(v)
                    // Gone, or in the trash already (the app doesn't show trashed items): done.
                    val e = current ?: return@place
                    if (!v.canWrite(e)) throw UserException("You can only view items in this vault.")
                    at = now()
                    // A vault with a manifest: the row leaves as live and comes back trashed, and the item's revision is named.
                    val row = rowForWrite(e.id, e.vaultId)
                    val m = if (row == null) null else manifestEntry(e.vaultId, listOf(row), listOf(row.copy(deletedAt = at)))
                    hash = row?.let { r -> core { Manifests.serverHash(r) } }
                    answer = api.call(activeId(), "/items/${e.id}" + Manifests.query(m, e.revision), method = "DELETE")
                    manifest = m
                },
                resync = {
                    syncLocked()
                    current = _vault.value?.get(entry.id)
                },
            )
            val done = current ?: return@withLock
            val change = ItemWrites.revision(answer)?.let { LocalChange.Trash(done.id, at, it, TRASH_SUMMARY, hash) }
            afterWrite(done.vaultId, answer, change, manifest)
        }
    }

    // --------------------------------------------------------- profile picture

    /** Account [id]'s offline copy and profile picture deleted from this device (log out, account removed). */
    private fun deleteLocalCopy(id: String) {
        store.deleteCache(id)
        if (itemRevs?.first == id) itemRevs = null
        if (manifestMemory?.first == id) manifestMemory = null
        if (trashSeen?.first == id) trashSeen = null
        _avatars.update { it - id }
    }

    /** Keep account [id]'s picture at [seq] ([jpeg] empty: none) on this device and show it. */
    private suspend fun keepAvatar(id: String, seq: Long, jpeg: ByteArray) {
        val image = withContext(Dispatchers.IO) {
            store.avatars.write(id, seq, jpeg)
            AvatarImage.decode(jpeg)
        }
        _avatars.update { if (image != null) it + (id to image) else it - id }
    }

    /**
     * After a sync of account [id] the server's picture is at [serverSeq]: fetched and opened only when
     * it differs from the one kept here. A network failure tries again at the next sync; a picture that
     * doesn't open (or isn't there) is kept as "none at this seq", so the initials stay.
     */
    private suspend fun refreshAvatar(id: String, session: Session, serverSeq: Long) {
        try {
            val cached = withContext(Dispatchers.IO) { store.avatars.read(id) }?.seq ?: 0
            if (!AvatarRules.needsFetch(cached, serverSeq)) return
            val o = api.call(id, "/account/avatar") as? JsonObject ?: return
            val seq = o.long("avatar_seq")
            val sealed = o.strOrNull("avatar")
            val jpeg = mutex.withLock {
                // Locked or signed out meanwhile: the next sync after unlock tries again.
                if (sessions[id] !== session || store.get().accounts[id]?.tokens == null) return
                if (sealed.isNullOrEmpty()) ByteArray(0)
                else runCatching { core { session.account.openAvatar(sealed) } }.getOrElse {
                    android.util.Log.w("PassAuth", "Profile picture couldn't be opened")
                    ByteArray(0)
                }
            }
            keepAvatar(id, seq, jpeg)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w("PassAuth", "Profile picture not fetched: ${e.javaClass.simpleName}")
        }
    }

    /** Set the active account's profile picture to [jpeg] (from [AvatarImage.prepare]): sealed with the Account Key, then uploaded. */
    suspend fun setAvatar(jpeg: ByteArray) {
        if (jpeg.isEmpty() || jpeg.size > AvatarRules.MAX_BYTES) throw UserException("That picture is too large. Choose another one.")
        val (id, sealed) = mutex.withLock {
            val id = activeId()
            val session = sessions[id] ?: throw UserException("Unlock first.")
            requireOnlineFor("Changing your profile picture")
            id to core { session.account.sealAvatar(jpeg) }
        }
        val o = api.call(id, "/account/avatar", buildJsonObject { put("avatar", sealed) }, "PUT") as? JsonObject
        keepAvatar(id, o?.long("avatar_seq") ?: 0, jpeg)
    }

    /** Remove the active account's profile picture (the initials come back). */
    suspend fun removeAvatar() {
        val id = mutex.withLock {
            val id = activeId()
            if (!sessions.containsKey(id)) throw UserException("Unlock first.")
            requireOnlineFor("Removing your profile picture")
            id
        }
        val o = api.call(id, "/account/avatar", method = "DELETE") as? JsonObject
        keepAvatar(id, o?.long("avatar_seq") ?: 0, ByteArray(0))
    }

    // ------------------------------------------- re-authentication, account

    /**
     * A fresh proof of the master password from the server: an OPAQUE login with
     * `purpose: "reauth"` on the signed-in session (the web vault's `reauth`).
     * The token is good for one sensitive request within five minutes.
     */
    private suspend fun reauthToken(id: String, password: String, secretKey: String?): String {
        val s = store.get()
        val a = s.accounts[id]?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
        val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
        return withContext(Dispatchers.Default) { security(id).reauth(a.email, password, sk) }
    }

    /** Account security requests of account [id]; [account] (unlocked) is needed only to re-wrap its key. */
    private suspend fun security(id: String, account: Account? = null) = AccountSecurity(
        { path, body, method, auth, headers -> api.call(id, path, body, method, auth, headers) },
        CoreSecurityCrypto(account),
        deviceInfo(),
    )

    private fun requireOnlineFor(what: String) {
        if (_vault.value?.offline == true) throw UserException("You're offline. $what needs your server.")
    }

    /**
     * Change the master password and/or the Secret Key setting of the active account
     * (the web vault's `changeKeys`). Returns a newly created Secret Key (show it once).
     *
     * Afterwards this device keeps working with the new password: the stored bundle and
     * Secret Key are replaced at once (see [afterKeyChange]), so the next unlock — here,
     * in autofill and in the passkey provider — uses them. The unlocked session, biometric
     * unlock and "never" keys hold the account key, which a re-wrap doesn't change, so they
     * stay valid. A sync then refreshes the offline copy (it carries the bundle too).
     * The server signs out every other device.
     */
    suspend fun changeMasterPassword(current: String, new: String, choice: SecretKeyChoice, secretKey: String?): String? = mutex.withLock {
        val s = store.get()
        val id = s.activeId
        val a = s.active?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
        val session = sessions[id] ?: throw UserException("Unlock your vault first.")
        requireOnlineFor("Changing your master password")
        val bundle = a.bundle ?: throw UserException("Sync your vault first.")
        val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
        // The server's minimums for new keys, asked again now (a stale copy could make keys it refuses).
        val kdf = PolicyRules.kdfMinimums(refreshConfig(id)) ?: a.policies?.let(PolicyRules::kdfMinimums)
        val change = withContext(Dispatchers.Default) {
            security(id, session.account).changeKeys(a.email, bundle, current, new, choice, sk, kdf)
        }
        // First thing after the server accepted it: the old bundle no longer matches the server.
        store.update { it.afterKeyChange(id, change) }
        persistForNever(id)
        syncAfterWrite()
        change.secretKey
    }

    /** Two-step login methods and recovery codes of the active account (GET /account). */
    suspend fun securityStatus(): SecurityStatus = security(activeId()).status()

    /** Items and storage of the active account against the server's limits (GET /account). */
    suspend fun accountUsage(): AccountUsage = security(activeId()).usage()

    suspend fun totpSetup(): TotpSetup = security(activeId()).totpSetup()

    /** Turn the authenticator app on with its code, after re-authentication (the master password, and the Secret Key when this device lacks it). */
    suspend fun totpEnable(code: String, password: String, secretKey: String?): List<String>? = mutex.withLock {
        val s = store.get()
        val id = s.activeId
        val a = s.active?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
        val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
        withContext(Dispatchers.Default) { security(id).totpEnable(code, a.email, password, sk) }
    }

    suspend fun emailTwoFactorSetup() = security(activeId()).emailSetup()

    /** Turn email codes on with the emailed code, after re-authentication (as [totpEnable]). */
    suspend fun emailTwoFactorEnable(code: String, password: String, secretKey: String?): List<String>? = mutex.withLock {
        val s = store.get()
        val id = s.activeId
        val a = s.active?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
        val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
        withContext(Dispatchers.Default) { security(id).emailEnable(code, a.email, password, sk) }
    }

    /** New recovery codes after re-authentication (the current ones stop working). */
    suspend fun regenerateRecoveryCodes(password: String, secretKey: String?): List<String> = mutex.withLock {
        val s = store.get()
        val id = s.activeId
        val a = s.active?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
        val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
        withContext(Dispatchers.Default) { security(id).regenerateRecoveryCodes(a.email, password, sk) }
    }

    /** Turn off a two-step method after re-authentication. */
    suspend fun disableTwoFactor(provider: String, password: String, secretKey: String?) {
        mutex.withLock {
            val s = store.get()
            val id = s.activeId
            val a = s.active?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
            val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
            withContext(Dispatchers.Default) { security(id).disable(provider, a.email, password, sk) }
        }
    }

    /** Remove a two-step login security key after re-authentication. */
    suspend fun removeSecurityKey(keyId: String, password: String, secretKey: String?) {
        mutex.withLock {
            val s = store.get()
            val id = s.activeId
            val a = s.active?.takeIf { it.tokens != null } ?: throw UserException("Sign in first.")
            val sk = secretKey?.trim()?.takeIf { it.isNotEmpty() } ?: s.secretKeys[a.email.lowercase()]
            withContext(Dispatchers.Default) { security(id).removeSecurityKey(keyId, a.email, password, sk) }
        }
    }

    /** The active account's sessions (Settings → Account security → Signed-in devices). */
    suspend fun accountSessions(): SessionList = security(activeId()).sessions()

    /** Sign out one of the active account's other sessions. */
    suspend fun revokeSession(sessionId: String) = security(activeId()).revokeSession(sessionId)

    /** Sign out every other session of the active account (servers with `revoke_others`); returns how many. */
    suspend fun revokeOtherSessions(): Int? = security(activeId()).revokeOtherSessions()

    /**
     * Forget a device of the active account (servers with `forget_device`): all its sessions end
     * and its next sign-in counts as a new device. When this app's own session was one of them
     * ([ForgetResult.current]), the account is signed out here too, without a remote sign-out
     * (that session is gone), and the two-step "remember this device" token is dropped (the
     * server forgot it).
     */
    suspend fun forgetDevice(deviceId: String): ForgetResult {
        val id = activeId()
        val r = security(id).forgetDevice(deviceId)
        if (r.current) {
            mutex.withLock {
                store.update { it.withoutRememberToken(id) }
                signOutLocally(id)
            }
        }
        return r
    }

    // ------------------------------------- approving another device's sign-in

    /**
     * The active account's sign-in requests from new devices (`GET /account/auth-requests`,
     * unanswered and unexpired, newest first), when the account is unlocked here and its server has
     * the feature; null otherwise (nothing to show).
     */
    suspend fun listAuthRequests(): AuthRequestListing? {
        val s = store.get()
        val id = s.activeId
        val a = s.accounts[id]?.takeIf { it.tokens != null } ?: return null
        if (id !in sessionIds.value) return null
        val features = a.features ?: refreshConfig(id)?.features ?: return null
        if (DeviceLogin.FEATURE !in features) return null
        return AuthRequestListing(id, AuthRequestApi(securityTransport(id)).list(now()))
    }

    /**
     * Approve [request] of [account] (as frozen when its sheet opened) with the words the user
     * picked ([DeviceApprovals.prepare]): when they are the request's words, the account key is
     * sealed to the new device's key (with the Secret Key this device keeps for the account, so the
     * new device can later unlock with the master password), the request's challenge is opened as
     * proof that the answer comes from an app that holds the keys, and the code the new device needs
     * is returned. Other words deny the request, and null is returned. Needs the vault unlocked here.
     */
    suspend fun approveAuthRequest(account: String, request: AuthRequest, chosenPhrase: String): String? {
        val s = store.get()
        if (account != s.activeId) throw UserException("This request is for another account. Switch back to it to answer.")
        val prepared = mutex.withLock {
            val session = sessions[account] ?: throw UserException("Unlock your vault first.")
            val secretKey = s.accounts[account]?.email?.lowercase()?.let { s.secretKeys[it] }
            core { DeviceApprovals.prepare(request, chosenPhrase, AccountApprovalCrypto(session.account), secretKey) }
        }
        val requests = AuthRequestApi(securityTransport(account))
        return when (prepared) {
            is PreparedApproval.Approve -> {
                requests.answer(request, prepared.body)
                prepared.code
            }
            PreparedApproval.Mismatch -> {
                requests.answer(request, DeviceApprovals.DENY)
                null
            }
        }
    }

    /** Deny [request] of [account] ("None of these"): needs nothing from the account's keys. */
    suspend fun denyAuthRequest(account: String, request: AuthRequest) {
        AuthRequestApi(securityTransport(account)).answer(request, DeviceApprovals.DENY)
    }

    // -------------------------------------------------------- invitations

    /**
     * Accept an invitation (the vault arrives with the sync that follows). On a server that signs
     * shares only a checked, signed invitation: its roster and key epoch become what this phone
     * trusts for the vault and a new signer is pinned, before the server is told.
     */
    suspend fun acceptInvitation(shown: Invitation) {
        val vaultId = shown.vaultId
        // The account is captured inside the lock: the answer goes to the account whose invitation was checked.
        val id = mutex.withLock {
            val (id, session) = unlockedAccount()
            val inv = _vault.value?.invitations?.firstOrNull { it.vaultId == vaultId } ?: throw UserException(InvitationText.NO_LONGER_OPEN)
            // Bound to what the sheet showed: checked differently since (another signer, key or roster) → refused.
            if (!Invitations.sameAsShown(inv, shown)) throw UserException(InvitationText.CHANGED)
            when (val t = inv.trust) {
                InvitationTrust.Unchecked -> {}
                InvitationTrust.Unsigned -> throw UserException(SignedSharing.unsignedInvitation(InvitationText.sharerShort(inv)))
                is InvitationTrust.Refused -> throw UserException(t.reason)
                is InvitationTrust.Signed -> {
                    val sh = session.sharing ?: throw UserException("Sync your vault first.")
                    // Pins written to the server before it is told (a failure leaves them as before).
                    sh.prepareAccept(vaultId, t)
                }
            }
            id
        }
        if (activeId() != id) throw UserException("You switched to another account meanwhile. Switch back and try again.")
        InvitationActions(securityTransport(id)) { if (activeId() == id) syncAfterAnswer() }.accept(vaultId)
    }

    /** Decline an invitation (a tombstone in the key pins with signed sharing); its vault's managers are asked to replace the key. */
    suspend fun declineInvitation(shown: Invitation) {
        val vaultId = shown.vaultId
        val id = mutex.withLock {
            val (id, session) = unlockedAccount()
            session.sharing?.let { sh ->
                // The tombstone at the roster version the check verified (a later share needs a newer one),
                // never for a vault id this account uses now (a made-up invitation carrying it).
                val rows = copy?.takeIf { it.first == id }?.second?.vaults.orEmpty().map { it.id }.toSet()
                // Only where it may be declined; `pins_decline` writes nothing for a vault this sync lists as a row.
                sh.declineInvitation(vaultId, shown.trust, rows)
                savePinsQuietly(sh)
            }
            id
        }
        InvitationActions(securityTransport(id)) { if (activeId() == id) syncAfterAnswer() }.decline(vaultId)
    }

    private fun securityTransport(id: String) = SecurityTransport { path, body, method, auth, headers -> api.call(id, path, body, method, auth, headers) }

    /** The sync after an answer the server took: a failure doesn't report the answer as failed (the copy shows as offline). */
    private suspend fun syncAfterAnswer() {
        try {
            sync()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            _vault.value = _vault.value?.copy(offline = true)
        }
    }

    // ------------------------------------------------- policies, two-step gate

    /**
     * The first sync after the keys are in memory (sign-in, unlock, restore). A server that
     * requires two-step login first (403 `two_step_required`) doesn't fail it: the account is
     * gated (by [ApiClient.onTwoStepRequired]) and the keys stay for [continueAfterTwoStep].
     */
    private suspend fun syncOrGate(fallbackToCache: Boolean = false, cacheFirst: Boolean = false) {
        try {
            syncLocked(fallbackToCache, cacheFirst, upkeep = true)
        } catch (e: ApiException) {
            if (!TwoStepGate.blocks(e)) throw e
        }
    }

    /**
     * The server says account [id] must set up two-step login first (live sync's
     * `two_step_required`): the same gate as a 403 `two_step_required` answer ([TwoStepGate]),
     * which also stops live sync for the account.
     */
    fun markTwoStepRequired(id: String) = gated.update { it + id }

    /**
     * After the gate's "Continue" (a two-step method is on now): with the keys in memory the vault
     * syncs, which lets it open (another 403 keeps the gate and is thrown); a locked account leaves
     * the gate and asks to be unlocked.
     */
    suspend fun continueAfterTwoStep() {
        val id = activeId()
        when (TwoStepGate.afterSetup(sessions.containsKey(id))) {
            TwoStepGate.Next.Sync -> sync()
            TwoStepGate.Next.Unlock -> gated.update { it - id }
        }
        refreshPoliciesLater(id)
    }

    /** [refreshPolicies] in the background: never blocks or fails sign-in and unlock. */
    private fun refreshPoliciesLater(id: String) {
        scope.launch {
            try {
                refreshPolicies(id)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Ask account [id]'s server for its features and policies (kept with the account; the longest
     * vault timeout follows), and read what the account still has to change (`GET /account`
     * `policy_violations`, servers with `policies`).
     */
    private suspend fun refreshPolicies(id: String) {
        val config = refreshConfig(id) ?: return
        if (PolicyRules.FEATURE !in config.features) return _violations.update { it - id }
        if (store.get().accounts[id]?.tokens == null) return
        val account = api.call(id, "/account") as? JsonObject ?: return
        val found = PolicyRules.readViolations(account["policy_violations"])
        if (store.get().accounts[id]?.tokens != null) _violations.update { it + (id to found) }
    }

    /**
     * The servers' longest vault timeout (the strictest among the signed-in accounts): a saved
     * choice above it is lowered to the longest one within it (through [updateSettings], so keys
     * kept for "never" are wiped) and Settings says so.
     */
    suspend fun enforceTimeoutPolicy() {
        val s = store.get()
        val limit = s.timeoutLimit
        if (PolicyRules.timeoutWithin(s.settings.vaultTimeout, limit)) return
        updateSettings { it.copy(vaultTimeout = PolicyRules.clampTimeout(it.vaultTimeout, limit), vaultTimeoutLowered = true) }
    }

    /** The active account's Secret Key kept on this device (for its Emergency Kit), if any. */
    suspend fun storedSecretKey(): String? = store.get().let { s -> s.active?.let { s.secretKeys[it.email.lowercase()] } }

    /**
     * Delete the active account on the server (with every vault it owns), after
     * re-authenticating with the master password, then forget it on this device
     * like Log out.
     */
    suspend fun deleteAccount(password: String, secretKey: String?) {
        mutex.withLock {
            val s = store.get()
            val id = s.activeId
            val a = s.active ?: throw UserException("Sign in first.")
            requireOnlineFor("Deleting your account")
            val token = reauthToken(id, password, secretKey)
            api.call(id, "/account", method = "DELETE", headers = mapOf("x-reauth-token" to token))
            // The server has ended every session of this account: no remote logout.
            closeSession(id)
            forgetSessionState(id)
            pendingMaster?.destroy()
            pendingMaster = null
            Keystore.deleteBiometricKey(id)
            deleteLocalCopy(id)
            val email = a.email.lowercase()
            val sameEmailElsewhere = s.accounts.any { (k, v) -> k != id && v.email.equals(email, ignoreCase = true) }
            val deletedUser = Stored.bundleUserId(a.bundle)
            store.update { st ->
                // The account is gone from the server: its roster memory goes too.
                (if (deletedUser != null) st.forgettingRoster(a.server, deletedUser) else st).copy(
                    secretKeys = if (sameEmailElsewhere) st.secretKeys else st.secretKeys - email,
                    rememberTokens = st.rememberTokens - "${a.server}|$email",
                )
            }
            val listed = s.accounts.filterValues(::isListed)
            if (listed.size > 1 || !listed.containsKey(id)) {
                removeAccount(id)
            } else {
                // Keep only the server address, so the sign-in screen still knows where to go, with what is
                // known about that server: forgetting its feature list would let it be signed in to again
                // without the check that it signs shares.
                store.updateAccount(id) {
                    AccountData(server = it.server, features = it.features, featuresAt = it.featuresAt, api = it.api, policies = it.policies, maxImportItems = it.maxImportItems)
                }
            }
        }
    }

    /** Check the master password locally against the account bundle (works offline). */
    suspend fun verifyMasterPassword(password: String) {
        val s = store.get()
        val a = s.active ?: throw UserException("Sign in first.")
        val bundle = a.bundle ?: throw UserException("Sync your vault first.")
        val b = AppJson.parseToJsonElement(bundle).jsonObject
        val skEnabled = b.bool("secret_key_enabled")
        val sk = s.secretKeys[a.email.lowercase()]
        if (skEnabled && sk == null) throw UserException(SECRET_KEY_REQUIRED)
        core {
            val master = deriveMasterKeys(password, sk, b.str("account_id"), b["kdf"].toString(), skEnabled)
            try {
                master.unlock(bundle).destroy()
            } catch (_: CoreException) {
                throw UserException("Wrong master password.")
            } finally {
                master.destroy()
            }
        }
    }

    /** The unlocked vault's items as a JSON array in the item format (input of the core's export functions). */
    fun itemsJsonForExport(): String {
        val v = requireVault()
        // Files aren't exported: no file key leaves in an export file.
        return v.entries.joinToString(",", "[", "]") { ItemCodec.encode(Attachments.strip(it.item)) }
    }

    // ------------------------------------------- Send, attachments, emergency access

    /** The active account's server's `/api/config` features (asked again when stale); null when unknown. */
    suspend fun features(): List<String>? = featuresOf(activeId())

    /** Account record [id]'s server's `/api/config` features (asked again when stale); null when unknown. */
    private suspend fun featuresOf(id: String): List<String>? {
        val a = store.get().accounts[id] ?: return null
        val now = System.currentTimeMillis()
        if (a.features != null && now >= a.featuresAt && now - a.featuresAt < FEATURES_MAX_AGE_MS) return a.features
        return refreshConfig(id)?.features ?: a.features
    }

    /** The active account's server's `/api/config` `limits`, asked now; null when it couldn't be read. */
    suspend fun serverLimits(): JsonObject? = publicConfig()?.limits

    /** The unlocked account of the active record, or a [UserException]. */
    private fun unlockedAccount(): Pair<String, Session> {
        val id = state.value.activeId
        val session = sessions[id] ?: throw UserException("Your vault is locked.")
        return id to session
    }

    /** Send, the owner's side, on the active account (its keys looked up at each call: a lock frees them). */
    fun sends(): SendActions {
        val id = state.value.activeId
        return SendActions(securityTransport(id), sendV2 = { featuresOf(id)?.contains(Sends.FEATURE_V2) == true }) {
            CoreSendCrypto(sessions[id]?.account ?: throw UserException("Your vault is locked."))
        }
    }

    /** The link of a Send (made on this account's server). */
    fun sendLink(id: String, key: String): String = Sends.link(state.value.server, id, key)

    /** The unlocked account's key fingerprint (what an emergency contact or a sharer checks with this person). */
    fun ownFingerprint(): String? = sessions[state.value.activeId]?.account?.let { runCatching { it.fingerprint() }.getOrNull() }

    /** The account's own user id (as the server names it), while unlocked. */
    fun userId(): String? = sessions[state.value.activeId]?.accountId

    /** An item's attachment flows (`files`) need these: the account and its session's requests. */
    fun uploadSteps(): UploadSteps {
        val (id, _) = unlockedAccount()
        fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
        return object : UploadSteps {
            override fun newId(): String = io.passauth.core.newId()
            override fun newKey(): String = io.passauth.core.fileNewKey()
            override fun encryptedSize(plain: Long): Long = io.passauth.core.fileEncryptedSize(plain.toULong()).toLong()
            override fun encryptor(key: String, itemId: String, attachmentId: String): FileCipher = EncryptingCipher(key, itemId, attachmentId)
            override suspend fun register(itemId: String, id2: String, size: Long) {
                api.call(id, "/items/${enc(itemId)}/attachments", buildJsonObject { put("id", id2); put("size", size) })
            }
            override suspend fun put(id2: String, size: Long, write: (java.io.OutputStream) -> Unit) {
                api.upload(id, "/attachments/${enc(id2)}", size, write)
            }
            override suspend fun discard(id2: String) {
                api.call(id, "/attachments/${enc(id2)}", method = "DELETE")
            }
        }
    }

    /** `GET` an attachment's encrypted file ([path]: the item's own, or an emergency access's) on the active account's session. */
    suspend fun openDownload(path: String): okhttp3.Response = api.download(state.value.activeId, path)

    /** Throws the server's error for a failed download answer. */
    suspend fun downloadFailed(res: okhttp3.Response): Nothing = api.fail(res)

    /** The files the server keeps for an item (`GET /items/{id}/attachments`). */
    suspend fun storedAttachments(itemId: String): List<StoredAttachment> =
        Attachments.readStored(api.call(activeId(), "/items/${java.net.URLEncoder.encode(itemId, "UTF-8")}/attachments"))

    /** Delete a file on the server; already gone counts as done. */
    suspend fun deleteStoredAttachment(attachmentId: String) {
        try {
            api.call(activeId(), "/attachments/${java.net.URLEncoder.encode(attachmentId, "UTF-8")}", method = "DELETE")
        } catch (e: ApiException) {
            if (e.status != 404) throw e
        }
    }

    // ---------------------------------------------------------- emergency

    private val _emergencyNotice = MutableStateFlow<String?>(null)

    /** The vault notice about the emergency roster ([EmergencyClient.ROSTER_ROLLED_BACK] / [EmergencyClient.ROSTER_UNREADABLE]). */
    val emergencyNotice: StateFlow<String?> = _emergencyNotice.asStateFlow()

    /** The vaults and key epochs the last fill saw (a change runs the fill again). */
    private var keysSignature: String? = null

    /** Emergency access of the active account (the web vault's `emergency-client.ts`); each operation pins the account it started on. */
    val emergency: EmergencyClient = EmergencyClient(object : EmergencyEnv {
        override suspend fun pin(): EmergencyAccount? {
            val s = store.get()
            val id = s.activeId
            val a = s.accounts[id]?.takeIf { it.tokens != null && it.server.isNotEmpty() } ?: return null
            val user = sessions[id]?.accountId ?: Stored.bundleUserId(a.bundle) ?: return null
            return EmergencyAccount(id, a.server, user)
        }

        /** [a] is still the active account, unlocked as the same user (the vault, its keys and its notice are the active account's). */
        private fun current(a: EmergencyAccount) = state.value.activeId == a.record && sessions[a.record]?.accountId == a.userId

        override suspend fun call(a: EmergencyAccount, path: String, body: JsonElement?, method: String, headers: Map<String, String>): JsonElement =
            api.call(a.record, path, body, method, headers = headers)
        override suspend fun features(a: EmergencyAccount): List<String>? = featuresOf(a.record)
        override fun crypto(a: EmergencyAccount): EmergencyCrypto? {
            if (!current(a)) return null
            val s = sessions[a.record] ?: return null
            // Vault keys are looked up when used: none once the account is no longer the active one.
            return CoreEmergencyCrypto(s.account) { vid -> if (current(a)) vaultKeys[vid] else null }
        }
        override fun unlocked(a: EmergencyAccount): Boolean = current(a) && _vault.value != null
        override fun vaults(a: EmergencyAccount): List<VaultInfo> = if (current(a)) _vault.value?.vaults.orEmpty() else emptyList()
        override suspend fun reauth(a: EmergencyAccount, password: String): String = reauthToken(a.record, password, null)
        override suspend fun rotateVaultKeys(a: EmergencyAccount, ids: List<String>): RotationReport =
            this@VaultRepository.rotateVaultKeys(ids, a.record to a.userId, personalOnly = true)
        override suspend fun sharedBefore(a: EmergencyAccount, vaultId: String): Boolean {
            if (!current(a)) return true
            val sh = sessions[a.record]?.sharing ?: return false
            return sh.sharedBefore(vaultId)
        }
        override suspend fun sync(a: EmergencyAccount) {
            if (current(a)) this@VaultRepository.sync()
        }
        override fun setNotice(a: EmergencyAccount, text: String?) {
            if (current(a)) _emergencyNotice.value = text
        }
        override suspend fun seenVersion(a: EmergencyAccount): Long = store.get().roster(a.server, a.userId).seen
        override suspend fun trustedSealed(a: EmergencyAccount): String? = store.get().roster(a.server, a.userId).trusted
        override suspend fun remember(a: EmergencyAccount, version: Long, sealed: String?) {
            store.update { it.rememberingRoster(a.server, a.userId, version, sealed) }
        }
    })

    /**
     * After a sync: when the vault list or a key epoch changed (a new vault, one no longer shared,
     * a replaced key), the emergency fill adds the wraps the server asks for (servers with emergency
     * keys only; in the background, never holding the lock).
     */
    private fun vaultKeysMaybeChanged(id: String, vaults: List<VaultInfo>) {
        val sig = id + "|" + vaults.sortedBy { it.id }.joinToString(";") { "${it.id},${it.role},${it.keyKind},${it.keyEpoch}" }
        if (sig == keysSignature) return
        keysSignature = sig
        scope.launch {
            try {
                emergency.fillEmergencyKeys()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // Tried again after the next change; the server keeps asking for the wraps.
            }
        }
    }

    /**
     * Of [vaultIds], the vaults whose only member is this account ([own]: their keys can be replaced
     * here) and the ones shared with others ([shared]: replaced in the web vault or the desktop app).
     * A vault whose members can't be read now counts as own: replacing its key checks again.
     */
    suspend fun splitShared(vaultIds: List<String>): Pair<List<String>, List<String>> {
        val (id, session) = unlockedAccount()
        val own = mutableListOf<String>()
        val shared = mutableListOf<String>()
        for (vid in vaultIds) {
            val alone = try {
                onlyMember(id, vid, session.accountId)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                true
            }
            if (alone) own += vid else shared += vid
        }
        return own to shared
    }

    /** Whether account [userId] is the only member of vault [vaultId] (`GET /vaults/{id}/members`); throws when that can't be read. */
    private suspend fun onlyMember(id: String, vaultId: String, userId: String): Boolean {
        val enc = java.net.URLEncoder.encode(vaultId, "UTF-8")
        val members = (api.call(id, "/vaults/$enc/members") as? JsonObject)?.get("members") as? kotlinx.serialization.json.JsonArray
            ?: throw UserException(EmergencyClient.UNEXPECTED)
        val ids = members.map { ((it as? JsonObject)?.get("user_id") as? JsonPrimitive)?.contentOrNull ?: throw UserException(EmergencyClient.UNEXPECTED) }
        return ids == listOf(userId)
    }

    /** What one vault's key replacement did. */
    private sealed interface Rotation {
        data object Done : Rotation
        data object Skipped : Rotation
        data class Shared(val name: String) : Rotation
        data class Unreadable(val name: String) : Rotation
        data class Review(val review: MemberReview) : Rotation
    }

    /**
     * Replace the keys of these vaults, one after the other (after an emergency contact who may have
     * kept their keys was removed, or when the server asks for it). A vault shared with other people
     * gets its new key sealed and signed for every member with a signed member list (servers with
     * signed sharing, on an account that can sign; [Rotation.Shared] and the report's text otherwise).
     * A vault that needs the user to check its members first (its first signed member list, or people
     * the list names but the server no longer does) is replaced only with the user's confirmation of
     * exactly that review ([approvals], by vault id); else the report lists the review
     * ([RotationReport.reviews]). A vault whose name doesn't open is left as it is (its new key would
     * lose the name) and listed too. Any other failure stops it and is thrown; the server keeps asking
     * for the rest (`rotation_pending`). [pinned]: the record and user id the caller started on
     * (emergency access, [personalOnly]: only vaults whose members are this account alone); null for
     * the active account.
     */
    suspend fun rotateVaultKeys(
        vaultIds: List<String>,
        pinned: Pair<String, String>? = null,
        approvals: Map<String, ReviewApproval> = emptyMap(),
        personalOnly: Boolean = false,
    ): RotationReport {
        var rotated = 0
        val shared = mutableListOf<String>()
        val unreadable = mutableListOf<String>()
        val reviews = mutableListOf<MemberReview>()
        try {
            for (vid in vaultIds) {
                when (val r = mutex.withLock { rotateLocked(vid, pinned, approvals[vid], personalOnly) }) {
                    Rotation.Done -> rotated++
                    Rotation.Skipped -> {}
                    is Rotation.Shared -> shared += r.name
                    is Rotation.Unreadable -> unreadable += r.name
                    is Rotation.Review -> reviews += r.review
                }
            }
        } finally {
            try {
                sync()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
            }
        }
        return RotationReport(rotated, shared, unreadable, reviews)
    }

    /**
     * A new key for vault [vaultId]: every item (trash included, each with its revision when signed)
     * and the vault's name re-encrypted with it, in one request. Everything is re-encrypted only from
     * the state verified by a sync in this same call, under the lock (the vault's key, name and epoch;
     * items are read from a fresh `/sync` but must open with that key, under the same key header).
     * With other members (or a signed member list, here or remembered) the key is sealed and signed
     * for each and the next roster signed after the user's review ([SharingSession.planRotation]). An
     * item changed meanwhile (409 `revision_conflict`) starts it again, a few times at most.
     */
    private suspend fun rotateLocked(vaultId: String, pinned: Pair<String, String>?, approval: ReviewApproval?, personalOnly: Boolean): Rotation {
        val id = activeId()
        val session = sessions[id] ?: throw UserException("Your vault is locked.")
        if (pinned != null && (pinned.first != id || pinned.second != session.accountId)) {
            throw UserException("You switched to another account meanwhile. Switch back and try again.")
        }
        val enc = java.net.URLEncoder.encode(vaultId, "UTF-8")
        repeat(ROTATE_ATTEMPTS) { attempt ->
            // The state this rotation re-encrypts: verified by this sync, under this lock.
            syncLocked()
            if (sessions[id] !== session || activeId() != id) throw UserException("Your vault is locked.")
            val own = _vault.value?.vaults?.firstOrNull { it.id == vaultId } ?: return Rotation.Skipped
            if (own.role != Role.Owner && own.role != Role.Admin) return Rotation.Skipped
            // A vault whose manifest warning isn't resolved gets no new key (its items aren't what its record says).
            if (own.manifest == ManifestState.Unresolved || own.manifest == ManifestState.Unchecked) throw UserException(Manifests.HELD)
            val header = vaultHeaders[vaultId] ?: return Rotation.Skipped
            val oldKey = vaultKeys[vaultId] ?: return Rotation.Skipped
            val oldEpoch = header.keyEpoch
            val sh = session.sharing?.takeIf { signedSharingOn(id, session, online = true) }
            // Round 5 Info: no key replacement (own vaults included) without loaded, readable key pins.
            sh?.requireReadyToReplace()
            val me = sh?.me ?: session.accountId
            val members = api.call(id, "/vaults/$enc/members") as? JsonObject ?: throw UserException(EmergencyClient.UNEXPECTED)
            val rows = (members["members"] as? kotlinx.serialization.json.JsonArray)?.map { it as? JsonObject ?: throw UserException(EmergencyClient.UNEXPECTED) }
                ?: throw UserException(EmergencyClient.UNEXPECTED)
            val ids = rows.map { SignedSharing.text(it, "user_id") ?: throw UserException(EmergencyClient.UNEXPECTED) }
            val alone = ids == listOf(me)
            // The member set that decides (emergency access: personal) is the one the new key goes to.
            if (personalOnly && !alone) return Rotation.Shared(own.name)
            val rosterSeq = SignedSharing.number(members, "member_roster_seq") ?: 0
            val latestRoster = SignedSharing.text(members, "member_roster")
            val trusted = sh?.rememberedRoster(vaultId)
            // A vault with a signed member list (listed or remembered) or other members is replaced
            // only signed; without signing, only a vault this account alone holds.
            val signed = RotationRules.mustSign(trusted, rosterSeq, latestRoster, alone)
            if (signed && (sh == null || !sh.canSign)) return Rotation.Shared(own.name)
            // Every item, trash included, as the server has it now (a trash summary has no data to
            // re-encrypt): only under the key header this sync verified, and each must open with its key.
            val text = api.callText(id, "/sync")
            val full = core { AppJson.decodeFromString(SyncResponse.serializer(), text) }
                // A server answer never says which hash a row's data has ([SyncItem.servedSha256] is this phone's own).
                .let { r -> r.copy(items = r.items?.map { it.copy(servedSha256 = null) }) }
            val fresh = full.vaults?.firstOrNull { it.id == vaultId }
            val wrapsV2 = SignedSharing.accountWrapsV2(full.user)
            // The members answer, the roster and the items must all belong to the state this sync verified.
            val membersEpoch = if (sh != null) SignedSharing.number(members, "key_epoch") else oldEpoch
            if (RotationRules.checkBase(header, membersEpoch, fresh, signed, trusted, rosterSeq, latestRoster) == RotationRules.Base.Retry) {
                if (attempt < ROTATE_ATTEMPTS - 1) return@repeat
                throw UserException(SignedSharing.CHANGED_JUST_NOW)
            }
            // The items re-encrypted must be, row by row, the copy this sync checked (against the vault's
            // manifest and the item edit counters), under the same manifest; the answer only adds the data
            // of trashed items, which the copy keeps by its hash. A newer copy this phone kept in place of
            // an older version served is what gets re-encrypted. Anything else changed meanwhile: again.
            val checked = copy?.takeIf { it.first == id }?.second?.items.orEmpty().filter { it.vaultId == vaultId }
            val items = fresh?.takeIf { it.manifestSeq == header.manifestSeq && it.manifest == header.manifest && it.manifestPrev == header.manifestPrev }
                ?.let { core { Manifests.rotationRows(checked, full.items.orEmpty().filter { it.vaultId == vaultId }) } }
            if (items == null) {
                if (attempt < ROTATE_ATTEMPTS - 1) return@repeat
                throw UserException(SignedSharing.CHANGED_JUST_NOW)
            }
            var plan: RotationPlan.Ready? = null
            if (signed) {
                sh!!
                if (trusted != null && !core { oldKey.matchesRoster(vaultId, trusted) }) throw UserException(SignedSharing.REFUSED)
                when (val p = core { sh.planRotation(vaultId, own.name, trusted, rows, approval) }) {
                    is RotationPlan.NeedsReview -> return Rotation.Review(p.review)
                    is RotationPlan.Ready -> plan = p
                }
            }
            val newEpoch = (oldEpoch ?: 0) + 1
            if (signed && items.any { it.revision == null }) throw UserException(SignedSharing.NEEDS_REVISIONS)
            var roster: String? = null
            var epochPin: String? = null
            val body = core {
                // The vault's name must survive the new key: one that doesn't open now stops this vault.
                val metaPlain = if (header.meta.isEmpty()) null else runCatching { oldKey.decryptMeta(vaultId, header.meta) }.getOrNull() ?: return@core null
                val made = session.account.newVaultKey(vaultId)
                try {
                    val newRows = mutableListOf<SyncItem>()
                    val reencrypted = kotlinx.serialization.json.buildJsonArray {
                        for (r in items) {
                            val json = try {
                                oldKey.decryptItem(EncryptedItem(r.id, vaultId, r.itemKey ?: throw UserException(CANT_REKEY), r.data ?: throw UserException(CANT_REKEY)))
                            } catch (_: CoreException) {
                                throw UserException(CANT_REKEY)
                            }
                            val e = made.key.encryptItem(json, r.id, vaultId)
                            newRows += SyncItem(e.id, vaultId, e.key, e.data, deletedAt = r.deletedAt)
                            add(buildJsonObject {
                                put("id", e.id)
                                put("vault_id", e.vaultId)
                                put("key", e.key)
                                put("data", e.data)
                                r.revision?.let { put("revision", it) }
                            })
                        }
                    }
                    val meta = metaPlain?.let { made.key.encryptMeta(vaultId, it) }
                    val keys = kotlinx.serialization.json.buildJsonArray {
                        // v2 (bound to the epoch the vault has after this write) once every app of the account reads it.
                        val ownWrap = if (wrapsV2 && oldEpoch != null) {
                            made.key.wrapForBound(session.account, vaultId, newEpoch.toULong())
                        } else {
                            made.key.wrapFor(session.account, vaultId)
                        }
                        add(buildJsonObject { put("user_id", me); put("wrapped_key", ownWrap); put("key_kind", VaultInfo.KEY_KIND_ACCOUNT) })
                        if (plan != null) {
                            for ((n, row) in rows.withIndex()) {
                                if (ids[n] == me) continue
                                val share = sh!!.sealAndSign(made.key, vaultId, row, newEpoch)
                                add(buildJsonObject {
                                    put("user_id", ids[n])
                                    put("wrapped_key", share.sealedKey)
                                    put("key_kind", "sealed")
                                    put("signature", share.signature)
                                })
                            }
                        }
                    }
                    if (plan != null) roster = sh!!.signRoster(made.key, vaultId, plan!!, newEpoch, rows)
                    epochPin = made.key.epochPinJson(vaultId, newEpoch.toULong())
                    // The manifest's keys change with the vault key: a whole new one, by the new key, for the new epoch, over the new data.
                    val manifest = fresh?.let { Manifests.rotationEntry(made.key, it, newRows) }
                    buildJsonObject {
                        put("keys", keys)
                        put("items", reencrypted)
                        manifest?.let { put("manifests", kotlinx.serialization.json.JsonArray(listOf(it.json()))) }
                        meta?.let { put("meta", it) }
                        oldEpoch?.let { put("key_epoch", it) }
                        roster?.let { put("roster", it) }
                    }
                } finally {
                    made.destroy()
                }
            } ?: return Rotation.Unreadable(own.name)
            try {
                api.call(id, "/vaults/$enc/rotate", body)
            } catch (e: ApiException) {
                when {
                    ItemWrites.vaultKeyChanged(e) -> {
                        syncAfterWrite()
                        throw UserException("Someone else replaced this vault's key just now. If the vault still asks for a new key, replace it again.")
                    }
                    e.status == 409 && e.hasCode("members_changed") -> {
                        syncAfterWrite()
                        throw UserException(membersChangedText(e, rows))
                    }
                    // An item edited, the member list signed, or anything else written into the vault meanwhile
                    // (its manifest moved on): start again with what the server has now.
                    ((e.status == 409 && (e.hasCode("revision_conflict") || e.hasCode("member_roster_changed"))) || Manifests.isConflict(e)) && attempt < ROTATE_ATTEMPTS - 1 -> return@repeat
                    (e.status == 409 && (e.hasCode("revision_conflict") || e.hasCode("member_roster_changed"))) || Manifests.isConflict(e) -> {
                        syncAfterWrite()
                        throw UserException(SignedSharing.CHANGED_JUST_NOW)
                    }
                    // 30 key replacements per vault and hour (round 4): said plainly, tried again later.
                    e.isRateLimited -> throw UserException(SignedSharing.keyReplacementLimited(e)!!)
                    else -> throw e
                }
            }
            val pin = epochPin
            if (sh != null && pin != null) {
                sh.rememberRotation(vaultId, roster, pin, plan?.newPins.orEmpty())
                savePinsQuietly(sh)
            }
            syncAfterWrite()
            return Rotation.Done
        }
        throw UserException(SignedSharing.CHANGED_JUST_NOW)
    }

    /** Who differs, from a 409 `members_changed` answer ([rows]: the member rows sent), named by (cleaned) email where known. */
    private fun membersChangedText(e: ApiException, rows: List<JsonObject>): String {
        val known = SignedSharing.people(sessions[state.value.activeId]?.sharing?.pins).associate { it.userId to it.email }
        val emails = rows.associate { SignedSharing.text(it, "user_id").orEmpty() to SignedSharing.clean(SignedSharing.text(it, "email")) }
        val ids = listOf("unknown", "identity_changed", "role_changed", "missing")
            .flatMap { k -> (e.body?.get(k) as? kotlinx.serialization.json.JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
            .distinct()
        if (ids.isEmpty()) return SignedSharing.CHANGED_JUST_NOW
        return SignedSharing.membersDiffer(ids.map { known[it]?.ifEmpty { null } ?: emails[it]?.ifEmpty { null } ?: SignedSharing.someone(it) })
    }

    // ---------------------------------------------- queries (autofill, phase 2)

    /**
     * Logins of the unlocked active account that match a web page (default match from settings;
     * regular expressions only from the account's own vaults).
     */
    fun loginsFor(pageUrl: String): List<Entry> {
        val fallback = state.value.settings.defaultMatch
        val v = _vault.value ?: return emptyList()
        return v.entries.filter { e -> e.item.login?.let { UrlMatcher.matchesAny(pageUrl, it, fallback, allowRegex = v.isPersonal(e)) } == true }
    }

    /** Passkeys saved for a relying party. */
    fun passkeysFor(rpId: String): List<Pair<Entry, Passkey>> =
        _vault.value?.entries.orEmpty().flatMap { e ->
            e.item.login?.passkeys.orEmpty().filter { it.rpId.equals(rpId, ignoreCase = true) }.map { e to it }
        }

    companion object {
        const val SECRET_KEY_REQUIRED = "secret_key_required"

        /** The app never shows the trash: `/sync` sends trashed items without key and data. */
        private const val TRASH_SUMMARY = true

        /** How long the server's `/api/config` features are trusted before asking again. */
        private const val FEATURES_MAX_AGE_MS = 6 * 60 * 60 * 1000L

        private const val CANT_REKEY = "Some items in this vault can't be decrypted, so its key can't be replaced yet."

        /** A key replacement starts again this often when an item or the member list changed meanwhile. */
        private const val ROTATE_ATTEMPTS = 3

        /** The server address as an origin (plus path), https only except local development hosts. */
        fun normalizeServer(url: String): String {
            val clean = url.trim().trimEnd('/')
            if (clean.isEmpty()) throw UserException("Enter your server address.")
            val p = UrlMatcher.parse(clean) ?: throw UserException("That isn't a valid server address.")
            val local = p.hostname == "localhost" || p.hostname == "127.0.0.1" || p.hostname == "10.0.2.2"
            if (p.scheme != "https" && !(p.scheme == "http" && local)) {
                throw UserException("Use an https:// address. Plain http is only allowed for localhost.")
            }
            val path = java.net.URI(p.href).rawPath.orEmpty().trimEnd('/')
            return p.origin + path
        }

        private fun bundleAccountId(bundle: String) = AppJson.parseToJsonElement(bundle).jsonObject.str("account_id")

        /** Rust core calls are CPU-bound (Argon2id, decryption): keep them off the main thread. */
        private suspend fun <T> core(block: () -> T): T = withContext(Dispatchers.Default) { block() }
    }
}
