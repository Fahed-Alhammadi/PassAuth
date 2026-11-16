package io.passauth.app.data

import android.os.Build
import io.passauth.core.Account
import io.passauth.core.ApprovedLogin
import io.passauth.core.CoreException
import io.passauth.core.EncryptedItem
import io.passauth.core.LoginRequestKey
import io.passauth.core.MasterKeys
import io.passauth.core.VaultKey
import io.passauth.core.accountFromSessionBytes
import io.passauth.core.createAccountWithKdf
import io.passauth.core.deriveMasterKeys
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

/** The unlocked vault of the active account. */
data class VaultData(
    val entries: List<Entry> = emptyList(),
    val vaults: List<VaultInfo> = emptyList(),
    val revision: Long = 0,
    /** Shown from the on-device copy because the server couldn't be reached. */
    val offline: Boolean = false,
    /** Vaults shared with the account and waiting for it to accept or decline (servers with `vault_invitations`). */
    val invitations: List<Invitation> = emptyList(),
) {
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

/** Unlocked keys of one account, in memory only (Rust handles). */
private class Session(val accountId: String, val account: Account) {
    fun close() = account.destroy()
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

    val state: StateFlow<AppState> = combine(store.data, sessionIds, gated) { s, open, g -> toState(s, open, g) }
        .stateIn(scope, SharingStarted.Eagerly, AppState())

    init {
        // Runs later: the request that noticed it may hold the lock.
        api.onSessionLost = { id -> scope.launch { mutex.withLock { closeSession(id) } } }
        // The server requires two-step login first: the app shows only the setup screen for that account.
        api.onTwoStepRequired = { id -> gated.update { it + id } }
    }

    private fun statusOf(id: String, a: AccountData?, open: Set<String>) = when {
        a == null || a.server.isEmpty() -> Status.Setup
        a.tokens == null -> Status.LoggedOut
        id in open -> Status.Unlocked
        else -> Status.Locked
    }

    private fun toState(s: Stored, open: Set<String>, gate: Set<String>): AppState {
        val a = s.active
        return AppState(
            loaded = true,
            status = statusOf(s.activeId, a, open),
            activeId = s.activeId,
            accounts = s.accounts.filter { (_, v) -> v.server.isNotEmpty() && v.email.isNotEmpty() }
                .map { (id, v) -> AccountSummary(id, v.email, v.name, v.server, statusOf(id, v, open)) },
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
        val ok = res.use { r ->
            r.isSuccessful && runCatching { AppJson.parseToJsonElement(r.body.string()).jsonObject.str("name") == "PassAuth" }.getOrDefault(false)
        }
        if (!ok) throw UserException("No PassAuth server answered at that address.")
        mutex.withLock {
            val s = store.get()
            closeSession(s.activeId)
            // A device sign-in in progress was for the old server.
            cancelDeviceLogin()
            dropPendingDeviceLogin()
            store.update { st ->
                val id = st.activeId.takeIf { st.accounts.containsKey(it) } ?: UUID.randomUUID().toString()
                val a = st.accounts[id] ?: AccountData()
                st.copy(activeId = id, accounts = st.accounts + (id to a.copy(server = origin, tokens = null, bundle = null, features = null, featuresAt = 0, api = null, policies = null)))
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
        dupes.forEach { closeSession(it); store.deleteCache(it); Keystore.deleteBiometricKey(it) }
        store.update { s ->
            val a = (s.accounts[id] ?: AccountData()).copy(
                email = email,
                tokens = Tokens(result.str("access_token"), result.str("refresh_token")),
                bundle = bundle,
                biometric = null,
                persistedKeys = null,
            )
            s.copy(activeId = id, accounts = s.accounts - dupes + (id to a))
        }
        Keystore.deleteBiometricKey(id)
        openSession(id, Session(bundleAccountId(bundle), account))
    }

    /** Create an account on the active record's server (the web vault's Register). */
    suspend fun register(email: String, name: String, password: String, withSecretKey: Boolean): Registered = mutex.withLock {
        val id = activeId()
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
            val bundle = a.bundle ?: api.call(id, "/sync").jsonObject["bundle"].toString().also { b ->
                store.updateAccount(id) { it.copy(bundle = b) }
            }
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
                core { accountFromSessionBytes(bundleAccountId(bundle), bytes) }
            } finally {
                bytes.fill(0)
            }
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
                val account = core { accountFromSessionBytes(bundleAccountId(bundle), bytes) }
                bytes.fill(0)
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
        copy = null
        _vault.value = null
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
            store.deleteCache(id)
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
        store.deleteCache(id)
        forgetSessionState(id)
        val listed = s.accounts.filterValues { it.server.isNotEmpty() && it.email.isNotEmpty() }
        if (listed.size > 1 || !listed.containsKey(id)) {
            removeAccount(id)
        } else {
            store.updateAccount(id) { it.copy(tokens = null, biometric = null, bundle = null, lastSync = 0) }
        }
    }

    /** What this app knew about account [id]'s session in memory: the two-step gate and its policy violations. */
    private fun forgetSessionState(id: String) {
        gated.update { it - id }
        _violations.update { it - id }
    }

    private suspend fun removeAccount(id: String) {
        store.update { s ->
            val rest = s.accounts - id
            val next = if (s.activeId == id) rest.entries.firstOrNull { it.value.tokens != null }?.key ?: rest.keys.firstOrNull() ?: "" else s.activeId
            s.copy(accounts = rest, activeId = next)
        }
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
    suspend fun sync() = syncQueue.run { mutex.withLock { syncLocked() } }

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
                if (id == s.activeId && sessions.containsKey(id)) sync() else refreshCacheLocked(id)
                outcome = outcome.copy(refreshed = outcome.refreshed + 1)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
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
        val cached = readSnapshot(id)
        val delta = deltaSyncEnabled(id)
        val result = DeltaSync.refresh(cached, delta, TRASH_SUMMARY) { path -> api.callText(id, path) }
        if (store.get().accounts[id]?.tokens == null) return // signed out meanwhile
        gated.update { it - id }
        when (result) {
            DeltaSync.CacheRefresh.Keep -> return
            DeltaSync.CacheRefresh.Current -> store.updateAccount(id) { it.copy(lastSync = System.currentTimeMillis()) }
            is DeltaSync.CacheRefresh.Write -> {
                val next = result.snapshot
                val text = core { next.encode() }
                mutex.withLock {
                    // Unlocked and shown meanwhile: its own sync writes the copy.
                    if (sessions.containsKey(id) && activeId() == id) return@withLock
                    withContext(Dispatchers.IO) { store.writeCache(id, text) }
                    store.updateAccount(id) {
                        it.copy(
                            lastSync = System.currentTimeMillis(),
                            name = (next.user as? JsonObject)?.strOrNull("name") ?: it.name,
                            bundle = next.bundle?.toString() ?: it.bundle,
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
    private suspend fun syncLocked(fallbackToCache: Boolean = false, cacheFirst: Boolean = false) {
        val id = activeId()
        val session = sessions[id] ?: return
        if (cacheFirst) {
            val cached = readSnapshot(id)
            if (cached != null && runCatching { show(id, session, cached, offline = false, mode = CopyStore.None) }.isSuccess) {
                scope.launch { backgroundSync(id, session) }
                return
            }
        }
        val (next, offline) = try {
            fetchSnapshot(id).also { gated.update { g -> g - id } } to false
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // An answer that isn't a vault is an error, not "offline".
            if (e is UserException && e.message == DeltaSync.unreadable().message) throw e
            val cached = if (fallbackToCache) readSnapshot(id) else null
            if (cached == null) {
                if (fallbackToCache && e !is ApiException) {
                    copy = null
                    _vault.value = VaultData(offline = true)
                    return
                }
                throw e
            }
            cached to true
        }
        show(id, session, next, offline, if (offline) CopyStore.None else CopyStore.Synced)
    }

    /** The server sync after a cache-first unlock; an unreachable server leaves the copy marked offline. */
    private suspend fun backgroundSync(id: String, session: Session) = mutex.withLock {
        if (sessions[id] !== session || activeId() != id) return@withLock
        try {
            syncLocked()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            if (sessions[id] === session && activeId() == id) _vault.value = _vault.value?.copy(offline = true)
        }
    }

    /** The account's copy after asking the server: since the copy's cursor when the server does delta sync, else everything. */
    private suspend fun fetchSnapshot(id: String): SyncSnapshot {
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
     */
    private suspend fun show(id: String, session: Session, snap: SyncSnapshot, offline: Boolean, mode: CopyStore) {
        if (sessions[id] !== session) return
        val previous = if (copy?.first == id) _vault.value?.let { Opened(it, vaultKeys, vaultHeaders, emptyList()) } else null
        val names = if (copy?.first == id) invitationNames else emptyMap()
        val opened = core { decryptVault(session.account, snap, previous, names) }
        if (sessions[id] !== session) {
            opened.fresh.forEach { it.destroy() }
            return
        }
        if (mode != CopyStore.None) {
            val text = core { snap.encode() }
            withContext(Dispatchers.IO) { store.writeCache(id, text) }
            if (mode == CopyStore.Synced) {
                store.updateAccount(id) {
                    it.copy(
                        lastSync = System.currentTimeMillis(),
                        name = (snap.user as? JsonObject)?.strOrNull("name") ?: it.name,
                        bundle = snap.bundle?.toString() ?: it.bundle,
                    )
                }
            }
        }
        // Keys of vaults gone or opened again are freed; kept ones live on in the new map.
        val kept = opened.keys.values
        vaultKeys.values.filter { old -> kept.none { it === old } }.forEach { it.destroy() }
        vaultKeys = opened.keys
        vaultHeaders = opened.headers
        invitationNames = opened.invitationNames
        copy = id to snap
        _vault.value = opened.data.copy(offline = offline)
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
        } catch (_: Exception) {
            _vault.value = _vault.value?.copy(offline = true)
        }
    }

    /**
     * After this device's write into [vaultId] ([answer]: the server's reply, with `vault_seq` on
     * servers with delta sync): when it is the vault's next number nothing else changed there, so
     * [change] is applied to the copy without asking the server; when the copy already has it
     * nothing is done; otherwise (other writes too, a move, an older server) the copy is synced,
     * as before every write.
     */
    private suspend fun afterWrite(vaultId: String, answer: JsonElement?, change: LocalChange?) {
        val id = activeId()
        val c = copy?.takeIf { it.first == id }
        val session = sessions[id]
        if (change == null || c == null || session == null) return syncAfterWrite()
        val known = c.second.vaults.firstOrNull { it.id == vaultId }?.seq
        val seq = ((answer as? JsonObject)?.get("vault_seq") as? JsonPrimitive)?.longOrNull
        when (SyncDecision.afterWrite(known, seq)) {
            SyncDecision.AfterWrite.Nothing -> return
            SyncDecision.AfterWrite.Sync -> return syncAfterWrite()
            SyncDecision.AfterWrite.ApplyLocally -> {
                val next = seq?.let { SyncMerge.applyLocal(change, vaultId, it, c.second) } ?: return syncAfterWrite()
                try {
                    show(id, session, next, offline = false, mode = CopyStore.LocalChange)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (_: Exception) {
                    syncAfterWrite()
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
    )

    /**
     * Decrypt a copy, reusing what [previous] already opened: a vault key whose header (wrapping,
     * kind, epoch) is unchanged, the vault's name while its `meta` is too, and items whose
     * ciphertext is the same in a vault whose key was kept. A vault key that can't be opened
     * (rotated) is skipped with its items, and so is an undecryptable item; trashed items aren't
     * shown (the app has no trash view; with `trash=summary` they have no data anyway).
     */
    private fun decryptVault(account: Account, snap: SyncSnapshot, previous: Opened?, previousNames: Map<String, String?>): Opened {
        val keys = mutableMapOf<String, VaultKey>()
        val headers = mutableMapOf<String, SyncVault>()
        val kept = mutableSetOf<String>()
        val fresh = mutableListOf<VaultKey>()
        val vaults = mutableListOf<VaultInfo>()
        val oldNames = previous?.data?.vaults.orEmpty().associate { it.id to it.name }
        for (v in snap.vaults) {
            val old = previous?.headers?.get(v.id)
            val oldKey = previous?.keys?.get(v.id)
            var name: String? = null
            val key = if (old != null && oldKey != null && old.sameKey(v)) {
                kept += v.id
                if (old.meta == v.meta) name = oldNames[v.id]
                oldKey
            } else {
                try {
                    account.openVaultKey(v.id, v.wrappedKey, v.keyKind).also { fresh += it }
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
            vaults += VaultInfo(v.id, shown, role, v.keyKind.ifEmpty { VaultInfo.KEY_KIND_ACCOUNT }, v.keyEpoch)
        }
        val before = previous?.data?.entries.orEmpty().associateBy { it.id }
        val entries = mutableListOf<Entry>()
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
                    continue // undecryptable item; skip
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
        }
        return Opened(VaultData(entries, vaults, snap.revision, invitations = invitations), keys, headers, fresh, names)
    }

    /** The vault name of an invitation, read with its sealed key (never kept); null when the account can't open it. */
    private fun invitationName(account: Account, inv: SyncInvitation): String? {
        val key = try {
            account.openVaultKey(inv.vaultId, inv.wrappedKey, "sealed")
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
        var answer: JsonElement? = null
        val created = ItemWrites.create(
            send = {
                val v = requireVault()
                val target = vaultId?.let { want -> v.vaults.firstOrNull { it.id == want } } ?: writableVault(v)
                val key = vaultKeys[target.id] ?: throw UserException("Vault not found.")
                targetId = target.id
                val enc = core { key.encryptItem(json, id, target.id) }
                answer = api.call(activeId(), "/items", body = ItemWrites.body(enc, target.keyEpoch))
                sent = enc
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
            afterWrite(targetId, answer, change)
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
                answer = api.call(activeId(), "/items/${entry.id}", body = ItemWrites.body(enc, target.keyEpoch, entry.revision), method = "PUT")
                sent = enc
                moved = target.id != entry.vaultId
            },
            resync = {
                syncLocked()
                _vault.value?.get(base.id)
            },
        )
        // A move also changed the vault it left (its number isn't in the answer): sync.
        val enc = sent
        val change = if (moved || enc == null) null else ItemWrites.revision(answer)?.let { rev -> LocalChange.Put(SyncItem(base.id, targetVaultId, enc.key, enc.data, rev, updatedAt = t)) }
        afterWrite(targetVaultId, answer, change)
    }

    /** Move an item to another vault the user can write to. */
    suspend fun moveItem(entry: Entry, vaultId: String) {
        if (vaultId == entry.vaultId) return
        updateItem(entry, entry.item, vaultId)
    }

    suspend fun setFavorite(entry: Entry, favorite: Boolean) = updateItem(entry, entry.item.copy(favorite = favorite))

    suspend fun trashItem(entry: Entry) {
        mutex.withLock {
            val v = requireVault()
            requireOnline(v)
            if (!v.canWrite(entry)) throw UserException("You can only view items in this vault.")
            val answer = api.call(activeId(), "/items/${entry.id}", method = "DELETE")
            val change = ItemWrites.revision(answer)?.let { LocalChange.Trash(entry.id, now(), it, TRASH_SUMMARY) }
            afterWrite(entry.vaultId, answer, change)
        }
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

    /** Accept an invitation (the vault arrives with the sync that follows). */
    suspend fun acceptInvitation(vaultId: String) = InvitationActions(securityTransport(activeId())) { syncAfterAnswer() }.accept(vaultId)

    /** Decline an invitation; its vault's managers are asked to replace the key. */
    suspend fun declineInvitation(vaultId: String) = InvitationActions(securityTransport(activeId())) { syncAfterAnswer() }.decline(vaultId)

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
            syncLocked(fallbackToCache, cacheFirst)
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
            store.deleteCache(id)
            val email = a.email.lowercase()
            val sameEmailElsewhere = s.accounts.any { (k, v) -> k != id && v.email.equals(email, ignoreCase = true) }
            store.update { st ->
                st.copy(
                    secretKeys = if (sameEmailElsewhere) st.secretKeys else st.secretKeys - email,
                    rememberTokens = st.rememberTokens - "${a.server}|$email",
                )
            }
            val listed = s.accounts.filterValues(::isListed)
            if (listed.size > 1 || !listed.containsKey(id)) {
                removeAccount(id)
            } else {
                // Keep only the server address, so the sign-in screen still knows where to go.
                store.updateAccount(id) { AccountData(server = it.server) }
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
        return v.entries.joinToString(",", "[", "]") { ItemCodec.encode(it.item) }
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
