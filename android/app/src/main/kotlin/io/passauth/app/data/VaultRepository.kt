package io.passauth.app.data

import android.os.Build
import io.passauth.core.Account
import io.passauth.core.CoreException
import io.passauth.core.EncryptedItem
import io.passauth.core.MasterKeys
import io.passauth.core.VaultKey
import io.passauth.core.accountFromSessionBytes
import io.passauth.core.createAccount
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
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
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

data class VaultInfo(val id: String, val name: String, val role: Role)

/** The unlocked vault of the active account. */
data class VaultData(
    val entries: List<Entry> = emptyList(),
    val vaults: List<VaultInfo> = emptyList(),
    val revision: Long = 0,
    /** Shown from the on-device copy because the server couldn't be reached. */
    val offline: Boolean = false,
) {
    val folders: List<String> get() = entries.mapNotNull { it.item.folder?.takeIf(String::isNotEmpty) }.distinct().sorted()
    fun get(id: String) = entries.firstOrNull { it.id == id }
    fun vaultName(id: String) = vaults.firstOrNull { it.id == id }?.name ?: "Vault"
    fun canWrite(e: Entry) = vaults.firstOrNull { it.id == e.vaultId }?.role != Role.Read
    val writable: List<VaultInfo> get() = vaults.filter { it.role != Role.Read }
}

sealed interface LoginResult {
    data object Done : LoginResult
    data class TwoFactor(val token: String, val providers: List<String>) : LoginResult
}

data class Registered(val secretKey: String?, val emailVerificationRequired: Boolean)

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
) {
    private val mutex = Mutex()
    private val sessions = mutableMapOf<String, Session>()
    private val sessionIds = MutableStateFlow<Set<String>>(emptySet())
    private var vaultKeys = mapOf<String, VaultKey>()
    private val _vault = MutableStateFlow<VaultData?>(null)
    private var pendingMaster: MasterKeys? = null
    private var pendingRemember = ""

    /** The active account's decrypted vault; null while locked. */
    val vault: StateFlow<VaultData?> = _vault.asStateFlow()

    val state: StateFlow<AppState> = combine(store.data, sessionIds) { s, open -> toState(s, open) }
        .stateIn(scope, SharingStarted.Eagerly, AppState())

    init {
        // Runs later: the request that noticed it may hold the lock.
        api.onSessionLost = { id -> scope.launch { mutex.withLock { closeSession(id) } } }
    }

    private fun statusOf(id: String, a: AccountData?, open: Set<String>) = when {
        a == null || a.server.isEmpty() -> Status.Setup
        a.tokens == null -> Status.LoggedOut
        id in open -> Status.Unlocked
        else -> Status.Locked
    }

    private fun toState(s: Stored, open: Set<String>): AppState {
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
            store.update { st ->
                val id = st.activeId.takeIf { st.accounts.containsKey(it) } ?: UUID.randomUUID().toString()
                val a = st.accounts[id] ?: AccountData()
                st.copy(activeId = id, accounts = st.accounts + (id to a.copy(server = origin, tokens = null, bundle = null)))
            }
        }
    }

    /** Whether the server allows sign-ups (from `/api/config`); null if unknown. */
    suspend fun signupsAllowed(): Boolean? = runCatching {
        val server = store.get().active?.server ?: return null
        api.get("$server/api/config").use { r -> AppJson.parseToJsonElement(r.body.string()).jsonObject.bool("signups_allowed") }
    }.getOrNull()

    // -------------------------------------------------------------- login

    private suspend fun deviceInfo() = buildJsonObject {
        put("id", store.get().deviceId)
        put("name", "PassAuth for Android (${Build.MODEL})")
        put("kind", "mobile")
    }

    suspend fun login(email: String, password: String, secretKey: String?): LoginResult = mutex.withLock {
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
        syncLocked()
        LoginResult.Done
    }

    suspend fun verifyTwoFactor(token: String, provider: String, code: String, remember: Boolean) {
        mutex.withLock {
            val id = activeId()
            val result = api.call(
                id, "/auth/2fa/verify", auth = false,
                body = buildJsonObject {
                    put("two_factor_token", token)
                    put("provider", provider)
                    put("code", code.trim().replace(" ", ""))
                    put("remember", remember)
                },
            ).jsonObject
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
            syncLocked()
        }
    }

    suspend fun sendTwoFactorEmail(token: String) {
        api.call(activeId(), "/auth/2fa/email", body = buildJsonObject { put("two_factor_token", token) }, auth = false)
    }

    private suspend fun finishLogin(id: String, master: MasterKeys, result: JsonObject) {
        val bundle = result["bundle"].toString()
        val email = result.str("email")
        val account = core { master.unlock(bundle) }
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
        val init = api.call(id, "/auth/register/init", body = buildJsonObject { put("email", email.trim()) }, auth = false).jsonObject
        val created = core { createAccount(init.str("account_id"), password, withSecretKey) }
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
            syncLocked(fallbackToCache = true)
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
            syncLocked(fallbackToCache = true)
        }
    }

    /** Vault timeout "never": restore keys kept on disk after the app restarts. */
    suspend fun restorePersisted(): Boolean = mutex.withLock {
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
        if (restored && sessions.containsKey(s.activeId)) syncLocked(fallbackToCache = true)
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
        _vault.value = null
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
        }
    }

    /** Log out of the active account and remove it from this device; the next one becomes active. */
    suspend fun logout() = mutex.withLock {
        val s = store.get()
        val id = s.activeId
        s.active?.let { api.logoutRemote(it.server, it.tokens) }
        closeSession(id)
        pendingMaster?.destroy()
        pendingMaster = null
        Keystore.deleteBiometricKey(id)
        store.deleteCache(id)
        val listed = s.accounts.filterValues { it.server.isNotEmpty() && it.email.isNotEmpty() }
        if (listed.size > 1 || !listed.containsKey(id)) {
            removeAccount(id)
        } else {
            // The last account stays as a signed-out record, so the sign-in screen remembers the server and email.
            store.updateAccount(id) { it.copy(tokens = null, biometric = null, bundle = null, lastSync = 0) }
        }
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
        if (sessions.containsKey(id)) syncLocked(fallbackToCache = true)
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

    suspend fun sync() = mutex.withLock { syncLocked() }

    /** Re-sync if the server has newer data (cheap revision check). */
    suspend fun refreshIfStale() {
        val current = _vault.value ?: return
        val id = activeId()
        val r = runCatching { api.call(id, "/sync/revision").jsonObject.long("revision") }.getOrNull() ?: return
        if (r > current.revision || current.offline) mutex.withLock { syncLocked() }
    }

    private suspend fun syncLocked(fallbackToCache: Boolean = false) {
        val id = activeId()
        val session = sessions[id] ?: return
        val (json, offline) = try {
            api.call(id, "/sync").toString() to false
        } catch (e: Exception) {
            val cached = if (fallbackToCache) store.readCache(id) else null
            if (cached == null) {
                if (fallbackToCache && e !is ApiException) {
                    _vault.value = VaultData(offline = true)
                    return
                }
                throw e
            }
            cached to true
        }
        if (sessions[id] !== session) return
        val data = AppJson.parseToJsonElement(json).jsonObject
        val (next, keys) = core { decryptVault(session.account, data) }
        if (!offline) {
            store.writeCache(id, json)
            store.updateAccount(id) {
                it.copy(
                    lastSync = System.currentTimeMillis(),
                    name = (data["user"] as? JsonObject)?.str("name") ?: it.name,
                    bundle = data["bundle"]?.toString() ?: it.bundle,
                )
            }
        }
        vaultKeys.values.forEach { it.destroy() }
        vaultKeys = keys
        _vault.value = next.copy(offline = offline)
    }

    private fun decryptVault(account: Account, data: JsonObject): Pair<VaultData, Map<String, VaultKey>> {
        val keys = mutableMapOf<String, VaultKey>()
        val vaults = mutableListOf<VaultInfo>()
        for (v in (data["vaults"] as? JsonArray).orEmpty()) {
            val o = v.jsonObject
            val vid = o.str("id")
            val key = try {
                account.openVaultKey(vid, o.str("wrapped_key"), o.str("key_kind"))
            } catch (_: CoreException) {
                continue // vault key unavailable (rotated); skip
            }
            val name = runCatching { AppJson.parseToJsonElement(key.decryptMeta(vid, o.str("meta"))).jsonObject.str("name") }
                .getOrNull()?.takeIf { it.isNotEmpty() } ?: "Vault"
            val role = when (o.str("role")) {
                "owner" -> Role.Owner
                "admin" -> Role.Admin
                "write" -> Role.Write
                else -> Role.Read
            }
            keys[vid] = key
            vaults += VaultInfo(vid, name, role)
        }
        val entries = mutableListOf<Entry>()
        for (row in (data["items"] as? JsonArray).orEmpty()) {
            val o = row.jsonObject
            val key = keys[o.str("vault_id")] ?: continue
            if (o.strOrNull("deleted_at") != null) continue
            val enc = EncryptedItem(o.str("id"), o.str("vault_id"), o.str("item_key"), o.str("data"))
            val item = try {
                ItemCodec.decode(key.decryptItem(enc))
            } catch (_: Exception) {
                continue // undecryptable item; skip
            }
            entries += Entry(enc.id, item, enc.vaultId, o.long("revision"), enc)
        }
        entries.sortWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.item.name })
        return VaultData(entries, vaults, data.long("revision")) to keys
    }

    // -------------------------------------------------------------- items

    private fun now() = System.currentTimeMillis() / 1000

    private fun writableVault(v: VaultData): VaultInfo =
        v.vaults.firstOrNull { it.role == Role.Owner } ?: v.vaults.firstOrNull { it.role != Role.Read }
            ?: throw UserException("You don't have a vault you can save to.")

    private fun requireVault() = _vault.value ?: throw UserException("Your vault is locked.")

    private suspend fun requireOnline(v: VaultData) {
        if (v.offline) throw UserException("You're offline. Changes can be saved once PassAuth reaches your server.")
    }

    suspend fun createItem(item: Item, vaultId: String?): String = mutex.withLock {
        val v = requireVault()
        requireOnline(v)
        val target = vaultId?.let { id -> v.vaults.firstOrNull { it.id == id } } ?: writableVault(v)
        val key = vaultKeys[target.id] ?: throw UserException("Vault not found.")
        val t = now()
        val id = core { newId() }
        val enc = core { key.encryptItem(ItemCodec.encode(item.copy(createdAt = t, updatedAt = t)), id, target.id) }
        api.call(activeId(), "/items", body = enc.toJson())
        syncLocked()
        id
    }

    suspend fun updateItem(entry: Entry, item: Item) {
        mutex.withLock {
            val v = requireVault()
            requireOnline(v)
            val vault = v.vaults.firstOrNull { it.id == entry.vaultId } ?: throw UserException("Vault not found.")
            if (vault.role == Role.Read) throw UserException("You can only view items in this vault.")
            val key = vaultKeys[vault.id] ?: throw UserException("Vault not found.")
            val t = now()
            var next = item.copy(updatedAt = t)
            val old = entry.item.login?.password
            val newPassword = next.login?.password
            if (next.login != null && !old.isNullOrEmpty() && old != newPassword && next.passwordHistory == entry.item.passwordHistory) {
                next = next.copy(passwordHistory = (listOf(PasswordChange(old, t)) + next.passwordHistory).take(20))
            }
            val enc = core { key.updateItem(entry.enc, ItemCodec.encode(next)) }
            val body = enc.toJson().let { JsonObject(it + ("revision" to kotlinx.serialization.json.JsonPrimitive(entry.revision))) }
            try {
                api.call(activeId(), "/items/${entry.id}", body = body, method = "PUT")
            } catch (e: ApiException) {
                if (e.status == 409) throw UserException("This item was changed on another device. Sync and try again.")
                throw e
            }
            syncLocked()
        }
    }

    suspend fun setFavorite(entry: Entry, favorite: Boolean) = updateItem(entry, entry.item.copy(favorite = favorite))

    suspend fun trashItem(entry: Entry) {
        mutex.withLock {
            val v = requireVault()
            requireOnline(v)
            if (!v.canWrite(entry)) throw UserException("You can only view items in this vault.")
            api.call(activeId(), "/items/${entry.id}", method = "DELETE")
            syncLocked()
        }
    }

    // ---------------------------------------------- queries (autofill, phase 2)

    /** Logins of the unlocked active account that match a web page (default match from settings). */
    fun loginsFor(pageUrl: String): List<Entry> {
        val fallback = state.value.settings.defaultMatch
        return _vault.value?.entries.orEmpty().filter { e -> e.item.login?.let { UrlMatcher.matchesAny(pageUrl, it, fallback) } == true }
    }

    /** Passkeys saved for a relying party. */
    fun passkeysFor(rpId: String): List<Pair<Entry, Passkey>> =
        _vault.value?.entries.orEmpty().flatMap { e ->
            e.item.login?.passkeys.orEmpty().filter { it.rpId.equals(rpId, ignoreCase = true) }.map { e to it }
        }

    companion object {
        const val SECRET_KEY_REQUIRED = "secret_key_required"

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

        private fun EncryptedItem.toJson() = buildJsonObject {
            put("id", id)
            put("vault_id", vaultId)
            put("key", key)
            put("data", data)
        }

        /** Rust core calls are CPU-bound (Argon2id, decryption): keep them off the main thread. */
        private suspend fun <T> core(block: () -> T): T = withContext(Dispatchers.Default) { block() }
    }
}

private fun JsonArray?.orEmpty(): List<JsonElement> = this ?: emptyList()
