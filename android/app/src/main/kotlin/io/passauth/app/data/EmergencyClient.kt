package io.passauth.app.data

import java.net.URLEncoder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** An emergency key in the core (its key never leaves Rust). */
interface EmergencyKeyHandle : AutoCloseable {
    fun sealFor(contactKey: String, grantorId: String, grantId: String): String

    /** The key of vault [vaultId] as this app holds it now, wrapped for this key's access. */
    fun wrapVaultKey(vaultId: String): String

    /** Open the vault key wrapped for [vaultId] and this key's access. */
    fun openVaultKey(vaultId: String, wrapped: String): OpenedVaultKey
}

/** A grantor's vault key, opened from its wrap: only for reading (closed at once after use). */
interface OpenedVaultKey : AutoCloseable {
    fun decryptMeta(vaultId: String, meta: String): String
    fun decryptItem(id: String, vaultId: String, key: String, data: String): String

    /**
     * Are [itemsJson] (every item row of the vault, as sent) exactly what the vault's manifest
     * records ([Manifests]; the core's `manifestVerify` without device memory)? Only asked for a
     * vault that has one.
     */
    fun manifestMatches(vaultId: String, keyEpoch: Long, manifestSeq: Long, sealed: String?, itemsJson: String): Boolean
}

class NewEmergencyKeyHandle(val wrapped: String, val key: EmergencyKeyHandle) : AutoCloseable {
    override fun close() = key.close()
}

/** The unlocked account's emergency functions (the core's `Account`; fakes in tests). */
interface EmergencyCrypto {
    fun newEmergencyKey(grantId: String): NewEmergencyKeyHandle
    fun openEmergencyKey(grantId: String, wrapped: String): EmergencyKeyHandle
    fun sealRoster(json: String): String
    fun openRoster(sealed: String): String
    fun openSealedEmergencyKey(grantorId: String, grantId: String, sealed: String): EmergencyKeyHandle
}

/** The account one emergency operation works on, pinned at its start: record [record] on [server], its user [userId]. */
data class EmergencyAccount(val record: String, val server: String, val userId: String)

/**
 * What the emergency client needs from the app (the repository; fakes in tests): requests on an
 * account's session, its keys while unlocked, its own sync, and this device's memory of the
 * roster (per account: the highest version opened and the last trusted roster, sealed). Every
 * operation pins the account once ([pin]) and passes it to each call, so switching account midway
 * never mixes two accounts' requests, keys or roster memory.
 */
interface EmergencyEnv {
    /** The active account, pinned for one operation; null without a signed-in account. */
    suspend fun pin(): EmergencyAccount?
    suspend fun call(a: EmergencyAccount, path: String, body: JsonElement? = null, method: String = if (body == null) "GET" else "POST", headers: Map<String, String> = emptyMap()): JsonElement
    suspend fun features(a: EmergencyAccount): List<String>?

    /** [a]'s unlocked keys; null when it is locked or no longer the active account. */
    fun crypto(a: EmergencyAccount): EmergencyCrypto?
    fun unlocked(a: EmergencyAccount): Boolean

    /** [a]'s vaults as last synced; empty when it is locked or no longer the active account. */
    fun vaults(a: EmergencyAccount): List<VaultInfo>
    suspend fun reauth(a: EmergencyAccount, password: String): String
    /** Replace the keys of these personal vaults (only while their members are this account alone). */
    suspend fun rotateVaultKeys(a: EmergencyAccount, ids: List<String>): RotationReport

    /** Signed sharing: the vault was shared under a signed member list (a trusted roster lists someone else, or it was seen signed). */
    suspend fun sharedBefore(a: EmergencyAccount, vaultId: String): Boolean
    suspend fun sync(a: EmergencyAccount)
    fun setNotice(a: EmergencyAccount, text: String?)
    suspend fun seenVersion(a: EmergencyAccount): Long
    suspend fun trustedSealed(a: EmergencyAccount): String?
    suspend fun remember(a: EmergencyAccount, version: Long, sealed: String?)
}

/**
 * What removing a contact did about vault keys: how many were replaced, why the rest wasn't (null:
 * all done), and what's left for the user ([RotationReport.leftover]; null: nothing).
 */
data class Removal(val rotated: Int, val failed: String?, val leftover: String? = null)

/** The roster as the Emergency page needs it. */
data class RosterState(
    /** null, "older" or "unreadable". */
    val problem: String?,
    val roster: Roster?,
    val confirmAgain: Set<String>,
    val removed: Set<String>,
)

/** The server's roster for review before "Use the server's list". */
data class ServerRoster(val roster: Roster?, val entries: List<ReviewedEntry>)

/** The server's roster changed between the review and "Use the server's list": read it again and show it again. */
class RosterChangedError : UserException("Your server's list of emergency contacts changed meanwhile. Check it again before you continue.")

/** An item of a grantor's vault, decrypted for viewing (memory only). */
data class GrantorEntry(val id: String, val vaultId: String, val item: Item, val deletedAt: Long?)

/** A grantor's vaults, decrypted for viewing: memory only. */
data class GrantorVault(
    val grant: Grant,
    val vaults: List<Pair<String, String>>,
    val items: List<GrantorEntry>,
    val failed: Int,
    /** Vaults (names) whose items aren't what their manifest records ([Manifests.WARNING]). */
    val mismatched: List<String> = emptyList(),
)

/**
 * Emergency access requests and keys (the web vault's `emergency-client.ts`, same flows and words;
 * the rules are in [Emergency]). Confirming a contact makes an emergency key for the access, after
 * the user compared the contact's fingerprint with them. Only vaults this app's own data says are
 * personal are ever wrapped, whatever the server lists. The roster lists the accesses this
 * account's apps may add wraps for; every write (and every fill) drops accesses the server no
 * longer lists, so one that ended can't be brought back. Unit-tested in EmergencyClientTest.
 */
class EmergencyClient(private val env: EmergencyEnv) {
    companion object {
        const val LOCKED = "The vault is locked. Unlock it and try again."
        const val UNEXPECTED = "The server sent an unexpected response. Try again."
        const val SERVER_TOO_OLD = "Your PassAuth server needs an update before emergency contacts can be confirmed or their vaults viewed. Ask the server's admin."
        const val APP_TOO_OLD = "This emergency access uses keys this version of PassAuth can't open. Update PassAuth, then try again."
        const val VAULTS_CHANGED = "Your vaults changed while this was being saved. Try again."
        const val NOT_OURS = "This access's key wasn't made by your account. Remove the contact, then name them again."
        const val ROSTER_ROLLED_BACK = "Your server sent an older list of emergency contacts, so PassAuth didn't change their access. Ask your server's admin."
        const val ROSTER_UNREADABLE = "Your server sent a list of emergency contacts that PassAuth can't open, so PassAuth didn't change their access. Ask your server's admin."
        const val SIGNED_OUT = "Sign in first."
        const val GONE = "This emergency contact is no longer on your server's list. Reload the page."

        fun path(id: String, rest: String = "") = "/emergency-access/${URLEncoder.encode(id, "UTF-8").replace("+", "%20")}$rest"

        fun hasCode(e: Throwable, code: String) = e is ApiException && e.hasCode(code)
    }

    private fun grantOf(value: JsonElement): Grant = Emergency.readGrant(value) ?: throw UserException(UNEXPECTED)

    private fun crypto(a: EmergencyAccount): EmergencyCrypto = env.crypto(a) ?: throw UserException(LOCKED)

    /** The active account, pinned for one operation (every request, key and roster memory of it is that account's). */
    private suspend fun pinned(): EmergencyAccount = env.pin() ?: throw UserException(SIGNED_OUT)

    suspend fun listGrants(): GrantLists = grants(pinned())

    private suspend fun grants(a: EmergencyAccount): GrantLists = Emergency.readGrants(env.call(a, "/emergency-access"))

    /** Throws unless the server gives contacts emergency keys (v2). */
    private suspend fun requireEmergencyKeys(a: EmergencyAccount) {
        val features = env.features(a) ?: throw UserException(UNREACHABLE)
        if (Emergency.KEYS_FEATURE !in features) throw UserException(SERVER_TOO_OLD)
    }

    /** Name a trusted contact (an account on this server with a verified email address). */
    suspend fun inviteContact(email: String, waitDays: Long): Grant = try {
        grantOf(env.call(pinned(), "/emergency-access", buildJsonObject { put("grantee_email", email.trim()); put("wait_days", waitDays) }))
    } catch (e: ApiException) {
        if (e.status == 404) throw UserException("There's no account with that email address on this server, or it isn't verified yet. Your contact needs an account here first.")
        if (e.status == 409) throw UserException("This person is your emergency contact already.")
        throw e
    }

    // ------------------------------------------------------------ the roster

    /** Remember a roster this device trusts: its version (never goes down) and the sealed roster itself (null: none). */
    private suspend fun rememberRoster(a: EmergencyAccount, version: Long, sealed: String?) {
        if (version < env.seenVersion(a)) return
        env.remember(a, version, sealed)
    }

    /** This device's last trusted roster, opened with the account's key; null when it keeps none (or it doesn't open). */
    private suspend fun trustedRoster(a: EmergencyAccount): Roster? {
        val sealed = env.trustedSealed(a) ?: return null
        val c = env.crypto(a) ?: return null
        return try {
            Emergency.readRoster(c.openRoster(sealed))
        } catch (_: Exception) {
            null
        }
    }

    private data class Opened(val roster: Roster, val seq: Long, val problem: String?)

    /** The account's roster from a listing, opened with its key: empty before any is stored. */
    private suspend fun openRoster(a: EmergencyAccount, lists: GrantLists): Opened {
        val c = crypto(a)
        val seq = lists.rosterSeq ?: 0
        var roster: Roster? = Emergency.EMPTY_ROSTER
        if (lists.roster != null) {
            roster = try {
                Emergency.readRoster(c.openRoster(lists.roster))
            } catch (_: Exception) {
                null
            }
        }
        if (roster == null) return Opened(Emergency.EMPTY_ROSTER, seq, "unreadable")
        if (Emergency.rosterIsOlder(roster, env.seenVersion(a))) return Opened(roster, seq, "older")
        rememberRoster(a, roster.version, lists.roster)
        return Opened(roster, seq, null)
    }

    /** Seal [next] and store it with the compare-and-swap number [seq], then remember it. */
    private suspend fun writeRoster(a: EmergencyAccount, next: Roster, seq: Long) {
        val sealed = crypto(a).sealRoster(Emergency.rosterJson(next))
        env.call(a, "/emergency-access/roster", buildJsonObject { put("roster", sealed); put("seq", seq) }, "PUT")
        rememberRoster(a, next.version, sealed)
    }

    private fun listedIds(lists: GrantLists) = lists.asGrantor.map { it.id }.toSet()

    private fun notice(problem: String) = if (problem == "older") ROSTER_ROLLED_BACK else ROSTER_UNREADABLE

    /**
     * Store the roster with one access added or taken out (null: only the cleanup), and without the
     * accesses the server no longer lists: once more when another device changed it meanwhile (409
     * `roster_changed`). A roster this device can't trust is never the base of a new one.
     */
    private suspend fun changeRoster(a: EmergencyAccount, change: Emergency.RosterChange?) {
        var attempt = 0
        while (true) {
            val lists = grants(a)
            val opened = openRoster(a, lists)
            if (opened.problem != null) {
                env.setNotice(a, notice(opened.problem))
                if (change is Emergency.RosterChange.Add) throw UserException(notice(opened.problem))
                return
            }
            if (change is Emergency.RosterChange.Add && Emergency.isRemoved(opened.roster, change.entry.id, change.entry.grantorKeyHash)) {
                throw UserException(Emergency.removedText("This contact"))
            }
            val next = Emergency.nextRoster(opened.roster, env.seenVersion(a), change, listedIds(lists)) ?: return
            try {
                writeRoster(a, next, opened.seq + 1)
                return
            } catch (e: Exception) {
                if (attempt > 0 || !hasCode(e, "roster_changed")) throw e
            }
            attempt++
        }
    }

    suspend fun rosterState(): RosterState {
        val a = pinned()
        if (env.crypto(a) == null) return RosterState(null, null, emptySet(), emptySet())
        val lists = grants(a)
        val opened = openRoster(a, lists)
        if (opened.problem != null) return RosterState(opened.problem, null, emptySet(), emptySet())
        val confirmAgain = mutableSetOf<String>()
        val removed = mutableSetOf<String>()
        for (g in lists.asGrantor) {
            val hash = g.grantorKey?.let(Emergency::sha256b64)
            if (Emergency.isRemoved(opened.roster, g.id, hash)) removed += g.id
            else if (Emergency.needsConfirmAgain(g, opened.roster, hash)) confirmAgain += g.id
        }
        return RosterState(null, opened.roster, confirmAgain, removed)
    }

    /** The server's roster, opened with the account's key, for review. Throws when it doesn't open. */
    suspend fun loadServerRoster(): ServerRoster {
        val a = pinned()
        val lists = grants(a)
        val c = crypto(a)
        val sealed = lists.roster ?: return ServerRoster(null, emptyList())
        val roster = try {
            Emergency.readRoster(c.openRoster(sealed))
        } catch (_: Exception) {
            null
        } ?: throw UserException(ROSTER_UNREADABLE)
        return ServerRoster(roster, Emergency.reviewRoster(roster, trustedRoster(a), listedIds(lists)))
    }

    /** "Use the server's list" with the master password: exactly what was reviewed is written forward. */
    suspend fun useServerRoster(reviewed: ServerRoster, password: String) {
        val a = pinned()
        env.reauth(a, password)
        val lists = grants(a)
        val c = crypto(a)
        var current: Roster? = Emergency.EMPTY_ROSTER
        if (lists.roster != null) {
            current = try {
                Emergency.readRoster(c.openRoster(lists.roster))
            } catch (_: Exception) {
                null
            }
            if (current == null) throw UserException(ROSTER_UNREADABLE)
        }
        val same = if (reviewed.roster == null) lists.roster == null else lists.roster != null && Emergency.rosterJson(reviewed.roster) == Emergency.rosterJson(current!!)
        if (!same) throw RosterChangedError()
        val next = Emergency.restoredRosterForward(reviewed.entries, current!!, trustedRoster(a), env.seenVersion(a), listedIds(lists))
        try {
            writeRoster(a, next, (lists.rosterSeq ?: 0) + 1)
        } catch (e: Exception) {
            throw if (hasCode(e, "roster_changed")) RosterChangedError() else e
        }
        env.setNotice(a, null)
        runCatching { fillEmergencyKeys() }
    }

    /** "Start a new list" with the master password, when the server's roster doesn't open with the account's key. */
    suspend fun startNewRoster(password: String) {
        val a = pinned()
        env.reauth(a, password)
        val lists = grants(a)
        if (openRoster(a, lists).problem != "unreadable") throw UserException("Your server's list of emergency contacts opens again. Reload the page.")
        try {
            writeRoster(a, Emergency.freshRoster(env.seenVersion(a), trustedRoster(a)), (lists.rosterSeq ?: 0) + 1)
        } catch (e: Exception) {
            throw if (hasCode(e, "roster_changed")) UserException("Your list of emergency contacts changed on another device just now. Try again.") else e
        }
        env.setNotice(a, null)
    }

    // --------------------------------------------------------------- the keys

    /** Of the vaults the server names, the ones this app's own data says are personal (one members request per vault). */
    private suspend fun personalOf(a: EmergencyAccount, wanted: List<String>): Pair<List<String>, List<String>> {
        val me = a.userId
        val vaults = env.vaults(a)
        fun own(id: String) = vaults.firstOrNull { it.id == id }?.let { OwnVault(it.id, it.role, it.keyKind) }
        val members = mutableMapOf<String, List<String>?>()
        for (id in LinkedHashSet(wanted)) {
            val v = own(id) ?: continue
            if (v.role != Role.Owner || v.kind != VaultInfo.KEY_KIND_ACCOUNT) continue
            try {
                members[id] = readMemberIds(env.call(a, "/vaults/${URLEncoder.encode(id, "UTF-8").replace("+", "%20")}/members"))
            } catch (e: ApiException) {
                if (e.status != 404) throw e
            }
        }
        val signed = members.keys.associateWith { env.sharedBefore(a, it) }
        return Emergency.vaultsToWrap(wanted) { id -> Emergency.isPersonal(own(id), members[id], me, signed[id] ?: true) }
    }

    /** The members' user ids of `GET /vaults/{id}/members`; null when malformed (a row that can't be read). */
    private fun readMemberIds(value: JsonElement): List<String>? {
        val list = (value as? JsonObject)?.get("members") as? JsonArray ?: return null
        return list.map { m ->
            ((m as? JsonObject)?.get("user_id") as? JsonPrimitive)?.takeIf { it.isString && it.content.isNotEmpty() }?.content ?: return null
        }
    }

    /** Each vault's key wrapped with [key], with the epoch of the key wrapped. */
    private fun wrapVaults(a: EmergencyAccount, key: EmergencyKeyHandle, vaultIds: List<String>): JsonArray {
        val vaults = env.vaults(a)
        return buildJsonArray {
            for (id in vaultIds) {
                val v = vaults.firstOrNull { it.id == id }
                val epoch = v?.keyEpoch ?: throw UserException(VAULTS_CHANGED)
                add(buildJsonObject { put("vault_id", id); put("wrapped_key", key.wrapVaultKey(id)); put("key_epoch", epoch) })
            }
        }
    }

    private fun vaultsMoved(e: Throwable) = hasCode(e, "emergency_vaults_changed") || hasCode(e, "vault_key_changed")

    private suspend fun currentAccess(a: EmergencyAccount, id: String): Grant = grants(a).asGrantor.firstOrNull { it.id == id } ?: throw UserException(GONE)

    /**
     * The grantor's step after the contact accepted ([g] as the user checked it, fingerprint
     * included): a new emergency key, put into the roster before the server gets anything of it,
     * then sealed to the contact's key, wrapped by this account's key and wrapping every personal
     * vault's key. When the access already holds a key, the roster points at that one.
     */
    suspend fun confirmContact(g: Grant): Grant {
        val a = pinned()
        requireEmergencyKeys(a)
        val who = Emergency.personName(g.grantee)
        if (g.grantee.publicKey.isEmpty()) throw UserException("$who's account has no key to confirm. Ask them to sign in once, then try again.")
        val keyChanged = { UserException("$who's key changed. Check their fingerprint again before you confirm them.") }
        val lists = grants(a)
        val fresh = lists.asGrantor.firstOrNull { it.id == g.id } ?: throw UserException(GONE)
        if (fresh.grantee.publicKey != g.grantee.publicKey) throw keyChanged()
        val opened = openRoster(a, lists)
        if (opened.problem == null && Emergency.isRemoved(opened.roster, g.id, fresh.grantorKey?.let(Emergency::sha256b64))) {
            throw UserException(Emergency.removedText(who))
        }
        if (Emergency.hasKeys(fresh)) {
            confirmAgainAs(a, g)
            return currentAccess(a, g.id)
        }
        if (fresh.status != GrantStatus.Accepted) throw UserException(VAULTS_CHANGED)
        val made = crypto(a).newEmergencyKey(g.id)
        try {
            val key = made.key
            // This account's id as the server names it, and the contact's key the user checked (the core refuses others).
            val sealed = key.sealFor(g.grantee.publicKey, g.grantor.id, g.id)
            changeRoster(a, Emergency.RosterChange.Add(Emergency.rosterEntry(g, g.grantee.publicKey, Emergency.sha256b64(made.wrapped))))
            var current = fresh
            var attempt = 0
            while (true) {
                val (wrap, refused) = personalOf(a, current.missingVaults)
                if (refused.isNotEmpty()) {
                    throw UserException(
                        "PassAuth couldn't check that every vault your server lists as personal is yours alone (one may be shared, or couldn't be opened here), so nothing was confirmed. Reload the page and try again.",
                    )
                }
                val body = buildJsonObject {
                    put("sealed_key", sealed)
                    put("grantor_key", made.wrapped)
                    put("vault_keys", wrapVaults(a, key, wrap))
                }
                try {
                    return grantOf(env.call(a, path(g.id, "/confirm"), body))
                } catch (e: Exception) {
                    if (attempt == 0 && vaultsMoved(e)) {
                        env.sync(a)
                        val again = currentAccess(a, g.id)
                        if (again.grantee.publicKey != g.grantee.publicKey) throw keyChanged()
                        if (again.status == GrantStatus.Accepted) {
                            current = again
                            attempt++
                            continue
                        }
                    }
                    // The access holds a key now (this try's answer was lost, or another app confirmed first): use that one.
                    val now = try {
                        currentAccess(a, g.id)
                    } catch (_: Exception) {
                        null
                    }
                    if (now != null && Emergency.hasKeys(now) && now.grantee.publicKey == g.grantee.publicKey) {
                        confirmAgainAs(a, g)
                        return now
                    }
                    throw e
                }
            }
        } finally {
            made.close()
        }
    }

    /**
     * "Confirm again": put an access that holds keys back into the roster, once the user checked the
     * contact's fingerprint ([checked]). No new key: the access's own `grantor_key` must open under
     * this account's key for this access.
     */
    suspend fun confirmAgain(checked: Grant) = confirmAgainAs(pinned(), checked)

    private suspend fun confirmAgainAs(a: EmergencyAccount, checked: Grant) {
        requireEmergencyKeys(a)
        val who = Emergency.personName(checked.grantee)
        val now = currentAccess(a, checked.id)
        if (checked.grantee.publicKey.isEmpty() || now.grantee.publicKey != checked.grantee.publicKey) {
            throw UserException("$who's key changed. Check their fingerprint again before you confirm them.")
        }
        val grantorKey = now.grantorKey
        if (!Emergency.hasKeys(now) || grantorKey == null) throw UserException(VAULTS_CHANGED)
        val hash = Emergency.sha256b64(grantorKey)
        val opened = openRoster(a, grants(a))
        if (opened.problem == null && Emergency.isRemoved(opened.roster, now.id, hash)) throw UserException(Emergency.removedText(who))
        try {
            crypto(a).openEmergencyKey(now.id, grantorKey).close()
        } catch (e: UserException) {
            throw e
        } catch (_: Exception) {
            throw UserException(NOT_OURS)
        }
        changeRoster(a, Emergency.RosterChange.Add(Emergency.rosterEntry(checked, checked.grantee.publicKey, hash)))
        runCatching { fillEmergencyKeys() }
    }

    private val fillLock = Mutex()
    private var filling: CompletableDeferred<Unit>? = null
    private var fillAgain = false

    /**
     * Add the wraps the server says are missing for the accesses the roster lists. One run at a
     * time, and one more when asked again meanwhile. A roster this device can't trust stops it,
     * with a vault notice; a trusted one first loses the accesses the server no longer lists.
     */
    suspend fun fillEmergencyKeys() {
        val (run, mine) = fillLock.withLock {
            filling?.let {
                fillAgain = true
                return@withLock it to false
            }
            CompletableDeferred<Unit>().also { filling = it } to true
        }
        if (!mine) return run.await()
        try {
            while (true) {
                fillLock.withLock { fillAgain = false }
                fillOnce()
                // Ending the run and checking for a request made meanwhile in one step: a caller that
                // joined this run has its fill run again, one that comes later starts its own.
                val done = fillLock.withLock {
                    if (fillAgain) return@withLock false
                    filling = null
                    true
                }
                if (done) break
            }
            run.complete(Unit)
        } catch (e: Throwable) {
            withContext(NonCancellable) { fillLock.withLock { if (filling === run) filling = null } }
            run.completeExceptionally(e)
            throw e
        }
    }

    /** One fill, on the account active when it starts (pinned for the whole run). */
    private suspend fun fillOnce() {
        val a = env.pin() ?: return
        val features = env.features(a) ?: return
        if (Emergency.FEATURE !in features || Emergency.KEYS_FEATURE !in features) return
        if (!env.unlocked(a)) return
        val lists = grants(a)
        val opened = openRoster(a, lists)
        if (opened.problem != null) {
            env.setNotice(a, notice(opened.problem))
            return
        }
        env.setNotice(a, null)
        var roster = opened.roster
        val listed = listedIds(lists)
        if (Emergency.pruneRoster(roster, listed).size < roster.accesses.size) {
            roster = roster.copy(accesses = Emergency.pruneRoster(roster, listed))
            try {
                changeRoster(a, null)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
            }
        }
        val hashes = lists.asGrantor.mapNotNull { g -> g.grantorKey?.let { it to Emergency.sha256b64(it) } }.toMap()
        val todo = Emergency.fillableAccesses(lists.asGrantor, roster, hashes)
        if (todo.isEmpty()) return
        val personal = personalOf(a, todo.flatMap { it.missingVaults }).first.toSet()
        for (g in todo) {
            val vaults = g.missingVaults.filter { it in personal }
            val c = env.crypto(a)
            val grantorKey = g.grantorKey
            if (vaults.isEmpty() || grantorKey == null || c == null) continue
            val key = try {
                c.openEmergencyKey(g.id, grantorKey)
            } catch (_: Exception) {
                continue // Not this account's key for this access: nothing this app can add.
            }
            val vaultKeys = key.use { wrapVaults(a, it, vaults) }
            try {
                env.call(a, path(g.id, "/vault-keys"), buildJsonObject { put("vault_keys", vaultKeys) }, "PUT")
            } catch (e: Exception) {
                if (!vaultsMoved(e)) throw e
            }
        }
    }

    /** A reauth token for [password], as the server wants for approving and shortening the wait. */
    private suspend fun reauthHeader(a: EmergencyAccount, password: String) = mapOf("x-reauth-token" to env.reauth(a, password))

    /** Change the waiting period; a shorter one needs the master password. */
    suspend fun changeWait(id: String, waitDays: Long, password: String? = null): Grant {
        val a = pinned()
        return grantOf(env.call(a, path(id), buildJsonObject { put("wait_days", waitDays) }, "PUT", if (password != null) reauthHeader(a, password) else emptyMap()))
    }

    suspend fun acceptGrant(id: String): Grant = grantOf(env.call(pinned(), path(id, "/accept"), null, "POST"))
    suspend fun requestAccess(id: String): Grant = grantOf(env.call(pinned(), path(id, "/request"), null, "POST"))

    /** Approve a request now; needs the master password. */
    suspend fun approveGrant(id: String, password: String): Grant {
        val a = pinned()
        return grantOf(env.call(a, path(id, "/approve"), null, "POST", reauthHeader(a, password)))
    }
    suspend fun rejectGrant(id: String): Grant = grantOf(env.call(pinned(), path(id, "/reject"), null, "POST"))

    /**
     * The grantor removes contact [g]: out of the roster first, then the access. When the contact
     * held the key, the vaults the server names that this app sees as personal get new keys now.
     * Already gone counts as done.
     */
    suspend fun removeContact(g: Grant): Removal {
        val a = pinned()
        changeRoster(a, Emergency.RosterChange.Remove(g.id, g.grantorKey?.let(Emergency::sha256b64)))
        val answer = try {
            env.call(a, path(g.id), null, "DELETE")
        } catch (e: ApiException) {
            if (e.status != 404) throw e
            return Removal(0, null)
        }
        val named = Emergency.vaultsToReKey(answer) { true }
        if (named.isEmpty()) return Removal(0, null)
        return try {
            val wrap = personalOf(a, named).first
            val vaults = Emergency.vaultsToReKey(answer) { it in wrap }
            val report = if (vaults.isNotEmpty()) env.rotateVaultKeys(a, vaults) else RotationReport.NONE
            Removal(report.rotated, null, report.leftover)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Removal(0, e.message ?: "Something went wrong.")
        }
    }

    /** The contact steps down or declines (never replaces anyone's keys). Already gone counts as done. */
    suspend fun leaveGrant(id: String) {
        val a = pinned()
        try {
            env.call(a, path(id), null, "DELETE")
        } catch (e: ApiException) {
            if (e.status != 404) throw e
        }
    }

    // -------------------------------------------------------------- the vault

    /**
     * Fetch and decrypt the personal vaults a grantor shared through emergency access (approved
     * accesses only). Every key handle is closed as soon as it has been used.
     */
    suspend fun openGrantorVault(id: String): GrantorVault {
        val a = pinned()
        requireEmergencyKeys(a)
        val answer = env.call(a, path(id, "/vault"))
        val data = Emergency.readGrantorVault(answer)
        val grant = Emergency.readGrant((answer as? JsonObject)?.get("grant"))
        if (data == null || grant == null || grant.id != id) throw UserException(UNEXPECTED)
        if (data.keyVersion != Emergency.KEY_VERSION) throw UserException(if (data.keyVersion == null) SERVER_TOO_OLD else APP_TOO_OLD)
        val key = try {
            crypto(a).openSealedEmergencyKey(grant.grantor.id, id, data.sealedKey)
        } catch (e: UserException) {
            throw e
        } catch (_: Exception) {
            throw UserException(
                "Your account's keys can't open the access ${Emergency.personName(grant.grantor)} gave you. Ask them to remove you as their emergency contact and name you again.",
            )
        }
        val vaults = mutableListOf<Pair<String, String>>()
        val items = mutableListOf<GrantorEntry>()
        val mismatched = mutableListOf<String>()
        var failed = 0
        key.use { k ->
            for (v in data.vaults) {
                val rows = data.items.filter { it.vaultId == v.id }
                val vaultKey = try {
                    k.openVaultKey(v.id, v.wrappedKey)
                } catch (_: Exception) {
                    failed += rows.size
                    continue
                }
                vaultKey.use { vk ->
                    val name = try {
                        (AppJson.parseToJsonElement(vk.decryptMeta(v.id, v.meta)) as? JsonObject)?.str("name")?.takeIf { CleanText.trim(it).isNotEmpty() }
                    } catch (_: Exception) {
                        null
                    } ?: "Vault"
                    vaults += v.id to name
                    // A vault with a manifest: the rows sent must be exactly what it records (read-only check, nothing remembered).
                    if (v.manifestSeq > 0) {
                        val sent = kotlinx.serialization.json.JsonArray(data.rawItems.filter { (it["vault_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content == v.id })
                        val ok = try {
                            vk.manifestMatches(v.id, v.keyEpoch, v.manifestSeq, v.manifest, sent.toString())
                        } catch (_: Exception) {
                            false
                        }
                        if (!ok) mismatched += name
                    }
                    for (r in rows) {
                        try {
                            items += GrantorEntry(r.id, v.id, ItemCodec.decode(vk.decryptItem(r.id, v.id, r.key, r.data)), r.deletedAt)
                        } catch (_: Exception) {
                            failed++
                        }
                    }
                }
            }
        }
        items.sortWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.item.name })
        return GrantorVault(grant, vaults, items, failed, mismatched)
    }
}
