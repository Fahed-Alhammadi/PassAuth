package io.passauth.app.data

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put

/*
 * Emergency access (servers with the `emergency_access` feature): someone (the grantor) names a
 * trusted contact with an account on the same server and a waiting period of 1–90 days. invited →
 * (the contact accepts) accepted → (the grantor checks the contact's fingerprint with them and
 * confirms) confirmed → (the contact asks) requested → (the grantor approves, or the waiting period
 * ends) approved. The grantor may reject a request or end an approved access (rejected; the contact
 * may ask again); either side may remove it.
 *
 * Keys (servers with `emergency_vault_keys`): confirming makes an emergency key for the access,
 * seals it to the contact's public key, keeps it wrapped by the grantor's account key
 * (`grantor_key`) and wraps each personal vault's key with it. The roster (sealed with the account
 * key, versioned inside) lists the accesses the grantor's apps may add wraps for; each device
 * remembers the highest version it opened and takes no older one.
 *
 * The web vault's `lib/emergency.ts`, with the same rules and words; pure and unit-tested in
 * EmergencyTest (every case of the web's `emergency.test.ts`). [EmergencyClient] does the requests.
 */

enum class GrantStatus(val wire: String) {
    Invited("invited"),
    Accepted("accepted"),
    Confirmed("confirmed"),
    Requested("requested"),
    Approved("approved"),
    Rejected("rejected"),
}

data class GrantPerson(val id: String, val email: String, val name: String, val publicKey: String)

data class Grant(
    val id: String,
    val status: GrantStatus,
    val waitDays: Long,
    val createdAt: Long,
    val updatedAt: Long,
    val requestedAt: Long?,
    val approvedAt: Long?,
    /** While a request waits: when the server approves it unless the grantor answers. */
    val autoApproveAt: Long?,
    val grantor: GrantPerson,
    val grantee: GrantPerson,
    /** The key scheme (2: an emergency key over the personal vaults); null when not given. */
    val keyVersion: Long?,
    /** The access's emergency key wrapped by this account's key, once confirmed. */
    val grantorKey: String?,
    /** Confirmed before emergency keys: the grantor confirms the contact again. */
    val reconfirm: Boolean,
    /** Personal vaults without a wrap for this access (when accepted: the vaults to wrap when confirming). */
    val missingVaults: List<String>,
    /** Confirmed before emergency keys, when the contact got the account key itself: they may keep it. */
    val v1Exposed: Boolean,
)

/** `GET /emergency-access`: the accesses both ways, and the account's sealed roster with its sequence number. */
data class GrantLists(
    val asGrantor: List<Grant>,
    val asGrantee: List<Grant>,
    /** The roster as the server keeps it (sealed); null until one is stored, or from servers without it. */
    val roster: String?,
    /** The roster's sequence number; null from servers without it. */
    val rosterSeq: Long?,
)

enum class Tone { Ok, Warn, Info }

data class StatusText(val label: String, val text: String, val tone: Tone)

enum class GrantorAction { Confirm, Approve, Reject, End, Wait, Remove }
enum class GranteeAction { Accept, Decline, Request, View, Remove }

/** One access the grantor's apps may add wraps for. */
data class RosterEntry(
    val id: String,
    /** The contact's public key the grantor checked by its fingerprint. */
    val contactKey: String,
    /** SHA-256 of the access's `grantor_key`, base64url. */
    val grantorKeyHash: String,
    /** The contact's email address and name as the grantor saw them when confirming (missing in entries from before). */
    val email: String? = null,
    val name: String? = null,
)

/** An access taken off the roster for good. */
data class RemovedEntry(val id: String, val grantorKeyHash: String)

data class Roster(val version: Long, val accesses: List<RosterEntry>, val removed: List<RemovedEntry> = emptyList())

/** One entry of the server's roster under review, and what taking the list would do for it. */
data class ReviewedEntry(val entry: RosterEntry, val wouldReturn: Boolean, val removed: Boolean)

/** The roster would pass the server's size limit: nothing is written (removed contacts are never dropped to make room). */
class RosterFullError : UserException("Your list of emergency contacts is full. Remove a contact you no longer need, then try again.")

/** A vault as this app's own sync shows it. */
data class OwnVault(val id: String, val role: Role, val kind: String)

/** `GET /emergency-access/{id}/vault`, as the core takes it. */
data class GrantorVaultData(
    /** The key scheme; null from servers before emergency keys (whose sealed key this app can't open). */
    val keyVersion: Long?,
    val sealedKey: String,
    val vaults: List<GrantorVaultRow>,
    val items: List<GrantorItemRow>,
    /** Every item row as sent (also ones this app can't read), for the vaults' manifests ([Manifests]). */
    val rawItems: List<JsonObject> = emptyList(),
)

/** [keyEpoch], [manifest], [manifestSeq]: the vault's manifest as the server sends it with the vault (0: none). */
data class GrantorVaultRow(val id: String, val meta: String, val wrappedKey: String, val keyEpoch: Long = 0, val manifest: String? = null, val manifestSeq: Long = 0)
data class GrantorItemRow(val id: String, val vaultId: String, val key: String, val data: String, val deletedAt: Long?, val updatedAt: Long)

object Emergency {
    const val FEATURE = "emergency_access"
    const val KEYS_FEATURE = "emergency_vault_keys"

    /** The key scheme this app makes and opens. */
    const val KEY_VERSION = 2L

    const val MIN_WAIT_DAYS = 1L
    const val MAX_WAIT_DAYS = 90L
    const val DEFAULT_WAIT_DAYS = 7L

    private fun str(v: JsonElement?): String = (v as? JsonPrimitive)?.takeIf { it.isString }?.content.orEmpty()
    private fun num(v: JsonElement?): Double? = (v as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() }
    private fun long(v: JsonElement?): Long? = num(v)?.toLong()
    private fun isTrue(v: JsonElement?): Boolean = (v as? JsonPrimitive)?.let { !it.isString && it.content == "true" } == true
    private fun strings(v: JsonElement?): List<String> =
        ((v as? JsonArray) ?: return emptyList()).mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.takeIf { s -> s.isNotEmpty() } }.distinct()

    private fun readPerson(v: JsonElement?): GrantPerson? {
        val p = v as? JsonObject ?: return null
        val id = str(p["id"]).ifEmpty { return null }
        return GrantPerson(id, str(p["email"]), str(p["name"]), str(p["public_key"]))
    }

    /** One emergency access from the API, or null when malformed (an unknown status included). */
    fun readGrant(value: JsonElement?): Grant? {
        val g = value as? JsonObject ?: return null
        val grantor = readPerson(g["grantor"]) ?: return null
        val grantee = readPerson(g["grantee"]) ?: return null
        val statusText = str(g["status"])
        val status = GrantStatus.entries.firstOrNull { it.wire == statusText } ?: return null
        val waitDays = num(g["wait_days"]) ?: return null
        val id = str(g["id"]).ifEmpty { return null }
        return Grant(
            id = id,
            status = status,
            waitDays = waitDays.toLong(),
            createdAt = long(g["created_at"]) ?: 0,
            updatedAt = long(g["updated_at"]) ?: 0,
            requestedAt = long(g["requested_at"]),
            approvedAt = long(g["approved_at"]),
            autoApproveAt = long(g["auto_approve_at"]),
            grantor = grantor,
            grantee = grantee,
            keyVersion = long(g["key_version"]),
            grantorKey = str(g["grantor_key"]).ifEmpty { null },
            reconfirm = isTrue(g["reconfirm"]),
            missingVaults = strings(g["missing_vaults"]),
            v1Exposed = isTrue(g["v1_exposed"]),
        )
    }

    /** `GET /emergency-access`: the contacts the account named, the people who named it, and the roster. */
    fun readGrants(value: JsonElement?): GrantLists {
        val v = value as? JsonObject ?: JsonObject(emptyMap())
        fun list(x: JsonElement?) = (x as? JsonArray)?.mapNotNull { readGrant(it) }.orEmpty()
        val seq = num(v["roster_seq"])
        return GrantLists(
            asGrantor = list(v["as_grantor"]),
            asGrantee = list(v["as_grantee"]),
            roster = str(v["roster"]).ifEmpty { null },
            rosterSeq = seq?.takeIf { it >= 0 && it == Math.floor(it) }?.toLong(),
        )
    }

    /** A person's name, else their email address. */
    fun personName(p: GrantPerson): String = CleanText.trim(p.name).ifEmpty { p.email }.ifEmpty { "Someone" }

    /** "1 day", "7 days". */
    fun daysText(days: Long): String = "$days ${if (days == 1L) "day" else "days"}"

    /** A waiting period the server accepts: a whole number of days from 1 to 90. */
    fun validWait(days: Double): Boolean = days == Math.floor(days) && days >= MIN_WAIT_DAYS && days <= MAX_WAIT_DAYS

    /** What a contact confirmed before emergency keys may still hold, said wherever removing them is offered. */
    fun v1Warning(who: String): String =
        "$who was confirmed with an earlier version of PassAuth, which gave them your account key. Removing them can't take that back. If you no longer trust them, change the passwords that matter or move to a new account."

    /** What confirming a contact ([who]) means, said before it is done. */
    fun confirmMeaning(who: String, v1Exposed: Boolean = false): String {
        val gives = "Confirming gives $who a key to your personal vaults. Once they get access (or at once, if your server is ever compromised), they can read everything in those vaults. Shared vaults and Sends stay out of reach."
        return if (v1Exposed) "$gives ${v1Warning(who)}"
        else "$gives If you remove them, PassAuth changes the keys of those vaults, so they can't read anything you add afterwards, unless your server is later compromised."
    }

    /** Why a contact confirmed before emergency keys has to be confirmed again. */
    fun reconfirmText(who: String): String =
        "PassAuth now gives emergency contacts a key to your personal vaults only. Confirm $who again to give them access."

    /** Statuses in which an access holds its keys: the contact has (or may get) the emergency key. */
    fun hasKeys(g: Grant): Boolean =
        g.status == GrantStatus.Confirmed || g.status == GrantStatus.Requested || g.status == GrantStatus.Approved || g.status == GrantStatus.Rejected

    /** What removing the contact of [g] does, for the grantor's confirmation. */
    fun removalText(g: Grant): String {
        val who = personName(g.grantee)
        val v1 = if (g.v1Exposed) " ${v1Warning(who)}" else ""
        if (!hasKeys(g)) return "$who can't ask for access any more.$v1"
        val changes = "Changing a vault's key also deletes the earlier versions kept of its items."
        if (g.v1Exposed) return "$who can't ask for access any more, and PassAuth changes the keys of your personal vaults. $changes$v1"
        val kept = if (g.status == GrantStatus.Confirmed) "" else " If they had access, they keep what they saw: change the passwords that matter if you no longer trust them."
        return "$who can't ask for access any more, and PassAuth changes the keys of your personal vaults, so they can't read anything you add afterwards, unless your server is later compromised. $changes$kept"
    }

    /** What a status means to the grantor, about their contact. [whenText] formats Unix seconds. */
    fun grantorStatus(g: Grant, whenText: (Long) -> String): StatusText {
        val who = personName(g.grantee)
        return when (g.status) {
            GrantStatus.Invited -> StatusText("Invited", "Waiting for $who to accept.", Tone.Info)
            GrantStatus.Accepted ->
                if (g.reconfirm) StatusText("Confirm again", reconfirmText(who), Tone.Warn)
                else StatusText("Confirm", "$who accepted. Check their fingerprint with them, then confirm them.", Tone.Warn)
            GrantStatus.Confirmed -> StatusText("Ready", "$who can ask for access. You'd have ${daysText(g.waitDays)} to say no.", Tone.Ok)
            GrantStatus.Requested -> StatusText(
                "Access requested",
                if (g.autoApproveAt != null) {
                    "$who asked for access${g.requestedAt?.let { " on ${whenText(it)}" }.orEmpty()}. Unless you reject it, they can view your personal vaults from ${whenText(g.autoApproveAt)}."
                } else {
                    "$who asked for access. Unless you reject it, they can view your personal vaults after ${daysText(g.waitDays)}."
                },
                Tone.Warn,
            )
            GrantStatus.Approved -> StatusText("Has access", "$who can view your personal vaults${g.approvedAt?.let { " since ${whenText(it)}" }.orEmpty()}.", Tone.Warn)
            GrantStatus.Rejected -> StatusText("Rejected", "You rejected $who's last request. They can ask again.", Tone.Info)
        }
    }

    /** What a status means to the contact, about the person who named them. */
    fun granteeStatus(g: Grant, whenText: (Long) -> String): StatusText {
        val who = personName(g.grantor)
        return when (g.status) {
            GrantStatus.Invited -> StatusText("Invitation", "$who named you as their emergency contact. Accept to be able to ask for access to their vaults if you ever need to.", Tone.Info)
            GrantStatus.Accepted -> StatusText("Waiting", "Waiting for $who to confirm you.", Tone.Info)
            GrantStatus.Confirmed -> StatusText("Ready", "You can ask for access. $who is told at once and has ${daysText(g.waitDays)} to say no.", Tone.Ok)
            GrantStatus.Requested -> StatusText(
                "Requested",
                if (g.autoApproveAt != null) "You asked for access. Unless $who rejects it, you can view their vaults from ${whenText(g.autoApproveAt)}."
                else "You asked for access. Unless $who rejects it, you can view their vaults after ${daysText(g.waitDays)}.",
                Tone.Warn,
            )
            GrantStatus.Approved -> StatusText("Access granted", "You can view $who's vaults.", Tone.Ok)
            GrantStatus.Rejected -> StatusText("Rejected", "$who rejected your request. You can ask again.", Tone.Info)
        }
    }

    /** What the grantor can do now, most important first. */
    fun grantorActions(g: Grant): List<GrantorAction> = when (g.status) {
        GrantStatus.Accepted -> listOf(GrantorAction.Confirm, GrantorAction.Wait, GrantorAction.Remove)
        GrantStatus.Requested -> listOf(GrantorAction.Approve, GrantorAction.Reject, GrantorAction.Wait, GrantorAction.Remove)
        GrantStatus.Approved -> listOf(GrantorAction.End, GrantorAction.Wait, GrantorAction.Remove)
        else -> listOf(GrantorAction.Wait, GrantorAction.Remove)
    }

    /** What the contact can do now, most important first. */
    fun granteeActions(g: Grant): List<GranteeAction> = when (g.status) {
        GrantStatus.Invited -> listOf(GranteeAction.Accept, GranteeAction.Decline)
        GrantStatus.Confirmed, GrantStatus.Rejected -> listOf(GranteeAction.Request, GranteeAction.Remove)
        GrantStatus.Approved -> listOf(GranteeAction.View, GranteeAction.Remove)
        else -> listOf(GranteeAction.Remove)
    }

    /** Grants that want the account's answer: contacts to confirm, requests to answer, invitations to accept. */
    fun needsAnswer(asGrantor: List<Grant>, asGrantee: List<Grant>): Int =
        asGrantor.count { it.status == GrantStatus.Accepted || it.status == GrantStatus.Requested } + asGrantee.count { it.status == GrantStatus.Invited }

    // ------------------------------------------------------------ the keys

    /**
     * Whether this app's own data says a vault is personal, the only kind whose key an emergency
     * contact may get: the account owns it with its own key, its members (invitees included) are this
     * account ([me]) alone, and with signed sharing it was never shared under a signed member list
     * ([sharedBefore]: a trusted roster lists someone else, or its key pin says it was signed).
     * Unknown vaults and members lists aren't.
     */
    fun isPersonal(vault: OwnVault?, members: List<String>?, me: String, sharedBefore: Boolean = false): Boolean {
        if (vault == null || vault.role != Role.Owner || vault.kind != VaultInfo.KEY_KIND_ACCOUNT || me.isEmpty() || members == null || sharedBefore) return false
        return members.size == 1 && members[0] == me
    }

    /** Which of the vaults the server asks to wrap ([wanted]) this app wraps: only those its own data says are personal. */
    fun vaultsToWrap(wanted: List<String>, personal: (String) -> Boolean): Pair<List<String>, List<String>> {
        val wrap = mutableListOf<String>()
        val refused = mutableListOf<String>()
        for (id in LinkedHashSet(wanted)) (if (personal(id)) wrap else refused) += id
        return wrap to refused
    }

    /** The accesses whose wraps this account should add now: holding keys, with this account's `grantor_key`, vaults missing. */
    fun accessesToFill(grants: List<Grant>): List<Grant> =
        grants.filter { hasKeys(it) && it.grantorKey != null && it.missingVaults.isNotEmpty() && (it.keyVersion ?: KEY_VERSION) == KEY_VERSION }

    /** The vault ids of an answer that asks for new keys (`rotation_pending` of `DELETE /emergency-access/{id}`). */
    fun vaultsToRotate(answer: JsonElement?): List<String> = strings((answer as? JsonObject)?.get("rotation_pending"))

    /** The vaults whose keys the grantor's app replaces after removing a contact: those named that are personal here. */
    fun vaultsToReKey(answer: JsonElement?, personal: (String) -> Boolean): List<String> = vaultsToWrap(vaultsToRotate(answer), personal).first

    // ---------------------------------------------------------- the roster

    /** SHA-256 of [text] (UTF-8), base64url: how the roster names an access's `grantor_key`. */
    fun sha256b64(text: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))

    val EMPTY_ROSTER = Roster(0, emptyList(), emptyList())

    /** Most removed accesses a roster keeps; the oldest go first. */
    const val MAX_REMOVED = 300

    /** The largest sealed roster the server takes (base64url characters). */
    const val MAX_SEALED_ROSTER = 48 * 1024

    const val MAX_EMAIL = 254
    const val MAX_NAME = 100

    /** A roster from its JSON (as the core opened it); null when malformed. Rosters from before `removed` have none. */
    fun readRoster(json: String): Roster? {
        val v = try {
            AppJson.parseToJsonElement(json)
        } catch (_: Exception) {
            return null
        }
        val r = v as? JsonObject ?: return null
        val version = (r["version"] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull ?: return null
        if (!version.isFinite() || version != Math.floor(version) || version < 0) return null
        val accessesRaw = r["accesses"] as? JsonArray ?: return null
        val removedRaw = r["removed"]
        if (removedRaw != null && removedRaw !is JsonArray) return null
        val accesses = mutableListOf<RosterEntry>()
        for (raw in accessesRaw) {
            val e = raw as? JsonObject ?: return null
            if (str(e["id"]).isEmpty() || str(e["contact_key"]).isEmpty() || str(e["grantor_key_hash"]).isEmpty()) return null
            val email = e["email"]
            val name = e["name"]
            if ((email != null && (email as? JsonPrimitive)?.isString != true) || (name != null && (name as? JsonPrimitive)?.isString != true)) return null
            accesses += RosterEntry(str(e["id"]), str(e["contact_key"]), str(e["grantor_key_hash"]), email?.let { str(it) }, name?.let { str(it) })
        }
        val removed = mutableListOf<RemovedEntry>()
        for (raw in (removedRaw as? JsonArray).orEmpty()) {
            val e = raw as? JsonObject ?: return null
            val hash = e["grantor_key_hash"] as? JsonPrimitive
            if (str(e["id"]).isEmpty() || hash == null || !hash.isString) return null
            removed += RemovedEntry(str(e["id"]), hash.content)
        }
        return Roster(version.toLong(), accesses, removed)
    }

    /** The roster's JSON, for `Account.sealEmergencyRoster` (keys in the web vault's order). */
    fun rosterJson(r: Roster): String = buildJsonObject {
        put("version", r.version)
        put("accesses", buildJsonArray {
            r.accesses.forEach { e ->
                add(buildJsonObject {
                    put("id", e.id)
                    put("contact_key", e.contactKey)
                    put("grantor_key_hash", e.grantorKeyHash)
                    e.email?.let { put("email", it) }
                    e.name?.let { put("name", it) }
                })
            }
        })
        put("removed", buildJsonArray { r.removed.forEach { x -> add(buildJsonObject { put("id", x.id); put("grantor_key_hash", x.grantorKeyHash) }) } })
    }.toString()

    /** How long [r] is once sealed (base64url of version, nonce, the JSON and the tag). */
    fun sealedLength(r: Roster): Int {
        val n = 1 + 24 + rosterJson(r).toByteArray(Charsets.UTF_8).size + 16
        return n / 3 * 4 + intArrayOf(0, 2, 3)[n % 3]
    }

    /** [removed] and then [add], each access once (a later copy counts as newer), the oldest trimmed beyond [MAX_REMOVED]. */
    private fun withRemoved(version: Long, accesses: List<RosterEntry>, removed: List<RemovedEntry>, add: List<RemovedEntry> = emptyList()): Roster {
        val all = mutableListOf<RemovedEntry>()
        for (x in removed + add) {
            val i = all.indexOfFirst { it.id == x.id }
            if (i >= 0) all.removeAt(i)
            all += x
        }
        val out = Roster(version, accesses, all.takeLast(MAX_REMOVED))
        if (sealedLength(out) > MAX_SEALED_ROSTER) throw RosterFullError()
        return out
    }

    /** Whether [r] took access [id] (or its key, by hash) off for good. */
    fun isRemoved(r: Roster?, id: String, grantorKeyHash: String? = null): Boolean =
        r?.removed?.any { it.id == id || (!grantorKeyHash.isNullOrEmpty() && it.grantorKeyHash == grantorKeyHash) } == true

    /** A roster entry for access [g] as the grantor confirms it: the contact key they checked, the name and email shown. */
    fun rosterEntry(g: Grant, checkedContactKey: String, grantorKeyHash: String): RosterEntry =
        RosterEntry(g.id, checkedContactKey, grantorKeyHash, CleanText.oneLine(g.grantee.email, MAX_EMAIL), CleanText.oneLine(g.grantee.name, MAX_NAME))

    /** The entries whose access the server still lists, in any state. */
    fun pruneRoster(r: Roster, listed: Set<String>): List<RosterEntry> = r.accesses.filter { it.id in listed }

    private fun removedOf(e: RosterEntry) = RemovedEntry(e.id, e.grantorKeyHash)

    /** A change to the roster: an access added (replacing one of the same id), or one taken out. */
    sealed interface RosterChange {
        data class Add(val entry: RosterEntry) : RosterChange
        data class Remove(val id: String, val hash: String? = null) : RosterChange
    }

    /**
     * The next roster after [r]: entries of accesses the server no longer lists ([listed]) dropped
     * and kept as removed, then [change] applied (null: only the dropping). Its version is one above
     * both [r]'s and [seen]. Null when nothing changes.
     */
    fun nextRoster(r: Roster, seen: Long, change: RosterChange?, listed: Set<String>? = null): Roster? {
        var accesses = if (listed != null) pruneRoster(r, listed) else r.accesses.toList()
        val gone = r.accesses.filter { e -> accesses.none { it === e } }.map(::removedOf).toMutableList()
        when (change) {
            is RosterChange.Add -> accesses = accesses.filter { it.id != change.entry.id } + change.entry
            is RosterChange.Remove -> {
                val entry = accesses.firstOrNull { it.id == change.id } ?: r.accesses.firstOrNull { it.id == change.id }
                accesses = accesses.filter { it.id != change.id }
                if (entry != null || change.hash != null) gone += RemovedEntry(change.id, entry?.grantorKeyHash ?: change.hash ?: "")
            }
            null -> Unit
        }
        val next = withRemoved(maxOf(r.version, seen) + 1, accesses, r.removed, gone)
        return if (rosterJson(next.copy(version = r.version)) == rosterJson(r)) null else next
    }

    /** Accesses that hold keys but that the (trusted) roster doesn't list and didn't remove: "Confirm again". */
    fun needsConfirmAgain(g: Grant, roster: Roster?, grantorKeyHash: String? = null): Boolean =
        roster != null && hasKeys(g) && roster.accesses.none { it.id == g.id } && !isRemoved(roster, g.id, grantorKeyHash)

    /** What the app says about an access the roster removed. */
    fun removedText(who: String): String = "$who was removed from your emergency contacts. To give them access again, add them as a new contact."

    /** A roster entry as the grantor reviews it: its own name and email (from inside the roster), or "Unknown contact". */
    fun entryLabel(e: RosterEntry): String {
        val name = e.name?.let(CleanText::trim).orEmpty()
        if (name.isNotEmpty() && !e.email.isNullOrEmpty()) return "$name (${e.email})"
        return name.ifEmpty { e.email.orEmpty() }.ifEmpty { "Unknown contact" }
    }

    /** The server's roster as the grantor reviews it before "Use the server's list". */
    fun reviewRoster(server: Roster, trusted: Roster?, listed: Set<String>): List<ReviewedEntry> =
        pruneRoster(server, listed).map { entry ->
            ReviewedEntry(
                entry,
                wouldReturn = trusted?.accesses?.none { it.id == entry.id && it.contactKey == entry.contactKey } ?: true,
                removed = isRemoved(server, entry.id, entry.grantorKeyHash) || isRemoved(trusted, entry.id, entry.grantorKeyHash),
            )
        }

    /** Whether [r] is older than the highest roster version this device has opened ([seen]): never act on it. */
    fun rosterIsOlder(r: Roster, seen: Long): Boolean = r.version < seen

    /** "Use the server's list": exactly the entries shown, less those removed and those no longer listed, one version above. */
    fun restoredRosterForward(shown: List<ReviewedEntry>, server: Roster, trusted: Roster?, seen: Long, listedNow: Set<String>): Roster {
        val accesses = shown.filter { !it.removed && it.entry.id in listedNow }.map { it.entry }
        val gone = server.accesses.filter { e -> accesses.none { it.id == e.id } }.map(::removedOf).toMutableList()
        for (r in shown) if (accesses.none { it === r.entry } && gone.none { it.id == r.entry.id }) gone += removedOf(r.entry)
        return withRemoved(maxOf(seen, server.version) + 1, accesses, server.removed + trusted?.removed.orEmpty(), gone)
    }

    /** "Start a new list": an empty one above the newest this device saw, keeping what its trusted roster removed. */
    fun freshRoster(seen: Long, trusted: Roster? = null): Roster = withRemoved(seen + 1, emptyList(), trusted?.removed.orEmpty())

    /** The accesses the fill may add wraps for: in the roster with the same contact key and grantor key, not removed. */
    fun fillableAccesses(grants: List<Grant>, roster: Roster, hashes: Map<String, String>): List<Grant> =
        accessesToFill(grants).filter { g ->
            val hash = g.grantorKey?.let { hashes[it] }
            !isRemoved(roster, g.id, hash) && roster.accesses.any { e -> e.id == g.id && e.contactKey == g.grantee.publicKey && hash != null && e.grantorKeyHash == hash }
        }

    // ----------------------------------------------------------- the vault

    /** `GET /emergency-access/{id}/vault` as the core takes it; null when malformed. */
    fun readGrantorVault(value: JsonElement?): GrantorVaultData? {
        val v = value as? JsonObject ?: return null
        val sealedKey = str(v["sealed_key"]).ifEmpty { return null }
        val vaultsRaw = v["vaults"] as? JsonArray ?: return null
        val itemsRaw = v["items"] as? JsonArray ?: return null
        val vaults = vaultsRaw.mapNotNull { raw ->
            val r = raw as? JsonObject ?: return@mapNotNull null
            if (str(r["id"]).isEmpty() || str(r["meta"]).isEmpty() || str(r["wrapped_key"]).isEmpty()) null
            else GrantorVaultRow(str(r["id"]), str(r["meta"]), str(r["wrapped_key"]), long(r["key_epoch"]) ?: 0, str(r["manifest"]).ifEmpty { null }, long(r["manifest_seq"]) ?: 0)
        }
        val items = itemsRaw.mapNotNull { raw ->
            val r = raw as? JsonObject ?: return@mapNotNull null
            if (str(r["id"]).isEmpty() || str(r["vault_id"]).isEmpty() || str(r["item_key"]).isEmpty() || str(r["data"]).isEmpty()) null
            else GrantorItemRow(str(r["id"]), str(r["vault_id"]), str(r["item_key"]), str(r["data"]), long(r["deleted_at"]), long(r["updated_at"]) ?: 0)
        }
        return GrantorVaultData(long(v["key_version"]), sealedKey, vaults, items, itemsRaw.mapNotNull { it as? JsonObject })
    }
}
