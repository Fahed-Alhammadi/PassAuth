package io.passauth.app.data

import io.passauth.core.Account
import io.passauth.core.CoreException
import io.passauth.core.SigningIdentity
import io.passauth.core.VaultKey
import io.passauth.core.mergePins
import io.passauth.core.pinCheck
import io.passauth.core.pinSet
import io.passauth.core.normalizeEmail
import io.passauth.core.pinsAdmit
import io.passauth.core.pinsObserve
import io.passauth.core.pinsCheckOwnIdentity
import io.passauth.core.pinsGrandfather
import io.passauth.core.pinsLeave
import io.passauth.core.pinsLegacyWrapAllowed
import io.passauth.core.pinsSetEpoch
import io.passauth.core.pinsSetOwnIdentity
import io.passauth.core.rosterHash
import io.passauth.core.rosterHead
import io.passauth.core.rosterMemberRole
import io.passauth.core.rosterReview
import io.passauth.core.rosterSignerRole
import io.passauth.core.verifyIdentity
import io.passauth.core.verifyRosterChain
import io.passauth.core.verifyShare
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/*
 * Signed sharing, the app's side (docs/ARCHITECTURE.md "Signed sharing", steps 0–8; core:
 * crates/core/src/sharing.rs through UniFFI). The server checks shapes and signatures against what
 * it stores, but it can't vouch for anything, so every check here is the app's own, against
 * identities it pinned:
 *  - "me" is the account id the core authenticated (never `/sync` `user.id`; a sync naming another
 *    account is refused), and this account's own identity is remembered: none or another one listed
 *    later pauses sharing (every shared vault refused, nothing signed);
 *  - key pins: other people's identities and each accepted vault's key (epoch, key id, retired key
 *    ids), sealed with the account key on the server (compare-and-swap) with the highest version
 *    opened kept on this phone (an older one from the server is a rollback);
 *  - every vault of every sync: key, signed member roster chain, share signature and signer, then
 *    the core's admission (`pins_admit`): used, held for the user's consent (a vault the account
 *    never accepted), or refused. Pins and memory change only after every check of the row passed;
 *  - invitations: unsigned ones can't be accepted on a server that signs; signed ones are checked
 *    in full before Accept, and their signer is pinned only when the user accepts;
 *  - key replacements: the member list reviewed (every member with fingerprint and pin state the
 *    first time a vault is signed, never automatically), sealed and signed for every member, with
 *    the next signed roster.
 * Pure apart from [SharingApi] and [SigningMemoryStore]; unit-tested with the real core in
 * SignedSharingTest.
 */

/**
 * This phone's memory of one account's signed sharing (keyed by server and the core-authenticated
 * account id, so logging out keeps it and another account never inherits it). [pinsSeq]: the
 * highest key-pins version opened here (never goes down) and [pinsSealed] that copy; [rosters]: per
 * vault id, the last member roster this phone trusted (JSON text as signed); [signed]: vaults seen
 * signed here; [ownIdentity]: this account's own identity hash once it had one; [generated]: the
 * hashes of identities this phone made and uploaded (the last few), so an upload whose answer was
 * lost still counts as made here once the server lists it. Writes merge ([merge]), never overwrite.
 */
@Serializable
data class SigningMemory(
    val pinsSeq: Long = 0,
    val pinsSealed: String? = null,
    val rosters: Map<String, String> = emptyMap(),
    val signed: Set<String> = emptySet(),
    val ownIdentity: String? = null,
    val generated: List<String> = emptyList(),
) {
    /** Nothing remembered yet (a server without signed sharing may be used without checks; [generated] alone doesn't count). */
    val isEmpty: Boolean get() = pinsSeq == 0L && pinsSealed == null && rosters.isEmpty() && signed.isEmpty() && ownIdentity == null

    /**
     * [other] merged in: the higher pins version with its sealed copy, per vault the roster with the
     * higher version, the union of vaults seen signed, the own identity remembered first.
     */
    fun merge(other: SigningMemory): SigningMemory {
        val (seq, sealed) = if (other.pinsSeq > pinsSeq || (other.pinsSeq == pinsSeq && pinsSealed == null)) other.pinsSeq to other.pinsSealed else pinsSeq to pinsSealed
        val r = rosters.toMutableMap()
        for ((vid, text) in other.rosters) {
            val mine = r[vid]
            if (mine == null || (SignedSharing.rosterVersion(text) ?: 0) > (SignedSharing.rosterVersion(mine) ?: 0)) r[vid] = text
        }
        return SigningMemory(seq, sealed, r, signed + other.signed, ownIdentity ?: other.ownIdentity, (generated + other.generated).distinct().takeLast(MAX_GENERATED))
    }

    companion object {
        const val MAX_GENERATED = 4
    }
}

/** A person's key pin state, as the core says it ([io.passauth.core.pinCheck]). */
enum class PinState { New, Match, Changed, Upgraded, EmailConflict }

/**
 * Who signed a share, as shown: [email] is the pinned one (the one the server listed when it is new),
 * [listedEmail] the different one the server lists now ("listed by your server as …"), both cleaned.
 * "Verified" ([verified]) is only ever shown next to the pinned email.
 */
data class SignerView(val email: String, val listedEmail: String?, val fingerprint: String, val pin: PinState, val verified: Boolean)

/** How far a vault's key was checked (shown next to its name). */
sealed interface VaultTrust {
    /** Not checked: a server without signed sharing. */
    data object Unchecked : VaultTrust

    /** The account's own key (`account`), its epoch pinned (and its roster checked, when it has one). */
    data object Own : VaultTrust

    /** Shared before signing existed (grandfathered or accepted before): usable, until an owner or admin signs it. */
    data object NotYetSigned : VaultTrust

    /** The share is signed by [signer] ([deleted]: their account is gone since) and checked. */
    data class Signed(val signer: SignerView, val deleted: Boolean) : VaultTrust
}

/** A vault this phone refused (never used), with its name (cleaned; opened only to read it) and why. */
data class RefusedVault(val id: String, val name: String, val reason: String)

/**
 * A shared vault the account never accepted (or left, and was shared again, or whose key was replaced
 * unsigned: [replaced]): never used until the user accepts it, shown like an invitation. Unsigned
 * new ones ([signer] null) can only be declined, except while the trust memory is missing.
 */
data class ConsentVault(
    val vaultId: String,
    val name: String,
    val role: String,
    val rejoin: Boolean,
    val signer: SignerView?,
    val deleted: Boolean,
    /** A vault already accepted whose key was replaced unsigned (by a member's app from before signing). */
    val replaced: Boolean = false,
    /** The account's trust memory is missing: unsigned vaults can be accepted too ("Not yet signed"). */
    val unsignedAllowed: Boolean = false,
    /**
     * What was checked, in one value (key id and epoch, signer identity hash, roster hash and
     * version, the flags): accepting binds to the vault as shown, so a server that changes it between
     * the check and the tap gets [SignedSharing.CHANGED_JUST_NOW] (re-review H).
     */
    val token: String = "",
) {
    val acceptable: Boolean get() = signer != null || replaced || unsignedAllowed
}

/**
 * Someone's identity differs from the one pinned ([conflict]: a new account with an email pinned for
 * another one): nothing that needs it is done until the user trusts the new one.
 */
data class IdentityChange(
    val userId: String,
    val email: String,
    val listedEmail: String?,
    val fingerprint: String,
    val identityHash: String,
    val identityJson: String,
    val conflict: Boolean,
    internal val pinEmail: String,
) {
    val text: String get() = if (conflict) SignedSharing.emailConflict(email) else SignedSharing.keysChanged(email)

    /** The email "Trust the new key" pins, as shown in its sheet (the one the server lists now). */
    val pinShown: String get() = SignedSharing.clean(SignedSharing.normalized(pinEmail))
}

/** A pinned identity, for Settings ([identityHash]: what "Mark as verified" marks, if still pinned). */
data class KnownPerson(val userId: String, val email: String, val fingerprint: String, val identityHash: String, val verified: Boolean)

/** An invitation's signature, checked before it can be accepted. */
sealed interface InvitationTrust {
    /** A server without signed sharing: the earlier wording (fingerprint the server lists). */
    data object Unchecked : InvitationTrust

    /** Not signed on a server that signs: Decline only. */
    data object Unsigned : InvitationTrust

    data class Refused(val reason: String) : InvitationTrust

    /** Signed by [signer] and checked; accepting pins the signer, the key and the roster. */
    data class Signed(
        val signer: SignerView,
        internal val signerJson: String,
        internal val pinEmail: String,
        internal val roster: String,
        internal val rosterVersion: Long,
        internal val epochPin: String,
    ) : InvitationTrust
}

/** One member of a [MemberReview] as shown. */
data class ReviewPerson(
    val userId: String,
    val role: String,
    /** The pinned email, else the one the server lists (cleaned). */
    val email: String,
    /** The server's email when it differs from the pinned one (cleaned). */
    val listedEmail: String?,
    val fingerprint: String,
    val pin: PinState,
    val verified: Boolean,
    val isSelf: Boolean,
    /** same, added, identity_changed or role_changed (against the trusted roster). */
    val change: String,
    /** The email a key replacement pins for them when they're new (the pinned one, else the server's), normalized; empty for none. */
    val pinEmail: String = "",
)

/** A member of the trusted roster the server no longer lists (confirmed per user id). */
data class MissingPerson(val userId: String, val role: String, val email: String)

/**
 * The member list a vault's next signed roster would list, for the user to check before anything is
 * sealed or signed ([first]: version 1, no roster trusted yet: compare every fingerprint).
 */
data class MemberReview(
    val vaultId: String,
    val vaultName: String,
    val version: Long,
    val first: Boolean,
    val members: List<ReviewPerson>,
    val missing: List<MissingPerson>,
    val digest: String,
    /** Stop: a key changed, or the server lists another identity than the trusted roster's (never signed). */
    val blocked: Boolean = false,
) {
    /** The emails shown for the people this review pins (new or upgraded keys), by user id: kept with the approval. */
    fun emailsToPin(): Map<String, String> =
        members.filter { !it.isSelf && (it.pin == PinState.New || it.pin == PinState.Upgraded) && it.pinEmail.isNotEmpty() }.associate { it.userId to it.pinEmail }
}

/** The user confirmed review [digest] of a vault, with the missing people [missing] (user ids). */
data class ReviewApproval(
    val digest: String,
    val missing: Set<String>,
    /** The emails the review showed for the people it pins ([MemberReview.emailsToPin]): pinned as shown, never from a later members answer. */
    val emails: Map<String, String> = emptyMap(),
)

/** What the app shows about signed sharing of the active account. */
data class SharingStatus(
    /** The server signs shares (or this phone has signed-sharing memory for the account). */
    val enabled: Boolean = false,
    /** The account's own identity fingerprint (computed here, never the server's); null without one. */
    val fingerprint: String? = null,
    val paused: Boolean = false,
    val pinsProblem: String? = null,
    val refused: List<RefusedVault> = emptyList(),
    val changed: List<IdentityChange> = emptyList(),
    val people: List<KnownPerson> = emptyList(),
    val consent: List<ConsentVault> = emptyList(),
    /** The account's trust memory (key pins) is missing ([SharingSession.memoryMissing]). */
    val memoryMissing: Boolean = false,
) {
    /** One key that changes whenever there's something new to warn about (a dismissed notice comes back). */
    val noticeKey: String
        get() = "sig:" + listOf(
            paused.toString(),
            memoryMissing.toString(),
            pinsProblem.orEmpty(),
            refused.joinToString(",") { it.id },
            changed.joinToString(",") { it.userId + it.identityHash },
            consent.joinToString(",") { it.vaultId },
        ).joinToString("|")
}

/** The requests signed sharing needs, on the account's session. */
interface SharingApi {
    /** `PUT /account/identity` with the record (JSON text); whether the server answered `created: true`. */
    suspend fun putIdentity(recordJson: String): Boolean

    /** `user.identity` of a fresh `/sync` (after 409 `identity_exists`). */
    suspend fun currentIdentity(): JsonElement?

    /** `GET /account/key-pins`: the sealed pins (null: none) and their version. */
    suspend fun getKeyPins(): Pair<String?, Long>

    /** `PUT /account/key-pins {key_pins, seq}`. */
    suspend fun putKeyPins(sealed: String, seq: Long)

    /** `GET /vaults/{id}/rosters?after=` → the roster texts (oldest first) and whether more follow. */
    suspend fun rosters(vaultId: String, after: Long): Pair<List<String>, Boolean>
}

/** This phone's [SigningMemory] of the account. */
interface SigningMemoryStore {
    suspend fun read(): SigningMemory

    /** [transform] applied to the stored memory in one step (the store's own lock). */
    suspend fun write(transform: (SigningMemory) -> SigningMemory)
}

/** A request failed before the server answered: retried at the next sync. */
class SharingOffline : Exception("offline")

/** The server's `/sync` names another account than the one unlocked here. */
class WrongAccountException : UserException("Your server sent the vault of another account. PassAuth didn't use it.")

object SignedSharing {
    const val FEATURE = "signed_sharing"

    const val REFUSED = "PassAuth couldn't verify this shared vault's key, so it isn't used. Ask its owner, or your server's admin."
    const val UNCHECKED = "PassAuth couldn't check this shared vault yet, so it isn't used until your server can be reached."
    const val PAUSED = "Your server lists a signing key that isn't yours. Sharing is paused on this device."
    const val PINS_ROLLED_BACK = "Your server sent an older list of known keys. PassAuth keeps using the one on this phone."
    const val PINS_UNREADABLE = "Your server's list of known keys can't be opened with your account's key. PassAuth keeps using the one on this phone."
    const val NOT_YET_SIGNED = "Not yet signed"
    const val CHANGED_JUST_NOW = "The vault's members changed just now. Sync and try again."
    const val TOO_MANY_CHANGES = "This shared vault has too many member changes to check here, so it isn't used."
    const val FIRST_TIME = "First time this vault is signed: compare these fingerprints with the people."
    const val NEEDS_REVISIONS = "Your server didn't send every item's revision, so PassAuth didn't replace this vault's key. Update your server and try again."
    const val NOT_SIGNED_HERE = "Your signing key isn't set up on this phone yet. Sync and try again."
    const val CONSENT = "Your server added this vault to your account. Accept only if you expected it."
    const val MEMORY_MISSING = "PassAuth couldn't find your list of known keys on your server, so each shared vault needs your OK again. If you didn't expect this, tell your server's admin."
    const val CONSENT_REPLACED = "Its key was replaced by an app that doesn't sign yet. Accept only if someone in this vault just replaced its key. It stays locked until you accept it."
    const val CONSENT_UNSIGNED = "It isn't signed, so it can't be accepted. Ask whoever shared it to update PassAuth and share it again."
    const val PINS_NOT_SAVED = "PassAuth couldn't save your list of known keys on your server, so nothing was accepted. Try again when your server can be reached."
    const val NO_DECLINE_NOW = "While PassAuth can't find your list of known keys, shared vaults can only be accepted or left for later."
    const val COMPARE_FIRST = "Compare the fingerprint with them first: this account uses an email you already know under another account."

    /**
     * Whether signed sharing is checked for an account: its server lists `signed_sharing` (in the
     * features kept, [kept], or asked now, [now]), this phone has trust memory for it ([hasMemory]), or
     * the server sent an identity, share, roster or key pins version ([signals]). An unknown
     * `/api/config` (null) turns nothing on by itself and persists nothing (web re-review A): a server
     * without the feature works as before once its config is known.
     */
    fun checksOn(kept: List<String>?, now: List<String>?, hasMemory: Boolean, signals: Boolean): Boolean =
        kept?.contains(FEATURE) == true || now?.contains(FEATURE) == true || hasMemory || signals

    /** One value for what a check showed (hashed, so it can be compared and kept short). */
    internal fun token(vararg parts: Any?): String {
        val d = java.security.MessageDigest.getInstance("SHA-256")
        for (p in parts) {
            val b = (p?.toString() ?: "\u0000null").toByteArray(Charsets.UTF_8)
            d.update(java.nio.ByteBuffer.allocate(4).putInt(b.size).array())
            d.update(b)
        }
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(d.digest())
    }

    /** Someone this phone knows only by user id (never pinned, no longer listed). */
    fun someone(userId: String) = "a former member (${userId.take(8)})"

    fun signedBy(email: String, deleted: Boolean) = "Signed by $email" + if (deleted) " (account deleted)" else ""

    /** "Signed by …" with the server's different email, never "Verified" next to it. */
    fun signerLine(s: SignerView, deleted: Boolean): String =
        signedBy(s.email, deleted) + (s.listedEmail?.let { " (listed by your server as $it)" } ?: "") + if (s.verified && s.listedEmail == null) " · Verified" else ""

    fun unsignedInvitation(name: String) = "This invitation isn't signed. Ask $name to update PassAuth and share again."

    fun keysChanged(email: String) = "$email's keys changed. Compare their fingerprint with them before you continue."

    fun emailConflict(email: String) = "Your server lists a new account for $email, whose keys you already know under another account."

    fun firstTime(email: String) = "First time you see $email's keys: compare this fingerprint with them"

    fun consentTitle(name: String) = "Your server added $name to your account"

    fun membersDiffer(people: List<String>) =
        "The server lists members your vault's signed member list doesn't: ${people.joinToString(", ")}. PassAuth didn't change the key."

    /** Why the core refused a vault (`pins_admit` reason), in words. */
    fun refusedReason(code: String): String = when (code) {
        "missing_epoch" -> "$REFUSED (Your server didn't say which key it uses.)"
        "paused" -> PAUSED
        "left" -> "You left or declined this vault, so PassAuth doesn't use it again unless it's shared with you again."
        "older" -> "$REFUSED (Your server sent an older key than one this phone already saw.)"
        "conflict" -> "$REFUSED (Your server sent a different key than the one it listed before.)"
        "downgraded" -> "$REFUSED (It was signed before and now isn't.)"
        "roster_forked" -> "$REFUSED (Your server sent a different member list than the one you saw before.)"
        else -> REFUSED
    }

    /** The label after a vault's name; null for none. */
    fun label(t: VaultTrust): String? = when (t) {
        VaultTrust.NotYetSigned -> NOT_YET_SIGNED
        is VaultTrust.Signed -> signedBy(t.signer.email, t.deleted)
        else -> null
    }

    /** A name or email from the server, made safe to show (one line, no invisible characters, at most 128 characters). */
    fun clean(s: String?): String = CleanText.oneLine(s, 128)

    /** A vault name from the server or a vault's encrypted name, cleaned (at most 64 characters). */
    fun cleanName(s: String?): String = CleanText.oneLine(s, 64)

    private val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** The identity fingerprint of an identity hash (base64url): its first 15 bytes in base32, in groups of four (the core's format). */
    fun fingerprintOfHash(hashB64: String): String? {
        val bytes = try {
            java.util.Base64.getUrlDecoder().decode(hashB64.trimEnd('='))
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (bytes.size < 15) return null
        val out = StringBuilder()
        var buffer = 0
        var bits = 0
        for (i in 0 until 15) {
            buffer = (buffer shl 8) or (bytes[i].toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                out.append(BASE32[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
        }
        return out.chunked(4).joinToString("-")
    }

    internal fun text(o: JsonObject?, key: String): String? = (o?.get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content

    internal fun number(o: JsonObject?, key: String): Long? = (o?.get(key) as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

    internal fun flag(o: JsonObject?, key: String): Boolean = (o?.get(key) as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull == true

    internal fun obj(text: String): JsonObject? = runCatching { AppJson.parseToJsonElement(text) as? JsonObject }.getOrNull()

    /** A roster's `key_epoch` and `version` (the core parsed and checked it before). */
    fun rosterEpoch(roster: String): Long? = number(obj(roster), "key_epoch")

    fun rosterVersion(roster: String): Long? = number(obj(roster), "version")

    /** The user ids a roster lists. */
    fun rosterMembers(roster: String): List<String> =
        (obj(roster)?.get("members") as? JsonArray).orEmpty().mapNotNull { text(it as? JsonObject, "user_id") }

    /** The pin of [userId] in key pins (JSON): `{user_id, email, identity, verified, …}`; null when not pinned. */
    fun pinOf(pins: String?, userId: String): JsonObject? =
        ((pins?.let(::obj))?.get("pins") as? JsonArray)?.firstNotNullOfOrNull { p -> (p as? JsonObject)?.takeIf { text(it, "user_id") == userId } }

    /** The epoch pin of a vault in key pins (JSON); null when the account never accepted it. */
    fun epochOf(pins: String?, vaultId: String): JsonObject? = ((pins?.let(::obj))?.get("epochs") as? JsonObject)?.get(vaultId) as? JsonObject

    /** Whether the key pins still have no grandfathered list (the account's first signed sync). */
    fun needsGrandfathering(pins: String?): Boolean {
        val g = pins?.let(::obj)?.get("grandfathered")
        return g == null || g is JsonNull
    }

    /** The own identity hash the key pins remember. */
    fun ownIdentityOf(pins: String?): String? = text(pins?.let(::obj), "own_identity")

    /** The people of key pins (JSON) for Settings. */
    fun people(pins: String?): List<KnownPerson> {
        val list = (pins?.let(::obj))?.get("pins") as? JsonArray ?: return emptyList()
        return list.mapNotNull { p ->
            val o = p as? JsonObject ?: return@mapNotNull null
            val id = text(o, "user_id") ?: return@mapNotNull null
            val hash = text(o, "identity") ?: return@mapNotNull null
            val fp = fingerprintOfHash(hash) ?: return@mapNotNull null
            KnownPerson(id, clean(normalized(text(o, "email"))), fp, hash, flag(o, "verified"))
        }.sortedBy { it.email.lowercase() }
    }

    /**
     * Key pins (JSON) with [userId]'s pin marked verified (after the user compared the fingerprint of
     * [identityHash]); null when that identity isn't (or no longer) the one pinned.
     */
    fun markVerified(pins: String?, userId: String, identityHash: String): String? {
        val o = pins?.let(::obj) ?: return null
        val list = o["pins"] as? JsonArray ?: return null
        val pin = list.firstOrNull { text(it as? JsonObject, "user_id") == userId } as? JsonObject ?: return null
        if (text(pin, "identity") != identityHash) return null
        val updated = JsonArray(list.map { p -> if (p === pin) JsonObject(pin + ("verified" to JsonPrimitive(true))) else p })
        return JsonObject(o + ("pins" to updated)).toString()
    }

    internal fun pinState(s: String): PinState = when (s) {
        "match" -> PinState.Match
        "upgraded" -> PinState.Upgraded
        "changed" -> PinState.Changed
        "email_conflict" -> PinState.EmailConflict
        else -> PinState.New
    }

    /** An email as the key pins compare it (trimmed, NFKC, lower case, IDNA ASCII domain): how pinned emails are shown. */
    fun normalized(email: String?): String = email?.takeIf { it.isNotBlank() }?.let { runCatching { normalizeEmail(it) }.getOrDefault(it) }.orEmpty()

    internal fun sameEmail(a: String?, b: String?): Boolean = normalized(a) == normalized(b)

    /** [pinned] and the server's [listed] email as shown: the pinned one first, the listed one only when it differs. */
    internal fun emails(pinned: String?, listed: String?): Pair<String, String?> {
        val p = pinned?.takeIf { it.isNotBlank() }
        return if (p != null) clean(normalized(p)) to (listed?.takeIf { it.isNotBlank() && !sameEmail(it, p) }?.let { clean(normalized(it)) })
        else clean(normalized(listed)) to null
    }

    /** A `roster_review` answer (JSON) as the app shows it. */
    fun parseReview(json: String, vaultName: String): MemberReview {
        val o = obj(json) ?: throw CoreException.Invalid("review")
        val members = (o["members"] as? JsonArray).orEmpty().map { m ->
            val r = m as? JsonObject ?: throw CoreException.Invalid("review")
            val (email, listed) = emails(text(r, "pinned_email"), text(r, "listed_email"))
            ReviewPerson(
                text(r, "user_id").orEmpty(),
                text(r, "role").orEmpty(),
                email.ifEmpty { someone(text(r, "user_id").orEmpty()) },
                listed,
                text(r, "fingerprint").orEmpty(),
                pinState(text(r, "pin").orEmpty()),
                flag(r, "verified"),
                flag(r, "is_self"),
                text(r, "change").orEmpty(),
                clean(normalized(text(r, "pinned_email")?.takeIf { it.isNotBlank() } ?: text(r, "listed_email"))),
            )
        }
        val missing = (o["missing"] as? JsonArray).orEmpty().map { m ->
            val r = m as? JsonObject ?: throw CoreException.Invalid("review")
            val id = text(r, "user_id").orEmpty()
            MissingPerson(id, text(r, "role").orEmpty(), clean(normalized(text(r, "pinned_email"))).ifEmpty { someone(id) })
        }
        return MemberReview(
            text(o, "vault_id").orEmpty(),
            vaultName,
            number(o, "version") ?: 0,
            flag(o, "first"),
            members,
            missing,
            // A blocked review has no usable digest (nothing may be signed from it).
            text(o, "digest") ?: if (flag(o, "blocked")) "" else throw CoreException.Invalid("review"),
            flag(o, "blocked"),
        )
    }
}

/**
 * The rules a key replacement follows before it re-encrypts anything (pure, unit-tested): it works
 * only from the state the sync in the same call verified (review Android H2), and a vault with any
 * signed history is replaced only signed (L1).
 */
object RotationRules {
    enum class Base { Ok, Retry }

    /**
     * Whether the key replacement must be signed: a roster this phone trusts ([trusted], remembered
     * even when the server now lists none), a roster the server lists, or other members.
     */
    fun mustSign(trusted: String?, rosterSeq: Long, latestRoster: String?, alone: Boolean): Boolean =
        trusted != null || rosterSeq > 0 || latestRoster != null || !alone

    /**
     * [verified]: the vault header this sync checked; [membersEpoch]: the members answer's `key_epoch`;
     * [fresh]: the vault header of the `/sync` the items are read from. With [signed]: the server's
     * roster ([rosterSeq], [latestRoster]) must be the trusted one ([trusted]). Anything else: sync
     * and check again ([Base.Retry]), never re-encrypt from it.
     */
    fun checkBase(verified: SyncVault, membersEpoch: Long?, fresh: SyncVault?, signed: Boolean, trusted: String?, rosterSeq: Long, latestRoster: String?): Base {
        if (membersEpoch != verified.keyEpoch) return Base.Retry
        if (fresh == null || !fresh.sameKey(verified)) return Base.Retry
        if (signed) {
            if (verified.keyEpoch == null) return Base.Retry
            val trustedVersion = trusted?.let { SignedSharing.rosterVersion(it) } ?: 0
            if (rosterSeq != trustedVersion || latestRoster != trusted) return Base.Retry
            if (trusted != null && SignedSharing.rosterEpoch(trusted) != verified.keyEpoch) return Base.Retry
        }
        return Base.Ok
    }
}

/** What checking one vault said. */
sealed interface VaultCheck {
    data class Ok(val trust: VaultTrust) : VaultCheck

    /** Never accepted by this account: held until the user accepts or declines it. */
    data class Consent(val vault: ConsentVault) : VaultCheck

    data class Refused(val reason: String) : VaultCheck
}

/** A key replacement's plan after the checks ([SharingSession.planRotation]). */
sealed interface RotationPlan {
    /** Go ahead: sign the next roster after [trusted] with [digest]; [newPins]: members to pin (identity JSON, email). */
    data class Ready(val trusted: String?, val digest: String, val newPins: List<Pair<String, String>>) : RotationPlan

    /** Show [review] and replace the key only after the user confirms it. */
    data class NeedsReview(val review: MemberReview) : RotationPlan
}

/**
 * Signed sharing of one unlocked account (one per session; [close] frees its signing key). Not
 * thread-safe: the repository calls it under its lock.
 */
class SharingSession(
    private val account: Account,
    private val api: SharingApi,
    private val memory: SigningMemoryStore,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) : AutoCloseable {
    /** "Me": the account id the core authenticated (the unlocked account's own), never the server's word. */
    val me: String = SignedSharing.text(SignedSharing.obj(account.legacyIdentityJson()), "user_id")
        ?: throw CoreException.Invalid("account id")

    private var identity: SigningIdentity? = null

    /** The `user.identity` text the identity was opened from (another one opens it again). */
    private var record: String? = null
    private var triedCreate = false

    /**
     * This unlock created the account's signing identity (`user.identity` was null and the upload
     * answered `created: true`, or the identity listed later is one this phone made and uploaded,
     * when that answer was lost): the only time vaults are grandfathered.
     */
    private var createdHere = false

    /** The server answered `identity_exists`: nothing is grandfathered at this sync (unless the listed identity is one made here). */
    private var skipGrandfather = false

    /**
     * The account has a signing identity but this phone found no key pins for it (the account's trust
     * memory is missing): nothing is grandfathered, every shared vault needs the user's consent.
     */
    var memoryMissing = false
        private set

    /** The key pins were empty when this session first loaded them (before its own identity was written). */
    private var noPinsFound = false

    /**
     * The server has newer key pins than this phone but they couldn't be fetched (re-review L): like
     * offline, nothing is written or grandfathered, and a shared vault the phone's own pins don't
     * admit isn't used ([SignedSharing.UNCHECKED]) until they can be read.
     */
    var pinsUnreachable = false
        private set

    /**
     * The identity record this session uploaded (`created: true`), so the copy stored with this
     * sync's `user.identity: null` can carry it: an offline unlock later then opens it instead of
     * pausing (extension re-review L3).
     */
    var uploadedRecord: String? = null
        private set

    /** The server lists keys that aren't this account's: nothing is signed, every shared vault refused. */
    var paused = false
        private set

    /** The key pins (JSON; null: none yet). */
    var pins: String? = null
        private set
    private var pinsSeq = 0L
    private var pinsLoaded = false

    /** Set while the server's key pins can't be used (rollback, unreadable): nothing is written. */
    var pinsProblem: String? = null
        private set
    private var dirty = false

    /** Identities that differ from their pins, by user id: kept until the user trusts the new key (never cleared by a sync). */
    private val changes = linkedMapOf<String, IdentityChange>()

    /** Roster chains fetched for invitations, by invitation content (fetched once). */
    private val invitationRosters = mutableMapOf<String, String>()

    /** What accepting a vault held for consent writes, by vault id (from the last check), and the vault as shown ([shown]). */
    private class ConsentPlan(val signer: Signer?, val roster: String?, val rosterVersion: Long?, val epochPin: String, val replaced: Boolean, val shown: ConsentVault)

    private val consentPlans = mutableMapOf<String, ConsentPlan>()

    /** The last check of each invitation, by vault id: accepting needs exactly the one shown. */
    private val invitationPlans = mutableMapOf<String, InvitationTrust>()

    /** This account's identity for checks: its signing identity, or its legacy one before it has one (or while paused). */
    val myIdentityJson: String get() = identity?.takeIf { !paused }?.publicIdentityJson() ?: account.legacyIdentityJson()

    /** The account's own identity fingerprint (computed here); null before it has a signing identity. */
    val fingerprint: String? get() = identity?.takeIf { !paused }?.fingerprint()

    /** Shares and rosters can be signed on this phone. */
    val canSign: Boolean get() = identity != null && !paused

    val changed: List<IdentityChange> get() = changes.values.toList()

    override fun close() {
        identity?.destroy()
        identity = null
    }

    // ------------------------------------------------------------ identity and pins

    /**
     * Step 0, at every sync answer: the account named must be this one; the key pins brought up to
     * date ([online]: `user.key_pins_seq` says they changed); the signing identity opened (or, online
     * and none yet, made and uploaded) and checked against the one this account remembers.
     */
    suspend fun refresh(user: JsonElement?, online: Boolean) {
        val u = user as? JsonObject
        SignedSharing.text(u, "id")?.let { if (it != me) throw WrongAccountException() }
        loadPins(SignedSharing.number(u, "key_pins_seq"), online)
        // A failed fetch isn't "none on the server" (re-review L: a fresh phone offline isn't trust memory missing).
        if (pinsLoaded && pinsProblem == null && !pinsUnreachable && pins == null) noPinsFound = true
        val rec = u?.get("identity")
        when {
            rec == null || rec is JsonNull -> {
                if (identity != null && record == null) {
                    // Made on this phone this session; the sync answer was read before the upload.
                    checkOwn()
                } else if (remembersOwn()) {
                    // This account had an identity: the server listing none is a rollback.
                    pause()
                } else if (identity == null && online && !triedCreate) {
                    createIdentity()
                }
            }
            rec !is JsonObject -> pause()
            rec.toString() != record || paused -> open(rec.toString())
        }
    }

    private suspend fun remembersOwn(): Boolean = SignedSharing.ownIdentityOf(pins) != null || memory.read().ownIdentity != null

    private fun pause() {
        identity?.destroy()
        identity = null
        paused = true
    }

    private suspend fun createIdentity() {
        triedCreate = true
        try {
            val made = account.newSigningIdentity()
            var kept = false
            try {
                // Remembered before the upload: a lost answer still counts as made here once it is listed.
                val hash = made.identity.identityHash()
                memory.write { it.merge(SigningMemory(generated = listOf(hash))) }
                val created = api.putIdentity(made.recordJson)
                identity?.destroy()
                identity = made.identity
                kept = true
                record = null
                paused = false
                createdHere = created
                uploadedRecord = made.recordJson
                checkOwn()
            } catch (e: ApiException) {
                if (!kept) made.identity.destroy()
                if (e.status == 409 && e.hasCode("identity_exists")) {
                    skipGrandfather = true
                    when (val cur = api.currentIdentity()) {
                        is JsonObject -> open(cur.toString())
                        else -> pause()
                    }
                } else if (e.status >= 500) {
                    // The server failed: tried again at the next sync (nothing is grandfathered meanwhile).
                    triedCreate = false
                }
            } catch (e: Throwable) {
                if (!kept) made.identity.destroy()
                throw e
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: CoreException) {
            pause()
        } catch (_: Exception) {
            // Not reached (or the answer was lost): tried again at the next sync.
            triedCreate = false
        }
    }

    private suspend fun open(text: String) {
        identity?.destroy()
        identity = null
        record = text
        try {
            identity = account.openSigningIdentity(text)
            paused = false
        } catch (_: CoreException) {
            // identity_mismatch, decrypt_failed or malformed: never sign or verify with it.
            pause()
            return
        }
        // One this phone made and uploaded (its answer lost): made here. The server can't forge a record
        // that opens under the account key to that hash.
        val hash = identity?.identityHash()
        if (hash != null && hash in memory.read().generated) {
            createdHere = true
            skipGrandfather = false
        }
        checkOwn()
    }

    /** The opened identity against the one this account remembers (key pins and this phone): another one pauses sharing. */
    private suspend fun checkOwn() {
        val hash = identity?.identityHash() ?: return
        val remembered = memory.read().ownIdentity
        val status = try {
            pinsCheckOwnIdentity(pins, hash)
        } catch (_: CoreException) {
            "mismatch"
        }
        if (status == "mismatch" || (remembered != null && remembered != hash)) return pause()
        if (status == "new") {
            pins = pinsSetOwnIdentity(pins, hash)
            dirty = true
        }
        if (remembered == null) memory.write { it.merge(SigningMemory(ownIdentity = hash)) }
    }

    private fun openLocal(m: SigningMemory): String? = m.pinsSealed?.let { runCatching { account.openKeyPins(it, m.pinsSeq.toULong()) }.getOrNull() }

    /** Pins this phone changed and couldn't write yet win over [base] (the core's merge). */
    private fun withOurs(base: String?): String? {
        val ours = pins
        if (!dirty || ours == null) return base
        if (base == null) return ours
        return runCatching { mergePins(base, ours) }.getOrDefault(ours)
    }

    private fun useLocal(m: SigningMemory) {
        if (pinsLoaded) return
        pins = withOurs(openLocal(m))
        pinsSeq = m.pinsSeq
        pinsLoaded = true
    }

    private suspend fun loadPins(serverSeq: Long?, online: Boolean) {
        val m = memory.read()
        if (!online || serverSeq == null) return useLocal(m)
        if (pinsLoaded && serverSeq == pinsSeq && pinsProblem == null) {
            pinsUnreachable = false
            return
        }
        if (serverSeq < m.pinsSeq) return rollback(m, SignedSharing.PINS_ROLLED_BACK)
        if (serverSeq == 0L) {
            pinsUnreachable = false
            pins = withOurs(null)
            pinsSeq = 0
            pinsLoaded = true
            pinsProblem = null
            return
        }
        val (sealed, seq) = try {
            api.getKeyPins()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            // Treated as offline: this phone's copy, nothing written or grandfathered, tried again next sync
            // (when this phone's copy is as new as the server says, it is simply used).
            pinsUnreachable = serverSeq > m.pinsSeq
            return useLocal(m)
        }
        pinsUnreachable = false
        if (seq < m.pinsSeq) return rollback(m, SignedSharing.PINS_ROLLED_BACK)
        if (sealed == null) {
            // A version without pins is unreadable; none at all (version 0) is the server having none.
            if (seq > 0) return rollback(m, SignedSharing.PINS_UNREADABLE)
            pins = withOurs(null)
            pinsSeq = 0
            pinsLoaded = true
            pinsProblem = null
            return
        }
        val opened = try {
            account.openKeyPins(sealed, seq.toULong())
        } catch (_: CoreException) {
            return rollback(m, SignedSharing.PINS_UNREADABLE)
        }
        pins = withOurs(opened)
        pinsSeq = seq
        pinsLoaded = true
        pinsProblem = null
        memory.write { it.merge(SigningMemory(pinsSeq = seq, pinsSealed = sealed)) }
    }

    private fun rollback(m: SigningMemory, why: String) {
        pins = withOurs(openLocal(m))
        pinsSeq = m.pinsSeq
        pinsLoaded = true
        pinsProblem = why
    }

    /**
     * Write the key pins when this phone changed them (compare-and-swap; on 409 `key_pins_changed`
     * read, merge and write again once). Nothing is written while the server's copy can't be used.
     */
    suspend fun savePins() {
        if (!dirty || pinsProblem != null || pinsUnreachable) return
        for (attempt in 0..1) {
            val p = pins ?: return
            val next = pinsSeq + 1
            val sealed = account.sealKeyPins(p, next.toULong())
            try {
                api.putKeyPins(sealed, next)
                pinsSeq = next
                dirty = false
                memory.write { it.merge(SigningMemory(pinsSeq = next, pinsSealed = sealed)) }
                return
            } catch (e: ApiException) {
                if (attempt > 0 || e.status != 409 || !e.hasCode("key_pins_changed")) throw e
                val (s, seq) = api.getKeyPins()
                val m = memory.read()
                if (s == null || seq < m.pinsSeq) return rollback(m, SignedSharing.PINS_ROLLED_BACK)
                val theirs = try {
                    account.openKeyPins(s, seq.toULong())
                } catch (_: CoreException) {
                    return rollback(m, SignedSharing.PINS_UNREADABLE)
                }
                memory.write { it.merge(SigningMemory(pinsSeq = seq, pinsSealed = s)) }
                pins = mergePins(theirs, p)
                pinsSeq = seq
            }
        }
    }

    private fun pin(identityJson: String, email: String, verified: Boolean) {
        pins = pinSet(pins, identityJson, email, verified, now())
        dirty = true
    }

    private fun setEpoch(vaultId: String, current: String, rosterVersion: Long?) {
        val next = pinsSetEpoch(pins, vaultId, current, rosterVersion?.toULong())
        if (next != pins) {
            pins = next
            dirty = true
        }
    }

    /**
     * At the account's first signed sync, only when this unlock created its signing identity ([online],
     * key pins usable, sharing not paused): [vaultIds] (the unsigned shared vaults it has now) that
     * were already in this phone's own offline copy from an earlier session ([earlier]; none on a fresh
     * install or a re-added account) stay usable without a consent ("Not yet signed"). Once per
     * account, and only once the identity state is known (made here, or the listed one opened): after
     * a failed or unanswered upload nothing is written and it is tried again at the next sync
     * (ARCHITECTURE "Grandfathering", rules 1 and 2). An account that already had an identity but no
     * key pins gets [memoryMissing] instead.
     */
    fun grandfather(vaultIds: List<String>, earlier: Set<String>, online: Boolean) {
        if (!online || paused || pinsProblem != null || pinsUnreachable || !pinsLoaded) return
        if (identity == null) return
        if (skipGrandfather) {
            skipGrandfather = false
            return
        }
        memoryMissing = !createdHere && noPinsFound
        if (!SignedSharing.needsGrandfathering(pins)) return
        // Only the unlock that created the identity writes the ids; otherwise an empty list.
        pins = pinsGrandfather(pins, if (createdHere) vaultIds.filter { it in earlier } else emptyList(), createdHere)
        dirty = true
    }

    /**
     * Accepted vaults (in the key pins' `epochs`) that were shared ([sharedBefore]: sealed rows of the
     * copy shown before) and that a verified sync ([current]: its vault ids) no longer lists get a
     * tombstone at the remembered roster version, so the server can't bring back the old copy later
     * (re-review L). Only online with usable pins.
     */
    suspend fun tombstoneRemoved(current: Set<String>, sharedBefore: Set<String>, online: Boolean) {
        if (!online || paused || pinsProblem != null || pinsUnreachable || !pinsLoaded) return
        val accepted = (pins?.let(SignedSharing::obj)?.get("epochs") as? JsonObject)?.keys ?: return
        for (vid in accepted.toList()) if (vid !in current && vid in sharedBefore) leave(vid)
    }

    /** Whether an `account` wrap of the vault may be a v1 wrap (the core's rule). */
    fun legacyAllowed(vaultId: String): Boolean = runCatching { pinsLegacyWrapAllowed(pins, vaultId) }.getOrDefault(false)

    /** The member roster this phone trusts for the vault (remembered only after a sync's checks passed). */
    suspend fun rememberedRoster(vaultId: String): String? = memory.read().rosters[vaultId]

    /**
     * Whether the vault was ever shared under a signed roster with someone else (emergency access
     * counts it as not personal): a trusted roster listing others, a signed epoch pin, or seen signed here.
     */
    suspend fun sharedBefore(vaultId: String): Boolean {
        val m = memory.read()
        val roster = m.rosters[vaultId]
        if (roster != null && SignedSharing.rosterMembers(roster).any { it != me }) return true
        if (vaultId in m.signed) return true
        val epoch = SignedSharing.epochOf(pins, vaultId)
        return epoch != null && epoch["signed_since"].let { it != null && it !is JsonNull }
    }

    /** "Mark as verified" after comparing [userId]'s fingerprint of [identityHash] out of band. */
    fun markVerified(userId: String, identityHash: String): Boolean {
        val next = SignedSharing.markVerified(pins, userId, identityHash) ?: return false
        pins = next
        dirty = true
        return true
    }

    /** "Trust the new key" of [userId] ([identityHash]: the one shown; [compared]: the user compared the fingerprint with them). */
    fun trustNewKey(shown: IdentityChange, compared: Boolean): Boolean {
        val userId = shown.userId
        // Exactly the change the sheet showed (identity and the email it pins), else compare again.
        val c = changes[userId]?.takeIf { it == shown } ?: return false
        // A second account with a known email: only after the user compared the fingerprint (Info).
        if (c.conflict && !compared) throw UserException(SignedSharing.COMPARE_FIRST)
        pin(c.identityJson, SignedSharing.normalized(c.pinEmail), compared)
        changes.remove(userId)
        invitationRosters.clear()
        return true
    }

    // ------------------------------------------------------------- checking

    /** The signer of a share: checked, compared with the pins; null (and a change noted) when it can't be trusted. */
    private class Signer(val userId: String, val view: SignerView, val json: String, val pinEmail: String, val hash: String)

    private fun signer(o: JsonObject): Signer? {
        val json = o.toString()
        val info = try {
            SignedSharing.obj(verifyIdentity(json)) ?: return null
        } catch (_: CoreException) {
            return null
        }
        val uid = SignedSharing.text(info, "user_id") ?: return null
        val fp = SignedSharing.text(info, "fingerprint") ?: return null
        val hash = SignedSharing.text(info, "hash") ?: return null
        val listed = SignedSharing.text(o, "email").orEmpty()
        if (uid == me) {
            // Signed by this account itself (a re-signed vault): only with its own identity.
            val mine = identity?.takeIf { !paused }?.identityHash() ?: return null
            return if (hash == mine) Signer(uid, SignerView("you", null, fp, PinState.Match, true), json, listed, hash) else null
        }
        val state = try {
            SignedSharing.pinState(pinCheck(pins, json, listed.ifEmpty { null }))
        } catch (_: CoreException) {
            return null
        }
        val pinned = SignedSharing.pinOf(pins, uid)
        val pinnedEmail = SignedSharing.text(pinned, "email").takeIf { state != PinState.New && state != PinState.EmailConflict }
        val (email, listedShown) = SignedSharing.emails(pinnedEmail, listed)
        if (state == PinState.Changed || state == PinState.EmailConflict) {
            changes[uid] = IdentityChange(uid, email.ifEmpty { SignedSharing.someone(uid) }, listedShown, fp, hash, json, state == PinState.EmailConflict, listed)
            return null
        }
        val verified = state == PinState.Match && SignedSharing.flag(pinned, "verified")
        return Signer(uid, SignerView(email.ifEmpty { SignedSharing.someone(uid) }, listedShown, fp, state, verified), json, listed, hash)
    }

    /**
     * The newest roster of [vaultId] after [after] (`GET …/rosters` page by page, at most 1000 versions
     * and 16 MiB of roster text per sync and vault), checked as a chain from [trusted] ending exactly
     * at [latest].
     */
    private suspend fun fetchChain(vaultId: String, trusted: String?, after: Long, latest: String): String {
        val newer = mutableListOf<String>()
        var bytes = 0L
        var from = after
        repeat(MAX_ROSTER_PAGES) {
            val (page, more) = try {
                api.rosters(vaultId, from)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: ApiException) {
                throw e
            } catch (_: Exception) {
                throw SharingOffline()
            }
            newer += page
            bytes += page.sumOf { it.length.toLong() }
            if (newer.size > MAX_ROSTER_VERSIONS || bytes > MAX_ROSTER_BYTES) throw CoreException.TooLarge("too_large")
            if (!more || page.isEmpty()) return verifyRosterChain(vaultId, trusted, newer, latest)
            from = SignedSharing.rosterVersion(page.last()) ?: throw CoreException.Invalid("roster version")
        }
        throw CoreException.TooLarge("too_large")
    }

    /**
     * The roster to trust for [vaultId] whose server-listed latest is [latest]: none (not signed), the
     * one remembered ([remembered]), or the newer ones checked as a chain from it. Nothing is
     * remembered here. Throws [CoreException] for a rollback, fork or a chain that doesn't verify,
     * [SharingOffline] when newer ones couldn't be fetched ([online] false: never asked).
     */
    private suspend fun trustedRoster(vaultId: String, remembered: String?, latest: String?, online: Boolean): String? {
        val head = SignedSharing.obj(rosterHead(vaultId, remembered, latest)) ?: throw CoreException.Invalid("roster head")
        return when (SignedSharing.text(head, "status")) {
            "unsigned" -> null
            "same" -> remembered
            "fetch" -> {
                if (!online) throw SharingOffline()
                fetchChain(vaultId, remembered, SignedSharing.number(head, "after") ?: 0, latest ?: throw CoreException.Invalid("roster"))
            }
            else -> throw CoreException.Invalid("roster head")
        }
    }

    private fun refusedFor(e: CoreException): String = if (e is CoreException.TooLarge) SignedSharing.TOO_MANY_CHANGES else SignedSharing.REFUSED

    /** Starts a sync's checks: consents are found again. */
    fun beginChecks() {
        consentPlans.clear()
        invitationPlans.clear()
    }

    /**
     * Step 1: check one vault row of a sync (before anything of it is used). [open] opens its key
     * (`legacyAllowed` for account wraps); [nameOf] reads its (cleaned) name, only for a vault held
     * for consent or refused. Pins and memory change only for a vault that passes every check.
     */
    suspend fun checkVault(v: SyncVault, open: (legacyAllowed: Boolean) -> VaultKey, nameOf: () -> String, online: Boolean): VaultCheck {
        val sealed = v.keyKind == "sealed"
        fun refused(reason: String) = VaultCheck.Refused(reason)
        // Paused: every shared vault is refused, before anything of it is opened (account vaults keep their epoch checks).
        if (paused && sealed) return refused(SignedSharing.PAUSED)
        val epoch = v.keyEpoch ?: return refused(SignedSharing.refusedReason("missing_epoch"))
        val key = try {
            open(legacyAllowed(v.id))
        } catch (_: CoreException) {
            return refused(SignedSharing.REFUSED)
        }
        try {
            val remembered = memory.read().rosters[v.id]
            val roster = try {
                trustedRoster(v.id, remembered, v.memberRoster, online)
            } catch (_: SharingOffline) {
                return refused(SignedSharing.UNCHECKED)
            } catch (_: ApiException) {
                return refused(SignedSharing.UNCHECKED)
            } catch (e: CoreException) {
                return refused(refusedFor(e))
            }
            val rosterVersion = roster?.let { SignedSharing.rosterVersion(it) ?: return refused(SignedSharing.REFUSED) }
            if (roster != null) {
                if (SignedSharing.rosterEpoch(roster) != epoch || !key.matchesRoster(v.id, roster)) return refused(SignedSharing.REFUSED)
                // My role is the trusted roster's (a paused account's own vaults keep only the key checks).
                if (!paused && rosterMemberRole(roster, myIdentityJson) != v.role) return refused(SignedSharing.REFUSED)
            }
            var signer: Signer? = null
            if (sealed) {
                val share = v.share as? JsonObject
                if (share != null) {
                    val o = share["signer"] as? JsonObject ?: return refused(SignedSharing.REFUSED)
                    val signature = SignedSharing.text(share, "signature") ?: return refused(SignedSharing.REFUSED)
                    val s = signer(o) ?: return refused(
                        changes[SignedSharing.text(o, "user_id")]?.let { it.text + " " + SignedSharing.REFUSED } ?: SignedSharing.REFUSED,
                    )
                    verifyShare(v.id, myIdentityJson, v.role, epoch.toULong(), v.wrappedKey, s.json, signature)
                    if (roster != null && rosterSignerRole(roster, s.json) !in MANAGERS) return refused(SignedSharing.REFUSED)
                    signer = s
                }
            }
            val current = key.epochPinJson(v.id, epoch.toULong())
            val observation = buildJsonObject {
                put("vault_id", v.id)
                put("key_kind", if (sealed) "sealed" else "account")
                put("key", AppJson.parseToJsonElement(current))
                if (rosterVersion != null) put("roster_version", rosterVersion) else put("roster_version", JsonNull)
                if (roster != null) put("roster_hash", rosterHash(roster)) else put("roster_hash", JsonNull)
                put("signed_share", signer != null)
                put("paused", paused)
            }
            // The core's admission, with what it says to pin (`pin`: key, signed history, roster version and hash) applied.
            val observed = SignedSharing.obj(pinsObserve(pins, observation.toString())) ?: return refused(SignedSharing.REFUSED)
            val admission = observed["admission"] as? JsonObject ?: return refused(SignedSharing.REFUSED)
            val deleted = SignedSharing.flag(v.share as? JsonObject, "signer_deleted")
            val status = SignedSharing.text(admission, "status")
            // Newer key pins couldn't be read: only what this phone's own pins admit is used.
            if (pinsUnreachable && status != "ok") return refused(SignedSharing.UNCHECKED)
            return when (status) {
                "ok" -> {
                    // Every check of the row passed: only now its pins and the roster are remembered.
                    signer?.let { s -> if (s.userId != me && (s.view.pin == PinState.New || s.view.pin == PinState.Upgraded)) pin(s.json, s.pinEmail, false) }
                    if (SignedSharing.flag(observed, "changed")) {
                        // Applied to the pins as they are now (with the signer pinned just now).
                        pins = (SignedSharing.obj(pinsObserve(pins, observation.toString()))?.get("pins") as? JsonObject)?.toString() ?: return refused(SignedSharing.REFUSED)
                        dirty = true
                    }
                    if (roster != null) remember(v.id, roster)
                    VaultCheck.Ok(
                        when (SignedSharing.text(admission, "trust")) {
                            "own" -> VaultTrust.Own
                            "signed" -> signer?.let { VaultTrust.Signed(it.view, deleted) } ?: VaultTrust.Own
                            else -> VaultTrust.NotYetSigned
                        },
                    )
                }
                "consent" -> {
                    val replaced = SignedSharing.flag(admission, "replaced")
                    val rejoin = SignedSharing.flag(admission, "rejoin")
                    val unsignedAllowed = memoryMissing && signer == null
                    val token = SignedSharing.token(
                        v.id, v.role, rejoin, replaced, unsignedAllowed, deleted,
                        signer?.userId, signer?.hash, signer?.json, current, rosterVersion, roster?.let { rosterHash(it) },
                    )
                    val shown = ConsentVault(v.id, nameOf(), v.role, rejoin, signer?.view, deleted, replaced, unsignedAllowed, token)
                    consentPlans[v.id] = ConsentPlan(signer, roster, rosterVersion, current, replaced, shown)
                    VaultCheck.Consent(shown)
                }
                else -> refused(SignedSharing.refusedReason(SignedSharing.text(admission, "reason").orEmpty()))
            }
        } catch (e: CoreException) {
            return refused(refusedFor(e))
        } catch (_: IllegalArgumentException) {
            return refused(SignedSharing.REFUSED)
        } finally {
            key.destroy()
        }
    }

    private suspend fun remember(vaultId: String, roster: String) {
        memory.write { it.merge(SigningMemory(rosters = mapOf(vaultId to roster), signed = setOf(vaultId))) }
    }

    /**
     * [block]'s changes to the key pins, written to the server before anything else happens (the
     * server is told, the roster remembered); when they can't be written the pins are as before and
     * [SignedSharing.PINS_NOT_SAVED] (or the server's error) is thrown (re-review L).
     */
    private suspend fun committing(block: () -> Unit) {
        val before = Triple(pins, pinsSeq, dirty)
        try {
            block()
            savePins()
            if (dirty) throw UserException(SignedSharing.PINS_NOT_SAVED)
        } catch (e: Throwable) {
            pins = before.first
            pinsSeq = before.second
            dirty = before.third
            if (e is kotlinx.coroutines.CancellationException || e is UserException || e is ApiException) throw e
            throw UserException(SignedSharing.PINS_NOT_SAVED)
        }
    }

    /**
     * Accept a vault held for consent exactly as [shown] (the vault, its key and signer as the last
     * check showed them; anything else is [SignedSharing.CHANGED_JUST_NOW]): the key pinned (the
     * tombstone cleared) and the signer pinned, written to the server first, then the roster remembered.
     */
    suspend fun acceptConsent(shown: ConsentVault) {
        val vaultId = shown.vaultId
        val p = consentPlans[vaultId]?.takeIf { it.shown == shown } ?: throw UserException(SignedSharing.CHANGED_JUST_NOW)
        if (paused) throw UserException(SignedSharing.PAUSED)
        val s = p.signer
        // Unsigned: only a key replaced by an app from before signing, or while the trust memory is missing.
        if (s == null && !p.replaced && !memoryMissing) throw UserException(SignedSharing.CONSENT_UNSIGNED)
        committing {
            if (s != null && s.userId != me && (s.view.pin == PinState.New || s.view.pin == PinState.Upgraded)) pin(s.json, s.pinEmail, false)
            setEpoch(vaultId, p.epochPin, if (s == null) null else p.rosterVersion)
        }
        if (s != null) p.roster?.let { remember(vaultId, it) }
        consentPlans.remove(vaultId)
    }

    /** Decline a vault held for consent: a tombstone at the roster version its check verified (or the remembered one). */
    suspend fun declineConsent(vaultId: String) {
        // While the trust memory is missing a server could otherwise push the user out of real vaults: Accept or later only.
        if (memoryMissing) throw UserException(SignedSharing.NO_DECLINE_NOW)
        leave(vaultId, consentPlans[vaultId]?.rosterVersion)
    }

    /**
     * Leaving, declining or a vault held for consent declined: a tombstone, so it never comes back
     * unless shared again; at the higher of the remembered roster version and [rosterVersion] (the
     * version a check of the declined invitation or consent verified).
     */
    suspend fun leave(vaultId: String, rosterVersion: Long? = null) {
        val remembered = memory.read().rosters[vaultId]?.let { SignedSharing.rosterVersion(it) } ?: 0
        val version = maxOf(remembered, rosterVersion ?: 0)
        pins = pinsLeave(pins, vaultId, version.toULong(), now())
        dirty = true
        consentPlans.remove(vaultId)
        invitationPlans.remove(vaultId)
    }

    /**
     * Step 3: check an invitation before it can be accepted: unsigned ones never; a signed one's
     * signer, share, roster chain (from the remembered roster, else version 1), the roles it gives,
     * its key and the admission. Nothing is pinned or remembered before the user accepts.
     */
    suspend fun checkInvitation(inv: SyncInvitation, open: (SyncInvitation) -> VaultKey?, online: Boolean): InvitationTrust =
        invitationTrust(inv, open, online).also { invitationPlans[inv.vaultId] = it }

    private suspend fun invitationTrust(inv: SyncInvitation, open: (SyncInvitation) -> VaultKey?, online: Boolean): InvitationTrust {
        if (paused) return InvitationTrust.Refused(SignedSharing.PAUSED)
        val share = inv.share as? JsonObject ?: return InvitationTrust.Unsigned
        val refused = InvitationTrust.Refused(SignedSharing.REFUSED)
        val o = share["signer"] as? JsonObject ?: return refused
        val signature = SignedSharing.text(share, "signature") ?: return refused
        val s = signer(o) ?: return InvitationTrust.Refused(changes[SignedSharing.text(o, "user_id")]?.text ?: SignedSharing.REFUSED)
        val epoch = inv.keyEpoch ?: return refused
        val latest = inv.memberRoster ?: return refused
        val cacheKey = Invitations.cacheKey(inv) + "\n" + share + "\n" + latest + "\n" + epoch
        return try {
            verifyShare(inv.vaultId, myIdentityJson, inv.role, epoch.toULong(), inv.wrappedKey, s.json, signature)
            val top = invitationRosters[cacheKey] ?: run {
                val remembered = memory.read().rosters[inv.vaultId]
                trustedRoster(inv.vaultId, remembered, latest, online) ?: return refused
            }
            if (top != latest || SignedSharing.rosterEpoch(top) != epoch) return refused
            invitationRosters[cacheKey] = top
            val version = SignedSharing.rosterVersion(top) ?: return refused
            if (rosterSignerRole(top, s.json) !in MANAGERS) return refused
            if (rosterMemberRole(top, myIdentityJson) != inv.role) return refused
            val key = open(inv) ?: return refused
            val current = try {
                if (!key.matchesRoster(inv.vaultId, top)) return refused
                key.epochPinJson(inv.vaultId, epoch.toULong())
            } finally {
                key.destroy()
            }
            val observation = buildJsonObject {
                put("vault_id", inv.vaultId)
                put("key_kind", "sealed")
                put("key", AppJson.parseToJsonElement(current))
                put("roster_version", version)
                put("roster_hash", rosterHash(top))
                put("signed_share", true)
                put("paused", false)
            }
            val admission = SignedSharing.obj(pinsAdmit(pins, observation.toString())) ?: return refused
            if (SignedSharing.text(admission, "status") == "refused") {
                return InvitationTrust.Refused(SignedSharing.refusedReason(SignedSharing.text(admission, "reason").orEmpty()))
            }
            InvitationTrust.Signed(s.view, s.json, s.pinEmail, top, version, current)
        } catch (_: SharingOffline) {
            InvitationTrust.Refused(SignedSharing.UNCHECKED)
        } catch (_: ApiException) {
            InvitationTrust.Refused(SignedSharing.UNCHECKED)
        } catch (e: CoreException) {
            InvitationTrust.Refused(refusedFor(e))
        } catch (_: IllegalArgumentException) {
            refused
        }
    }

    /**
     * Accepting a checked invitation exactly as shown ([t]: the last check of it; anything else is
     * [SignedSharing.CHANGED_JUST_NOW]): the signer pinned and the key epoch accepted (a tombstone
     * cleared), written to the server first; then the roster remembered. The server is told after.
     */
    suspend fun prepareAccept(vaultId: String, t: InvitationTrust.Signed) {
        if (invitationPlans[vaultId] != t) throw UserException(SignedSharing.CHANGED_JUST_NOW)
        if (paused) throw UserException(SignedSharing.PAUSED)
        committing {
            if (t.signer.pin == PinState.New || t.signer.pin == PinState.Upgraded) pin(t.signerJson, t.pinEmail, false)
            setEpoch(vaultId, t.epochPin, t.rosterVersion)
        }
        remember(vaultId, t.roster)
    }

    // ------------------------------------------------------------- key replacement

    /**
     * Step 5, before replacing the key of [vaultId] ([trusted]: the roster this sync verified, or none;
     * [rows]: the `GET …/members` rows that will hold the new key): the core's review of the next
     * roster. Blocked (a key changed, another identity than the trusted roster's, the server lists
     * another identity for me) or a member the trusted roster doesn't have: stop with a
     * [UserException]. Version 1 (no trusted roster) and people the roster lists but the server no
     * longer does need the user's confirmation of exactly this review ([approval]).
     */
    fun planRotation(vaultId: String, vaultName: String, trusted: String?, rows: List<JsonObject>, approval: ReviewApproval?): RotationPlan {
        val id = identity?.takeIf { !paused } ?: throw UserException(if (paused) SignedSharing.PAUSED else SignedSharing.NOT_SIGNED_HERE)
        val json = try {
            rosterReview(vaultId, trusted, id.publicIdentityJson(), JsonArray(rows).toString(), pins)
        } catch (_: CoreException.RosterUnauthorized) {
            throw UserException("Only the vault's owner can make this change to its signed member list.")
        } catch (_: CoreException) {
            throw UserException(SignedSharing.REFUSED)
        }
        val review = SignedSharing.parseReview(json, vaultName)
        if (review.blocked) {
            for (p in review.members) {
                if (p.pin != PinState.Changed && p.pin != PinState.EmailConflict) continue
                val row = rows.firstOrNull { SignedSharing.text(it, "user_id") == p.userId } ?: continue
                val hash = runCatching { SignedSharing.text(SignedSharing.obj(verifyIdentity(row.toString())), "hash") }.getOrNull() ?: continue
                changes[p.userId] = IdentityChange(p.userId, p.email, p.listedEmail, p.fingerprint, hash, row.toString(), p.pin == PinState.EmailConflict, SignedSharing.text(row, "email").orEmpty())
            }
            val changed = review.members.filter { it.pin == PinState.Changed || it.pin == PinState.EmailConflict }
            if (changed.isNotEmpty()) throw UserException(changes[changed[0].userId]?.text ?: SignedSharing.keysChanged(changed[0].email))
            throw UserException(SignedSharing.membersDiffer(review.members.filter { it.change != "same" || it.isSelf }.map { it.email }.ifEmpty { listOf("your own account") }))
        }
        if (!review.first) {
            val bad = review.members.filter { it.change != "same" }
            if (bad.isNotEmpty()) throw UserException(SignedSharing.membersDiffer(bad.map { it.email }))
        }
        if (review.first || review.missing.isNotEmpty()) {
            val ok = approval != null && approval.digest == review.digest && approval.missing.containsAll(review.missing.map { it.userId })
            if (!ok) return RotationPlan.NeedsReview(review)
        }
        // Pinned with the emails the confirmed review showed (the digest covers ids, identities and roles, not emails).
        val newPins = review.members.filter { !it.isSelf && (it.pin == PinState.New || it.pin == PinState.Upgraded) }.mapNotNull { p ->
            rows.firstOrNull { SignedSharing.text(it, "user_id") == p.userId }?.let { it.toString() to (approval?.emails?.get(p.userId) ?: p.pinEmail) }
        }
        return RotationPlan.Ready(trusted, review.digest, newPins)
    }

    /** The share of [newKey] for member [row] at [keyEpoch], sealed and signed. */
    fun sealAndSign(newKey: VaultKey, vaultId: String, row: JsonObject, keyEpoch: Long): io.passauth.core.SignedShare {
        val id = identity?.takeIf { !paused } ?: throw UserException(SignedSharing.PAUSED)
        return id.sealAndSignShare(newKey, vaultId, row.toString(), SignedSharing.text(row, "role").orEmpty(), keyEpoch.toULong())
    }

    /** The roster after [plan]'s trusted one at [keyEpoch] listing [rows] (the reviewed list), signed. */
    fun signRoster(newKey: VaultKey, vaultId: String, plan: RotationPlan.Ready, keyEpoch: Long, rows: List<JsonObject>): String {
        val id = identity?.takeIf { !paused } ?: throw UserException(SignedSharing.PAUSED)
        return try {
            id.signRoster(newKey, vaultId, plan.trusted, keyEpoch.toULong(), JsonArray(rows).toString(), plan.digest)
        } catch (_: CoreException.ReviewMismatch) {
            throw UserException(SignedSharing.CHANGED_JUST_NOW)
        }
    }

    /**
     * After a key replacement the server took: the new key ([epochPin]) is pinned, and with a signed
     * [roster] that roster is what this phone trusts now; reviewed members new to the pins are pinned.
     */
    suspend fun rememberRotation(vaultId: String, roster: String?, epochPin: String, newPins: List<Pair<String, String>>) {
        for ((json, email) in newPins) runCatching { pin(json, email, false) }
        setEpoch(vaultId, epochPin, roster?.let { SignedSharing.rosterVersion(it) })
        if (roster != null) remember(vaultId, roster)
    }

    companion object {
        private val MANAGERS = setOf("owner", "admin")
        private const val MAX_ROSTER_PAGES = 10
        private const val MAX_ROSTER_VERSIONS = 1000
        private const val MAX_ROSTER_BYTES = 16L * 1024 * 1024
    }
}
