package io.passauth.app.data

import io.passauth.core.Account
import io.passauth.core.CoreException
import io.passauth.core.SigningIdentity
import io.passauth.core.VaultKey
import io.passauth.core.mergePins
import io.passauth.core.pinCheck
import io.passauth.core.pinSet
import io.passauth.core.normalizeEmail
import io.passauth.core.pinsAccept
import io.passauth.core.pinsAdmit
import io.passauth.core.pinsObserve
import io.passauth.core.pinsCheckOwnIdentity
import io.passauth.core.pinsGrandfather
import io.passauth.core.pinsLeave
import io.passauth.core.pinsLegacyWrapAllowed
import io.passauth.core.accountWrapIsBound
import io.passauth.core.pinsDecline
import io.passauth.core.pinsMergeLastKnown
import io.passauth.core.pinsRecordRotation
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
 * lost still counts as made here once the server lists it (cleared once key pins with the own
 * identity and the grandfathered list are stored). Round 4 (cross-client rules 3 and 6):
 * [usable]: the vaults this phone last showed as usable (checked "ok", or every vault shown while
 * the server didn't sign; never rows a locked background refresh wrote); [candidates]: [usable] as
 * it was when this phone first made the account's identity (recorded once: what grandfathering may
 * keep); [missing]: the unsigned shared vaults that may be accepted by the key id shown (written once
 * at the first signed sync, when the trust memory was missing ([missingWhy] "memory") or this phone
 * made the identity without an earlier copy ("device"); it only shrinks); [absent]: accepted shared
 * vaults a verified sync no longer listed, with how many syncs in a row (tombstoned at two, or when
 * the server says the vault is gone). Round 5 (Android H): [unsentSealed] = this phone's key pins
 * with changes the server doesn't have yet (sealed with version [unsentSeq]), kept until a `PUT`
 * succeeded and merged on top of every copy loaded, so a failed write never leaves a change (an own
 * key replacement, a tombstone, an accept) only in session memory. Writes merge ([merge]), never overwrite.
 */
@Serializable
data class SigningMemory(
    val pinsSeq: Long = 0,
    val pinsSealed: String? = null,
    val rosters: Map<String, String> = emptyMap(),
    val signed: Set<String> = emptySet(),
    val ownIdentity: String? = null,
    val generated: List<String> = emptyList(),
    val usable: Set<String>? = null,
    val candidates: Set<String>? = null,
    val missing: Set<String>? = null,
    val missingWhy: String? = null,
    val absent: Map<String, Int> = emptyMap(),
    val unsentSealed: String? = null,
    val unsentSeq: Long = 0,
) {
    /** Nothing remembered yet (a server without signed sharing may be used without checks; [generated] and [usable] alone don't count). */
    val isEmpty: Boolean get() = pinsSeq == 0L && pinsSealed == null && rosters.isEmpty() && signed.isEmpty() && ownIdentity == null && unsentSealed == null

    /**
     * [other] merged in: the higher pins version with its sealed copy, per vault the roster with the
     * higher version, the union of vaults seen signed, the own identity remembered first; candidates
     * and missing written once (missing only shrinks), [other]'s usable list and absences.
     */
    fun merge(other: SigningMemory): SigningMemory {
        val (seq, sealed) = if (other.pinsSeq > pinsSeq || (other.pinsSeq == pinsSeq && pinsSealed == null)) other.pinsSeq to other.pinsSealed else pinsSeq to pinsSealed
        val r = rosters.toMutableMap()
        for ((vid, text) in other.rosters) {
            val mine = r[vid]
            if (mine == null || (SignedSharing.rosterVersion(text) ?: 0) > (SignedSharing.rosterVersion(mine) ?: 0)) r[vid] = text
        }
        val m = when {
            missing == null -> other.missing
            other.missing == null -> missing
            else -> missing intersect other.missing
        }
        return SigningMemory(
            seq, sealed, r, signed + other.signed, ownIdentity ?: other.ownIdentity, (generated + other.generated).distinct().takeLast(MAX_GENERATED),
            other.usable ?: usable, candidates ?: other.candidates, m, missingWhy ?: other.missingWhy, absent + other.absent,
            // Unsent pins are never dropped by a merge (only a successful write clears them).
            unsentSealed ?: other.unsentSealed, if (unsentSealed != null) unsentSeq else other.unsentSeq,
        )
    }

    companion object {
        const val MAX_GENERATED = 4
        const val MISSING_MEMORY = "memory"
        const val MISSING_DEVICE = "device"
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
 * on a vault never seen signed: [replaced]): never used until the user accepts it, shown like an
 * invitation. Unsigned ones ([signer] null) never offer Decline (a server could make a real vault
 * look like this): they can be accepted by the key id shown ([keyId]) when [replaced] or
 * [unsignedAllowed], and otherwise stay locked ("Ask the vault's owner to sign this vault.").
 */
data class ConsentVault(
    val vaultId: String,
    val name: String,
    val role: String,
    val rejoin: Boolean,
    val signer: SignerView?,
    val deleted: Boolean,
    /** A vault already accepted, never seen signed, whose key changed (signed or not). */
    val replaced: Boolean = false,
    /** Unsigned, and this phone may accept it by its key id (trust memory missing, or a phone without an earlier copy). */
    val unsignedAllowed: Boolean = false,
    /**
     * What was checked, in one value (key id and epoch, signer identity hash and the email shown,
     * roster hash and version, the flags): accepting binds to the vault as shown, so a server that
     * changes it between the check and the tap gets [SignedSharing.CHANGED_JUST_NOW] (re-review H).
     */
    val token: String = "",
    /** The account held this vault with its own key wrap (a personal vault now served as shared). */
    val own: Boolean = false,
    /** The key id of the key it would accept (shown for unsigned ones). */
    val keyId: String = "",
    /** A vault from before signed for the first time at the same key (round 5): trusted only with the user's OK. */
    val firstSigned: Boolean = false,
    /** The core's `declinable` (round 5 M2): none of rejoin, replaced, own, first signed or held, and signed. */
    val coreDeclinable: Boolean = false,
) {
    val acceptable: Boolean get() = signer != null || replaced || unsignedAllowed

    /**
     * Decline only where the core's verdict says `declinable` and a signer is named: never for a
     * replaced key, a vault that was the account's own, a re-join or a first signature (a
     * puppet-signed consent for a vault the account uses must not lead the user into giving it up).
     */
    val declinable: Boolean get() = coreDeclinable && signer != null && !replaced && !own && !rejoin && !firstSigned
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

    /**
     * Signed by [signer] and checked; accepting pins the signer (with [pinEmail], the email shown,
     * normalized; [pinVerified] kept from an upgraded pin) and accepts [observation] (the vault row as
     * checked, with the chain's roster hashes) with the core's `pins_accept`.
     */
    data class Signed(
        val signer: SignerView,
        internal val signerJson: String,
        internal val pinEmail: String,
        internal val roster: String,
        internal val rosterVersion: Long,
        internal val epochPin: String,
        internal val observation: String = "",
        internal val pinVerified: Boolean = false,
        /**
         * The core's admission of the invitation (`invitation: true`, round 5 Android M): [rejoin] a
         * vault left before and shared again, [held] a new key for a vault the account has (signed
         * history required), [declinable] whether Decline may be offered (never for a vault in use).
         */
        val rejoin: Boolean = false,
        val held: Boolean = false,
        val declinable: Boolean = true,
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
    /** Why unsigned vaults may be accepted by key id here ([SigningMemory.MISSING_MEMORY] or [SigningMemory.MISSING_DEVICE]); null for none. */
    val missingWhy: String? = null,
    /** Shared vaults held neutrally until this phone finished the account's first signed sync (rule 2). */
    val checking: List<RefusedVault> = emptyList(),
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

    /**
     * Whether the account still holds vault [vaultId] (`GET /vaults/{id}/members`): false when the
     * server answers 404 (gone: non-members get 404; a 403 can be a policy, two-step or reauth
     * refusal and never counts, [SignedSharing.removalConfirmed]), true when it lists the members,
     * null when it can't be told.
     */
    suspend fun stillMember(vaultId: String): Boolean? = null
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
    const val NEW_DEVICE = "This phone had no earlier copy of your shared vaults, so each one shared before signing needs your OK once. Accept only the ones you expected."
    const val CONSENT_REPLACED = "Its key was replaced by an app that doesn't sign yet. Accept only if someone in this vault just replaced its key. It stays locked until you accept it."
    const val ASK_OWNER_TO_SIGN = "Ask the vault's owner to sign this vault."
    const val CONSENT_UNSIGNED = "It isn't signed, so PassAuth keeps it locked. $ASK_OWNER_TO_SIGN"
    const val CANT_DECLINE = "Only a vault signed by someone you can name can be declined here. PassAuth keeps this one locked."
    const val STILL_CHECKING = "PassAuth is still checking this shared vault. It isn't used until the check is done."
    const val MEMORY_UNREADABLE = "PassAuth can't read this phone's list of known keys, so shared vaults aren't used and nothing is changed. Sign out and in again if this stays."
    const val TOO_MANY_KEY_REPLACEMENTS = "This vault's key was replaced too often in the last hour. Try again later."
    const val UNSIGNED_KEY_LABEL = "Key id (compare it with the vault's owner)"
    const val PINS_NOT_SAVED = "PassAuth couldn't save your list of known keys on your server, so nothing was accepted. Try again when your server can be reached."
    const val NO_DECLINE_NOW = "While PassAuth can't find your list of known keys, shared vaults can only be accepted or left for later."
    const val COMPARE_FIRST = "Compare the fingerprint with them first: this account uses an email you already know under another account."
    const val NOT_DECLINABLE = "PassAuth keeps this one locked until you decide. It can't be declined here, because that could give up a vault you use."
    const val PINS_UNSENT = "PassAuth couldn't check your list of known keys right now, so it didn't replace any key. Try again when your server can be reached."

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

    /** The words for a key replacement the server refused for its hourly limit (429 `rate_limited`, round 4); null for any other error. */
    fun keyReplacementLimited(e: ApiException): String? =
        if (!e.isRateLimited) null else TOO_MANY_KEY_REPLACEMENTS + (tooManyAttemptsMessage(e)?.let { " ($it)" } ?: "")

    /**
     * Whether an error of `GET /vaults/{id}/members` confirms the account no longer holds the vault:
     * only a 404 (the server answers non-members with 404). A 403 can be a policy, two-step or reauth
     * refusal and must never tombstone a vault.
     */
    fun removalConfirmed(e: ApiException): Boolean = e.status == 404

    /** Someone this phone knows only by user id (never pinned, no longer listed). */
    fun someone(userId: String) = "a former member (${userId.take(8)})"

    fun signedBy(email: String, deleted: Boolean) = "Signed by $email" + if (deleted) " (account deleted)" else ""

    /** "Signed by …" with the server's different email, never "Verified" next to it. */
    fun signerLine(s: SignerView, deleted: Boolean): String =
        signedBy(s.email, deleted) + (s.listedEmail?.let { " (listed by your server as $it)" } ?: "") + if (s.verified && s.listedEmail == null) " · Verified" else ""

    fun unsignedInvitation(name: String) = "This invitation isn't signed. Ask $name to update PassAuth and share again."

    /** What a signed invitation's admission adds (round 5 Android M): a re-join, or a new key for a vault the account has; null for none. */
    fun invitationNote(t: InvitationTrust.Signed, vaultName: String): String? = when {
        t.held -> "This is a new key for $vaultName, which you already have. Accept only if someone in this vault just replaced its key."
        t.rejoin -> "You left or declined $vaultName before, and it was shared with you again."
        else -> null
    }

    fun keysChanged(email: String) = "$email's keys changed. Compare their fingerprint with them before you continue."

    fun emailConflict(email: String) = "Your server lists a new account for $email, whose keys you already know under another account."

    fun firstTime(email: String) = "First time you see $email's keys: compare this fingerprint with them"

    fun consentTitle(name: String) = "Your server added $name to your account"

    /** A consent row's signer as its wording names them: the pinned email, else "someone listed by your server as …" (never the server's word alone). */
    fun signerName(s: SignerView): String = if (s.pin == PinState.New) "someone listed by your server as ${s.email}" else s.email

    /**
     * What a vault held for consent says (round 4): a replaced key names its signer (pinned email
     * first) or says it is unsigned; a vault the account held with its own key warns first.
     */
    fun consentText(c: ConsentVault): String {
        val s = c.signer
        val base = when {
            c.replaced && s != null -> "The key of ${c.name} was replaced and signed by ${signerName(s)} for the first time. Compare their fingerprint before you accept."
            c.replaced -> "The key of ${c.name} was replaced by an app that doesn't sign yet. Accept only if someone in this vault just replaced its key."
            // Round 5 M: the first signature of a vault from before, at the same key.
            c.firstSigned && s != null -> "${c.name} is signed for the first time, by ${signerName(s)}. Compare their fingerprint before you accept."
            else -> CONSENT
        }
        return if (c.own) "${c.name} was your own vault. Your server now says someone else gave you a new key for it. Accept only if you shared this vault and expected a key change. $base" else base
    }

    /** The help line of an unsigned vault held for consent: accepted by its key id where allowed, else locked. */
    fun unsignedConsentNote(c: ConsentVault, why: String?): String = when {
        c.replaced -> "Not signed. Compare its key id with whoever replaced the key."
        c.unsignedAllowed -> (if (why == SigningMemory.MISSING_DEVICE) NEW_DEVICE else "$NOT_YET_SIGNED: accept it only if you expected it.") + " Compare its key id with the vault's owner."
        else -> CONSENT_UNSIGNED
    }

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
        "own_vault" -> "$REFUSED (It names a vault that is your own.)"
        "held" -> "$REFUSED (It names a vault you already have, without the signed history a new key needs.)"
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

    /**
     * `/sync` `user.account_wraps_v2` (servers from 0.14): every signed-in app of the account reads
     * v2 (epoch-bound) account wraps, so new own wraps may be written v2. Only a JSON `true` counts;
     * absent (older server) or anything else = v1. A hint for compatibility only: a server that lies
     * can only make this app write v1, as before.
     */
    fun accountWrapsV2(user: JsonElement?): Boolean = flag(user as? JsonObject, "account_wraps_v2")

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

    /** The vault ids the key pins grandfathered (`{vault id: key id}` since round 5; empty before the first signed sync). */
    fun grandfathered(pins: String?): Set<String> = (pins?.let(::obj)?.get("grandfathered") as? JsonObject)?.keys.orEmpty()

    /** Whether two key pins (JSON) say the same, apart from their version (the seq they were sealed with). */
    fun samePins(a: String?, b: String?): Boolean {
        if (a == b) return true
        val x = a?.let(::obj) ?: return false
        val y = b?.let(::obj) ?: return false
        return JsonObject(x - "version") == JsonObject(y - "version")
    }

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

    /**
     * An email as the key pins compare it (trimmed, NFKC, lower case, IDNA ASCII domain): how pinned
     * emails are shown. Empty when the core can't normalize it (round 5 Info: never the raw email,
     * which isn't pinned then and shows as "someone listed by your server").
     */
    fun normalized(email: String?): String = email?.takeIf { it.isNotBlank() }?.let { runCatching { normalizeEmail(it) }.getOrNull() }.orEmpty()

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
                // Pinned in the one normalized form (cleaned only for display).
                normalized(text(r, "pinned_email")?.takeIf { it.isNotBlank() } ?: text(r, "listed_email")),
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

    /** Held neutrally (not used, no Accept or Decline) until this phone finished the account's first signed sync (rule 2). */
    data class Held(val reason: String) : VaultCheck
}

/** A key replacement's plan after the checks ([SharingSession.planRotation]). */
sealed interface RotationPlan {
    /** Go ahead: sign the next roster after [trusted] with [digest]; [newPins]: members to pin (identity JSON, email, verified). */
    data class Ready(val trusted: String?, val digest: String, val newPins: List<Triple<String, String, Boolean>>) : RotationPlan

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
    /**
     * The vaults this phone showed as usable before this unlock ([SigningMemory.usable]): recorded
     * once as the grandfathering candidates when this phone first makes the account's identity.
     */
    private val earlier: Set<String> = emptySet(),
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

    /**
     * The server answered that it has no key pins for the account (an online load; never set by an
     * offline or cache-first open, and cleared by an online load that found pins: final review M).
     */
    private var noPinsFound = false

    /** The key pins were last loaded from the server (else from this phone's copy). */
    private var loadedOnline = false

    /** This session's first grandfathering run decided which vaults may be accepted by key id. */
    private var missingDecided = false

    /** Whether this account's own identity was known (this phone's memory or the key pins) when this unlock began (rule 6). */
    private var ownKnownAtStart: Boolean? = null

    /**
     * This phone's copy of the key pins can't be opened (rule 7): shared vaults are refused, the
     * account's own vaults are checked against the server's pins (read only) when it sent readable
     * ones, and nothing is written or replaced.
     */
    var memoryUnreadable = false
        private set

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

    /**
     * The version of the key pins the server holds as far as this session knows for certain (it
     * loaded them from the server, or wrote them itself, without a problem); null otherwise.
     */
    val serverPinsSeq: Long? get() = pinsSeq.takeIf { pinsLoaded && loadedOnline && pinsProblem == null && !pinsUnreachable && !dirty }
    private var pinsLoaded = false

    /** Set while the server's key pins can't be used (rollback, unreadable): nothing is written. */
    var pinsProblem: String? = null
        private set

    /** The pins differ from the server's copy (this phone changed them, or knows more): written at the next save. */
    private var dirty = false

    /** Round 5: the server's pins and this phone's remember different own identities: nothing merged or written, sharing paused. */
    private var conflict = false

    /** The sealed unsent pins this session wrote or read ([SigningMemory.unsentSealed]), and the pins it wrote there. */
    private var knownUnsent: String? = null
    private var unsentText: String? = null

    /** Identities that differ from their pins, by user id: kept until the user trusts the new key (never cleared by a sync). */
    private val changes = linkedMapOf<String, IdentityChange>()

    /** The user ids whose changed identity this sync's checks noted (the others are dropped at its end). */
    private val seenChanges = mutableSetOf<String>()

    /** Roster chains fetched for invitations, by invitation content (fetched once). */
    private val invitationRosters = mutableMapOf<String, Trusted>()

    /**
     * What accepting a vault held for consent writes, by vault id (from the last check): the signer
     * and roster, and [observation] (the row as checked, with the chain's roster hashes) for the
     * core's `pins_accept`; [shown]: the vault as shown.
     */
    private class ConsentPlan(val signer: Signer?, val roster: String?, val rosterVersion: Long?, val observation: String, val replaced: Boolean, val shown: ConsentVault)

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
        if (ownKnownAtStart == null) ownKnownAtStart = memory.read().ownIdentity != null || SignedSharing.ownIdentityOf(pins) != null
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
        // Another own identity in the server's pins than in this phone's: paused (round 5).
        if (conflict) pause()
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
                // The grandfathering candidates are recorded once, the first time (rule 6).
                val hash = made.identity.identityHash()
                memory.write { it.merge(SigningMemory(generated = listOf(hash), candidates = earlier)) }
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
                } else if (e.status != 404 && e.status != 409) {
                    // Not set up (a server error, a limit, a refusal): tried again at the next sync (rule 2),
                    // nothing grandfathered meanwhile. 404: this server doesn't sign.
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
        // Only if no own identity was known when this unlock began (rule 6: never every later unlock).
        if (hash != null && ownKnownAtStart != true && hash in memory.read().generated) {
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

    /**
     * This phone's unsent pins ([SigningMemory.unsentSealed]); null when there are none. Ones that
     * can't be opened make the trust memory unreadable (rule 7: nothing is used or written then).
     */
    private fun openUnsent(m: SigningMemory): String? {
        val sealed = m.unsentSealed ?: return null
        knownUnsent = sealed
        return try {
            account.openKeyPins(sealed, m.unsentSeq.toULong())
        } catch (_: CoreException) {
            memoryUnreadable = true
            null
        }
    }

    /**
     * Round 5: the account's own identity differs between the server's pins and this phone's
     * (`identity_mismatch`): nothing is merged or written and sharing pauses for this session.
     */
    private fun identityConflict() {
        conflict = true
        pinsProblem = SignedSharing.PAUSED
    }

    /**
     * [base] (the copy loaded: the server's, merged with this phone's last-known pins, or this phone's
     * own) with this phone's unsent changes on top: this session's pins when it changed them, else
     * the unsent pins kept on this phone (`mergePins`: only for unsent changes). [server]: the copy as
     * written on the server, which decides whether anything is left to write ([dirty]).
     */
    private suspend fun adopt(base: String?, server: String?, m: SigningMemory): String? {
        val ours = if (dirty && pins != null) pins else openUnsent(m)
        val merged = when {
            ours == null -> base
            base == null -> ours
            else -> try {
                mergePins(base, ours)
            } catch (_: CoreException.IdentityMismatch) {
                identityConflict()
                dirty = false
                return base
            }
        }
        dirty = merged != null && !SignedSharing.samePins(merged, server)
        // Already on the server (a write whose answer was lost): the unsent copy is done with.
        if (!dirty && m.unsentSealed != null && !memoryUnreadable) clearUnsent()
        return merged
    }

    /**
     * Rule 5 / round 5 M1: whenever a newer server copy arrives and this phone has no unsent changes,
     * only what never goes back is taken from its last-known pins (`pinsMergeLastKnown`); with unsent
     * changes those win ([adopt]). Another own identity on either side: nothing merged.
     */
    private fun withLastKnown(server: String, local: String?, m: SigningMemory): String {
        if (local == null || (dirty && pins != null) || m.unsentSealed != null) return server
        return try {
            pinsMergeLastKnown(server, local)
        } catch (_: CoreException.IdentityMismatch) {
            identityConflict()
            server
        } catch (_: CoreException) {
            server
        }
    }

    /**
     * The pins this session changed, kept on this phone as unsent (round 5 Android H) before any
     * write is tried and whatever its outcome; cleared only once a `PUT` succeeded ([clearUnsent]).
     */
    private suspend fun persistUnsent() {
        if (!dirty || memoryUnreadable || conflict) return
        val p = pins ?: return
        if (p == unsentText) return
        val seq = pinsSeq
        val sealed = account.sealKeyPins(p, seq.toULong())
        memory.write { it.copy(unsentSealed = sealed, unsentSeq = seq) }
        knownUnsent = sealed
        unsentText = p
    }

    /** The unsent pins this session knows of are written: forgotten (another process's newer ones are kept). */
    private suspend fun clearUnsent() {
        val known = knownUnsent
        memory.write { if (it.unsentSealed == null || it.unsentSealed != known) it else it.copy(unsentSealed = null, unsentSeq = 0) }
        knownUnsent = null
        unsentText = null
    }

    /** Rolls the unsent copy back to [before] (an accept whose pins couldn't be written: nothing was accepted). */
    private suspend fun restoreUnsent(before: String?, wasDirty: Boolean) {
        if (memoryUnreadable || conflict) return
        if (wasDirty && before != null) {
            unsentText = null
            persistUnsent()
        } else if (knownUnsent != null) {
            clearUnsent()
        }
    }

    private suspend fun useLocal(m: SigningMemory) {
        if (pinsLoaded) return
        val local = openLocal(m)
        memoryUnreadable = m.pinsSealed != null && local == null
        pins = adopt(local, local, m)
        pinsSeq = m.pinsSeq
        pinsLoaded = true
        loadedOnline = false
    }

    /** The server answered that it has no key pins (version 0). */
    private suspend fun serverHasNone(m: SigningMemory) {
        pinsProblem = null
        memoryUnreadable = false
        pins = adopt(null, null, m)
        pinsSeq = 0
        pinsLoaded = true
        loadedOnline = true
        if (conflict) pinsProblem = SignedSharing.PAUSED
        // Unsent pins kept on this phone from before are the account's memory: it isn't missing here.
        noPinsFound = m.unsentSealed == null
    }

    private suspend fun loadPins(serverSeq: Long?, online: Boolean) {
        val m = memory.read()
        if (!online) return useLocal(m)
        // Round 5 L: a sync without `user.key_pins_seq` says nothing about the pins: they are fetched anyway.
        if (serverSeq != null && pinsLoaded && loadedOnline && serverSeq == pinsSeq && pinsProblem == null) {
            pinsUnreachable = false
            return
        }
        if (serverSeq != null && serverSeq < m.pinsSeq) return rollback(m, SignedSharing.PINS_ROLLED_BACK, online = true)
        if (serverSeq == 0L) {
            pinsUnreachable = false
            return serverHasNone(m)
        }
        val (sealed, seq) = try {
            api.getKeyPins()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            // Treated as offline: this phone's copy, nothing written or grandfathered, tried again next sync
            // (when this phone's copy is as new as the server says, it is simply used; an unknown version is offline).
            pinsUnreachable = serverSeq == null || serverSeq > m.pinsSeq
            return useLocal(m)
        }
        pinsUnreachable = false
        if (seq < m.pinsSeq) return rollback(m, SignedSharing.PINS_ROLLED_BACK, online = true)
        if (sealed == null) {
            // A version without pins is unreadable; none at all (version 0) is the server having none.
            if (seq > 0) return rollback(m, SignedSharing.PINS_UNREADABLE)
            return serverHasNone(m)
        }
        val opened = try {
            account.openKeyPins(sealed, seq.toULong())
        } catch (_: CoreException) {
            return rollback(m, SignedSharing.PINS_UNREADABLE)
        }
        pinsProblem = null
        memoryUnreadable = false
        // Rule 5: this phone's last-known pins (no unsent changes) or its unsent changes, on top of the server's.
        val base = withLastKnown(opened, openLocal(m), m)
        pins = adopt(base, opened, m)
        pinsSeq = seq
        pinsLoaded = true
        loadedOnline = true
        noPinsFound = false
        if (conflict) pinsProblem = SignedSharing.PAUSED
        // What the server's copy lacks is kept as unsent first: the server's copy never replaces it unwritten.
        persistUnsent()
        memory.write { it.merge(SigningMemory(pinsSeq = seq, pinsSealed = sealed)) }
    }

    /**
     * The server's pins can't be used ([why]): this phone's copy is. When that can't be opened either
     * (rule 7), nothing runs without pins: the server's copy ([online]) is opened read only (the
     * account's own vaults keep their epoch and key id checks), shared vaults are refused, nothing is written.
     */
    private suspend fun rollback(m: SigningMemory, why: String, online: Boolean = false) {
        val local = openLocal(m)
        if (local == null && m.pinsSealed != null) {
            memoryUnreadable = true
            pins = if (!online) null else try {
                val (sealed, seq) = api.getKeyPins()
                sealed?.let { account.openKeyPins(it, seq.toULong()) }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            }
            dirty = false
        } else {
            memoryUnreadable = false
            pins = adopt(local, local, m)
        }
        pinsSeq = m.pinsSeq
        pinsLoaded = true
        loadedOnline = online
        pinsProblem = why
    }

    /** Once the stored key pins hold the own identity and the grandfathered list: the identity made here and its candidates are done with (rule 6). */
    private suspend fun clearPendingIdentity() {
        val p = pins ?: return
        if (dirty || SignedSharing.ownIdentityOf(p) == null || SignedSharing.needsGrandfathering(p)) return
        if (memory.read().let { it.generated.isEmpty() && it.candidates == null }) return
        memory.write { it.copy(generated = emptyList(), candidates = null) }
    }

    /**
     * Write the key pins when this phone changed them (compare-and-swap; on 409 `key_pins_changed`
     * read, merge and write again once). The change is kept on this phone as unsent first (round 5
     * Android H) and stays there until a write succeeds. Nothing is written while the server's copy
     * can't be used, before the pins were loaded, or while the own identity differs.
     */
    suspend fun savePins() {
        if (dirty && memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
        if (!dirty || !pinsLoaded || conflict) return
        persistUnsent()
        if (pinsProblem != null || pinsUnreachable) return
        for (attempt in 0..1) {
            val p = pins ?: return
            val next = pinsSeq + 1
            val sealed = account.sealKeyPins(p, next.toULong())
            try {
                api.putKeyPins(sealed, next)
                pinsSeq = next
                dirty = false
                memory.write { it.merge(SigningMemory(pinsSeq = next, pinsSealed = sealed)) }
                clearUnsent()
                clearPendingIdentity()
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
                // This phone's unsent changes on the newer copy ("ours wins" only for them).
                val merged = try {
                    mergePins(theirs, p)
                } catch (_: CoreException.IdentityMismatch) {
                    identityConflict()
                    return
                }
                pins = merged
                pinsSeq = seq
                dirty = !SignedSharing.samePins(merged, theirs)
                persistUnsent()
                memory.write { it.merge(SigningMemory(pinsSeq = seq, pinsSealed = s)) }
                if (!dirty) {
                    clearUnsent()
                    return
                }
            }
        }
    }

    private fun pin(identityJson: String, email: String, verified: Boolean) {
        // One form everywhere: the normalized email (round 4). One the core can't normalize isn't pinned (round 5 Info).
        val normalized = SignedSharing.normalized(email)
        if (normalized.isEmpty() && email.isNotBlank()) throw CoreException.Invalid("email")
        pins = pinSet(pins, identityJson, normalized, verified, now())
        dirty = true
    }

    /**
     * A key this phone itself just gave the vault (its own key replacement): `pins_record_rotation`
     * with this account's own row's kind ([keyKind]) and the signed [roster]'s version and hash
     * together (or neither, unsigned).
     */
    private fun recordRotation(vaultId: String, keyKind: String, current: String, roster: String?) {
        val next = pinsRecordRotation(pins, vaultId, keyKind, current, roster?.let { SignedSharing.rosterVersion(it)?.toULong() ?: throw CoreException.Invalid("roster version") }, roster?.let { rosterHash(it) })
        if (!SignedSharing.samePins(next, pins)) {
            pins = next
            dirty = true
        }
    }

    /**
     * At the account's first signed sync, only when this unlock created its signing identity ([online],
     * key pins usable, sharing not paused): the unsigned shared vaults it has now ([vaults]: vault id
     * and the key id of the key it has now) that
     * this phone showed as usable before (the candidates recorded when it made the identity; none on
     * a fresh install or a re-added account) stay usable without a consent ("Not yet signed"). Once
     * per account, and only once the identity state is known (made here, or the listed one opened):
     * after a failed or unanswered upload nothing is written and it is tried again at the next sync
     * (ARCHITECTURE "Grandfathering", rules 1 and 2). An account that already had an identity but no
     * key pins gets [memoryMissing] instead. The vaults that then wait may be accepted by their key id
     * ([SigningMemory.missing], written once): all of them when the trust memory is missing or this
     * phone made the identity without an earlier copy, and, when another device wrote the list first,
     * the ones this phone had before (iOS final review M1, case c).
     */
    suspend fun grandfather(vaults: List<Pair<String, String>>, online: Boolean) {
        if (!online || paused || pinsProblem != null || pinsUnreachable || !pinsLoaded || memoryUnreadable) return
        val vaultIds = vaults.map { it.first }
        if (identity == null) return
        if (skipGrandfather) {
            skipGrandfather = false
            return
        }
        memoryMissing = !createdHere && noPinsFound
        val m = memory.read()
        val candidates = m.candidates ?: earlier
        val first = SignedSharing.needsGrandfathering(pins)
        if (first) {
            // Only the unlock that created the identity writes the ids; otherwise an empty list.
            // Each with the key id it has now (round 5: a planted key under a grandfathered id needs consent).
            val chosen = if (createdHere) vaults.filter { it.first in candidates } else emptyList()
            val list = JsonArray(chosen.map { (vid, keyId) -> buildJsonObject { put("vault_id", vid); put("key_id", keyId) } }).toString()
            pins = pinsGrandfather(pins, list, createdHere)
            dirty = true
        }
        val kept = SignedSharing.grandfathered(pins)
        val (waiting, why) = when {
            createdHere && candidates.isEmpty() -> vaultIds.filter { it !in kept } to SigningMemory.MISSING_DEVICE
            createdHere -> vaultIds.filter { it in candidates && it !in kept } to SigningMemory.MISSING_DEVICE
            first && memoryMissing -> vaultIds to SigningMemory.MISSING_MEMORY
            else -> emptyList<String>() to null
        }
        // Decided once, at this session's first grandfathering run (vaults that come later wait for a signature).
        if (!missingDecided && waiting.isNotEmpty() && m.missing == null) memory.write { it.merge(SigningMemory(missing = waiting.toSet(), missingWhy = why)) }
        missingDecided = true
        clearPendingIdentity()
    }

    /** Whether this phone finished the account's first signed sync: identity known, key pins loaded and grandfathered (rule 2). */
    val firstSignedSyncDone: Boolean
        get() = identity != null && !paused && pinsLoaded && !memoryUnreadable && !SignedSharing.needsGrandfathering(pins)

    /** Why unsigned vaults may be accepted by key id on this phone (null: none). */
    suspend fun missingWhy(): String? = memory.read().let { m -> m.missingWhy.takeIf { !m.missing.isNullOrEmpty() } }

    /**
     * Accepted vaults (in the key pins' `epochs`) that were shared ([sharedBefore]: sealed rows of the
     * copy shown before) and that a verified sync ([current]: its vault ids) no longer lists get a
     * tombstone at the remembered roster version, so the server can't bring back the old copy later
     * (re-review L) — but only once the removal is confirmed (cross-client rule 3): the server says
     * the vault is gone (404 for its members; never a 403), or two verified syncs in a row didn't list it.
     * One sync that omitted it never makes the account give it up. Only online with usable pins.
     */
    suspend fun tombstoneRemoved(current: Set<String>, sharedBefore: Set<String>, online: Boolean) {
        if (!online || paused || pinsProblem != null || pinsUnreachable || !pinsLoaded || memoryUnreadable) return
        val accepted = (pins?.let(SignedSharing::obj)?.get("epochs") as? JsonObject)?.keys ?: return
        val before = memory.read().absent
        // Absences still open: accepted and still not listed (a vault listed again starts over).
        val absent = before.filterKeys { it in accepted && it !in current }.toMutableMap()
        for (vid in accepted.toList()) {
            if (vid in current) continue
            if (absent.containsKey(vid)) {
                // Not listed by two verified syncs in a row.
                leave(vid)
                absent.remove(vid)
                continue
            }
            if (vid !in sharedBefore) continue
            val member = try {
                api.stillMember(vid)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            }
            if (member == false) leave(vid) else absent[vid] = 1
        }
        if (absent != before) memory.write { it.copy(absent = absent) }
    }

    /**
     * Whether an `account` wrap of the vault at [keyEpoch] (the row's `key_epoch`) may be a v1 wrap
     * (the core's rule: refused at or below the highest epoch this account opened from a v2 wrap).
     */
    fun legacyAllowed(vaultId: String, keyEpoch: Long?): Boolean =
        runCatching { pinsLegacyWrapAllowed(pins, vaultId, (keyEpoch ?: 0).coerceAtLeast(0).toULong()) }.getOrDefault(false)

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
        seenChanges.remove(userId)
        invitationRosters.clear()
        return true
    }

    // ------------------------------------------------------------- checking

    /**
     * The signer of a share: checked, compared with the pins; null (and a change noted) when it can't
     * be trusted. [pinEmail]/[pinVerified]: what pinning them writes (rule 4): a new person under the
     * email shown (normalized), an upgraded one keeps the pinned email and its verified mark.
     */
    private class Signer(val userId: String, val view: SignerView, val json: String, val pinEmail: String, val hash: String, val pinVerified: Boolean = false)

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
            seenChanges += uid
            return null
        }
        val verified = state == PinState.Match && SignedSharing.flag(pinned, "verified")
        val upgraded = state == PinState.Upgraded && !pinnedEmail.isNullOrBlank()
        val pinEmail = SignedSharing.normalized(if (upgraded) pinnedEmail else listed)
        val pinVerified = upgraded && SignedSharing.flag(pinned, "verified")
        return Signer(uid, SignerView(email.ifEmpty { SignedSharing.someone(uid) }, listedShown, fp, state, verified), json, pinEmail, hash, pinVerified)
    }

    /**
     * The newest roster of [vaultId] after [after] (`GET …/rosters` page by page, at most 1000 versions
     * and 16 MiB of roster text per sync and vault), checked as a chain from [trusted] ending exactly
     * at [latest].
     */
    private suspend fun fetchChain(vaultId: String, trusted: String?, after: Long, latest: String): Trusted {
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
            if (!more || page.isEmpty()) return Trusted(verifyRosterChain(vaultId, trusted, newer, latest), chainHashes(trusted, newer))
            from = SignedSharing.rosterVersion(page.last()) ?: throw CoreException.Invalid("roster version")
        }
        throw CoreException.TooLarge("too_large")
    }

    /**
     * `chain_hashes` of a fetched chain (round 4): the roster hash of the trusted roster it started
     * from (if any) and of every newer roster checked, by version (decimal text).
     */
    private fun chainHashes(trusted: String?, newer: List<String>): Map<String, String> {
        val out = linkedMapOf<String, String>()
        for (r in listOfNotNull(trusted) + newer) out[(SignedSharing.rosterVersion(r) ?: throw CoreException.Invalid("roster version")).toString()] = rosterHash(r)
        return out
    }

    /** The roster trusted for a vault ([roster], null: not signed) and, when a chain was fetched for it, its roster hashes ([chain]). */
    private class Trusted(val roster: String?, val chain: Map<String, String>?)

    /**
     * The roster to trust for [vaultId] whose server-listed latest is [latest]: none (not signed), the
     * one remembered ([remembered]), or the newer ones checked as a chain from it. Nothing is
     * remembered here. Throws [CoreException] for a rollback, fork or a chain that doesn't verify,
     * [SharingOffline] when newer ones couldn't be fetched ([online] false: never asked).
     */
    private suspend fun trustedRoster(vaultId: String, remembered: String?, latest: String?, online: Boolean): Trusted {
        val head = SignedSharing.obj(rosterHead(vaultId, remembered, latest)) ?: throw CoreException.Invalid("roster head")
        return when (SignedSharing.text(head, "status")) {
            "unsigned" -> Trusted(null, null)
            "same" -> Trusted(remembered, null)
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
        seenChanges.clear()
    }

    /** Ends a sync's checks: a changed identity none of its rows or invitations showed any more is dropped (final review Info: stale entries). */
    fun endChecks() {
        changes.keys.retainAll(seenChanges)
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
        // This phone's trust memory can't be read (rule 7): no shared vault is used.
        if (memoryUnreadable && sealed) return refused(SignedSharing.MEMORY_UNREADABLE)
        // No key pins loaded (identity or pins couldn't be read at all): no shared vault is used (round 5 Info).
        if (!pinsLoaded && sealed) return refused(SignedSharing.UNCHECKED)
        val epoch = v.keyEpoch ?: return refused(SignedSharing.refusedReason("missing_epoch"))
        val key = try {
            open(legacyAllowed(v.id, epoch))
        } catch (_: CoreException) {
            return refused(SignedSharing.REFUSED)
        }
        try {
            val remembered = memory.read().rosters[v.id]
            val trusted = try {
                trustedRoster(v.id, remembered, v.memberRoster, online)
            } catch (_: SharingOffline) {
                return refused(SignedSharing.UNCHECKED)
            } catch (_: ApiException) {
                return refused(SignedSharing.UNCHECKED)
            } catch (e: CoreException) {
                return refused(refusedFor(e))
            }
            val roster = trusted.roster
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
            // An own vault opened from a v2 (epoch-bound) wrap: the pins remember it (`bound_since`), so a v1 wrap at that epoch is refused later.
            val bound = !sealed && accountWrapIsBound(v.wrappedKey)
            val observation = observation(v.id, if (sealed) "sealed" else "account", current, rosterVersion, roster, trusted.chain, signer != null, boundWrap = bound).toString()
            // The core's admission, with what it says to pin (`pin`: key, signed history, roster version and hash) applied.
            val observed = SignedSharing.obj(pinsObserve(pins, observation)) ?: return refused(SignedSharing.REFUSED)
            val admission = observed["admission"] as? JsonObject ?: return refused(SignedSharing.REFUSED)
            val deleted = SignedSharing.flag(v.share as? JsonObject, "signer_deleted")
            val status = SignedSharing.text(admission, "status")
            // Newer key pins couldn't be read: only what this phone's own pins admit is used.
            if (pinsUnreachable && status != "ok") return refused(SignedSharing.UNCHECKED)
            return when (status) {
                "ok" -> {
                    // Every check of the row passed: only now its pins and the roster are remembered.
                    // Nothing is written to pins that were never loaded (they'd replace the account's).
                    if (pinsLoaded) signer?.let { s -> if (s.userId != me && (s.view.pin == PinState.New || s.view.pin == PinState.Upgraded)) pin(s.json, s.pinEmail, s.pinVerified) }
                    if (pinsLoaded && SignedSharing.flag(observed, "changed")) {
                        // Applied to the pins as they are now (with the signer pinned just now).
                        pins = (SignedSharing.obj(pinsObserve(pins, observation))?.get("pins") as? JsonObject)?.toString() ?: return refused(SignedSharing.REFUSED)
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
                    // Rule 2: before this phone finished the account's first signed sync an unsigned row is
                    // held neutrally (no Accept, no Decline): an honest server's vaults aren't turned into consents.
                    if (signer == null && !firstSignedSyncDone) return VaultCheck.Held(SignedSharing.STILL_CHECKING)
                    val replaced = SignedSharing.flag(admission, "replaced")
                    val rejoin = SignedSharing.flag(admission, "rejoin")
                    val own = SignedSharing.flag(admission, "own")
                    val firstSigned = SignedSharing.flag(admission, "first_signed")
                    val declinable = SignedSharing.flag(admission, "declinable")
                    // Unsigned: by the key id shown, only for the vaults written as waiting at the first signed sync (rule 1).
                    val unsignedAllowed = signer == null && !replaced && v.id in memory.read().missing.orEmpty()
                    val keyId = SignedSharing.text(SignedSharing.obj(current), "key_id").orEmpty()
                    val token = SignedSharing.token(
                        v.id, v.role, rejoin, replaced, own, firstSigned, declinable, unsignedAllowed, deleted, keyId,
                        signer?.userId, signer?.hash, signer?.json, signer?.pinEmail, signer?.pinVerified, signer?.view?.email, signer?.view?.listedEmail,
                        current, rosterVersion, roster?.let { rosterHash(it) },
                    )
                    val shown = ConsentVault(v.id, nameOf(), v.role, rejoin, signer?.view, deleted, replaced, unsignedAllowed, token, own, keyId, firstSigned, declinable)
                    consentPlans[v.id] = ConsentPlan(signer, roster, rosterVersion, observation, replaced, shown)
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

    /**
     * A `VaultObservation` (JSON) for the core: `signed_share` and `paused` always (required since
     * round 4), `roster_hash` exactly with `roster_version`, `chain_hashes` whenever a chain was
     * fetched ([chain]), `invitation: true` for an invitation ([invitation]).
     */
    private fun observation(vaultId: String, kind: String, current: String, rosterVersion: Long?, roster: String?, chain: Map<String, String>?, signedShare: Boolean, invitation: Boolean = false, boundWrap: Boolean = false): JsonObject = buildJsonObject {
        put("vault_id", vaultId)
        put("key_kind", kind)
        put("key", AppJson.parseToJsonElement(current))
        if (rosterVersion != null) put("roster_version", rosterVersion) else put("roster_version", JsonNull)
        if (roster != null) put("roster_hash", rosterHash(roster)) else put("roster_hash", JsonNull)
        if (chain != null) put("chain_hashes", JsonObject(chain.mapValues { JsonPrimitive(it.value) }))
        put("signed_share", signedShare)
        put("paused", paused)
        // An invitation (round 5 Android M): never grandfathered or own, held when the account has the vault; the same in admit and accept.
        if (invitation) put("invitation", true)
        // Only for `account` rows (the core refuses it on a sealed one).
        if (boundWrap) put("bound_wrap", true)
    }

    /** The key pins with [observation] accepted (`pins_accept`); what the core refuses is said in words. */
    private fun accept(observation: String) {
        pins = try {
            pinsAccept(pins, observation)
        } catch (_: CoreException.RosterForked) {
            throw UserException(SignedSharing.refusedReason("roster_forked"))
        } catch (_: CoreException.IdentityMismatch) {
            throw UserException(SignedSharing.PAUSED)
        } catch (_: CoreException) {
            // rollback (left, older, conflicting or downgraded) or malformed.
            throw UserException(SignedSharing.REFUSED)
        }
        dirty = true
    }

    /** A vault the user answered: no longer waiting, no longer counted as absent. */
    private suspend fun answered(vaultId: String) {
        memory.write { it.copy(missing = it.missing?.minus(vaultId), absent = it.absent - vaultId) }
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
        if (!pinsLoaded || conflict) throw UserException(SignedSharing.PINS_NOT_SAVED)
        try {
            block()
            savePins()
            if (dirty) throw UserException(SignedSharing.PINS_NOT_SAVED)
        } catch (e: Throwable) {
            pins = before.first
            pinsSeq = before.second
            dirty = before.third
            // The unsent copy on this phone goes back too: nothing was accepted.
            if (e !is kotlinx.coroutines.CancellationException) runCatching { restoreUnsent(before.first, before.third) }
            if (e is kotlinx.coroutines.CancellationException || e is UserException || e is ApiException) throw e
            throw UserException(SignedSharing.PINS_NOT_SAVED)
        }
    }

    /**
     * Accept a vault held for consent exactly as [shown] (the vault, its key and signer and the email
     * shown, as the last check showed them; anything else is [SignedSharing.CHANGED_JUST_NOW]): the
     * row accepted with the core's `pins_accept` (key, roster version and hash; a tombstone cleared and
     * marked re-joined; an own vault marked) and the signer pinned under the email shown, written to
     * the server first, then the roster remembered.
     */
    suspend fun acceptConsent(shown: ConsentVault) {
        val vaultId = shown.vaultId
        val p = consentPlans[vaultId]?.takeIf { it.shown == shown } ?: throw UserException(SignedSharing.CHANGED_JUST_NOW)
        if (paused) throw UserException(SignedSharing.PAUSED)
        if (memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
        val s = p.signer
        // Unsigned: only a replaced key, or a vault written as waiting at the first signed sync, by the key id shown.
        if (s == null && !p.replaced && !shown.unsignedAllowed) throw UserException(SignedSharing.CONSENT_UNSIGNED)
        committing {
            if (s != null && s.userId != me && (s.view.pin == PinState.New || s.view.pin == PinState.Upgraded)) pin(s.json, s.pinEmail, s.pinVerified)
            accept(p.observation)
        }
        if (s != null) p.roster?.let { remember(vaultId, it) }
        answered(vaultId)
        consentPlans.remove(vaultId)
    }

    /**
     * Decline a vault held for consent exactly as [shown], only where the core's verdict says
     * `declinable` (round 5 M2: never a re-join, a replaced key, an own vault, a first signature or a
     * held key; never unsigned): `pins_decline` for a row of this sync, which leaves the key pins as
     * they are (a server-chosen roster version never goes into a tombstone). The account then leaves
     * the vault on the server.
     */
    suspend fun declineConsent(shown: ConsentVault) {
        val p = consentPlans[shown.vaultId]?.takeIf { it.shown == shown } ?: throw UserException(SignedSharing.CHANGED_JUST_NOW)
        // While the trust memory is missing a server could otherwise push the user out of real vaults: Accept or later only.
        if (memoryMissing) throw UserException(SignedSharing.NO_DECLINE_NOW)
        if (!shown.declinable || p.signer == null) throw UserException(SignedSharing.CANT_DECLINE)
        if (memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
        decline(shown.vaultId, currentRow = true)
        answered(shown.vaultId)
    }

    /**
     * Declining invitation [vaultId] ([trust]: its check as shown): only where it may be declined (a
     * signed one whose admission says `declinable`), with `pins_decline` (round 5 M2): a tombstone at
     * roster version 0 only for a vault the account doesn't hold — none when the key pins accepted it,
     * it was left already, or it is one of this sync's vault rows ([rows], whatever its check said).
     */
    suspend fun declineInvitation(vaultId: String, trust: InvitationTrust, rows: Set<String>) {
        if (trust is InvitationTrust.Signed && !trust.declinable) throw UserException(SignedSharing.NOT_DECLINABLE)
        invitationPlans.remove(vaultId)
        if (memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
        if (!pinsLoaded || conflict) return
        decline(vaultId, currentRow = vaultId in rows)
    }

    private fun decline(vaultId: String, currentRow: Boolean) {
        val next = pinsDecline(pins, vaultId, currentRow, now())
        if (!SignedSharing.samePins(next, pins)) {
            pins = next
            dirty = true
        }
        consentPlans.remove(vaultId)
        invitationPlans.remove(vaultId)
    }

    /**
     * Leaving, or a removal this phone confirmed: a tombstone, so it never comes back unless shared
     * again; at the remembered roster version (the core raises it to what the pin knew).
     */
    suspend fun leave(vaultId: String) {
        val remembered = memory.read().rosters[vaultId]?.let { SignedSharing.rosterVersion(it) } ?: 0
        pins = pinsLeave(pins, vaultId, remembered.toULong(), now())
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
            val trusted = invitationRosters[cacheKey] ?: run {
                val remembered = memory.read().rosters[inv.vaultId]
                trustedRoster(inv.vaultId, remembered, latest, online)
            }
            val top = trusted.roster ?: return refused
            if (top != latest || SignedSharing.rosterEpoch(top) != epoch) return refused
            invitationRosters[cacheKey] = trusted
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
            // With the chain's roster hashes when it was fetched (round 4: a chain re-signed from version 1
            // must contain the roster the account last trusted).
            // `invitation: true` (round 5 Android M): an invitation never re-pins a vault the account has
            // (`held` unless a signed newer key on a vault with signed history), never its own (`own_vault`);
            // the same observation is what accepting passes to `pins_accept`, so the flags shown are the flags accepted.
            val observation = observation(inv.vaultId, "sealed", current, version, top, trusted.chain, true, invitation = true).toString()
            val admission = SignedSharing.obj(pinsAdmit(pins, observation)) ?: return refused
            when (SignedSharing.text(admission, "status")) {
                "consent" -> {}
                "refused" -> return InvitationTrust.Refused(SignedSharing.refusedReason(SignedSharing.text(admission, "reason").orEmpty()))
                // Anything else for an invitation isn't what the core promises: not accepted.
                else -> return refused
            }
            // An own vault or a replaced key are never offered as an invitation (the core refuses own vaults).
            if (SignedSharing.flag(admission, "own")) return InvitationTrust.Refused(SignedSharing.refusedReason("own_vault"))
            if (SignedSharing.flag(admission, "replaced")) return refused
            InvitationTrust.Signed(
                s.view, s.json, s.pinEmail, top, version, current, observation, s.pinVerified,
                rejoin = SignedSharing.flag(admission, "rejoin"),
                held = SignedSharing.flag(admission, "held"),
                declinable = SignedSharing.flag(admission, "declinable"),
            )
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
        if (memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
        committing {
            // The signer under the email shown (an upgraded pin keeps its email and mark), the row with `pins_accept`.
            if (t.signer.pin == PinState.New || t.signer.pin == PinState.Upgraded) pin(t.signerJson, t.pinEmail, t.pinVerified)
            accept(t.observation)
        }
        remember(vaultId, t.roster)
        answered(vaultId)
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
        // Rule 7: no key replacement without readable trust memory (its pins couldn't be written).
        if (memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
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
        // Pinned with the emails the confirmed review showed (the digest covers ids, identities and roles, not emails);
        // an upgraded pin keeps its pinned email and verified mark (rule 4).
        val newPins = review.members.filter { !it.isSelf && (it.pin == PinState.New || it.pin == PinState.Upgraded) }.mapNotNull { p ->
            val row = rows.firstOrNull { SignedSharing.text(it, "user_id") == p.userId } ?: return@mapNotNull null
            val pinned = SignedSharing.pinOf(pins, p.userId)
            val pinnedEmail = SignedSharing.text(pinned, "email")
            if (p.pin == PinState.Upgraded && !pinnedEmail.isNullOrBlank()) Triple(row.toString(), SignedSharing.normalized(pinnedEmail), SignedSharing.flag(pinned, "verified"))
            else Triple(row.toString(), approval?.emails?.get(p.userId) ?: p.pinEmail, false)
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
    suspend fun rememberRotation(vaultId: String, roster: String?, epochPin: String, newPins: List<Triple<String, String, Boolean>>, keyKind: String = "account") {
        for ((json, email, verified) in newPins) runCatching { pin(json, email, verified) }
        // `pins_record_rotation` (round 5): the roster's version always with its hash. The server took the
        // replacement already, so a refusal here leaves the pins to the next sync's checks.
        runCatching { recordRotation(vaultId, keyKind, epochPin, roster) }
        if (roster != null) remember(vaultId, roster)
        // Kept on this phone as unsent at once (round 5 Android H): a failed key-pins write must not
        // let the old key be accepted again after the next unlock.
        persistUnsent()
    }

    /**
     * Before any key replacement (round 5 Info): the key pins loaded and readable, not paused, not
     * rolled back or unreachable; otherwise a [UserException] and nothing is replaced.
     */
    fun requireReadyToReplace() {
        if (paused) throw UserException(SignedSharing.PAUSED)
        if (memoryUnreadable) throw UserException(SignedSharing.MEMORY_UNREADABLE)
        pinsProblem?.let { throw UserException(it) }
        if (!pinsLoaded || pinsUnreachable) throw UserException(SignedSharing.PINS_UNSENT)
    }

    companion object {
        private val MANAGERS = setOf("owner", "admin")
        private const val MAX_ROSTER_PAGES = 10
        private const val MAX_ROSTER_VERSIONS = 1000
        private const val MAX_ROSTER_BYTES = 16L * 1024 * 1024
    }
}

/**
 * Whose account bundle this is (round 5, iOS H, checked on every client): a restored session
 * (biometric unlock, timeout "never") is used only when the stored bundle is its own, and a bundle a
 * sync or a locked background refresh brings is stored only when it is the account's own, so a server
 * can't make "me" (and with it this phone's trust memory) another account id.
 */
object AccountBundles {
    /**
     * The account restored from its session bytes under the stored [bundle]'s account id, only when
     * the bundle opens under its Account Key to its keys (`Account.matches_bundle`); null otherwise
     * (ask for the master password).
     */
    fun restore(bundle: String, bytes: ByteArray): Account? {
        val id = Stored.bundleUserId(bundle) ?: return null
        val account = io.passauth.core.accountFromSessionBytes(id, bytes)
        if (account.matchesBundle(bundle)) return account
        account.destroy()
        return null
    }

    /**
     * The bundle to keep after a sync brought [next] ([stored]: the one kept): with the account
     * unlocked ([unlocked]) only one `matches_bundle` accepts; locked, only one naming the same
     * account id as the kept one (checked when a session is restored from it). Else the kept one.
     */
    fun toStore(unlocked: Account?, stored: String?, next: String?): String? {
        if (next == null || next == stored) return stored
        if (unlocked != null) return if (unlocked.matchesBundle(next)) next else stored
        val keptId = Stored.bundleUserId(stored) ?: return stored
        return if (Stored.bundleUserId(next) == keptId) next else stored
    }
}
