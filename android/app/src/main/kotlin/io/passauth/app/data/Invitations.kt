package io.passauth.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull

/*
 * Vault invitations (servers with the `vault_invitations` feature; the server side is
 * `crates/server/src/vault/sharing.rs`). Sharing a vault with someone who isn't a member yet makes
 * an invitation; nothing of the vault reaches their apps until they accept it, so nobody can put a
 * vault, or logins planted in it, into someone's apps without their consent. Every `/sync` answer,
 * full or delta, lists the pending invitations in full, each with the vault key sealed to the
 * account (opened only to read the vault's name) and the sharer's public key. The sealed key is
 * anonymous, so nothing proves who sent it: the fingerprint shown is only the one the server lists
 * for the sharer, never presented as a check, and the user is asked to accept only invitations
 * they expected. Mirrors the web vault's `invitations.ts` and the iOS app's
 * `Shared/Invitations.swift`; pure, JVM-tested in InvitationsTest.
 */

/** Who shared a vault: their account and public key (for its fingerprint). */
@Serializable
data class InvitedBy(
    val id: String,
    val email: String = "",
    val name: String = "",
    @SerialName("public_key") val publicKey: String = "",
    /** Signed sharing: their signing identity (null for an account without one). */
    @SerialName("signing_key") val signingKey: String? = null,
    @SerialName("identity_signature") val identitySignature: String? = null,
)

/** A pending invitation as `/sync` lists it (the vault key and name still encrypted). */
@Serializable
data class SyncInvitation(
    @SerialName("vault_id") val vaultId: String,
    val role: String,
    /** The vault key sealed to this account's public key. */
    @SerialName("wrapped_key") val wrappedKey: String,
    /** The vault's name etc., encrypted with that key. */
    val meta: String,
    /** Null once the sharer's account is deleted. */
    @SerialName("invited_by") val invitedBy: InvitedBy? = null,
    /** Unix seconds; null when the server didn't say. */
    @SerialName("invited_at") val invitedAt: Long? = null,
    /** The vault's key epoch (signed into the share); null from older servers. */
    @SerialName("key_epoch") val keyEpoch: Long? = null,
    /** Signed sharing: `{signature, signer, signer_deleted}`, or null (not signed). */
    val share: JsonElement? = null,
    /** Signed sharing: the vault's latest member roster (JSON text) and its version (0: none). */
    @SerialName("member_roster") val memberRoster: String? = null,
    @SerialName("member_roster_seq") val memberRosterSeq: Long? = null,
)

/** An invitation as the app shows it. */
data class Invitation(
    val vaultId: String,
    val role: String,
    /** The vault's name; null when this account's keys can't open the invitation (then it can only be declined). */
    val name: String?,
    val invitedBy: InvitedBy?,
    val invitedAt: Long?,
    /** Its signature, checked (servers with signed sharing); [InvitationTrust.Unchecked] otherwise. */
    val trust: InvitationTrust = InvitationTrust.Unchecked,
) {
    /** It can be accepted: checked and signed, or from a server without signed sharing. */
    val acceptable: Boolean get() = name != null && (trust is InvitationTrust.Signed || trust == InvitationTrust.Unchecked)
}

object Invitations {
    /** The `/api/config` feature of servers with invitations. */
    const val FEATURE = "vault_invitations"

    /** The name shown for a vault whose (opened) name is empty. */
    const val UNNAMED = "Shared vault"

    private fun text(v: JsonElement?): String? = (v as? JsonPrimitive)?.takeIf { it.isString }?.content

    /**
     * The `invitations` of a `/sync` answer (or a stored copy). Servers without the feature send
     * none; an entry without a vault id, sealed key, encrypted name or role is left out, a vault
     * listed twice counts once, and a role this app doesn't know is kept as sent, so the invitation
     * can still be answered. Never throws: one bad entry doesn't make the answer unreadable.
     */
    fun read(value: JsonElement?): List<SyncInvitation> {
        val list = value as? JsonArray ?: return emptyList()
        val seen = mutableSetOf<String>()
        return list.mapNotNull { raw ->
            val o = raw as? JsonObject ?: return@mapNotNull null
            val vaultId = text(o["vault_id"])?.takeIf { it.isNotEmpty() && it !in seen } ?: return@mapNotNull null
            val wrapped = text(o["wrapped_key"])?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val meta = text(o["meta"])?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val role = text(o["role"])?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val by = (o["invited_by"] as? JsonObject)?.let { b ->
                text(b["id"])?.let { id ->
                    // Server-chosen text: shown cleaned (one line, no invisible characters, capped).
                    InvitedBy(id, CleanText.oneLine(text(b["email"]), 128), CleanText.oneLine(text(b["name"]), 128), text(b["public_key"]).orEmpty(), text(b["signing_key"]), text(b["identity_signature"]))
                }
            }
            fun whole(v: JsonElement?) = (v as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull
                ?.takeIf { it.isFinite() && it == Math.floor(it) }?.toLong()
            val at = whole(o["invited_at"])
            seen += vaultId
            SyncInvitation(
                vaultId, role, wrapped, meta, by, at,
                keyEpoch = whole(o["key_epoch"]),
                share = (o["share"] as? JsonObject),
                memberRoster = text(o["member_roster"]),
                memberRosterSeq = whole(o["member_roster_seq"]),
            )
        }
    }

    /**
     * The invitations as the app shows them, in the server's order (oldest first). [open] reads
     * the vault's name with the sealed key and returns null (or throws) when that isn't possible.
     */
    fun open(list: List<SyncInvitation>, open: (SyncInvitation) -> String?): List<Invitation> = list.map { inv ->
        val name = try {
            open(inv)
        } catch (_: Exception) {
            null
        }
        Invitation(inv.vaultId, inv.role, name, inv.invitedBy, inv.invitedAt)
    }

    /**
     * Whether the invitation listed now is the one a sheet showed ([shown]): the same vault, role,
     * name, sharer and the same check (signer, key and roster). Accepting binds to it, so a server
     * that changes the invitation between the check and the tap gets [InvitationText.CHANGED].
     */
    fun sameAsShown(current: Invitation?, shown: Invitation): Boolean = current != null && current == shown

    /** What identifies an opened name: the vault, its sealed key and encrypted name. */
    fun cacheKey(inv: SyncInvitation) = "${inv.vaultId}\n${inv.wrappedKey}\n${inv.meta}"

    /** A vault's name from its decrypted `meta` JSON: a non-blank `name`, else [UNNAMED]. */
    fun nameOf(meta: JsonElement?): String {
        val name = CleanText.oneLine(text((meta as? JsonObject)?.get("name")), 64)
        return name.ifEmpty { UNNAMED }
    }
}

/** Invitation wording, as the web vault's Settings → Vaults & sharing (pure, unit-tested). */
object InvitationText {
    const val INTRO = "A vault shared with you appears in your apps only after you accept it."

    /** Under the fingerprint, and in the accept sheet: the fingerprint can't prove who sent an invitation. */
    const val EXPECTED = "Accept only invitations you expected."
    const val CANT_OPEN_TITLE = "Invitation that can't be opened"
    const val NO_LONGER_OPEN = "This invitation is no longer open. The person who shared the vault may have cancelled it."
    const val DECLINE_BODY = "The vault won't appear in your apps. The invitation already gave your account the vault's key, " +
        "so the people who manage the vault will be asked to replace it."
    const val CHANGED = "This invitation changed since it was shown. Check it again before you accept."
    private const val NOBODY = "the person who shared it"

    /**
     * The checked signer of a signed invitation as shown: the pinned email (the one its share lists
     * when they're new), never the server's `invited_by`; a different email the server lists only as
     * "listed by your server as …" (re-review M). Null for an invitation that isn't signed and checked.
     */
    fun signer(inv: Invitation): String? {
        val t = inv.trust as? InvitationTrust.Signed ?: return null
        val listed = t.signer.listedEmail
            ?: inv.invitedBy?.email?.takeIf { it.isNotBlank() && !SignedSharing.sameEmail(it, t.signer.email) }?.let { SignedSharing.clean(SignedSharing.normalized(it)) }
        return t.signer.email + (listed?.let { " (listed by your server as $it)" } ?: "")
    }

    /** Who shared the vault: "Alex Morgan (alex@example.com)", the email alone, or a note when their account is gone (a signed one: [signer]). */
    fun sharerName(inv: Invitation): String {
        signer(inv)?.let { return it }
        val by = inv.invitedBy ?: return "Someone whose account was deleted"
        val name = by.name.trim()
        val email = by.email.trim()
        if (name.isNotEmpty() && email.isNotEmpty()) return "$name ($email)"
        return name.ifEmpty { email.ifEmpty { "Someone on this server" } }
    }

    /** The sharer's name alone, for running text ("ask Alex Morgan to…"). */
    fun sharerShort(inv: Invitation): String =
        (inv.trust as? InvitationTrust.Signed)?.signer?.email ?: inv.invitedBy?.name?.trim()?.ifEmpty { null } ?: inv.invitedBy?.email?.trim()?.ifEmpty { null } ?: NOBODY

    fun title(inv: Invitation): String = inv.name ?: CANT_OPEN_TITLE

    /** "From Alex Morgan (alex@example.com), 12 Nov 2026, 10:00" ([date] formats unix seconds). */
    fun fromLine(inv: Invitation, date: (Long) -> String): String =
        "From ${sharerName(inv)}" + (inv.invitedAt?.let { ", ${date(it)}" } ?: "")

    fun roleLabel(role: String): String = when (role) {
        "owner" -> "Owner"
        "admin" -> "Admin"
        "write" -> "Can edit"
        "read" -> "Can view"
        else -> role
    }

    fun roleSentence(role: String): String? = when (role) {
        "read" -> "You'll be able to view its items."
        "write" -> "You'll be able to view and edit its items."
        "admin" -> "You'll be able to edit its items and share the vault."
        else -> null
    }

    /**
     * "Fingerprint your server lists for alex@example.com" (the name without an email): the server
     * names the sharer and gives their key, so this shows which key it lists, not that they sent it.
     */
    fun fingerprintLabel(inv: Invitation): String =
        "Fingerprint your server lists for ${inv.invitedBy?.email?.trim()?.ifEmpty { null } ?: sharerShort(inv)}"

    fun cantOpen(inv: Invitation): String =
        "Your account's keys can't open this invitation, so PassAuth can't show the vault's name. " +
            "Decline it, then ask ${sharerShort(inv)} to share the vault again."

    /** Shown instead of the fingerprint when it can't be shown. */
    fun noFingerprint(inv: Invitation): String = if (inv.invitedBy == null) {
        "The account that shared this vault no longer exists. $EXPECTED"
    } else {
        "Your server didn't list a key for ${sharerShort(inv)}, so PassAuth can't show a fingerprint. $EXPECTED"
    }

    fun acceptTitle(inv: Invitation) = "Accept \"${inv.name.orEmpty()}\"?"

    fun acceptSubtitle(inv: Invitation) = "Shared by ${sharerName(inv)}"

    fun acceptBody(inv: Invitation): String =
        listOfNotNull("The vault and its items appear in all your apps.", roleSentence(inv.role), "The people who manage it can add and change items in it.")
            .joinToString(" ")

    fun joined(inv: Invitation) = "You joined \"${inv.name.orEmpty()}\"."

    fun declineSubtitle(inv: Invitation) = inv.name ?: "From ${sharerName(inv)}"

    /** One quiet line for the vault list while invitations wait; null when there are none. */
    fun notice(list: List<Invitation>): String? {
        if (list.isEmpty()) return null
        val tail = " Nothing from ${if (list.size == 1) "it" else "them"} reaches your apps until you accept."
        if (list.size > 1) return "You have ${list.size} invitations to shared vaults.$tail"
        val inv = list[0]
        val who = if (inv.invitedBy == null && inv.trust !is InvitationTrust.Signed) "Someone" else sharerShort(inv)
        val what = inv.name?.let { "the shared vault \"$it\"" } ?: "a shared vault"
        return "$who invited you to $what.$tail"
    }

    fun noticeAction(list: List<Invitation>) = if (list.size == 1) "See the invitation" else "See the invitations"

    /** Identifies a set of invitations, so a dismissed notice comes back when a new one arrives. */
    fun noticeKey(list: List<Invitation>): String = list.map { it.vaultId }.sorted().joinToString(",")
}

/**
 * Answering an invitation (the requests, apart from the transport): accept makes it a membership
 * and the vault arrives whole at the next sync; decline removes it, and the server asks the vault's
 * managers to replace the key. [sync] runs after each answer.
 */
class InvitationActions(private val api: SecurityTransport, private val sync: suspend () -> Unit) {
    private fun path(vaultId: String) = "/vaults/${java.net.URLEncoder.encode(vaultId, "UTF-8").replace("+", "%20")}/invitation"

    /** Accept; an invitation that is gone (cancelled, vault deleted: 404) refreshes the list and says so. */
    suspend fun accept(vaultId: String) {
        try {
            api.call("${path(vaultId)}/accept", null, "POST", true, emptyMap())
        } catch (e: ApiException) {
            if (e.status != 404) throw e
            // Show what is there now; a failed refresh doesn't hide why nothing was accepted.
            try {
                sync()
            } catch (c: kotlinx.coroutines.CancellationException) {
                throw c
            } catch (_: Exception) {
            }
            throw UserException(InvitationText.NO_LONGER_OPEN)
        }
        sync()
    }

    /** Decline; already gone (404) is fine: the list is refreshed either way. */
    suspend fun decline(vaultId: String) {
        try {
            api.call(path(vaultId), null, "DELETE", true, emptyMap())
        } catch (e: ApiException) {
            if (e.status != 404) throw e
        }
        sync()
    }
}
