package io.passauth.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/*
 * Offline changes (ARCHITECTURE "Offline changes (waiting to sync)"): an item created, edited or
 * moved to the trash while the server can't be reached waits on this phone, sealed with the account
 * key, and is sent later. Everything here is pure (JVM-tested in OfflineChangesTest); the
 * repository does the requests and the storage.
 */

/** The exact body of the last attempt of a change that may have reached the server. */
@Serializable
data class SentBody(
    val key: String,
    val data: String,
    @SerialName("key_epoch") val keyEpoch: Long? = null,
)

@Serializable
enum class ChangeKind {
    @SerialName("create") Create,
    @SerialName("edit") Edit,
    @SerialName("trash") Trash,
}

@Serializable
enum class ChangeState {
    @SerialName("waiting") Waiting,
    @SerialName("held") Held,
    @SerialName("conflict") Conflict,
}

/** One waiting change (one per item). [item]: the decrypted item as the editor saved it (create/edit); null for trash. */
@Serializable
data class OfflineChange(
    val id: String,
    val kind: ChangeKind,
    @SerialName("vault_id") val vaultId: String,
    @SerialName("item_id") val itemId: String,
    @SerialName("base_revision") val baseRevision: Long? = null,
    val item: JsonObject? = null,
    val sent: SentBody? = null,
    @SerialName("created_at") val createdAt: Long,
    val state: ChangeState = ChangeState.Waiting,
    val reason: String? = null,
)

/** The list of one account, as sealed: `{"version": 1, "changes": [...]}`. */
@Serializable
data class OfflineList(
    val version: Int = 1,
    val changes: List<OfflineChange> = emptyList(),
) {
    fun of(itemId: String): OfflineChange? = changes.firstOrNull { it.itemId == itemId }

    val waiting: Int get() = changes.count { it.state != ChangeState.Conflict }
    val conflicts: Int get() = changes.count { it.state == ChangeState.Conflict }
}

/** How the server holds an item now, as far as sending a change needs to know ([vaultId]: the vault it is in now). */
data class ServerRow(val revision: Long?, val data: String?, val trashed: Boolean, val vaultId: String? = null)

/** A change from this phone's point of view against [ServerRow]: what to do next. */
sealed interface SendDecision {
    /** The server already has it (or nothing is left to do): the change goes. */
    data object Done : SendDecision

    /** Send the request now. */
    data object Send : SendDecision

    /**
     * An earlier attempt landed but the change's item is newer than what it sent (a later save was
     * merged into the change): send the item as an edit over the server's current row.
     */
    data object EditOver : SendDecision

    /** A create whose id the server holds with other content: send under a new id. */
    data object NewId : SendDecision

    /** The user decides; [deleted]: the item is gone from the server (or in its trash). */
    data class Conflict(val deleted: Boolean) : SendDecision
}

/** After a failed send. */
sealed interface SendFailure {
    /** No answer from the server: stop and try again later (the change stays waiting). */
    data object Stop : SendFailure

    /** Sync and decide again. */
    data object Again : SendFailure

    /** Not sent; said with [reason] until things change. */
    data class Held(val reason: String) : SendFailure

    /** Changed on another device: the user decides. */
    data object Conflict : SendFailure
}

/** A field shown in the conflict sheet: this phone's value and the server's, marked when they differ. */
data class FieldDiff(val label: String, val mine: String, val theirs: String, val secret: Boolean = false) {
    val differs: Boolean get() = mine != theirs
}

object OfflineChanges {
    /** At most this many changes wait per account. */
    const val MAX = 500

    /** Retries of a send that met `revision_conflict` (then a conflict) or a manifest/key change (then held). */
    const val ATTEMPTS = 3

    const val TOO_MANY = "Too many changes are waiting. Connect to the internet before making more."
    const val NEEDS_CONNECTION = "You're offline. This needs a connection."
    const val HAS_WAITING_CHANGE = "This item has a change waiting to sync. Try again once it's sent."
    const val TRASHED_OFFLINE = "This item is in the trash. Restoring it needs a connection."
    const val UNREADABLE = "PassAuth couldn't read the changes waiting on this device. Try again once you're online."
    const val WAITING = "Waiting to sync"
    const val CONFLICT = "Changed on another device"
    const val DISCARD = "Discard this change"
    const val DISCARD_CONFIRM = "Your change to this item will be lost."
    const val COPY_SUFFIX = " (offline copy)"

    const val DELETED = "Deleted on another device."
    const val CHANGED_ELSEWHERE = "The item changed on the server. Try again."
    const val UNREADABLE_CHANGE = "This change can't be read."
    const val CANT_OPEN = "This item can't be opened on this device."
    const val VAULT_GONE = "This vault is no longer available."
    const val READ_ONLY = "You can no longer change items in this vault."
    const val VAULT_WARNING = "This vault's record of changes needs your review first."

    fun marker(c: OfflineChange): String = when (c.state) {
        ChangeState.Waiting -> WAITING
        ChangeState.Held -> "Not sent: ${c.reason ?: "Try again later."}"
        ChangeState.Conflict -> CONFLICT
    }

    /** The sync status line ("3 changes waiting to sync"), decisions first; null with nothing waiting. */
    fun status(list: OfflineList): String? = when {
        list.conflicts > 0 -> if (list.conflicts == 1) "1 change needs your decision" else "${list.conflicts} changes need your decision"
        list.waiting > 0 -> if (list.waiting == 1) "1 change waiting to sync" else "${list.waiting} changes waiting to sync"
        else -> null
    }

    /** The warning before Log out, Change server, removing or deleting the account; null when nothing waits. */
    fun lostWarning(count: Int): String? = when {
        count <= 0 -> null
        count == 1 -> "1 change hasn't been sent and will be lost."
        else -> "$count changes haven't been sent and will be lost."
    }

    /**
     * Does a write that failed with [e] wait in the list? Only when the server didn't answer (no
     * network, DNS, refused or reset connection, TLS, timeout: [UnreachableException]) or answered
     * 502/503/504 (a proxy in front of it). Never for any other answer.
     */
    fun shouldWait(e: Throwable): Boolean = e is UnreachableException || (e is ApiException && e.status in 502..504)

    /**
     * [next] merged into [list] (one change per item, rules of the contract). Throws [UserException]
     * ([TOO_MANY]) for a new change beyond [MAX], ([TRASHED_OFFLINE]) for an edit of an item trashed offline.
     */
    fun add(list: OfflineList, next: OfflineChange, max: Int = MAX): OfflineList {
        val at = list.changes.indexOfFirst { it.itemId == next.itemId }
        if (at < 0) {
            if (list.changes.size >= max) throw UserException(TOO_MANY)
            return list.copy(changes = list.changes + next)
        }
        val old = list.changes[at]
        val merged: OfflineChange? = when (old.kind) {
            ChangeKind.Create -> when (next.kind) {
                ChangeKind.Create, ChangeKind.Edit -> old.copy(item = next.item, state = ChangeState.Waiting, reason = null)
                // Nothing reached the server: nothing to send. Maybe it did: a trash of what may be there.
                ChangeKind.Trash -> if (old.sent == null) null else old.copy(kind = ChangeKind.Trash, baseRevision = null, item = null, state = ChangeState.Waiting, reason = null)
            }
            ChangeKind.Edit -> when (next.kind) {
                // A decision that stands stays to be made; anything else is decided again.
                ChangeKind.Create, ChangeKind.Edit -> old.copy(item = next.item, state = if (old.state == ChangeState.Conflict) ChangeState.Conflict else ChangeState.Waiting, reason = old.reason.takeIf { old.state == ChangeState.Conflict })
                ChangeKind.Trash -> old.copy(kind = ChangeKind.Trash, item = null, state = ChangeState.Waiting, reason = null)
            }
            ChangeKind.Trash -> when (next.kind) {
                ChangeKind.Trash -> old
                else -> throw UserException(TRASHED_OFFLINE)
            }
        }
        return list.copy(changes = if (merged == null) list.changes.filterIndexed { i, _ -> i != at } else list.changes.mapIndexed { i, c -> if (i == at) merged else c })
    }

    /** [list] without the change of [itemId]. */
    fun remove(list: OfflineList, itemId: String): OfflineList = list.copy(changes = list.changes.filter { it.itemId != itemId })

    /** [list] with [c] in place of the change of the same item (added at the end when there is none). */
    fun put(list: OfflineList, c: OfflineChange): OfflineList =
        if (list.changes.any { it.itemId == c.itemId }) list.copy(changes = list.changes.map { if (it.itemId == c.itemId) c else it })
        else list.copy(changes = list.changes + c)

    /**
     * What to do with [c] against the server's row of its item ([row] null: the server has no such
     * item). [sentMatches]: the change's item equals the server's decrypted item (ignoring `rev` and
     * `format`, see [sameContent]); only looked at when the row holds what an earlier attempt sent.
     * An attempt that landed is done only when no later save was merged into the change since.
     */
    fun decide(c: OfflineChange, row: ServerRow?, sentMatches: Boolean = true): SendDecision {
        val landed = row != null && c.sent != null && row.data != null && row.data == c.sent.data
        return when (c.kind) {
            ChangeKind.Create -> when {
                row == null -> SendDecision.Send
                landed -> if (sentMatches) SendDecision.Done else SendDecision.EditOver
                else -> SendDecision.NewId
            }
            ChangeKind.Edit -> when {
                // Deleted for good on another device; one in the trash is treated alike (this app has no trash to edit in).
                row == null || row.trashed -> SendDecision.Conflict(deleted = true)
                landed -> if (sentMatches) SendDecision.Done else SendDecision.EditOver
                row.revision != null && row.revision == c.baseRevision -> SendDecision.Send
                else -> SendDecision.Conflict(deleted = false)
            }
            ChangeKind.Trash -> when {
                row == null || row.trashed -> SendDecision.Done
                // The server holds this device's own last attempt (create or edit merged into the trash): trash it.
                landed -> SendDecision.Send
                row.revision != null && row.revision == c.baseRevision -> SendDecision.Send
                else -> SendDecision.Conflict(deleted = false)
            }
        }
    }

    /**
     * The same item content, ignoring what a send stamps on its own: the edit counter (`rev`, counted
     * up by the core), `format` (stamped by the core) and the times (stamped again at each attempt).
     */
    fun sameContent(a: Item, b: Item): Boolean {
        fun plain(i: Item) = i.copy(format = null, createdAt = 0, updatedAt = 0, extra = JsonObject(i.extra - "rev"))
        return plain(a) == plain(b)
    }

    /**
     * A change is held, not sent, when its vault is gone, the user can no longer write to it, or the
     * vault didn't pass this sync's checks ([ManifestState.Unresolved] / [ManifestState.Unchecked];
     * vaults refused by signed sharing are not in [vault] at all). Null: it may be sent.
     */
    fun holdReason(vault: VaultInfo?): String? = when {
        vault == null -> VAULT_GONE
        vault.role == Role.Read -> READ_ONLY
        vault.manifest == ManifestState.Unresolved -> VAULT_WARNING
        vault.manifest == ManifestState.Unchecked -> Manifests.UNCHECKED
        else -> null
    }

    /**
     * After a send failed with [e] on its [attempt]th try (1-based): no answer → stop; the item
     * changed meanwhile → decide again (then a conflict); a manifest or key change → again (then
     * held); anything else → held, in the app's words ([words]).
     */
    fun afterFailure(e: Throwable, attempt: Int, words: (Throwable) -> String): SendFailure {
        if (shouldWait(e)) return SendFailure.Stop
        val revision = e is ConflictException || (e is ApiException && e.status == 409 && e.hasCode("revision_conflict"))
        if (revision) return if (attempt < ATTEMPTS) SendFailure.Again else SendFailure.Conflict
        val stale = e is ItemWrites.StaleCopy || Manifests.isConflict(e) || ItemWrites.vaultKeyChanged(e) || e.message == Manifests.CHANGED_ELSEWHERE
        if (stale && attempt < ATTEMPTS) return SendFailure.Again
        return SendFailure.Held(words(e))
    }

    /** "Keep both" / "Save mine as a new item": this phone's version as a new item in the same vault. */
    fun asNew(c: OfflineChange, newItemId: String, newChangeId: String, rename: (JsonObject) -> JsonObject): OfflineChange = c.copy(
        id = newChangeId, kind = ChangeKind.Create, itemId = newItemId, baseRevision = null,
        item = c.item?.let(rename), sent = null, state = ChangeState.Waiting, reason = null,
    )

    /** "Keep mine" / "Move to trash anyway": the change again, now over the server's [revision]. */
    fun over(c: OfflineChange, revision: Long?): OfflineChange =
        c.copy(baseRevision = revision, sent = null, state = ChangeState.Waiting, reason = null)

    /** The conflict sheet's rows: every field either version has, in the editor's order. */
    fun differences(mine: Item, theirs: Item): List<FieldDiff> {
        val rows = mutableListOf<FieldDiff>()
        fun add(label: String, a: String, b: String, secret: Boolean = false) {
            if (a.isNotEmpty() || b.isNotEmpty()) rows += FieldDiff(label, a, b, secret)
        }
        add("Name", mine.name, theirs.name)
        add("Folder", mine.folder.orEmpty(), theirs.folder.orEmpty())
        val ml = mine.login
        val tl = theirs.login
        if (ml != null || tl != null) {
            add("Username", ml?.username.orEmpty(), tl?.username.orEmpty())
            add("Password", ml?.password.orEmpty(), tl?.password.orEmpty(), secret = true)
            add("Websites", ml?.urls.orEmpty().joinToString("\n") { it.url }, tl?.urls.orEmpty().joinToString("\n") { it.url })
            add("Authenticator key", ml?.totp.orEmpty(), tl?.totp.orEmpty(), secret = true)
            val mp = ml?.passkeys.orEmpty().size
            val tp = tl?.passkeys.orEmpty().size
            if (mp + tp > 0) add("Passkeys", mp.toString(), tp.toString())
        }
        val mc = mine.card
        val tc = theirs.card
        if (mc != null || tc != null) {
            add("Cardholder", mc?.cardholderName.orEmpty(), tc?.cardholderName.orEmpty())
            add("Card number", mc?.number.orEmpty(), tc?.number.orEmpty(), secret = true)
            add("Expires", listOfNotNull(mc?.expMonth?.ifEmpty { null }, mc?.expYear?.ifEmpty { null }).joinToString("/"), listOfNotNull(tc?.expMonth?.ifEmpty { null }, tc?.expYear?.ifEmpty { null }).joinToString("/"))
            add("Security code", mc?.code.orEmpty(), tc?.code.orEmpty(), secret = true)
        }
        if (mine.identity != null || theirs.identity != null) {
            fun text(i: Identity?) = i?.let {
                listOf(
                    listOf(it.title, it.firstName, it.middleName, it.lastName).filter(String::isNotEmpty).joinToString(" "),
                    it.company, it.email, it.phone, it.address1, it.address2,
                    listOf(it.postalCode, it.city, it.state).filter(String::isNotEmpty).joinToString(" "), it.country, it.username,
                ).filter(String::isNotEmpty).joinToString("\n")
            }.orEmpty()
            fun ids(i: Identity?) = i?.let { listOf(it.ssn, it.passportNumber, it.licenseNumber).filter(String::isNotEmpty).joinToString("\n") }.orEmpty()
            add("Personal details", text(mine.identity), text(theirs.identity))
            add("ID numbers", ids(mine.identity), ids(theirs.identity), secret = true)
        }
        if (mine.sshKey != null || theirs.sshKey != null) {
            add("SSH key", mine.sshKey?.fingerprint.orEmpty(), theirs.sshKey?.fingerprint.orEmpty())
        }
        val mf = mine.fields.joinToString("\n") { "${it.name}: ${if (it.type == FieldType.Hidden) "••••" else it.value}" }
        val tf = theirs.fields.joinToString("\n") { "${it.name}: ${if (it.type == FieldType.Hidden) "••••" else it.value}" }
        add("Custom fields", mf, tf)
        add("Notes", mine.notes, theirs.notes)
        add("Favorite", if (mine.favorite) "Yes" else "", if (theirs.favorite) "Yes" else "")
        return rows
    }

    /**
     * The entries shown: [base] (the checked offline copy) with [list] on top. Created items appear
     * ([make] with no base entry), edits show the new content, items moved to the trash leave the
     * list, except while the trash waits for the user's decision (the item is still there). [decode]
     * reads a change's item; one that can't be read leaves the entry as it is.
     */
    fun <E> overlay(base: List<E>, list: OfflineList, idOf: (E) -> String, make: (OfflineChange, Item, E?) -> E, decode: (JsonObject) -> Item?): List<E> {
        if (list.changes.isEmpty()) return base
        val byItem = list.changes.associateBy { it.itemId }
        val out = ArrayList<E>(base.size + list.changes.size)
        val seen = HashSet<String>()
        for (e in base) {
            val id = idOf(e)
            seen += id
            val c = byItem[id]
            when {
                c == null -> out += e
                c.kind == ChangeKind.Trash -> if (c.state == ChangeState.Conflict) out += e
                else -> out += (c.item?.let(decode)?.let { make(c, it, e) } ?: e)
            }
        }
        for (c in list.changes) {
            if (c.itemId in seen || c.kind == ChangeKind.Trash) continue
            val item = c.item?.let(decode) ?: continue
            out += make(c, item, null)
        }
        return out
    }
}

/** No answer from the server (network, DNS, connection, TLS, timeout). */
class UnreachableException : UserException(UNREACHABLE)
