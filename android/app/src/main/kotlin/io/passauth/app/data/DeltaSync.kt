package io.passauth.app.data

import java.net.URLEncoder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/*
 * Delta sync (servers whose `/api/config` `features` has "delta_sync"; the server side is
 * `crates/server/src/vault/sync.rs`). The offline copy of an account is the last `/sync` answer
 * with every later change merged in (ciphertext only, the shape of a full answer), so the
 * server's opaque `cursor` and each vault's `seq` are always stored together with the items they
 * describe. `GET /sync?since=<cursor>` then brings only what changed. The pure parts are here
 * (JVM-tested in DeltaSyncTest); VaultRepository does the requests, decryption and storage.
 * Mirrors the iOS app's `Shared/DeltaSync.swift`.
 */

/** A vault header of a `/sync` answer, as the server sends it (`meta` and the key encrypted). */
@Serializable
data class SyncVault(
    val id: String,
    val meta: String = "",
    val role: String = "",
    @SerialName("wrapped_key") val wrappedKey: String = "",
    @SerialName("key_kind") val keyKind: String = "",
    @SerialName("rotation_pending") val rotationPending: Long? = null,
    /** Goes up with every key replacement (API v2); null from older servers. */
    @SerialName("key_epoch") val keyEpoch: Long? = null,
    /** Goes up with every write into the vault (delta sync); null from older servers. */
    val seq: Long? = null,
) {
    /** The same vault key as [other] describes (wrapping, kind and epoch): an opened key can be kept. */
    fun sameKey(other: SyncVault): Boolean = wrappedKey == other.wrappedKey && keyKind == other.keyKind && keyEpoch == other.keyEpoch
}

/** An item row of a `/sync` answer (ciphertext and metadata). */
@Serializable
data class SyncItem(
    val id: String,
    @SerialName("vault_id") val vaultId: String,
    /** Null for an item in the trash of a `trash=summary` answer. */
    @SerialName("item_key") val itemKey: String? = null,
    val data: String? = null,
    val revision: Long? = null,
    /** Moved to the trash at (unix seconds); null for live items. */
    @SerialName("deleted_at") val deletedAt: Long? = null,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

/** An item that left a vault since the cursor (deleted for good, or moved to another vault). */
@Serializable
data class SyncDeleted(val id: String, @SerialName("vault_id") val vaultId: String)

/** A `/sync` answer: everything, or ([delta]) what changed since the cursor sent. */
@Serializable
data class SyncResponse(
    /** Kept raw: a revision sent as a string is refused, as before. */
    val revision: JsonElement? = null,
    val cursor: String? = null,
    val user: JsonElement? = null,
    val bundle: JsonElement? = null,
    val vaults: List<SyncVault>? = null,
    val items: List<SyncItem>? = null,
    val deleted: List<SyncDeleted>? = null,
    val reset: List<String>? = null,
    val delta: Boolean = false,
    /**
     * Vaults shared with the account and not accepted yet, always the full list (servers with
     * `vault_invitations`). Kept raw and read leniently ([Invitations.read]): one malformed entry
     * never makes the answer unreadable.
     */
    val invitations: JsonElement? = null,
)

/**
 * What this device has of an account: the sync revision of its copy and each vault's sequence
 * number ([vaults] null when the copy has no numbers: an older server or copy).
 */
data class SyncPosition(val revision: Long, val vaults: Map<String, Long>?)

/**
 * An account's copy: the last `/sync` answer with every later change merged in, in the shape of a
 * full answer (stored as the offline copy; readable as a full answer). [cursor]: the server's
 * cursor of the answer this copy was last brought up to date with (null: the server doesn't do
 * delta sync); never newer than the items: a local change applied on top keeps it, so the next
 * delta brings that change again, which is harmless.
 */
@Serializable
data class SyncSnapshot(
    val revision: Long,
    val cursor: String? = null,
    val user: JsonElement? = null,
    /** The account bundle (every server sends it; required where a copy is stored without unlocking). */
    val bundle: JsonElement? = null,
    val vaults: List<SyncVault> = emptyList(),
    val items: List<SyncItem> = emptyList(),
    /** The pending invitations of the answer (every answer replaces them); empty in copies from before. */
    val invitations: List<SyncInvitation> = emptyList(),
) {
    val position: SyncPosition
        get() {
            val seqs = mutableMapOf<String, Long>()
            for (v in vaults) seqs[v.id] = v.seq ?: return SyncPosition(revision, null)
            return SyncPosition(revision, seqs)
        }

    fun encode(): String = AppJson.encodeToString(SyncSnapshot.serializer(), this)

    companion object {
        /** The stored copy, or null when it can't be read as one (also a plain `/sync` answer stored before delta sync). */
        fun decode(text: String): SyncSnapshot? = DeltaSync.parse(text)?.let { SyncMerge.apply(it, null) }
    }
}

/** A write this device made, as the server stored it, to apply to the copy without asking the server again. */
sealed interface LocalChange {
    /** Created or changed in place: the row as sent (`item_key`, `data`) with the server's revision. */
    data class Put(val item: SyncItem) : LocalChange

    /** Moved to the trash ([summary]: the copy keeps trashed items without key and data). */
    data class Trash(val id: String, val at: Long, val revision: Long, val summary: Boolean) : LocalChange

    data class Restore(val id: String, val revision: Long) : LocalChange

    /** Deleted for good. */
    data class Purge(val id: String) : LocalChange
}

object SyncMerge {
    /**
     * The copy after [r]: a full answer replaces [base]; a delta (`delta: true`) is applied to it:
     * `deleted` first (only from the vault it names), then the rows of the `reset` vaults, then
     * `items` upserted by id (an item that moved between two readable vaults is in both lists), and
     * items of vaults missing from `vaults` dropped with them. Vault headers, revision, cursor, user
     * and bundle come from the answer, and so do the pending invitations: every answer, full or
     * delta, lists them in full (none from servers without them).
     *
     * Null for an answer that isn't a vault snapshot (a numeric revision ≥ 0, `vaults` and `items`;
     * only trashed rows without key and data) or a delta without the copy it was asked for.
     */
    fun apply(r: SyncResponse, base: SyncSnapshot?): SyncSnapshot? {
        val revision = (r.revision as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it >= 0 } ?: return null
        val vaults = r.vaults ?: return null
        val items = r.items ?: return null
        if (items.any { (it.itemKey == null || it.data == null) && it.deletedAt == null }) return null
        val bundle = r.bundle?.takeIf { it !is JsonNull }
        val invitations = Invitations.read(r.invitations)
        if (!r.delta) return SyncSnapshot(revision, r.cursor, r.user, bundle, vaults, items, invitations)
        base ?: return null
        val gone = r.deleted.orEmpty().map { it.vaultId to it.id }.toSet()
        val reset = r.reset.orEmpty().toSet()
        val upserted = items.map { it.id }.toSet()
        val readable = vaults.map { it.id }.toSet()
        val rows = base.items.filter { (it.vaultId to it.id) !in gone && it.vaultId !in reset && it.id !in upserted }.toMutableList()
        // An id twice in one answer (never sent by the server): the later row wins.
        rows += items.asReversed().distinctBy { it.id }.asReversed()
        rows.removeAll { it.vaultId !in readable }
        return SyncSnapshot(revision, r.cursor, r.user ?: base.user, bundle ?: base.bundle, vaults, rows, invitations)
    }

    /**
     * This device's own [change] in [vaultId], applied to the copy after the server answered
     * [vaultSeq] = the copy's number + 1 (nothing else was written there meanwhile): the row is
     * replaced or removed and the vault's number set. Revision, cursor and invitations stay (the
     * next delta from that cursor brings the row again). Null when the copy can't take it (vault or item not
     * there, a summary row to restore): sync instead.
     */
    fun applyLocal(change: LocalChange, vaultId: String, vaultSeq: Long, s: SyncSnapshot): SyncSnapshot? {
        if (s.vaults.none { it.id == vaultId }) return null
        val vaults = s.vaults.map { if (it.id == vaultId) it.copy(seq = vaultSeq) else it }
        fun at(id: String) = s.items.indexOfFirst { it.id == id && it.vaultId == vaultId }
        val items: List<SyncItem> = when (change) {
            is LocalChange.Put -> {
                val row = change.item
                if (row.vaultId != vaultId || row.itemKey == null || row.data == null) return null
                val old = s.items.firstOrNull { it.id == row.id }
                s.items.filter { it.id != row.id } + row.copy(createdAt = row.createdAt ?: old?.createdAt)
            }
            is LocalChange.Trash -> {
                val i = at(change.id).takeIf { it >= 0 } ?: return null
                val row = s.items[i].copy(deletedAt = change.at, revision = change.revision, updatedAt = change.at)
                s.items.toMutableList().apply { this[i] = if (change.summary) row.copy(itemKey = null, data = null) else row }
            }
            is LocalChange.Restore -> {
                val i = at(change.id).takeIf { it >= 0 } ?: return null
                if (s.items[i].itemKey == null || s.items[i].data == null) return null
                s.items.toMutableList().apply { this[i] = this[i].copy(deletedAt = null, revision = change.revision) }
            }
            is LocalChange.Purge -> {
                if (at(change.id) < 0) return null
                s.items.filterNot { it.id == change.id && it.vaultId == vaultId }
            }
        }
        return s.copy(vaults = vaults, items = items)
    }
}

/** When to talk to the server, from the numbers alone. */
object SyncDecision {
    /**
     * `GET /sync/revision` answered [revision] and (servers with delta sync) each vault's number:
     * does the copy at [have] lack something? Without vault numbers (older server or copy): only a
     * newer revision counts, as before. With them: any other revision (profile, bundle and
     * membership changes have no vault number; after this device's own writes were applied to the
     * copy its revision is behind, which costs one small delta), or any vault whose number differs,
     * that is new, or that is gone.
     */
    fun isStale(revision: Long, vaults: Map<String, Long>?, have: SyncPosition): Boolean {
        val mine = have.vaults
        if (vaults == null || mine == null) return revision > have.revision
        return revision != have.revision || vaults != mine
    }

    enum class AfterWrite {
        /** The copy already has the write (a retried create whose first attempt it holds). */
        Nothing,

        /** The vault's next number: only this write happened there, apply it to the copy. */
        ApplyLocally,

        /** Other writes too, numbers unknown, or numbers gone backwards (a restored server): sync. */
        Sync,
    }

    /** After this device's write into a vault: [known] = the copy's number for it, [vaultSeq] = the server's answer (`vault_seq`; null from older servers). */
    fun afterWrite(known: Long?, vaultSeq: Long?): AfterWrite = when {
        known == null || vaultSeq == null -> AfterWrite.Sync
        vaultSeq == known -> AfterWrite.Nothing
        vaultSeq == known + 1 -> AfterWrite.ApplyLocally
        else -> AfterWrite.Sync
    }

    /**
     * A live sync message (`{"type":"sync","revision","vaults"}`) against the copy at [have] (null:
     * nothing open to refresh). With [vaults] (servers with delta sync): sync when it is empty (a
     * profile or account change) or names a vault whose number is newer than the copy's (or a vault
     * the copy doesn't have), whoever wrote it; this device's own writes are already in the copy and
     * are skipped that way. Without (older servers): a newer revision, as before.
     */
    fun onLiveSync(revision: Long, vaults: Map<String, Long>?, have: SyncPosition?): Boolean {
        have ?: return false
        vaults ?: return revision > have.revision
        if (vaults.isEmpty()) return true
        val mine = have.vaults ?: return true
        return vaults.any { (id, seq) -> seq > (mine[id] ?: -1) }
    }
}

/**
 * One sync in flight and at most one waiting: a request made while a sync is already waiting joins
 * that one (it starts after the request was made, so it sees everything the request would have); a
 * request made while one runs waits for the next. Errors go to every waiter. The work runs in
 * [scope], so a caller that goes away doesn't cancel it for the others.
 */
class SyncQueue(private val scope: CoroutineScope) {
    private var running: Deferred<Unit>? = null
    private var waiting: Deferred<Unit>? = null

    suspend fun run(work: suspend () -> Unit) {
        val job = synchronized(this) { waiting ?: enqueue(work) }
        job.start()
        job.await()
    }

    /** A new run after the one in flight (or at once when idle). Called with the lock held. */
    private fun enqueue(work: suspend () -> Unit): Deferred<Unit> {
        val before = running
        lateinit var self: Deferred<Unit>
        self = scope.async(start = CoroutineStart.LAZY) {
            before?.join()
            synchronized(this@SyncQueue) {
                if (waiting === self) {
                    waiting = null
                    running = self
                }
            }
            try {
                work()
            } finally {
                synchronized(this@SyncQueue) { if (running === self) running = null }
            }
        }
        if (before == null) running = self else waiting = self
        return self
    }
}

/** The requests of a sync, apart from the transport (`get`: an authenticated GET below `/api`, returning the body). */
object DeltaSync {
    /** The `/api/config` feature of servers that answer `GET /sync?since=<cursor>`. */
    const val FEATURE = "delta_sync"

    /** `/sync`, `/sync?since=<cursor>`, and `trash=summary` for apps that never show the trash. */
    fun path(since: String?, trashSummary: Boolean): String {
        val query = buildList {
            // A cursor is base64url; anything else is escaped so it can't add parameters.
            if (!since.isNullOrEmpty()) add("since=" + URLEncoder.encode(since, Charsets.UTF_8))
            if (trashSummary) add("trash=summary")
        }
        return if (query.isEmpty()) "/sync" else "/sync?" + query.joinToString("&")
    }

    /** A `/sync` answer, or null when it isn't JSON in that shape. */
    fun parse(text: String): SyncResponse? = try {
        AppJson.decodeFromString(SyncResponse.serializer(), text)
    } catch (_: SerializationException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    fun unreadable() = UserException("The server's answer couldn't be read.")

    /**
     * The copy after a sync from [base]: since its cursor when the server does delta sync
     * ([delta]), else everything. Throws for an answer that isn't a vault snapshot; nothing is
     * stored here, so a failed or interrupted sync leaves the previous copy and cursor.
     */
    suspend fun fetch(base: SyncSnapshot?, delta: Boolean, trashSummary: Boolean, get: suspend (String) -> String): SyncSnapshot {
        val since = if (delta) base?.cursor else null
        val answer = parse(get(path(since, trashSummary))) ?: throw unreadable()
        return SyncMerge.apply(answer, if (since == null) null else base) ?: throw unreadable()
    }

    sealed interface CacheRefresh {
        /** The copy is current (`/sync/revision` matched it): nothing to fetch or write. */
        data object Current : CacheRefresh

        /** The answer was older than the copy: never downgrade, keep it. */
        data object Keep : CacheRefresh

        data class Write(val snapshot: SyncSnapshot) : CacheRefresh
    }

    /**
     * A locked account's copy brought up to date without decrypting anything: with delta sync and a
     * cursor, `/sync/revision` decides and only the changes are fetched and merged; otherwise the
     * whole `/sync` replaces the copy (when not older), as before. The copy written must carry the
     * account bundle (the next unlock needs it).
     */
    suspend fun refresh(cached: SyncSnapshot?, delta: Boolean, trashSummary: Boolean, get: suspend (String) -> String): CacheRefresh {
        if (delta && cached?.cursor != null) {
            // Network and session errors end the refresh; an unreadable answer just means "fetch".
            val text = get("/sync/revision")
            val poll = try {
                AppJson.parseToJsonElement(text) as? JsonObject
            } catch (_: SerializationException) {
                null
            }
            val revision = (poll?.get("revision") as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
            if (revision != null && !SyncDecision.isStale(revision, vaultNumbers(poll["vaults"]), cached.position)) return CacheRefresh.Current
            val next = fetch(cached, true, trashSummary, get)
            if (next.bundle !is JsonObject) throw unreadable()
            return if (next.revision < cached.revision) CacheRefresh.Keep else CacheRefresh.Write(next)
        }
        val next = fetch(null, false, trashSummary, get)
        if (next.bundle !is JsonObject) throw unreadable()
        if (cached != null && next.revision < cached.revision) return CacheRefresh.Keep
        return CacheRefresh.Write(next)
    }

    /** `{"<vault>": seq}` of `/sync/revision` and live sync messages; null when absent (older servers). */
    fun vaultNumbers(j: JsonElement?): Map<String, Long>? =
        (j as? JsonObject)?.mapNotNull { (id, v) -> (v as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.let { id to it } }?.toMap()
}
