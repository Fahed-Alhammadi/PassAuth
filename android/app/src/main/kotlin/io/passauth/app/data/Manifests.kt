package io.passauth.app.data

import io.passauth.core.VaultKey
import io.passauth.core.manifestDataHash
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/*
 * Vault manifests (ARCHITECTURE "Vault manifests"; the server side is
 * `crates/server/src/vault/manifest.rs`, the checks are the Rust core's). Every vault has a small
 * record, sealed with a key derived from the vault key, of how many items it holds (live and in the
 * trash) and a sum over their encrypted data; every write into the vault carries the next version.
 * After each sync this phone compares the items it now holds with that record and remembers the
 * highest version it saw, so a server that serves an older copy of an item, hides a new one, hides a
 * deletion or brings a deleted item back is noticed even by a phone that never saw the newer state.
 *
 * The pure parts are here (JVM-tested in ManifestsTest with the real core); VaultRepository does the
 * requests and keeps the state. Same rules as the web vault, the extension and the iOS app.
 */

/** How a vault of the copy shown stands against its manifest. */
enum class ManifestState {
    /** The vault has no manifest (and this phone never saw one for it). */
    None,

    /** The items are exactly what the manifest records. */
    Ok,

    /** The manifest is older than one this phone saw, doesn't open, or records other items: warned, no writes. */
    Unresolved,

    /**
     * A copy from this phone (shown before the server answered) with trashed rows from before
     * manifests, which carry no hash: it can't be checked until the next sync, which is asked for
     * before any write.
     */
    Unchecked,
}

/** The next manifest of a vault, as a write carries it (`manifests: [{vault_id, seq, sealed}]`, or the query of a request without a body). */
data class ManifestEntry(val vaultId: String, val seq: Long, val sealed: String) {
    fun json(): JsonObject = buildJsonObject {
        put("vault_id", vaultId)
        put("seq", seq)
        put("sealed", sealed)
    }
}

object Manifests {
    /** The `/api/config` feature of servers that keep vault manifests. */
    const val FEATURE = "vault_manifest"

    const val WARNING = "Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date."
    const val USE_SERVER_COPY = "Use the server's copy"
    const val CONFIRM_TITLE = "Use the server's copy?"
    const val CONFIRM_BODY = "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. " +
        "Do this only if you know why it changed, for example after the server was restored from a backup."
    const val READERS = "Someone who can edit this vault can review it."
    const val HELD = "This vault can't be changed until its warning is resolved."
    const val CHANGED_ELSEWHERE = "This vault changed on another device. Try again."
    const val NOT_READY = "This can't be done until every member's apps are up to date."

    /** A write is sent at most this often when the vault changed elsewhere meanwhile. */
    const val ATTEMPTS = 3

    /** The server's answer to a write whose manifest isn't the vault's next one (or is missing from a copy that still said "none"). */
    fun isConflict(e: Throwable): Boolean = e is ApiException && (e.hasCode("manifest_conflict") || e.hasCode("manifest_required"))

    fun isNotReady(e: Throwable): Boolean = e is ApiException && e.hasCode("manifest_not_ready")

    /** The hash of the data the server holds for [row], when the row can say (base64url SHA-256 of the data text). */
    fun serverHash(row: SyncItem): String? = row.servedSha256 ?: row.data?.let { manifestDataHash(it) } ?: row.dataSha256

    /** [row] can be counted: it has its data or a hash of it. */
    fun countable(row: SyncItem): Boolean = row.servedSha256 != null || row.data != null || row.dataSha256 != null

    /**
     * An item row as the core takes it: `id`, `deleted_at` and the `data` the server holds, or the
     * hash of it for a row kept without data (trash summary) or a newer copy this phone kept in
     * place of the version served ([SyncItem.servedSha256]).
     */
    fun row(i: SyncItem): JsonObject = buildJsonObject {
        put("id", i.id)
        put("deleted_at", i.deletedAt)
        when {
            i.servedSha256 != null -> put("data_sha256", i.servedSha256)
            i.data != null -> put("data", i.data)
            i.dataSha256 != null -> put("data_sha256", i.dataSha256)
        }
    }

    fun rows(items: List<SyncItem>): String = buildJsonArray { items.forEach { add(row(it)) } }.toString()

    private fun epoch(v: SyncVault) = (v.keyEpoch ?: 0).toULong()

    /** What the core said about one vault; [version]: what to remember from now on (0: nothing). */
    data class Check(val status: String, val version: Long)

    /**
     * The vault [v] of a copy against its manifest (the core's `manifestVerify`): [items] are every
     * row of that vault as the phone holds them after applying the sync answer, [remembered] the
     * highest version this phone saw (null: none). Anything thrown (malformed rows, an id twice)
     * counts as a mismatch.
     */
    fun verify(key: VaultKey, v: SyncVault, remembered: Long?, items: List<SyncItem>): Check = try {
        val c = key.manifestVerify(v.id, epoch(v), (v.manifestSeq ?: 0).coerceAtLeast(0).toULong(), v.manifest, remembered?.toULong(), rows(items))
        Check(c.status, c.version.toLong())
    } catch (_: Exception) {
        Check("mismatch", remembered ?: 0)
    }

    /** What a whole copy's check gave: each opened vault's state, the versions to remember, and the vaults that couldn't be counted. */
    data class Judged(val states: Map<String, ManifestState>, val remember: Map<String, Long>, val incomplete: Set<String>)

    /**
     * Every vault of a copy whose key is open ([keys]) checked against its manifest. A vault that
     * has a manifest, or that this phone remembers one of ([memory]), is always checked, whatever
     * features the server lists (a server that stops listing [FEATURE] can't switch the check
     * off); a vault with neither has nothing to check (the core's "none", decided here without
     * handing it the rows). [incompleteIsMismatch]: the copy is a whole answer from the server, so
     * every row has to be countable.
     */
    fun judge(
        vaults: List<SyncVault>,
        items: List<SyncItem>,
        keys: Map<String, VaultKey>,
        memory: Map<String, Long>,
        incompleteIsMismatch: Boolean = false,
    ): Judged {
        val byVault = items.groupBy { it.vaultId }
        val states = mutableMapOf<String, ManifestState>()
        val remember = mutableMapOf<String, Long>()
        val incomplete = mutableSetOf<String>()
        for (v in vaults) {
            val key = keys[v.id] ?: continue
            val remembered = memory[v.id]
            if ((v.manifestSeq ?: 0) <= 0 && remembered == null) {
                states[v.id] = ManifestState.None
                continue
            }
            val check = verify(key, v, remembered, byVault[v.id].orEmpty())
            states[v.id] = when (check.status) {
                "none" -> ManifestState.None
                "ok" -> {
                    if (check.version > 0) remember[v.id] = check.version
                    ManifestState.Ok
                }
                "incomplete" -> if (incompleteIsMismatch) ManifestState.Unresolved else {
                    incomplete += v.id
                    ManifestState.Unchecked
                }
                else -> ManifestState.Unresolved
            }
        }
        return Judged(states, remember, incomplete)
    }

    /**
     * The manifest entry a write into [v] carries: null when the vault has none (the write goes as
     * before). [removed]: the affected rows as the copy holds them before the write; [added]: as
     * they are after it (with the exact `data` sent). Only for a vault whose state is [ManifestState.Ok];
     * [UserException] ([HELD]) otherwise.
     */
    fun next(key: VaultKey, v: SyncVault, state: ManifestState?, removed: List<SyncItem>, added: List<SyncItem>): ManifestEntry? {
        val seq = v.manifestSeq ?: 0
        if (seq <= 0 && state != ManifestState.Unresolved && state != ManifestState.Unchecked) return null
        val sealed = v.manifest
        if (state != ManifestState.Ok || sealed == null || removed.any { !countable(it) }) throw UserException(HELD)
        val w = try {
            key.manifestNext(v.id, epoch(v), seq.toULong(), sealed, rows(removed), rows(added))
        } catch (_: Exception) {
            throw UserException(HELD)
        }
        return ManifestEntry(v.id, w.seq.toLong(), w.sealed)
    }

    /** The query of a request without a body (trash): the item's revision and the vault's next manifest; empty for a vault without one. */
    fun query(entry: ManifestEntry?, revision: Long?): String {
        entry ?: return ""
        val parts = buildList {
            if (revision != null) add("revision=$revision")
            add("manifest_seq=${entry.seq}")
            // base64url: nothing to escape, but nothing else may add a parameter.
            add("manifest=" + java.net.URLEncoder.encode(entry.sealed, "UTF-8"))
        }
        return "?" + parts.joinToString("&")
    }

    /** `manifest_seq` of a write's answer: the vault's manifest version after it (null: an older server). */
    fun answered(answer: kotlinx.serialization.json.JsonElement?): Long? =
        ((answer as? JsonObject)?.get("manifest_seq") as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

    /**
     * This device's write with manifest [sent] is the vault's latest: the copy may take it without
     * asking the server. Without one sent, only while the answer says the vault still has none
     * (a manifest that appeared meanwhile is fetched and checked by a sync).
     */
    fun mayApplyLocally(sent: ManifestEntry?, answer: kotlinx.serialization.json.JsonElement?): Boolean =
        if (sent == null) (answered(answer) ?: 0) <= 0 else answered(answer) == sent.seq

    /** How many trashed items one purge request names: at most 250, and never more than the server's `limits.max_import_items`. */
    fun purgeChunk(maxImportItems: Int?): Int = minOf(250, maxImportItems?.takeIf { it > 0 } ?: 250)

    /**
     * May this phone start [v]'s first manifest now? The server keeps manifests and says every
     * member's apps do ([SyncVault.manifestOk]), the vault has none and this phone never saw one,
     * the account can write to it, and every row can be counted.
     */
    fun mayStart(v: SyncVault, state: ManifestState?, role: Role?, listed: Boolean, remembered: Long?, rows: List<SyncItem>): Boolean =
        listed && state == ManifestState.None && (v.manifestSeq ?: 0) == 0L && v.manifestOk == true && v.seq != null &&
            role != null && role != Role.Read && remembered == null && rows.all(::countable)

    /** The version of a new baseline: above the vault row's and above everything this phone remembers. */
    fun baselineSeq(rowSeq: Long?, remembered: Long?): Long = maxOf(rowSeq ?: 0, remembered ?: 0) + 1

    /**
     * `PUT /vaults/{id}/manifest`: the vault's first manifest ([seq] 1 on a vault without one) or a
     * new baseline, for exactly [rows] (every row of the vault in the copy), pinned to the vault's
     * number of the sync the copy came from. Null when the copy has no number for the vault.
     */
    fun startBody(key: VaultKey, v: SyncVault, seq: Long, rows: List<SyncItem>): Pair<JsonObject, ManifestEntry>? {
        val vaultSeq = v.seq ?: return null
        val sealed = key.manifestStart(v.id, epoch(v), seq.toULong(), rows(rows))
        return buildJsonObject {
            put("base_seq", (v.manifestSeq ?: 0).coerceAtLeast(0))
            put("seq", seq)
            put("sealed", sealed)
            put("vault_seq", vaultSeq)
        } to ManifestEntry(v.id, seq, sealed)
    }

    /**
     * The trashed rows of a vault the server's trash retention says are due ([trashDays] > 0, by the
     * server's own clock [serverTime]): for a vault with a manifest the apps delete them, not the server.
     */
    fun dueTrash(rows: List<SyncItem>, serverTime: Long?, trashDays: Long?): List<SyncItem> {
        if (serverTime == null || trashDays == null || trashDays <= 0) return emptyList()
        val before = serverTime - trashDays * 86_400
        return rows.filter { it.deletedAt != null && it.deletedAt < before }
    }

    /** `POST /vaults/{id}/trash/purge`: [due] deleted for good as one vault write carrying [entry]. */
    fun purgeBody(due: List<SyncItem>, entry: ManifestEntry): JsonObject = buildJsonObject {
        put("items", buildJsonArray {
            for (r in due) add(buildJsonObject {
                put("id", r.id)
                r.revision?.let { put("revision", it) }
            })
        })
        put("manifests", JsonArray(listOf(entry.json())))
    }

    /**
     * The manifest a key replacement carries: made with the new key for the new epoch (the old one's
     * + 1) over the re-encrypted [rows], as the vault's next version. Null for a vault without one.
     */
    fun rotationEntry(newKey: VaultKey, v: SyncVault, rows: List<SyncItem>): ManifestEntry? {
        val seq = v.manifestSeq ?: 0
        if (seq <= 0) return null
        val sealed = newKey.manifestStart(v.id, epoch(v) + 1u, (seq + 1).toULong(), rows(rows))
        return ManifestEntry(v.id, seq + 1, sealed)
    }

    // ------------------------------------------------------------ device memory

    /** The remembered versions from their stored JSON (`{"<vault id>": version}`); anything malformed is left out. */
    fun decodeMemory(text: String?): Map<String, Long> {
        val o = text?.let { runCatching { AppJson.parseToJsonElement(it) as? JsonObject }.getOrNull() } ?: return emptyMap()
        return o.mapNotNull { (id, v) -> (v as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it >= 1 }?.let { id to it } }.toMap()
    }

    fun encodeMemory(m: Map<String, Long>): String = JsonObject(m.mapValues { JsonPrimitive(it.value) }).toString()

    /** [memory] with [updates]: never lowered, and vaults that are gone stay (a server could hide a vault and show it again). */
    fun merged(memory: Map<String, Long>, updates: Map<String, Long>): Map<String, Long> {
        val out = memory.toMutableMap()
        for ((id, v) in updates) if (v >= 1) out[id] = maxOf(v, out[id] ?: v)
        return out
    }
}

/**
 * Part S: this app only uses servers that sign shares (`/api/config` feature `signed_sharing`,
 * every server since 0.12.0). A server that doesn't list it could otherwise switch the checks off
 * on a phone that has no memory yet.
 */
object ServerSupport {
    const val UPDATE_SERVER = "Update your PassAuth server to keep using this app."

    /** A server whose `/api/config` was read ([features]): usable only when it lists signed sharing (servers before API 2 list nothing). */
    fun supported(features: List<String>): Boolean = SignedSharing.FEATURE in features
}

/** The account's server is too old for this app ([ServerSupport]): nothing is asked of it or taken from it. */
class ServerTooOldException : UserException(ServerSupport.UPDATE_SERVER)
