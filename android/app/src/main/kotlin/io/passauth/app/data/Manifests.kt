package io.passauth.app.data

import io.passauth.core.VaultKey
import io.passauth.core.manifestDataHash
import io.passauth.core.manifestLink
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
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

    /**
     * The server's own whole answer has a manifest that is older than one this phone saw, isn't on
     * the history this phone saw, doesn't open, or records other items: warned, no writes.
     */
    Unresolved,

    /**
     * Not checked against an answer of the server yet: a copy from this phone (shown before the
     * server answered, or while it can't be reached) that doesn't pass, can't be counted, or is
     * more than one step ahead of what this phone remembers; or what this phone remembers can't be
     * read right now. No warning (a warning only ever comes from the server's answer); the next
     * sync decides, and it is asked for before any write.
     */
    Unchecked,
}

/** What this phone remembers of a vault's manifest: the version and the link of the last one it checked "ok" or wrote itself. */
data class ManifestMark(val version: Long, val link: String)

/**
 * The next manifest of a vault, as a write carries it (`manifests: [{vault_id, seq, prev, sealed}]`,
 * or the query of a request without a body). [prev]: the link of the manifest it replaces; [link]:
 * its own, remembered with [seq] once the server stored it.
 */
data class ManifestEntry(val vaultId: String, val seq: Long, val prev: String, val sealed: String, val link: String) {
    fun json(): JsonObject = buildJsonObject {
        put("vault_id", vaultId)
        put("seq", seq)
        put("prev", prev)
        put("sealed", sealed)
    }

    val mark: ManifestMark get() = ManifestMark(seq, link)
}

/** The server couldn't be asked for a vault's manifest log (no answer, 5xx, 429): the sync answer isn't checked, so it isn't taken. */
class ManifestLogUnavailable(cause: Throwable? = null) : java.io.IOException("The vault's record of changes couldn't be loaded.", cause)

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

    /** `GET /vaults/{id}/manifest-log` is asked at most this often for one check (more pages: the log doesn't connect). */
    const val LOG_REQUESTS = 5

    /** The highest whole number every client and the server count with (2^53 − 1). */
    const val MAX_NUMBER = 9_007_199_254_740_991L

    /** The server's answer to a write whose manifest isn't the vault's next one (or is missing from a copy that still said "none"). */
    fun isConflict(e: Throwable): Boolean = e is ApiException && (e.hasCode("manifest_conflict") || e.hasCode("manifest_required"))

    fun isNotReady(e: Throwable): Boolean = e is ApiException && e.hasCode("manifest_not_ready")

    /** The hash of the data the server holds for [row], when the row can say (base64url SHA-256 of the data text). */
    fun serverHash(row: SyncItem): String? = row.servedSha256 ?: row.data?.let { manifestDataHash(it) } ?: row.dataSha256

    /** [row] can be counted: it has its data or a hash of it. */
    fun countable(row: SyncItem): Boolean = row.servedSha256 != null || row.data != null || row.dataSha256 != null

    /**
     * An item row as the core takes it, built from the parsed fields only: `id`, `deleted_at` (the
     * one thing that says live or trashed) and the `data` the server holds, or the hash of it for a
     * row kept without data (trash summary) or a newer copy this phone kept in place of the version
     * served ([SyncItem.servedSha256]).
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

    private fun seqOf(v: SyncVault) = (v.manifestSeq ?: 0).coerceAtLeast(0)

    /** A link as it travels: base64url of 32 bytes, 43 characters. */
    fun isLink(s: String?): Boolean = s != null && s.length == 43 && s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }

    /**
     * The link of the manifest the row [v] carries (the core's `manifestLink`: nothing is opened, so
     * it also works for a manifest this phone can't read); null for a vault without one, or a row
     * that doesn't carry all three fields.
     */
    fun linkOf(v: SyncVault): String? {
        val seq = seqOf(v)
        val sealed = v.manifest ?: return null
        val prev = v.manifestPrev ?: return null
        if (seq <= 0) return null
        return try {
            manifestLink(seq.toULong(), prev, sealed)
        } catch (_: Exception) {
            null
        }
    }

    /** What the core said about one vault; [mark]: what to remember from now on (null: nothing). */
    data class Check(val status: String, val mark: ManifestMark?) {
        val version: Long get() = mark?.version ?: 0
    }

    /**
     * The vault [v] of a copy against its manifest (the core's `manifestVerify`): [items] are every
     * row of that vault as the phone holds them after applying the sync answer, [remembered] what
     * this phone remembers of it (null: nothing), [log] the entries of the vault's manifest log (the
     * JSON array as the server sent it) after a "need_log". Anything thrown (malformed rows, an id
     * twice, a `deleted_at` that is no time) counts as a mismatch.
     */
    fun verify(key: VaultKey, v: SyncVault, remembered: ManifestMark?, items: List<SyncItem>, log: String? = null): Check = try {
        val c = key.manifestVerify(
            v.id, epoch(v), seqOf(v).toULong(), v.manifestPrev, v.manifest,
            remembered?.version?.toULong(), remembered?.link, log, rows(items),
        )
        val link = c.link
        Check(c.status, if (c.version > 0uL && link != null) ManifestMark(c.version.toLong(), link) else null)
    } catch (_: Exception) {
        Check("mismatch", remembered)
    }

    /**
     * What a whole copy's check gave: each opened vault's state and the marks to remember. [failed]:
     * vaults that don't pass (rollback or mismatch); [incomplete]: vaults that couldn't be counted;
     * [unlogged]: vaults more than one step ahead of this phone's memory whose log wasn't asked for
     * (a copy from this phone). The last three are [ManifestState.Unresolved] in a whole answer of
     * the server and [ManifestState.Unchecked] otherwise.
     */
    data class Judged(
        val states: Map<String, ManifestState>,
        val remember: Map<String, ManifestMark>,
        val incomplete: Set<String> = emptySet(),
        val failed: Set<String> = emptySet(),
        val unlogged: Set<String> = emptySet(),
    ) {
        /** Vaults whose verdict needs the server's whole answer before it counts. */
        val undecided: Set<String> get() = incomplete + failed
    }

    /**
     * Every vault of a copy whose key is open ([keys]) checked against its manifest. A vault that
     * has a manifest, or that this phone remembers one of ([memory]), is always checked, whatever
     * features the server lists (a server that stops listing [FEATURE] can't switch the check
     * off); a vault with neither has nothing to check (the core's "none", decided here without
     * handing it the rows).
     *
     * [whole]: the copy is a whole answer from the server, so its verdict stands: a vault that
     * doesn't pass or can't be counted is [ManifestState.Unresolved] (the warning). Otherwise (a
     * delta on this phone's copy, or the copy itself) such a vault is only [ManifestState.Unchecked]:
     * a warning is raised from the server's whole answer alone.
     *
     * [hidden]: vaults with a live row that doesn't open; with a manifest that would pass, that is a
     * mismatch (an item hidden behind a record that counts it).
     *
     * [log]: asks the server for a vault's manifest log after the version given (the entries as a
     * JSON array; null: the server refused, or the log doesn't connect: a mismatch). Called for a
     * vault more than one step ahead of [memory]; it throws [ManifestLogUnavailable] when the server
     * can't be asked, and so does this: the answer isn't checked, nothing of it may be kept. Null
     * for a copy from this phone (nothing is asked; such a vault is [ManifestState.Unchecked]).
     */
    suspend fun judge(
        vaults: List<SyncVault>,
        items: List<SyncItem>,
        keys: Map<String, VaultKey>,
        memory: Map<String, ManifestMark>,
        whole: Boolean = false,
        hidden: Set<String> = emptySet(),
        log: (suspend (vaultId: String, after: Long) -> String?)? = null,
    ): Judged {
        val byVault = items.groupBy { it.vaultId }
        val states = mutableMapOf<String, ManifestState>()
        val remember = mutableMapOf<String, ManifestMark>()
        val incomplete = mutableSetOf<String>()
        val failed = mutableSetOf<String>()
        val unlogged = mutableSetOf<String>()
        val undecided = if (whole) ManifestState.Unresolved else ManifestState.Unchecked
        for (v in vaults) {
            val key = keys[v.id] ?: continue
            val remembered = memory[v.id]
            if (seqOf(v) <= 0 && remembered == null) {
                states[v.id] = ManifestState.None
                continue
            }
            val rows = byVault[v.id].orEmpty()
            var check = verify(key, v, remembered, rows)
            if (check.status == "need_log") {
                if (log == null) {
                    unlogged += v.id
                    states[v.id] = ManifestState.Unchecked
                    continue
                }
                // The log's entries are trusted for nothing beyond what the hashes prove; none (refused, unreadable, too long) proves nothing.
                val entries = log(v.id, remembered?.version ?: 0)
                check = if (entries == null) Check("mismatch", remembered) else verify(key, v, remembered, rows, entries)
                if (check.status == "need_log") check = Check("mismatch", remembered)
            }
            states[v.id] = when (check.status) {
                "none" -> ManifestState.None
                "ok" -> if (v.id in hidden) {
                    failed += v.id
                    undecided
                } else {
                    check.mark?.let { remember[v.id] = it }
                    ManifestState.Ok
                }
                "incomplete" -> {
                    incomplete += v.id
                    undecided
                }
                else -> {
                    failed += v.id
                    undecided
                }
            }
        }
        return Judged(states, remember, incomplete, failed, unlogged)
    }

    // ------------------------------------------------------------ the log

    /** `GET /vaults/{id}/manifest-log?after=<seq>`. */
    fun logPath(vaultId: String, after: Long): String =
        "/vaults/" + java.net.URLEncoder.encode(vaultId, "UTF-8").replace("+", "%20") + "/manifest-log?after=" + after.coerceAtLeast(0)

    /**
     * A vault's manifest log after version [after], as the JSON array the core takes: [page] asks
     * the server (`{entries: [{seq, prev, digest}], more}`), again from the last entry while it says
     * `more`, at most [LOG_REQUESTS] times. Null when the answer settles it as "doesn't connect": the
     * server refused (404 or 400), the answer isn't in that shape, or there are more pages than
     * that. [ManifestLogUnavailable] when the server couldn't be asked (no answer, any other error):
     * nothing is known then, and nothing may be decided.
     */
    suspend fun fetchLog(after: Long, page: suspend (after: Long) -> JsonElement?): String? {
        val all = mutableListOf<JsonElement>()
        var from = after
        repeat(LOG_REQUESTS) {
            val answer = try {
                page(from)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: ApiException) {
                if (e.status == 404 || e.status == 400) return null
                throw ManifestLogUnavailable(e)
            } catch (e: Exception) {
                throw ManifestLogUnavailable(e)
            }
            val o = answer as? JsonObject ?: return null
            val entries = o["entries"] as? JsonArray ?: return null
            all.addAll(entries)
            val more = (o["more"] as? JsonPrimitive)?.takeIf { !it.isString }?.content
            if (more != "true") return JsonArray(all).toString()
            // More follows: from the last entry, which has to be further on (else the server would be asked the same again).
            val last = ((entries.lastOrNull() as? JsonObject)?.get("seq") as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: return null
            if (last <= from || last > MAX_NUMBER) return null
            from = last
        }
        return null
    }

    // ------------------------------------------------------------- writes

    /**
     * The manifest entry a write into [v] carries: null when the vault has none (the write goes as
     * before). [removed]: the affected rows as the copy holds them before the write; [added]: as
     * they are after it (with the exact `data` sent). Only for a vault whose state is [ManifestState.Ok];
     * [UserException] ([HELD]) otherwise.
     */
    fun next(key: VaultKey, v: SyncVault, state: ManifestState?, removed: List<SyncItem>, added: List<SyncItem>): ManifestEntry? {
        val seq = seqOf(v)
        if (seq <= 0 && state != ManifestState.Unresolved && state != ManifestState.Unchecked) return null
        val sealed = v.manifest
        val prev = v.manifestPrev
        if (state != ManifestState.Ok || sealed == null || prev == null || removed.any { !countable(it) }) throw UserException(HELD)
        val w = try {
            key.manifestNext(v.id, epoch(v), seq.toULong(), prev, sealed, rows(removed), rows(added))
        } catch (_: Exception) {
            throw UserException(HELD)
        }
        return ManifestEntry(v.id, w.seq.toLong(), w.prev, w.sealed, w.link)
    }

    /** The query of a request without a body (trash): the item's revision and the vault's next manifest (version, the link it replaces, sealed text: all three or none); empty for a vault without one. */
    fun query(entry: ManifestEntry?, revision: Long?): String {
        entry ?: return ""
        val parts = buildList {
            if (revision != null) add("revision=$revision")
            add("manifest_seq=${entry.seq}")
            // base64url: nothing to escape, but nothing else may add a parameter.
            add("manifest_prev=" + java.net.URLEncoder.encode(entry.prev, "UTF-8"))
            add("manifest=" + java.net.URLEncoder.encode(entry.sealed, "UTF-8"))
        }
        return "?" + parts.joinToString("&")
    }

    /** `manifest_seq` of a write's answer: the vault's manifest version after it (null: an older server). */
    fun answered(answer: JsonElement?): Long? =
        ((answer as? JsonObject)?.get("manifest_seq") as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

    /** The server stored exactly the manifest [sent] with this write: the vault's rows are the copy's with this write, and its manifest is this one. */
    fun stored(sent: ManifestEntry?, answer: JsonElement?): Boolean = sent != null && answered(answer) == sent.seq

    /**
     * This device's write with manifest [sent] is the vault's latest: the copy may take it without
     * asking the server. Without one sent, only while the answer says the vault still has none
     * (a manifest that appeared meanwhile is fetched and checked by a sync).
     */
    fun mayApplyLocally(sent: ManifestEntry?, answer: JsonElement?): Boolean =
        if (sent == null) (answered(answer) ?: 0) <= 0 else answered(answer) == sent.seq

    /** How many trashed items one purge request names: at most 250, and never more than the server's `limits.max_import_items`. */
    fun purgeChunk(maxImportItems: Int?): Int = minOf(250, maxImportItems?.takeIf { it > 0 } ?: 250)

    /**
     * May this phone start [v]'s first manifest now? The server keeps manifests and says every
     * member's apps do ([SyncVault.manifestOk]), the vault has none and this phone never saw one,
     * the account can write to it, every row can be counted, and none of its items is marked as
     * served in an older version ([marked]: a first record must not be made over a copy the server
     * rolled back).
     */
    fun mayStart(v: SyncVault, state: ManifestState?, role: Role?, listed: Boolean, remembered: ManifestMark?, rows: List<SyncItem>, marked: Set<String> = emptySet()): Boolean =
        listed && state == ManifestState.None && seqOf(v) == 0L && v.manifestOk == true && v.seq != null &&
            role != null && role != Role.Read && remembered == null && rows.all(::countable) &&
            rows.none { it.servedSha256 != null || it.id in marked }

    /** The version of a new baseline: above the vault row's and above everything this phone remembers. */
    fun baselineSeq(rowSeq: Long?, remembered: Long?): Long = maxOf(rowSeq ?: 0, remembered ?: 0, 0).coerceAtMost(MAX_NUMBER - 1) + 1

    /**
     * `PUT /vaults/{id}/manifest`: the vault's first manifest ([seq] 1 on a vault without one) or a
     * new baseline, for exactly [rows] (every row of the vault in the copy), pinned to the vault's
     * number of the sync the copy came from, and naming the manifest the row carries now as the one
     * it replaces (whatever it is: a baseline is built on what the server shows; none when the row
     * doesn't carry all three fields). Null when the copy has no number for the vault.
     */
    fun startBody(key: VaultKey, v: SyncVault, seq: Long, rows: List<SyncItem>): Pair<JsonObject, ManifestEntry>? {
        val vaultSeq = v.seq ?: return null
        val prev = linkOf(v)
        val w = key.manifestStart(v.id, epoch(v), seq.toULong(), prev, rows(rows))
        return buildJsonObject {
            put("base_seq", seqOf(v))
            put("seq", w.seq.toLong())
            put("prev", w.prev)
            put("sealed", w.sealed)
            put("vault_seq", vaultSeq)
        } to ManifestEntry(v.id, w.seq.toLong(), w.prev, w.sealed, w.link)
    }

    /**
     * The trashed rows of a vault this phone may delete for good. Neither the server's clock nor a
     * row's `deleted_at` is covered by the manifest, so both are bounded by what this phone saw:
     *
     * - the server's rule: retention is on ([trashDays] ≥ 1) and the row has been in the trash
     *   longer than that by the server's own clock ([serverTime]);
     * - this phone has itself seen the row in the trash for at least that long by its own clock
     *   ([seen]: when it first saw each item trashed, [TrashSeen]; [deviceNow]);
     * - the server's clock is within a day of this phone's.
     *
     * Numbers that don't fit give nothing (never an overflow).
     */
    fun dueTrash(rows: List<SyncItem>, serverTime: Long?, trashDays: Long?, seen: Map<String, Long>, deviceNow: Long): List<SyncItem> {
        if (serverTime == null || trashDays == null || trashDays < 1) return emptyList()
        if (serverTime < 0 || serverTime > MAX_NUMBER || trashDays > MAX_TRASH_DAYS || deviceNow < 0 || deviceNow > MAX_NUMBER) return emptyList()
        if (kotlin.math.abs(serverTime - deviceNow) > CLOCK_SLACK_SECONDS) return emptyList()
        val span = trashDays * 86_400
        val before = serverTime - span
        val seenBefore = deviceNow - span
        return rows.filter { r ->
            val at = r.deletedAt
            val first = seen[r.id]
            at != null && at > 0 && at < before && first != null && first <= seenBefore
        }
    }

    /** The server's clock may differ from this phone's by a day at most for old trash to be deleted. */
    const val CLOCK_SLACK_SECONDS = 86_400L

    /** A retention above this (a thousand times the server's highest setting) is no retention this app acts on. */
    const val MAX_TRASH_DAYS = 3_650_000L

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
     * + 1) over the re-encrypted [rows], as the vault's next version, naming the manifest it
     * replaces (sealed under the old key: the chain crosses keys by hashes alone). Null for a vault
     * without one.
     */
    fun rotationEntry(newKey: VaultKey, v: SyncVault, rows: List<SyncItem>): ManifestEntry? {
        val seq = seqOf(v)
        if (seq <= 0) return null
        if (seq >= MAX_NUMBER) throw UserException(HELD)
        val prev = linkOf(v) ?: throw UserException(HELD)
        val w = newKey.manifestStart(v.id, epoch(v) + 1u, (seq + 1).toULong(), prev, rows(rows))
        return ManifestEntry(v.id, w.seq.toLong(), w.prev, w.sealed, w.link)
    }

    /**
     * The rows a key replacement re-encrypts. The app's copy keeps trashed items without their data,
     * so every item is asked for again in full ([full]: that answer's rows of the vault); they are
     * used only when they are, row by row, the copy this phone checked ([copy]: the vault's rows as
     * shown, checked against the manifest and the item edit counters): the same ids, the same
     * place (live or trashed), the same data (by its hash where the copy has none). A newer copy
     * this phone kept in place of an older version served ([SyncItem.servedSha256]) is what gets
     * re-encrypted, under the server's revision. Null when the answer differs from the copy
     * (something changed meanwhile: sync and start again).
     */
    fun rotationRows(copy: List<SyncItem>, full: List<SyncItem>): List<SyncItem>? {
        if (copy.size != full.size) return null
        val mine = copy.associateBy { it.id }
        if (mine.size != copy.size) return null
        val out = mutableListOf<SyncItem>()
        for (r in full) {
            val c = mine[r.id] ?: return null
            if ((c.deletedAt == null) != (r.deletedAt == null)) return null
            val data = r.data ?: return null
            r.itemKey ?: return null
            val hash = manifestDataHash(data)
            out += when {
                c.servedSha256 != null -> if (c.servedSha256 == hash && c.data != null && c.itemKey != null) r.copy(itemKey = c.itemKey, data = c.data) else return null
                c.data != null -> if (c.data == data && c.itemKey == r.itemKey) r else return null
                else -> if (c.dataSha256 == hash) r else return null
            }
        }
        return if (out.map { it.id }.toSet().size == out.size) out else null
    }

    // ------------------------------------------------------------ device memory

    /**
     * What this phone remembers from its stored JSON (`{"<vault id>": {"version": n, "link": "…"}}`).
     * An entry that isn't a version ≥ 1 with a link (the first version's bare number included) is
     * "nothing remembered": half a memory is never handed to the core.
     */
    fun decodeMemory(text: String?): Map<String, ManifestMark> {
        val o = text?.let { runCatching { AppJson.parseToJsonElement(it) as? JsonObject }.getOrNull() } ?: return emptyMap()
        return o.mapNotNull { (id, v) ->
            val e = v as? JsonObject ?: return@mapNotNull null
            val version = (e["version"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it in 1..MAX_NUMBER } ?: return@mapNotNull null
            val link = (e["link"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf(::isLink) ?: return@mapNotNull null
            id to ManifestMark(version, link)
        }.toMap()
    }

    fun encodeMemory(m: Map<String, ManifestMark>): String = JsonObject(m.mapValues { (_, mark) -> buildJsonObject { put("version", mark.version); put("link", mark.link) } }).toString()

    /**
     * [memory] with [updates]: the higher version wins; at the same version the one already there
     * stays (a link is never replaced at its version: if the two differ, one of them is on another
     * history and the next check says so). Vaults that are gone stay (a server could hide a vault
     * and show it again).
     */
    fun merged(memory: Map<String, ManifestMark>, updates: Map<String, ManifestMark>): Map<String, ManifestMark> {
        val out = memory.toMutableMap()
        for ((id, m) in updates) {
            if (m.version < 1 || m.version > MAX_NUMBER || !isLink(m.link)) continue
            val have = out[id]
            if (have == null || m.version > have.version) out[id] = m
        }
        return out
    }
}

/**
 * When this phone first saw each item in the trash (item id → its own clock, unix seconds), kept
 * per account next to the offline copy. Old trash is deleted for good only after this phone has
 * itself watched an item sit in the trash for the server's retention ([Manifests.dueTrash]): the
 * time a row says it was trashed at is the server's word alone.
 */
object TrashSeen {
    fun decode(text: String?): Map<String, Long> {
        val o = text?.let { runCatching { AppJson.parseToJsonElement(it) as? JsonObject }.getOrNull() } ?: return emptyMap()
        return o.mapNotNull { (id, v) -> (v as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it in 0..Manifests.MAX_NUMBER }?.let { id to it } }.toMap()
    }

    fun encode(m: Map<String, Long>): String = JsonObject(m.mapValues { JsonPrimitive(it.value) }).toString()

    /**
     * The memory for the copy's [rows] at [now]: an item seen in the trash for the first time gets
     * [now] (one already there keeps its time, unless that lies in the future: a clock set back);
     * one that is live again or gone from the copy is forgotten (seen trashed again later, it
     * starts over).
     */
    fun updated(memory: Map<String, Long>, rows: List<SyncItem>, now: Long): Map<String, Long> {
        val out = LinkedHashMap<String, Long>()
        for (r in rows) {
            if (r.deletedAt == null) continue
            val first = memory[r.id]
            out[r.id] = if (first == null || first > now) now else first
        }
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

    /**
     * Nothing is known about the server (no feature list kept from before) and it can't say now:
     * never "probably fine". A server could otherwise get around the check by breaking its own
     * `/api/config`.
     */
    fun cantConnect() = UserException(CANT_CONNECT)

    const val CANT_CONNECT = "PassAuth couldn't reach your server. Check the connection and try again."

    /**
     * What decides for a server whose `/api/config` was asked now ([asked]: null when it couldn't be
     * read) with the list kept from before ([kept]: null when none): the answer when there is one,
     * else the kept list, else nothing ([cantConnect]).
     */
    fun decide(asked: List<String>?, kept: List<String>?): List<String> = asked ?: kept ?: throw cantConnect()
}

/** The account's server is too old for this app ([ServerSupport]): nothing is asked of it or taken from it. */
class ServerTooOldException : UserException(ServerSupport.UPDATE_SERVER)
