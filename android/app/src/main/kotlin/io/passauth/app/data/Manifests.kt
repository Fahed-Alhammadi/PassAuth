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
     * The items are exactly what the manifest records, but one of them doesn't open on this phone
     * (its key or data doesn't decrypt, [ItemOpening] case c): a notice ([Manifests.UNOPENABLE]) and
     * the item listed so it can be deleted for good. The manifest itself passed, so the vault is
     * written to like one that is [Ok] (review round 3, rule T1: holding it only pushed people to
     * delete the item).
     */
    Unopenable,

    /**
     * Not checked against an answer of the server yet: a copy from this phone (shown before the
     * server answered, or while it can't be reached) that doesn't pass, can't be counted, or is
     * more than one step ahead of what this phone remembers; or what this phone remembers can't be
     * read right now. No warning (a warning only ever comes from the server's answer); the next
     * sync decides, and it is asked for before any write.
     */
    Unchecked,
}

/** What this phone remembers of a vault's manifest: the version and the link of the last one it checked "ok", wrote itself or accepted. */
data class ManifestMark(val version: Long, val link: String)

/**
 * One vault's entry in this phone's memory: [mark] (null: nothing remembered) and [accepts], how
 * often the user replaced it with "Use the server's copy" ([Manifests.replaced]). The counter orders
 * two copies of the memory before the version does, so a copy from before an acceptance (a higher
 * version) never brings the old mark back.
 */
data class Remembered(
    val mark: ManifestMark?,
    val accepts: Long = 0,
    /**
     * The user accepted that the server shows no manifest for this vault any more
     * ([Manifests.CONFIRM_NO_RECORD]): nothing is checked for it until one exists again, and the
     * vault says so ([Manifests.NOT_CHECKED]). Only on an entry without a [mark]; gone with the next mark.
     */
    val notChecked: Boolean = false,
)

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

    /** A write into a vault this phone couldn't check yet (no warning shows): the web vault's words. */
    const val UNCHECKED = "PassAuth couldn't check this vault with your server yet. Try again in a moment."

    /** The emergency access view of a vault that has no manifest: nothing could be checked. */
    const val VIEW_UNCHECKED = "This vault has no record of changes yet, so PassAuth couldn't check that nothing is missing or out of date."

    /** "Use the server's copy" when the server shows no manifest for a vault this phone remembers one of (rule T3). */
    const val CONFIRM_NO_RECORD = "Your server no longer shows a record of changes for this vault. If you continue, PassAuth stops checking " +
        "this vault for missing, restored or out-of-date items until a new record is started."

    /** The quiet note of a vault after that, until it has a manifest again. */
    const val NOT_CHECKED = "This vault isn't being checked for missing or restored items."

    // Items that don't open (rule S2; review round 3, rule T1: a notice, no hold, no instruction to delete).
    const val UNOPENABLE_ITEM = "Item that can't be opened"
    const val UNOPENABLE = "An item in this vault can't be opened."
    const val DELETE_FOR_GOOD = "Delete for good"
    const val DELETE_FOR_GOOD_CONFIRM = "This item can't be opened on this device. It may still open on another device or in a newer version of PassAuth. " +
        "Deleting it removes it for everyone."

    /** "Delete for good" of an item of a newer app ([ItemOpening.NEWER_ITEM]): owners and admins only ([mayDeleteNewer]). */
    const val DELETE_NEWER_CONFIRM = "This item was saved by a newer version of PassAuth. Update PassAuth to see it. Deleting it removes it for everyone."

    /** A new vault key needs every item read and encrypted again: not while this app can't read one of them. */
    const val NEWER_NO_NEW_KEY = "This vault has items from a newer version of PassAuth. Update PassAuth, or have an owner delete them, then try again."

    /**
     * May a member with [role] delete an item of a newer app for good? Only the vault's owners and
     * admins (the personal vault's owner included), and, as for an item that can't be opened, not
     * in a vault whose warning stands ([state]: reviewed first; the write itself needs a manifest
     * that passed, [next]). Members who can only write or read see the row without an action.
     */
    fun mayDeleteNewer(role: Role?, state: ManifestState?): Boolean =
        (role == Role.Owner || role == Role.Admin) && state != ManifestState.Unresolved

    /** A new vault key needs every item encrypted again: not while one of them doesn't open here. */
    const val UNOPENABLE_NO_NEW_KEY = "This vault's key can't be replaced on this device while an item in it can't be opened."

    // This phone's memory can't be read (rule S4).
    const val MEMORY_UNREADABLE = "PassAuth can't read this device's record of your vaults."
    const val RESET_MEMORY = "Reset on this device"
    const val RESET_MEMORY_CONFIRM = "PassAuth will trust what your server shows now and start a new record on this device."

    /** The link a first manifest names (32 zero bytes): never a remembered link. */
    const val ZERO_LINK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    const val CHANGED_ELSEWHERE = "This vault changed on another device. Try again."

    /** "Use the server's copy": the answer fetched after the confirmation isn't the case the user was shown ([asConfirmed]). */
    const val SERVER_COPY_CHANGED = "The server's copy of this vault changed just now, so it wasn't accepted. Check what the app shows now."
    const val NOT_READY = "This can't be done until every member's apps are up to date."

    /** A write is sent at most this often when the vault changed elsewhere meanwhile. */
    const val ATTEMPTS = 3

    /**
     * `GET /vaults/{id}/manifest-log` is asked at most this often for one check of one vault (25 pages
     * of 2000 entries; more pages: the log doesn't connect).
     */
    const val LOG_REQUESTS = 25

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

    /** A mark this phone may remember and hand to the core: a version ≥ 1 with a link that isn't the all-zero one. */
    fun isMark(m: ManifestMark?): Boolean = m != null && m.version in 1..MAX_NUMBER && isLink(m.link) && m.link != ZERO_LINK

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
     * The check behind "Use the server's copy" (the core's `manifestAccept`): the vault row [v]
     * against exactly [items] with nothing remembered. "ok": the manifest served records exactly
     * these rows ([Check.mark]: what takes the place of this phone's memory); "none": the server
     * shows no manifest (the memory is forgotten); anything else, or anything thrown: nothing may be
     * remembered.
     */
    fun accept(key: VaultKey, v: SyncVault, items: List<SyncItem>): Check = try {
        val c = key.manifestAccept(v.id, epoch(v), seqOf(v).toULong(), v.manifestPrev, v.manifest, rows(items))
        val link = c.link
        when (c.status) {
            "ok" -> ManifestMark(c.version.toLong(), link.orEmpty()).takeIf(::isMark)?.let { Check("ok", it) } ?: Check("mismatch", null)
            "none" -> Check("none", null)
            else -> Check(c.status, null)
        }
    } catch (_: Exception) {
        Check("mismatch", null)
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
        /** Of [failed]: vaults "Use the server's copy" can accept on this phone alone ([accept] gave "ok" or "none"). */
        val acceptable: Set<String> = emptySet(),
        /** Vaults whose manifest passed but that hold a row that doesn't open ([ManifestState.Unopenable]). */
        val unopenable: Set<String> = emptySet(),
        /** Of [acceptable]: the server shows no manifest ([accept] gave "none"), so accepting forgets this phone's memory of the vault ([CONFIRM_NO_RECORD]). */
        val noRecord: Set<String> = emptySet(),
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
     * [hidden]: vaults with a row that doesn't open ([ItemOpening] case c). With a manifest that
     * passes, the vault is [ManifestState.Unopenable] whatever the copy is (the row doesn't open in
     * any answer): a notice, the row listed; what the core checked is remembered and the vault is
     * written to as usual.
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
        val acceptable = mutableSetOf<String>()
        val unopenable = mutableSetOf<String>()
        val noRecord = mutableSetOf<String>()
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
                "ok" -> {
                    check.mark?.let { remember[v.id] = it }
                    if (v.id in hidden) {
                        unopenable += v.id
                        ManifestState.Unopenable
                    } else {
                        ManifestState.Ok
                    }
                }
                "incomplete" -> {
                    incomplete += v.id
                    undecided
                }
                else -> {
                    failed += v.id
                    // What the warning offers: an acceptance on this phone alone, or (writers) a new baseline.
                    when (accept(key, v, rows).status) {
                        "ok" -> acceptable += v.id
                        "none" -> {
                            acceptable += v.id
                            noRecord += v.id
                        }
                    }
                    undecided
                }
            }
        }
        return Judged(states, remember, incomplete, failed, unlogged, acceptable, unopenable, noRecord)
    }

    /**
     * Rule S3: may the copy a locked background refresh left beside the checked one take its place?
     * Only when, judged with the keys like a delta from the server ([judged], no log asked), every
     * opened vault passes its manifest and its place in the chain ("ok") or has none, and no item
     * came in an older version than this phone remembers ([rolledBack]). Anything else: the refreshed
     * copy is dropped and the next sync decides.
     */
    fun adoptable(judged: Judged, rolledBack: Boolean): Boolean =
        !rolledBack && judged.undecided.isEmpty() && judged.unlogged.isEmpty() &&
            judged.states.values.all { it == ManifestState.Ok || it == ManifestState.None }

    // ------------------------------------------------------------ the log

    /** `GET /vaults/{id}/manifest-log?after=<seq>`. */
    fun logPath(vaultId: String, after: Long): String =
        "/vaults/" + urlPart(vaultId) + "/manifest-log?after=" + after.coerceAtLeast(0)

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
            // (The entries go to the core as they came; only for paging is the highest version among the well-formed ones read.)
            val last = entries.mapNotNull { ((it as? JsonObject)?.get("seq") as? JsonPrimitive)?.takeIf { p -> !p.isString }?.longOrNull?.takeIf { n -> n in 1..MAX_NUMBER } }.maxOrNull() ?: return null
            if (last <= from) return null
            from = last
        }
        return null
    }

    // ------------------------------------------------------------- writes

    /**
     * The manifest entry a write into [v] carries: null when the vault has none (the write goes as
     * before). [removed]: the affected rows as the copy holds them before the write; [added]: as
     * they are after it (with the exact `data` sent). Only for a vault whose manifest passed
     * ([writable]: [ManifestState.Ok], and [ManifestState.Unopenable], whose manifest passed too:
     * a row that doesn't open holds nothing back, rule T1); [UserException] ([HELD]) otherwise.
     */
    fun next(key: VaultKey, v: SyncVault, state: ManifestState?, removed: List<SyncItem>, added: List<SyncItem>): ManifestEntry? {
        val seq = seqOf(v)
        if (seq <= 0 && state != ManifestState.Unresolved && state != ManifestState.Unchecked) return null
        val sealed = v.manifest
        val prev = v.manifestPrev
        if (!writable(state) || sealed == null || prev == null || removed.any { !countable(it) }) throw UserException(HELD)
        val w = try {
            key.manifestNext(v.id, epoch(v), seq.toULong(), prev, sealed, rows(removed), rows(added))
        } catch (_: Exception) {
            throw UserException(HELD)
        }
        return ManifestEntry(v.id, w.seq.toLong(), w.prev, w.sealed, w.link)
    }

    /** A vault with a manifest in this state takes writes: the manifest passed for the copy shown. */
    fun writable(state: ManifestState?): Boolean = state == ManifestState.Ok || state == ManifestState.Unopenable

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

    /** `manifest_link` of a write's answer: the link of the vault's manifest after it (null: the vault has none, or an older server). */
    fun answeredLink(answer: JsonElement?): String? =
        ((answer as? JsonObject)?.get("manifest_link") as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf(::isLink)

    /**
     * The server stored exactly the manifest [sent] with this write (rule S6): the answer's
     * `manifest_link` is the link of what was sent. The version alone doesn't say that: a retried
     * create whose first attempt got through answers the same version though the retry sealed its
     * manifest again.
     */
    fun stored(sent: ManifestEntry?, answer: JsonElement?): Boolean = sent != null && isLink(sent.link) && answeredLink(answer) == sent.link

    /**
     * This device's write with manifest [sent] is the vault's latest: the copy may take it without
     * asking the server, and [sent] is remembered. Without one sent, only while the answer says the
     * vault still has none (a manifest that appeared meanwhile is fetched and checked by a sync).
     */
    fun mayApplyLocally(sent: ManifestEntry?, answer: JsonElement?): Boolean =
        if (sent == null) (answered(answer) ?: 0) <= 0 && answeredLink(answer) == null else stored(sent, answer)

    /** How many trashed items one purge request names: at most 250, and never more than the server's `limits.max_import_items`. */
    fun purgeChunk(maxImportItems: Int?): Int = minOf(250, maxImportItems?.takeIf { it > 0 } ?: 250)

    /**
     * May this phone start [v]'s first manifest now? The server keeps manifests and says every
     * member's apps do ([SyncVault.manifestOk]), the vault has none and this phone never saw one,
     * the account can write to it, every row can be counted, and none of its items is marked as
     * served in an older version ([marked]: a first record must not be made over a copy the server
     * rolled back) and none of its rows fails to decrypt ([unopenable]: such rows are deleted first;
     * live rows always, trashed ones only when the copy has their key and data, which a
     * `trash=summary` copy doesn't: there this app can't tell. An item of a newer app, [ItemOpening]
     * case b, doesn't count).
     */
    fun mayStart(
        v: SyncVault, state: ManifestState?, role: Role?, listed: Boolean, remembered: ManifestMark?, rows: List<SyncItem>,
        marked: Set<String> = emptySet(), unopenable: Boolean = false,
    ): Boolean =
        listed && state == ManifestState.None && seqOf(v) == 0L && v.manifestOk == true && v.seq != null &&
            role != null && role != Role.Read && remembered == null && !unopenable && rows.all(::countable) &&
            rows.none { it.servedSha256 != null || it.id in marked }

    /**
     * `PUT /vaults/{id}/manifest`: the vault's first manifest (version 1 on a vault without one) or a
     * new baseline, always exactly one version above the manifest the row carries (the server takes
     * nothing else; what this phone remembers plays no part), for exactly [rows] (every row of the
     * vault in the copy), pinned to the vault's number of the sync the copy came from, and naming the
     * manifest the row carries now as the one it replaces (whatever it is: a baseline is built on
     * what the server shows). Null when the copy has no number for the vault. Throws when the row
     * has a version but not the other two fields, or a row can't be counted.
     */
    fun startBody(key: VaultKey, v: SyncVault, rows: List<SyncItem>): Pair<JsonObject, ManifestEntry>? {
        val vaultSeq = v.seq ?: return null
        val base = seqOf(v)
        if (base >= MAX_NUMBER) throw IllegalStateException("no version above this one")
        val prev = if (base > 0) linkOf(v) ?: throw IllegalStateException("the row doesn't carry its manifest") else null
        val w = key.manifestStart(v.id, epoch(v), (base + 1).toULong(), prev, rows(rows))
        return buildJsonObject {
            put("base_seq", seqOf(v))
            put("seq", w.seq.toLong())
            put("prev", w.prev)
            put("sealed", w.sealed)
            put("vault_seq", vaultSeq)
        } to ManifestEntry(v.id, w.seq.toLong(), w.prev, w.sealed, w.link)
    }

    /** What "Use the server's copy" does for one vault, once everything was fetched again ([serverCopy]). */
    sealed interface ServerCopy {
        /** Accepted on this phone alone: [mark] (the manifest served) takes the place of its memory. No request. */
        data class Accept(val mark: ManifestMark) : ServerCopy

        /** Accepted on this phone alone: the server shows no manifest, so the vault's memory is forgotten. No request. */
        data object Forget : ServerCopy

        /** The manifest served doesn't record the rows served: a new baseline is written ([body] for `PUT …/manifest`), by an account that can write. */
        data class Baseline(val body: JsonObject, val entry: ManifestEntry) : ServerCopy

        /** Nothing this account can do ([READERS]). */
        data object Readers : ServerCopy

        /** No baseline can be made from what the server sent (a row without data, a version without its manifest). */
        data object Broken : ServerCopy
    }

    /**
     * Whether [plan], made from the answer fetched after the confirmation, is the case the user
     * confirmed (rule T3): "no record" ([noRecord], [CONFIRM_NO_RECORD]) only forgets, and the
     * ordinary text ([CONFIRM_BODY]) never does. Otherwise nothing is accepted ([SERVER_COPY_CHANGED]).
     * [ServerCopy.Readers] and [ServerCopy.Broken] accept nothing either way and keep their own words.
     */
    fun asConfirmed(plan: ServerCopy, noRecord: Boolean): Boolean = when (plan) {
        ServerCopy.Forget -> noRecord
        is ServerCopy.Accept, is ServerCopy.Baseline -> !noRecord
        ServerCopy.Readers, ServerCopy.Broken -> true
    }

    /**
     * Rule S1: what "Use the server's copy" does for vault [v] of the whole answer just fetched
     * ([rows]: its item rows), after the user confirmed. Every role accepts on this phone alone when
     * the manifest served records exactly these rows, or there is none ([accept]); otherwise an
     * account that can write makes a new baseline one version above the row's.
     */
    fun serverCopy(key: VaultKey, v: SyncVault, role: Role?, rows: List<SyncItem>): ServerCopy {
        val a = accept(key, v, rows)
        val mark = a.mark
        return when {
            a.status == "ok" && mark != null -> ServerCopy.Accept(mark)
            a.status == "none" -> ServerCopy.Forget
            role == null || role == Role.Read -> ServerCopy.Readers
            else -> try {
                startBody(key, v, rows)?.let { ServerCopy.Baseline(it.first, it.second) } ?: ServerCopy.Broken
            } catch (_: Exception) {
                ServerCopy.Broken
            }
        }
    }

    /**
     * `DELETE /items/{id}/permanent` for a row that doesn't open (rule S2; the server deletes a live
     * row with it too): the query names the row's revision and, for a vault with a manifest, the
     * next one without the row ([entry]).
     */
    fun deletePath(row: SyncItem, entry: ManifestEntry?): String {
        val id = urlPart(row.id)
        val query = if (entry != null) query(entry, row.revision) else row.revision?.let { "?revision=$it" }.orEmpty()
        return "/items/$id/permanent$query"
    }

    /**
     * The trashed rows of a vault this phone may delete for good. Neither the server's clock nor a
     * row's `deleted_at` is covered by the manifest, so both are bounded by what this phone saw:
     *
     * - the server's rule: retention is on ([trashDays] ≥ 1) and the row has been in the trash
     *   longer than that by the server's own clock ([serverTime]);
     * - this phone has itself seen the row in the trash for at least that long, and never less than
     *   [MIN_TRASH_WATCH_DAYS] days, by its own clock ([seen]: when it first saw each item trashed,
     *   [TrashSeen]; [deviceNow]): a server that names a retention of one day still waits a week;
     * - the server's clock is within a day of this phone's.
     *
     * Numbers that don't fit give nothing (never an overflow).
     */
    fun dueTrash(rows: List<SyncItem>, serverTime: Long?, trashDays: Long?, seen: Map<String, Long>, deviceNow: Long): List<SyncItem> {
        if (serverTime == null || trashDays == null || trashDays < 1) return emptyList()
        if (serverTime < 0 || serverTime > MAX_NUMBER || trashDays > MAX_TRASH_DAYS || deviceNow < 0 || deviceNow > MAX_NUMBER) return emptyList()
        if (kotlin.math.abs(serverTime - deviceNow) > CLOCK_SLACK_SECONDS) return emptyList()
        val before = serverTime - trashDays * 86_400
        val seenBefore = deviceNow - maxOf(trashDays, MIN_TRASH_WATCH_DAYS) * 86_400
        return rows.filter { r ->
            val at = r.deletedAt
            val first = seen[r.id]
            at != null && at > 0 && at < before && first != null && first <= seenBefore
        }
    }

    /** Whatever retention the server names, old trash goes only after this phone watched it there for this many days. */
    const val MIN_TRASH_WATCH_DAYS = 7L

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
                // The same data under another key: the server changed the key alone (rule T1 a). The key this phone holds is the one that opens it.
                c.data != null -> if (c.data == data) (if (c.itemKey == null || c.itemKey == r.itemKey) r else r.copy(itemKey = c.itemKey)) else return null
                else -> if (c.dataSha256 == hash) r else return null
            }
        }
        return if (out.map { it.id }.toSet().size == out.size) out else null
    }

    // ------------------------------------------------------------ device memory

    private fun wholeNumber(e: JsonElement?): Long? = (e as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

    /**
     * What this phone remembers from its stored JSON
     * (`{"<vault id>": {"version": n, "link": "…", "accepts": k, "not_checked": true}}`). An entry that isn't a version ≥ 1
     * with a link that isn't all zero (the first version's bare number included) is "nothing
     * remembered": half a memory is never handed to the core. Its `accepts` (missing: 0) is kept
     * either way; `not_checked` (rule T3) counts only on an entry without a mark.
     */
    fun decodeMemory(text: String?): Map<String, Remembered> {
        val o = text?.let { runCatching { AppJson.parseToJsonElement(it) as? JsonObject }.getOrNull() } ?: return emptyMap()
        return o.mapNotNull { (id, v) ->
            val e = v as? JsonObject ?: return@mapNotNull null
            val accepts = wholeNumber(e["accepts"])?.takeIf { it in 0..MAX_NUMBER } ?: 0
            val version = wholeNumber(e["version"])
            val link = (e["link"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val mark = if (version != null && link != null) ManifestMark(version, link).takeIf(::isMark) else null
            val notChecked = mark == null && (e["not_checked"] as? JsonPrimitive)?.takeIf { !it.isString }?.content == "true"
            if (mark == null && accepts == 0L && !notChecked) null else id to Remembered(mark, accepts, notChecked)
        }.toMap()
    }

    fun encodeMemory(m: Map<String, Remembered>): String = JsonObject(
        m.mapValues { (_, r) ->
            buildJsonObject {
                r.mark?.let { put("version", it.version); put("link", it.link) }
                if (r.accepts > 0) put("accepts", r.accepts)
                if (r.notChecked && r.mark == null) put("not_checked", true)
            }
        },
    ).toString()

    /** The marks of [memory] (what a check is made against). */
    fun marks(memory: Map<String, Remembered>): Map<String, ManifestMark> = memory.mapNotNull { (id, r) -> r.mark?.let { id to it } }.toMap()

    /**
     * [memory] advanced by [updates] (a check that gave "ok", or this phone's own stored write): the
     * higher version wins; at the same version the one already there stays (a link is never replaced
     * at its version: if the two differ, one of them is on another history and the next check says
     * so). `accepts` stays. Vaults that are gone stay (a server could hide a vault and show it again).
     */
    fun merged(memory: Map<String, Remembered>, updates: Map<String, ManifestMark>): Map<String, Remembered> {
        val out = memory.toMutableMap()
        for ((id, m) in updates) {
            if (!isMark(m)) continue
            val have = out[id]
            if (have?.mark == null || m.version > have.mark.version) out[id] = Remembered(m, have?.accepts ?: 0)
        }
        return out
    }

    /**
     * Two copies of the memory brought together ([stored]: what the file holds; [mine]: what this
     * process holds), per vault: the entry with more acceptances wins; with as many, the higher
     * version (none counts as 0); with the same version, the stored one.
     */
    fun joined(stored: Map<String, Remembered>, mine: Map<String, Remembered>): Map<String, Remembered> {
        val out = stored.toMutableMap()
        for ((id, m) in mine) {
            val have = out[id]
            val newer = have == null || m.accepts > have.accepts ||
                (m.accepts == have.accepts && (m.mark?.version ?: 0) > (have.mark?.version ?: 0))
            if (newer) out[id] = m
        }
        return out
    }

    /**
     * [memory] after "Use the server's copy" for vault [vaultId] (the only way a mark is replaced or
     * goes down): [mark] takes the place of whatever was remembered (null: forgotten, the server
     * shows no manifest), and the vault's `accepts` goes up by one. [notChecked]: the user accepted
     * "no record" ([CONFIRM_NO_RECORD]); kept on the forgotten entry until a mark is remembered again.
     */
    fun replaced(memory: Map<String, Remembered>, vaultId: String, mark: ManifestMark?, notChecked: Boolean = false): Map<String, Remembered> {
        val m = mark?.takeIf(::isMark)
        return memory + (vaultId to Remembered(m, (memory[vaultId]?.accepts ?: 0).coerceAtMost(MAX_NUMBER - 1) + 1, notChecked && m == null))
    }
}

/**
 * Rule S4: how often in a row this phone's memory of an account couldn't be read ([attempts]), and
 * whether a sync with the server finished meanwhile ([synced]). After [OFFER_AFTER] such reads
 * across at least one finished sync the app says so and offers "Reset on this device"; one good
 * read starts over.
 */
data class UnreadableMemory(val attempts: Int = 0, val synced: Boolean = false) {
    fun failed(synced: Boolean): UnreadableMemory = UnreadableMemory((attempts + 1).coerceAtMost(1_000), this.synced || synced)

    val offerReset: Boolean get() = attempts >= OFFER_AFTER && synced

    companion object {
        const val OFFER_AFTER = 3

        /**
         * This phone's memory of an account reads: its manifest marks, its item edit counters and its
         * trash times, each in a file of its own. One that doesn't read is enough for "unreadable"
         * (final review N6: the counters or the trash times alone had no way out).
         */
        fun readable(manifests: Boolean, revs: Boolean, trashSeen: Boolean): Boolean = manifests && revs && trashSeen

        /** The count after one more look at the memory ([readable]: null, it starts over; else one more failed read, [synced]: at a finished sync). */
        fun after(current: UnreadableMemory?, readable: Boolean, synced: Boolean): UnreadableMemory? =
            if (readable) null else (current ?: UnreadableMemory()).failed(synced)
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
