package io.passauth.app.data

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * Item rollback detection (ARCHITECTURE "Item edit counter"): every item carries an encrypted edit
 * counter `rev` the server can't change ([Item.rev]); this phone remembers, per account and next to
 * the offline copy, the highest `rev` it has seen of each item. A sync that serves a lower one is a
 * rollback (the server sent an older version): the newer copy this phone had is kept when there is
 * one, the item is marked and the vault says so. Never silently accepted. A new phone starts empty
 * (trust on first sight). Equal `rev` with other content is an edit by an app from before: accepted.
 *
 * Pure (the core's `itemRevCheck` passed in), unit-tested in ItemRevsTest.
 */
object ItemRevs {
    const val ITEM_WARNING = "Your server sent an older version of this item."
    const val KEPT_NEWER = "Your server sent older versions of some items. PassAuth kept the newer copies it had."
    const val SENT_OLDER = "Your server sent older versions of some items."

    /** The vault-level notice, or null when nothing was rolled back. */
    fun notice(rolledBack: Set<String>, keptNewer: Boolean): String? = when {
        rolledBack.isEmpty() -> null
        keptNewer -> KEPT_NEWER
        else -> SENT_OLDER
    }

    /** The remembered map from its stored JSON (`{"<item id>": rev}`); anything malformed is left out. */
    fun decode(text: String?): Map<String, Long> {
        val o = text?.let { runCatching { AppJson.parseToJsonElement(it) as? JsonObject }.getOrNull() } ?: return emptyMap()
        return o.mapNotNull { (id, v) -> (v as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it >= 0 }?.let { id to it } }.toMap()
    }

    fun encode(m: Map<String, Long>): String = JsonObject(m.mapValues { JsonPrimitive(it.value) }).toString()

    sealed interface Verdict {
        /** Show the served item; [remember] its rev (null: nothing new to remember). */
        data class Accept(val remember: Long?) : Verdict

        /** An older version than this phone saw: [keepPrior] when the copy it had is newer than the one served. */
        data class Rollback(val keepPrior: Boolean) : Verdict
    }

    /**
     * What to do with a served item of [served] rev. [remembered]: the highest rev this phone
     * remembers of it (null: never seen); [prior]: the rev of the newer copy this phone has of it
     * (its offline copy, or a version an earlier build's locked refresh held), if it was read. [check] is the
     * core's `itemRevCheck` ("new", "same", "newer" or "rollback").
     */
    fun judge(remembered: Long?, served: Long, prior: Long?, check: (Long?, Long) -> String): Verdict {
        val known = listOfNotNull(remembered, prior).maxOrNull()
        return when (check(known, served)) {
            "new", "newer" -> Verdict.Accept(served)
            "same" -> Verdict.Accept(null)
            else -> Verdict.Rollback(keepPrior = prior != null && prior > served)
        }
    }

    /** At most this many items are remembered; beyond it the ones seen longest ago go first. */
    const val MAX_REMEMBERED = 20_000

    /** At most this many kept newer copies wait for an item the server stopped sending ([waiting]). */
    const val MAX_WAITING = 200

    /**
     * The memory after a sync: [updates] merged in (never lowered; an item updated moves to the
     * end, so the order is "seen longest ago first"), and the ids in [forget] dropped. An item is
     * forgotten only when its absence is certain ([gone], or this phone deleted it for good
     * itself): a server that hides an item for one sync and serves an old version afterwards must
     * still be noticed. Over [MAX_REMEMBERED] the oldest go, items not in [present] (the copy)
     * before the others.
     */
    fun merged(memory: Map<String, Long>, updates: Map<String, Long>, forget: Set<String> = emptySet(), present: Set<String> = emptySet()): Map<String, Long> {
        val out = LinkedHashMap(memory)
        for ((id, rev) in updates) {
            val have = out[id]
            if (have != null && have >= rev) continue
            out.remove(id)
            out[id] = rev
        }
        out.keys.removeAll(forget)
        if (out.size > MAX_REMEMBERED) {
            val oldest = out.keys.toList()
            var over = out.size - MAX_REMEMBERED
            for (id in oldest) {
                if (over == 0) break
                if (id !in present) {
                    out.remove(id)
                    over--
                }
            }
            for (id in oldest) {
                if (over == 0) break
                if (out.remove(id) != null) over--
            }
        }
        return out
    }

    /**
     * The items whose absence from a sync's copy is authenticated: in the copy this phone had
     * ([before]), in none of the vaults now ([after]), and their vault is still there with a
     * manifest that passed for this very copy ([states]: [ManifestState.Ok]), which counts every
     * item of the vault. Anything else (a vault without a manifest, a vault that is gone or
     * warned) may be the server hiding the item: remembered on.
     */
    fun gone(before: SyncSnapshot?, after: SyncSnapshot, states: Map<String, ManifestState>): Set<String> {
        before ?: return emptySet()
        val now = after.items.map { it.id }.toSet()
        val vaults = after.vaults.map { it.id }.toSet()
        return (before.items + before.held).filter { it.id !in now && it.vaultId in vaults && states[it.vaultId] == ManifestState.Ok }.map { it.id }.toSet()
    }

    /**
     * Newer copies this phone kept ([SyncItem.servedSha256]) of items the server no longer sends,
     * without that being certain ([forget]: the ids whose absence is): they wait in the copy's
     * `held` rows, unseen, so an old version served later still finds the newer copy to keep.
     * [before]: the copy this phone had; [after]: the one it has now. At most [MAX_WAITING], the
     * latest first.
     */
    fun waiting(before: SyncSnapshot?, after: SyncSnapshot, forget: Set<String>): List<SyncItem> {
        before ?: return emptyList()
        val now = after.items.map { it.id }.toSet()
        val kept = before.items.filter { it.servedSha256 != null }.map { it.copy(servedSha256 = null) }
        return (kept + before.held)
            .filter { it.id !in now && it.id !in forget && it.deletedAt == null && it.itemKey != null && it.data != null }
            .distinctBy { it.id to it.data }
            .take(MAX_WAITING)
    }

    /**
     * The row kept when a newer copy this phone had ([prior]) stays in place of the older version the
     * server sent ([served]): the newer copy's key and data, under the served row's `revision` (so
     * editing it saves over the version the server has, instead of a conflict), with [servedHash],
     * the hash of the data the server holds, which is what the vault's manifest records ([Manifests]).
     */
    fun keptRow(prior: SyncItem, served: SyncItem, servedHash: String?): SyncItem =
        prior.copy(revision = served.revision, servedSha256 = servedHash, dataSha256 = null)

    /**
     * [row] is a newer copy this phone kept in place of an older version the server sent: the item
     * stays marked ([ITEM_WARNING], and the vault's notice) for as long as the row is that copy,
     * across later syncs, this phone's other writes and lock and unlock, until it is rewritten (an
     * edit saved, or the server sending that version or a newer one).
     */
    fun isKept(row: SyncItem): Boolean = row.servedSha256 != null

    /** [snap] with the rows in [kept] (by item id) in place of the ones served. */
    fun keepRows(snap: SyncSnapshot, kept: Map<String, SyncItem>): SyncSnapshot {
        if (kept.isEmpty()) return snap
        return snap.copy(items = snap.items.filter { it.id !in kept } + kept.values)
    }
}
