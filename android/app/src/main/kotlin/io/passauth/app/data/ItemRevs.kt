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
     * (its offline copy or a version a locked refresh replaced), if it was read. [check] is the
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

    /**
     * The memory after a sync: [updates] merged in (never lowered), and, when [present] is given
     * (a sync's whole copy), ids no longer in it dropped (deleted for good, purged, or moved out of
     * every vault of the account).
     */
    fun merged(memory: Map<String, Long>, updates: Map<String, Long>, present: Set<String>?): Map<String, Long> {
        val out = memory.toMutableMap()
        for ((id, rev) in updates) out[id] = maxOf(rev, out[id] ?: rev)
        if (present != null) out.keys.retainAll(present)
        return out
    }

    /**
     * The row kept when a newer copy this phone had ([prior]) stays in place of the older version the
     * server sent ([served]): the newer copy's key and data, under the served row's `revision` (so
     * editing it saves over the version the server has, instead of a conflict), with [servedHash],
     * the hash of the data the server holds, which is what the vault's manifest records ([Manifests]).
     */
    fun keptRow(prior: SyncItem, served: SyncItem, servedHash: String?): SyncItem =
        prior.copy(revision = served.revision, servedSha256 = servedHash, dataSha256 = null)

    /** [snap] with the rows in [kept] (by item id) in place of the ones served. */
    fun keepRows(snap: SyncSnapshot, kept: Map<String, SyncItem>): SyncSnapshot {
        if (kept.isEmpty()) return snap
        return snap.copy(items = snap.items.filter { it.id !in kept } + kept.values)
    }

    /**
     * A locked refresh's [next] copy keeping, in `held`, the versions of each item it replaces:
     * nothing is decrypted while locked, so the next unlocked sync compares them ([judge]) and keeps
     * the newest. Per item at most two: the one held first (the version this phone last checked)
     * and [cached]'s row (the latest one replaced). Only rows whose ciphertext changed are held;
     * items gone from [next] drop theirs.
     */
    fun withHeld(next: SyncSnapshot, cached: SyncSnapshot?): SyncSnapshot {
        if (cached == null) return next
        val now = next.items.associateBy { it.id }
        val first = cached.held.groupBy { it.id }.mapValues { it.value.first() }
        val old = cached.items.associateBy { it.id }
        val held = mutableListOf<SyncItem>()
        val ids = (first.keys + old.keys).filter { it in now }.toSet()
        for (id in ids) {
            val current = now.getValue(id).data
            listOfNotNull(first[id], old[id])
                .filter { it.data != null && it.itemKey != null && it.deletedAt == null && it.data != current }
                .distinctBy { it.data }
                .forEach { held += it }
        }
        return next.copy(held = held)
    }
}
