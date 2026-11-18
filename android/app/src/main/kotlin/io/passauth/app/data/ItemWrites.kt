package io.passauth.app.data

import io.passauth.core.EncryptedItem
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * How item writes answer the server (API v2), apart from the encryption itself (which the
 * repository passes in, so this is JVM-tested in ItemWritesTest):
 *
 * - Bodies carry the `key_epoch` of the vault key the item was encrypted with, when the server
 *   sent one in `/sync` (older servers don't; nothing is sent then).
 * - 409 `vault_key_changed` (the key was replaced, e.g. a member was removed; nothing written):
 *   sync for the new key and try once more, encrypting again. A create keeps its item id. An
 *   update goes ahead only if the item still has the content the change was made to (a key
 *   rotation re-encrypts every item under a new revision); otherwise it is the usual conflict.
 * - A create whose id already exists (409 `item_exists`, "item id already exists" from older
 *   servers): an earlier attempt with this id got through and only its answer was lost, so that
 *   item is updated instead of saving a second one.
 * - Vault manifests ([Manifests]): a write into a vault that has one carries the vault's next
 *   manifest. 409 `manifest_conflict` (something else in the vault changed) or 400
 *   `manifest_required` (the copy still said the vault has none): sync, check the vault, make the
 *   manifest again from the fresh copy and send again, at most [Manifests.ATTEMPTS] times in all;
 *   never the "changed on another device, overwrite?" conflict.
 */
object ItemWrites {
    /** After a retry's sync the item is no longer there (deleted for good or moved to the trash elsewhere): nothing to save over. */
    const val DELETED_ELSEWHERE = "This item was deleted on another device."

    /** [send] asks for the sync-and-retry of a manifest conflict itself (its copy can't make the manifest). */
    class StaleCopy : Exception()

    private fun manifestRetry(e: Throwable) = e is StaleCopy || Manifests.isConflict(e)

    fun body(enc: EncryptedItem, keyEpoch: Long?, revision: Long? = null, manifests: List<ManifestEntry> = emptyList()): JsonObject = buildJsonObject {
        put("id", enc.id)
        put("vault_id", enc.vaultId)
        put("key", enc.key)
        put("data", enc.data)
        if (keyEpoch != null) put("key_epoch", keyEpoch)
        if (revision != null) put("revision", revision)
        if (manifests.isNotEmpty()) put("manifests", kotlinx.serialization.json.JsonArray(manifests.map { it.json() }))
    }

    /** The item's new revision in a write's answer; null when it isn't there (the copy is synced instead). */
    fun revision(answer: JsonElement?): Long? = ((answer as? JsonObject)?.get("revision") as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

    fun vaultKeyChanged(e: Throwable): Boolean = e is ApiException && e.status == 409 && e.hasCode("vault_key_changed")

    fun itemExists(e: Throwable): Boolean = e is ApiException && e.status == 409 && e.hasCode("item_exists", "item id already exists")

    enum class Created { New, UpdatedEarlierAttempt }

    /**
     * [send] encrypts the item (under the same id every time) with the vault key the repository
     * holds now and posts it. [resync] fetches the vault's new key. [updateEarlierAttempt]
     * syncs, finds the item an earlier attempt created and updates it; false if it isn't there.
     */
    suspend fun create(send: suspend () -> Unit, resync: suspend () -> Unit, updateEarlierAttempt: suspend () -> Boolean): Created {
        var retried = false
        var sends = 0
        while (true) {
            try {
                sends++
                send()
                return Created.New
            } catch (e: Exception) {
                when {
                    manifestRetry(e) -> {
                        if (sends >= Manifests.ATTEMPTS) throw UserException(Manifests.CHANGED_ELSEWHERE)
                        resync()
                    }
                    e !is ApiException -> throw e
                    vaultKeyChanged(e) && !retried -> {
                        retried = true
                        resync()
                    }
                    itemExists(e) -> if (updateEarlierAttempt()) return Created.UpdatedEarlierAttempt else throw e
                    else -> throw e
                }
            }
        }
    }

    /**
     * [send] encrypts the change for the given entry (its key wrapping and revision) and puts it.
     * [resync] syncs and returns the item as the server has it now (null if gone: [DELETED_ELSEWHERE]).
     * Any other 409 is a [ConflictException] (the item changed elsewhere); a manifest conflict never is.
     */
    suspend fun update(base: Entry, send: suspend (Entry) -> Unit, resync: suspend () -> Entry?) {
        var entry = base
        var keyRetried = false
        var sends = 0
        while (true) {
            try {
                sends++
                send(entry)
                return
            } catch (e: Exception) {
                when {
                    manifestRetry(e) -> if (sends >= Manifests.ATTEMPTS) throw UserException(Manifests.CHANGED_ELSEWHERE)
                    e !is ApiException -> throw e
                    vaultKeyChanged(e) && !keyRetried -> keyRetried = true
                    else -> throw if (e.status == 409 && !vaultKeyChanged(e)) ConflictException() else e
                }
            }
            // The item as the server has it now: the change goes ahead only on the content it was made to.
            val fresh = resync() ?: throw UserException(DELETED_ELSEWHERE)
            if (fresh.vaultId != base.vaultId || fresh.item != base.item) throw ConflictException()
            entry = fresh
        }
    }

    /**
     * A write that only changes an item's place (trash): [send] does nothing when the item is no
     * longer there to change (gone, or already in the trash: done). A manifest conflict, or the item
     * edited meanwhile (409 `revision_conflict`: the write named its revision), syncs ([resync]) and
     * starts again, at most [Manifests.ATTEMPTS] sends.
     */
    suspend fun place(send: suspend () -> Unit, resync: suspend () -> Unit) {
        var sends = 0
        while (true) {
            try {
                sends++
                send()
                return
            } catch (e: Exception) {
                val again = manifestRetry(e) || (e is ApiException && e.status == 409 && e.hasCode("revision_conflict"))
                if (!again) throw e
                if (sends >= Manifests.ATTEMPTS) throw UserException(Manifests.CHANGED_ELSEWHERE)
                resync()
            }
        }
    }
}
