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
 */
object ItemWrites {
    fun body(enc: EncryptedItem, keyEpoch: Long?, revision: Long? = null): JsonObject = buildJsonObject {
        put("id", enc.id)
        put("vault_id", enc.vaultId)
        put("key", enc.key)
        put("data", enc.data)
        if (keyEpoch != null) put("key_epoch", keyEpoch)
        if (revision != null) put("revision", revision)
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
        while (true) {
            try {
                send()
                return Created.New
            } catch (e: ApiException) {
                when {
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
     * [resync] syncs and returns the item as the server has it now (null if gone). Any other 409
     * is a [ConflictException] (the item changed elsewhere).
     */
    suspend fun update(base: Entry, send: suspend (Entry) -> Unit, resync: suspend () -> Entry?) {
        try {
            send(base)
            return
        } catch (e: ApiException) {
            if (!vaultKeyChanged(e)) throw if (e.status == 409) ConflictException() else e
        }
        val fresh = resync()
        if (fresh == null || fresh.vaultId != base.vaultId || fresh.item != base.item) throw ConflictException()
        try {
            send(fresh)
        } catch (e: ApiException) {
            throw if (e.status == 409 && !vaultKeyChanged(e)) ConflictException() else e
        }
    }
}
