package io.passauth.app.data

import io.passauth.core.CoreException
import io.passauth.core.EncryptedItem

/*
 * Rows that don't open (review round 3, rule T1). A row of a vault whose key this phone holds is
 * one of four things:
 *
 * - it opens: the item;
 * - (a) only the `item_key` the server sent fails, and this phone has a row with the same id, vault
 *   and `data` whose key opens it (its stored copy, the copy shown, a version that waits): the item,
 *   and the copy keeps the key this phone had. An honest server never changes a key without the
 *   data, and a vault's manifest covers the data only, so nothing is warned or held for it;
 * - (b) it decrypts, but this app can't read what is inside (an item type or format of a newer
 *   app): listed as [NEWER_ITEM], nothing else; its row counts in manifests like any other;
 * - (c) it doesn't decrypt: listed as [Manifests.UNOPENABLE_ITEM], with the name this phone knows
 *   the item by when it has an earlier version of it.
 *
 * Pure (the core is reached through [decrypt]); VaultRepository.decryptVault uses it for every row.
 */
object ItemOpening {
    const val NEWER_ITEM = "Item from a newer version of PassAuth"
    const val NEWER_NOTE = "Update PassAuth to see this item."

    sealed interface Result {
        /** The item, and the [row] the copy keeps: the one served, or ([keptKey]) the served one with the key this phone had. */
        data class Opened(val item: Item, val row: SyncItem, val keptKey: Boolean = false) : Result

        /** Case (b): decrypted, not readable by this app. */
        data object Newer : Result

        /** Case (c): doesn't decrypt. [name]: what this phone last knew the item as (null: it never opened it). */
        data class Unopenable(val name: String?) : Result
    }

    private sealed interface Try {
        data class Read(val item: Item) : Try
        data object Unknown : Try
        data object Failed : Try
    }

    /**
     * The core's error for data that decrypted but isn't an item it knows (its `Error::Json`,
     * worded "json: …"); a failed decryption is [CoreException.DecryptFailed], and text that isn't
     * ciphertext at all (bad base64, too short, an unknown ciphertext version) is "malformed data"
     * or "unsupported ciphertext version": nothing was decrypted then, so that is case (c).
     */
    fun isUnknownContent(e: Throwable): Boolean = e is CoreException.Invalid && e.message?.startsWith("json:") == true

    private fun attempt(row: SyncItem, key: String, data: String, decrypt: (EncryptedItem) -> String, decode: (String) -> Item): Try {
        val json = try {
            decrypt(EncryptedItem(row.id, row.vaultId, key, data))
        } catch (e: Exception) {
            return if (isUnknownContent(e)) Try.Unknown else Try.Failed
        }
        return try {
            Try.Read(decode(json))
        } catch (_: Exception) {
            Try.Unknown
        }
    }

    /**
     * [row] (with key and data) opened with its vault's key ([decrypt]: the core's `decryptItem`).
     * [known]: the rows this phone has under the same item id (any vault, any version); only one
     * with the same vault and the very same `data` can stand in for the served key (case a), and it
     * must open now, with the vault key as it is. An earlier version of the same vault that opens only
     * gives case (c) its name.
     */
    fun open(row: SyncItem, known: List<SyncItem>, decrypt: (EncryptedItem) -> String, decode: (String) -> Item = ItemCodec::decode): Result {
        val key = row.itemKey ?: return Result.Unopenable(null)
        val data = row.data ?: return Result.Unopenable(null)
        when (val t = attempt(row, key, data, decrypt, decode)) {
            is Try.Read -> return Result.Opened(t.item, row)
            Try.Unknown -> return Result.Newer
            Try.Failed -> Unit
        }
        val mine = known.filter { it.id == row.id && it.itemKey != null && it.data != null }
        for (k in mine.filter { it.vaultId == row.vaultId && it.data == data && it.itemKey != key }.distinctBy { it.itemKey }) {
            when (val t = attempt(row, k.itemKey!!, data, decrypt, decode)) {
                is Try.Read -> return Result.Opened(t.item, row.copy(itemKey = k.itemKey), keptKey = true)
                Try.Unknown -> return Result.Newer
                Try.Failed -> Unit
            }
        }
        val name = mine.filter { it.vaultId == row.vaultId && it.data != data }.firstNotNullOfOrNull { k ->
            (attempt(k, k.itemKey!!, k.data!!, decrypt, decode) as? Try.Read)?.item?.name?.takeIf { it.isNotBlank() }
        }
        return Result.Unopenable(name)
    }
}
