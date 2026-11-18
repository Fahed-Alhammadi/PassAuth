package io.passauth.app.data

import android.content.Context
import android.util.Log
import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.serialization.SerializationException

/** DataStore serializer that keeps the whole [Stored] JSON encrypted with a Keystore key. */
private object StoredSerializer : Serializer<Stored> {
    override val defaultValue = Stored()

    override suspend fun readFrom(input: InputStream): Stored {
        val blob = input.readBytes()
        if (blob.isEmpty()) return defaultValue
        return try {
            val plain = Keystore.decrypt(Keystore.storeKey(), blob)
            AppJson.decodeFromString(Stored.serializer(), plain.decodeToString()).migrated()
        } catch (e: SerializationException) {
            throw CorruptionException("stored state unreadable", e)
        } catch (e: java.security.GeneralSecurityException) {
            throw CorruptionException("stored state unreadable", e)
        }
    }

    override suspend fun writeTo(t: Stored, output: OutputStream) {
        val plain = AppJson.encodeToString(Stored.serializer(), t).encodeToByteArray()
        output.write(Keystore.encrypt(Keystore.storeKey(), plain))
    }
}

/**
 * Tokens, settings and per-account data in an encrypted DataStore, plus an
 * encrypted cache of each account's last `/sync` response (ciphertext from the
 * server, so the vault opens offline).
 */
class SecureStore(private val context: Context, scope: CoroutineScope) {
    private val store: DataStore<Stored> = DataStoreFactory.create(
        serializer = StoredSerializer,
        corruptionHandler = ReplaceFileCorruptionHandler {
            Log.w("PassAuth", "Stored state could not be decrypted; starting fresh")
            Stored()
        },
        scope = scope,
        produceFile = { File(context.filesDir, "datastore/passauth.bin") },
    )

    val data = store.data

    suspend fun get(): Stored = store.data.first().let { s ->
        if (s.deviceId.isNotEmpty()) s else update { it.copy(deviceId = UUID.randomUUID().toString()) }
    }

    suspend fun update(transform: suspend (Stored) -> Stored): Stored = store.updateData(transform)

    /** Update one account's record (no-op if it was removed meanwhile). */
    suspend fun updateAccount(id: String, transform: (AccountData) -> AccountData): Stored = update { s ->
        val a = s.accounts[id] ?: return@update s
        s.copy(accounts = s.accounts + (id to transform(a)))
    }

    // ------------------------------------------------------------ sync cache

    private fun cacheFile(id: String) = File(File(context.noBackupFilesDir, "vault"), "$id.bin")

    fun writeCache(id: String, json: String) {
        val f = cacheFile(id)
        f.parentFile?.mkdirs()
        val tmp = File(f.parentFile, "${f.name}.tmp")
        tmp.writeBytes(Keystore.encrypt(Keystore.storeKey(), json.encodeToByteArray()))
        tmp.renameTo(f)
    }

    fun readCache(id: String): String? = runCatching {
        val f = cacheFile(id)
        if (!f.exists()) null else Keystore.decrypt(Keystore.storeKey(), f.readBytes()).decodeToString()
    }.getOrNull()

    private fun memory(id: String, kind: String) = SealedFile(
        File(File(context.noBackupFilesDir, "vault"), "$id.$kind"),
        seal = { Keystore.encrypt(Keystore.storeKey(), it) },
        open = { Keystore.decrypt(Keystore.storeKey(), it) },
    )

    /** The highest item edit counters this phone saw of account [id] ([ItemRevs]), with the offline copy. */
    fun revs(id: String): SealedFile = memory(id, "revs")

    /** The version and link of the last manifest this phone checked or wrote of each vault of account [id] ([Manifests]), with the offline copy. */
    fun manifests(id: String): SealedFile = memory(id, "manifests")

    /** When this phone first saw each trashed item of account [id] in the trash ([TrashSeen]), with the offline copy. */
    fun trashSeen(id: String): SealedFile = memory(id, "trashseen")

    /** Deletes account [id]'s offline copy (with its item edit counters, manifest memory and trash times) and its profile picture (log out, account removed). */
    fun deleteCache(id: String) {
        cacheFile(id).delete()
        revs(id).delete()
        manifests(id).delete()
        trashSeen(id).delete()
        avatars.delete(id)
    }

    // ------------------------------------------------------- profile pictures

    /** Each account's profile picture, sealed with the store key ([AvatarCache]). */
    val avatars = AvatarCache(
        File(context.noBackupFilesDir, "avatars"),
        seal = { Keystore.encrypt(Keystore.storeKey(), it) },
        open = { Keystore.decrypt(Keystore.storeKey(), it) },
    )
}

/**
 * A small sealed file of what this phone remembers (item edit counters, manifest versions). A file
 * that is there but can't be opened right now (a Keystore hiccup) is not an empty one: it is never
 * read as "nothing remembered" and never written over, or one bad read would wipe the memory the
 * rollback checks rest on. [seal]/[open]: the store key's encryption (fakes in tests).
 */
class SealedFile(private val file: File, private val seal: (ByteArray) -> ByteArray, private val open: (ByteArray) -> ByteArray) {
    sealed interface Read {
        /** No file: nothing was ever remembered. */
        data object Missing : Read

        /** A file that doesn't open now: unknown, not empty. */
        data object Unreadable : Read

        data class Text(val text: String) : Read
    }

    fun read(): Read = synchronized(lock) {
        if (!file.exists()) return Read.Missing
        try {
            Read.Text(open(file.readBytes()).decodeToString())
        } catch (_: Exception) {
            Read.Unreadable
        }
    }

    /**
     * Write what [merge] makes of the text the file holds now (null: no file yet). False, and
     * nothing written, while the file is unreadable.
     */
    fun write(merge: (String?) -> String): Boolean = synchronized(lock) {
        val now = when (val r = read()) {
            Read.Unreadable -> return false
            Read.Missing -> null
            is Read.Text -> r.text
        }
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.writeBytes(seal(merge(now).encodeToByteArray()))
        if (!tmp.renameTo(file)) {
            tmp.delete()
            return false
        }
        true
    }

    fun delete() {
        synchronized(lock) {
            file.delete()
            File(file.parentFile, "${file.name}.tmp").delete()
        }
    }

    private companion object {
        /** One writer at a time across every sealed file (they are small and rarely written). */
        val lock = Any()
    }
}
