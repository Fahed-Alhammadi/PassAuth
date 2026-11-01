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
            AppJson.decodeFromString(Stored.serializer(), plain.decodeToString())
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

    fun deleteCache(id: String) {
        cacheFile(id).delete()
    }
}
