package io.passauth.app.data

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.io.File
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** An upload in progress, waiting or failed (shown on its item's page). */
data class UploadTask(
    val key: String,
    val itemId: String,
    val name: String,
    /** The file's own size in bytes. */
    val size: Long,
    /** "queued", "uploading", "saving" or "failed". */
    val state: String,
    /** Progress of the upload, 0–1. */
    val fraction: Float = 0f,
    val error: String? = null,
)

/**
 * A decrypted copy for Open, Share or Save, made while account record [account] was unlocked (lock
 * [generation]): [AttachmentManager.isCurrent] says whether it may still be handed out.
 */
class DownloadedFile internal constructor(val file: File, internal val account: String, internal val generation: Long)

/**
 * Attachments on this phone (the web vault's `files.ts`): uploads run one after the other in the
 * app's scope (leaving the item doesn't stop them) and stop when the vault locks or signs out,
 * deleting their attachment again. After the file is on the server the item is saved with it in its
 * list, starting from the item as last synced (tried again after a sync); if that fails for good the
 * attachment is deleted. Downloads are decrypted into the app's cache (kept only after the core
 * confirmed the whole file) for Open, Share and Save; those copies are deleted when the vault locks,
 * when the app starts and, once older than ten minutes, at the next download and whenever the app
 * goes to the background. A lock also stops every download: one that finishes anyway is deleted
 * instead of handed out ([isCurrent]).
 */
class AttachmentManager(private val context: Context, private val repo: VaultRepository, private val scope: CoroutineScope) : DefaultLifecycleObserver {
    private val _uploads = MutableStateFlow<List<UploadTask>>(emptyList())
    val uploads: StateFlow<List<UploadTask>> = _uploads.asStateFlow()
    private val queue = Mutex()
    private val stops = mutableMapOf<String, AtomicBoolean>()

    /** Goes up each time the vault closes (lock, log out, another account): copies made before can't be handed out. */
    private val lockGeneration = AtomicLong(0)

    /** Downloads running now, cancelled when the vault closes. */
    private val downloads = mutableSetOf<Job>()

    /** Folders of downloads in progress (pruning old copies leaves them alone). */
    private val activeDirs = mutableSetOf<File>()

    /** Decrypted copies for Open, Share and Save (the app's cache, never backed up). */
    val tempDir: File get() = File(context.cacheDir, "attachments")

    init {
        clearTemp()
        // Locked, signed out or another account: nothing can be saved into an item any more.
        scope.launch {
            repo.vault.map { it != null }.distinctUntilChanged().collect { open ->
                if (open) return@collect
                lockGeneration.incrementAndGet()
                synchronized(downloads) { downloads.toList() }.forEach { it.cancel() }
                synchronized(stops) { stops.values.forEach { it.set(true) } }
                _uploads.update { list -> list.filter { it.state == "saving" } }
                clearTemp()
            }
        }
    }

    fun clearTemp() {
        runCatching { tempDir.deleteRecursively() }
    }

    /** Copies handed to other apps a while ago (ten minutes) have been read by now: delete them. */
    fun pruneOld() {
        val now = System.currentTimeMillis()
        val busy = synchronized(activeDirs) { activeDirs.toSet() }
        runCatching { tempDir.listFiles()?.filter { it !in busy && now - it.lastModified() > 10 * 60_000 }?.forEach { it.deleteRecursively() } }
    }

    /** The app went to the background (process lifecycle): old copies go now, not only at the next download. */
    override fun onStop(owner: LifecycleOwner) = pruneOld()

    private fun isCurrent(account: String, generation: Long) =
        lockGeneration.get() == generation && repo.vault.value != null && repo.state.value.activeId == account

    /** Whether [d] may still be handed to another app or saved: the vault hasn't closed since it was made, and it still exists. */
    fun isCurrent(d: DownloadedFile) = isCurrent(d.account, d.generation) && d.file.exists()

    /** Delete a copy that won't be used. */
    fun discard(d: DownloadedFile) {
        d.file.parentFile?.deleteRecursively()
    }

    private fun patch(key: String, f: (UploadTask) -> UploadTask) = _uploads.update { list -> list.map { if (it.key == key) f(it) else it } }
    private fun drop(key: String) = _uploads.update { list -> list.filter { it.key != key } }

    /** The picked file's name and size (null when the provider doesn't say). */
    private fun describe(uri: Uri): Pair<String, Long?> {
        var name = ""
        var size: Long? = null
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                name = c.getString(0).orEmpty()
                if (!c.isNull(1)) size = c.getLong(1)
            }
        }
        return Attachments.cleanName(name) to size
    }

    /**
     * Attach the file at [uri] to item [itemId]: checked against the server's limit first (throws a
     * [UserException] that the page shows), then queued.
     */
    suspend fun attach(itemId: String, uri: Uri) {
        val features = repo.features()
        if (features != null && Attachments.FEATURE !in features) throw UserException("Adding files is turned off on this server.")
        val (name, known) = withContext(Dispatchers.IO) { describe(uri) }
        // A provider that doesn't say: count the bytes once.
        val size = known ?: withContext(Dispatchers.IO) {
            context.contentResolver.openInputStream(uri)?.use { s ->
                var n = 0L
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val r = s.read(buf)
                    if (r < 0) break
                    n += r
                }
                n
            } ?: throw UserException("PassAuth couldn't read this file.")
        }
        val maxMb = Attachments.limitMb(repo.serverLimits())
        if (Attachments.tooLarge(size, maxMb) { io.passauth.core.fileEncryptedSize(it.toULong()).toLong() }) {
            throw UserException("\"$name\" is larger than your server allows (${maxMb} MB). Pick a smaller file.")
        }
        val key = "upload-" + UUID.randomUUID()
        val stop = AtomicBoolean(false)
        synchronized(stops) { stops[key] = stop }
        _uploads.update { it + UploadTask(key, itemId, name, size, "queued") }
        scope.launch { queue.withLock { run(key, uri, stop) } }
    }

    /** Stop an upload that hasn't reached its save yet (its attachment is deleted), or forget a failed one. */
    fun cancel(key: String) {
        val task = _uploads.value.firstOrNull { it.key == key } ?: return
        if (task.state == "saving") return
        synchronized(stops) { stops[key]?.set(true) }
        if (task.state == "failed" || task.state == "queued") drop(key)
    }

    private suspend fun run(key: String, uri: Uri, stop: AtomicBoolean) {
        val task = _uploads.value.firstOrNull { it.key == key }
        try {
            if (task == null || stop.get()) return drop(key)
            currentEntry(task.itemId)
            patch(key) { it.copy(state = "uploading", fraction = 0f) }
            var last = 0L
            val done = withContext(Dispatchers.IO) {
                Upload.run(
                    open = { context.contentResolver.openInputStream(uri) ?: throw UserException("PassAuth couldn't read this file.") },
                    plainSize = task.size,
                    itemId = task.itemId,
                    steps = repo.uploadSteps(),
                    progress = { read ->
                        val now = System.currentTimeMillis()
                        // At most ten updates a second.
                        if (now - last >= 100 || read == task.size) {
                            last = now
                            patch(key) { it.copy(fraction = if (task.size > 0) read.toFloat() / task.size else 1f) }
                        }
                    },
                    stopped = { stop.get() },
                )
            }
            patch(key) { it.copy(state = "saving", fraction = 1f) }
            val att = Attachment(done.id, task.name, task.size, done.key)
            try {
                listInItem(task.itemId, att)
            } catch (e: Exception) {
                // The item doesn't list the file, so nobody could open it: delete it again.
                runCatching { repo.deleteStoredAttachment(att.id) }
                throw e
            }
            drop(key)
        } catch (e: kotlinx.coroutines.CancellationException) {
            drop(key)
            throw e
        } catch (e: TransferCancelled) {
            drop(key)
        } catch (e: Exception) {
            if (stop.get()) drop(key) else patch(key) { it.copy(state = "failed", error = fileError(e)) }
        } finally {
            synchronized(stops) { stops.remove(key) }
        }
    }

    /** The item as last synced, or why it can't be changed. */
    private fun currentEntry(itemId: String): Entry {
        val v = repo.vault.value ?: throw UserException("The vault is locked. Unlock it and try again.")
        return v.get(itemId) ?: throw UserException("This item is no longer in your vault. It may have been deleted on another device.")
    }

    /** Worth trying the save again after a sync: not an answer that will stay the same (a full storage, a gone item). */
    private fun retrySave(e: Exception) = e !is ApiException || e.status == 409 || e.status == 429 || (e.status >= 500 && e.status != 507)

    /** Save the item with [att] added to its list, starting from the item as last synced each try. */
    private suspend fun listInItem(itemId: String, att: Attachment) {
        var attempt = 1
        while (true) {
            val entry = currentEntry(itemId)
            try {
                repo.updateItem(entry, Attachments.add(entry.item, listOf(att)))
                return
            } catch (e: Exception) {
                if (attempt >= 3 || !retrySave(e) || repo.vault.value == null) throw e
                delay(1500L * attempt)
                runCatching { repo.sync() }
            }
            attempt++
        }
    }

    /** Remove a file: the item is saved without it first, then the server deletes the file (a file already gone is fine). */
    suspend fun remove(itemId: String, attachmentId: String) {
        val entry = currentEntry(itemId)
        repo.updateItem(entry, Attachments.remove(entry.item, attachmentId))
        runCatching { repo.deleteStoredAttachment(attachmentId) }
    }

    /**
     * Download and decrypt [att] of item [itemId] from [path] (the item's own, or an emergency
     * access's) into a fresh folder of the cache, under its download name. Only a whole, authentic
     * file is kept; [MissingFile] when the server doesn't have it any more.
     */
    suspend fun download(path: String, itemId: String, att: Attachment, progress: (Float) -> Unit = {}): DownloadedFile {
        val account = repo.state.value.activeId
        val generation = lockGeneration.get()
        if (!isCurrent(account, generation)) throw UserException(LOCKED_TEXT)
        pruneOld()
        // Tracked so that a lock cancels it (the caller's coroutine).
        val job = currentCoroutineContext()[Job]
        if (job != null) synchronized(downloads) { downloads += job }
        val dir = File(tempDir, UUID.randomUUID().toString())
        synchronized(activeDirs) { activeDirs += dir }
        try {
            val res = repo.openDownload(path)
            if (res.code == 404) {
                res.close()
                throw MissingFile()
            }
            if (!res.isSuccessful) repo.downloadFailed(res)
            dir.mkdirs()
            val dest = File(dir, Attachments.downloadName(att.name))
            val total = runCatching { io.passauth.core.fileEncryptedSize(att.size.toULong()).toLong() }.getOrDefault(0L)
            withContext(Dispatchers.IO) {
                res.use { r ->
                    DecryptingCipher(att.key, itemId, att.id).use { cipher ->
                        FileTransfer.decryptToFile(
                            r.body.byteStream(), cipher, dest,
                            progress = { got -> if (total > 0) progress(got.toFloat() / total) },
                            stopped = { !isCurrent(account, generation) },
                        )
                    }
                }
            }
            // Locked (or another account) while it was decrypting: the copy isn't kept.
            if (!isCurrent(account, generation)) throw UserException(LOCKED_TEXT)
            return DownloadedFile(dest, account, generation)
        } catch (e: java.io.IOException) {
            dir.deleteRecursively()
            throw UserException(UNREACHABLE)
        } catch (e: TransferCancelled) {
            dir.deleteRecursively()
            throw UserException(LOCKED_TEXT)
        } catch (e: Throwable) {
            dir.deleteRecursively()
            throw e
        } finally {
            synchronized(activeDirs) { activeDirs -= dir }
            if (job != null) synchronized(downloads) { downloads -= job }
        }
    }

    /** Copy a downloaded file to where the user chose (Save), then delete the copy in the cache. */
    suspend fun saveTo(d: DownloadedFile, uri: Uri) = withContext(Dispatchers.IO) {
        try {
            if (!isCurrent(d)) throw UserException(LOCKED_TEXT)
            context.contentResolver.openOutputStream(uri)?.use { out -> d.file.inputStream().use { it.copyTo(out) } }
                ?: throw UserException("PassAuth couldn't write the file there.")
        } finally {
            discard(d)
        }
    }

    companion object {
        const val LOCKED_TEXT = "The vault is locked. Unlock it and try again."

        /** What went wrong with a file, in plain words. */
        fun fileError(e: Throwable): String = when {
            e is ApiException && e.hasCode("too_large") -> "${ServerErrors.text(e)} Pick a smaller file."
            e is ApiException && e.status == 429 -> "Too many uploads at once. Wait a minute, then try again."
            e is ApiException -> ServerErrors.text(e)
            e is io.passauth.core.CoreException -> "This file couldn't be decrypted: it is damaged or incomplete. Try again."
            e is UserException -> e.message.orEmpty()
            else -> e.message?.takeIf { it.isNotEmpty() }?.let { ShownText.clean(it, ServerErrors.MESSAGE_MAX) } ?: "Something went wrong."
        }
    }
}
