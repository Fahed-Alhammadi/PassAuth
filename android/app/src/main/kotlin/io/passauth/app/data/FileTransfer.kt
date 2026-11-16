package io.passauth.app.data

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/** One file's encryption or decryption in pieces (the core's `FileEncryptor` / `FileDecryptor`; fakes in tests). */
interface FileCipher : AutoCloseable {
    fun push(chunk: ByteArray): ByteArray
    fun finish(): ByteArray
}

/** The upload was stopped (the vault locked, the user cancelled): its attachment is deleted. */
class TransferCancelled : UserException("The upload was stopped.")

/** The server doesn't have the file (any more): 404 on download. */
class MissingFile : UserException("This file is no longer on the server.")

/** The file couldn't be decrypted: it is damaged or incomplete. */
class DamagedFile : UserException("This file couldn't be decrypted: it is damaged or incomplete. Try again.")

/** The picked file gave a different number of bytes than it said it had. */
class FileChanged : UserException("The file changed while PassAuth was reading it. Try again.")

/** A failure inside a request body, carried through the HTTP client as an IOException ([cause] is thrown again). */
class BodyFailure(cause: Throwable) : IOException(cause.message, cause)

/**
 * Moving attachment files (the web vault's `transfer.ts`): encryption and decryption in 1 MiB
 * pieces, so a large file never sits whole in memory. Pure apart from the streams it is given;
 * unit-tested in FileTransferTest.
 */
object FileTransfer {
    const val READ_CHUNK = 1024 * 1024

    /**
     * Encrypt everything [input] gives (exactly [plainSize] bytes, else [FileChanged]) with
     * [cipher] into [out]; returns the bytes written. [progress] gets the plaintext bytes read so
     * far; [stopped] is asked between pieces.
     */
    fun encrypt(
        input: InputStream,
        plainSize: Long,
        cipher: FileCipher,
        out: OutputStream,
        chunk: Int = READ_CHUNK,
        progress: (Long) -> Unit = {},
        stopped: () -> Boolean = { false },
    ): Long {
        val buf = ByteArray(chunk)
        var read = 0L
        var written = 0L
        while (true) {
            if (stopped()) throw TransferCancelled()
            val n = readFully(input, buf)
            if (n <= 0) break
            read += n
            if (read > plainSize) throw FileChanged()
            val enc = cipher.push(if (n == buf.size) buf else buf.copyOf(n))
            out.write(enc)
            written += enc.size
            progress(read)
        }
        if (read != plainSize) throw FileChanged()
        val last = cipher.finish()
        out.write(last)
        written += last.size
        return written
    }

    /**
     * Decrypt [input] with [cipher] into [dest]: plaintext goes to a `.part` file next to it, which
     * becomes [dest] only after the core confirmed the whole file (`finish`); on any error it is
     * deleted and nothing of the file stays. [progress] gets the encrypted bytes read so far.
     */
    fun decryptToFile(
        input: InputStream,
        cipher: FileCipher,
        dest: File,
        progress: (Long) -> Unit = {},
        stopped: () -> Boolean = { false },
    ) {
        val part = File(dest.parentFile, "${dest.name}.part")
        try {
            part.outputStream().buffered().use { out -> decrypt(input, cipher, out, progress, stopped) }
            if (!part.renameTo(dest)) throw IOException("couldn't keep the file")
        } catch (e: Throwable) {
            part.delete()
            dest.delete()
            throw e
        }
    }

    /** Decrypt [input] into [out]; the caller discards [out] unless this returns. */
    fun decrypt(input: InputStream, cipher: FileCipher, out: OutputStream, progress: (Long) -> Unit = {}, stopped: () -> Boolean = { false }) {
        val buf = ByteArray(64 * 1024)
        var received = 0L
        try {
            while (true) {
                if (stopped()) throw TransferCancelled()
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                received += n
                out.write(cipher.push(buf.copyOf(n)))
                progress(received)
            }
            out.write(cipher.finish())
        } catch (e: io.passauth.core.CoreException) {
            throw DamagedFile()
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray): Int {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) break
            off += n
        }
        return if (off == 0) -1 else off
    }
}

/** What an upload needs from the core and the server (fakes in tests). */
interface UploadSteps {
    fun newId(): String
    fun newKey(): String
    fun encryptedSize(plain: Long): Long
    fun encryptor(key: String, itemId: String, attachmentId: String): FileCipher

    /** `POST /items/{itemId}/attachments {id, size}`. */
    suspend fun register(itemId: String, id: String, size: Long)

    /**
     * `PUT /attachments/{id}` with exactly [size] bytes that [write] produces. [write] may run more
     * than once (a session renewed after a 401): each run makes a new key.
     */
    suspend fun put(id: String, size: Long, write: (OutputStream) -> Unit)

    /** `DELETE /attachments/{id}` (an upload that failed or was stopped). */
    suspend fun discard(id: String)
}

data class Uploaded(val id: String, val key: String)

/** The upload flow: register, encrypt while sending, and delete the attachment again on any failure. */
object Upload {
    suspend fun run(
        open: () -> InputStream,
        plainSize: Long,
        itemId: String,
        steps: UploadSteps,
        progress: (Long) -> Unit = {},
        stopped: () -> Boolean = { false },
    ): Uploaded {
        val id = steps.newId()
        val size = steps.encryptedSize(plainSize)
        if (stopped()) throw TransferCancelled()
        steps.register(itemId, id, size)
        try {
            var key = ""
            steps.put(id, size) { out ->
                // A new key for every run: an earlier run's key encrypted bytes that never became a file.
                key = steps.newKey()
                steps.encryptor(key, itemId, id).use { cipher ->
                    open().use { input ->
                        val written = FileTransfer.encrypt(input, plainSize, cipher, out, progress = progress, stopped = stopped)
                        if (written != size) throw FileChanged()
                    }
                }
            }
            return Uploaded(id, key)
        } catch (e: Throwable) {
            try {
                steps.discard(id)
            } catch (_: Exception) {
            }
            throw if (e is BodyFailure && e.cause != null) e.cause!! else e
        }
    }
}
