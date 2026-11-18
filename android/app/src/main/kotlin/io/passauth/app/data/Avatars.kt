package io.passauth.app.data

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.graphics.Rect
import android.net.Uri
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer

/**
 * Profile pictures: a small square JPEG sealed with the Account Key on the server (`/account/avatar`,
 * feature [FEATURE]); `/sync` `user.avatar_seq` says when it changed. With no picture the initials stay.
 */
object AvatarRules {
    const val FEATURE = "avatar"

    /** Width and height of the uploaded picture. */
    const val SIDE = 256

    /** The core's `MAX_AVATAR_BYTES`: the JPEG is re-encoded at lower quality until it fits. */
    const val MAX_BYTES = 256 * 1024

    /** JPEG qualities tried, best first. */
    val QUALITIES = listOf(85, 75, 65, 55, 45, 35, 25)

    /** The server's picture is fetched only when its sequence differs from the one kept (absent: an older server, nothing to do). */
    fun needsFetch(cachedSeq: Long, serverSeq: Long?): Boolean = serverSeq != null && serverSeq != cachedSeq

    /** The longest side a picked image is decoded at: a very wide or tall one is never held in memory at full size. */
    const val MAX_DECODE_SIDE = 4096

    /**
     * The size a picked [width]×[height] image is decoded at; null: as it is. Downsampled so the
     * short side stays at least twice [SIDE] (no need to decode a 50 MP photo), and further when
     * the long side would still be above [MAX_DECODE_SIDE] (a panorama strip is cropped to its
     * centre anyway).
     */
    fun decodeSize(width: Int, height: Int): Pair<Int, Int>? {
        if (width <= 0 || height <= 0) return null
        val short = minOf(width, height)
        val long = maxOf(width, height)
        val ratio = maxOf(short.toDouble() / (SIDE * 2), long.toDouble() / MAX_DECODE_SIDE)
        if (ratio <= 1.0) return null
        return (width / ratio).toInt().coerceIn(1, MAX_DECODE_SIDE) to (height / ratio).toInt().coerceIn(1, MAX_DECODE_SIDE)
    }

    /** The centred square of a [width]×[height] image: left, top and side. */
    fun centerSquare(width: Int, height: Int): Triple<Int, Int, Int> {
        val side = minOf(width, height)
        return Triple((width - side) / 2, (height - side) / 2, side)
    }

    /** The first encoding by [encode] (given a quality) that fits in [max] bytes; null if none does. */
    fun encodeWithin(max: Int = MAX_BYTES, qualities: List<Int> = QUALITIES, encode: (Int) -> ByteArray): ByteArray? {
        for (q in qualities) {
            val out = encode(q)
            if (out.isNotEmpty() && out.size <= max) return out
        }
        return null
    }
}

/** One account's picture as kept on this device: the server's [seq] and the JPEG (empty: none at that seq). */
class AvatarEntry(val seq: Long, val jpeg: ByteArray) {
    val hasPicture: Boolean get() = jpeg.isNotEmpty()
}

/**
 * Per-account picture files (`<dir>/<account id>.bin`): the sequence (8 bytes) and the JPEG, the whole
 * file sealed by [seal] (the app's Keystore key). Unreadable files count as none.
 */
class AvatarCache(
    private val dir: File,
    private val seal: (ByteArray) -> ByteArray,
    private val open: (ByteArray) -> ByteArray,
) {
    private fun file(id: String) = File(dir, "$id.bin")

    fun read(id: String): AvatarEntry? = runCatching {
        val f = file(id)
        if (!f.exists()) return null
        val plain = open(f.readBytes())
        if (plain.size < 8) return null
        AvatarEntry(ByteBuffer.wrap(plain, 0, 8).long, plain.copyOfRange(8, plain.size))
    }.getOrNull()

    fun write(id: String, seq: Long, jpeg: ByteArray) {
        dir.mkdirs()
        val plain = ByteBuffer.allocate(8 + jpeg.size).putLong(seq).put(jpeg).array()
        val f = file(id)
        val tmp = File(dir, "${f.name}.tmp")
        tmp.writeBytes(seal(plain))
        if (!tmp.renameTo(f)) {
            f.delete()
            tmp.renameTo(f)
        }
    }

    fun delete(id: String) {
        file(id).delete()
        File(dir, "$id.bin.tmp").delete()
    }

    /** Files of accounts not in [keep] removed (records gone from the device). */
    fun prune(keep: Set<String>) {
        dir.listFiles()?.forEach { f ->
            val id = f.name.removeSuffix(".tmp").removeSuffix(".bin")
            if (id !in keep) f.delete()
        }
    }
}

/** Android image work for profile pictures (not unit-testable on the JVM). */
object AvatarImage {
    /**
     * The picked image as the picture to upload: decoded downsampled, centre-cropped to a square,
     * scaled to [AvatarRules.SIDE] and re-encoded as JPEG within [AvatarRules.MAX_BYTES] (no EXIF/GPS:
     * the original file is never uploaded).
     */
    fun prepare(context: Context, uri: Uri): ByteArray = try {
        encode(context, uri)
    } catch (e: UserException) {
        throw e
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (_: Throwable) {
        // Also an image too large for this phone's memory (an Error, not an Exception): never a crash.
        throw UserException(CANT_OPEN)
    }

    private const val CANT_OPEN = "That picture couldn't be opened. Choose another one."

    private fun encode(context: Context, uri: Uri): ByteArray {
        val source = ImageDecoder.createSource(context.contentResolver, uri)
        val decoded = try {
            ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                AvatarRules.decodeSize(info.size.width, info.size.height)?.let { (w, h) -> decoder.setTargetSize(w, h) }
            }
        } catch (_: Throwable) {
            throw UserException(CANT_OPEN)
        }
        val square = squareOf(decoded)
        if (square !== decoded) decoded.recycle()
        // JPEG has no alpha: transparent areas drawn on white instead of black.
        val opaque = Bitmap.createBitmap(AvatarRules.SIDE, AvatarRules.SIDE, Bitmap.Config.ARGB_8888)
        android.graphics.Canvas(opaque).apply {
            drawColor(android.graphics.Color.WHITE)
            drawBitmap(square, null, Rect(0, 0, AvatarRules.SIDE, AvatarRules.SIDE), android.graphics.Paint(android.graphics.Paint.FILTER_BITMAP_FLAG))
        }
        square.recycle()
        try {
            return AvatarRules.encodeWithin { q ->
                ByteArrayOutputStream().also { opaque.compress(Bitmap.CompressFormat.JPEG, q, it) }.toByteArray()
            } ?: throw UserException("That picture is too large. Choose another one.")
        } finally {
            opaque.recycle()
        }
    }

    private fun squareOf(b: Bitmap): Bitmap {
        val (left, top, side) = AvatarRules.centerSquare(b.width, b.height)
        return if (side == b.width && side == b.height) b else Bitmap.createBitmap(b, left, top, side, side)
    }

    /** A kept JPEG as an image to draw; null when it doesn't decode. */
    fun decode(jpeg: ByteArray): ImageBitmap? =
        if (jpeg.isEmpty()) null else runCatching { BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size)?.asImageBitmap() }.getOrNull()
}
