package io.passauth.app.data

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Finds a QR code in a grayscale frame (the Y plane of a camera image) with
 * ZXing core. Pure JVM, so it is unit-tested on generated images. Not
 * thread-safe: use one instance per analyzer thread.
 */
class QrDecoder {
    private val reader = QRCodeReader()
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )

    /** [luminance] holds [height] rows of [rowStride] bytes; the image is the first [width] bytes of each row. */
    fun decode(luminance: ByteArray, width: Int, height: Int, rowStride: Int = width): String? {
        val source = PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false)
        // Also try light-on-dark codes (dark mode setup pages).
        return read(source) ?: read(source.invert())
    }

    private fun read(source: LuminanceSource): String? = try {
        reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (_: ReaderException) {
        null
    } finally {
        reader.reset()
    }
}
