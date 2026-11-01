package io.passauth.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import io.passauth.app.data.OtpAuth
import io.passauth.app.data.OtpParse
import io.passauth.app.data.QrDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The camera analyzer's decoder, on generated QR images laid out like a camera's Y plane. */
class QrDecoderTest {
    private val uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

    /** A [size]² luminance image (with [stride] ≥ size bytes per row) of [text] as a QR code. */
    private fun frame(text: String, size: Int, stride: Int = size, invert: Boolean = false, offsetX: Int = 0): ByteArray {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size / 2, size / 2, mapOf(EncodeHintType.MARGIN to 2))
        val out = ByteArray(stride * size) { 0x7F } // gray padding, like real frames
        for (y in 0 until size) for (x in 0 until size) {
            val inside = x - offsetX in 0 until m.width && y - size / 4 in 0 until m.height
            val dark = inside && m.get(x - offsetX, y - size / 4)
            val v = if (!inside) 200 else if (dark != invert) 20 else 235
            out[y * stride + x] = v.toByte()
        }
        return out
    }

    @Test
    fun decodesQrInFrame() {
        val d = QrDecoder()
        assertEquals(uri, d.decode(frame(uri, 480, offsetX = 100), 480, 480))
    }

    @Test
    fun honoursRowStride() {
        val d = QrDecoder()
        assertEquals(uri, d.decode(frame(uri, 400, stride = 448, offsetX = 80), 400, 400, rowStride = 448))
    }

    @Test
    fun decodesInvertedCodes() {
        assertEquals(uri, QrDecoder().decode(frame(uri, 480, invert = true, offsetX = 100), 480, 480))
    }

    @Test
    fun emptyFrameHasNoCode() {
        assertNull(QrDecoder().decode(ByteArray(320 * 240) { 0x40 }, 320, 240))
    }

    @Test
    fun scannedTextBecomesTheStoredKey() {
        val text = QrDecoder().decode(frame(uri, 480, offsetX = 100), 480, 480)!!
        val r = OtpAuth.parse(text)
        assertTrue(r is OtpParse.Valid)
        assertEquals(uri, (r as OtpParse.Valid).key.value)
    }
}
