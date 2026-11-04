package io.passauth.app.data

import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder

/** The modules of a QR code, [size] × [size] including the quiet zone; true = dark. */
class QrMatrix(val size: Int, private val dark: BooleanArray) {
    operator fun get(x: Int, y: Int): Boolean = dark[y * size + x]
}

/** QR codes with ZXing core (pure JVM, no bitmaps): drawn by the UI module by module. */
object QrEncoder {
    fun encode(text: String, quietZone: Int = 2): QrMatrix {
        val m = Encoder.encode(text, ErrorCorrectionLevel.M, mapOf(EncodeHintType.CHARACTER_SET to "UTF-8")).matrix
        val size = m.width + quietZone * 2
        val dark = BooleanArray(size * size)
        for (y in 0 until m.height) {
            for (x in 0 until m.width) {
                if (m.get(x, y).toInt() == 1) dark[(y + quietZone) * size + x + quietZone] = true
            }
        }
        return QrMatrix(size, dark)
    }
}
