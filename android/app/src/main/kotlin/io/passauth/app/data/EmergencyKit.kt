package io.passauth.app.data

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import java.io.OutputStream

/**
 * The Emergency Kit (the web vault's `kit.ts`): server, email, Secret Key and a line
 * to write the master password on. Saved as a PDF only to a place the user picks.
 */
object EmergencyKit {
    const val FILE_NAME = "PassAuth Emergency Kit.pdf"

    private const val INTRO =
        "Print this page or keep it somewhere safe and offline, such as a drawer or a safe. You need it to sign in on a new device. " +
            "Nobody, not even your server administrator, can recover your master password or Secret Key for you."
    private const val WARN = "Write your master password by hand only if this kit is stored somewhere nobody else can reach."

    /** One A4 page (points). */
    fun writePdf(out: OutputStream, server: String, email: String, secretKey: String, created: String) {
        val doc = PdfDocument()
        try {
            val page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, 1).create())
            val c = page.canvas
            val left = 56f
            val width = 595 - 2 * 56
            var y = 64f
            fun text(s: String, size: Float, color: Int = 0xFF0B1A3A.toInt(), bold: Boolean = false, mono: Boolean = false): Float {
                val paint = TextPaint(TextPaint.ANTI_ALIAS_FLAG).apply {
                    textSize = size
                    this.color = color
                    typeface = Typeface.create(if (mono) Typeface.MONOSPACE else Typeface.SANS_SERIF, if (bold) Typeface.BOLD else Typeface.NORMAL)
                }
                val layout = StaticLayout.Builder.obtain(s, 0, s.length, paint, width).setAlignment(Layout.Alignment.ALIGN_NORMAL).build()
                c.save()
                c.translate(left, y)
                layout.draw(c)
                c.restore()
                return layout.height.toFloat()
            }
            val muted = 0xFF5A6A85.toInt()
            val line = android.graphics.Paint().apply { color = 0xFFD6DFEC.toInt(); strokeWidth = 1f }
            y += text("PassAuth Emergency Kit", 24f, bold = true) + 6
            y += text("Created $created", 11f, muted) + 18
            y += text(INTRO, 12f) + 24
            for ((label, value, mono) in listOf(Triple("SERVER", server, true), Triple("EMAIL", email, false), Triple("SECRET KEY", secretKey, true))) {
                y += text(label, 9f, muted) + 4
                y += text(value, 14f, mono = mono) + 12
                c.drawLine(left, y, left + width, y, line)
                y += 14
            }
            y += text("MASTER PASSWORD", 9f, muted) + 36
            c.drawLine(left, y, left + width, y, android.graphics.Paint().apply { color = Color.BLACK; strokeWidth = 1f })
            y += 28
            text(WARN, 11f, 0xFF6B4000.toInt())
            doc.finishPage(page)
            doc.writeTo(out)
        } finally {
            doc.close()
        }
    }
}
