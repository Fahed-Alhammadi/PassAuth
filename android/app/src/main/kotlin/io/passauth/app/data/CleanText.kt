package io.passauth.app.data

/**
 * Text that came from elsewhere (the server, another device, another member's item), made safe to
 * show: the web vault's `lib/text.ts` with the same rules. Pure, unit-tested in CleanTextTest.
 */
object CleanText {
    /**
     * Characters that change how text around them looks without being seen themselves: format
     * characters (Unicode Cf: bidi embeddings, overrides and isolates, the marks U+200E/F,
     * zero-width spaces and joiners, the byte order mark), and the Hangul fillers that render as blanks.
     */
    private fun isFormat(cp: Int) =
        Character.getType(cp) == Character.FORMAT.toInt() || cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0

    /** Control characters (Unicode Cc: C0, DEL, C1) and the line and paragraph separators. */
    private fun isControl(cp: Int): Boolean {
        val t = Character.getType(cp)
        return t == Character.CONTROL.toInt() || t == Character.LINE_SEPARATOR.toInt() || t == Character.PARAGRAPH_SEPARATOR.toInt()
    }

    /** White space as JavaScript's `\s` and `trim()` see it. */
    fun isSpace(cp: Int): Boolean = when (cp) {
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF -> true
        else -> cp in 0x2000..0x200A
    }

    /** [s] without control and format characters (for file names: nothing is put in their place). */
    fun stripInvisible(s: String): String {
        val out = StringBuilder(s.length)
        forEachCodePoint(s) { cp -> if (!isFormat(cp) && !isControl(cp)) out.appendCodePoint(cp) }
        return out.toString()
    }

    /** Runs of white space folded into one space. */
    fun foldSpace(s: String): String {
        val out = StringBuilder(s.length)
        var space = false
        forEachCodePoint(s) { cp ->
            if (isSpace(cp)) {
                if (!space) out.append(' ')
                space = true
            } else {
                out.appendCodePoint(cp)
                space = false
            }
        }
        return out.toString()
    }

    /** [s] without white space at either end (JavaScript's `trim`). */
    fun trim(s: String): String {
        var start = 0
        var end = s.length
        while (start < end && isSpace(s.codePointAt(start))) start += Character.charCount(s.codePointAt(start))
        while (end > start && isSpace(s.codePointBefore(end))) end -= Character.charCount(s.codePointBefore(end))
        return s.substring(start, end)
    }

    /** [s] without white space at its end. */
    fun trimEnd(s: String): String {
        var end = s.length
        while (end > 0 && isSpace(s.codePointBefore(end))) end -= Character.charCount(s.codePointBefore(end))
        return s.substring(0, end)
    }

    /** Characters (code points) of [s]. */
    fun length(s: String): Int = s.codePointCount(0, s.length)

    /** The first [n] characters (code points) of [s]. */
    fun take(s: String, n: Int): String = if (n >= length(s)) s else s.substring(0, s.offsetByCodePoints(0, n.coerceAtLeast(0)))

    /**
     * [value] as one line of plain text to show: format characters removed, control characters and
     * line breaks turned into spaces, runs of white space folded into one, trimmed, and at most
     * [max] characters (code points), the last one then an ellipsis.
     */
    fun oneLine(value: String?, max: Int): String {
        if (value == null) return ""
        val spaced = StringBuilder(value.length)
        forEachCodePoint(value) { cp ->
            when {
                isFormat(cp) -> Unit
                isControl(cp) -> spaced.append(' ')
                else -> spaced.appendCodePoint(cp)
            }
        }
        val s = trim(foldSpace(spaced.toString()))
        return if (length(s) <= max) s else trimEnd(take(s, (max - 1).coerceAtLeast(0))) + "…"
    }

    private inline fun forEachCodePoint(s: String, f: (Int) -> Unit) {
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            f(cp)
            i += Character.charCount(cp)
        }
    }
}
