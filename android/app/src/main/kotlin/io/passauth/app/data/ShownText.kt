package io.passauth.app.data

/**
 * Text PassAuth shows that someone else wrote: a server's error message, the name a new device
 * gives itself in a sign-in request. It is shown as plain text and first cleaned here, so it can't
 * reorder or hide PassAuth's own words around it: tabs and line breaks become spaces, control and
 * format characters (Unicode Cc and Cf: bidi overrides and isolates U+202A–E and U+2066–9, the marks
 * U+200E/F, U+FEFF…) are dropped, runs of spaces collapse, and it is cut to `max` characters (code
 * points), with an ellipsis when cut. The same rules as the extension's `shownText`.
 */
object ShownText {
    private fun isBreak(cp: Int) =
        cp == 0x09 || cp == 0x0A || cp == 0x0B || cp == 0x0C || cp == 0x0D || cp == 0x85 || cp == 0x2028 || cp == 0x2029

    fun clean(text: String?, max: Int): String {
        if (text.isNullOrEmpty() || max <= 0) return ""
        val out = StringBuilder()
        var space = false
        var i = 0
        while (i < text.length) {
            val cp = text.codePointAt(i)
            i += Character.charCount(cp)
            val type = Character.getType(cp)
            when {
                isBreak(cp) || type == Character.SPACE_SEPARATOR.toInt() -> space = out.isNotEmpty()
                type == Character.CONTROL.toInt() || type == Character.FORMAT.toInt() -> Unit
                else -> {
                    if (space) out.append(' ')
                    space = false
                    out.appendCodePoint(cp)
                }
            }
        }
        val clean = out.toString()
        if (clean.codePointCount(0, clean.length) <= max) return clean
        return clean.substring(0, clean.offsetByCodePoints(0, max - 1)).trimEnd() + "…"
    }
}
