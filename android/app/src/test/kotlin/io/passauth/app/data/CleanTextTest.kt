package io.passauth.app.data

import org.junit.Assert.assertEquals
import org.junit.Test

/** [CleanText]: the cases of the web vault's `text.test.ts` that apply (Kotlin's types rule out non-strings). */
class CleanTextTest {
    @Test
    fun dropsControlAndFormatCharactersBidiOverridesAndIsolatesIncluded() {
        assertEquals("invoicefdp.exe", CleanText.stripInvisible("invoice‮fdp.exe"))
        assertEquals("abcde", CleanText.stripInvisible("a‪b‫c‬d‭e"))
        assertEquals("abcde", CleanText.stripInvisible("a⁦b⁧c⁨d⁩e"))
        assertEquals("abcde", CleanText.stripInvisible("﻿a‎b‏c​d‍e"))
        assertEquals("abcdefg", CleanText.stripInvisible("a\u0000b\u001Fc\u007Fd\u0085e f g"))
        assertEquals("ab", CleanText.stripInvisible("aㅤb"))
        assertEquals("Grüße, 東京 🙂", CleanText.stripInvisible("Grüße, 東京 🙂"))
    }

    @Test
    fun makesOneLineOfAtMostSoManyCharacters() {
        assertEquals("Chrome on macOS", CleanText.oneLine("  Chrome\u000Aon\u0009macOS  ", 64))
        assertEquals("Your MacBook", CleanText.oneLine("Your‮ MacBook", 64))
        assertEquals("x".repeat(63) + "…", CleanText.oneLine("x".repeat(70), 64))
        assertEquals(10, CleanText.length(CleanText.oneLine("🙂".repeat(70), 10)))
        assertEquals("exactly ten", CleanText.oneLine("exactly ten", 11))
        assertEquals("", CleanText.oneLine(null, 64))
    }
}
