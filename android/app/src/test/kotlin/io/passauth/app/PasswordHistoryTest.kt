package io.passauth.app

import io.passauth.app.data.PasswordChange
import io.passauth.app.data.PasswordHistory
import java.util.Locale
import java.util.TimeZone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordHistoryTest {
    @Test
    fun newestFirstWithoutEmptyEntries() {
        val list = listOf(PasswordChange("old", 100), PasswordChange("", 300), PasswordChange("newer", 200))
        assertEquals(listOf("newer", "old"), PasswordHistory.entries(list).map { it.password })
    }

    @Test
    fun summaries() {
        assertEquals("No previous passwords", PasswordHistory.summary(0))
        assertEquals("1 previous password", PasswordHistory.summary(1))
        assertEquals("3 previous passwords", PasswordHistory.summary(3))
    }

    @Test
    fun changedLabels() {
        // 2026-01-02 15:04:05 UTC
        val label = PasswordHistory.changedLabel(1767366245, Locale.US, TimeZone.getTimeZone("UTC"))
        assertTrue(label, label.startsWith("Changed Jan 2, 2026"))
        assertTrue(label, label.contains("3:04"))
        val berlin = PasswordHistory.changedLabel(1767366245, Locale.US, TimeZone.getTimeZone("Europe/Berlin"))
        assertTrue(berlin, berlin.contains("4:04"))
        assertEquals("Date unknown", PasswordHistory.changedLabel(0))
    }
}
