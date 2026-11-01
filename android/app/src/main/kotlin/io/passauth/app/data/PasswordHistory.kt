package io.passauth.app.data

import java.text.DateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Formatting of an item's previous passwords (`password_history`). */
object PasswordHistory {
    /** Previous passwords to show, newest first (empty ones are dropped). */
    fun entries(history: List<PasswordChange>): List<PasswordChange> =
        history.filter { it.password.isNotEmpty() }.sortedByDescending { it.changedAt }

    /** "Password history" row label with its count. */
    fun summary(count: Int): String = when (count) {
        0 -> "No previous passwords"
        1 -> "1 previous password"
        else -> "$count previous passwords"
    }

    /** When the password stopped being current, e.g. "Changed Jan 2, 2026, 3:04 PM". */
    fun changedLabel(unixSeconds: Long, locale: Locale = Locale.getDefault(), zone: TimeZone = TimeZone.getDefault()): String {
        if (unixSeconds <= 0) return "Date unknown"
        val f = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale).apply { timeZone = zone }
        return "Changed " + f.format(Date(unixSeconds * 1000))
    }
}
