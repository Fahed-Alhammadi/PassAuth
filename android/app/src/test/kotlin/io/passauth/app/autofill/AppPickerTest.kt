package io.passauth.app.autofill

import android.text.InputType
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** "Choose a login…" in apps, and verification-code fields. */
class AppPickerTest {
    private val text = InputType.TYPE_CLASS_TEXT
    private val password = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    private val number = InputType.TYPE_CLASS_NUMBER

    private fun form(vararg f: FieldInfo<String>) = FieldClassifier.parse(f.toList())
    private val signIn = form(FieldInfo("u", inputType = text, idEntry = "username"), FieldInfo("p", inputType = password))
    private val userOnly = form(FieldInfo("u", inputType = text, idEntry = "email"))
    private val codeOnly = form(FieldInfo("c", inputType = number, idEntry = "otp"))

    @Test
    fun pickerEntryOnSignInFormsWithoutAMatch() {
        assertTrue(AddSite.offerEntry(allowed = true, matched = false, form = signIn, app = true) { true })
        assertEquals("Choose a login…", AddSite.entryTitle(app = true))
        assertEquals("Add this site to a login…", AddSite.entryTitle(app = false))
        // An app's first step asking only for the user name gets it too; a website's doesn't.
        assertTrue(AddSite.offerEntry(true, false, userOnly, app = true) { true })
        assertFalse(AddSite.offerEntry(true, false, userOnly, app = false) { true })
        // Not when something matched, on a code-only screen, when not allowed, or with nothing to pick.
        assertFalse(AddSite.offerEntry(true, matched = true, form = signIn, app = true) { true })
        assertFalse(AddSite.offerEntry(true, false, codeOnly, app = true) { true })
        assertFalse(AddSite.offerEntry(allowed = false, matched = false, form = signIn, app = true) { true })
        assertFalse(AddSite.offerEntry(true, false, signIn, app = true) { false })
    }

    @Test
    fun guessedLoginsComeFirstButAreOnlySorted() {
        val logins = mapOf(
            "a" to Login(username = "a", urls = listOf(LoginUrl("https://example.com", UrlMatch.Default))),
            "b" to Login(username = "b", urls = listOf(LoginUrl("https://www.instagram.com", UrlMatch.Default))),
            "c" to Login(username = "c", urls = listOf(LoginUrl("https://other.org", UrlMatch.Default))),
        )
        val targets = logins.map { (id, l) -> AddSite.Target(id, id, l.username, AddSite.siteOf(l), personal = true) }
        assertEquals(listOf("b", "a", "c"), AddSite.guessesFirst(targets, listOf("instagram.com")) { logins[it] }.map { it.id })
        assertEquals(listOf("a", "b", "c"), AddSite.guessesFirst(targets, emptyList()) { logins[it] }.map { it.id })
        // A guess alone never makes a login a match for the app (only asset links do).
        val app = FillTarget.App("com.instagram.android")
        assertFalse(AutofillMatcher.matches(app, logins.getValue("b"), UrlMatch.Domain, allowRegex = true))
    }

    @Test
    fun verificationCodeFields() {
        fun kind(f: FieldInfo<String>) = FieldClassifier.classify(f)
        // Hints and autocomplete.
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", htmlTag = "input", htmlAttrs = mapOf("autocomplete" to "one-time-code"))))
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", inputType = number, autofillHints = listOf("2faAppOTPCode"))))
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", inputType = text, autofillHints = listOf("emailOTPCode"))))
        // Names: otp/totp/2fa, or a short "code" field.
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", inputType = number, idEntry = "totp_input")))
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", inputType = text, idEntry = "sms_code", maxLength = 6)))
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", inputType = number, hint = "Enter code")))
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", htmlTag = "input", htmlAttrs = mapOf("type" to "number", "name" to "code"))))
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", htmlTag = "input", htmlAttrs = mapOf("type" to "text", "name" to "code", "maxlength" to "6"), maxLength = 6)))
        // A six-digit number box with nothing else said about it.
        assertEquals(FieldKind.Otp, kind(FieldInfo("c", inputType = number, maxLength = 6)))
        // Not verification codes: postal, promo and long "code" fields, other numbers.
        assertEquals(FieldKind.Other, kind(FieldInfo("c", inputType = text, idEntry = "postal_code", maxLength = 6)))
        assertEquals(FieldKind.Other, kind(FieldInfo("c", inputType = text, idEntry = "promo_code", maxLength = 8)))
        assertEquals(FieldKind.Other, kind(FieldInfo("c", inputType = text, idEntry = "code")))
        assertEquals(FieldKind.Other, kind(FieldInfo("c", inputType = number, maxLength = 4)))
        assertEquals(FieldKind.Other, kind(FieldInfo("c", htmlTag = "input", htmlAttrs = mapOf("type" to "number", "name" to "quantity"))))
        // A code-only screen is a form PassAuth answers (with the logins that have a code).
        val f = FieldClassifier.parse(listOf(FieldInfo("c", inputType = number, maxLength = 6)))
        assertEquals("c", f.otp?.id)
        assertTrue(f.fillIds.isEmpty())
    }
}
