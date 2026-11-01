package io.passauth.app.autofill

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FieldClassifierTest {
    private val text = InputType.TYPE_CLASS_TEXT
    private val password = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    private val email = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
    private val number = InputType.TYPE_CLASS_NUMBER

    private fun native(id: String, inputType: Int = text, hints: List<String> = emptyList(), entry: String? = null, hint: String? = null) =
        FieldInfo(id, autofillHints = hints, inputType = inputType, idEntry = entry, hint = hint)

    private fun web(id: String, vararg attrs: Pair<String, String>) = FieldInfo(id, htmlTag = "input", htmlAttrs = mapOf(*attrs))

    @Test
    fun autofillHintsWin() {
        assertEquals(FieldKind.Password, FieldClassifier.classify(native("p", text, listOf("password"))))
        assertEquals(FieldKind.Password, FieldClassifier.classify(native("p", text, listOf("newPassword"))))
        assertEquals(FieldKind.Username, FieldClassifier.classify(native("u", text, listOf("emailAddress"))))
        assertEquals(FieldKind.Username, FieldClassifier.classify(native("u", text, listOf("username"))))
        assertEquals(FieldKind.Otp, FieldClassifier.classify(native("o", number, listOf("smsOTPCode"))))
        // A field marked as something else is never a login field, whatever its id says.
        assertEquals(FieldKind.Other, FieldClassifier.classify(native("c", text, listOf("creditCardNumber"), entry = "login_card")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(native("z", text, listOf("postalCode"))))
    }

    @Test
    fun inputTypesAndIds() {
        assertEquals(FieldKind.Password, FieldClassifier.classify(native("p", password)))
        assertEquals(FieldKind.Password, FieldClassifier.classify(native("p", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD)))
        assertEquals(FieldKind.Password, FieldClassifier.classify(native("p", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)))
        assertEquals(FieldKind.Username, FieldClassifier.classify(native("e", email)))
        assertEquals(FieldKind.Username, FieldClassifier.classify(native("u", text, entry = "et_username")))
        assertEquals(FieldKind.Username, FieldClassifier.classify(native("u", text, hint = "Email or phone")))
        assertEquals(FieldKind.Otp, FieldClassifier.classify(native("o", number, hint = "Verification code")))
        assertEquals(FieldKind.Otp, FieldClassifier.classify(native("o", password, entry = "otp_input")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(native("s", text, entry = "search_user")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(native("m", text or InputType.TYPE_TEXT_FLAG_MULTI_LINE, entry = "user_bio")))
    }

    @Test
    fun htmlAttributes() {
        assertEquals(FieldKind.Password, FieldClassifier.classify(web("p", "type" to "password", "name" to "pw")))
        assertEquals(FieldKind.Username, FieldClassifier.classify(web("u", "type" to "email")))
        assertEquals(FieldKind.Username, FieldClassifier.classify(web("u", "type" to "text", "name" to "login")))
        assertEquals(FieldKind.Username, FieldClassifier.classify(web("u", "type" to "text", "autocomplete" to "username")))
        assertEquals(FieldKind.Otp, FieldClassifier.classify(web("o", "type" to "text", "autocomplete" to "one-time-code")))
        assertEquals(FieldKind.Otp, FieldClassifier.classify(web("o", "type" to "tel", "name" to "totp")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(web("q", "type" to "search", "name" to "q")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(web("q", "type" to "text", "name" to "search_users")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(web("h", "type" to "hidden", "name" to "user")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(FieldInfo("t", htmlTag = "textarea", htmlAttrs = mapOf("name" to "user"))))
    }

    @Test
    fun usernameIsTheClosestTextFieldBeforeThePassword() {
        val form = FieldClassifier.parse(
            listOf(native("search", text, entry = "search"), native("first", text), native("second", text), native("pw", password)),
        )
        assertEquals("second", form.username?.id)
        assertEquals(listOf("pw"), form.passwords.map { it.id })
        assertEquals(listOf("second", "pw"), form.fillIds)
    }

    @Test
    fun explicitUsernameWins() {
        val form = FieldClassifier.parse(listOf(web("e", "type" to "email", "name" to "email"), web("x", "type" to "text", "name" to "nickname"), web("p", "type" to "password")))
        assertEquals("e", form.username?.id)
    }

    @Test
    fun phoneHintIsAUsernameCandidate() {
        val form = FieldClassifier.parse(listOf(native("tel", InputType.TYPE_CLASS_PHONE, listOf("phone")), native("pw", password)))
        assertEquals("tel", form.username?.id)
    }

    @Test
    fun identifierFirstAndOtpOnlyForms() {
        val first = FieldClassifier.parse(listOf(web("u", "type" to "email", "autocomplete" to "username"), web("n", "type" to "text", "name" to "nickname")))
        assertEquals("u", first.username?.id)
        assertTrue(first.passwords.isEmpty())

        val nothing = FieldClassifier.parse(listOf(web("n", "type" to "text", "name" to "nickname")))
        assertTrue(nothing.isEmpty)

        val otp = FieldClassifier.parse(listOf(native("code", number, listOf("smsOTPCode"))))
        assertEquals("code", otp.otp?.id)
        assertTrue(otp.fillIds.isEmpty())
        assertNull(otp.username)
    }

    @Test
    fun signUpFormKeepsEveryPasswordField() {
        val form = FieldClassifier.parse(listOf(native("u", email), native("p1", password, hints = listOf("newPassword")), native("p2", password)))
        assertEquals(listOf("p1", "p2"), form.passwords.map { it.id })
        assertEquals("u", form.username?.id)
    }
}
