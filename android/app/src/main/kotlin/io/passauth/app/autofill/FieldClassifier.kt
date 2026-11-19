package io.passauth.app.autofill

import android.text.InputType
import java.util.Locale

/** What a text field in a form is for. */
enum class FieldKind { Username, Password, Otp, Other }

/**
 * One editable text field of an autofill request, reduced to the facts the
 * heuristics need (no Android framework objects), so classification is unit-tested
 * on the JVM. [id] is the `AutofillId` in the service and anything in tests.
 */
data class FieldInfo<T>(
    val id: T,
    /** `View.getAutofillHints()` (Android hints or HTML autocomplete tokens). */
    val autofillHints: List<String> = emptyList(),
    /** `ViewNode.getInputType()`; 0 when unknown (most web fields). */
    val inputType: Int = 0,
    /** Resource entry name, e.g. "et_username". */
    val idEntry: String? = null,
    /** The hint (placeholder) shown in an empty field. */
    val hint: String? = null,
    /** Text of a label for the field, when the app provides one. */
    val label: String? = null,
    /** HTML tag for web content ("input"), null for native views. */
    val htmlTag: String? = null,
    /** HTML attributes for web content (type, name, id, autocomplete, placeholder, aria-label…). */
    val htmlAttrs: Map<String, String> = emptyMap(),
    /** Currently shown text (for save requests). */
    val value: String? = null,
    val focused: Boolean = false,
    /** Longest text the field takes (`maxTextLength` / HTML `maxlength`); 0 when unknown. */
    val maxLength: Int = 0,
)

/** The login fields found in one request, in document order. */
data class LoginForm<T>(
    val username: FieldInfo<T>?,
    val passwords: List<FieldInfo<T>>,
    val otp: FieldInfo<T>?,
) {
    val password: FieldInfo<T>? get() = passwords.firstOrNull()
    val isEmpty: Boolean get() = username == null && passwords.isEmpty() && otp == null

    /** The fields PassAuth fills with a login (username and every password field). */
    val fillIds: List<T> get() = listOfNotNull(username?.id) + passwords.map { it.id }
}

/**
 * Login-field heuristics: autofill hints first, then the input type, then the
 * HTML attributes and the field's id/hint text, like the extension's
 * `content/fields.ts` (same username and one-time-code patterns).
 */
object FieldClassifier {
    private val USER_HINT = Regex("user|email|login|account|identifier|mail|e-mail|username", RegexOption.IGNORE_CASE)
    private val OTP_HINT = Regex("otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code", RegexOption.IGNORE_CASE)
    private val PASSWORD_HINT = Regex("pass(word|wd|code)?\\b|pwd|passwort|mot.?de.?passe|contrase", RegexOption.IGNORE_CASE)
    private val SEARCH_HINT = Regex("search|query|find", RegexOption.IGNORE_CASE)
    /** "code" fields that are a verification code only when short (`sms_code`, "Enter code"), not a postal or promo code. */
    private val CODE_HINT = Regex("(^|[^a-z])code([^a-z]|$)|code$", RegexOption.IGNORE_CASE)
    private val NOT_OTP_CODE = Regex("post|zip|promo|coupon|voucher|gift|referr|invite|country|area|dial|discount|captcha|qr", RegexOption.IGNORE_CASE)

    /** Resource ids of browsers' address bars (and compatibility-mode structures): never a login field. */
    val URL_BAR_IDS = setOf(
        "url_bar", "location_bar_edit_text", "mozac_browser_toolbar_url_view", "url_edit_text", "url_field",
        "omnibarTextInput", "search_box", "addressbar_url", "url", "address_bar_edit_text", "urlbar", "edit_url",
    )
    private val TEXT_TYPES = setOf("text", "email", "tel", "")

    // Android hint constants (View.AUTOFILL_HINT_*, androidx HintConstants) and HTML autocomplete
    // tokens, lower-cased with separators removed.
    private val PASSWORD_HINTS = setOf("password", "currentpassword", "newpassword")
    private val USERNAME_HINTS = setOf("username", "newusername", "emailaddress", "email", "webauthn")
    private val OTP_HINTS = setOf("smsotpcode", "onetimecode", "2faappotpcode", "otp", "smsotp", "emailotpcode")
    /** Phone numbers are used as usernames by some apps: a candidate next to a password field. */
    private val PHONE_HINTS = setOf("phone", "phonenumber", "tel", "phonenational", "telnational")

    /** Hints that say a field is something else (address, card…): never treat those as login fields. */
    private val OTHER_HINTS = setOf(
        "name", "personname", "givenname", "familyname", "postaladdress", "postalcode", "streetaddress",
        "creditcardnumber", "creditcardsecuritycode", "creditcardexpirationdate", "creditcardexpirationmonth",
        "creditcardexpirationyear", "creditcardexpirationday", "ccnumber", "cccsc", "ccexp", "birthdate", "gender",
        "addresscountry", "addresslocality", "addressregion", "country", "organization", "phonecountrycode",
    )

    private fun norm(h: String) = h.lowercase(Locale.ROOT).filter { it.isLetterOrDigit() }

    private fun text(f: FieldInfo<*>): String = buildString {
        append(f.idEntry.orEmpty()).append(' ')
        append(f.hint.orEmpty()).append(' ')
        append(f.label.orEmpty()).append(' ')
        for (k in listOf("name", "id", "autocomplete", "placeholder", "aria-label", "label")) {
            append(f.htmlAttrs[k].orEmpty()).append(' ')
        }
    }

    private fun htmlType(f: FieldInfo<*>) = f.htmlAttrs["type"]?.lowercase(Locale.ROOT)

    private fun autocomplete(f: FieldInfo<*>) = f.htmlAttrs["autocomplete"]?.lowercase(Locale.ROOT).orEmpty()

    /** Password input types (text, number and web variations). */
    fun isPasswordInputType(type: Int): Boolean {
        val cls = type and InputType.TYPE_MASK_CLASS
        val variation = type and InputType.TYPE_MASK_VARIATION
        return when (cls) {
            InputType.TYPE_CLASS_TEXT -> variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            InputType.TYPE_CLASS_NUMBER -> variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
            else -> false
        }
    }

    private fun isEmailInputType(type: Int): Boolean {
        if (type and InputType.TYPE_MASK_CLASS != InputType.TYPE_CLASS_TEXT) return false
        val variation = type and InputType.TYPE_MASK_VARIATION
        return variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    }

    /** Text-like fields that could hold a username (not multi-line, dates, numbers…). */
    private fun isTextLike(f: FieldInfo<*>): Boolean {
        if (f.htmlTag != null) {
            if (!f.htmlTag.equals("input", ignoreCase = true)) return false
            return (htmlType(f) ?: "") in TEXT_TYPES
        }
        if (f.inputType == 0) return true
        val cls = f.inputType and InputType.TYPE_MASK_CLASS
        if (cls == InputType.TYPE_CLASS_PHONE) return true
        if (cls != InputType.TYPE_CLASS_TEXT) return false
        if (f.inputType and InputType.TYPE_TEXT_FLAG_MULTI_LINE != 0) return false
        val variation = f.inputType and InputType.TYPE_MASK_VARIATION
        return variation in setOf(
            InputType.TYPE_TEXT_VARIATION_NORMAL,
            InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
            InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS,
            InputType.TYPE_TEXT_VARIATION_WEB_EDIT_TEXT,
            InputType.TYPE_TEXT_VARIATION_FILTER,
        )
    }

    /** Classify one field on its own; [Username] here means "clearly a username field". */
    fun classify(f: FieldInfo<*>): FieldKind {
        if (f.htmlTag == null && f.idEntry != null && f.idEntry in URL_BAR_IDS) return FieldKind.Other
        val hints = f.autofillHints.map(::norm).filter { it.isNotEmpty() } + autocomplete(f).split(' ').map(::norm).filter { it.isNotEmpty() }
        if (hints.any { it in OTP_HINTS || (it.contains("otp") && !it.startsWith("cc")) }) return FieldKind.Otp
        if (hints.any { it in PASSWORD_HINTS }) return FieldKind.Password
        if (hints.any { it in USERNAME_HINTS }) return FieldKind.Username
        if (hints.any { it in OTHER_HINTS || it.startsWith("creditcard") || it.startsWith("postal") || it.startsWith("cc") }) {
            return FieldKind.Other
        }

        val type = htmlType(f)
        val t = text(f)
        if (f.htmlTag != null) {
            if (!f.htmlTag.equals("input", ignoreCase = true)) return FieldKind.Other
            if (type == "password") return FieldKind.Password
            val digits = type == "number" || type == "tel" || f.htmlAttrs["inputmode"].equals("numeric", ignoreCase = true)
            if (type == "number") return if (OTP_HINT.containsMatchIn(t) || shortCode(f, t, number = true)) FieldKind.Otp else FieldKind.Other
            if ((type ?: "") !in TEXT_TYPES) return FieldKind.Other
            if (OTP_HINT.containsMatchIn(t) || shortCode(f, t, number = digits)) return FieldKind.Otp
            if (SEARCH_HINT.containsMatchIn(t)) return FieldKind.Other
            if (type == "email" || USER_HINT.containsMatchIn(t)) return FieldKind.Username
            return FieldKind.Other
        }

        if (isPasswordInputType(f.inputType)) {
            return if (OTP_HINT.containsMatchIn(t)) FieldKind.Otp else FieldKind.Password
        }
        // Verification codes are often number fields.
        val number = f.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_NUMBER
        if ((number || isTextLike(f)) && (OTP_HINT.containsMatchIn(t) || shortCode(f, t, number))) return FieldKind.Otp
        if (!isTextLike(f)) return FieldKind.Other
        if (SEARCH_HINT.containsMatchIn(t)) return FieldKind.Other
        if (isEmailInputType(f.inputType)) return FieldKind.Username
        // A field whose id or hint says "password" but whose input type wasn't set as one.
        if (f.inputType == 0 && PASSWORD_HINT.containsMatchIn(t) && !USER_HINT.containsMatchIn(t)) return FieldKind.Password
        if (USER_HINT.containsMatchIn(t)) return FieldKind.Username
        return FieldKind.Other
    }

    /**
     * A short code field: named "code" (not a postal, promo… code) and taking 4–10 characters or
     * digits only; or a digits-only field of exactly 6 with nothing else said about it (the usual
     * verification code box).
     */
    private fun shortCode(f: FieldInfo<*>, t: String, number: Boolean): Boolean {
        if (NOT_OTP_CODE.containsMatchIn(t) || USER_HINT.containsMatchIn(t) || SEARCH_HINT.containsMatchIn(t)) return false
        val short = f.maxLength in 4..10
        if (CODE_HINT.containsMatchIn(t) && (short || number)) return true
        return number && f.maxLength == 6 && !PASSWORD_HINT.containsMatchIn(t)
    }

    /**
     * Find the login fields of a request ([fields] in document order). The
     * username is an explicit username field, else the closest text field before
     * the first password field (like the extension's `usernameFieldFor`). Without a
     * password field, only an explicit username field counts (identifier-first logins).
     */
    fun <T> parse(fields: List<FieldInfo<T>>): LoginForm<T> {
        val kinds = fields.map { it to classify(it) }
        val passwords = kinds.filter { it.second == FieldKind.Password }.map { it.first }
        val otp = kinds.firstOrNull { it.second == FieldKind.Otp }?.first
        val explicit = kinds.filter { it.second == FieldKind.Username }.map { it.first }
        val firstPw = passwords.firstOrNull()?.let { fields.indexOf(it) }
        val username = when {
            firstPw != null -> {
                // Prefer the explicit username closest before the password field, then any explicit one,
                // then the closest plain text field before it.
                explicit.lastOrNull { fields.indexOf(it) < firstPw }
                    ?: explicit.firstOrNull()
                    ?: kinds.take(firstPw).lastOrNull { (f, k) -> k == FieldKind.Other && isTextLike(f) && plainCandidate(f) }?.first
            }
            else -> explicit.firstOrNull()
        }
        return LoginForm(username, passwords, otp)
    }

    /** A text field without hints that rule it out as a username (search boxes, other hint types). */
    private fun plainCandidate(f: FieldInfo<*>): Boolean {
        if (f.idEntry != null && f.idEntry in URL_BAR_IDS) return false
        val hints = f.autofillHints.map(::norm).filter { it.isNotEmpty() }
        if (hints.any { it !in PHONE_HINTS }) return false
        val t = text(f)
        return !SEARCH_HINT.containsMatchIn(t) && !OTP_HINT.containsMatchIn(t)
    }
}
