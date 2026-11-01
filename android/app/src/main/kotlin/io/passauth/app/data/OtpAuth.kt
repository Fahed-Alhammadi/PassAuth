package io.passauth.app.data

import java.net.URLDecoder

/** An authenticator key ready for the item's `login.totp` field. */
data class OtpKey(
    /** What is stored: the full `otpauth://totp/…` URI, or a bare base32 secret. */
    val value: String,
    val issuer: String = "",
    val account: String = "",
) {
    /** "Example (alice@example.com)", for notices. */
    val label: String
        get() = when {
            issuer.isNotEmpty() && account.isNotEmpty() -> "$issuer ($account)"
            else -> issuer.ifEmpty { account }
        }
}

sealed interface OtpParse {
    data class Valid(val key: OtpKey) : OtpParse
    data class Invalid(val reason: String) : OtpParse
}

/**
 * Reads authenticator keys from scanned QR codes, the clipboard or typing:
 * `otpauth://totp/…` URIs (kept whole, as the web vault stores them) and plain
 * base32 secrets. The checks mirror the core's TOTP parser (`crates/core/src/totp.rs`),
 * so anything accepted here produces codes.
 */
object OtpAuth {
    private const val PREFIX = "otpauth://totp/"

    fun parse(input: String): OtpParse {
        val text = input.trim()
        if (text.isEmpty()) return OtpParse.Invalid("Enter or scan an authenticator key.")
        val lower = text.lowercase()
        return when {
            lower.startsWith("otpauth-migration:") -> OtpParse.Invalid(
                "This is an authenticator app's export of several accounts. Scan the QR code a website shows when you set up two-step login.",
            )
            lower.startsWith("otpauth://hotp/") -> OtpParse.Invalid("This is a counter-based (HOTP) key. PassAuth supports time-based (TOTP) keys only.")
            lower.startsWith(PREFIX) -> parseUri(PREFIX + text.substring(PREFIX.length))
            lower.contains("://") -> OtpParse.Invalid("This isn't an authenticator key. Look for a QR code or key on the website's two-step login setup page.")
            else -> {
                val secret = cleanBase32(text)
                if (decodeBase32(secret) == null) {
                    OtpParse.Invalid("That isn't a valid authenticator key. Keys use the letters A–Z and digits 2–7.")
                } else {
                    OtpParse.Valid(OtpKey(secret))
                }
            }
        }
    }

    /** True when the stored value produces codes (empty counts as valid: no key). */
    fun isUsable(value: String?): Boolean = value.isNullOrBlank() || parse(value) is OtpParse.Valid

    private fun parseUri(uri: String): OtpParse {
        val rest = uri.substring(PREFIX.length)
        val path = rest.substringBefore('?')
        val query = if (rest.contains('?')) rest.substringAfter('?') else ""
        var secret: String? = null
        var issuerParam = ""
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val k = pair.substringBefore('=').lowercase()
            val v = if (pair.contains('=')) pair.substringAfter('=') else ""
            when (k) {
                "secret" -> secret = v
                "issuer" -> issuerParam = decode(v)
                "algorithm" -> if (v.uppercase() !in setOf("SHA1", "SHA256", "SHA512")) return OtpParse.Invalid("This key uses an unsupported algorithm ($v).")
                "digits" -> if (v.toIntOrNull()?.let { it in 6..10 } != true) return OtpParse.Invalid("This key asks for an unsupported number of digits ($v).")
                "period" -> if ((v.toLongOrNull() ?: 0) <= 0) return OtpParse.Invalid("This key has an invalid period ($v).")
            }
        }
        val s = secret ?: return OtpParse.Invalid("This QR code has no secret key in it.")
        if (decodeBase32(cleanBase32(s)) == null) return OtpParse.Invalid("The secret key in this QR code isn't valid.")
        val label = decode(path)
        val issuer = issuerParam.ifEmpty { if (label.contains(':')) label.substringBefore(':').trim() else "" }
        val account = if (label.contains(':')) label.substringAfter(':').trim() else label.trim()
        return OtpParse.Valid(OtpKey(uri, issuer, account))
    }

    private fun decode(s: String) = runCatching { URLDecoder.decode(s.replace("+", "%2B"), Charsets.UTF_8) }.getOrDefault(s)

    /** Spaces, hyphens and padding removed, upper case (what the core's decoder ignores). */
    fun cleanBase32(s: String): String = s.filter { !it.isWhitespace() && it != '-' && it != '=' }.uppercase()

    /** RFC 4648 base32 without padding, strict like the core's (`data_encoding::BASE32_NOPAD`); null if invalid or empty. */
    fun decodeBase32(s: String): ByteArray? {
        if (s.isEmpty() || s.length % 8 !in setOf(0, 2, 4, 5, 7)) return null
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0L
        var bits = 0
        for (c in s) {
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in '2'..'7' -> c - '2' + 26
                else -> return null
            }
            buffer = (buffer shl 5) or v.toLong()
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write(((buffer shr bits) and 0xff).toInt())
            }
        }
        // Leftover bits must be zero (canonical encoding).
        if (bits > 0 && (buffer and ((1L shl bits) - 1)) != 0L) return null
        return out.toByteArray().takeIf { it.isNotEmpty() }
    }
}
