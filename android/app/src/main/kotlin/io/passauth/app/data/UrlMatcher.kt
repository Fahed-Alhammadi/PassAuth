package io.passauth.app.data

import java.net.URI
import java.util.Locale

/**
 * Website matching for autofill: a port of the extension's `background/urls.ts`,
 * with the same semantics (including WHATWG-style URL normalisation for
 * "exact" and "starts with").
 */
object UrlMatcher {
    // "domain" matching uses the shared suffix list in [PublicSuffixes]. It is not the full
    // Public Suffix List: hosts under an unlisted multi-label suffix fall back to the last
    // two labels, which can over-match. Use "host" matching on such items.

    /** Longest regex pattern PassAuth evaluates (patterns come from shared vaults too). */
    const val MAX_REGEX_LENGTH = 300

    /**
     * Patterns likely to backtrack catastrophically: a quantified group that itself
     * contains a quantifier, e.g. "(a+)+" or "(.*a){10}". They are not evaluated.
     */
    fun unsafeRegex(pattern: String): Boolean =
        pattern.length > MAX_REGEX_LENGTH || Regex("""\([^)]*[+*}][^)]*\)\s*[+*{]""").containsMatchIn(pattern)

    private val DEFAULT_PORTS = mapOf("http" to 80, "https" to 443, "ws" to 80, "wss" to 443, "ftp" to 21)

    /** The parts of a URL the matcher needs, normalised like the browser's `URL`. */
    data class Parsed(
        val scheme: String,
        /** Lowercase host name without port. */
        val hostname: String,
        /** Host name plus a non-default port. */
        val host: String,
        val href: String,
    ) {
        val origin: String get() = "$scheme://$host"
    }

    /** Parse like `new URL(url.includes("://") ? url : "https://" + url)`; null if invalid. */
    fun parse(url: String): Parsed? {
        val text = url.trim().let { if (it.contains("://")) it else "https://$it" }
        val u = try {
            URI(text)
        } catch (_: Exception) {
            return null
        }
        val scheme = u.scheme?.lowercase(Locale.ROOT) ?: return null
        if (u.isOpaque) return Parsed(scheme, "", "", text)
        val hostname = (u.host ?: u.rawAuthority?.substringAfterLast('@')?.substringBefore(':') ?: "")
            .lowercase(Locale.ROOT)
        if (hostname.isEmpty() && (scheme == "http" || scheme == "https")) return null
        val port = u.port.takeIf { it >= 0 && it != DEFAULT_PORTS[scheme] }
        val host = if (port != null) "$hostname:$port" else hostname
        val href = buildString {
            append(scheme).append("://")
            u.rawUserInfo?.let { append(it).append('@') }
            append(host)
            append(u.rawPath?.takeIf { it.isNotEmpty() } ?: "/")
            u.rawQuery?.let { append('?').append(it) }
            u.rawFragment?.let { append('#').append(it) }
        }
        return Parsed(scheme, hostname, host, href)
    }

    fun baseDomain(host: String): String {
        val h = host.lowercase(Locale.ROOT).removeSuffix(".")
        if (h.all { it.isDigit() || it == '.' } || h.contains(':') || !h.contains('.')) return h
        val labels = h.split('.')
        val suffix = PublicSuffixes.suffixOf(h)
        if (suffix.isEmpty()) return labels.takeLast(2).joinToString(".")
        // One label more than the public suffix ("home.duckdns.org"); a bare suffix stays as it is.
        val n = suffix.count { it == '.' } + 2
        return labels.takeLast(minOf(n, labels.size)).joinToString(".")
    }

    /** Does the page URL match a saved website? `fallback` resolves "default" (the user's setting). */
    fun matches(page: String, item: LoginUrl, fallback: UrlMatch = UrlMatch.Domain): Boolean {
        val p = parse(page) ?: return false
        if (p.scheme != "http" && p.scheme != "https") return false
        val match = if (item.match == UrlMatch.Default) fallback else item.match
        if (match == UrlMatch.Never || match == UrlMatch.Default) return false
        if (match == UrlMatch.Regex) {
            if (unsafeRegex(item.url)) return false
            // Only the page's origin and path (no query or fragment, so "?bank.com" can't satisfy it).
            val path = runCatching { URI(p.href).rawPath }.getOrNull()?.ifEmpty { "/" } ?: "/"
            return try {
                Regex(item.url, RegexOption.IGNORE_CASE).containsMatchIn((p.origin + path).take(2048))
            } catch (_: Exception) {
                false
            }
        }
        val u = parse(item.url) ?: return false
        return when (match) {
            UrlMatch.Exact -> p.href == u.href
            UrlMatch.StartsWith -> p.href.startsWith(u.href)
            UrlMatch.Host -> p.host == u.host
            else -> baseDomain(p.hostname) == baseDomain(u.hostname)
        }
    }

    /** Any of the login's websites matches the page. */
    fun matchesAny(page: String, login: Login, fallback: UrlMatch = UrlMatch.Domain): Boolean =
        login.urls.any { matches(page, it, fallback) }

    /** Refuse to send a secret saved for an https site to an http page. */
    fun downgrade(page: String, item: LoginUrl): Boolean {
        if (item.match == UrlMatch.Regex) {
            return Regex("^http:", RegexOption.IGNORE_CASE).containsMatchIn(page) &&
                !Regex("^https?://localhost[:/]", RegexOption.IGNORE_CASE).containsMatchIn(page) &&
                Regex("^\\^?https:", RegexOption.IGNORE_CASE).containsMatchIn(item.url)
        }
        val p = parse(page) ?: return false
        val u = parse(item.url) ?: return false
        return u.scheme == "https" && p.scheme == "http" && p.hostname != "localhost"
    }
}
