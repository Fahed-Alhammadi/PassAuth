package io.passauth.app.data

import io.passauth.core.SavedUrl
import io.passauth.core.matchUrls
import io.passauth.core.matchesUrl
import io.passauth.core.normalizeHost
import java.net.URI
import java.util.Locale
import io.passauth.core.baseDomain as coreBaseDomain
import io.passauth.core.downgrade as coreDowngrade
import io.passauth.core.regexError as coreRegexError
import io.passauth.core.regexWarning as coreRegexWarning
import io.passauth.core.resolveMatch as coreResolveMatch

/**
 * Website matching for autofill: thin wrappers over the Rust core's site logic
 * (`crates/core/src/site`, the same code the extension, the web vault and the iOS app run), in
 * the app's own types. A saved website is a [LoginUrl]; "default" resolves with the user's
 * default match setting (`fallback`); [allowRegex] is false for a login in a vault somebody
 * shared, whose regular expressions never count. The core uses the full Public Suffix List,
 * parses addresses like browsers (WHATWG, UTS #46 host names) and runs patterns on a
 * linear-time engine; an `androidapp://` address is never a website.
 *
 * [parse] stays here for the app's other uses of an address: the host shown for a server or an
 * item, the server address check and the autofill target.
 */
object UrlMatcher {
    private val DEFAULT_PORTS = mapOf("http" to 80, "https" to 443, "ws" to 80, "wss" to 443, "ftp" to 21)

    /** The parts of a URL the app shows or checks, normalised like the browser's `URL`. */
    data class Parsed(
        val scheme: String,
        /** Lowercase host name without port (internationalised names in ASCII). */
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
        // java.net.URI takes a non-ASCII host for a registry name: no host, no port; read both from the authority.
        val authority = if (u.host == null) u.rawAuthority?.substringAfterLast('@') else null
        var hostname = (u.host ?: authority?.substringBefore(':') ?: "").lowercase(Locale.ROOT)
        if (hostname.isEmpty() && (scheme == "http" || scheme == "https")) return null
        // Internationalised names in their ASCII (punycode) form, as the browser's URL has them and
        // as the core converts them: "bücher.de" is "xn--bcher-kva.de", "straße.de" "xn--strae-oqa.de".
        if (!hostname.startsWith("[") && hostname.any { it.code > 0x7f }) {
            hostname = normalizeHost(hostname) ?: return null
        }
        val rawPort = authority?.substringAfter(':', "")?.takeIf { it.isNotEmpty() }
            ?.let { p -> p.toIntOrNull()?.takeIf { it in 0..65535 && p.all(Char::isDigit) } ?: return null }
        val port = (rawPort ?: u.port).takeIf { it >= 0 && it != DEFAULT_PORTS[scheme] }
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

    /**
     * The site a host belongs to, as "domain" matching compares it (the never-save list is keyed
     * by it): its registrable domain by the full Public Suffix List ("home.duckdns.org",
     * "nas.myfritz.net"), else the host itself (an IP address, a bare suffix, "localhost").
     */
    fun baseDomain(host: String): String = coreBaseDomain(host)

    /**
     * Does the page URL match a saved website? `fallback` resolves "default" (the user's setting).
     * [allowRegex]: regular expressions count only for the user's own items; a pattern from a
     * vault somebody shared was written by somebody else (and would run on every page the user
     * visits), so it never matches, also when "default" resolves to it.
     */
    fun matches(page: String, item: LoginUrl, fallback: UrlMatch = UrlMatch.Domain, allowRegex: Boolean = true): Boolean =
        matchesUrl(page, item.url, item.match.wire, fallback.wire, allowRegex)

    /** Any of the login's websites matches the page ([allowRegex]: see [matches]); one call into the core. */
    fun matchesAny(page: String, login: Login, fallback: UrlMatch = UrlMatch.Domain, allowRegex: Boolean = true): Boolean =
        login.urls.isNotEmpty() && matchUrls(page, fallback.wire, login.urls.map { SavedUrl(it.url, it.match.wire, allowRegex) }).any { it }

    /** Refuse to send a secret saved for an https site to an http page (localhost excepted). */
    fun downgrade(page: String, item: LoginUrl): Boolean = coreDowngrade(page, item.url, item.match.wire)

    /**
     * Why the core refuses [pattern] as a website pattern (longer than 300 characters, too large,
     * or syntax it doesn't have such as look-around or back-references), or null when it runs.
     */
    fun regexError(pattern: String): String? = coreRegexError(pattern)

    /** Under a pattern that doesn't pin its website (the core's `regexWarning`). */
    const val PATTERN_WARNING =
        "This pattern isn't tied to one website, so it could match other sites. Start it with ^https://example\\.com/ (your site's address)."

    /**
     * What the item editor says under a saved website, or null: only for an entry the core runs as
     * a regular expression (`resolveMatch` gives "regex": the "Regular expression" match, or
     * "Default" while that is the default and the entry isn't a plain address), why the core refuses
     * it, or [PATTERN_WARNING] when it isn't anchored to one website. Saving is never blocked.
     */
    fun patternNote(url: String, match: UrlMatch, fallback: UrlMatch): String? {
        val pattern = url.trim()
        if (pattern.isEmpty() || coreResolveMatch(pattern, match.wire, fallback.wire) != "regex") return null
        regexError(pattern)?.let { return "This pattern never matches a page: $it" }
        return if (coreRegexWarning(pattern) != null) PATTERN_WARNING else null
    }
}
