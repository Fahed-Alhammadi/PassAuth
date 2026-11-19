package io.passauth.app.autofill

import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import java.util.Locale

/**
 * Which websites an app belongs to, so a login saved on a website is offered in the site's app.
 *
 * - [candidates]: the base domains worth checking for an app, guessed from its package name
 *   (`com.instagram.android` → `instagram.com`) and kept only when one of the user's logins is
 *   saved for that domain. A guess alone never fills anything: any app can pick any package name.
 * - The service then checks each candidate's Digital Asset Links
 *   (`https://<domain>/.well-known/assetlinks.json`, also `www.<domain>`): only a domain that lists
 *   the app with the signing certificate it is installed with ([io.passauth.app.credentials.AssetLinks.APP_LOGIN_RELATIONS])
 *   becomes one of [FillTarget.App.linkedDomains], and only those logins are suggested.
 * - Unverified guesses only sort the "Choose a login…" picker, where the user decides.
 *
 * Pure logic: the base domain function is passed in (the core's in the app), so this is unit-tested.
 */
object AppLinks {
    /** At most this many domains are checked per app (each one is a network request on a cache miss). */
    const val MAX_CANDIDATES = 3

    /** Package name parts that say nothing about the website ("android", "app", build flavours…). */
    private val FILLER = setOf(
        "android", "app", "apps", "application", "mobile", "client", "lite", "droid", "phone", "free", "pro",
        "prod", "production", "release", "beta", "alpha", "debug", "main", "official", "global", "intl", "international",
        "mobileapp", "androidapp", "and", "mob", "activity", "launcher",
    )

    /** Generic first parts (country codes, com, org…) never matched as a brand. */
    private fun generic(label: String) = label.length < 3 || label in setOf("com", "org", "net", "edu", "gov", "www", "co")

    private fun labels(packageName: String): List<String> =
        packageName.lowercase(Locale.ROOT).split('.').map { it.trim() }.filter { it.isNotEmpty() && it.all { c -> c.isLetterOrDigit() || c == '-' } }

    /**
     * Domains spelled by the package name in reverse (`com.example.mail.android` → `example.com`,
     * `mail.example.com`), without trailing filler parts. Not checked against anything.
     */
    fun packageDomains(packageName: String): List<String> {
        val l = labels(packageName).toMutableList()
        while (l.size > 2 && l.last() in FILLER) l.removeAt(l.size - 1)
        if (l.size < 2) return emptyList()
        return (2..l.size).map { n -> l.take(n).reversed().joinToString(".") }
    }

    /** The base domain of a login website the app could belong to (http/https, not "never" or a regular expression). */
    fun webBase(url: LoginUrl, baseDomain: (String) -> String): String? {
        if (url.match == UrlMatch.Never || url.match == UrlMatch.Regex) return null
        val p = UrlMatcher.parse(url.url.trim()) ?: return null
        if (p.scheme != "http" && p.scheme != "https" || p.hostname.isEmpty()) return null
        return baseDomain(p.hostname).lowercase(Locale.ROOT).ifEmpty { null }
    }

    /** The base domains the [logins] are saved for. */
    fun loginBases(logins: List<Login>, baseDomain: (String) -> String): Set<String> =
        logins.flatMap { l -> l.urls.mapNotNull { webBase(it, baseDomain) } }.toSet()

    /**
     * The base domains to check for [packageName]: base domains of [packageDomains], then
     * login domains whose name is a distinctive part of the package (`com.amazon.mShop.android`
     * → `amazon.de` when a login is saved there), kept only if in [loginBases]. At most
     * [MAX_CANDIDATES], best guesses first.
     */
    fun candidates(packageName: String, loginBases: Set<String>, baseDomain: (String) -> String): List<String> {
        if (loginBases.isEmpty()) return emptyList()
        val out = LinkedHashSet<String>()
        for (d in packageDomains(packageName)) {
            val base = baseDomain(d).lowercase(Locale.ROOT)
            if (base in loginBases) out += base
        }
        val parts = labels(packageName).drop(1).filter { !generic(it) && it !in FILLER }.toSet()
        if (parts.isNotEmpty()) {
            for (base in loginBases.sorted()) {
                if (base.substringBefore('.') in parts) out += base
            }
        }
        return out.take(MAX_CANDIDATES)
    }

    /** Is [url] a website of one of the app's verified domains ([linked] = base domains)? */
    fun isLinkedUrl(url: LoginUrl, linked: Set<String>, baseDomain: (String) -> String): Boolean =
        linked.isNotEmpty() && webBase(url, baseDomain)?.let { it in linked } == true

    /** Where to look for a domain's asset links: the domain itself, then `www.`. */
    fun assetLinkHosts(base: String): List<String> = listOf(base, "www.$base")
}
