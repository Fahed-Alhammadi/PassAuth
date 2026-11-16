package io.passauth.app.autofill

import io.passauth.app.data.Entry
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultData
import io.passauth.core.SavedUrl
import io.passauth.core.matchUrls
import java.util.Locale

/** Where a request comes from: a website (in a browser or verified WebView) or a native app. */
sealed interface FillTarget {
    /** Web content. Android reports only the scheme and domain, never the path. */
    data class Web(val scheme: String, val domain: String) : FillTarget {
        /** The page address used for matching: `scheme://domain/`. */
        val pageUrl: String get() = "$scheme://$domain/"
        val origin: String get() = UrlMatcher.parse(pageUrl)?.origin ?: "$scheme://$domain"
        val host: String get() = UrlMatcher.parse(pageUrl)?.hostname ?: domain
    }

    /** A native app, matched by logins with the website `androidapp://<package>`. */
    data class App(val packageName: String) : FillTarget {
        val uri: String get() = "$ANDROID_APP_SCHEME$packageName"
    }

    companion object {
        const val ANDROID_APP_SCHEME = "androidapp://"

        /**
         * Decide what a request may be matched against:
         * - web content in a trusted browser, or in an app's WebView whose web domain
         *   lists the app in its Digital Asset Links ([webViewVerified]), matches by website;
         * - web content in any other app matches only that app's own logins
         *   (an app controls its WebView, so its web domain proves nothing);
         * - a browser without web content (its address bar, menus) gets nothing:
         *   the browser's package name is never used to match;
         * - any other app matches `androidapp://<package>`;
         * - PassAuth itself gets nothing.
         *
         * A missing web scheme is taken as https (Chrome and WebView report it; others may not).
         * Returns null when nothing may be filled.
         */
        fun resolve(
            packageName: String,
            webDomain: String?,
            webScheme: String?,
            trustedBrowser: Boolean,
            webViewVerified: Boolean,
            ownPackage: String,
        ): FillTarget? {
            if (packageName == ownPackage || packageName.isBlank()) return null
            val domain = webDomain?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }
            if (domain != null) {
                val scheme = webScheme?.lowercase(Locale.ROOT)?.takeIf { it.isNotEmpty() } ?: "https"
                if (scheme != "http" && scheme != "https") return null
                if (UrlMatcher.parse("$scheme://$domain/") == null) return null
                if (trustedBrowser || webViewVerified) return Web(scheme, domain)
                return App(packageName)
            }
            if (trustedBrowser) return null
            return App(packageName)
        }
    }
}

/** Which logins may be offered for a [FillTarget], and what to save. */
object AutofillMatcher {
    /** Is [url] the `androidapp://` website of [packageName]? */
    fun isAppUrl(url: LoginUrl, packageName: String): Boolean {
        if (url.match == UrlMatch.Never || url.match == UrlMatch.Regex) return false
        val u = url.url.trim()
        return u.startsWith(FillTarget.ANDROID_APP_SCHEME, ignoreCase = true) &&
            u.substring(FillTarget.ANDROID_APP_SCHEME.length).trimEnd('/').equals(packageName, ignoreCase = true)
    }

    /**
     * Is [login] allowed for [target]? Web: a website matches the page (default match from
     * settings; the core never takes an `androidapp://` address for a website) and no website
     * would be an https → http downgrade (the extension's refusal). App: one of its websites is
     * `androidapp://<package>`. [allowRegex]: the login is in one of the user's own vaults
     * ([VaultData.isPersonal]), the only place its regular expressions count: anyone can share a
     * vault with the user and plant a slow or catch-all pattern.
     */
    fun matches(target: FillTarget, login: Login, defaultMatch: UrlMatch, allowRegex: Boolean): Boolean =
        matching(target, listOf(login), defaultMatch) { allowRegex }.isNotEmpty()

    /**
     * The indices of [logins] allowed for [target], in order. Websites are matched in one call
     * into the core for all of them; only logins that match are checked for a downgrade.
     */
    private fun matching(target: FillTarget, logins: List<Login>, defaultMatch: UrlMatch, allowRegex: (Int) -> Boolean): List<Int> = when (target) {
        is FillTarget.App -> logins.indices.filter { i -> logins[i].urls.any { isAppUrl(it, target.packageName) } }
        is FillTarget.Web -> {
            val page = target.pageUrl
            val saved = logins.flatMapIndexed { i, l -> val allow = allowRegex(i); l.urls.map { SavedUrl(it.url, it.match.wire, allow) } }
            val hits = if (saved.isEmpty()) emptyList() else matchUrls(page, defaultMatch.wire, saved)
            var at = 0
            logins.indices.filter { i ->
                val urls = logins[i].urls
                val matched = (at until at + urls.size).any { hits[it] }
                at += urls.size
                matched && urls.none { UrlMatcher.downgrade(page, it) }
            }
        }
    }

    /** The vault's logins for [target], keeping order (regular expressions only from the user's own vaults). */
    fun candidates(target: FillTarget, vault: VaultData, defaultMatch: UrlMatch): List<Entry> {
        val entries = vault.entries.filter { it.item.login != null }
        return matching(target, entries.map { it.item.login!! }, defaultMatch) { vault.isPersonal(entries[it]) }.map { entries[it] }
    }

    /** The never-save key: a website's base domain, or `androidapp://<package>`. */
    fun neverSaveKey(target: FillTarget): String = when (target) {
        is FillTarget.Web -> UrlMatcher.baseDomain(target.host)
        is FillTarget.App -> target.uri
    }

    /** The website stored on a new login: the page origin, or `androidapp://<package>`. */
    fun saveUrl(target: FillTarget): String = when (target) {
        is FillTarget.Web -> target.origin
        is FillTarget.App -> target.uri
    }

    /** Where a login lives, for the save rule: can it be edited, is it in the user's own vault, and the vault's name. */
    data class Place(val writable: Boolean, val personal: Boolean, val vault: String = "")

    /**
     * The matching logins of [target] as [SaveRule] candidates (id, name, login), keeping the
     * matcher's order. Regular expressions count only for logins in the user's own vaults
     * ([Place.personal]), so a shared vault can't make its logins candidates for every site.
     */
    fun <K> saveCandidates(
        target: FillTarget,
        logins: List<Triple<K, String, Login>>,
        defaultMatch: UrlMatch,
        place: (K) -> Place,
    ): List<SaveRule.Candidate<K>> {
        val places = logins.map { place(it.first) }
        return matching(target, logins.map { it.third }, defaultMatch) { places[it].personal }.map { i ->
            val (id, name, l) = logins[i]
            val p = places[i]
            SaveRule.Candidate(id, name, l.username, l.password, p.writable, p.personal, p.vault)
        }
    }
}
