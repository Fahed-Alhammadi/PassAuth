package io.passauth.app.autofill

import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
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
     * Is [login] allowed for [target]? Web: a website matches the page (default match
     * from settings) and no website would be an https → http downgrade (the extension's
     * refusal). App: one of its websites is `androidapp://<package>`. Web logins never
     * match apps and app logins never match websites.
     */
    fun matches(target: FillTarget, login: Login, defaultMatch: UrlMatch): Boolean = when (target) {
        is FillTarget.Web -> {
            val page = target.pageUrl
            login.urls.any { !it.url.trim().startsWith(FillTarget.ANDROID_APP_SCHEME, ignoreCase = true) && UrlMatcher.matches(page, it, defaultMatch) } &&
                login.urls.none { UrlMatcher.downgrade(page, it) }
        }
        is FillTarget.App -> login.urls.any { isAppUrl(it, target.packageName) }
    }

    /** Matching logins as (id, login) pairs, keeping order. */
    fun <K> candidates(target: FillTarget, logins: List<Pair<K, Login>>, defaultMatch: UrlMatch): List<Pair<K, Login>> =
        logins.filter { (_, l) -> matches(target, l, defaultMatch) }

    /** PassAuth's own web vault: never fill or save there (it would capture the master password). */
    fun isVaultPage(target: FillTarget, server: String): Boolean {
        if (target !is FillTarget.Web || server.isBlank()) return false
        val s = UrlMatcher.parse(server) ?: return false
        return s.origin == target.origin
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

    sealed interface SavePlan<out K> {
        data object Nothing : SavePlan<kotlin.Nothing>
        data object New : SavePlan<kotlin.Nothing>
        data class Update<K>(val id: K) : SavePlan<K>
    }

    /**
     * What to do with submitted credentials (the extension's `onSubmitted`): update
     * the password of the same site's login with the same username, save a new login,
     * or nothing (unchanged password, read-only vault, no password).
     */
    fun <K> planSave(
        target: FillTarget,
        username: String,
        password: String,
        logins: List<Pair<K, Login>>,
        defaultMatch: UrlMatch,
        canWrite: (K) -> Boolean,
    ): SavePlan<K> {
        if (password.isEmpty()) return SavePlan.Nothing
        val sameUser = candidates(target, logins, defaultMatch).firstOrNull { (_, l) -> l.username.equals(username, ignoreCase = true) }
            ?: return SavePlan.New
        if (sameUser.second.password == password || !canWrite(sameUser.first)) return SavePlan.Nothing
        return SavePlan.Update(sameUser.first)
    }
}
