package io.passauth.app.autofill

import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher

/**
 * "Add this site to a login": one account used on several sites or apps (a mail login also used
 * on another domain, or in the provider's app). The site's or app's address is added as one more
 * website of a login the user picks, so that login is suggested and filled there from now on
 * instead of a second copy being saved. The same rules as the browser extension:
 *
 * - Only logins the user can edit are offered, and none whose websites already match the place.
 * - The address added is the page's origin (`https://host`) for a website (only ever a trusted
 *   browser or an asset-linked WebView: [FillTarget.Web]) or `androidapp://<package>` for an app
 *   ([AutofillMatcher.saveUrl]), with match "default" (the user's own matching setting).
 * - Never offered for the web domain of an app's WebView that isn't asset-linked ([allowed]).
 *
 * Pure logic (no Android types): unit-tested in AddSiteTest.
 */
object AddSite {
    /** At most this many "Add this site" rows on the save sheet. */
    const val MAX_ADD_TO = 3

    /** A login the place can be added to. [site]: the place it is saved for now (host or app), for the sheet's text. */
    data class Target<K>(
        val id: K,
        val name: String,
        val username: String,
        val site: String,
        /** In the user's own vault (not one somebody shared). */
        val personal: Boolean,
        /** The vault's name, for the warning on a shared-vault login. */
        val vault: String = "",
    )

    /**
     * May the place be added to a login at all? A website target is trusted by construction
     * ([FillTarget.resolve]). An app whose request carried a web domain is an app's WebView that
     * its domain's asset links don't list: what it shows proves nothing, so nothing is offered.
     */
    fun allowed(target: FillTarget, webDomain: String?): Boolean = when (target) {
        is FillTarget.Web -> true
        is FillTarget.App -> webDomain.isNullOrBlank()
    }

    /** The address added to the login: the page origin, or `androidapp://<package>`. */
    fun address(target: FillTarget): String = AutofillMatcher.saveUrl(target)

    /** The login with [target]'s address added as one more website (match "default"). */
    fun withSite(login: Login, target: FillTarget): Login =
        login.copy(urls = login.urls + LoginUrl(address(target), UrlMatch.Default))

    /** Where a login is saved for now: its first website's host (without "www."), else its app's package; "" when none. */
    fun siteOf(login: Login): String {
        for (u in login.urls) {
            if (u.match == UrlMatch.Regex || u.url.isBlank()) continue
            val p = UrlMatcher.parse(u.url) ?: continue
            if ((p.scheme == "http" || p.scheme == "https") && p.hostname.isNotEmpty()) return p.hostname.removePrefix("www.")
        }
        return login.urls.firstOrNull { it.url.trim().startsWith(FillTarget.ANDROID_APP_SCHEME, ignoreCase = true) }
            ?.url?.trim()?.substring(FillTarget.ANDROID_APP_SCHEME.length)?.trimEnd('/').orEmpty()
    }

    /** Does one of [login]'s websites already match [target]? (Regular expressions only from the user's own vaults.) */
    fun alreadyMatches(target: FillTarget, login: Login, defaultMatch: UrlMatch, personal: Boolean): Boolean =
        AutofillMatcher.matches(target, login, defaultMatch, allowRegex = personal)

    /**
     * The logins [target] can be added to (for the picker): ones the user can edit whose websites
     * don't match [target] yet. The user's own vaults first, otherwise in vault order.
     */
    fun <K> targets(
        target: FillTarget,
        logins: List<Triple<K, String, Login>>,
        defaultMatch: UrlMatch,
        place: (K) -> AutofillMatcher.Place,
    ): List<Target<K>> = logins.mapNotNull { (id, name, login) ->
        val p = place(id)
        if (!p.writable || alreadyMatches(target, login, defaultMatch, p.personal)) return@mapNotNull null
        Target(id, name, login.username, siteOf(login), p.personal, p.vault)
    }.sortedByDescending { it.personal }

    /**
     * The save sheet's "Add this site" rows: the user's OWN (personal, editable) logins for other
     * places saved with exactly the typed user name (trimmed, any case) and password: the same
     * account, used on one more site or app. Only when the save has no login for this place to
     * offer ([siteTargets] empty) and both a user name and a password were typed (a password alone
     * says nothing about the account). At most [MAX_ADD_TO]; never preselected.
     */
    fun <K> sameAccountElsewhere(
        target: FillTarget,
        logins: List<Triple<K, String, Login>>,
        defaultMatch: UrlMatch,
        place: (K) -> AutofillMatcher.Place,
        typedUser: String,
        password: String,
        siteTargets: List<*>,
    ): List<Target<K>> {
        val user = typedUser.trim().lowercase()
        if (siteTargets.isNotEmpty() || user.isEmpty() || password.isEmpty()) return emptyList()
        val out = mutableListOf<Target<K>>()
        for ((id, name, login) in logins) {
            if (out.size >= MAX_ADD_TO) break
            if (login.password != password || login.username.trim().lowercase() != user) continue
            val p = place(id)
            if (!p.writable || !p.personal || alreadyMatches(target, login, defaultMatch, true)) continue
            out += Target(id, name, login.username, siteOf(login), personal = true, vault = p.vault)
        }
        return out
    }

    /** "Adds <place> to <name>. …" (the save sheet's note while such a row is selected). */
    fun describe(t: Target<*>, place: String): String =
        "Adds $place to ${t.name.ifEmpty { "this login" }}. Its user name and password stay the same, and it is suggested here from now on."

    /** Said while such a row is selected: only for a site of the same account. */
    fun warning(t: Target<*>, place: String, here: String = "site"): String =
        if (t.site.isNotEmpty()) "Only add it if $place uses the same account as ${t.site}." else "Only add it if this $here uses the same account."

    /** The picker's confirmation text. */
    fun confirmText(t: Target<*>, place: String, here: String = "site"): String {
        val name = t.name.ifEmpty { "This login" }
        val same = if (t.site.isNotEmpty()) "Add a $here only when it uses the same account as ${t.site}." else "Add a $here only when it uses the same account."
        return "$name will be suggested and filled on $place. Its user name and password stay the same. $same"
    }

    /** The warning for a login in a vault somebody shared (null for the user's own vault). */
    fun sharedWarning(t: Target<*>, here: String = "site"): String? =
        if (t.personal) null else "This login is in ${t.vault.ifEmpty { "a shared vault" }}: everyone in it will see the $here you add."
}
