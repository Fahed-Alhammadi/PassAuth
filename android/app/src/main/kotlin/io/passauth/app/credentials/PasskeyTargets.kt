package io.passauth.app.credentials

import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.Passkey
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultData

/**
 * Where a new passkey is saved (the extension's `saveTargets` / `storePasskey`): the user
 * picks one of the logins for this site, or a new login.
 */
object PasskeyTargets {
    /** Save target meaning "create a new login" (never an item id: those are UUIDs). */
    const val NEW_LOGIN = "new"

    /** Hostnames of a login's http(s) URLs, lowercase, without a trailing dot. */
    private fun loginHosts(e: Entry): List<String> =
        e.item.login?.urls.orEmpty().mapNotNull { u ->
            UrlMatcher.parse(u.url)?.takeIf { it.scheme == "http" || it.scheme == "https" }?.hostname?.lowercase()?.removeSuffix(".")
        }

    /** The page's host for a browser origin (`https://host[:port]`), else the RP ID (apps). */
    fun hostOf(origin: String, rpId: String): String =
        origin.takeIf { it.startsWith("https://", ignoreCase = true) }?.let(UrlMatcher::parse)?.hostname?.lowercase()?.removeSuffix(".") ?: rpId.lowercase()

    /**
     * Logins a new passkey can be saved in: ones you can edit whose website is this exact host,
     * the RP ID, or a subdomain of the RP ID (where the passkey also works). Never just "the
     * same base domain": cloudy.example.com and bazarr.example.com are different sites.
     * Best first: this exact host, then a matching user name, then by name.
     */
    fun saveTargets(vault: VaultData, host: String, rpId: String, userName: String, displayName: String = ""): List<Entry> {
        val rp = rpId.lowercase()
        val names = listOf(userName, displayName).map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        fun score(e: Entry): Int {
            val user = e.item.login?.username.orEmpty().trim().lowercase()
            val userMatch = user.isNotEmpty() && names.any { it == user || it == user.substringBefore("@") }
            return (if (host in loginHosts(e)) 2 else 0) + (if (userMatch) 1 else 0)
        }
        return vault.entries
            .filter { it.item.login != null && vault.canWrite(it) }
            .filter { e -> loginHosts(e).any { it == host || it == rp || it.endsWith(".$rp") } }
            .sortedWith(compareByDescending<Entry> { score(it) }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.item.name })
    }

    /** The preselected target: the best login for this exact host, else a new login. */
    fun defaultTarget(targets: List<Entry>, host: String): String =
        targets.firstOrNull { host in loginHosts(it) }?.id ?: NEW_LOGIN

    sealed interface Plan {
        data class Attach(val entry: Entry, val item: Item) : Plan
        data class Create(val item: Item) : Plan
    }

    /** The chosen login (still one you can edit for this site) gets the passkey; otherwise a new login for [host]. */
    fun plan(vault: VaultData, p: Passkey, host: String, target: String): Plan {
        val e = if (target == NEW_LOGIN) null else saveTargets(vault, host, p.rpId, "").firstOrNull { it.id == target }
        val l = e?.item?.login
        if (e != null && l != null) return Plan.Attach(e, e.item.copy(login = l.copy(passkeys = l.passkeys + p)))
        return Plan.Create(
            Item(
                name = p.rpName.ifEmpty { p.rpId },
                login = Login(username = p.userName, password = "", urls = listOf(LoginUrl("https://$host", UrlMatch.Default)), passkeys = listOf(p)),
            ),
        )
    }
}
