package io.passauth.app.credentials

import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.Passkey
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultData
import io.passauth.core.PasskeyLogin
import io.passauth.core.PasskeyTarget
import io.passauth.core.passkeyDefaultTarget
import io.passauth.core.passkeySaveTargets

/**
 * Where a new passkey is saved: the user picks one of the logins for this site, or a new login.
 * Which logins qualify, their order and which one is preselected are the Rust core's rules
 * (`passkeySaveTargets` / `passkeyDefaultTarget`, the same as the extension and the iOS app).
 */
object PasskeyTargets {
    /** Save target meaning "create a new login" (never an item id: those are UUIDs). */
    const val NEW_LOGIN = "new"

    /** A login offered under "Save in". [preferred]: the core allows preselecting it. */
    class Target(val entry: Entry, internal val core: PasskeyTarget) {
        val id: String get() = entry.id
        val preferred: Boolean get() = core.preferred
    }

    /** The page's host for a browser origin (`https://host[:port]`), else the RP ID (apps). */
    fun hostOf(origin: String, rpId: String): String =
        origin.takeIf { it.startsWith("https://", ignoreCase = true) }?.let(UrlMatcher::parse)?.hostname?.lowercase()?.removeSuffix(".") ?: rpId.lowercase()

    /**
     * Logins a new passkey can be saved in: ones you can edit whose website is this exact host,
     * the RP ID, or a subdomain of the RP ID (where the passkey also works). Never just "the
     * same base domain": cloudy.example.com and bazarr.example.com are different sites, and an
     * `androidapp://` address is not a website. Logins in your own vault come first, then ones in
     * vaults somebody shared (listed with their vault's name, never preselected: see
     * [defaultTarget]); within each: this exact host, then a matching user name, then by name.
     * A login whose vault is unknown is left out.
     */
    fun saveTargets(vault: VaultData, host: String, rpId: String, userName: String, displayName: String = ""): List<Target> {
        val logins = vault.entries.filter { e -> e.item.login != null && vault.vaults.any { it.id == e.vaultId } }
        val byId = logins.associateBy { it.id }
        val offered = passkeySaveTargets(
            logins.map { e ->
                val l = e.item.login!!
                val personal = vault.isPersonal(e)
                PasskeyLogin(e.id, e.item.name, l.username, l.urls.map { it.url }, vault.canWrite(e), personal, if (personal) null else vault.vaultName(e.vaultId))
            },
            host, rpId, userName, displayName,
        )
        return offered.mapNotNull { t -> byId[t.id]?.let { Target(it, t) } }
    }

    /**
     * The preselected target: the best login for this exact host in the user's OWN vault, else
     * a new login. Never a login in a shared vault: anyone on the server can share a vault with
     * this account and put a login for the site in it, and the passkey's private key would then
     * go to that vault's members by default. Such a login can still be chosen.
     */
    fun defaultTarget(targets: List<Target>): String = passkeyDefaultTarget(targets.map { it.core })

    /** The sheet's warning for a target in a shared vault (null for the user's own vault or a new login). */
    fun sharedWarning(vault: VaultData, e: Entry?): String? =
        e?.takeIf { !vault.isOwn(it) }?.let { "Saving here shares this passkey with everyone in ${vault.vaultName(it.vaultId)}." }

    /** The row text under a target's name: its user name, and the vault's name when somebody shared it. */
    fun detail(vault: VaultData, e: Entry): String {
        val user = e.item.login?.username.orEmpty().ifEmpty { "No user name" }
        return if (vault.isOwn(e)) user else "$user · ${vault.vaultName(e.vaultId)}"
    }

    sealed interface Plan {
        data class Attach(val entry: Entry, val item: Item) : Plan
        data class Create(val item: Item) : Plan
    }

    /** The chosen login (still one you can edit for this site) gets the passkey; otherwise a new login for [host]. */
    fun plan(vault: VaultData, p: Passkey, host: String, target: String): Plan {
        val e = if (target == NEW_LOGIN) null else saveTargets(vault, host, p.rpId, "").firstOrNull { it.id == target }?.entry
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
