package io.passauth.app.autofill

import android.content.Context
import io.passauth.app.AppGraph
import io.passauth.app.credentials.AppSigning
import io.passauth.app.credentials.AssetLinks
import io.passauth.app.credentials.PrivilegedApps
import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.VaultData
import io.passauth.core.sha256
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.withTimeoutOrNull

/** Autofill decisions shared by the service and its unlock activity. */
class AutofillEngine(private val context: Context, private val graph: AppGraph) {
    private val ownPackage = context.packageName

    private fun certFingerprints(packageName: String): List<String> =
        AppSigning.of(context, packageName)?.let { info -> AppSigning.certificateDigests(info, ::sha256).map(AssetLinks::fingerprint) }.orEmpty()

    /**
     * Where the request comes from (see [FillTarget.resolve]). A browser counts only if
     * its package and signing certificate are on the privileged allowlist. A WebView in
     * another app is filled for its web domain only if that domain's asset links list
     * the app (checked over the network, at most [dalTimeoutMs]).
     */
    suspend fun target(p: ParsedStructure, dalTimeoutMs: Long = 2_500): FillTarget? {
        if (p.packageName.isEmpty() || p.packageName == ownPackage) return null
        val prints = certFingerprints(p.packageName)
        val browser = prints.isNotEmpty() && PrivilegedApps.isTrusted(context, p.packageName, prints)
        var verified = false
        val domain = p.webDomain
        if (domain != null && !browser && prints.isNotEmpty()) {
            verified = graph.assetLinks.cached(domain, p.packageName, prints)
                ?: withTimeoutOrNull(dalTimeoutMs) { graph.assetLinks.verify(domain, p.packageName, prints) }
                ?: false
        }
        return FillTarget.resolve(p.packageName, domain, p.webScheme, browser, verified, ownPackage)
    }

    private fun settings() = graph.repo.state.value.settings

    /** Is filling (or saving) blocked for this target: PassAuth's own web vault. */
    fun blocked(target: FillTarget): Boolean = AutofillMatcher.isVaultPage(target, graph.repo.state.value.server)

    fun matches(vault: VaultData, target: FillTarget): List<Entry> {
        if (blocked(target)) return emptyList()
        val logins = vault.entries.mapNotNull { e -> e.item.login?.let { e to it } }
        return AutofillMatcher.candidates(target, logins, settings().defaultMatch).map { it.first }
    }

    /** Offer to save on this target? ("Ask to save" on, not on the never-save list, not the web vault.) */
    fun offerSave(target: FillTarget): Boolean {
        val s = settings()
        return s.askToSave && AutofillMatcher.neverSaveKey(target) !in s.neverSave && !blocked(target)
    }

    /** The username and password a save request submitted. */
    fun submitted(form: LoginForm<*>): Pair<String, String>? {
        val pws = form.passwords.mapNotNull { it.value?.takeIf(String::isNotEmpty) }
        // Change-password forms (current, new, confirm): the new password is the repeated last one.
        val password = when {
            pws.size >= 2 && pws[pws.size - 1] == pws[pws.size - 2] -> pws.last()
            else -> pws.firstOrNull()
        } ?: return null
        return form.username?.value.orEmpty().trim() to password
    }

    /** Apply a save request to the unlocked vault; returns a short notice, or null if nothing changed. */
    suspend fun save(vault: VaultData, target: FillTarget, username: String, password: String, appLabel: String?): String? {
        if (!offerSave(target)) return null
        val logins = vault.entries.mapNotNull { e -> e.item.login?.let { e.id to it } }
        val plan = AutofillMatcher.planSave(target, username, password, logins, settings().defaultMatch) { id ->
            vault.get(id)?.let(vault::canWrite) == true
        }
        return when (plan) {
            AutofillMatcher.SavePlan.Nothing -> null
            is AutofillMatcher.SavePlan.Update -> {
                val e = vault.get(plan.id) ?: return null
                // updateItem keeps the old password in the history (like the extension).
                graph.repo.updateItem(e, e.item.copy(login = e.item.login!!.copy(password = password)))
                "Password updated in PassAuth."
            }
            AutofillMatcher.SavePlan.New -> {
                val name = when (target) {
                    is FillTarget.Web -> target.host.removePrefix("www.")
                    is FillTarget.App -> appLabel ?: target.packageName
                }
                graph.repo.createItem(
                    Item(
                        name = name,
                        login = Login(username = username, password = password, urls = listOf(LoginUrl(AutofillMatcher.saveUrl(target), UrlMatch.Default))),
                    ),
                    null,
                )
                "Login saved to PassAuth."
            }
        }
    }

    fun appLabel(packageName: String): String? = runCatching {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
    }.getOrNull()

    suspend fun addNeverSave(key: String) {
        graph.repo.updateSettings { s -> if (key in s.neverSave) s else s.copy(neverSave = s.neverSave + key) }
    }

    companion object {
        /** Save requests waiting for an unlock (in memory only, a few minutes). */
        private val pendingSaves = ConcurrentHashMap<String, PendingSave>()

        data class PendingSave(val target: FillTarget, val username: String, val password: String, val appLabel: String?, val at: Long)

        fun putPendingSave(p: PendingSave): String {
            val now = System.currentTimeMillis()
            pendingSaves.entries.removeIf { now - it.value.at > 300_000 }
            return UUID.randomUUID().toString().also { pendingSaves[it] = p }
        }

        fun takePendingSave(token: String): PendingSave? =
            pendingSaves.remove(token)?.takeIf { System.currentTimeMillis() - it.at <= 300_000 }
    }
}
