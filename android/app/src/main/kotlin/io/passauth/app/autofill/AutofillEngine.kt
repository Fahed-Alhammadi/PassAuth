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
import io.passauth.app.data.Role
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

    /** Matching logins for the target (the PassAuth server's own web vault is an ordinary website). */
    fun matches(vault: VaultData, target: FillTarget): List<Entry> {
        val logins = vault.entries.mapNotNull { e -> e.item.login?.let { e to it } }
        return AutofillMatcher.candidates(target, logins, settings().defaultMatch).map { it.first }
    }

    /** Offer to save on this target? ("Ask to save" on and not on the never-save list.) */
    fun offerSave(target: FillTarget): Boolean {
        val s = settings()
        return s.askToSave && AutofillMatcher.neverSaveKey(target) !in s.neverSave
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

    /** What a site or app is called in prompts and on a new login: the host (without "www."), or the app's name. */
    fun placeName(target: FillTarget, appLabel: String?): String = when (target) {
        is FillTarget.Web -> target.host.removePrefix("www.")
        is FillTarget.App -> appLabel ?: target.packageName
    }

    /**
     * The logins for [target] as the save rule sees them (see [SaveRule]): each with whether it
     * can be edited and whether it is in the user's own vault. A login whose vault is unknown
     * counts as neither.
     */
    fun saveCandidates(vault: VaultData, target: FillTarget): List<SaveRule.Candidate<String>> =
        AutofillMatcher.saveCandidates(
            target,
            vault.entries.mapNotNull { e -> e.item.login?.let { Triple(e.id, e.item.name, it) } },
            settings().defaultMatch,
        ) { id ->
            val info = vault.get(id)?.let { e -> vault.vaults.firstOrNull { it.id == e.vaultId } }
            AutofillMatcher.Place(writable = info != null && info.role != Role.Read, personal = info?.personal == true, vault = info?.name.orEmpty())
        }

    /** What Android's save dialog can say about [target] before anything is typed (see [SaveRule.hint]). */
    fun saveHint(vault: VaultData, target: FillTarget): SaveRule.Hint? = SaveRule.hint(saveCandidates(vault, target))

    /** The default plan for a save request on the unlocked vault (nothing when saving is off for [target]). */
    fun planSave(vault: VaultData, target: FillTarget, username: String, password: String): SaveRule.Plan<String> =
        if (!offerSave(target)) SaveRule.Plan.Nothing else SaveRule.plan(saveCandidates(vault, target), username, password)

    /**
     * Carry out [plan]: update the chosen login (password, and the user name if one was typed)
     * or create a new one. Returns a short notice that names the login that changed, or null
     * if nothing changed.
     */
    suspend fun applySave(vault: VaultData, target: FillTarget, username: String, password: String, appLabel: String?, plan: SaveRule.Plan<String>): String? =
        when (plan) {
            SaveRule.Plan.Nothing -> null
            is SaveRule.Plan.Update -> {
                val e = vault.get(plan.id)
                val login = e?.item?.login
                if (e == null || login == null) {
                    null
                } else {
                    // updateItem keeps the old password in the history (like the extension).
                    graph.repo.updateItem(e, e.item.copy(login = SaveRule.apply(login, username, password)))
                    "Login updated: ${e.item.name.ifEmpty { placeName(target, appLabel) }}"
                }
            }
            SaveRule.Plan.New -> {
                val name = placeName(target, appLabel)
                graph.repo.createItem(
                    Item(
                        name = name,
                        login = Login(username = username.trim(), password = password, urls = listOf(LoginUrl(AutofillMatcher.saveUrl(target), UrlMatch.Default))),
                    ),
                    null,
                )
                "New login saved: $name"
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
        private const val PENDING_MS = 300_000L

        /** How long a save waits for an unlock. */
        const val PENDING_WAIT_MS = PENDING_MS

        /** Save requests waiting for PassAuth's sheet or an unlock (in memory only, a few minutes). */
        private val pendingSaves = ConcurrentHashMap<String, PendingSave>()

        /**
         * A typed user name and password waiting to be saved. [accountId]: the account that was
         * active when the user chose to save, the only one it may be saved in; [claimed]:
         * PassAuth's sheet has taken it over.
         */
        data class PendingSave(
            val target: FillTarget,
            val username: String,
            val password: String,
            val appLabel: String?,
            val at: Long,
            val accountId: String,
            val claimed: Boolean = false,
        )

        private fun fresh(p: PendingSave) = System.currentTimeMillis() - p.at <= PENDING_MS

        /** Expired entries go on every access, not only when the next save comes in. */
        private fun prune() {
            pendingSaves.entries.removeIf { !fresh(it.value) }
        }

        fun putPendingSave(p: PendingSave): String {
            prune()
            return UUID.randomUUID().toString().also { pendingSaves[it] = p }
        }

        /** The save for [token], removed from memory; null if it expired or was already taken or dropped. */
        fun takePendingSave(token: String): PendingSave? {
            prune()
            return pendingSaves.remove(token)
        }

        /** PassAuth's sheet opened for this save: it is no longer saved by itself at the next unlock. */
        fun claimPendingSave(token: String) {
            prune()
            pendingSaves.computeIfPresent(token) { _, p -> p.copy(claimed = true) }
        }

        /** A save the sheet never opened for (see [PassAuthAutofillService.onSaveRequest]), removed from memory. */
        fun takeUnclaimedSave(token: String): PendingSave? {
            prune()
            var taken: PendingSave? = null
            pendingSaves.computeIfPresent(token) { _, p -> if (p.claimed) p else null.also { taken = p } }
            return taken
        }

        /** The sheet closed without saving (declined, cancelled, backed out): forget the typed login. */
        fun dropPendingSave(token: String) {
            pendingSaves.remove(token)
            prune()
        }

        /** Lock, log out or another account: nothing typed for the previous session stays in memory. */
        fun clearPendingSaves() = pendingSaves.clear()

        /** For tests. */
        internal fun pendingCount(): Int = pendingSaves.size
    }
}
