package io.passauth.app.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Bundle
import android.service.autofill.FillResponse
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import androidx.lifecycle.lifecycleScope
import io.passauth.app.ServiceActivity
import io.passauth.app.autofill.AutofillResponses.Companion.addAll
import io.passauth.app.data.VaultData
import io.passauth.app.ui.vault.currentTotp
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.launch

/**
 * Started by the autofill framework (or the save prompt) when PassAuth must act
 * at the moment the user picks something:
 * - [MODE_UNLOCK]: the vault was locked; unlock, then hand back the matching logins
 *   (`EXTRA_AUTHENTICATION_RESULT` = a [FillResponse]).
 * - [MODE_DATASET]: a login with a verification code was picked; hand back that
 *   login (a Dataset) with a fresh code, and copy the code if the setting is on.
 * - [MODE_SAVE]: a save prompt was accepted while locked; unlock, then save. When the vault
 *   already has a login for the site or app, a sheet says what will happen ("Update login?"
 *   or "Save login?") and lets the user change where it is saved.
 * - [MODE_NEVER]: "Never" on the save prompt; add the site or app to the never-save list.
 * - [MODE_OPEN]: "Open PassAuth".
 */
class AutofillAuthActivity : ServiceActivity() {
    private val engine by lazy { AutofillEngine(this, graph) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return
        when (intent.getStringExtra(EXTRA_MODE)) {
            MODE_OPEN -> {
                openApp()
                cancel()
            }
            MODE_NEVER -> withVaultless {
                intent.getStringExtra(EXTRA_KEY)?.let { engine.addNeverSave(it) }
                toast("PassAuth won't offer to save logins here. You can change this in Settings → Autofill.")
                cancel()
            }
            MODE_UNLOCK -> withVault("Unlock to fill", "Your vault is locked. Unlock it to fill your login.") { vault, _ -> fillResponse(vault) }
            MODE_DATASET -> withVault("Unlock to fill", "Your vault is locked. Unlock it to fill your login.") { vault, _ -> dataset(vault) }
            MODE_SAVE -> {
                // From here on this sheet decides; the save is no longer applied by itself at the next unlock.
                intent.getStringExtra(EXTRA_KEY)?.let(AutofillEngine::claimPendingSave)
                withVault("Unlock to save", "Your vault is locked. Unlock it to save this login in PassAuth.") { vault, _ -> save(vault) }
            }
            else -> cancel()
        }
    }

    private fun withVaultless(block: suspend () -> Unit) {
        lifecycleScope.launch { runCatching { block() } }
    }

    private fun structure(): AssistStructure? =
        intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)

    private fun inlineRequest(): InlineSuggestionsRequest? =
        intent.getParcelableExtra(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST, InlineSuggestionsRequest::class.java)

    private fun finishWith(result: android.os.Parcelable?) {
        if (result == null) return cancel()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, result))
        finish()
    }

    /** The response the locked request would have had: one dataset per matching login. */
    private suspend fun fillResponse(vault: VaultData) {
        val parsed = structure()?.let(StructureParser::parse) ?: return cancel()
        val target = engine.target(parsed) ?: return cancel()
        val form = parsed.form
        val ui = AutofillResponses(this, inlineRequest())
        val settings = graph.repo.state.value.settings
        val datasets = buildDatasets(this, ui, engine, vault, target, form, settings)
        if (datasets.isEmpty()) {
            toast("No logins in PassAuth match this ${if (target is FillTarget.App) "app" else "site"}.")
            return cancel()
        }
        val b = FillResponse.Builder().addAll(datasets)
        // This response replaces the locked one, so it needs the save prompt again.
        if (engine.offerSave(target)) {
            AutofillResponses.saveInfo(this, form, sender(this, MODE_NEVER, key = AutofillMatcher.neverSaveKey(target)), engine.saveHint(vault, target))?.let(b::setSaveInfo)
        }
        finishWith(b.build())
    }

    /** A login with a verification code was picked: fill it with a fresh code. */
    private suspend fun dataset(vault: VaultData) {
        val parsed = structure()?.let(StructureParser::parse) ?: return cancel()
        val target = engine.target(parsed) ?: return cancel()
        val id = intent.getStringExtra(EXTRA_ENTRY) ?: return cancel()
        // Checked again here: the login must still match this site or app.
        val entry = engine.matches(vault, target).firstOrNull { it.id == id } ?: return cancel()
        val secret = entry.item.login?.totp?.takeIf { it.isNotBlank() }
        val code = secret?.let { runCatching { currentTotp(it).code }.getOrNull() }
        val ds = AutofillResponses(this, inlineRequest()).dataset(entry, parsed.form, auth = null, otpCode = code)
        if (code != null && graph.repo.state.value.settings.autoCopyTotp && parsed.form.otp == null) {
            graph.clipboard.copy(code, "Verification code")
            toast("Verification code copied. Paste it when the ${if (target is FillTarget.App) "app" else "site"} asks.")
        }
        finishWith(ds)
    }

    private suspend fun save(vault: VaultData) {
        val p = intent.getStringExtra(EXTRA_KEY)?.let(AutofillEngine::takePendingSave)
        if (p == null) {
            // The login waited in memory only (never in the intent) and is gone: the app restarted or it expired.
            toast("PassAuth couldn't save this login. Sign in again to save it.")
            return cancel()
        }
        // A typed login is only ever saved in the account that was active when the user chose to save.
        if (p.accountId != graph.repo.state.value.activeId) {
            toast("PassAuth didn't save this login: another account is active now. Sign in again to save it.")
            return cancel()
        }
        if (!engine.offerSave(p.target)) return saved(null)
        val candidates = engine.saveCandidates(vault, p.target)
        val plan = SaveRule.plan(candidates, p.username, p.password)
        // No login the user could choose instead: nothing to decide (a new login, or already saved).
        if (SaveRule.targets(candidates, p.username, p.password).isEmpty() || plan == SaveRule.Plan.Nothing) {
            return try {
                saved(engine.applySave(vault, p.target, p.username, p.password, p.appLabel, plan) ?: "This login is already saved in PassAuth.")
            } catch (e: Exception) {
                saved("Couldn't save to PassAuth: ${io.passauth.app.ui.errorMessage(e)}")
            }
        }
        askSave(p, candidates, plan, null)
    }

    /**
     * "Update login?" / "Save login?": what will change, and "Save in" to change it. What the
     * sheet shows is what gets saved: if the chosen login is gone by the time the user confirms
     * (a sync), the choices are shown again instead of saving somewhere else.
     */
    private fun askSave(p: AutofillEngine.Companion.PendingSave, candidates: List<SaveRule.Candidate<String>>, plan: SaveRule.Plan<String>, notice: String?) {
        val targets = SaveRule.targets(candidates, p.username, p.password)
        val place = engine.placeName(p.target, p.appLabel)
        val here = if (p.target is FillTarget.App) "app" else "site"
        fun target(choice: String?) = targets.firstOrNull { it.id == choice }
        confirm(
            title = { if (target(it) != null) "Update login?" else "Save login?" },
            place = place,
            body = { SaveRule.describe(target(it), p.username, place) },
            action = { if (target(it) != null) "Update login" else "Save login" },
            choicesLabel = "Save in",
            choices = targets.map { c ->
                // A login in a vault somebody shared says so: its other members will see what is saved.
                val user = c.username.ifEmpty { "No user name" }
                ServiceActivity.Choice(c.id, c.name.ifEmpty { place }, if (c.personal) user else "$user · ${c.vault.ifEmpty { "Shared vault" }}")
            } + ServiceActivity.Choice(SAVE_NEW, "New login", place, ServiceActivity.Symbol.New),
            initialChoice = (plan as? SaveRule.Plan.Update)?.id ?: SAVE_NEW,
            error = notice,
            quiet = listOf(
                ServiceActivity.Quiet("Never for this $here") {
                    engine.addNeverSave(AutofillMatcher.neverSaveKey(p.target))
                    saved("PassAuth won't offer to save logins here. You can change this in Settings → Autofill.")
                },
            ),
        ) {
            if (p.accountId != graph.repo.state.value.activeId) throw io.passauth.app.data.UserException("Another account is active now. Sign in again to save this login.")
            val current = graph.repo.vault.value ?: throw io.passauth.app.data.UserException("PassAuth is locked. Sign in to $place again to save this login.")
            val now = engine.saveCandidates(current, p.target)
            val chosenPlan = SaveRule.planFor(now, chosen.takeIf { it != SAVE_NEW }, p.username, p.password)
            if (chosenPlan == null) {
                // The login the sheet showed is no longer one this save may go to: ask again.
                askSave(p, now, SaveRule.plan(now, p.username, p.password), "That login is no longer in your vault. Choose where to save.")
            } else {
                saved(engine.applySave(current, p.target, p.username, p.password, p.appLabel, chosenPlan) ?: "This login is already saved in PassAuth.")
            }
        }
    }

    private fun saved(notice: String?) {
        notice?.let(::toast)
        setResult(RESULT_OK)
        finish()
    }

    override fun onDestroy() {
        // Closed without saving (declined, cancelled, backed out at the unlock): the typed login leaves memory.
        if (isFinishing && intent.getStringExtra(EXTRA_MODE) == MODE_SAVE) intent.getStringExtra(EXTRA_KEY)?.let(AutofillEngine::dropPendingSave)
        super.onDestroy()
    }

    companion object {
        private const val EXTRA_MODE = "mode"
        private const val EXTRA_ENTRY = "entry"
        private const val EXTRA_KEY = "key"
        const val MODE_UNLOCK = "unlock"
        const val MODE_DATASET = "dataset"
        const val MODE_SAVE = "save"
        const val MODE_NEVER = "never"
        const val MODE_OPEN = "open"

        /** "Save in" choice meaning a new login (never an item id: those are UUIDs). */
        private const val SAVE_NEW = "new"

        private val requestCodes = AtomicInteger(1)

        /**
         * An IntentSender for this activity. Mutable where the framework must add the
         * assist structure and inline request; explicit (component set) either way.
         */
        fun sender(context: Context, mode: String, entry: String? = null, key: String? = null): IntentSender {
            val intent = Intent(context, AutofillAuthActivity::class.java)
                .putExtra(EXTRA_MODE, mode)
                .apply { entry?.let { putExtra(EXTRA_ENTRY, it) }; key?.let { putExtra(EXTRA_KEY, it) } }
            val mutable = mode == MODE_UNLOCK || mode == MODE_DATASET
            val flags = PendingIntent.FLAG_CANCEL_CURRENT or if (mutable) PendingIntent.FLAG_MUTABLE else PendingIntent.FLAG_IMMUTABLE
            return PendingIntent.getActivity(context, requestCodes.getAndIncrement(), intent, flags).intentSender
        }

        /**
         * One dataset per matching login (filled directly, or through [MODE_DATASET] when it
         * has a verification code to copy or fill), plus "Open PassAuth". On a form with
         * only a one-time-code field, the logins that have a verification code.
         */
        fun buildDatasets(
            context: Context,
            ui: AutofillResponses,
            engine: AutofillEngine,
            vault: VaultData,
            target: FillTarget,
            form: LoginForm<android.view.autofill.AutofillId>,
            settings: io.passauth.app.data.Settings,
        ): List<android.service.autofill.Dataset> {
            val otpOnly = form.fillIds.isEmpty() && form.otp != null
            val entries = engine.matches(vault, target).filter { !otpOnly || !it.item.login?.totp.isNullOrBlank() }
            val out = entries.mapNotNull { e ->
                val auth = if (AutofillResponses.wantsTotpAuth(e, form, settings)) sender(context, MODE_DATASET, entry = e.id) else null
                ui.dataset(e, form, auth)
            }.toMutableList()
            ui.openDataset(form.fillIds + listOfNotNull(form.otp?.id), sender(context, MODE_OPEN))?.let { out += it }
            return out
        }
    }
}
