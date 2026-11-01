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
 * - [MODE_SAVE]: a save prompt was accepted while locked; unlock, then save.
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
            MODE_UNLOCK -> withVault("Unlock to fill") { vault, _ -> fillResponse(vault) }
            MODE_DATASET -> withVault("Unlock to fill") { vault, _ -> dataset(vault) }
            MODE_SAVE -> withVault("Unlock to save") { vault, _ -> save(vault) }
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
            AutofillResponses.saveInfo(form, sender(this, MODE_NEVER, key = AutofillMatcher.neverSaveKey(target)))?.let(b::setSaveInfo)
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
        val p = intent.getStringExtra(EXTRA_KEY)?.let(AutofillEngine::takePendingSave) ?: return cancel()
        try {
            engine.save(vault, p.target, p.username, p.password, p.appLabel)?.let(::toast)
        } catch (e: Exception) {
            toast("Couldn't save to PassAuth: ${io.passauth.app.ui.errorMessage(e)}")
        }
        setResult(RESULT_OK)
        finish()
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
