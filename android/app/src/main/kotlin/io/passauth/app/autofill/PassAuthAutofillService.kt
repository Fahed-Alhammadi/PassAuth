package io.passauth.app.autofill

import android.os.CancellationSignal
import android.os.SystemClock
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.widget.Toast
import io.passauth.app.autofill.AutofillResponses.Companion.addAll
import io.passauth.app.data.Status
import io.passauth.app.graph
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Android autofill service: fills logins of the active account into apps and
 * browsers, and offers to save new or changed logins. A login already saved for the
 * site or app is updated instead of saving a second one (see [SaveRule]).
 *
 * Unlocked: one dataset per matching login (drop-down and keyboard suggestions)
 * plus "Open PassAuth". Locked: a single "PassAuth is locked" entry whose
 * authentication opens [AutofillAuthActivity], which unlocks and returns the
 * datasets. No secrets are logged.
 */
class PassAuthAutofillService : AutofillService() {
    private val engine by lazy { AutofillEngine(this, graph) }

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val started = SystemClock.elapsedRealtime()
        val job: Job = graph.scope.launch {
            try {
                // Android drops replies after about 5 s: answer in time, even if only with "PassAuth is locked".
                callback.onSuccess(withTimeoutOrNull(HARD_LIMIT_MS) { respond(request, StructureParser.parse(structure), started) })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "fill request failed: ${e.javaClass.simpleName}")
                callback.onSuccess(null)
            }
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    private suspend fun respond(request: FillRequest, parsed: ParsedStructure, started: Long): FillResponse? {
        val form = parsed.form
        if (form.isEmpty) return null
        val target = engine.target(parsed) ?: return null
        val state = graph.loadedState()
        if (state.status == Status.Setup || state.status == Status.LoggedOut) return null
        val ids = (form.fillIds + listOfNotNull(form.otp?.id)).distinct()
        val offerSave = engine.offerSave(target)
        // With the vault open, Android's save dialog can say whether a saved login gets updated.
        fun saveInfo(vault: io.passauth.app.data.VaultData?) = if (!offerSave) null else AutofillResponses.saveInfo(
            this, form,
            AutofillAuthActivity.sender(this, AutofillAuthActivity.MODE_NEVER, key = AutofillMatcher.neverSaveKey(target)),
            vault?.let { engine.saveHint(it, target) },
        )
        val ui = AutofillResponses(this, request.inlineSuggestionsRequest)
        // Whatever is left of the time budget; if the vault isn't ready by then, offer the unlock entry
        // (its activity returns the logins straight away when the vault turns out to be unlocked).
        val left = (VAULT_DEADLINE_MS - (SystemClock.elapsedRealtime() - started)).coerceAtLeast(MIN_VAULT_WAIT_MS)
        val vault = withTimeoutOrNull(left) { graph.awaitVault() }
        val save = saveInfo(vault)
        val b = FillResponse.Builder()
        if (vault == null) {
            // Locked: the user unlocks in PassAuth, which then returns the matching logins.
            b.setAuthentication(ids.toTypedArray(), AutofillAuthActivity.sender(this, AutofillAuthActivity.MODE_UNLOCK), ui.lockedPresentations(state.email))
        } else {
            val datasets = AutofillAuthActivity.buildDatasets(this, ui, engine, vault, target, form, state.settings)
            // Only "Open PassAuth" and nothing to save: stay out of the way.
            if (datasets.size <= 1 && save == null && form.password == null) return null
            b.addAll(datasets)
        }
        save?.let(b::setSaveInfo)
        return b.build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess()
        val parsed = StructureParser.parse(structure)
        graph.scope.launch {
            try {
                val target = engine.target(parsed)
                val creds = engine.submitted(parsed.form)
                if (target == null || creds == null || !engine.offerSave(target)) return@launch callback.onSuccess()
                val label = (target as? FillTarget.App)?.let { engine.appLabel(it.packageName) ?: parsed.windowTitle }
                val vault = graph.awaitVault()
                val account = graph.repo.state.value.activeId
                // Through PassAuth's own sheet (the typed login stays in memory, never in the intent).
                fun askInSheet() {
                    val token = AutofillEngine.putPendingSave(
                        AutofillEngine.Companion.PendingSave(target, creds.first, creds.second, label, System.currentTimeMillis(), account),
                    )
                    callback.onSuccess(AutofillAuthActivity.sender(this@PassAuthAutofillService, AutofillAuthActivity.MODE_SAVE, key = token))
                    saveIfTheSheetNeverOpens(token, account)
                }
                // Locked: unlock in PassAuth, then save there.
                if (vault == null) return@launch askInSheet()
                val plan = engine.planSave(vault, target, creds.first, creds.second)
                // No user name was typed and the place has one login of the user's own: that login is
                // never overwritten on the strength of Android's dialog alone. PassAuth shows which
                // login would change ("Update login?") and lets the user choose.
                if (SaveRule.needsSheet(plan)) return@launch askInSheet()
                callback.onSuccess()
                engine.applySave(vault, target, creds.first, creds.second, label, plan)?.let { toast(it) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "save request failed: ${e.javaClass.simpleName}")
                toast("Couldn't save to PassAuth: ${io.passauth.app.ui.errorMessage(e)}")
                runCatching { callback.onSuccess() }
            }
        }
    }

    /**
     * Android opens PassAuth's sheet from the app that was filled, and can't once that app has
     * closed its sign-in screen: the save the user agreed to would be lost without a word. So a
     * save the sheet never took over is applied as soon as the same account's vault is unlocked,
     * within the few minutes it is kept in memory. Nobody sees a sheet then, so an update of
     * "the only login here" (no user name typed) is saved as a new login instead
     * ([SaveRule.withoutSheet]); the notice names the login that changed.
     */
    private fun saveIfTheSheetNeverOpens(token: String, account: String) {
        graph.scope.launch {
            // The sheet takes the save over the moment it opens: give Android that long.
            delay(SHEET_GRACE_MS)
            val vault = withTimeoutOrNull(AutofillEngine.PENDING_WAIT_MS) {
                graph.repo.state.first { it.loaded && it.status == Status.Unlocked }
                graph.repo.vault.filterNotNull().first()
            }
            // Out of memory on every way out of here (the sheet's own copy is not touched).
            val p = AutofillEngine.takeUnclaimedSave(token) ?: return@launch
            // Only the account that was asked, and only while it is really unlocked.
            if (vault == null || p.accountId != account) return@launch
            if (graph.repo.state.value.let { it.activeId != account || it.status != Status.Unlocked }) return@launch
            try {
                val plan = SaveRule.withoutSheet(engine.planSave(vault, p.target, p.username, p.password))
                engine.applySave(vault, p.target, p.username, p.password, p.appLabel, plan)?.let { toast(it) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "save after unlock failed: ${e.javaClass.simpleName}")
                toast("Couldn't save to PassAuth: ${io.passauth.app.ui.errorMessage(e)}")
            }
        }
    }

    private fun toast(text: String) = Toast.makeText(applicationContext, text, Toast.LENGTH_SHORT).show()

    private companion object {
        const val TAG = "PassAuthAutofill"
        const val VAULT_DEADLINE_MS = 3_500L
        const val MIN_VAULT_WAIT_MS = 250L
        const val HARD_LIMIT_MS = 4_500L
        const val SHEET_GRACE_MS = 3_000L
    }
}
