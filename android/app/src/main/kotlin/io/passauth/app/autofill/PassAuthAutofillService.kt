package io.passauth.app.autofill

import android.os.CancellationSignal
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
import kotlinx.coroutines.launch

/**
 * Android autofill service: fills logins of the active account into apps and
 * browsers, and offers to save new or changed logins.
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
        val job: Job = graph.scope.launch {
            try {
                callback.onSuccess(respond(request, StructureParser.parse(structure)))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "fill request failed: ${e.javaClass.simpleName}")
                callback.onSuccess(null)
            }
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    private suspend fun respond(request: FillRequest, parsed: ParsedStructure): FillResponse? {
        val form = parsed.form
        if (form.isEmpty) return null
        val target = engine.target(parsed) ?: return null
        if (engine.blocked(target)) return null
        val state = graph.loadedState()
        if (state.status == Status.Setup || state.status == Status.LoggedOut) return null
        val ids = (form.fillIds + listOfNotNull(form.otp?.id)).distinct()
        val save = if (engine.offerSave(target)) {
            AutofillResponses.saveInfo(form, AutofillAuthActivity.sender(this, AutofillAuthActivity.MODE_NEVER, key = AutofillMatcher.neverSaveKey(target)))
        } else {
            null
        }
        val ui = AutofillResponses(this, request.inlineSuggestionsRequest)
        val vault = graph.awaitVault()
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
                if (vault == null) {
                    // Locked: unlock in PassAuth, then save there (credentials stay in memory, never in the intent).
                    val token = AutofillEngine.putPendingSave(
                        AutofillEngine.Companion.PendingSave(target, creds.first, creds.second, label, System.currentTimeMillis()),
                    )
                    callback.onSuccess(AutofillAuthActivity.sender(this@PassAuthAutofillService, AutofillAuthActivity.MODE_SAVE, key = token))
                    return@launch
                }
                callback.onSuccess()
                engine.save(vault, target, creds.first, creds.second, label)?.let { toast(it) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "save request failed: ${e.javaClass.simpleName}")
                toast("Couldn't save to PassAuth: ${io.passauth.app.ui.errorMessage(e)}")
                runCatching { callback.onSuccess() }
            }
        }
    }

    private fun toast(text: String) = Toast.makeText(applicationContext, text, Toast.LENGTH_SHORT).show()

    private companion object {
        const val TAG = "PassAuthAutofill"
    }
}
