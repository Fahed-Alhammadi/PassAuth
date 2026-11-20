package io.passauth.app.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Bundle
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
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
 * - [MODE_CREDENTIAL_SAVE]: an app asked Credential Manager to save a password and the user
 *   chose PassAuth (a `CreateEntry` of [io.passauth.app.credentials.PassAuthCredentialService]);
 *   unlock, then the same save rule and sheet as an autofill save, answered with a
 *   `CreatePasswordResponse`.
 * - [MODE_NEVER]: "Never" on the save prompt; add the site or app to the never-save list.
 * - [MODE_OPEN]: "Open PassAuth".
 * - [MODE_ADD_SITE]: "Add this site to a login…" (nothing matched); pick a login, confirm,
 *   add the site or app to it ([AddSite]) and hand that login back (a Dataset) to fill.
 */
class AutofillAuthActivity : ServiceActivity() {
    private val engine by lazy { AutofillEngine(this, graph) }

    /** The id a new login saved from this sheet gets, however often Save is tapped. */
    private val saveItemId = java.util.UUID.randomUUID().toString()

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
            MODE_ADD_SITE -> withVault("Unlock to fill", "Your vault is locked. Unlock it to choose the login to fill here.") { vault, _ -> addSite(vault) }
            MODE_CREDENTIAL_SAVE -> withVault("Unlock to save", "Your vault is locked. Unlock it to save this password in PassAuth.") { vault, _ -> credentialSave(vault) }
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
        val target = engine.target(parsed)?.let { engine.linked(it, vault) } ?: return cancel()
        val form = parsed.form
        val ui = AutofillResponses(this, inlineRequest())
        val settings = graph.repo.state.value.settings
        val datasets = buildDatasets(this, ui, engine, vault, target, form, settings, AddSite.allowed(target, parsed.webDomain))
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
        val target = engine.target(parsed)?.let { engine.linked(it, vault) } ?: return cancel()
        val id = intent.getStringExtra(EXTRA_ENTRY) ?: return cancel()
        // Checked again here: the login must still match this site or app.
        val entry = engine.matches(vault, target).firstOrNull { it.id == id } ?: return cancel()
        finishWith(fillWith(entry, parsed, target))
    }

    /** [entry] as a Dataset for the form, with a fresh verification code (copied too when the setting is on). */
    private fun fillWith(entry: io.passauth.app.data.Entry, parsed: ParsedStructure, target: FillTarget): android.service.autofill.Dataset? {
        val secret = entry.item.login?.totp?.takeIf { it.isNotBlank() }
        val code = secret?.let { runCatching { currentTotp(it).code }.getOrNull() }
        val ds = AutofillResponses(this, inlineRequest()).dataset(entry, parsed.form, auth = null, otpCode = code)
        if (code != null && graph.repo.state.value.settings.autoCopyTotp && parsed.form.otp == null) {
            graph.clipboard.copy(code, "Verification code")
            toast("Verification code copied. Paste it when the ${if (target is FillTarget.App) "app" else "site"} asks.")
        }
        return ds
    }

    /** "Add this site to a login…": nothing matched here; the user picks the login of the same account. */
    private suspend fun addSite(vault: VaultData) {
        val parsed = structure()?.let(StructureParser::parse) ?: return cancel()
        val target = engine.target(parsed)?.let { engine.linked(it, vault) } ?: return cancel()
        // Never for an app's WebView its domain doesn't vouch for (the entry isn't offered there either).
        if (!AddSite.allowed(target, parsed.webDomain)) return cancel()
        val place = engine.placeName(target, (target as? FillTarget.App)?.let { engine.appLabel(it.packageName) ?: parsed.windowTitle })
        pickLogin(parsed, target, place, vault, null)
    }

    private fun pickLogin(parsed: ParsedStructure, target: FillTarget, place: String, vault: VaultData, notice: String?) {
        val here = if (target is FillTarget.App) "app" else "site"
        val targets = engine.addSiteTargets(vault, target)
        if (targets.isEmpty()) {
            return message("No login to add this $here to", "PassAuth has no login you can edit that isn't already suggested on $place. Sign in, and PassAuth offers to save the login.")
        }
        val app = target is FillTarget.App
        pick(
            title = if (app) "Choose a login" else "Add this $here to a login",
            place = place,
            body = if (app) {
                "Choose the login you use in $place. PassAuth fills it, and can suggest it in this app from now on."
            } else {
                "Choose the login you use on $place. It is suggested and filled here from now on."
            },
            choices = targets.map { t ->
                val detail = listOf(t.username.ifEmpty { "No user name" }, t.site, if (t.personal) "" else t.vault.ifEmpty { "Shared vault" })
                ServiceActivity.Choice(t.id, t.name.ifEmpty { t.site.ifEmpty { "Untitled" } }, detail.filter { it.isNotEmpty() }.joinToString(" · "))
            },
            action = "Continue",
            error = notice,
        ) { id ->
            val t = targets.firstOrNull { it.id == id } ?: return@pick
            confirmAddSite(parsed, target, place, t)
        }
    }

    private fun confirmAddSite(parsed: ParsedStructure, target: FillTarget, place: String, t: AddSite.Target<String>) {
        val here = if (target is FillTarget.App) "app" else "site"
        val app = target is FillTarget.App
        val name = t.name.ifEmpty { t.site.ifEmpty { "this login" } }
        confirm(
            title = { if (app) "Use $name for $place from now on?" else "Add $place to $name?" },
            place = place,
            body = { AddSite.confirmText(t, place, here) },
            action = { if (app) "Fill and remember" else "Add site" },
            warning = { AddSite.sharedWarning(t, here) },
            quiet = listOfNotNull(
                // An app: fill this one time without remembering (the user picked the login themselves).
                if (!app) {
                    null
                } else {
                    ServiceActivity.Quiet("Fill once") {
                        val now = graph.repo.vault.value ?: throw io.passauth.app.data.UserException("PassAuth is locked. Choose the login again.")
                        val e = now.get(t.id)?.takeIf { it.item.login != null }
                            ?: return@Quiet pickLogin(parsed, target, place, now, "That login is no longer in your vault. Choose another.")
                        finishWith(fillWith(e, parsed, target))
                    }
                },
                ServiceActivity.Quiet("Choose another") {
                    val now = graph.repo.vault.value ?: throw io.passauth.app.data.UserException("PassAuth is locked.")
                    pickLogin(parsed, target, place, now, null)
                },
            ),
        ) {
            val current = graph.repo.vault.value ?: throw io.passauth.app.data.UserException("PassAuth is locked. Choose the login again.")
            // The login as it is now: gone, view-only or changed since the list was shown → choose again.
            if (engine.addSiteTargets(current, target).none { it.id == t.id } && engine.matches(current, target).none { it.id == t.id }) {
                return@confirm pickLogin(parsed, target, place, current, "That login can no longer be added here. Choose another.")
            }
            // Saved first (errors stay on this sheet); only a saved login is filled.
            val entry = engine.addSite(current, t.id, target)
            toast("$place added to $name.")
            finishWith(fillWith(entry, parsed, target))
        }
    }

    private suspend fun save(vault: VaultData) {
        val pending = intent.getStringExtra(EXTRA_KEY)?.let(AutofillEngine::takePendingSave)
        if (pending == null) {
            // The login waited in memory only (never in the intent) and is gone: the app restarted or it expired.
            toast("PassAuth couldn't save this login. Sign in again to save it.")
            return cancel()
        }
        // A typed login is only ever saved in the account that was active when the user chose to save.
        if (pending.accountId != graph.repo.state.value.activeId) {
            toast("PassAuth didn't save this login: another account is active now. Sign in again to save it.")
            return cancel()
        }
        if (!engine.offerSave(pending.target)) return saved(null)
        saveFlow(vault, pending)
    }

    private val credentialMode get() = intent.getStringExtra(EXTRA_MODE) == MODE_CREDENTIAL_SAVE

    /**
     * Credential Manager `createCredential(CreatePasswordRequest)`: the caller is the place (a
     * browser on the privileged allowlist by its web origin, any other app by its package), the
     * request's id and password the typed login. The user picked PassAuth in Android's sheet, so
     * "Ask to save" and the never-save list don't hold it back.
     */
    private suspend fun credentialSave(vault: VaultData) {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return cancel()
        val call = request.callingRequest as? CreatePasswordRequest ?: return cancel()
        val found = io.passauth.app.credentials.PassAuthCredentialService.passwordTarget(this, request.callingAppInfo)
            ?: return failCredential("PassAuth can't save passwords for this app.")
        if (call.password.isEmpty()) return failCredential("There's no password to save.")
        val label = (found as? FillTarget.App)?.let { engine.appLabel(it.packageName) }
        saveFlow(vault, AutofillEngine.Companion.PendingSave(found, call.id.trim(), call.password, label, System.currentTimeMillis(), graph.repo.state.value.activeId))
    }

    private fun failCredential(text: String) {
        val r = Intent()
        PendingIntentHandler.setCreateCredentialException(r, CreateCredentialUnknownException(text))
        toast(text)
        setResult(RESULT_OK, r)
        finish()
    }

    /** The save rule for [pending]: saved at once when there's nothing to choose, else the sheet. */
    private suspend fun saveFlow(vault: VaultData, pending: AutofillEngine.Companion.PendingSave) {
        // An app: also the logins of websites that vouch for it (asset links).
        val p = pending.copy(target = engine.linked(pending.target, vault))
        val candidates = engine.saveCandidates(vault, p.target)
        val plan = SaveRule.plan(candidates, p.username, p.password)
        val addTo = engine.sameAccountElsewhere(vault, p.target, p.username, p.password)
        // No login the user could choose instead: nothing to decide (a new login, or already saved).
        if (addTo.isEmpty() && (SaveRule.targets(candidates, p.username, p.password).isEmpty() || plan == SaveRule.Plan.Nothing)) {
            return try {
                saved(engine.applySave(vault, p.target, p.username, p.password, p.appLabel, plan) ?: "This login is already saved in PassAuth.")
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                val text = "Couldn't save to PassAuth: ${io.passauth.app.ui.errorMessage(e)}"
                if (credentialMode) failCredential(text) else saved(text)
            }
        }
        askSave(p, candidates, plan, addTo, null)
    }

    /**
     * "Update login?" / "Save login?": what will change, and "Save in" to change it. What the
     * sheet shows is what gets saved: if the chosen login is gone by the time the user confirms
     * (a sync), the choices are shown again instead of saving somewhere else.
     */
    private fun askSave(
        p: AutofillEngine.Companion.PendingSave,
        candidates: List<SaveRule.Candidate<String>>,
        plan: SaveRule.Plan<String>,
        addTo: List<AddSite.Target<String>>,
        notice: String?,
    ) {
        val targets = SaveRule.targets(candidates, p.username, p.password)
        // A new login's id, the same for every tap on Save in this sheet (an attempt whose answer was lost isn't saved twice).
        val newItemId = saveItemId
        val place = engine.placeName(p.target, p.appLabel)
        val here = if (p.target is FillTarget.App) "app" else "site"
        fun target(choice: String?) = targets.firstOrNull { it.id == choice }
        // Same account on another site or app: "Add this site" rows (ids prefixed: never a login's own id).
        fun adding(choice: String?) = choice?.takeIf { it.startsWith(ADD_TO) }?.let { c -> addTo.firstOrNull { ADD_TO + it.id == c } }
        val addWord = if (p.target is FillTarget.App) "app" else "site"
        confirm(
            title = { if (adding(it) != null) "Add $addWord to login?" else if (target(it) != null) "Update login?" else "Save login?" },
            place = place,
            body = { c -> adding(c)?.let { AddSite.describe(it, place) } ?: SaveRule.describe(target(c), p.username, place) },
            action = { if (adding(it) != null) "Add $addWord" else if (target(it) != null) "Update login" else "Save login" },
            choicesLabel = "Save in",
            choices = targets.map { c ->
                // A login in a vault somebody shared says so: its other members will see what is saved.
                val user = c.username.ifEmpty { "No user name" }
                ServiceActivity.Choice(c.id, c.name.ifEmpty { place }, if (c.personal) user else "$user · ${c.vault.ifEmpty { "Shared vault" }}")
            } + addTo.map { t ->
                ServiceActivity.Choice(ADD_TO + t.id, t.name.ifEmpty { t.site.ifEmpty { "Login" } }, "Add this $addWord · ${t.site.ifEmpty { t.username.ifEmpty { "same account" } }}")
            } + ServiceActivity.Choice(SAVE_NEW, "New login", place, ServiceActivity.Symbol.New),
            initialChoice = (plan as? SaveRule.Plan.Update)?.id ?: SAVE_NEW,
            error = notice,
            // A login in a shared vault is only ever chosen here, by the user, with this warning.
            warning = { c -> adding(c)?.let { AddSite.warning(it, place, addWord) } ?: SaveRule.sharedWarning(target(c)) },
            // An app that asked to save through Credential Manager is answered "saved" or "cancelled"; "Never" is autofill's.
            quiet = if (credentialMode) emptyList() else listOf(
                ServiceActivity.Quiet("Never for this $here") {
                    engine.addNeverSave(AutofillMatcher.neverSaveKey(p.target))
                    saved("PassAuth won't offer to save logins here. You can change this in Settings → Autofill.")
                },
            ),
        ) {
            if (p.accountId != graph.repo.state.value.activeId) throw io.passauth.app.data.UserException("Another account is active now. Sign in again to save this login.")
            val current = graph.repo.vault.value ?: throw io.passauth.app.data.UserException("PassAuth is locked. Sign in to $place again to save this login.")
            adding(chosen)?.let { t ->
                // Still the same account (editable, own vault, the typed user name and password); otherwise ask again.
                val still = engine.sameAccountElsewhere(current, p.target, p.username, p.password).any { it.id == t.id }
                if (!still) {
                    val now = engine.saveCandidates(current, p.target)
                    return@confirm askSave(
                        p, now, SaveRule.plan(now, p.username, p.password),
                        engine.sameAccountElsewhere(current, p.target, p.username, p.password),
                        "That login changed. Check where to save, then try again.",
                    )
                }
                engine.addSite(current, t.id, p.target)
                return@confirm saved("$place added to ${t.name.ifEmpty { "your login" }}.")
            }
            val now = engine.saveCandidates(current, p.target)
            val chosenPlan = SaveRule.planFor(now, chosen.takeIf { it != SAVE_NEW }, p.username, p.password)
            if (chosenPlan == null) {
                // The login the sheet showed is no longer one this save may go to: ask again.
                askSave(p, now, SaveRule.plan(now, p.username, p.password), engine.sameAccountElsewhere(current, p.target, p.username, p.password), "That login is no longer in your vault. Choose where to save.")
            } else {
                saved(engine.applySave(current, p.target, p.username, p.password, p.appLabel, chosenPlan, newItemId) ?: "This login is already saved in PassAuth.")
            }
        }
    }

    private fun saved(notice: String?) {
        notice?.let(::toast)
        if (credentialMode) {
            val r = Intent()
            PendingIntentHandler.setCreateCredentialResponse(r, CreatePasswordResponse())
            setResult(RESULT_OK, r)
        } else {
            setResult(RESULT_OK)
        }
        finish()
    }

    override fun cancel() {
        if (!credentialMode) return super.cancel()
        val r = Intent()
        PendingIntentHandler.setCreateCredentialException(r, CreateCredentialCancellationException("The user didn't save the password."))
        setResult(RESULT_OK, r)
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
        const val MODE_ADD_SITE = "add-site"
        const val MODE_CREDENTIAL_SAVE = "credential-save"

        /** "Save in" choice meaning a new login (never an item id: those are UUIDs). */
        private const val SAVE_NEW = "new"

        /** Prefix of a "Save in" choice that adds the site or app to a login for another place. */
        private const val ADD_TO = "add:"

        private val requestCodes = AtomicInteger(1)

        /**
         * An IntentSender for this activity. Mutable where the framework must add the
         * assist structure and inline request; explicit (component set) either way.
         */
        fun sender(context: Context, mode: String, entry: String? = null, key: String? = null): IntentSender {
            val intent = Intent(context, AutofillAuthActivity::class.java)
                .putExtra(EXTRA_MODE, mode)
                .apply { entry?.let { putExtra(EXTRA_ENTRY, it) }; key?.let { putExtra(EXTRA_KEY, it) } }
            val mutable = mode == MODE_UNLOCK || mode == MODE_DATASET || mode == MODE_ADD_SITE
            val flags = PendingIntent.FLAG_CANCEL_CURRENT or if (mutable) PendingIntent.FLAG_MUTABLE else PendingIntent.FLAG_IMMUTABLE
            return PendingIntent.getActivity(context, requestCodes.getAndIncrement(), intent, flags).intentSender
        }

        /** The `CreateEntry` of a Credential Manager password save: mutable (the framework adds the request), explicit. */
        fun credentialSave(context: Context): PendingIntent {
            val intent = Intent(context, AutofillAuthActivity::class.java).putExtra(EXTRA_MODE, MODE_CREDENTIAL_SAVE)
            return PendingIntent.getActivity(context, requestCodes.getAndIncrement(), intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }

        /**
         * One dataset per matching login (filled directly, or through [MODE_DATASET] when it
         * has a verification code to copy or fill), plus "Open PassAuth". On a form with
         * only a one-time-code field, the logins that have a verification code. When no login
         * matches a sign-in form and [addSite] ([AddSite.allowed]): "Add this site to a login…".
         */
        fun buildDatasets(
            context: Context,
            ui: AutofillResponses,
            engine: AutofillEngine,
            vault: VaultData,
            target: FillTarget,
            form: LoginForm<android.view.autofill.AutofillId>,
            settings: io.passauth.app.data.Settings,
            addSite: Boolean,
        ): List<android.service.autofill.Dataset> {
            val otpOnly = form.fillIds.isEmpty() && form.otp != null
            val entries = engine.matches(vault, target).filter { !otpOnly || !it.item.login?.totp.isNullOrBlank() }
            val out = entries.mapNotNull { e ->
                val auth = if (AutofillResponses.wantsTotpAuth(e, form, settings)) sender(context, MODE_DATASET, entry = e.id) else null
                // A screen that only asks for the code: "Verification code" (from which login underneath).
                ui.dataset(e, form, auth, codeOnly = otpOnly)
            }.toMutableList()
            // Nothing saved for this place: offer to add it to a login of the same account ([AddSite]).
            if (AddSite.offerEntry(addSite, entries.isNotEmpty(), form, target is FillTarget.App) { engine.addSiteTargets(vault, target).isNotEmpty() }) {
                val place = engine.placeName(target, (target as? FillTarget.App)?.let { engine.appLabel(it.packageName) })
                ui.addSiteDataset(form.fillIds, target is FillTarget.App, place, sender(context, MODE_ADD_SITE))?.let { out += it }
            }
            ui.openDataset(form.fillIds + listOfNotNull(form.otp?.id), sender(context, MODE_OPEN))?.let { out += it }
            return out
        }
    }
}
