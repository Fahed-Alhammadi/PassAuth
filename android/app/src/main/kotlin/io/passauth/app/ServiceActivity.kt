package io.passauth.app

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Person
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import io.passauth.app.data.Status
import io.passauth.app.data.VaultData
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.auth.UnlockFields
import io.passauth.app.ui.auth.rememberUnlockUi
import io.passauth.app.ui.components.ChoiceRow
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.GroupLabel
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptHeader
import io.passauth.app.ui.components.PromptSheet
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.RowDivider
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.components.TileRowInset
import io.passauth.app.ui.components.largeText
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.theme.isDark
import kotlinx.coroutines.launch

/**
 * Base of the activities the autofill and credential services start. They stay
 * see-through while they work without asking anything. When they must ask, they
 * show a sheet over the calling app (never a full page) in the decision-sheet
 * anatomy (ui/components/DecisionSheet.kt): unlock (master password or biometrics),
 * a confirmation with an optional choice, or a message.
 */
abstract class ServiceActivity : SecureActivity() {
    private sealed interface Screen {
        data object None : Screen
        data class Unlock(val title: String, val reason: String) : Screen
        data class Confirm(
            /** What is being decided, for the current choice (e.g. "Update login?"). */
            val title: (String?) -> String,
            /** The site or app, under the title. */
            val place: String,
            val body: (String?) -> String?,
            /** The primary button, for the current choice (a verb: "Save passkey"). */
            val action: (String?) -> String,
            val onConfirm: suspend () -> Unit,
            /** Optional single choice (e.g. "Save in"); the pick is in [chosen]. */
            val choicesLabel: String? = null,
            val choices: List<Choice> = emptyList(),
            val footnote: String? = null,
            val quiet: List<Quiet> = emptyList(),
            /** The account that was active when the sheet opened. */
            val account: String = "",
        ) : Screen
        data class Message(val title: String, val body: String, val openApp: Boolean) : Screen
    }

    private var screen by mutableStateOf<Screen>(Screen.None)
    private var busy by mutableStateOf(false)
    private var error by mutableStateOf<String?>(null)
    private var onUnlocked: (suspend (VaultData) -> Unit)? = null

    /** A row of a confirmation's choice list. [symbol] replaces the first letter of [title] on the tile. */
    data class Choice(val id: String, val title: String, val detail: String, val symbol: Symbol? = null)

    enum class Symbol { New, Person }

    /** A quiet action under the primary button (besides "Cancel"). */
    class Quiet(val label: String, val onClick: suspend () -> Unit)

    /** The choice picked on the confirm screen. */
    protected var chosen by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // These sheets ask for consent (save, sign in, unlock): no other app may draw over them
        // to hide what is being agreed to or to pass a tap through.
        window.setHideOverlayWindows(true)
        onBackPressedDispatcher.addCallback(this, object : androidx.activity.OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (!busy) cancel()
            }
        })
        setContent {
            val state by graph.repo.state.collectAsStateWithLifecycle()
            PassAuthTheme(state.settings.theme) {
                val s = screen
                if (s != Screen.None) {
                    // The sheet's colour runs under the navigation bar: its buttons follow the theme.
                    val dark = isDark(state.settings.theme)
                    SideEffect { WindowCompat.getInsetsController(window, window.decorView).isAppearanceLightNavigationBars = !dark }
                    Content(s, state)
                }
            }
        }
    }

    @Composable
    private fun Content(s: Screen, state: io.passauth.app.data.AppState) {
        val scope = rememberCoroutineScope()
        when (s) {
            Screen.None -> Unit
            is Screen.Unlock -> {
                when (state.status) {
                    Status.Locked -> UnlockPrompt(s, UiCtx(graph, state, this, scope, { toast(it) }, {}))
                    // Runs in the activity's scope: hiding the unlock screen must not cancel the work.
                    Status.Unlocked -> LaunchedEffect(state.activeId) {
                        val cb = onUnlocked ?: return@LaunchedEffect
                        onUnlocked = null
                        lifecycleScope.launch {
                            val vault = graph.awaitVault()
                            if (vault == null) {
                                onUnlocked = cb
                                return@launch
                            }
                            screen = Screen.None
                            cb(vault)
                        }
                    }
                    else -> MessagePrompt(Screen.Message("Sign in to PassAuth", "Open PassAuth and sign in to your account first.", openApp = true))
                }
            }
            // A consent sheet belongs to the unlocked session it was opened in: locking, logging out
            // or switching account closes it (and with it whatever was waiting to be saved).
            is Screen.Confirm -> if (state.status == Status.Unlocked && state.activeId == s.account) ConfirmPrompt(s) else LaunchedEffect(Unit) { cancel() }
            is Screen.Message -> MessagePrompt(s)
        }
    }

    @Composable
    private fun UnlockPrompt(s: Screen.Unlock, ctx: UiCtx) {
        val ui = rememberUnlockUi(ctx)
        val focus = remember { FocusRequester() }
        // Biometrics ask first when they are on; otherwise the keyboard opens on the password.
        LaunchedEffect(Unit) { if (!ui.canBio) runCatching { focus.requestFocus() } }
        PromptSheet(
            onClose = ::cancel,
            canClose = !ui.busy,
            error = ui.error,
            actions = {
                PrimaryButton(if (ui.busy) "Unlocking…" else "Unlock", ui::submit, enabled = ui.password.isNotEmpty(), busy = ui.busy)
                QuietActions {
                    if (ui.canBio) QuietButton("Use biometrics", ui::biometric, enabled = !ui.busy, icon = Icons.Outlined.Fingerprint)
                    QuietButton("Cancel", ::cancel, enabled = !ui.busy)
                }
            },
        ) {
            PromptHeader(s.title, ctx.state.email) { Tile(icon = Icons.Outlined.Lock) }
            PromptText(s.reason)
            Column(verticalArrangement = Arrangement.spacedBy(Space.m)) { UnlockFields(ui, Modifier.focusRequester(focus)) }
        }
    }

    private fun symbol(s: Symbol?): ImageVector? = when (s) {
        Symbol.New -> Icons.Outlined.Add
        Symbol.Person -> Icons.Outlined.Person
        null -> null
    }

    @Composable
    private fun ConfirmPrompt(s: Screen.Confirm) {
        fun run(block: suspend () -> Unit) {
            if (busy) return
            busy = true
            error = null
            lifecycleScope.launch {
                try {
                    block()
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    error = io.passauth.app.ui.errorMessage(e)
                } finally {
                    busy = false
                }
            }
        }
        PromptSheet(
            onClose = ::cancel,
            canClose = !busy,
            error = error,
            actions = {
                PrimaryButton(s.action(chosen), { run(s.onConfirm) }, busy = busy)
                QuietActions {
                    s.quiet.forEach { q -> QuietButton(q.label, { run(q.onClick) }, enabled = !busy) }
                    QuietButton(if (s.quiet.isEmpty()) "Cancel" else "Not now", ::cancel, enabled = !busy)
                }
            },
        ) {
            PromptHeader(s.title(chosen), s.place) { Tile(s.place) }
            s.body(chosen)?.let { PromptText(it) }
            if (s.choices.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(Space.s)) {
                    s.choicesLabel?.let { GroupLabel(it) }
                    GroupCard(Modifier.selectableGroup()) {
                        val inset = if (largeText()) Space.l else TileRowInset
                        s.choices.forEachIndexed { n, c ->
                            if (n > 0) RowDivider(inset)
                            ChoiceRow(c.title, c.detail, selected = chosen == c.id, onClick = { chosen = c.id }, enabled = !busy, icon = symbol(c.symbol))
                        }
                    }
                    s.footnote?.let { PromptText(it, Modifier) }
                }
            } else {
                s.footnote?.let { PromptText(it) }
            }
        }
    }

    @Composable
    private fun MessagePrompt(s: Screen.Message) {
        PromptSheet(
            onClose = ::cancel,
            closeLabel = "Close",
            actions = {
                if (s.openApp) {
                    PrimaryButton("Open PassAuth", { openApp(); cancel() })
                    QuietActions { QuietButton("Close", ::cancel) }
                } else {
                    PrimaryButton("Close", ::cancel)
                }
            },
        ) {
            PromptHeader(s.title) { Tile(icon = if (s.openApp) Icons.Outlined.Lock else Icons.Outlined.ErrorOutline) }
            PromptText(s.body)
        }
    }

    /**
     * Run [block] with the active account's unlocked vault. If it's locked, the
     * unlock sheet is shown first ([unlockTitle] and one line saying why);
     * `unlockedHere` tells the block the user has just proven who they are.
     */
    protected fun withVault(unlockTitle: String, reason: String, block: suspend (vault: VaultData, unlockedHere: Boolean) -> Unit) {
        lifecycleScope.launch {
            val vault = graph.awaitVault()
            if (vault != null) {
                block(vault, false)
            } else {
                onUnlocked = { v -> block(v, true) }
                screen = Screen.Unlock(unlockTitle, reason)
            }
        }
    }

    /**
     * Ask the user to confirm; [onConfirm] errors are shown on the sheet. [title], [body]
     * and [action] follow the current choice (its id, or null when there are no choices).
     */
    protected fun confirm(
        title: (String?) -> String,
        place: String,
        body: (String?) -> String?,
        action: (String?) -> String,
        choicesLabel: String? = null,
        choices: List<Choice> = emptyList(),
        initialChoice: String? = null,
        footnote: String? = null,
        quiet: List<Quiet> = emptyList(),
        error: String? = null,
        onConfirm: suspend () -> Unit,
    ) {
        this.error = error
        chosen = initialChoice
        screen = Screen.Confirm(title, place, body, action, onConfirm, choicesLabel, choices, footnote, quiet, graph.repo.state.value.activeId)
    }

    /** Show a message with a Close button (the request fails when closed). */
    protected fun message(title: String, body: String) {
        screen = Screen.Message(title, body, openApp = false)
    }

    protected fun hideUi() {
        screen = Screen.None
    }

    protected fun openApp() {
        startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    protected fun toast(text: String) = Toast.makeText(applicationContext, text, Toast.LENGTH_SHORT).show()

    /** The user backed out: finish without a result. */
    protected open fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }
}
