package io.passauth.app

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import io.passauth.app.data.Status
import io.passauth.app.data.VaultData
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.auth.AuthFrame
import io.passauth.app.ui.auth.UnlockScreen
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.theme.PassAuthTheme
import kotlinx.coroutines.launch

/**
 * Base of the activities the autofill and credential services start. They stay
 * see-through while they work without asking anything; they show the unlock
 * screen (master password or biometrics) when the vault is locked, and
 * confirmation or error screens in PassAuth's style.
 */
abstract class ServiceActivity : SecureActivity() {
    private sealed interface Screen {
        data object None : Screen
        data class Unlock(val title: String) : Screen
        data class Confirm(
            val title: String,
            val subtitle: String?,
            val body: String?,
            val action: String,
            val onConfirm: suspend () -> Unit,
        ) : Screen
        data class Message(val title: String, val body: String, val openApp: Boolean) : Screen
    }

    private var screen by mutableStateOf<Screen>(Screen.None)
    private var busy by mutableStateOf(false)
    private var error by mutableStateOf<String?>(null)
    private var onUnlocked: (suspend (VaultData) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        onBackPressedDispatcher.addCallback(this, object : androidx.activity.OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = cancel()
        })
        setContent {
            val state by graph.repo.state.collectAsStateWithLifecycle()
            PassAuthTheme(state.settings.theme) {
                val s = screen
                if (s != Screen.None) {
                    Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) { Content(s, state) }
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
                    Status.Locked -> {
                        val ctx = UiCtx(graph, state, this, scope, { toast(it) }, {})
                        UnlockScreen(ctx, title = s.title, embedded = true)
                    }
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
                    else -> MessageScreen(Screen.Message("Sign in to PassAuth", "Open PassAuth and sign in to your account first.", openApp = true))
                }
            }
            is Screen.Confirm -> AuthFrame(s.title, s.subtitle) {
                s.body?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
                ErrorText(error)
                Button(
                    onClick = {
                        if (busy) return@Button
                        busy = true
                        error = null
                        lifecycleScope.launch {
                            try {
                                s.onConfirm()
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                error = io.passauth.app.ui.errorMessage(e)
                            } finally {
                                busy = false
                            }
                        }
                    },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(s.action) }
                OutlinedButton(onClick = { cancel() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            is Screen.Message -> MessageScreen(s)
        }
    }

    @Composable
    private fun MessageScreen(s: Screen.Message) {
        AuthFrame(s.title, null) {
            Text(s.body, style = MaterialTheme.typography.bodyMedium)
            if (s.openApp) {
                Button(onClick = { openApp(); cancel() }, modifier = Modifier.fillMaxWidth()) { Text("Open PassAuth") }
            }
            OutlinedButton(onClick = { cancel() }, modifier = Modifier.fillMaxWidth()) { Text("Close") }
        }
    }

    /**
     * Run [block] with the active account's unlocked vault. If it's locked, the
     * unlock screen is shown first; `unlockedHere` tells the block the user has
     * just proven who they are.
     */
    protected fun withVault(unlockTitle: String, block: suspend (vault: VaultData, unlockedHere: Boolean) -> Unit) {
        lifecycleScope.launch {
            val vault = graph.awaitVault()
            if (vault != null) {
                block(vault, false)
            } else {
                onUnlocked = { v -> block(v, true) }
                screen = Screen.Unlock(unlockTitle)
            }
        }
    }

    /** Ask the user to confirm; [onConfirm] errors are shown on the screen. */
    protected fun confirm(title: String, subtitle: String?, body: String?, action: String, onConfirm: suspend () -> Unit) {
        error = null
        screen = Screen.Confirm(title, subtitle, body, action, onConfirm)
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
