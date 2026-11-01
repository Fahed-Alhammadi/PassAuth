package io.passauth.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.passauth.app.ui.AppRoot
import io.passauth.app.ui.Route
import io.passauth.app.ui.theme.PassAuthTheme
import kotlinx.coroutines.launch

class MainActivity : SecureActivity() {
    /** A screen to open, requested by an intent (Android's autofill or passkey settings). */
    val requestedRoute = mutableStateOf<Route?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (savedInstanceState == null) handle(intent)
        // Live sync only while PassAuth is on screen (and unlocked: see LiveSync).
        lifecycleScope.launch { repeatOnLifecycle(Lifecycle.State.STARTED) { graph.live.run() } }
        setContent {
            val state by graph.repo.state.collectAsStateWithLifecycle()
            PassAuthTheme(state.settings.theme) {
                AppRoot(graph, state, this)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        // The "AutofillSettings" alias is the settings activity of the autofill service and the passkey provider.
        if (intent?.component?.className?.endsWith(".AutofillSettings") == true || intent?.getBooleanExtra(EXTRA_AUTOFILL_SETTINGS, false) == true) {
            requestedRoute.value = Route.Settings("autofill")
        }
    }

    override fun onResume() {
        super.onResume()
        lifecycleScope.launch { runCatching { graph.repo.refreshIfStale() } }
    }

    companion object {
        const val EXTRA_AUTOFILL_SETTINGS = "io.passauth.app.AUTOFILL_SETTINGS"
    }
}
