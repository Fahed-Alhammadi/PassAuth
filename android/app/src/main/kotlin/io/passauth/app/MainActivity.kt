package io.passauth.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import io.passauth.app.ui.AppRoot
import io.passauth.app.ui.theme.PassAuthTheme
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {
    private val graph get() = (application as PassAuthApp).graph
    private var secureRequests = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val state by graph.repo.state.collectAsStateWithLifecycle()
            PassAuthTheme(state.settings.theme) {
                AppRoot(graph, state, this)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        lifecycleScope.launch { runCatching { graph.repo.refreshIfStale() } }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        graph.lock.touch()
    }

    /**
     * Screens that show secrets keep the window out of screenshots, screen
     * recordings and the recents preview (FLAG_SECURE). Reference-counted.
     */
    fun setSecure(on: Boolean) {
        secureRequests = (secureRequests + if (on) 1 else -1).coerceAtLeast(0)
        if (secureRequests > 0 && !BuildConfig.ALLOW_SCREENSHOTS) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
