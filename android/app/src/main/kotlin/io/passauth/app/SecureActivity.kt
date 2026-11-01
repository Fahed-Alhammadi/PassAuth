package io.passauth.app

import android.view.WindowManager
import androidx.fragment.app.FragmentActivity

/** Base of PassAuth's activities: reference-counted FLAG_SECURE and vault-timeout activity tracking. */
abstract class SecureActivity : FragmentActivity() {
    protected val graph: AppGraph get() = (application as PassAuthApp).graph
    private var secureRequests = 0

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
