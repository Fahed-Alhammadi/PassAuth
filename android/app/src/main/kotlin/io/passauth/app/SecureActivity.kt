package io.passauth.app

import android.view.WindowManager
import androidx.fragment.app.FragmentActivity

/** Base of PassAuth's activities: reference-counted FLAG_SECURE and overlay hiding, and vault-timeout activity tracking. */
abstract class SecureActivity : FragmentActivity() {
    protected val graph: AppGraph get() = (application as PassAuthApp).graph
    private var secureRequests = 0
    private var overlayRequests = 0

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

    /**
     * While a decision is on screen (a consent sheet, a sign-in approval, a confirmation), no other
     * app may draw over PassAuth: an overlay could hide what is being agreed to, or let a tap
     * through to a button it covers. Android hides other apps' overlays while a window that asks
     * for it is visible ([android.view.Window.setHideOverlayWindows], permission
     * HIDE_OVERLAY_WINDOWS). Reference-counted: shown again once the last decision is gone.
     */
    fun hideOverlays(on: Boolean) {
        overlayRequests = (overlayRequests + if (on) 1 else -1).coerceAtLeast(0)
        window.setHideOverlayWindows(overlayRequests > 0)
    }
}
