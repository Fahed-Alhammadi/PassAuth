package io.passauth.app.data

import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Vault timeout, like the extension: lock (or log out) every account after the
 * chosen minutes without use, as soon as the app leaves the screen
 * ("Immediately"), only when the app process restarts, or never.
 */
class LockManager(private val repo: VaultRepository, private val scope: CoroutineScope) : DefaultLifecycleObserver {
    private var lastActivity = SystemClock.elapsedRealtime()
    private var timer: Job? = null

    /** Call on user interaction. */
    fun touch() {
        lastActivity = SystemClock.elapsedRealtime()
        schedule()
    }

    override fun onStart(owner: LifecycleOwner) {
        if (expired()) fire() else schedule()
    }

    override fun onStop(owner: LifecycleOwner) {
        if (repo.state.value.settings.vaultTimeout == VaultTimeout.Immediately) fire() else schedule()
    }

    private fun minutes(): Int? = repo.state.value.settings.vaultTimeout.minutes?.takeIf { it > 0 }

    private fun expired(): Boolean {
        val m = minutes() ?: return false
        return SystemClock.elapsedRealtime() - lastActivity >= m * 60_000L
    }

    private fun schedule() {
        timer?.cancel()
        val m = minutes() ?: return
        val wait = m * 60_000L - (SystemClock.elapsedRealtime() - lastActivity)
        timer = scope.launch {
            delay(wait.coerceAtLeast(0))
            fire()
        }
    }

    private fun fire() {
        timer?.cancel()
        val s = repo.state.value
        if (s.accounts.none { it.status == Status.Unlocked } && s.status != Status.Unlocked) return
        scope.launch {
            runCatching {
                if (s.settings.timeoutAction == TimeoutAction.Logout) repo.logoutAll() else repo.lockAll()
            }
        }
    }
}
