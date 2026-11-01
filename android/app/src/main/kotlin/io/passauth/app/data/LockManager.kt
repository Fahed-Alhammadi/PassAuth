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
    private var systemScreenUntil = 0L

    /** Call on user interaction. */
    fun touch() {
        lastActivity = SystemClock.elapsedRealtime()
        schedule()
    }

    /**
     * The app is about to open a system screen it comes back from (e.g. the file
     * picker for an export), so leaving the screen shouldn't trigger "Immediately".
     * If the user doesn't come back within two minutes, the vault locks anyway.
     */
    fun expectSystemScreen() {
        systemScreenUntil = SystemClock.elapsedRealtime() + SYSTEM_SCREEN_GRACE_MS
    }

    override fun onStart(owner: LifecycleOwner) {
        systemScreenUntil = 0L
        if (expired()) fire() else schedule()
    }

    override fun onStop(owner: LifecycleOwner) {
        val grace = systemScreenUntil - SystemClock.elapsedRealtime()
        if (grace > 0) {
            timer?.cancel()
            timer = scope.launch {
                delay(grace)
                fire()
            }
            return
        }
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

    private companion object {
        const val SYSTEM_SCREEN_GRACE_MS = 2 * 60_000L
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
