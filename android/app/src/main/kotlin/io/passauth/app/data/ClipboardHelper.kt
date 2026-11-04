package io.passauth.app.data

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Copies marked sensitive (hidden from clipboard previews) and cleared after the
 * user's delay, but only while the clipboard still holds PassAuth's copy (so a
 * clip the user copied meanwhile is left alone). An alarm repeats the clearing
 * in case the app's process is stopped before the delay ends.
 */
class ClipboardHelper(
    private val context: Context,
    private val scope: CoroutineScope,
    private val clearAfterSeconds: () -> Int,
) {
    private val cm = context.getSystemService(ClipboardManager::class.java)
    private var clearJob: Job? = null

    /** Returns the delay in seconds after which the clipboard clears (0 = never). */
    fun copy(text: String, label: String, sensitive: Boolean = true): Int {
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = PersistableBundle().apply {
            if (sensitive) putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            putBoolean(EXTRA_OURS, true)
        }
        cm.setPrimaryClip(clip)
        val stamp = runCatching { cm.primaryClipDescription?.timestamp }.getOrNull() ?: 0L
        clearJob?.cancel()
        val after = clearAfterSeconds()
        if (after > 0) {
            schedule(context, after * 1000L, stamp)
            clearJob = scope.launch {
                delay(after * 1000L)
                clearIfOurs(context, stamp)
                cancelAlarm(context)
            }
        }
        return after
    }

    /** Backstop for the in-process timer: clears after the delay even if the process was stopped. */
    class ClearReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            clearIfOurs(context, intent.getLongExtra(EXTRA_STAMP, 0L))
        }
    }

    companion object {
        private const val EXTRA_OURS = "io.passauth.clip"
        private const val EXTRA_STAMP = "stamp"

        /** True when the current clip is the one PassAuth set at [stamp] (or can't be read, e.g. in the background). */
        internal fun isOurs(desc: ClipDescription?, stamp: Long): Boolean {
            desc ?: return true
            val marked = desc.extras?.getBoolean(EXTRA_OURS) == true
            return marked && (stamp == 0L || desc.timestamp == stamp)
        }

        private fun clearIfOurs(context: Context, stamp: Long) {
            val cm = context.getSystemService(ClipboardManager::class.java) ?: return
            // Apps in the background can't read the clipboard; then clear, as before.
            val desc = runCatching { cm.primaryClipDescription }.getOrNull()
            if (isOurs(desc, stamp)) runCatching { cm.clearPrimaryClip() }
        }

        private fun pending(context: Context, stamp: Long = 0L): PendingIntent = PendingIntent.getBroadcast(
            context,
            0,
            Intent(context, ClearReceiver::class.java).putExtra(EXTRA_STAMP, stamp),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        private fun schedule(context: Context, delayMs: Long, stamp: Long) {
            val am = context.getSystemService(AlarmManager::class.java) ?: return
            runCatching { am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + delayMs, pending(context, stamp)) }
        }

        private fun cancelAlarm(context: Context) {
            context.getSystemService(AlarmManager::class.java)?.cancel(pending(context))
        }
    }
}

fun secondsLabel(s: Int) = if (s < 60) "$s seconds" else "${s / 60} minute${if (s > 60) "s" else ""}"

fun copiedNote(label: String, clearAfter: Int) =
    "$label copied." + if (clearAfter > 0) " Clipboard clears in ${secondsLabel(clearAfter)}." else ""
