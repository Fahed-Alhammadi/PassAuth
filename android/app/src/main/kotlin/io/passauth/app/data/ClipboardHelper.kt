package io.passauth.app.data

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Copies marked sensitive (hidden from clipboard previews) and cleared after the user's delay. */
class ClipboardHelper(
    context: Context,
    private val scope: CoroutineScope,
    private val clearAfterSeconds: () -> Int,
) {
    private val cm = context.getSystemService(ClipboardManager::class.java)
    private var clearJob: Job? = null

    /** Returns the delay in seconds after which the clipboard clears (0 = never). */
    fun copy(text: String, label: String, sensitive: Boolean = true): Int {
        val clip = ClipData.newPlainText(label, text)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        clearJob?.cancel()
        val after = clearAfterSeconds()
        if (after > 0) {
            clearJob = scope.launch {
                delay(after * 1000L)
                runCatching { cm.clearPrimaryClip() }
            }
        }
        return after
    }
}

fun secondsLabel(s: Int) = if (s < 60) "$s seconds" else "${s / 60} minute${if (s > 60) "s" else ""}"

fun copiedNote(label: String, clearAfter: Int) =
    "$label copied." + if (clearAfter > 0) " Clipboard clears in ${secondsLabel(clearAfter)}." else ""
