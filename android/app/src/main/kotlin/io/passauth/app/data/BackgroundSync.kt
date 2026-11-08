package io.passauth.app.data

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.passauth.app.graph
import kotlinx.coroutines.flow.first
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.concurrent.TimeUnit

/**
 * Pure decisions for the locked cache refresh: which `/sync` bodies are a valid
 * offline copy, and whether a fetched copy may replace the cached one.
 */
object CacheRefresh {
    /**
     * The revision of a `/sync` response, or null when the body isn't a vault
     * snapshot (must be a JSON object with a numeric `revision`, a `bundle`
     * object and `vaults` + `items` arrays). Nothing is decrypted.
     */
    fun revisionOf(json: String): Long? {
        val o = runCatching { AppJson.parseToJsonElement(json) }.getOrNull() as? JsonObject ?: return null
        val rev = (o["revision"] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull() ?: return null
        if (rev < 0) return null
        if (o["bundle"] !is JsonObject) return null
        if (o["vaults"] !is JsonArray || o["items"] !is JsonArray) return null
        return rev
    }

    /**
     * Write the fetched copy only when it parsed ([fetched] not null) and is not
     * older than the cached one. A missing or unreadable cache ([cached] null)
     * is always replaced by a valid response.
     */
    fun shouldWrite(fetched: Long?, cached: Long?): Boolean =
        fetched != null && (cached == null || fetched >= cached)
}

/** Periodic refresh of every account's encrypted offline copy while the app is closed. */
object BackgroundSync {
    const val WORK_NAME = "background-sync"
    private const val TAG_PREFIX = "interval-"
    private const val MIN_MINUTES = 15L // WorkManager's floor
    private const val MAX_FLEX_MINUTES = 15L

    /** Flex window in minutes: a quarter of the interval, at most 15 minutes (and never below WorkManager's 5). */
    fun flexMinutes(intervalMinutes: Long): Long = minOf(intervalMinutes / 4, MAX_FLEX_MINUTES).coerceAtLeast(5)

    /**
     * Keep the unique periodic work in line with the setting: cancelled when [minutes]
     * is 0 or no account is signed in; otherwise enqueued (KEEP) or, if the interval
     * changed since it was scheduled, replaced (UPDATE).
     */
    suspend fun schedule(context: Context, minutes: Int, hasAccounts: Boolean) {
        val wm = WorkManager.getInstance(context.applicationContext)
        if (minutes <= 0 || !hasAccounts) {
            wm.cancelUniqueWork(WORK_NAME)
            return
        }
        val interval = minutes.toLong().coerceAtLeast(MIN_MINUTES)
        val tag = "$TAG_PREFIX$interval"
        val current = runCatching { wm.getWorkInfosForUniqueWorkFlow(WORK_NAME).first() }.getOrNull().orEmpty()
            .firstOrNull { !it.state.isFinished }
        val policy = if (current != null && tag !in current.tags) ExistingPeriodicWorkPolicy.UPDATE else ExistingPeriodicWorkPolicy.KEEP
        val request = PeriodicWorkRequestBuilder<BackgroundSyncWorker>(interval, TimeUnit.MINUTES, flexMinutes(interval), TimeUnit.MINUTES)
            .addTag(tag)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build(),
            )
            .build()
        wm.enqueueUniquePeriodicWork(WORK_NAME, policy, request)
    }
}

/**
 * Runs in the app's own process (the default WorkManager initializer) and uses the
 * app's repository and [ApiClient], so token refreshes share the in-process
 * de-duplication: a second, parallel refresh would be flagged as token reuse by
 * the server and end the session.
 */
class BackgroundSyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val graph = applicationContext.graph
        graph.loadedState()
        val outcome = graph.repo.refreshAllCaches()
        if (outcome.networkFailures > 0 && outcome.refreshed == 0) {
            Log.i("PassAuth", "Background sync: server unreachable, will retry")
            return Result.retry()
        }
        return Result.success()
    }
}
