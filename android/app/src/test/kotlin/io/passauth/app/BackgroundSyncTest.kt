package io.passauth.app

import io.passauth.app.data.BACKGROUND_SYNC_DEFAULT
import io.passauth.app.data.BACKGROUND_SYNC_OPTIONS
import io.passauth.app.data.BackgroundSync
import io.passauth.app.data.DeltaSync
import io.passauth.app.data.SyncSnapshot
import io.passauth.app.data.UserException
import io.passauth.app.data.Settings
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class BackgroundSyncTest {
    private fun snapshot(revision: Any) =
        """{"revision":$revision,"user":{"name":"A"},"bundle":{"secret_key_enabled":false},"vaults":[],"items":[]}"""

    /** The locked refresh without delta sync: [fetched] as the server's `/sync`, [cached] as the copy on the device. */
    private fun refresh(fetched: String, cached: String?): DeltaSync.CacheRefresh = runBlocking {
        DeltaSync.refresh(cached?.let { SyncSnapshot.decode(it) }, delta = false, trashSummary = true) { path ->
            assertEquals("/sync?trash=summary", path)
            fetched
        }
    }

    private fun written(r: DeltaSync.CacheRefresh) = (r as? DeltaSync.CacheRefresh.Write)?.snapshot

    @Test
    fun validSnapshotIsWrittenWithItsRevision() {
        assertEquals(7L, written(refresh(snapshot(7), null))?.revision)
        assertEquals(0L, written(refresh(snapshot(0), null))?.revision)
    }

    @Test
    fun malformedBodiesAreRejected() {
        for (body in listOf(
            "",
            "<html>Sign in</html>",
            "[]",
            """{"error":"unauthorized"}""",
            snapshot("\"7\""), // string revision
            snapshot(-1),
            """{"revision":3,"bundle":{},"vaults":[]}""", // items missing
            """{"revision":3,"bundle":"x","vaults":[],"items":[]}""", // bundle not an object
            """{"revision":3,"vaults":[],"items":[]}""", // no bundle: the next unlock needs it
            """{"revision":3,"bundle":{},"vaults":[],"items":[{"id":"i1","vault_id":"v1"}]}""", // a live item without its data
            snapshot(7).dropLast(1), // truncated
        )) {
            assertThrows(body, UserException::class.java) { refresh(body, null) }
        }
    }

    @Test
    fun writesOnlyValidAndNotOlder() {
        assertEquals(5L, written(refresh(snapshot(5), snapshot(5)))?.revision)
        assertEquals(6L, written(refresh(snapshot(6), snapshot(5)))?.revision)
        assertEquals(DeltaSync.CacheRefresh.Keep, refresh(snapshot(4), snapshot(5)))
        // An unreadable copy is replaced.
        assertEquals(3L, written(refresh(snapshot(3), "garbage"))?.revision)
    }

    @Test
    fun flexIsAQuarterCappedAt15() {
        assertEquals(7L, BackgroundSync.flexMinutes(30))
        assertEquals(15L, BackgroundSync.flexMinutes(60))
        assertEquals(15L, BackgroundSync.flexMinutes(720))
        assertEquals(5L, BackgroundSync.flexMinutes(15))
    }

    @Test
    fun settingDefaultsAndStaysBackwardCompatible() {
        assertEquals(120, BACKGROUND_SYNC_DEFAULT)
        assertEquals(listOf(0, 30, 60, 120, 360, 720), BACKGROUND_SYNC_OPTIONS.map { it.first })
        val old = Json { ignoreUnknownKeys = true }.decodeFromString(Settings.serializer(), """{"autoCopyTotp":false}""")
        assertEquals(BACKGROUND_SYNC_DEFAULT, old.backgroundSyncMinutes)
    }
}
