package io.passauth.app

import io.passauth.app.data.BACKGROUND_SYNC_DEFAULT
import io.passauth.app.data.BACKGROUND_SYNC_OPTIONS
import io.passauth.app.data.BackgroundSync
import io.passauth.app.data.CacheRefresh
import io.passauth.app.data.Settings
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundSyncTest {
    private fun snapshot(revision: Any) =
        """{"revision":$revision,"user":{"name":"A"},"bundle":{"secret_key_enabled":false},"vaults":[],"items":[]}"""

    @Test
    fun validSnapshotYieldsItsRevision() {
        assertEquals(7L, CacheRefresh.revisionOf(snapshot(7)))
        assertEquals(0L, CacheRefresh.revisionOf(snapshot(0)))
    }

    @Test
    fun malformedBodiesAreRejected() {
        assertNull(CacheRefresh.revisionOf(""))
        assertNull(CacheRefresh.revisionOf("<html>Sign in</html>"))
        assertNull(CacheRefresh.revisionOf("[]"))
        assertNull(CacheRefresh.revisionOf("""{"error":"unauthorized"}"""))
        assertNull(CacheRefresh.revisionOf(snapshot("\"7\""))) // string revision
        assertNull(CacheRefresh.revisionOf(snapshot(-1)))
        assertNull(CacheRefresh.revisionOf("""{"revision":3,"bundle":{},"vaults":[]}""")) // items missing
        assertNull(CacheRefresh.revisionOf("""{"revision":3,"bundle":"x","vaults":[],"items":[]}""")) // bundle not an object
        assertNull(CacheRefresh.revisionOf(snapshot(7).dropLast(1))) // truncated
    }

    @Test
    fun writesOnlyValidAndNotOlder() {
        assertTrue(CacheRefresh.shouldWrite(fetched = 5, cached = null))
        assertTrue(CacheRefresh.shouldWrite(fetched = 5, cached = 5))
        assertTrue(CacheRefresh.shouldWrite(fetched = 6, cached = 5))
        assertFalse(CacheRefresh.shouldWrite(fetched = 4, cached = 5))
        assertFalse(CacheRefresh.shouldWrite(fetched = null, cached = 5))
        assertFalse(CacheRefresh.shouldWrite(fetched = null, cached = null))
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
