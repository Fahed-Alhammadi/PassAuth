package io.passauth.app

import io.passauth.app.data.LiveAction
import io.passauth.app.data.LiveMessage
import io.passauth.app.data.LiveSyncProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Messages of the server's /api/ws (crates/server/src/state.rs notify_sync / notify_logout). */
class LiveSyncProtocolTest {
    @Test
    fun parsesServerMessages() {
        assertEquals(LiveMessage.Sync(1767366245123), LiveSyncProtocol.parse("""{"type":"sync","revision":1767366245123}"""))
        assertEquals(LiveMessage.Logout, LiveSyncProtocol.parse("""{"type":"logout"}"""))
    }

    @Test
    fun ignoresUnknownOrBrokenMessages() {
        assertNull(LiveSyncProtocol.parse("""{"type":"hello"}"""))
        assertNull(LiveSyncProtocol.parse("""{"type":"sync"}"""))
        assertNull(LiveSyncProtocol.parse("""{"type":"sync","revision":"soon"}"""))
        assertNull(LiveSyncProtocol.parse("not json"))
        assertNull(LiveSyncProtocol.parse("[]"))
    }

    @Test
    fun syncsOnlyForNewerRevisions() {
        assertEquals(LiveAction.Sync, LiveSyncProtocol.action(LiveMessage.Sync(11), 10))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(10), 10)) // our own save, already synced
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(9), 10))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(11), null)) // locked: nothing to refresh
        assertEquals(LiveAction.CheckSession, LiveSyncProtocol.action(LiveMessage.Logout, 10))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(null, 10))
    }

    @Test
    fun socketUrls() {
        assertEquals("wss://vault.example.com/api/ws?access_token=a%2Bb%3D", LiveSyncProtocol.socketUrl("https://vault.example.com", "a+b="))
        assertEquals("ws://10.0.2.2:8091/api/ws?access_token=t", LiveSyncProtocol.socketUrl("http://10.0.2.2:8091", "t"))
        assertEquals("wss://example.com/pass/api/ws?access_token=t", LiveSyncProtocol.socketUrl("https://example.com/pass", "t"))
    }

    @Test
    fun backoffDoublesUpToAMinute() {
        assertEquals(listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 32_000L, 60_000L, 60_000L), (0..7).map { LiveSyncProtocol.backoffMillis(it) })
        assertEquals(1_200L, LiveSyncProtocol.backoffMillis(0, jitter = 1.0))
    }
}
