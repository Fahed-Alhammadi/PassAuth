package io.passauth.app

import io.passauth.app.data.LiveAction
import io.passauth.app.data.LiveMessage
import io.passauth.app.data.LiveSyncProtocol
import io.passauth.app.data.SyncPosition
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Messages of the server's /api/ws (crates/server/src/state.rs notify_sync / notify_logout). */
class LiveSyncProtocolTest {
    @Test
    fun parsesServerMessages() {
        assertEquals(LiveMessage.Sync(1767366245123), LiveSyncProtocol.parse("""{"type":"sync","revision":1767366245123}"""))
        assertEquals(LiveMessage.Logout, LiveSyncProtocol.parse("""{"type":"logout"}"""))
    }

    @Test
    fun parsesHelloAndVaultNumbers() {
        assertEquals(LiveMessage.Hello("o-1"), LiveSyncProtocol.parse("""{"type":"hello","origin":"o-1"}"""))
        assertEquals(LiveMessage.Sync(7, mapOf("A" to 3L), "o-1"), LiveSyncProtocol.parse("""{"type":"sync","revision":7,"vaults":{"A":3},"origin":"o-1"}"""))
        assertEquals(LiveMessage.Sync(8, emptyMap(), null), LiveSyncProtocol.parse("""{"type":"sync","revision":8,"vaults":{}}"""))
    }

    /** Sign in with another device (crates/server/src/ws.rs `auth_request_message`). */
    @Test
    fun signInRequests() {
        assertEquals(LiveMessage.AuthRequest("r-1"), LiveSyncProtocol.parse("""{"type":"auth_request","id":"r-1"}"""))
        assertEquals(LiveMessage.AuthRequestAnswered("r-1"), LiveSyncProtocol.parse("""{"type":"auth_request_answered","id":"r-1"}"""))
        assertNull(LiveSyncProtocol.parse("""{"type":"auth_request"}"""))
        assertNull(LiveSyncProtocol.parse("""{"type":"auth_request_answered","id":""}"""))
        assertEquals(LiveAction.ListAuthRequests, LiveSyncProtocol.action(LiveMessage.AuthRequest("r-1"), null))
        assertEquals(LiveAction.AuthRequestAnswered, LiveSyncProtocol.action(LiveMessage.AuthRequestAnswered("r-1"), SyncPosition(1, null)))
    }

    /** The admin turned on the two-step policy (crates/server/src/ws.rs): the gate, and no reconnecting. */
    @Test
    fun twoStepRequiredStopsLiveSync() {
        assertEquals(LiveMessage.TwoStepRequired, LiveSyncProtocol.parse("""{"type":"two_step_required"}"""))
        assertEquals(LiveAction.TwoStepRequired, LiveSyncProtocol.action(LiveMessage.TwoStepRequired, SyncPosition(1, null)))
        assertEquals(LiveAction.TwoStepRequired, LiveSyncProtocol.action(LiveMessage.TwoStepRequired, null))
        assertTrue(LiveSyncProtocol.closedForTwoStep(1008, "two_step_required"))
        assertFalse(LiveSyncProtocol.closedForTwoStep(1008, "policy"))
        assertFalse(LiveSyncProtocol.closedForTwoStep(1000, "two_step_required"))
        assertFalse(LiveSyncProtocol.closedForTwoStep(1001, null))
    }

    @Test
    fun ignoresUnknownOrBrokenMessages() {
        assertNull(LiveSyncProtocol.parse("""{"type":"hello"}""")) // no origin
        assertNull(LiveSyncProtocol.parse("""{"type":"sync"}"""))
        assertNull(LiveSyncProtocol.parse("""{"type":"sync","revision":"soon"}"""))
        assertNull(LiveSyncProtocol.parse("not json"))
        assertNull(LiveSyncProtocol.parse("[]"))
    }

    /** Older servers (no vault numbers in the message): a newer revision syncs. With numbers: DeltaSyncTest.liveMessages. */
    @Test
    fun syncsOnlyForNewerRevisions() {
        val have = SyncPosition(10, null)
        assertEquals(LiveAction.Sync, LiveSyncProtocol.action(LiveMessage.Sync(11), have))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(10), have)) // our own save, already synced
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(9), have))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(11), null)) // locked: nothing to refresh
        assertEquals(LiveAction.CheckSession, LiveSyncProtocol.action(LiveMessage.Logout, have))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Hello("o"), have))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(null, have))
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
