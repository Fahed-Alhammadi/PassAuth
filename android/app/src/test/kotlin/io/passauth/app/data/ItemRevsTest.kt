package io.passauth.app.data

import io.passauth.core.itemRevCheck
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Item rollback detection ([ItemRevs]) with the core's `itemRevCheck`. */
class ItemRevsTest {
    private val check = { r: Long?, served: Long -> itemRevCheck(r?.toULong(), served.toULong()) }

    @Test
    fun judgesWhatTheServerSentAgainstWhatThisPhoneSaw() {
        assertEquals(ItemRevs.Verdict.Accept(3), ItemRevs.judge(null, 3, null, check))
        assertEquals(ItemRevs.Verdict.Accept(4), ItemRevs.judge(3, 4, null, check))
        // Equal rev, other content: an edit by an app from before; accepted, nothing new remembered.
        assertEquals(ItemRevs.Verdict.Accept(null), ItemRevs.judge(3, 3, null, check))
        // Older than remembered: flagged; the copy this phone had is kept only when it is newer than the one served.
        assertEquals(ItemRevs.Verdict.Rollback(keepPrior = false), ItemRevs.judge(3, 2, null, check))
        assertEquals(ItemRevs.Verdict.Rollback(keepPrior = true), ItemRevs.judge(3, 2, 3, check))
        assertEquals(ItemRevs.Verdict.Rollback(keepPrior = false), ItemRevs.judge(3, 2, 2, check))
        // Nothing remembered (a copy from before this version) but a newer copy on the phone: still a rollback.
        assertEquals(ItemRevs.Verdict.Rollback(keepPrior = true), ItemRevs.judge(null, 1, 4, check))
        // An older held version doesn't flag a newer one served.
        assertEquals(ItemRevs.Verdict.Accept(5), ItemRevs.judge(null, 5, 4, check))
    }

    @Test
    fun remembersOnlyUpwardsAndForgetsItemsGone() {
        val m = mapOf("a" to 3L, "b" to 7L, "gone" to 2L)
        assertEquals(mapOf("a" to 4L, "b" to 7L, "gone" to 2L, "c" to 1L), ItemRevs.merged(m, mapOf("a" to 4L, "b" to 5L, "c" to 1L), null))
        assertEquals(mapOf("a" to 3L, "b" to 7L), ItemRevs.merged(m, emptyMap(), setOf("a", "b")))
        assertEquals(m, ItemRevs.decode(ItemRevs.encode(m)))
        assertEquals(mapOf("ok" to 1L), ItemRevs.decode("""{"ok":1,"s":"2","neg":-1,"f":1.5}"""))
        assertEquals(emptyMap<String, Long>(), ItemRevs.decode("not json"))
        assertEquals(emptyMap<String, Long>(), ItemRevs.decode(null))
    }

    @Test
    fun noticesSayWhatHappened() {
        assertNull(ItemRevs.notice(emptySet(), false))
        assertEquals("Your server sent older versions of some items.", ItemRevs.notice(setOf("a"), false))
        assertEquals("Your server sent older versions of some items. PassAuth kept the newer copies it had.", ItemRevs.notice(setOf("a"), true))
        assertEquals("Your server sent an older version of this item.", ItemRevs.ITEM_WARNING)
    }

    private fun row(id: String, data: String?, deleted: Long? = null) = SyncItem(id, "v", if (data == null) null else "k-$data", data, 1, deleted)

    @Test
    fun aLockedRefreshHoldsTheVersionsItReplaces() {
        val cached = SyncSnapshot(1, items = listOf(row("a", "a1"), row("b", "b1"), row("gone", "g1")))
        val next = SyncSnapshot(2, items = listOf(row("a", "a2"), row("b", "b1"), row("new", "n1")))
        val held = ItemRevs.withHeld(next, cached)
        assertEquals(listOf(row("a", "a1")), held.held)
        // A second refresh: the version held first (last checked) stays, the latest replaced is added; at most two per item.
        val third = ItemRevs.withHeld(SyncSnapshot(3, items = listOf(row("a", "a3"), row("b", "b1"))), held)
        assertEquals(setOf("a1", "a2"), third.held.map { it.data }.toSet())
        val fourth = ItemRevs.withHeld(SyncSnapshot(4, items = listOf(row("a", "a4"))), third)
        assertEquals(setOf("a1", "a3"), fourth.held.map { it.data }.toSet())
        // Back to a held version: not held twice; an item gone drops its versions.
        assertEquals(listOf("a4"), ItemRevs.withHeld(SyncSnapshot(5, items = listOf(row("a", "a1"))), fourth).held.map { it.data })
        assertTrue(ItemRevs.withHeld(SyncSnapshot(5, items = emptyList()), fourth).held.isEmpty())
    }

    @Test
    fun heldVersionsSurviveTheStoredCopyAndNeverComeFromAServer() {
        val s = SyncSnapshot(1, bundle = kotlinx.serialization.json.JsonObject(emptyMap()), items = listOf(row("a", "a2")), held = listOf(row("a", "a1")))
        assertEquals(listOf(row("a", "a1")), SyncSnapshot.decode(s.encode())!!.held)
        val answer = """{"revision":1,"vaults":[],"items":[],"held":[{"id":"a","vault_id":"v","item_key":"k","data":"d"}]}"""
        assertTrue(SyncMerge.apply(DeltaSync.parse(answer)!!, null)!!.held.isEmpty())
        val kept = ItemRevs.keepRows(s, mapOf("a" to row("a", "a1")))
        assertEquals(listOf(row("a", "a1")), kept.items)
    }
}
