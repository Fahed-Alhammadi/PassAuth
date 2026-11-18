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
    fun remembersOnlyUpwardsAndForgetsOnlyWhatIsGoneForCertain() {
        val m = mapOf("a" to 3L, "b" to 7L, "gone" to 2L)
        assertEquals(mapOf("a" to 4L, "b" to 7L, "gone" to 2L, "c" to 1L), ItemRevs.merged(m, mapOf("a" to 4L, "b" to 5L, "c" to 1L)))
        // An item missing from the copy stays remembered; only one named as gone for certain is dropped.
        assertEquals(m, ItemRevs.merged(m, emptyMap(), present = setOf("a", "b")))
        assertEquals(mapOf("a" to 3L, "b" to 7L), ItemRevs.merged(m, emptyMap(), forget = setOf("gone")))
        assertEquals(m, ItemRevs.decode(ItemRevs.encode(m)))
        assertEquals(mapOf("ok" to 1L), ItemRevs.decode("""{"ok":1,"s":"2","neg":-1,"f":1.5}"""))
        assertEquals(emptyMap<String, Long>(), ItemRevs.decode("not json"))
        assertEquals(emptyMap<String, Long>(), ItemRevs.decode(null))
        // A counter near the top of what clients count with is kept as it is.
        assertEquals(mapOf("big" to 9_007_199_254_740_990L), ItemRevs.decode(ItemRevs.encode(ItemRevs.merged(emptyMap(), mapOf("big" to 9_007_199_254_740_990L)))))
    }

    /** Review L7 (R8): hiding an item (or its vault) for one sync must not make this phone forget it. */
    @Test
    fun anItemIsForgottenOnlyWhenAPassingManifestSaysItIsGone() {
        fun vault(id: String) = SyncVault(id)
        fun item(id: String, vault: String) = SyncItem(id, vault, "k", "d-$id", 1)
        val before = SyncSnapshot(1, vaults = listOf(vault("m"), vault("plain"), vault("warned"), vault("left")), items = listOf(item("a", "m"), item("b", "m"), item("p", "plain"), item("w", "warned"), item("l", "left"), item("moved", "m")))
        // Now: "a", "p", "w" are missing; "moved" is in another vault; the vault "left" is gone altogether.
        val after = SyncSnapshot(2, vaults = listOf(vault("m"), vault("plain"), vault("warned")), items = listOf(item("b", "m"), item("moved", "plain")))
        val states = mapOf("m" to ManifestState.Ok, "plain" to ManifestState.None, "warned" to ManifestState.Unresolved)
        // Only the item absent from the vault whose manifest passed for this very answer.
        assertEquals(setOf("a"), ItemRevs.gone(before, after, states))
        assertEquals(emptySet<String>(), ItemRevs.gone(before, after, states + ("m" to ManifestState.Unchecked)))
        assertEquals(emptySet<String>(), ItemRevs.gone(null, after, states))
        // The server hides "p" (a vault without a manifest) for one sync and then serves an old version: still a rollback.
        val memory = mapOf("a" to 5L, "p" to 5L, "w" to 5L, "l" to 5L)
        val kept = ItemRevs.merged(memory, emptyMap(), ItemRevs.gone(before, after, states), after.items.map { it.id }.toSet())
        assertEquals(setOf("p", "w", "l"), kept.keys)
        assertEquals(ItemRevs.Verdict.Rollback(keepPrior = false), ItemRevs.judge(kept["p"], 3, null, check))
        // This phone's own purge is certain too.
        assertEquals(setOf("w", "l"), ItemRevs.merged(kept, emptyMap(), forget = setOf("p")).keys)
    }

    @Test
    fun theMemoryIsCappedAtTheItemsSeenLast() {
        val many = (1..ItemRevs.MAX_REMEMBERED).associate { "i$it" to 1L }
        // Two more than fit: the ones seen longest ago go, those not in the copy first.
        val next = ItemRevs.merged(many, mapOf("new1" to 1L, "new2" to 1L), present = setOf("i1", "i2", "new1", "new2"))
        assertEquals(ItemRevs.MAX_REMEMBERED, next.size)
        assertTrue("i1" in next && "i2" in next && "new1" in next && "new2" in next)
        assertTrue("i3" !in next && "i4" !in next && "i5" in next)
        // An item seen again (a newer counter) counts as seen last.
        val bumped = ItemRevs.merged(many, mapOf("i1" to 2L, "new" to 1L))
        assertTrue("i1" in bumped && "i2" !in bumped)
        assertEquals(2L, bumped["i1"])
        // Kept in that order through the stored text.
        assertEquals(bumped.keys.toList(), ItemRevs.decode(ItemRevs.encode(bumped)).keys.toList())
    }

    @Test
    fun aKeptNewerCopyWaitsWhileItsItemIsMissingWithoutThatBeingCertain() {
        val keptRow = SyncItem("a", "v", "k-new", "newer", 4, servedSha256 = "served")
        val before = SyncSnapshot(1, vaults = listOf(SyncVault("v")), items = listOf(keptRow, SyncItem("b", "v", "k", "b1", 1)))
        // The server stops sending "a" (no manifest says it is gone): the newer copy waits, unseen.
        val after = SyncSnapshot(2, vaults = listOf(SyncVault("v")), items = listOf(SyncItem("b", "v", "k", "b1", 1)))
        val waiting = ItemRevs.waiting(before, after, emptySet())
        assertEquals(listOf("newer"), waiting.map { it.data })
        assertNull("it is no longer a row standing in for a served one", waiting[0].servedSha256)
        // It stays through further syncs, in the stored copy…
        val stored = SyncSnapshot.decode(after.copy(bundle = kotlinx.serialization.json.JsonObject(emptyMap()), held = waiting).encode())!!
        assertEquals(listOf("newer"), ItemRevs.waiting(stored, after, emptySet()).map { it.data })
        // …until the item comes back (the old version served then finds the newer copy to compare with)…
        val back = after.copy(items = after.items + SyncItem("a", "v", "k-old", "older", 5))
        assertTrue(ItemRevs.waiting(stored, back, emptySet()).isEmpty())
        // …or it is gone for certain.
        assertTrue(ItemRevs.waiting(stored, after, setOf("a")).isEmpty())
        assertTrue(ItemRevs.waiting(null, after, emptySet()).isEmpty())
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
    fun heldVersionsSurviveTheStoredCopyAndNeverComeFromAServer() {
        val s = SyncSnapshot(1, bundle = kotlinx.serialization.json.JsonObject(emptyMap()), items = listOf(row("a", "a2")), held = listOf(row("a", "a1")))
        assertEquals(listOf(row("a", "a1")), SyncSnapshot.decode(s.encode())!!.held)
        val answer = """{"revision":1,"vaults":[],"items":[],"held":[{"id":"a","vault_id":"v","item_key":"k","data":"d"}]}"""
        assertTrue(SyncMerge.apply(DeltaSync.parse(answer)!!, null)!!.held.isEmpty())
        val kept = ItemRevs.keepRows(s, mapOf("a" to row("a", "a1")))
        assertEquals(listOf(row("a", "a1")), kept.items)
    }
}
