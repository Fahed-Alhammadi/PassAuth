package io.passauth.app.data

import io.passauth.app.ui.errorMessage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * Delta sync's pure parts (DeltaSync.kt): merging answers into the copy, applying this device's
 * own writes, the decisions on numbers, the request paths, the sync queue, and the client side of
 * the protocol against a scripted server. The same cases as the iOS `DeltaSyncTests`.
 */
class DeltaSyncTest {
    private val bundle = buildJsonObject { put("account_id", "acc"); put("secret_key_enabled", false) }
    private val bundleJson = """"bundle":{"account_id":"acc","secret_key_enabled":false},"user":{"name":"Alex"}"""

    private fun vault(id: String, seq: Long?, epoch: Long? = 0, wrapped: String? = null, meta: String = "m") =
        SyncVault(id, meta, "owner", wrapped ?: "w-$id", "account", null, epoch, seq)

    private fun item(id: String, vault: String, data: String = "d", revision: Long = 1, deletedAt: Long? = null) =
        SyncItem(id, vault, "k-$id", "$data-$id", revision, deletedAt)

    private fun snapshot(vaults: List<SyncVault>, items: List<SyncItem>, revision: Long = 10, cursor: String? = "c1") =
        SyncSnapshot(revision, cursor, buildJsonObject { put("name", "Alex") }, bundle, vaults, items)

    private fun answer(json: String): SyncResponse = DeltaSync.parse(json)!!

    private fun ids(s: SyncSnapshot) = s.items.map { "${it.vaultId}/${it.id}" }.sorted()

    private fun vaultJson(id: String, seq: Long, epoch: Long = 0, wrapped: String = "w-$id") =
        """{"id":"$id","meta":"m","role":"owner","wrapped_key":"$wrapped","key_kind":"account","key_epoch":$epoch,"seq":$seq}"""

    // ------------------------------------------------------------------ merge

    @Test
    fun fullAnswerReplacesTheCopy() {
        val base = snapshot(listOf(vault("A", 3)), listOf(item("1", "A"), item("2", "A")))
        val full = answer("""{"revision":12,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("B", 1)}],"items":[{"id":"9","vault_id":"B","item_key":"k","data":"d","revision":4,"deleted_at":null}]}""")
        val next = SyncMerge.apply(full, base)!!
        assertEquals(12L, next.revision)
        assertEquals("c2", next.cursor)
        assertEquals(listOf("B/9"), ids(next))
        assertEquals(SyncPosition(12, mapOf("B" to 1L)), next.position)
    }

    @Test
    fun deletedFirstThenUpsertedById() {
        val base = snapshot(listOf(vault("A", 3)), listOf(item("1", "A"), item("2", "A"), item("3", "A")))
        // 1 deleted for good, 2 changed, 4 new; 3 untouched.
        val delta = answer(
            """{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 6)}],
            "items":[{"id":"2","vault_id":"A","item_key":"k","data":"new","revision":5},{"id":"4","vault_id":"A","item_key":"k","data":"d4","revision":6}],
            "deleted":[{"id":"1","vault_id":"A"}],"reset":[]}""",
        )
        val next = SyncMerge.apply(delta, base)!!
        assertEquals(listOf("A/2", "A/3", "A/4"), ids(next))
        assertEquals("new", next.items.first { it.id == "2" }.data)
        assertEquals("untouched rows are kept", "d-3", next.items.first { it.id == "3" }.data)
        assertEquals("c2", next.cursor)
        assertEquals(11L, next.revision)
        assertEquals(6L, next.vaults.single().seq)
    }

    @Test
    fun itemMovedBetweenTwoReadableVaults() {
        val base = snapshot(listOf(vault("A", 3), vault("B", 7)), listOf(item("1", "A"), item("2", "B")))
        // 1 moved A → B: a tombstone in A and the row in B, in the same answer.
        val moved = answer(
            """{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 4)},${vaultJson("B", 8)}],
            "items":[{"id":"1","vault_id":"B","item_key":"kB","data":"dB","revision":9}],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}""",
        )
        val next = SyncMerge.apply(moved, base)!!
        assertEquals(listOf("B/1", "B/2"), ids(next))
        assertEquals(1, next.items.count { it.id == "1" })
        // A tombstone only removes the row from the vault it names: an item already in B stays.
        val stale = answer(
            """{"delta":true,"revision":12,"cursor":"c3",$bundleJson,"vaults":[${vaultJson("A", 4)},${vaultJson("B", 8)}],
            "items":[],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}""",
        )
        assertEquals(listOf("B/1", "B/2"), ids(SyncMerge.apply(stale, next)!!))
    }

    @Test
    fun resetVaultIsReplacedWholeAndItsKeyOpenedAgain() {
        val base = snapshot(listOf(vault("A", 3), vault("B", 7)), listOf(item("1", "A"), item("2", "A"), item("3", "B")))
        // The key of A was replaced: every item of A comes again (re-encrypted); 2 is gone from A.
        val delta = answer(
            """{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 9, epoch = 1, wrapped = "w-A2")},${vaultJson("B", 7)}],
            "items":[{"id":"1","vault_id":"A","item_key":"k2","data":"d2","revision":9}],"deleted":[],"reset":["A"]}""",
        )
        val next = SyncMerge.apply(delta, base)!!
        assertEquals(listOf("A/1", "B/3"), ids(next))
        assertEquals("k2", next.items.first { it.id == "1" }.itemKey)
        val a = next.vaults.first { it.id == "A" }
        assertEquals(1L, a.keyEpoch)
        assertFalse("a changed header opens the vault key again", a.sameKey(base.vaults[0]))
        assertTrue(next.vaults[1].sameKey(base.vaults[1]))
    }

    @Test
    fun vaultLostTakesItsItems() {
        val base = snapshot(listOf(vault("A", 3), vault("S", 5)), listOf(item("1", "A"), item("2", "S"), item("3", "S")))
        // Removed from the shared vault S: it is missing from `vaults`.
        val delta = answer("""{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 3)}],"items":[],"deleted":[],"reset":[]}""")
        val next = SyncMerge.apply(delta, base)!!
        assertEquals(listOf("A/1"), ids(next))
        assertEquals(listOf("A"), next.vaults.map { it.id })
    }

    @Test
    fun deltaNeedsTheCopyItWasAskedFor() {
        assertNull(SyncMerge.apply(answer("""{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[],"items":[],"deleted":[],"reset":[]}"""), null))
    }

    @Test
    fun invalidAnswersAreRefused() {
        val base = snapshot(listOf(vault("A", 3)), listOf(item("1", "A")))
        for (bad in listOf(
            """{"revision":"7",$bundleJson,"vaults":[],"items":[]}""",
            """{$bundleJson,"vaults":[],"items":[]}""",
            """{"revision":-1,$bundleJson,"vaults":[],"items":[]}""",
            """{"revision":7,$bundleJson,"items":[]}""",
            """{"revision":7,$bundleJson,"vaults":[]}""",
            // A live item without its key and data.
            """{"revision":7,$bundleJson,"vaults":[],"items":[{"id":"1","vault_id":"A"}]}""",
        )) {
            assertNull(bad, DeltaSync.parse(bad)?.let { SyncMerge.apply(it, base) })
        }
        assertNull(DeltaSync.parse("<html>"))
        // A trashed item without them is a `trash=summary` row.
        assertNotNull(SyncMerge.apply(answer("""{"revision":7,$bundleJson,"vaults":[],"items":[{"id":"1","vault_id":"A","revision":3,"deleted_at":1700000000}]}"""), null))
    }

    @Test
    fun copyRoundTripsAndReadsOlderCopies() {
        val s = snapshot(listOf(vault("A", 3)), listOf(item("1", "A", deletedAt = 1_700_000_000), SyncItem("2", "A", null, null, 2, 5)))
        assertEquals(s, SyncSnapshot.decode(s.encode()))
        // A copy stored before delta sync (a plain `/sync` answer): no cursor, no numbers.
        val old = """{"revision":4,$bundleJson,"vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account"}],"items":[{"id":"1","vault_id":"A","item_key":"k","data":"d","revision":1,"deleted_at":null}]}"""
        val copy = SyncSnapshot.decode(old)!!
        assertNull(copy.cursor)
        assertEquals(SyncPosition(4, null), copy.position)
        assertNull(SyncSnapshot.decode("garbage"))
    }

    // ---------------------------------------------------------- local changes

    @Test
    fun ownWritesApplyToTheCopy() {
        val base = snapshot(listOf(vault("A", 3)), listOf(item("1", "A"), item("2", "A")))
        val put = SyncMerge.applyLocal(LocalChange.Put(SyncItem("1", "A", "k9", "d9", 9)), "A", 4, base)!!
        assertEquals("d9", put.items.first { it.id == "1" }.data)
        assertEquals(4L, put.vaults.single().seq)
        assertEquals("the cursor stays: the next delta brings the row again", "c1", put.cursor)
        assertEquals(10L, put.revision)
        val created = SyncMerge.applyLocal(LocalChange.Put(SyncItem("3", "A", "k", "d", 1)), "A", 5, put)!!
        assertEquals(listOf("A/1", "A/2", "A/3"), ids(created))

        val trashed = SyncMerge.applyLocal(LocalChange.Trash("2", 1_700_000_000, 11, summary = false), "A", 6, created)!!
        assertEquals(1_700_000_000L, trashed.items.first { it.id == "2" }.deletedAt)
        assertNotNull(trashed.items.first { it.id == "2" }.data)
        val summary = SyncMerge.applyLocal(LocalChange.Trash("2", 1, 11, summary = true), "A", 6, created)!!
        assertNull("trash=summary keeps no data for trashed items", summary.items.first { it.id == "2" }.data)
        // Restoring needs the data: a summary row can't be restored locally.
        assertNull(SyncMerge.applyLocal(LocalChange.Restore("2", 12), "A", 7, summary))
        val restored = SyncMerge.applyLocal(LocalChange.Restore("2", 12), "A", 7, trashed)!!
        assertNull(restored.items.first { it.id == "2" }.deletedAt)
        val purged = SyncMerge.applyLocal(LocalChange.Purge("2"), "A", 8, restored)!!
        assertEquals(listOf("A/1", "A/3"), ids(purged))
        assertEquals(8L, purged.vaults.single().seq)
        // Not in the copy: sync instead.
        assertNull(SyncMerge.applyLocal(LocalChange.Purge("zz"), "A", 9, purged))
        assertNull(SyncMerge.applyLocal(LocalChange.Put(item("4", "X")), "X", 1, purged))
    }

    // -------------------------------------------------------------- decisions

    @Test
    fun afterWrite() {
        assertEquals(SyncDecision.AfterWrite.ApplyLocally, SyncDecision.afterWrite(4, 5))
        assertEquals("someone else wrote too", SyncDecision.AfterWrite.Sync, SyncDecision.afterWrite(4, 7))
        assertEquals("a retried create the copy already has", SyncDecision.AfterWrite.Nothing, SyncDecision.afterWrite(5, 5))
        assertEquals("numbers gone backwards: a restored server", SyncDecision.AfterWrite.Sync, SyncDecision.afterWrite(7, 5))
        assertEquals(SyncDecision.AfterWrite.Sync, SyncDecision.afterWrite(null, 5))
        assertEquals("older server", SyncDecision.AfterWrite.Sync, SyncDecision.afterWrite(4, null))
    }

    @Test
    fun revisionPoll() {
        val have = SyncPosition(10, mapOf("A" to 3L, "B" to 7L))
        assertFalse(SyncDecision.isStale(10, mapOf("A" to 3L, "B" to 7L), have))
        assertTrue("profile or bundle change", SyncDecision.isStale(11, mapOf("A" to 3L, "B" to 7L), have))
        assertTrue(SyncDecision.isStale(10, mapOf("A" to 4L, "B" to 7L), have))
        assertTrue("a vault shared with the account", SyncDecision.isStale(10, mapOf("A" to 3L, "B" to 7L, "C" to 1L), have))
        assertTrue("a vault gone", SyncDecision.isStale(10, mapOf("A" to 3L), have))
        assertTrue("a restored server", SyncDecision.isStale(10, mapOf("A" to 2L, "B" to 7L), have))
        // Older server or copy without numbers: a newer revision only, as before.
        assertTrue(SyncDecision.isStale(11, null, have))
        assertFalse(SyncDecision.isStale(10, null, have))
        assertFalse(SyncDecision.isStale(9, null, have))
        assertFalse(SyncDecision.isStale(10, mapOf("A" to 3L), SyncPosition(10, null)))
    }

    @Test
    fun liveMessages() {
        val have = SyncPosition(10, mapOf("A" to 3L, "B" to 7L))
        assertTrue(SyncDecision.onLiveSync(11, mapOf("A" to 4L), have))
        assertFalse("this device's own write, already applied", SyncDecision.onLiveSync(11, mapOf("A" to 3L), have))
        assertFalse("out of order: older numbers", SyncDecision.onLiveSync(12, mapOf("A" to 2L, "B" to 7L), have))
        assertTrue("a vault the copy doesn't have", SyncDecision.onLiveSync(11, mapOf("C" to 1L), have))
        assertTrue("profile or account change", SyncDecision.onLiveSync(11, emptyMap(), have))
        assertTrue("copy without numbers", SyncDecision.onLiveSync(11, mapOf("A" to 3L), SyncPosition(10, null)))
        assertTrue(SyncDecision.onLiveSync(11, null, have))
        assertFalse(SyncDecision.onLiveSync(10, null, have))
        assertFalse("locked: nothing to refresh", SyncDecision.onLiveSync(11, mapOf("A" to 9L), null))
        // Whoever wrote: the numbers decide (a session's other processes share its origin).
        assertEquals(LiveAction.Sync, LiveSyncProtocol.action(LiveMessage.Sync(11, mapOf("A" to 4L), "mine"), have))
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveMessage.Sync(11, mapOf("A" to 3L), "other"), have))
    }

    @Test
    fun paths() {
        assertEquals("/sync", DeltaSync.path(null, false))
        assertEquals("/sync?since=AQgAbc-_9", DeltaSync.path("AQgAbc-_9", false))
        assertEquals("/sync?since=AQ&trash=summary", DeltaSync.path("AQ", true))
        assertEquals("/sync?trash=summary", DeltaSync.path(null, true))
        assertEquals("a cursor can't add parameters", "/sync?since=a%26b%3Dc", DeltaSync.path("a&b=c", false))
        assertEquals(mapOf("A" to 3L, "B" to 4L), DeltaSync.vaultNumbers(JsonObject(mapOf("A" to JsonPrimitive(3), "B" to JsonPrimitive(4), "C" to JsonPrimitive("x")))))
        assertNull(DeltaSync.vaultNumbers(null))
    }

    // ----------------------------------------- the client against a scripted server

    /** Answers queued per path (exact, else the path without its query); every request recorded. */
    private class ScriptedServer {
        private val answers = mutableMapOf<String, ArrayDeque<String>>()
        val paths = mutableListOf<String>()

        fun answer(path: String, body: String) {
            answers.getOrPut(path) { ArrayDeque() }.addLast(body)
        }

        @Synchronized
        fun get(path: String): String {
            paths += path
            val queue = answers[path]?.takeIf { it.isNotEmpty() } ?: answers[path.substringBefore('?')]?.takeIf { it.isNotEmpty() }
            return queue?.removeFirst() ?: throw UserException("Can't reach your PassAuth server.")
        }
    }

    @Test
    fun fetchUsesTheCursorOnlyWithDeltaSync(): Unit = runBlocking {
        val base = snapshot(listOf(vault("A", 3)), listOf(item("1", "A")))
        val server = ScriptedServer()
        server.answer("/sync", """{"revision":11,"cursor":"c2",$bundleJson,"vaults":[],"items":[]}""")
        DeltaSync.fetch(base, delta = false, trashSummary = false) { server.get(it) }
        assertEquals("no delta sync on this server: everything, as before", listOf("/sync"), server.paths)

        server.answer(
            "/sync?since=c1&trash=summary",
            """{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 4)}],"items":[{"id":"2","vault_id":"A","item_key":"k","data":"d","revision":2}],"deleted":[],"reset":[]}""",
        )
        val next = DeltaSync.fetch(base, delta = true, trashSummary = true) { server.get(it) }
        assertEquals("/sync?since=c1&trash=summary", server.paths.last())
        assertEquals(listOf("A/1", "A/2"), ids(next))

        // An unreadable answer: an error, nothing to store (the caller keeps its copy and cursor).
        server.answer("/sync", "<html>proxy</html>")
        val e = assertThrows(UserException::class.java) { runBlocking { DeltaSync.fetch(base, delta = true, trashSummary = false) { server.get(it) } } }
        assertEquals("The server's answer couldn't be read.", e.message)
    }

    @Test
    fun cacheRefreshAsksForChangesOnly(): Unit = runBlocking {
        val cached = snapshot(listOf(vault("A", 3)), listOf(item("1", "A")))
        val server = ScriptedServer()
        // Current: only the revision poll.
        server.answer("/sync/revision", """{"revision":10,"vaults":{"A":3}}""")
        assertEquals(DeltaSync.CacheRefresh.Current, DeltaSync.refresh(cached, delta = true, trashSummary = true) { server.get(it) })
        assertEquals(listOf("/sync/revision"), server.paths)

        // A vault moved on: the changes since the cursor, merged; nothing decrypted.
        server.answer("/sync/revision", """{"revision":11,"vaults":{"A":4}}""")
        server.answer(
            "/sync",
            """{"delta":true,"revision":11,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 4)}],"items":[{"id":"2","vault_id":"A","item_key":"k","data":"d","revision":2}],"deleted":[{"id":"1","vault_id":"A"}],"reset":[]}""",
        )
        val next = (DeltaSync.refresh(cached, delta = true, trashSummary = true) { server.get(it) } as DeltaSync.CacheRefresh.Write).snapshot
        assertEquals(listOf("/sync/revision", "/sync?since=c1&trash=summary"), server.paths.takeLast(2))
        assertEquals(listOf("A/2"), ids(next))
        assertEquals("c2", next.cursor)

        // Without delta sync: the whole answer, never older than the copy.
        server.answer("/sync", """{"revision":12,"cursor":"c3",$bundleJson,"vaults":[],"items":[]}""")
        assertEquals(12L, (DeltaSync.refresh(cached, delta = false, trashSummary = true) { server.get(it) } as DeltaSync.CacheRefresh.Write).snapshot.revision)
        server.answer("/sync", """{"revision":9,$bundleJson,"vaults":[],"items":[]}""")
        assertEquals("never downgrade", DeltaSync.CacheRefresh.Keep, DeltaSync.refresh(cached, delta = false, trashSummary = true) { server.get(it) })
        // No copy yet: everything.
        server.answer("/sync", """{"revision":1,$bundleJson,"vaults":[],"items":[]}""")
        assertTrue(DeltaSync.refresh(null, delta = true, trashSummary = true) { server.get(it) } is DeltaSync.CacheRefresh.Write)
        assertEquals("/sync?trash=summary", server.paths.last())
        // Offline: the error ends the refresh.
        assertThrows(UserException::class.java) { runBlocking { DeltaSync.refresh(cached, delta = true, trashSummary = true) { server.get(it) } } }
    }

    /**
     * The repository's sequence against one server: everything first, then only changes from the
     * stored cursor; this device's write at the vault's next number applied without a request;
     * someone else's write in between → a delta from the unchanged cursor; polls and live messages
     * decide by the numbers.
     */
    @Test
    fun clientSequenceAgainstAServerWithDeltaSync(): Unit = runBlocking {
        val server = ScriptedServer()
        server.answer("/sync", """{"revision":5,"cursor":"c1",$bundleJson,"vaults":[${vaultJson("A", 3)}],"items":[{"id":"1","vault_id":"A","item_key":"k","data":"d","revision":3}]}""")
        var copy = DeltaSync.fetch(null, delta = true, trashSummary = true) { server.get(it) }
        assertEquals("/sync?trash=summary", server.paths.last())

        // Own create answered with the vault's next number: applied, no request.
        val answer = obj("""{"id":"2","revision":9,"vault_seq":4}""")
        val seq = (answer["vault_seq"] as JsonPrimitive).content.toLong()
        assertEquals(SyncDecision.AfterWrite.ApplyLocally, SyncDecision.afterWrite(copy.position.vaults!!["A"], seq))
        assertEquals(9L, ItemWrites.revision(answer))
        copy = SyncMerge.applyLocal(LocalChange.Put(SyncItem("2", "A", "k2", "d2", 9)), "A", 4, copy)!!
        assertEquals(1, server.paths.size)
        // Its live message: nothing to do. Another device's: sync.
        assertEquals(LiveAction.Ignore, LiveSyncProtocol.action(LiveSyncProtocol.parse("""{"type":"sync","revision":6,"vaults":{"A":4},"origin":"me"}"""), copy.position))
        assertEquals(LiveAction.Sync, LiveSyncProtocol.action(LiveSyncProtocol.parse("""{"type":"sync","revision":7,"vaults":{"A":5}}"""), copy.position))

        // Someone else wrote 5; our edit is 6: sync from the cursor the copy still has.
        assertEquals(SyncDecision.AfterWrite.Sync, SyncDecision.afterWrite(copy.position.vaults!!["A"], 6))
        server.answer(
            "/sync",
            """{"delta":true,"revision":8,"cursor":"c2",$bundleJson,"vaults":[${vaultJson("A", 6)}],"items":[{"id":"2","vault_id":"A","item_key":"k2b","data":"d2b","revision":10},{"id":"3","vault_id":"A","item_key":"k","data":"d","revision":5}],"deleted":[],"reset":[]}""",
        )
        copy = DeltaSync.fetch(copy, delta = true, trashSummary = true) { server.get(it) }
        assertEquals("/sync?since=c1&trash=summary", server.paths.last())
        assertEquals(listOf("A/1", "A/2", "A/3"), ids(copy))
        assertEquals(SyncPosition(8, mapOf("A" to 6L)), copy.position)
        // The stored copy keeps cursor and items together.
        assertEquals(copy, SyncSnapshot.decode(copy.encode()))
        // Poll: current → nothing; behind → stale.
        assertFalse(SyncDecision.isStale(8, mapOf("A" to 6L), copy.position))
        assertTrue(SyncDecision.isStale(9, mapOf("A" to 7L), copy.position))
    }

    private fun obj(text: String) = AppJson.parseToJsonElement(text) as JsonObject

    // -------------------------------------------------------------- sync queue

    @Test
    fun oneSyncRunsAndOneWaits(): Unit = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val queue = SyncQueue(scope)
            val runs = AtomicInteger()
            val gate = CompletableDeferred<Unit>()
            val started = CompletableDeferred<Unit>()
            val first = async(Dispatchers.Default) {
                queue.run {
                    runs.incrementAndGet()
                    started.complete(Unit)
                    gate.await()
                }
            }
            started.await()
            // Three requests while the first runs: one more sync, which all three wait for.
            val waiting = (0 until 3).map { async(Dispatchers.Default) { queue.run { runs.incrementAndGet() } } }
            delay(100)
            assertEquals(1, runs.get())
            gate.complete(Unit)
            first.await()
            waiting.awaitAll()
            assertEquals(2, runs.get())
            // Idle again: the next request runs at once.
            queue.run { runs.incrementAndGet() }
            assertEquals(3, runs.get())
            // An error reaches the waiters, and the queue keeps working.
            assertThrows(IllegalStateException::class.java) { runBlocking { queue.run { error("offline") } } }
            queue.run { runs.incrementAndGet() }
            assertEquals(4, runs.get())
        } finally {
            scope.cancel()
        }
    }

    // ------------------------------------------------------------------ quotas

    @Test
    fun storageUsageAndQuotaMessage() {
        val u = AccountUsage.parse(obj("""{"usage":{"item_count":120,"storage_bytes":1258291},"limits":{"max_items":500,"max_storage_bytes":52428800}}"""))
        assertTrue(u.limited)
        assertEquals("120 of 500 items", u.itemsLine)
        assertEquals("1.2 MB of 50 MB", u.storageLine)
        assertEquals(0.24f, u.itemsUsed!!, 0.0001f)
        assertFalse(u.full)
        assertFalse("no limit: nothing shown", AccountUsage.parse(obj("""{"usage":{"item_count":3,"storage_bytes":10},"limits":{"max_items":0,"max_storage_bytes":0}}""")).limited)
        assertFalse("older servers", AccountUsage.parse(obj("""{"email":"a@example.com"}""")).limited)
        val full = AccountUsage.parse(obj("""{"usage":{"item_count":10,"storage_bytes":0},"limits":{"max_items":10,"max_storage_bytes":0}}"""))
        assertTrue(full.full)
        assertNull(full.storageLine)
        assertEquals("0 bytes", AccountUsage.bytes(0))
        assertEquals("1.5 KB", AccountUsage.bytes(1536))
        assertEquals("1 MB", AccountUsage.bytes(1_048_576))
        assertEquals("30 MB", AccountUsage.bytes(10_485_760L * 3))
        assertEquals("2 GB", AccountUsage.bytes(1_073_741_824L * 2))

        val quota = ApiException(403, "quota_exceeded", "storage limit reached")
        assertEquals("You've reached this server's storage limit. Delete items or ask the server's admin.", errorMessage(quota))
        assertEquals(QUOTA_EXCEEDED_MESSAGE, errorMessage(quota))
    }
}
