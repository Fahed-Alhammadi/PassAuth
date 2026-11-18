package io.passauth.app.data

import io.passauth.core.Account
import io.passauth.core.VaultKey
import io.passauth.core.accountFromSessionBytes
import io.passauth.core.manifestDataHash
import java.io.File
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Vault manifests ([Manifests], [ItemWrites], [SyncMerge]) with the real core (the host build) and
 * a small stand-in for the server that keeps the rules of `crates/server/src/vault/manifest.rs`:
 * a vault with a manifest takes a write only with the next version that names the current one
 * (the hash chain), stores it opaque and lists it in the vault's manifest log.
 */
class ManifestsTest {
    private companion object {
        /** The link a first manifest names: 32 zero bytes. */
        const val ZERO = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }

    private val fixture: JsonObject by lazy {
        val file = generateSequence(File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
            .map { File(it, "testdata/vectors.json") }.firstOrNull { it.isFile }
        Json.parseToJsonElement(requireNotNull(file) { "testdata/vectors.json not found" }.readText()).jsonObject["vaultManifest"]!!.jsonObject
    }
    private val vaultId: String get() = fixture["vaultId"]!!.jsonPrimitive.content
    private val epoch: Long get() = fixture["keyEpoch"]!!.jsonPrimitive.long

    private fun account(): Account =
        accountFromSessionBytes(fixture["accountId"]!!.jsonPrimitive.content, java.util.Base64.getUrlDecoder().decode(fixture["sessionBytes"]!!.jsonPrimitive.content))

    private fun key(): VaultKey = account().openVaultKey(vaultId, fixture["wrappedKey"]!!.jsonPrimitive.content, "account", epoch.toULong(), false)

    private fun row(id: String, data: String?, deleted: Long? = null, vault: String = vaultId, revision: Long = 1, sha: String? = null) =
        SyncItem(id, vault, if (data == null) null else "k-$id", data, revision, deleted, dataSha256 = sha)

    private fun digest(sealed: String) = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(sealed.toByteArray()))

    /**
     * What the server keeps of one vault, with its rules for writes: a manifest must be the next
     * version and name the vault's current one (its link) as the one it replaces; every stored
     * manifest goes into the vault's log.
     */
    private inner class Server(val key: VaultKey, val vault: String = vaultId, var epoch: Long = this@ManifestsTest.epoch) {
        var rows = listOf<SyncItem>()
        var seq = 0L
        var manifestSeq = 0L
        var manifest: String? = null
        var manifestPrev: String? = null
        var log = listOf<JsonObject>()
        var requests = 0
        var logRequests = 0

        fun header(ok: Boolean = true) = SyncVault(
            vault, role = "owner", keyKind = "account", keyEpoch = epoch, seq = seq,
            manifest = manifest, manifestSeq = manifestSeq, manifestPrev = manifestPrev, manifestOk = ok,
        )
        fun snapshot() = SyncSnapshot(seq, vaults = listOf(header()), items = rows)

        /** The link of the vault's current manifest (32 zero bytes while it has none). */
        fun link(): String = Manifests.linkOf(header()) ?: ZERO
        fun mark() = ManifestMark(manifestSeq, link())

        /** The same state under another name: what a server that forks the vault's history shows someone else. */
        fun fork() = Server(key, vault, epoch).also {
            it.rows = rows; it.seq = seq; it.manifestSeq = manifestSeq; it.manifest = manifest; it.manifestPrev = manifestPrev; it.log = log
        }

        private fun store(m: ManifestEntry) {
            manifest = m.sealed
            manifestSeq = m.seq
            manifestPrev = m.prev
            log = log + buildJsonObject { put("seq", m.seq); put("prev", m.prev); put("digest", digest(m.sealed)) }
        }

        /** Any write into the vault: the manifest sent must be the next one and name the current one (or none for a vault without). */
        fun write(sent: List<ManifestEntry>, change: (List<SyncItem>) -> List<SyncItem>): JsonObject {
            requests++
            val m = sent.firstOrNull { it.vaultId == vault }
            if (manifestSeq > 0 && m == null) throw ApiException(400, "manifest_required", "Update PassAuth to change this vault.")
            if (m != null && m.seq != manifestSeq + 1) throw ApiException(409, "manifest_conflict", "the vault changed")
            if (m != null && manifestSeq == 0L) throw ApiException(409, "manifest_conflict", "the vault has no manifest")
            if (m != null && !Manifests.isLink(m.prev)) throw ApiException(400, "bad_request", "prev is no link")
            if (m != null && m.prev != link()) throw ApiException(409, "manifest_conflict", "built on another manifest")
            rows = change(rows)
            seq++
            if (m != null) store(m)
            return buildJsonObject { put("revision", 9); put("vault_seq", seq); put("manifest_seq", manifestSeq) }
        }

        /** `PUT /vaults/{id}/manifest`. */
        fun putManifest(body: JsonObject): JsonObject {
            val to = body["seq"]!!.jsonPrimitive.long
            if (body["base_seq"]!!.jsonPrimitive.long != manifestSeq || body["vault_seq"]!!.jsonPrimitive.long != seq) throw ApiException(409, "manifest_conflict", "x")
            if (body["prev"]!!.jsonPrimitive.content != link()) throw ApiException(409, "manifest_conflict", "built on another manifest")
            if (to <= manifestSeq || to > manifestSeq + 1_000_000) throw ApiException(400, "bad_request", "seq")
            store(ManifestEntry(vault, to, body["prev"]!!.jsonPrimitive.content, body["sealed"]!!.jsonPrimitive.content, ""))
            seq++
            return buildJsonObject { put("vault_seq", seq); put("manifest_seq", manifestSeq) }
        }

        /** `GET /vaults/{id}/manifest-log?after=`: oldest first, [page] entries an answer. */
        fun logPage(after: Long, page: Int = 2000): JsonObject {
            logRequests++
            val rest = log.filter { it["seq"]!!.jsonPrimitive.long > after }
            return buildJsonObject {
                put("entries", kotlinx.serialization.json.JsonArray(rest.take(page)))
                put("more", rest.size > page)
            }
        }

        /** The log as the app asks for it ([Manifests.fetchLog]). */
        fun logSource(page: Int = 2000): suspend (String, Long) -> String? = { _, after -> Manifests.fetchLog(after) { from -> logPage(from, page) } }

        /** Another device's write (the same rules, straight from the server's state). */
        fun otherDevice(removed: List<SyncItem>, added: List<SyncItem>) {
            val m = Manifests.next(key, header(), ManifestState.Ok, removed, added)
            write(listOfNotNull(m)) { r -> r.filter { old -> removed.none { it.id == old.id } } + added }
        }

        fun status(remembered: ManifestMark? = null) = Manifests.verify(key, header(), remembered, rows).status

        /** What a phone that remembers [memory] makes of this server's whole answer (asking for the log when it has to). */
        fun judged(memory: ManifestMark?, whole: Boolean = true, log: (suspend (String, Long) -> String?)? = logSource()) = runBlocking {
            Manifests.judge(listOf(header()), rows, mapOf(vault to key), listOfNotNull(memory?.let { vault to it }).toMap(), whole, log = log)
        }
    }

    /** A vault with three items (one in the trash) and its first manifest. */
    private fun started(): Server {
        val s = Server(key())
        s.rows = listOf(row("a", "data-a"), row("b", "data-b"), row("c", "data-c", deleted = 100))
        s.seq = 5
        val (body, entry) = Manifests.startBody(s.key, s.header(), 1, s.rows)!!
        assertEquals(0L, body["base_seq"]!!.jsonPrimitive.long)
        assertEquals(1L, body["seq"]!!.jsonPrimitive.long)
        assertEquals(5L, body["vault_seq"]!!.jsonPrimitive.long)
        assertEquals(entry.sealed, body["sealed"]!!.jsonPrimitive.content)
        assertEquals("a first manifest replaces none", ZERO, body["prev"]!!.jsonPrimitive.content)
        s.putManifest(body)
        assertEquals("ok", s.status())
        assertEquals("the link the builder gave is the stored manifest's", entry.link, s.link())
        return s
    }

    private fun judge(vaults: List<SyncVault>, items: List<SyncItem>, keys: Map<String, VaultKey>, memory: Map<String, ManifestMark>, whole: Boolean = false, hidden: Set<String> = emptySet()) =
        runBlocking { Manifests.judge(vaults, items, keys, memory, whole, hidden) }

    // ------------------------------------------------------------- rows

    @Test
    fun rowsCarryTheDataTheServerHoldsOrItsHash() {
        val live = Manifests.row(row("a", "data-a"))
        assertEquals("data-a", live["data"]!!.jsonPrimitive.content)
        assertNull(live["data_sha256"])
        assertEquals(kotlinx.serialization.json.JsonNull, live["deleted_at"])
        // A trashed row of a summary answer: no data, the server's hash.
        val summary = Manifests.row(row("c", null, deleted = 7, sha = "h"))
        assertNull(summary["data"])
        assertEquals("h", summary["data_sha256"]!!.jsonPrimitive.content)
        assertEquals(7L, summary["deleted_at"]!!.jsonPrimitive.long)
        // A newer copy kept in place of the version served: the hash of what the server holds, never the kept data.
        val kept = Manifests.row(row("a", "newer").copy(servedSha256 = "served"))
        assertNull(kept["data"])
        assertEquals("served", kept["data_sha256"]!!.jsonPrimitive.content)
        // With data, a hash next to it is ignored (the data is hashed).
        assertNull(Manifests.row(row("a", "data-a", sha = "lie"))["data_sha256"])
        assertTrue(Manifests.countable(row("a", "d")) && Manifests.countable(row("c", null, 1, sha = "h")))
        assertFalse(Manifests.countable(row("c", null, 1)))
        assertEquals(manifestDataHash("data-a"), Manifests.serverHash(row("a", "data-a")))
        assertEquals("served", Manifests.serverHash(row("a", "newer").copy(servedSha256 = "served")))
        assertEquals("h", Manifests.serverHash(row("c", null, 1, sha = "h")))
    }

    @Test
    fun aServerAnswerNeverNamesTheHashOfARowButTheStoredCopyKeepsIt() {
        val answer = DeltaSync.parse(
            """{"revision":3,"cursor":"c","server_time":1000,"trash_days":30,"vaults":[{"id":"v","manifest":"m","manifest_seq":4,"manifest_prev":"p","manifest_ok":true}],
               "items":[{"id":"a","vault_id":"v","item_key":"k","data":"d","served_sha256":"planted"},
                        {"id":"t","vault_id":"v","deleted_at":5,"data_sha256":"h"}]}""",
        )!!
        val snap = SyncMerge.apply(answer, null)!!
        assertNull("a server can't plant the hash a row is counted with", snap.items[0].servedSha256)
        assertEquals("h", snap.items[1].dataSha256)
        assertEquals(1000L, snap.serverTime)
        assertEquals(30L, snap.trashDays)
        assertEquals("m", snap.vaults[0].manifest)
        assertEquals(4L, snap.vaults[0].manifestSeq)
        assertEquals("p", snap.vaults[0].manifestPrev)
        assertEquals(true, snap.vaults[0].manifestOk)
        assertTrue("one whole answer, as sent", snap.whole)
        // The phone's own copy: its kept rows and the summary hashes survive store and load; the server's clock isn't stored.
        val mine = snap.copy(items = listOf(snap.items[0].copy(servedSha256 = "served"), snap.items[1]))
        val loaded = SyncSnapshot.decode(mine.encode())!!
        assertEquals("served", loaded.items[0].servedSha256)
        assertEquals("h", loaded.items[1].dataSha256)
        assertEquals("m", loaded.vaults[0].manifest)
        assertEquals(4L, loaded.vaults[0].manifestSeq)
        assertEquals("the three manifest fields stay together in the stored copy", "p", loaded.vaults[0].manifestPrev)
        assertNull(loaded.serverTime)
        assertFalse("the stored copy is this phone's, not an answer", loaded.whole)
        // A delta keeps the copy's rows as they are and takes the answer's vault rows.
        val delta = DeltaSync.parse("""{"revision":4,"delta":true,"vaults":[{"id":"v","manifest":"m2","manifest_seq":5}],"items":[{"id":"n","vault_id":"v","item_key":"k","data":"d","served_sha256":"x"}]}""")!!
        val merged = SyncMerge.apply(delta, loaded)!!
        assertEquals("served", merged.items.first { it.id == "a" }.servedSha256)
        assertNull(merged.items.first { it.id == "n" }.servedSha256)
        assertEquals(5L, merged.vaults[0].manifestSeq)
        assertFalse("a delta on this phone's copy isn't a whole answer", merged.whole)
    }

    /** Review H1 (R2): the hash a row is counted with never comes from the server. */
    @Test
    fun aServerRowThatNamesItsOwnHashIsStillCountedByTheDataItCarries() {
        val s = started()
        val v = s.header()
        fun answer(a: String) = DeltaSync.parse(
            """{"revision":3,"vaults":[{"id":"${v.id}","role":"owner","key_kind":"account","key_epoch":${v.keyEpoch},"seq":${v.seq},
                 "manifest":"${v.manifest}","manifest_seq":${v.manifestSeq},"manifest_prev":"${v.manifestPrev}"}],
               "items":[$a,{"id":"b","vault_id":"${v.id}","item_key":"k","data":"data-b"},{"id":"c","vault_id":"${v.id}","deleted_at":100,"data_sha256":"${manifestDataHash("data-c")}"}]}""",
        )!!
        val honest = SyncMerge.apply(answer("""{"id":"a","vault_id":"${v.id}","item_key":"k","data":"data-a"}"""), null)!!
        assertEquals(ManifestState.Ok, judge(honest.vaults, honest.items, mapOf(vaultId to s.key), emptyMap(), whole = honest.whole).states[vaultId])
        // An older version of "a", with the hash of the current one planted next to it.
        val tampered = SyncMerge.apply(answer("""{"id":"a","vault_id":"${v.id}","item_key":"k","data":"an-older-version","served_sha256":"${manifestDataHash("data-a")}"}"""), null)!!
        assertNull(tampered.items.first { it.id == "a" }.servedSha256)
        val j = judge(tampered.vaults, tampered.items, mapOf(vaultId to s.key), emptyMap(), whole = tampered.whole)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        assertTrue(j.remember.isEmpty())
    }

    // ----------------------------------------------------------- verify

    @Test
    fun aSyncIsJudgedAgainstEachVaultsManifest() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        val first = s.mark()
        // Ok: the version and the link are remembered.
        var j = judge(listOf(s.header()), s.rows, keys, emptyMap(), whole = true)
        assertEquals(mapOf(vaultId to ManifestState.Ok), j.states)
        assertEquals(mapOf(vaultId to first), j.remember)
        // An item hidden, one brought back, an older version served, a trashed one shown live: unresolved, nothing remembered.
        for (bad in listOf(s.rows.drop(1), s.rows + row("z", "old"), listOf(row("a", "older")) + s.rows.drop(1), s.rows.map { if (it.id == "c") it.copy(deletedAt = null) else it })) {
            j = judge(listOf(s.header()), bad, keys, mapOf(vaultId to first), whole = true)
            assertEquals(ManifestState.Unresolved, j.states[vaultId])
            assertEquals(setOf(vaultId), j.failed)
            assertTrue(j.remember.isEmpty())
        }
        // A lower version than this phone saw, or no manifest after one was seen: rollback.
        val later = ManifestMark(2, first.link)
        j = judge(listOf(s.header()), s.rows, keys, mapOf(vaultId to later), whole = true)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        assertTrue(j.remember.isEmpty())
        j = judge(listOf(s.header().copy(manifest = null, manifestSeq = 0, manifestPrev = null)), s.rows, keys, mapOf(vaultId to first), whole = true)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        // A manifest that doesn't open (another key epoch, or without the link it replaced): mismatch.
        j = judge(listOf(s.header().copy(keyEpoch = epoch + 1)), s.rows, keys, emptyMap(), whole = true)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        j = judge(listOf(s.header().copy(manifestPrev = null)), s.rows, keys, emptyMap(), whole = true)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        // No manifest and none seen: nothing to check. A vault whose key isn't open isn't judged.
        j = judge(listOf(s.header().copy(manifest = null, manifestSeq = 0, manifestPrev = null), SyncVault("other", manifest = "x", manifestSeq = 3)), s.rows, keys, emptyMap(), whole = true)
        assertEquals(mapOf(vaultId to ManifestState.None), j.states)
        // Malformed rows (an id twice, a time in the trash that is no time) are a mismatch, not a crash.
        assertEquals("mismatch", Manifests.verify(s.key, s.header(), null, s.rows + s.rows[0]).status)
        for (noTime in listOf(0L, -5L)) {
            assertEquals("mismatch", Manifests.verify(s.key, s.header(), null, s.rows.map { if (it.id == "c") it.copy(deletedAt = noTime) else it }).status)
        }
    }

    /** Rule R4: a warning is raised from the server's whole answer alone. */
    @Test
    fun onlyTheServersWholeAnswerRaisesAWarning() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        val hiddenRow = s.rows.drop(1)
        // A delta merged into this phone's copy, or the copy itself: not decided yet (no warning; the write waits for the sync).
        val delta = judge(listOf(s.header()), hiddenRow, keys, emptyMap(), whole = false)
        assertEquals(ManifestState.Unchecked, delta.states[vaultId])
        assertEquals(setOf(vaultId), delta.undecided)
        assertTrue(delta.remember.isEmpty())
        // The same rows as the server's whole answer: the warning.
        val whole = judge(listOf(s.header()), hiddenRow, keys, emptyMap(), whole = true)
        assertEquals(ManifestState.Unresolved, whole.states[vaultId])
        assertEquals(setOf(vaultId), whole.undecided)
        // A rollback computed from this phone's copy (its memory ahead of its copy) is no warning either.
        val behind = judge(listOf(s.header()), s.rows, keys, mapOf(vaultId to ManifestMark(4, s.link())), whole = false)
        assertEquals(ManifestState.Unchecked, behind.states[vaultId])
        // Nothing is written while it isn't decided.
        assertThrows(UserException::class.java) { Manifests.next(s.key, s.header(), delta.states[vaultId], emptyList(), listOf(row("n", "d"))) }
    }

    /** Review M (R5): an item the app can't open, behind a manifest that counts it, is an item being hidden. */
    @Test
    fun anItemThatDoesNotOpenBehindAPassingManifestIsAMismatch() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        // The rows count (a corrupted `item_key` changes nothing the manifest covers), but one live item doesn't open.
        val whole = judge(listOf(s.header()), s.rows, keys, emptyMap(), whole = true, hidden = setOf(vaultId))
        assertEquals(ManifestState.Unresolved, whole.states[vaultId])
        assertEquals(setOf(vaultId), whole.failed)
        assertTrue("nothing is remembered of an answer with a hidden item", whole.remember.isEmpty())
        assertEquals(ManifestState.Unchecked, judge(listOf(s.header()), s.rows, keys, emptyMap(), whole = false, hidden = setOf(vaultId)).states[vaultId])
        // A live row without its data never gets this far: the answer isn't a vault snapshot at all.
        assertNull(SyncMerge.apply(DeltaSync.parse("""{"revision":1,"vaults":[{"id":"v"}],"items":[{"id":"a","vault_id":"v","data_sha256":"h"}]}""")!!, null))
        // Another vault's hidden item doesn't touch this one; a vault without a manifest has nothing to say.
        assertEquals(ManifestState.Ok, judge(listOf(s.header()), s.rows, keys, emptyMap(), whole = true, hidden = setOf("other")).states[vaultId])
    }

    // ------------------------------------------------------------ the chain

    /** Review core H1: a phone that saw (or wrote) version n never accepts another history at n or above. */
    @Test
    fun forkThenJoinIsNoticedWithAndWithoutTheLog() {
        val s = started()
        // Both devices hold version 1. The phone creates "new" and purges the trashed "c": version 2, remembered.
        val forked = s.fork()
        val n = row("new", "data-new")
        val mine = Manifests.next(s.key, s.header(), ManifestState.Ok, s.rows.filter { it.id == "c" }, listOf(n))!!
        s.write(listOf(mine)) { r -> r.filter { it.id != "c" } + n }
        val remembered = mine.mark
        assertEquals(remembered, s.mark())
        assertEquals(ManifestState.Ok, s.judged(remembered).states[vaultId])
        // The server kept showing the other device version 1; it edits "a": another, valid version 2.
        val a = forked.rows.first { it.id == "a" }
        forked.otherDevice(listOf(a), listOf(a.copy(data = "data-a2")))
        assertEquals(2L, forked.manifestSeq)
        // Joined at the same version: the items match that manifest, but it isn't the one this phone wrote.
        assertEquals("mismatch", forked.status(remembered))
        var j = forked.judged(remembered)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        assertTrue(j.remember.isEmpty())
        assertEquals("no log is needed to see that", 0, forked.logRequests)
        // Joined one or two versions later: its predecessor isn't what this phone remembers, so only the
        // log can say, and the branch's own log doesn't lead back to this phone's manifest.
        for (step in 1..2) {
            forked.otherDevice(emptyList(), listOf(row("more$step", "data-more$step")))
            assertEquals("need_log", forked.status(remembered))
            j = forked.judged(remembered)
            assertEquals(ManifestState.Unresolved, j.states[vaultId])
            assertTrue(j.remember.isEmpty())
            assertEquals(step, forked.logRequests)
        }
        // A log made up to look connected (this phone's own entry spliced in) proves nothing: the hashes don't meet.
        val spliced = kotlinx.serialization.json.JsonArray(s.log + forked.log.drop(2)).toString()
        assertEquals(4L, forked.manifestSeq)
        assertEquals("mismatch", Manifests.verify(forked.key, forked.header(), remembered, forked.rows, spliced).status)
        // Without the log in hand (a copy from this phone, nothing asked): not decided, no warning, nothing remembered.
        j = forked.judged(remembered, whole = false, log = null)
        assertEquals(ManifestState.Unchecked, j.states[vaultId])
        assertEquals(setOf(vaultId), j.unlogged)
        assertTrue(j.remember.isEmpty())
        // The phone's own history, several versions on (other devices wrote meanwhile): accepted through the log.
        s.otherDevice(emptyList(), listOf(row("x1", "d1")))
        s.otherDevice(emptyList(), listOf(row("x2", "d2")))
        s.otherDevice(emptyList(), listOf(row("x3", "d3")))
        assertEquals("need_log", s.status(remembered))
        j = s.judged(remembered)
        assertEquals(ManifestState.Ok, j.states[vaultId])
        assertEquals(s.mark(), j.remember[vaultId])
        // One step ahead needs no log at all.
        val before = s.mark()
        s.otherDevice(emptyList(), listOf(row("x4", "d4")))
        val requests = s.logRequests
        assertEquals(ManifestState.Ok, s.judged(before).states[vaultId])
        assertEquals(requests, s.logRequests)
    }

    @Test
    fun aLogThatCannotBeFetchedLeavesTheAnswerUntakenAndARefusalIsAMismatch() {
        val s = started()
        val remembered = s.mark()
        repeat(3) { n -> s.otherDevice(emptyList(), listOf(row("x$n", "d$n"))) }
        assertEquals("need_log", s.status(remembered))
        // No answer, a 5xx, a 429: the sync has failed for this answer. Nothing is judged, nothing remembered, no warning.
        for (failure in listOf<Exception>(java.io.IOException("no route"), ApiException(503, "unavailable", "x"), ApiException(429, "rate_limited", "x"), ApiException(401, "unauthorized", "x"))) {
            val thrown = runCatching { s.judged(remembered, log = { _, after -> Manifests.fetchLog(after) { throw failure } }) }.exceptionOrNull()
            assertTrue("$failure → $thrown", thrown is ManifestLogUnavailable)
            assertEquals(failure, thrown!!.cause)
        }
        // 404 (not a member any more, or no such log) and 400 are answers: the log doesn't connect.
        for (status in listOf(404, 400)) {
            val j = s.judged(remembered, log = { _, after -> Manifests.fetchLog(after) { throw ApiException(status, "not_found", "x") } })
            assertEquals(ManifestState.Unresolved, j.states[vaultId])
            assertTrue(j.remember.isEmpty())
        }
        // So is an answer that isn't a log, or an empty one.
        for (answer in listOf("null", "[]", """{"entries":"x","more":false}""", """{"entries":[],"more":false}""")) {
            val j = s.judged(remembered, log = { _, after -> Manifests.fetchLog(after) { Json.parseToJsonElement(answer) } })
            assertEquals(answer, ManifestState.Unresolved, j.states[vaultId])
        }
        // Pages are followed from the last entry; more than five requests is no log.
        assertEquals(ManifestState.Ok, s.judged(remembered, log = s.logSource(page = 2)).states[vaultId])
        assertEquals(2, s.logRequests)
        s.logRequests = 0
        repeat(4) { n -> s.otherDevice(emptyList(), listOf(row("y$n", "e$n"))) }
        assertEquals(ManifestState.Unresolved, s.judged(remembered, log = s.logSource(page = 1)).states[vaultId])
        assertEquals(Manifests.LOG_REQUESTS, s.logRequests)
        assertEquals(ManifestState.Ok, s.judged(remembered, log = s.logSource(page = 2)).states[vaultId])
        // "more" without getting further would ask the same again: no log.
        var asked = 0
        assertNull(runBlocking { Manifests.fetchLog(1) { asked++; Json.parseToJsonElement("""{"entries":[{"seq":1,"prev":"p","digest":"d"}],"more":true}""") } })
        assertEquals(1, asked)
        assertEquals("/vaults/a%20b/manifest-log?after=7", Manifests.logPath("a b", 7))
    }

    @Test
    fun aWriteThatDoesNotNameTheCurrentManifestIsRefusedByTheServer() {
        val s = started()
        val n = row("n", "data-n")
        val good = Manifests.next(s.key, s.header(), ManifestState.Ok, emptyList(), listOf(n))!!
        assertEquals(s.link(), good.prev)
        assertEquals(good.json()["prev"]!!.jsonPrimitive.content, good.prev)
        // The right version on another predecessor (a manifest built on another history).
        val other = good.copy(prev = manifestDataHash("something else"))
        assertTrue(Manifests.isConflict(assertThrows(ApiException::class.java) { s.write(listOf(other)) { it + n } }))
        assertEquals(1L, s.manifestSeq)
        assertEquals(400, assertThrows(ApiException::class.java) { s.write(listOf(good.copy(prev = "nope"))) { it + n } }.status)
        s.write(listOf(good)) { it + n }
        assertEquals(good.mark, s.mark())
        // A baseline or a first manifest names the row it replaces too.
        val stale = Manifests.startBody(s.key, s.header().copy(manifestPrev = ZERO), 5, s.rows)!!.first
        assertTrue(Manifests.isConflict(assertThrows(ApiException::class.java) { s.putManifest(stale) }))
        // And never jumps more than a million versions.
        val far = Manifests.startBody(s.key, s.header(), s.manifestSeq + 1_000_001, s.rows)!!.first
        assertEquals(400, assertThrows(ApiException::class.java) { s.putManifest(far) }.status)
    }

    @Test
    fun summaryRowsAreCountedByTheServersHashAndOldCopiesAreIncomplete() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        val summary = s.rows.map { if (it.deletedAt != null) it.copy(itemKey = null, data = null, dataSha256 = manifestDataHash(it.data!!)) else it }
        assertEquals(ManifestState.Ok, judge(listOf(s.header()), summary, keys, emptyMap()).states[vaultId])
        // A wrong hash is a mismatch.
        val lied = summary.map { if (it.deletedAt != null) it.copy(dataSha256 = manifestDataHash("other")) else it }
        assertEquals(ManifestState.Unresolved, judge(listOf(s.header()), lied, keys, emptyMap(), whole = true).states[vaultId])
        // A copy cached before the hash existed: can't be counted; nothing remembered; asked for again in full.
        val old = summary.map { it.copy(dataSha256 = null) }
        val j = judge(listOf(s.header()), old, keys, emptyMap())
        assertEquals(ManifestState.Unchecked, j.states[vaultId])
        assertEquals(setOf(vaultId), j.incomplete)
        assertTrue(j.remember.isEmpty())
        // Still without hashes in a whole answer from the server: a mismatch.
        val whole = judge(listOf(s.header()), old, keys, emptyMap(), whole = true)
        assertEquals(ManifestState.Unresolved, whole.states[vaultId])
    }

    @Test
    fun deviceMemoryIsAVersionWithItsLinkAndOnlyGoesUp() {
        val l1 = manifestDataHash("one")
        val l2 = manifestDataHash("two")
        val m = mapOf("a" to ManifestMark(3, l1), "gone" to ManifestMark(9, l1))
        assertEquals(mapOf("a" to ManifestMark(4, l2), "gone" to ManifestMark(9, l1), "b" to ManifestMark(1, l2)), Manifests.merged(m, mapOf("a" to ManifestMark(4, l2), "b" to ManifestMark(1, l2))))
        // Never lowered; at the same version the link already there stays; half a mark is no mark.
        assertEquals(m, Manifests.merged(m, mapOf("a" to ManifestMark(2, l2), "gone" to ManifestMark(9, l2), "zero" to ManifestMark(0, l2), "nolink" to ManifestMark(5, "short"))))
        assertEquals(m, Manifests.decodeMemory(Manifests.encodeMemory(m)))
        // The first version's bare numbers, a version without a link, a link that isn't one: nothing remembered.
        assertEquals(
            mapOf("ok" to ManifestMark(1, l1)),
            Manifests.decodeMemory("""{"ok":{"version":1,"link":"$l1"},"old":7,"half":{"version":2},"other":{"link":"$l1"},"bad":{"version":2,"link":"x"},"zero":{"version":0,"link":"$l1"},"s":{"version":"2","link":"$l1"},"f":{"version":1.5,"link":"$l1"}}"""),
        )
        assertEquals(emptyMap<String, ManifestMark>(), Manifests.decodeMemory("""{"a":3,"b":9}"""))
        assertEquals(emptyMap<String, ManifestMark>(), Manifests.decodeMemory("not json"))
        assertEquals(emptyMap<String, ManifestMark>(), Manifests.decodeMemory(null))
        assertTrue(Manifests.isLink(l1) && Manifests.isLink(ZERO))
        assertFalse(Manifests.isLink(l1 + "A") || Manifests.isLink(l1.dropLast(1) + "=") || Manifests.isLink(null))
    }

    /** Review L2 (R4): memory that can't be read isn't empty memory, and is never written over. */
    @Test
    fun memoryThatCannotBeReadIsNotEmptyAndIsNeverOverwritten() {
        val dir = java.nio.file.Files.createTempDirectory("pa-memory").toFile()
        try {
            var broken = false
            val file = SealedFile(java.io.File(dir, "acct.manifests"), seal = { it.reversedArray() }, open = { if (broken) throw java.security.GeneralSecurityException("keystore") else it.reversedArray() })
            assertEquals(SealedFile.Read.Missing, file.read())
            val link = manifestDataHash("one")
            assertTrue(file.write { had -> assertNull(had); Manifests.encodeMemory(mapOf("v" to ManifestMark(7, link))) })
            assertEquals(mapOf("v" to ManifestMark(7, link)), Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text))
            // The Keystore fails for a moment: unknown, not "nothing remembered"; a write is refused and the file is untouched.
            broken = true
            assertEquals(SealedFile.Read.Unreadable, file.read())
            var asked = false
            assertFalse(file.write { asked = true; Manifests.encodeMemory(emptyMap()) })
            assertFalse("nothing is merged into what can't be read", asked)
            broken = false
            assertEquals(mapOf("v" to ManifestMark(7, link)), Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text))
            // A write merges with what the file holds.
            assertTrue(file.write { had -> Manifests.encodeMemory(Manifests.merged(Manifests.decodeMemory(had), mapOf("w" to ManifestMark(1, link)))) })
            assertEquals(setOf("v", "w"), Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text).keys)
            file.delete()
            assertEquals(SealedFile.Read.Missing, file.read())
        } finally {
            dir.deleteRecursively()
        }
    }

    // ------------------------------------------------------------ writes

    @Test
    fun aVaultWithoutAManifestSendsNothingNew() {
        val k = key()
        val v = SyncVault(vaultId, keyEpoch = epoch, seq = 3, manifestSeq = 0)
        assertNull(Manifests.next(k, v, ManifestState.None, emptyList(), listOf(row("n", "d"))))
        assertNull(Manifests.next(k, v.copy(manifestSeq = null), null, emptyList(), listOf(row("n", "d"))))
        val body = ItemWrites.body(io.passauth.core.EncryptedItem("n", vaultId, "k", "d"), epoch, revision = 2, manifests = emptyList())
        assertNull(body["manifests"])
        assertEquals("", Manifests.query(null, 7))
        assertNull(Manifests.rotationEntry(k, v, listOf(row("n", "d"))))
        assertNull(Manifests.linkOf(v))
        // Applied locally exactly as before.
        assertTrue(Manifests.mayApplyLocally(null, buildJsonObject { put("vault_seq", 4); put("manifest_seq", 0) }))
        assertTrue(Manifests.mayApplyLocally(null, buildJsonObject { put("vault_seq", 4) }))
        // Nothing sent, but the answer says the vault has a manifest now: sync and check instead.
        assertFalse(Manifests.mayApplyLocally(null, buildJsonObject { put("vault_seq", 4); put("manifest_seq", 1) }))
        assertEquals(250, Manifests.purgeChunk(10_000))
        assertEquals(250, Manifests.purgeChunk(null))
        assertEquals(100, Manifests.purgeChunk(100))
    }

    @Test
    fun everyWriteCarriesTheNextManifestForExactlyWhatItChanges() {
        val s = started()
        fun entry(removed: List<SyncItem>, added: List<SyncItem>) = Manifests.next(s.key, s.header(), ManifestState.Ok, removed, added)!!
        // Create.
        val n = row("n", "data-n")
        var m = entry(emptyList(), listOf(n))
        assertEquals(2L, m.seq)
        val body = ItemWrites.body(io.passauth.core.EncryptedItem("n", vaultId, "k-n", "data-n"), epoch, manifests = listOf(m))
        assertEquals(m.json(), body["manifests"]!!.jsonArray.single())
        assertEquals(vaultId, m.json()["vault_id"]!!.jsonPrimitive.content)
        var seen = s.mark()
        s.write(listOf(m)) { it + n }
        assertEquals("ok", s.status(seen))
        assertEquals("what the builder says to remember is the stored manifest", m.mark, s.mark())
        // Edit: the row as held leaves, the row as sent arrives.
        val a = s.rows.first { it.id == "a" }
        val a2 = a.copy(data = "data-a2")
        m = entry(listOf(a), listOf(a2))
        seen = s.mark()
        s.write(listOf(m)) { r -> r.map { if (it.id == "a") a2 else it } }
        assertEquals("ok", s.status(seen))
        // Trash: the same data, in the trash; the query names the item's revision and the manifest.
        val b = s.rows.first { it.id == "b" }
        m = entry(listOf(b), listOf(b.copy(deletedAt = 50)))
        assertEquals("?revision=12&manifest_seq=${m.seq}&manifest_prev=${m.prev}&manifest=${m.sealed}", Manifests.query(m, 12))
        seen = s.mark()
        s.write(listOf(m)) { r -> r.map { if (it.id == "b") b.copy(deletedAt = 50) else it } }
        assertEquals("ok", s.status(seen))
        // Old trash deleted for good, several at once.
        val trash = s.rows.filter { it.deletedAt != null }
        assertEquals(2, trash.size)
        m = entry(trash, emptyList())
        val purge = Manifests.purgeBody(trash, m)
        assertEquals(trash.map { it.id }, purge["items"]!!.jsonArray.map { it.jsonObject["id"]!!.jsonPrimitive.content })
        assertEquals(1L, purge["items"]!!.jsonArray[0].jsonObject["revision"]!!.jsonPrimitive.long)
        assertEquals(m.json(), purge["manifests"]!!.jsonArray.single())
        seen = s.mark()
        s.write(listOf(m)) { r -> r.filter { it.deletedAt == null } }
        assertEquals("ok", s.status(seen))
        assertEquals(5L, s.manifestSeq)
        // A wrong manifest (the row left out) would be stored by the server as it is, and everyone would see the mismatch.
        val wrong = entry(emptyList(), emptyList())
        seen = s.mark()
        s.write(listOf(wrong)) { it + row("x", "data-x") }
        assertEquals("mismatch", s.status(seen))
    }

    @Test
    fun aMoveTakesTheItemOutOfOneManifestAndIntoTheOther() {
        val from = started()
        val to = Server(account().newVaultKey("00000000-0000-4000-8000-0000000000f1").key, vault = "00000000-0000-4000-8000-0000000000f1", epoch = 0)
        to.rows = listOf(row("t", "data-t", vault = to.vault))
        to.putManifest(Manifests.startBody(to.key, to.header(), 1, to.rows)!!.first)
        val a = from.rows.first { it.id == "a" }
        val moved = SyncItem("a", to.vault, "k2", "re-encrypted")
        val out = Manifests.next(from.key, from.header(), ManifestState.Ok, listOf(a), emptyList())!!
        val into = Manifests.next(to.key, to.header(), ManifestState.Ok, emptyList(), listOf(moved))!!
        val body = ItemWrites.body(io.passauth.core.EncryptedItem("a", to.vault, "k2", "re-encrypted"), 0, 3, listOf(out, into))
        assertEquals(listOf(from.vault, to.vault), body["manifests"]!!.jsonArray.map { it.jsonObject["vault_id"]!!.jsonPrimitive.content })
        val (fromSeen, toSeen) = from.mark() to to.mark()
        from.write(listOf(out, into)) { r -> r.filter { it.id != "a" } }
        to.write(listOf(out, into)) { it + moved }
        assertEquals("ok", from.status(fromSeen))
        assertEquals("ok", to.status(toSeen))
        // A trashed item keeps its place when it moves (the row's own `deleted_at` goes into the other vault's manifest).
        val trashed = moved.copy(id = "t2", deletedAt = 77)
        val intoTrash = Manifests.next(to.key, to.header(), ManifestState.Ok, emptyList(), listOf(trashed))!!
        val toSeen2 = to.mark()
        to.write(listOf(intoTrash)) { it + trashed }
        assertEquals("ok", to.status(toSeen2))
        assertEquals("mismatch", Manifests.verify(to.key, to.header(), toSeen2, to.rows.map { if (it.id == "t2") it.copy(deletedAt = null) else it }).status)
        // Into a vault without a manifest: only the vault it leaves carries one.
        assertNull(Manifests.next(to.key, to.header().copy(manifest = null, manifestSeq = 0, manifestPrev = null), ManifestState.None, emptyList(), listOf(moved)))
    }

    @Test
    fun aHeldVaultIsNeverWrittenTo() {
        val s = started()
        for (state in listOf(ManifestState.Unresolved, ManifestState.Unchecked, null, ManifestState.None)) {
            val e = assertThrows(UserException::class.java) { Manifests.next(s.key, s.header(), state, emptyList(), listOf(row("n", "d"))) }
            assertEquals("This vault can't be changed until its warning is resolved.", e.message)
        }
        // Also when the manifest vanished after one was seen (the row says "none" but the vault is unresolved).
        assertThrows(UserException::class.java) { Manifests.next(s.key, s.header().copy(manifest = null, manifestSeq = 0), ManifestState.Unresolved, emptyList(), listOf(row("n", "d"))) }
        // A row that doesn't carry the link its manifest replaced can't be built on.
        assertThrows(UserException::class.java) { Manifests.next(s.key, s.header().copy(manifestPrev = null), ManifestState.Ok, emptyList(), listOf(row("n", "d"))) }
        // A row that can't be counted can't leave a manifest.
        assertThrows(UserException::class.java) { Manifests.next(s.key, s.header(), ManifestState.Ok, listOf(row("c", null, 100)), emptyList()) }
    }

    @Test
    fun theCopyTakesAnOwnWriteOnlyWithTheAnsweredManifestVersion() {
        val s = started()
        val n = row("n", "data-n")
        val m = Manifests.next(s.key, s.header(), ManifestState.Ok, emptyList(), listOf(n))!!
        val before = s.snapshot()
        val seen = s.mark()
        val answer = s.write(listOf(m)) { it + n }
        assertTrue(Manifests.mayApplyLocally(m, answer))
        assertTrue(Manifests.stored(m, answer))
        assertFalse(Manifests.stored(null, answer) || Manifests.stored(m.copy(seq = m.seq + 1), answer))
        assertEquals(SyncDecision.AfterWrite.ApplyLocally, SyncDecision.afterWrite(before.vaults[0].seq, answer["vault_seq"]!!.jsonPrimitive.long))
        val next = SyncMerge.applyLocal(LocalChange.Put(n.copy(revision = 9)), vaultId, answer["vault_seq"]!!.jsonPrimitive.long, before, m)!!
        // The row's manifest and version are the ones sent: the copy's rows and manifest still belong together.
        assertEquals(m.sealed, next.vaults[0].manifest)
        assertEquals(m.seq, next.vaults[0].manifestSeq)
        assertEquals("the link it replaced goes with it: the next write is built on this row", m.prev, next.vaults[0].manifestPrev)
        assertEquals(m.link, Manifests.linkOf(next.vaults[0]))
        assertFalse(next.whole)
        assertEquals("ok", Manifests.verify(s.key, next.vaults[0], seen, next.items).status)
        // What is remembered of the write is the copy's own row: a later sync showing that version must show that link.
        assertEquals(Manifests.Check("ok", m.mark), Manifests.verify(s.key, next.vaults[0], m.mark, next.items))
        // The server took the manifest but other things were written into the vault too (a name, sharing): the rows are
        // still the copy's with this write, taken under the vault's old number so the sync that follows brings the rest.
        val under = SyncMerge.applyLocal(LocalChange.Put(n.copy(revision = 9)), vaultId, before.vaults[0].seq!!, before, m)!!
        assertEquals(before.vaults[0].seq, under.vaults[0].seq)
        assertEquals("ok", Manifests.verify(s.key, under.vaults[0], m.mark, under.items).status)
        assertEquals(s.snapshot().items.map { it.id }, next.items.map { it.id })
        // Another version in the answer (someone wrote right after), none at all, or an entry for another vault: sync instead.
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("vault_seq", 7); put("manifest_seq", m.seq + 1) }))
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("vault_seq", 7) }))
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("manifest_seq", "${m.seq}") }))
        assertNull(SyncMerge.applyLocal(LocalChange.Put(n), vaultId, 7, before, m.copy(vaultId = "other")))
    }

    @Test
    fun aLocalTrashWithoutDataKeepsTheHashAndStillVerifies() {
        val s = started()
        val b = s.rows.first { it.id == "b" }
        val m = Manifests.next(s.key, s.header(), ManifestState.Ok, listOf(b), listOf(b.copy(deletedAt = 60)))!!
        val before = s.snapshot()
        val answer = s.write(listOf(m)) { r -> r.map { if (it.id == "b") b.copy(deletedAt = 60) else it } }
        val next = SyncMerge.applyLocal(LocalChange.Trash("b", 60, 9, summary = true, dataSha256 = Manifests.serverHash(b)), vaultId, answer["vault_seq"]!!.jsonPrimitive.long, before, m)!!
        val kept = next.items.first { it.id == "b" }
        assertNull(kept.data)
        assertNull(kept.itemKey)
        assertEquals(manifestDataHash("data-b"), kept.dataSha256)
        assertEquals("ok", Manifests.verify(s.key, next.vaults[0], m.mark, next.items).status)
        // Through store and load too.
        val loaded = SyncSnapshot.decode(next.encode())!!
        assertEquals("ok", Manifests.verify(s.key, loaded.vaults[0], m.mark, loaded.items).status)
        // A kept newer copy that is trashed keeps the hash of what the server holds.
        val keptNewer = before.copy(items = before.items.map { if (it.id == "b") it.copy(data = "newer", servedSha256 = manifestDataHash("data-b")) else it })
        val t = SyncMerge.applyLocal(LocalChange.Trash("b", 60, 9, summary = true, dataSha256 = "ignored"), vaultId, 7, keptNewer, m)!!.items.first { it.id == "b" }
        assertEquals(manifestDataHash("data-b"), t.dataSha256)
        assertNull(t.servedSha256)
        // Old trash removed locally in one go; a manifest alone changes no rows.
        val purged = SyncMerge.applyLocal(LocalChange.PurgeAll(setOf("b", "c")), vaultId, 8, next)!!
        assertEquals(listOf("a"), purged.items.map { it.id })
        assertNull(SyncMerge.applyLocal(LocalChange.PurgeAll(setOf("nope")), vaultId, 8, next))
        assertEquals(next.items, SyncMerge.applyLocal(LocalChange.ManifestOnly, vaultId, 8, next, m.copy(seq = 3))!!.items)
    }

    @Test
    fun aNewerCopyKeptAfterARollbackCountsAsWhatTheServerHoldsAndTakesItsRevision() {
        val s = started()
        // The server sent an older version of "a" (revision 4) with a manifest that records it (e.g. a baseline); the phone keeps its newer copy.
        val served = s.rows.first { it.id == "a" }.copy(revision = 4)
        val prior = row("a", "newer-on-the-phone", revision = 7)
        val kept = ItemRevs.keptRow(prior, served, Manifests.serverHash(served))
        assertEquals("the server's revision, so an edit saves over its copy instead of a conflict", 4L, kept.revision)
        assertEquals("newer-on-the-phone", kept.data)
        val copy = ItemRevs.keepRows(s.snapshot(), mapOf("a" to kept))
        assertEquals("ok", Manifests.verify(s.key, copy.vaults[0], s.mark(), copy.items).status)
        // Editing it: the manifest drops what the server holds, not the kept data.
        val edited = kept.copy(data = "edited", servedSha256 = null)
        val m = Manifests.next(s.key, copy.vaults[0], ManifestState.Ok, listOf(kept), listOf(edited))!!
        val seen = s.mark()
        s.write(listOf(m)) { r -> r.map { if (it.id == "a") edited else it } }
        assertEquals("ok", s.status(seen))
    }

    /** Review M4 (R9): the mark of a kept newer copy lasts as long as the row is that copy. */
    @Test
    fun aKeptNewerCopyStaysMarkedUntilItIsRewritten() {
        val s = started()
        val served = s.rows.first { it.id == "a" }.copy(revision = 4)
        val kept = ItemRevs.keptRow(row("a", "newer-on-the-phone", revision = 7), served, Manifests.serverHash(served))
        assertTrue(ItemRevs.isKept(kept))
        assertFalse(ItemRevs.isKept(served))
        var copy = ItemRevs.keepRows(s.snapshot(), mapOf("a" to kept))
        fun marked() = copy.items.filter(ItemRevs::isKept).map { it.id }
        assertEquals(listOf("a"), marked())
        // Lock and unlock (the stored copy read back).
        copy = SyncSnapshot.decode(copy.encode())!!
        assertEquals(listOf("a"), marked())
        // A later delta that doesn't bring the item.
        val delta = DeltaSync.parse("""{"revision":9,"delta":true,"vaults":[${AppJson.encodeToString(SyncVault.serializer(), s.header())}],"items":[{"id":"n","vault_id":"$vaultId","item_key":"k","data":"d"}]}""")!!
        copy = SyncMerge.apply(delta, copy)!!
        assertEquals(listOf("a"), marked())
        // This phone's own writes to other items (applied to the copy), a trash included.
        copy = SyncMerge.applyLocal(LocalChange.Put(row("b", "data-b2", revision = 5)), vaultId, copy.vaults[0].seq!! + 1, copy)!!
        copy = SyncMerge.applyLocal(LocalChange.Trash("n", 60, 6, summary = true, dataSha256 = "h"), vaultId, copy.vaults[0].seq!! + 1, copy)!!
        assertEquals(listOf("a"), marked())
        // A first manifest is never started over such a copy, nor over an item marked as served older without a copy to keep.
        val none = s.header().copy(manifest = null, manifestSeq = 0, manifestPrev = null)
        assertFalse(Manifests.mayStart(none, ManifestState.None, Role.Owner, true, null, copy.items))
        assertFalse(Manifests.mayStart(none, ManifestState.None, Role.Owner, true, null, s.rows, marked = setOf("b")))
        assertTrue(Manifests.mayStart(none, ManifestState.None, Role.Owner, true, null, s.rows, marked = setOf("elsewhere")))
        // Until the row is rewritten: an edit saved…
        val edited = SyncMerge.applyLocal(LocalChange.Put(row("a", "edited", revision = 8)), vaultId, copy.vaults[0].seq!! + 1, copy)!!
        assertTrue(edited.items.none(ItemRevs::isKept))
        // …or the server sending the item again (that version or a newer one is then taken as served).
        val again = DeltaSync.parse("""{"revision":10,"delta":true,"vaults":[${AppJson.encodeToString(SyncVault.serializer(), s.header())}],"items":[{"id":"a","vault_id":"$vaultId","item_key":"k","data":"newer-on-the-phone","served_sha256":"x"}]}""")!!
        assertTrue(SyncMerge.apply(again, copy)!!.items.none(ItemRevs::isKept))
    }

    // ------------------------------------------------------- retry loops

    private fun entryOf(r: SyncItem, name: String = "Mail") = Entry(r.id, Item(name = name), r.vaultId, r.revision ?: 0, io.passauth.core.EncryptedItem(r.id, r.vaultId, r.itemKey ?: "", r.data ?: ""))

    @Test
    fun aConflictSyncsRecomputesAndSendsAgain() = runBlocking {
        val s = started()
        var copy = s.snapshot()
        // Another device writes after this phone's sync: the phone's manifest is no longer the next one.
        s.otherDevice(emptyList(), listOf(row("other", "data-o")))
        val n = row("n", "data-n")
        var syncs = 0
        val created = ItemWrites.create(
            send = {
                val m = Manifests.next(s.key, copy.vaults[0], ManifestState.Ok, emptyList(), listOf(n))
                s.write(listOfNotNull(m)) { it + n }
            },
            resync = { syncs++; copy = s.snapshot() },
            updateEarlierAttempt = { error("not expected") },
        )
        assertEquals(ItemWrites.Created.New, created)
        assertEquals(1, syncs)
        assertEquals(2, s.requests - 1)
        assertEquals("ok", s.status())
        assertEquals(listOf("a", "b", "c", "other", "n"), s.rows.map { it.id })
    }

    @Test
    fun aStaleCopyThatStillSaidNoManifestGetsManifestRequiredAndRetries() = runBlocking {
        val s = Server(key())
        s.rows = listOf(row("a", "data-a"))
        var copy = s.snapshot()
        // Another device starts the vault's manifest; this phone's copy still says "none".
        s.putManifest(Manifests.startBody(s.key, s.header(), 1, s.rows)!!.first)
        val a2 = row("a", "data-a2")
        var sends = 0
        ItemWrites.update(
            entryOf(s.rows[0]),
            send = { e ->
                sends++
                val held = copy.items.first { it.id == e.id }
                val state = if ((copy.vaults[0].manifestSeq ?: 0) > 0) ManifestState.Ok else ManifestState.None
                val m = Manifests.next(s.key, copy.vaults[0], state, listOf(held), listOf(a2))
                s.write(listOfNotNull(m)) { listOf(a2) }
            },
            resync = { copy = s.snapshot(); entryOf(copy.items[0]) },
        )
        assertEquals(2, sends)
        assertEquals("ok", s.status())
    }

    @Test
    fun threeConflictsEndTheWriteAndAManifestConflictIsNeverTheOverwriteDialog() {
        val conflict = ApiException(409, "manifest_conflict", "the vault changed")
        val required = ApiException(400, "manifest_required", "Update PassAuth to change this vault.")
        for (answer in listOf(conflict, required)) {
            var sends = 0
            var syncs = 0
            var e = assertThrows(UserException::class.java) {
                runBlocking { ItemWrites.create(send = { sends++; throw answer }, resync = { syncs++ }, updateEarlierAttempt = { error("no") }) }
            }
            assertEquals("This vault changed on another device. Try again.", e.message)
            assertEquals(3, sends)
            assertEquals(2, syncs)
            sends = 0
            val base = entryOf(row("a", "d"))
            e = assertThrows(UserException::class.java) { runBlocking { ItemWrites.update(base, send = { sends++; throw answer }, resync = { base }) } }
            assertFalse(e is ConflictException)
            assertEquals("This vault changed on another device. Try again.", e.message)
            assertEquals(3, sends)
            sends = 0
            e = assertThrows(UserException::class.java) { runBlocking { ItemWrites.place(send = { sends++; throw answer }, resync = {}) } }
            assertEquals("This vault changed on another device. Try again.", e.message)
            assertEquals(3, sends)
        }
        // The copy can't make the manifest (unchecked, or the row isn't in it): the same sync-and-retry, nothing sent meanwhile.
        var tries = 0
        runBlocking { ItemWrites.create(send = { if (++tries == 1) throw ItemWrites.StaleCopy() }, resync = {}, updateEarlierAttempt = { false }) }
        assertEquals(2, tries)
    }

    @Test
    fun afterAConflictTheWritesOwnPreconditionsAreCheckedOnTheFreshCopy() {
        val conflict = ApiException(409, "manifest_conflict", "x")
        val base = entryOf(row("a", "d"))
        // The item itself was changed elsewhere meanwhile: the usual conflict, nothing sent on top.
        var sends = 0
        assertThrows(ConflictException::class.java) {
            runBlocking { ItemWrites.update(base, send = { sends++; throw conflict }, resync = { entryOf(row("a", "d2", revision = 2), name = "Changed elsewhere") }) }
        }
        assertEquals(1, sends)
        // Gone (deleted for good or trashed elsewhere): said so, never the overwrite dialog (there is nothing to save over).
        for (first in listOf<Exception>(conflict, ItemWrites.StaleCopy(), ApiException(409, "vault_key_changed", "x"))) {
            val gone = assertThrows(UserException::class.java) { runBlocking { ItemWrites.update(base, send = { throw first }, resync = { null }) } }
            assertFalse(gone is ConflictException)
            assertEquals("This item was deleted on another device.", gone.message)
        }
        // Unchanged (something else in the vault changed): sent again with the fresh entry.
        val sent = mutableListOf<Long>()
        runBlocking { ItemWrites.update(base, send = { e -> sent += e.revision; if (sent.size == 1) throw conflict }, resync = { entryOf(row("a", "d", revision = 5)) }) }
        assertEquals(listOf(1L, 5L), sent)
        // An item's own revision conflict stays the overwrite dialog.
        assertThrows(ConflictException::class.java) { runBlocking { ItemWrites.update(base, send = { throw ApiException(409, "revision_conflict", "x") }, resync = { error("no") }) } }
        // Trash: an item edited meanwhile (its revision was named) syncs and goes again; other errors stand.
        var n = 0
        runBlocking { ItemWrites.place(send = { if (++n == 1) throw ApiException(409, "revision_conflict", "x") }, resync = {}) }
        assertEquals(2, n)
        assertThrows(ApiException::class.java) { runBlocking { ItemWrites.place(send = { throw ApiException(403, "forbidden", "x") }, resync = { error("no") }) } }
    }

    // ------------------------------------------- start, baseline, old trash

    @Test
    fun aFirstManifestIsStartedOnlyWhenEverythingAllowsIt() {
        val s = Server(key())
        s.rows = listOf(row("a", "data-a"), row("c", null, deleted = 5, sha = manifestDataHash("data-c")))
        val v = s.header(ok = true)
        assertTrue(Manifests.mayStart(v, ManifestState.None, Role.Write, true, null, s.rows))
        assertTrue(Manifests.mayStart(v, ManifestState.None, Role.Owner, true, null, s.rows))
        assertFalse("the server doesn't list the feature", Manifests.mayStart(v, ManifestState.None, Role.Owner, false, null, s.rows))
        assertFalse("a member's app is too old", Manifests.mayStart(v.copy(manifestOk = false), ManifestState.None, Role.Owner, true, null, s.rows))
        assertFalse(Manifests.mayStart(v.copy(manifestOk = null), ManifestState.None, Role.Owner, true, null, s.rows))
        assertFalse("view only", Manifests.mayStart(v, ManifestState.None, Role.Read, true, null, s.rows))
        assertFalse("the vault isn't shown", Manifests.mayStart(v, ManifestState.None, null, true, null, s.rows))
        assertFalse("one was seen before", Manifests.mayStart(v, ManifestState.None, Role.Owner, true, ManifestMark(2, ZERO), s.rows))
        assertFalse(Manifests.mayStart(v, ManifestState.Unresolved, Role.Owner, true, null, s.rows))
        assertFalse("it has one", Manifests.mayStart(v.copy(manifestSeq = 1, manifest = "m"), ManifestState.Ok, Role.Owner, true, null, s.rows))
        assertFalse("a row can't be counted", Manifests.mayStart(v, ManifestState.None, Role.Owner, true, null, s.rows + row("old", null, deleted = 1)))
        assertFalse("no vault number to pin it to", Manifests.mayStart(v.copy(seq = null), ManifestState.None, Role.Owner, true, null, s.rows))
        assertNull(Manifests.startBody(s.key, v.copy(seq = null), 1, s.rows))
        // Started: version 1 for exactly these rows.
        val (body, entry) = Manifests.startBody(s.key, v, 1, s.rows)!!
        val answer = s.putManifest(body)
        assertEquals(1L, entry.seq)
        assertTrue(Manifests.mayApplyLocally(entry, answer))
        assertEquals("ok", s.status())
        assertTrue(Manifests.isNotReady(ApiException(409, "manifest_not_ready", "x")))
        assertFalse(Manifests.isConflict(ApiException(409, "manifest_not_ready", "x")))
        assertTrue(Manifests.isConflict(ApiException(400, "manifest_required", "x")) && Manifests.isConflict(ApiException(409, "manifest_conflict", "x")))
        assertFalse(Manifests.isConflict(ApiException(409, "revision_conflict", "x")))
    }

    @Test
    fun useTheServersCopyWritesABaselineAboveEverythingSeen() {
        assertEquals(4L, Manifests.baselineSeq(3, null))
        assertEquals(8L, Manifests.baselineSeq(3, 7))
        assertEquals(4L, Manifests.baselineSeq(3, 2))
        assertEquals(8L, Manifests.baselineSeq(0, 7))
        assertEquals(1L, Manifests.baselineSeq(null, null))
        assertEquals("never past what the server counts", Manifests.MAX_NUMBER, Manifests.baselineSeq(3, Long.MAX_VALUE))
        // A server restored from a backup: an old manifest and old rows, below what this phone remembers.
        val s = started()
        val first = s.mark()
        s.otherDevice(emptyList(), listOf(row("n", "data-n")))
        val remembered = ManifestMark(6, manifestDataHash("a state the server no longer has"))
        assertEquals("rollback", s.status(remembered))
        val seq = Manifests.baselineSeq(s.manifestSeq, remembered.version)
        val shown = s.link()
        val (body, entry) = Manifests.startBody(s.key, s.header(), seq, s.rows)!!
        assertEquals(s.manifestSeq, body["base_seq"]!!.jsonPrimitive.long)
        assertEquals(7L, body["seq"]!!.jsonPrimitive.long)
        assertEquals("built on the manifest the server shows", shown, body["prev"]!!.jsonPrimitive.content)
        s.putManifest(body)
        assertEquals(7L, entry.seq)
        assertEquals(entry.mark, s.mark())
        // The phone that wrote it remembers it and passes; so does a device that remembers the manifest it replaced.
        assertEquals("ok", s.status(entry.mark))
        assertEquals("ok", s.status(ManifestMark(2, shown)))
        // And one further back on that history, through the log.
        assertEquals("need_log", s.status(first))
        assertEquals(ManifestState.Ok, s.judged(first).states[vaultId])
        // A baseline is one device's acceptance: another that remembers a state outside this history still warns.
        assertEquals(ManifestState.Unresolved, s.judged(remembered).states[vaultId])
        assertEquals(ManifestState.Unresolved, s.judged(ManifestMark(9, shown)).states[vaultId])
        // A manifest this phone can't open is still what a baseline is built on (its link needs nothing opened).
        val unreadable = s.header().copy(manifest = "AAAA-not-a-manifest")
        assertNotNull(Manifests.linkOf(unreadable))
        assertEquals(Manifests.linkOf(unreadable), Manifests.startBody(s.key, unreadable, 9, s.rows)!!.first["prev"]!!.jsonPrimitive.content)
        // The vault changed between the sync and the request: a conflict, tried again from a new sync.
        val stale = Manifests.startBody(s.key, s.header().copy(seq = s.seq - 1), 9, s.rows)!!.first
        assertTrue(Manifests.isConflict(assertThrows(ApiException::class.java) { s.putManifest(stale) }))
    }

    /** Review M1 (R7): the server's clock and a row's `deleted_at` are its word alone; this phone's own watch bounds both. */
    @Test
    fun oldTrashIsDeletedOnlyAfterThisPhoneWatchedItForTheRetention() {
        val day = 86_400L
        val now = 100 * day
        val rows = listOf(row("live", "d"), row("fresh", "d", deleted = now - 29 * day), row("edge", "d", deleted = now - 30 * day), row("due", null, deleted = now - 30 * day - 1, sha = "h"), row("ancient", "d", deleted = 5))
        val watched = rows.associate { it.id to now - 31 * day }
        // The server's rule, for items this phone has watched long enough.
        assertEquals(listOf("due", "ancient"), Manifests.dueTrash(rows, now, 30, watched, now).map { it.id })
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, 0, watched, now))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, null, watched, now))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, null, 30, watched, now))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, -1, watched, now))
        // The attack: every trashed row "deleted long ago", or a retention of one day with a clock far ahead.
        // Nothing this phone hasn't itself seen in the trash for the retention goes.
        val lied = rows.map { if (it.deletedAt != null) it.copy(deletedAt = 1) else it }
        assertEquals("first seen just now", emptyList<SyncItem>(), Manifests.dueTrash(lied, now, 1, lied.associate { it.id to now }, now))
        assertEquals("never seen trashed", emptyList<SyncItem>(), Manifests.dueTrash(lied, now, 1, emptyMap(), now))
        assertEquals("seen for 29 of 30 days", emptyList<SyncItem>(), Manifests.dueTrash(lied, now, 30, lied.associate { it.id to now - 29 * day }, now))
        assertEquals(listOf("fresh", "edge", "due", "ancient"), Manifests.dueTrash(lied, now, 30, lied.associate { it.id to now - 30 * day }, now).map { it.id })
        // The server's clock more than a day from this phone's: nothing, whichever way.
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now + day + 1, 30, watched, now))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now - day - 1, 30, watched, now))
        assertEquals(listOf("edge", "due", "ancient"), Manifests.dueTrash(rows, now + day, 30, watched, now).map { it.id })
        // Numbers that don't fit never overflow into "due".
        for ((time, days) in listOf(9_000_000_000_000_000_000L to 1L, now to Long.MAX_VALUE, now to Long.MAX_VALUE / 86_400 + 1, Long.MAX_VALUE to 30L, -5L to 30L)) {
            assertEquals("$time, $days", emptyList<SyncItem>(), Manifests.dueTrash(lied, time, days, lied.associate { it.id to 0L }, now))
            assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(lied, time, days, lied.associate { it.id to 0L }, time))
        }
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows.map { it.copy(deletedAt = -9) }, now, 30, watched, now))

        // The memory: set when an item is first seen in the trash, kept while it stays there, dropped when it is live again or gone.
        var seen = TrashSeen.updated(emptyMap(), rows, 1000)
        assertEquals(setOf("fresh", "edge", "due", "ancient"), seen.keys)
        assertTrue(seen.values.all { it == 1000L })
        val later = rows.filter { it.id != "ancient" }.map { if (it.id == "fresh") it.copy(deletedAt = null) else it } + row("newly", "d", deleted = 7)
        seen = TrashSeen.updated(seen, later, 5000)
        assertEquals(mapOf("edge" to 1000L, "due" to 1000L, "newly" to 5000L), seen)
        // Trashed again later: the watch starts over. A time in the future (the clock was set back) starts over too.
        seen = TrashSeen.updated(seen, rows, 9000)
        assertEquals(9000L, seen["fresh"])
        assertEquals(9000L, seen["ancient"])
        assertEquals(1000L, seen["edge"])
        assertEquals(500L, TrashSeen.updated(mapOf("due" to 99_999L), rows, 500)["due"])
        assertEquals(seen, TrashSeen.decode(TrashSeen.encode(seen)))
        assertEquals(mapOf("ok" to 1L), TrashSeen.decode("""{"ok":1,"s":"2","neg":-1,"f":1.5}"""))
        assertEquals(emptyMap<String, Long>(), TrashSeen.decode(null))
        // Right after this version is installed nothing is due: the watch has only just begun.
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, 30, TrashSeen.updated(emptyMap(), rows, now), now))
    }

    @Test
    fun aKeyReplacementCarriesAWholeNewManifestForTheNewKeyAndEpoch() {
        val s = started()
        val made = account().newVaultKey(vaultId).key
        val reencrypted = s.rows.map { it.copy(itemKey = "new-" + it.id, data = "new-" + it.data) }
        val before = s.mark()
        val m = Manifests.rotationEntry(made, s.header(), reencrypted)!!
        assertEquals(s.manifestSeq + 1, m.seq)
        assertEquals("it names the manifest it replaces, sealed under the old key", before.link, m.prev)
        // After the rotation the server holds the new rows under the new epoch: checked with the new key.
        val after = s.header().copy(keyEpoch = epoch + 1, manifest = m.sealed, manifestSeq = m.seq, manifestPrev = m.prev)
        assertEquals(Manifests.Check("ok", m.mark), Manifests.verify(made, after, before, reencrypted))
        // Not with the old key, the old epoch or the old data.
        assertEquals("mismatch", Manifests.verify(s.key, after, before, reencrypted).status)
        assertEquals("mismatch", Manifests.verify(made, after.copy(keyEpoch = epoch), before, reencrypted).status)
        assertEquals("mismatch", Manifests.verify(made, after, before, s.rows).status)
        // Nor for a device that remembers another manifest at the version it replaced.
        val elsewhere = ManifestMark(before.version, manifestDataHash("another history"))
        assertEquals("need_log", Manifests.verify(made, after, elsewhere, reencrypted).status)
        val log = kotlinx.serialization.json.JsonArray(s.log + buildJsonObject { put("seq", m.seq); put("prev", m.prev); put("digest", digest(m.sealed)) }).toString()
        assertEquals("mismatch", Manifests.verify(made, after, elsewhere, reencrypted, log).status)
        // A row that doesn't carry its whole manifest can't be replaced by a key replacement.
        assertThrows(UserException::class.java) { Manifests.rotationEntry(made, s.header().copy(manifestPrev = null), reencrypted) }
    }

    /** Difference-table row 8: a key replacement re-encrypts the copy this phone checked, nothing else. */
    @Test
    fun aKeyReplacementReencryptsExactlyTheCopyThisPhoneChecked() {
        val full = listOf(row("a", "data-a", revision = 4), row("b", "data-b"), row("c", "data-c", deleted = 100))
        // The copy keeps trashed items by their hash only.
        val copy = full.map { if (it.deletedAt != null) it.copy(itemKey = null, data = null, dataSha256 = manifestDataHash(it.data!!)) else it }
        assertEquals(full, Manifests.rotationRows(copy, full))
        // A newer copy this phone kept instead of the older version served is what goes on, under the server's revision.
        val kept = ItemRevs.keptRow(row("a", "newer-on-the-phone", revision = 9), full[0], Manifests.serverHash(full[0]))
        val picked = Manifests.rotationRows(listOf(kept) + copy.drop(1), full)!!
        assertEquals("newer-on-the-phone", picked[0].data)
        assertEquals(kept.itemKey, picked[0].itemKey)
        assertEquals(4L, picked[0].revision)
        assertEquals(full.drop(1), picked.drop(1))
        // Anything else than the checked copy isn't re-encrypted: another version of an item, one more, one less,
        // one moved between the trash and the vault, a trashed item with other data, a row without its data.
        assertNull(Manifests.rotationRows(copy, listOf(row("a", "an-older-version")) + full.drop(1)))
        assertNull(Manifests.rotationRows(copy, full + row("z", "brought-back")))
        assertNull(Manifests.rotationRows(copy, full.drop(1)))
        assertNull(Manifests.rotationRows(copy, full.map { if (it.id == "c") it.copy(deletedAt = null) else it }))
        assertNull(Manifests.rotationRows(copy, full.map { if (it.id == "c") it.copy(data = "other") else it }))
        assertNull(Manifests.rotationRows(copy, full.map { if (it.id == "b") it.copy(data = null) else it }))
        assertNull(Manifests.rotationRows(copy, listOf(full[0], full[0], full[2])))
        assertNull("the kept copy stood for another served version", Manifests.rotationRows(listOf(kept.copy(servedSha256 = manifestDataHash("x"))) + copy.drop(1), full))
        assertNull(Manifests.rotationRows(copy.map { it.copy(dataSha256 = null) }, full))
        assertEquals(emptyList<SyncItem>(), Manifests.rotationRows(emptyList(), emptyList()))
    }

    // ------------------------------------------------------ emergency view

    /** The emergency client on a fake server, with the real core checking the vault's manifest. */
    private fun grantorView(s: Server, items: String): GrantorVault = runBlocking {
        val opened = object : OpenedVaultKey {
            override fun decryptMeta(vaultId: String, meta: String) = """{"name":"Personal"}"""
            override fun decryptItem(id: String, vaultId: String, key: String, data: String): String {
                if (key == "broken") throw io.passauth.core.CoreException.DecryptFailed("decrypt_failed")
                return ItemCodec.encode(Item(name = id))
            }
            override fun manifestMatches(vaultId: String, keyEpoch: Long, manifestSeq: Long, prev: String?, sealed: String?, itemsJson: String): Boolean =
                s.key.manifestVerify(vaultId, keyEpoch.toULong(), manifestSeq.toULong(), prev, sealed, null, null, null, itemsJson).status == "ok"
            override fun close() {}
        }
        val handle = object : EmergencyKeyHandle {
            override fun sealFor(contactKey: String, grantorId: String, grantId: String) = error("not used")
            override fun wrapVaultKey(vaultId: String) = error("not used")
            override fun openVaultKey(vaultId: String, wrapped: String): OpenedVaultKey = opened
            override fun close() {}
        }
        val crypto = object : EmergencyCrypto {
            override fun newEmergencyKey(grantId: String) = error("not used")
            override fun openEmergencyKey(grantId: String, wrapped: String) = error("not used")
            override fun sealRoster(json: String) = error("not used")
            override fun openRoster(sealed: String) = error("not used")
            override fun openSealedEmergencyKey(grantorId: String, grantId: String, sealed: String): EmergencyKeyHandle = handle
        }
        val v = s.header()
        val answer = Json.parseToJsonElement(
            """{"sealed_key":"sk","key_version":2,
                "grant":{"id":"g1","status":"approved","wait_days":7,"created_at":1,"updated_at":1,"key_version":2,
                         "grantor":{"id":"them","email":"them@example.com","name":"Them","public_key":"pk"},
                         "grantee":{"id":"me","email":"me@example.com","name":"Me","public_key":"pk2"}},
                "vaults":[{"id":"${v.id}","meta":"m","wrapped_key":"w","key_epoch":${v.keyEpoch},"manifest":"${v.manifest}","manifest_seq":${v.manifestSeq},"manifest_prev":"${v.manifestPrev}"}],
                "items":$items}""",
        )
        val env = object : EmergencyEnv {
            override suspend fun pin() = EmergencyAccount("record", "https://pa.example", "me")
            override suspend fun call(a: EmergencyAccount, path: String, body: kotlinx.serialization.json.JsonElement?, method: String, headers: Map<String, String>) = answer
            override suspend fun features(a: EmergencyAccount) = listOf(Emergency.FEATURE, Emergency.KEYS_FEATURE)
            override fun crypto(a: EmergencyAccount): EmergencyCrypto = crypto
            override fun unlocked(a: EmergencyAccount) = true
            override fun vaults(a: EmergencyAccount) = emptyList<VaultInfo>()
            override suspend fun reauth(a: EmergencyAccount, password: String) = error("not used")
            override suspend fun rotateVaultKeys(a: EmergencyAccount, ids: List<String>) = error("not used")
            override suspend fun sharedBefore(a: EmergencyAccount, vaultId: String) = false
            override suspend fun sync(a: EmergencyAccount) {}
            override fun setNotice(a: EmergencyAccount, text: String?) {}
            override suspend fun seenVersion(a: EmergencyAccount) = 0L
            override suspend fun trustedSealed(a: EmergencyAccount): String? = null
            override suspend fun remember(a: EmergencyAccount, version: Long, sealed: String?) {}
        }
        EmergencyClient(env).openGrantorVault("g1")
    }

    /** Review M2 (R5): the emergency view counts the rows it read and shows; a row it can't use or open is an item being hidden. */
    @Test
    fun theEmergencyViewWarnsWhenAnItemIsHiddenOrMisplacedBehindTheRecord() {
        val s = started()
        fun sent(id: String, extra: String) = """{"id":"$id","vault_id":"$vaultId"$extra}"""
        val a = sent("a", ""","item_key":"k","data":"data-a","deleted_at":null""")
        val b = sent("b", ""","item_key":"k","data":"data-b","deleted_at":null""")
        val c = sent("c", ""","item_key":"k","data":"data-c","deleted_at":100""")
        // As the grantor's vault is: no warning, every item shown (the trashed one as trashed).
        val honest = grantorView(s, "[$a,$b,$c]")
        assertTrue(honest.mismatched.isEmpty())
        assertEquals(listOf("a", "b", "c"), honest.items.map { it.id })
        assertEquals(0, honest.failed)
        // An item hidden behind its hash: the app can't show it, the record counts it → the warning.
        val hidden = grantorView(s, "[${sent("a", ""","data_sha256":"${manifestDataHash("data-a")}","deleted_at":null""")},$b,$c]")
        assertEquals(listOf("Personal"), hidden.mismatched)
        assertEquals(listOf("b", "c"), hidden.items.map { it.id })
        // The same without its key, with a key that opens nothing, or simply left out.
        assertEquals(listOf("Personal"), grantorView(s, "[${sent("a", ""","data":"data-a","deleted_at":null""")},$b,$c]").mismatched)
        val unopened = grantorView(s, "[${sent("a", ""","item_key":"broken","data":"data-a","deleted_at":null""")},$b,$c]")
        assertEquals(listOf("Personal"), unopened.mismatched)
        assertEquals(1, unopened.failed)
        assertEquals(listOf("Personal"), grantorView(s, "[$b,$c]").mismatched)
        // A deleted item shown as live: a field of the server's own ("trashed") says nothing; `deleted_at` alone counts.
        val revived = grantorView(s, "[$a,$b,${sent("c", ""","item_key":"k","data":"data-c","deleted_at":null,"trashed":true""")}]")
        assertEquals(listOf("Personal"), revived.mismatched)
        // A `deleted_at` that is no time, and a row that names no vault.
        for (noTime in listOf("0", "-4", "\"soon\"", "1.5", "true")) {
            assertEquals(noTime, listOf("Personal"), grantorView(s, "[$a,$b,${sent("c", ""","item_key":"k","data":"data-c","deleted_at":$noTime""")}]").mismatched)
        }
        assertEquals(listOf("Personal"), grantorView(s, """[$a,$b,$c,{"id":"x","item_key":"k","data":"d"}]""").mismatched)
        // The rows the core is given are built from the fields read, nothing else.
        assertEquals(
            """[{"id":"i","deleted_at":null,"data":"d"},{"id":"t","deleted_at":9,"data":"e"}]""",
            Emergency.manifestRows(listOf(GrantorItemRow("i", "v", "k", "d", null, 0), GrantorItemRow("t", "v", "k", "e", 9, 0))),
        )
    }

    // ------------------------------------------------------- numbers (R12)

    @Test
    fun numbersOutsideWhatEveryClientCountsWithAreNoAnswer() {
        fun answer(vault: String, item: String = "") = DeltaSync.parse("""{"revision":1,"vaults":[{"id":"v"$vault}],"items":[{"id":"a","vault_id":"v","item_key":"k","data":"d"$item}]}""")
        assertNotNull(SyncMerge.apply(answer(""","seq":9007199254740991,"manifest_seq":0,"key_epoch":3""", ""","deleted_at":5""")!!, null))
        for (bad in listOf(""","seq":9007199254740992""", ""","seq":9223372036854775807""", ""","seq":-1""", ""","manifest_seq":9007199254740992""", ""","manifest_seq":-2""", ""","key_epoch":-1""", ""","key_epoch":9007199254740992""")) {
            assertNull(bad, SyncMerge.apply(answer(bad)!!, null))
        }
        for (bad in listOf(""","deleted_at":-1""", ""","deleted_at":9007199254740992""")) assertNull(bad, SyncMerge.apply(answer("", bad)!!, null))
        // Fractions and text aren't numbers at all: the answer doesn't parse.
        for (bad in listOf(""","seq":1.5""", ""","manifest_seq":true""", ""","key_epoch":2.5""", ""","seq":"many"""")) assertNull(bad, answer(bad)?.let { SyncMerge.apply(it, null) })
        assertNull(answer("", ""","deleted_at":1.5""")?.let { SyncMerge.apply(it, null) })
        // The top of the range is still counted with, without overflow.
        assertEquals(SyncDecision.AfterWrite.Sync, SyncDecision.afterWrite(Manifests.MAX_NUMBER, Long.MAX_VALUE))
        assertThrows(UserException::class.java) {
            Manifests.rotationEntry(key(), SyncVault(vaultId, keyEpoch = epoch, manifest = "m", manifestSeq = Manifests.MAX_NUMBER, manifestPrev = ZERO), emptyList())
        }
    }

    // ------------------------------------------------------------ Part S

    @Test
    fun onlyServersThatSignSharesAreUsed() {
        assertTrue(ServerSupport.supported(listOf("delta_sync", "signed_sharing")))
        // API 2 without the feature, and a server from before API 2 (it lists nothing).
        assertFalse(ServerSupport.supported(listOf("delta_sync", "vault_manifest")))
        assertFalse(ServerSupport.supported(emptyList()))
        assertFalse(ServerSupport.supported(ServerConfig.parse(Json.parseToJsonElement("""{"name":"PassAuth"}""").jsonObject).features))
        assertFalse(ServerSupport.supported(ServerConfig.parse(Json.parseToJsonElement("""{"name":"PassAuth","api":2,"features":["key_epoch"]}""").jsonObject).features))
        val current = ServerConfig.parse(Json.parseToJsonElement("""{"name":"PassAuth","api":2,"features":["signed_sharing","vault_manifest"],"limits":{"max_import_items":250}}""").jsonObject)
        assertTrue(ServerSupport.supported(current.features))
        assertEquals(250, current.maxImportItems)
        assertNull(ServerConfig.parse(Json.parseToJsonElement("""{"limits":{"max_import_items":"250"}}""").jsonObject).maxImportItems)
        assertEquals("Update your PassAuth server to keep using this app.", ServerTooOldException().message)
    }

    /** Review H2 (R10): a server can't get around the check by breaking its own `/api/config`. */
    @Test
    fun aServerWhoseConfigCannotBeReadIsOnlyUsedWithAListKeptFromBefore() {
        val signed = listOf("delta_sync", "signed_sharing")
        // Asked and answered: the answer decides, whatever was kept.
        assertEquals(signed, ServerSupport.decide(signed, null))
        assertFalse(ServerSupport.supported(ServerSupport.decide(listOf("delta_sync"), signed)))
        // Can't be asked now: the list kept from before decides (offline use goes on; a list without the feature stays refused).
        assertTrue(ServerSupport.supported(ServerSupport.decide(null, signed)))
        assertFalse(ServerSupport.supported(ServerSupport.decide(null, listOf("delta_sync"))))
        // Nothing kept and nothing answered (a new phone, or a record reset after its account was deleted): can't connect.
        val e = assertThrows(UserException::class.java) { ServerSupport.decide(null, null) }
        assertFalse(e is ServerTooOldException)
        assertEquals(ServerSupport.CANT_CONNECT, e.message)
    }

    @Test
    fun theWordsAreTheOnesEveryAppUses() {
        assertEquals("Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date.", Manifests.WARNING)
        assertEquals("Use the server's copy", Manifests.USE_SERVER_COPY)
        assertEquals("Use the server's copy?", Manifests.CONFIRM_TITLE)
        assertEquals(
            "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. Do this only if you know why it changed, for example after the server was restored from a backup.",
            Manifests.CONFIRM_BODY,
        )
        assertEquals("Someone who can edit this vault can review it.", Manifests.READERS)
        assertEquals("This can't be done until every member's apps are up to date.", Manifests.NOT_READY)
        assertEquals("vault_manifest", Manifests.FEATURE)
        assertEquals(3, Manifests.ATTEMPTS)
        assertNotNull(Manifests.answered(buildJsonObject { put("manifest_seq", 0) }))
    }
}
