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
        var manifestPuts = 0

        /** Baselines stored within the hour (10 are taken, then 429). */
        var baselines = 0

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
            return answer()
        }

        /** What every write answers: the vault's number, and its manifest's version and link after the request (null: none). */
        fun answer(): JsonObject = buildJsonObject {
            put("revision", 9); put("vault_seq", seq); put("manifest_seq", manifestSeq)
            put("manifest_link", if (manifestSeq > 0) kotlinx.serialization.json.JsonPrimitive(link()) else kotlinx.serialization.json.JsonNull)
        }

        /**
         * `POST /items`: a create whose item is already stored exactly like this (an earlier attempt
         * got through, only its answer was lost) answers 200 again, stores no manifest and needs none.
         */
        fun create(sent: List<ManifestEntry>, item: SyncItem): JsonObject {
            if (rows.any { it.id == item.id && it.data == item.data && it.itemKey == item.itemKey }) {
                requests++
                return answer()
            }
            if (rows.any { it.id == item.id }) throw ApiException(409, "item_exists", "x")
            return write(sent) { it + item }
        }

        /** `DELETE /items/{id}/permanent` (live or trashed) as the app asks for it ([Manifests.deletePath]). */
        fun deletePermanent(path: String): JsonObject {
            val (resource, query) = path.split("?", limit = 2).let { it[0] to it.getOrElse(1) { "" } }
            val id = java.net.URLDecoder.decode(resource.removePrefix("/items/").removeSuffix("/permanent"), "UTF-8")
            val q = query.split("&").filter { it.isNotEmpty() }.associate { it.substringBefore("=") to java.net.URLDecoder.decode(it.substringAfter("="), "UTF-8") }
            val row = rows.firstOrNull { it.id == id } ?: throw ApiException(404, "not_found", "x")
            if (q["revision"]?.toLong() != row.revision) throw ApiException(409, "revision_conflict", "x")
            val sent = q["manifest"]?.let { ManifestEntry(vault, q.getValue("manifest_seq").toLong(), q.getValue("manifest_prev"), it, "") }
            return write(listOfNotNull(sent)) { r -> r.filter { it.id != id } }
        }

        /**
         * `PUT /vaults/{id}/manifest`: a first manifest or a baseline, always exactly one version above
         * the current one (round 2: no jumps); a member's eleventh stored baseline within the hour is a 429.
         */
        fun putManifest(body: JsonObject): JsonObject {
            manifestPuts++
            val to = body["seq"]!!.jsonPrimitive.long
            val base = body["base_seq"]!!.jsonPrimitive.long
            if (to != base + 1) throw ApiException(400, "bad_request", "seq")
            if (base != manifestSeq || body["vault_seq"]!!.jsonPrimitive.long != seq) throw ApiException(409, "manifest_conflict", "x")
            if (body["prev"]!!.jsonPrimitive.content != link()) throw ApiException(409, "manifest_conflict", "built on another manifest")
            if (base > 0 && baselines >= 10) throw ApiException(429, "rate_limited", "Too many requests", retryAfter = 1800)
            if (base > 0) baselines++
            store(ManifestEntry(vault, to, body["prev"]!!.jsonPrimitive.content, body["sealed"]!!.jsonPrimitive.content, ""))
            seq++
            return answer()
        }

        /** The server's admin restores a backup: the vault as it was in [earlier]. */
        fun restore(earlier: Server) {
            rows = earlier.rows; seq = earlier.seq; manifestSeq = earlier.manifestSeq; manifest = earlier.manifest; manifestPrev = earlier.manifestPrev; log = earlier.log
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
        val (body, entry) = Manifests.startBody(s.key, s.header(), s.rows)!!
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

    /** Review M (R5) and rule S2: an item the app can't open behind a manifest that counts it warns the vault, with its own way out. */
    @Test
    fun anItemThatDoesNotOpenBehindAPassingManifestWarnsTheVaultWithItsOwnWayOut() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        // The rows count (a corrupted `item_key` changes nothing the manifest covers), but one live item doesn't open.
        val whole = judge(listOf(s.header()), s.rows, keys, emptyMap(), whole = true, hidden = setOf(vaultId))
        assertEquals(ManifestState.Unopenable, whole.states[vaultId])
        assertEquals(setOf(vaultId), whole.unopenable)
        assertTrue("it isn't a manifest that doesn't match: \"Use the server's copy\" has nothing to do here", whole.failed.isEmpty() && whole.acceptable.isEmpty())
        assertEquals("what the core checked is remembered", s.mark(), whole.remember[vaultId])
        // The row doesn't open in any answer: the same from a delta or the stored copy, and nothing is fetched again for it.
        val delta = judge(listOf(s.header()), s.rows, keys, emptyMap(), whole = false, hidden = setOf(vaultId))
        assertEquals(ManifestState.Unopenable, delta.states[vaultId])
        assertTrue(delta.undecided.isEmpty())
        // A manifest that doesn't match as well is that first.
        assertEquals(ManifestState.Unresolved, judge(listOf(s.header()), s.rows.drop(1), keys, emptyMap(), whole = true, hidden = setOf(vaultId)).states[vaultId])
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
        // Joined one version later: nothing can lie between the two, so a predecessor that isn't what this
        // phone remembers is a mismatch at once (round 2: no log is asked for).
        forked.otherDevice(emptyList(), listOf(row("more1", "data-more1")))
        assertEquals("mismatch", forked.status(remembered))
        assertEquals(ManifestState.Unresolved, forked.judged(remembered).states[vaultId])
        assertEquals(0, forked.logRequests)
        // Two versions later only the log can say, and the branch's own log doesn't lead back to this phone's manifest.
        forked.otherDevice(emptyList(), listOf(row("more2", "data-more2")))
        assertEquals("need_log", forked.status(remembered))
        j = forked.judged(remembered)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        assertTrue(j.remember.isEmpty())
        assertEquals(1, forked.logRequests)
        // The server's entries go to the core as they came; rubbish among them (round 2) changes nothing either way.
        val rubbish = """[null,7,"x",[],{"seq":"2"},{"seq":3.5,"prev":1,"digest":null},""" + forked.log.joinToString(",") + "]"
        assertEquals("mismatch", Manifests.verify(forked.key, forked.header(), remembered, forked.rows, rubbish).status)
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
        val honest = """[null,"x",{"seq":1},""" + s.log.joinToString(",") + """,{"seq":99,"prev":7,"digest":[]}]"""
        assertEquals("rubbish around the real entries is skipped", "ok", Manifests.verify(s.key, s.header(), remembered, s.rows, honest).status)
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
        // The entries are handed on as they came, malformed ones included; paging goes by the highest version among the well-formed.
        val pages = listOf("""{"entries":[{"seq":2,"prev":"p","digest":"d"},null,{"seq":"9"},{"seq":3.0,"prev":1}],"more":true}""", """{"entries":[{"seq":4,"prev":"p","digest":"d"}],"more":false}""")
        val froms = mutableListOf<Long>()
        val all = runBlocking { Manifests.fetchLog(1) { from -> froms += from; Json.parseToJsonElement(pages[froms.size - 1]) } }
        assertEquals(listOf(1L, 2L), froms)
        assertEquals("""[{"seq":2,"prev":"p","digest":"d"},null,{"seq":"9"},{"seq":3.0,"prev":1},{"seq":4,"prev":"p","digest":"d"}]""", all)
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
        val stale = Manifests.startBody(s.key, s.header().copy(manifestPrev = ZERO), s.rows)!!.first
        assertTrue(Manifests.isConflict(assertThrows(ApiException::class.java) { s.putManifest(stale) }))
        // And is always exactly one version above it (round 2): the server takes nothing else, and the app never builds anything else.
        val next = Manifests.startBody(s.key, s.header(), s.rows)!!.first
        assertEquals(s.manifestSeq + 1, next["seq"]!!.jsonPrimitive.long)
        assertEquals(400, assertThrows(ApiException::class.java) { s.putManifest(JsonObject(next + ("seq" to kotlinx.serialization.json.JsonPrimitive(s.manifestSeq + 2)))) }.status)
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
        fun mem(vararg e: Pair<String, ManifestMark>) = e.associate { it.first to Remembered(it.second) }
        val m = mem("a" to ManifestMark(3, l1), "gone" to ManifestMark(9, l1))
        assertEquals(mem("a" to ManifestMark(4, l2), "gone" to ManifestMark(9, l1), "b" to ManifestMark(1, l2)), Manifests.merged(m, mapOf("a" to ManifestMark(4, l2), "b" to ManifestMark(1, l2))))
        // Never lowered; at the same version the link already there stays; half a mark, or the all-zero link, is no mark.
        assertEquals(m, Manifests.merged(m, mapOf("a" to ManifestMark(2, l2), "gone" to ManifestMark(9, l2), "zero" to ManifestMark(0, l2), "nolink" to ManifestMark(5, "short"), "first" to ManifestMark(5, ZERO))))
        assertEquals(m, Manifests.decodeMemory(Manifests.encodeMemory(m)))
        assertEquals(mapOf("a" to ManifestMark(3, l1), "gone" to ManifestMark(9, l1)), Manifests.marks(m))
        // The first version's bare numbers, a version without a link, a link that isn't one or is all zero: nothing remembered.
        assertEquals(
            mem("ok" to ManifestMark(1, l1)),
            Manifests.decodeMemory("""{"ok":{"version":1,"link":"$l1"},"old":7,"half":{"version":2},"other":{"link":"$l1"},"bad":{"version":2,"link":"x"},"zero":{"version":0,"link":"$l1"},"s":{"version":"2","link":"$l1"},"f":{"version":1.5,"link":"$l1"},"z":{"version":3,"link":"$ZERO"}}"""),
        )
        assertEquals(emptyMap<String, Remembered>(), Manifests.decodeMemory("""{"a":3,"b":9}"""))
        assertEquals(emptyMap<String, Remembered>(), Manifests.decodeMemory("not json"))
        assertEquals(emptyMap<String, Remembered>(), Manifests.decodeMemory(null))
        assertTrue(Manifests.isLink(l1) && Manifests.isLink(ZERO))
        assertFalse(Manifests.isLink(l1 + "A") || Manifests.isLink(l1.dropLast(1) + "=") || Manifests.isLink(null))
        assertEquals(ZERO, Manifests.ZERO_LINK)
        assertTrue(Manifests.isMark(ManifestMark(1, l1)))
        assertFalse(Manifests.isMark(ManifestMark(1, ZERO)) || Manifests.isMark(ManifestMark(0, l1)) || Manifests.isMark(null))
    }

    /** Round 2, contract §3: an acceptance replaces the memory (also downwards), and a copy from before it never brings the old mark back. */
    @Test
    fun anAcceptanceReplacesTheMemoryAndAStaleCopyNeverBringsTheOldMarkBack() {
        val high = ManifestMark(50, manifestDataHash("fifty"))
        val low = ManifestMark(40, manifestDataHash("forty"))
        val before = mapOf("v" to Remembered(high), "w" to Remembered(ManifestMark(2, manifestDataHash("w"))))
        // Replace: whatever was stored, also a higher version; the counter goes up.
        val after = Manifests.replaced(before, "v", low)
        assertEquals(Remembered(low, 1), after["v"])
        assertEquals(before["w"], after["w"])
        // A copy of the memory from before the acceptance (the higher version) loses when the two are brought together, either way round.
        assertEquals(after, Manifests.joined(after, before))
        assertEquals(after, Manifests.joined(before, after))
        // With as many acceptances the higher version wins, and at the same version what is stored stays.
        val ahead = mapOf("v" to Remembered(ManifestMark(41, manifestDataHash("forty-one")), 1))
        assertEquals(ahead["v"], Manifests.joined(after, ahead)["v"])
        assertEquals(ahead["v"], Manifests.joined(ahead, after)["v"])
        val other = mapOf("v" to Remembered(ManifestMark(40, manifestDataHash("another forty")), 1))
        assertEquals(after["v"], Manifests.joined(after, other)["v"])
        // Ordinary advance keeps the counter and never lowers.
        assertEquals(Remembered(ManifestMark(41, high.link), 1), Manifests.merged(after, mapOf("v" to ManifestMark(41, high.link)))["v"])
        assertEquals(after, Manifests.merged(after, mapOf("v" to ManifestMark(39, high.link))))
        // Forget (the server shows no manifest): no mark, but the counter survives the stored text, so the old copy still loses.
        val forgotten = Manifests.replaced(after, "v", null)
        assertEquals(Remembered(null, 2), forgotten["v"])
        assertNull(Manifests.marks(forgotten)["v"])
        val read = Manifests.decodeMemory(Manifests.encodeMemory(forgotten))
        assertEquals(forgotten, read)
        assertEquals(forgotten, Manifests.joined(read, before))
        assertEquals("accepts is read where it is and counts 0 where it isn't", mapOf("x" to Remembered(low, 3), "y" to Remembered(low, 0)),
            Manifests.decodeMemory("""{"x":{"version":40,"link":"${low.link}","accepts":3},"y":{"version":40,"link":"${low.link}","accepts":"3"}}"""))
        // A first manifest may be started again once the memory is forgotten.
        assertNull(forgotten["v"]?.mark)
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
            val seven = mapOf("v" to Remembered(ManifestMark(7, link)))
            assertTrue(file.write { had -> assertNull(had); Manifests.encodeMemory(seven) })
            assertEquals(seven, Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text))
            // The Keystore fails for a moment: unknown, not "nothing remembered"; a write is refused and the file is untouched.
            broken = true
            assertEquals(SealedFile.Read.Unreadable, file.read())
            var asked = false
            assertFalse(file.write { asked = true; Manifests.encodeMemory(emptyMap()) })
            assertFalse("nothing is merged into what can't be read", asked)
            broken = false
            assertEquals(seven, Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text))
            assertFalse("a file that reads is never moved aside", file.setAside())
            // A write merges with what the file holds.
            assertTrue(file.write { had -> Manifests.encodeMemory(Manifests.merged(Manifests.decodeMemory(had), mapOf("w" to ManifestMark(1, link)))) })
            assertEquals(setOf("v", "w"), Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text).keys)
            file.delete()
            assertEquals(SealedFile.Read.Missing, file.read())
        } finally {
            dir.deleteRecursively()
        }
    }

    /** Rule S4 (rereview-mobile F4): unreadable memory has a way out, and doesn't speak of a warning nobody sees. */
    @Test
    fun unreadableMemoryIsOfferedAResetAfterThreeFailedReadsAcrossASync() {
        var t = UnreadableMemory()
        assertFalse(t.offerReset)
        t = t.failed(synced = false)   // the copy shown at unlock
        t = t.failed(synced = false)
        t = t.failed(synced = false)
        assertFalse("never before a sync with the server finished", t.offerReset)
        t = t.failed(synced = true)
        assertTrue(t.offerReset)
        assertFalse("twice isn't again and again", UnreadableMemory().failed(true).failed(true).offerReset)
        assertTrue(UnreadableMemory().failed(false).failed(true).failed(false).offerReset)
        assertEquals("PassAuth can't read this device's record of your vaults.", Manifests.MEMORY_UNREADABLE)
        assertEquals("Reset on this device", Manifests.RESET_MEMORY)
        assertEquals("PassAuth will trust what your server shows now and start a new record on this device.", Manifests.RESET_MEMORY_CONFIRM)
        assertFalse("no warning shows, so the refusal doesn't speak of one", Manifests.UNCHECKED.contains("warning"))

        // The reset: the record that doesn't open is moved aside, and the phone goes on as one that remembers nothing.
        val dir = java.nio.file.Files.createTempDirectory("pa-reset").toFile()
        try {
            var broken = false
            val file = SealedFile(java.io.File(dir, "acct.manifests"), seal = { it.reversedArray() }, open = { if (broken) throw java.security.GeneralSecurityException("corrupt") else it.reversedArray() })
            val s = started()
            assertTrue(file.write { Manifests.encodeMemory(mapOf(vaultId to Remembered(ManifestMark(9, manifestDataHash("gone"))))) })
            broken = true
            assertEquals(SealedFile.Read.Unreadable, file.read())
            assertTrue(file.setAside())
            assertEquals(SealedFile.Read.Missing, file.read())
            assertTrue("kept beside it, not destroyed", java.io.File(dir, "acct.manifests.unreadable").exists())
            // What the server shows now is trusted and a new record starts.
            val memory = Manifests.decodeMemory(null)
            val j = s.judged(Manifests.marks(memory)[vaultId])
            assertEquals(ManifestState.Ok, j.states[vaultId])
            assertTrue(file.write { had -> Manifests.encodeMemory(Manifests.merged(Manifests.decodeMemory(had), j.remember)) })
            broken = false
            assertEquals(s.mark(), Manifests.marks(Manifests.decodeMemory((file.read() as SealedFile.Read.Text).text))[vaultId])
            file.delete()
            assertFalse(java.io.File(dir, "acct.manifests.unreadable").exists())
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
        to.putManifest(Manifests.startBody(to.key, to.header(), to.rows)!!.first)
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
        assertFalse(Manifests.stored(null, answer) || Manifests.stored(m.copy(link = manifestDataHash("another sealing")), answer))
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
        // Another manifest in the answer (someone wrote right after), none at all, the version without its link (a server
        // from before round 2), a link that isn't text, or an entry for another vault: sync instead.
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("vault_seq", 7); put("manifest_seq", m.seq + 1); put("manifest_link", manifestDataHash("later")) }))
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("vault_seq", 7) }))
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("vault_seq", 7); put("manifest_seq", m.seq) }))
        assertFalse(Manifests.mayApplyLocally(m, buildJsonObject { put("manifest_seq", m.seq); put("manifest_link", 5) }))
        assertTrue(Manifests.mayApplyLocally(m, buildJsonObject { put("manifest_seq", m.seq); put("manifest_link", m.link) }))
        assertEquals(m.link, Manifests.answeredLink(answer))
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
        s.putManifest(Manifests.startBody(s.key, s.header(), s.rows)!!.first)
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
        assertFalse("a row of it doesn't open (rule S2: deleted first)", Manifests.mayStart(v, ManifestState.None, Role.Owner, true, null, s.rows, unopenable = true))
        assertNull(Manifests.startBody(s.key, v.copy(seq = null), s.rows))
        // Started: version 1 for exactly these rows.
        val (body, entry) = Manifests.startBody(s.key, v, s.rows)!!
        val answer = s.putManifest(body)
        assertEquals(1L, entry.seq)
        assertTrue(Manifests.mayApplyLocally(entry, answer))
        assertEquals("ok", s.status())
        assertTrue(Manifests.isNotReady(ApiException(409, "manifest_not_ready", "x")))
        assertFalse(Manifests.isConflict(ApiException(409, "manifest_not_ready", "x")))
        assertTrue(Manifests.isConflict(ApiException(400, "manifest_required", "x")) && Manifests.isConflict(ApiException(409, "manifest_conflict", "x")))
        assertFalse(Manifests.isConflict(ApiException(409, "revision_conflict", "x")))
    }

    /**
     * What VaultRepository does with a phone's copies and memory, with the same pure pieces
     * ([CopyFiles], [DeltaSync.refresh], [Manifests.judge], [Manifests.adoptable], the memory
     * operations), so the rules can be run here against the stand-in server.
     */
    private inner class Phone(val s: Server, dir: File, val role: Role = Role.Owner) {
        val files = CopyFiles(dir, seal = { it.reversedArray() }, open = { it.reversedArray() })
        var memory = mapOf<String, Remembered>()
        val keys = mapOf(vaultId to s.key)
        val bundle = JsonObject(emptyMap())
        var state: ManifestState? = null
        var acceptable = false

        /** The server shows no manifest for the vault this phone remembers one of: the warning's confirmation is [Manifests.CONFIRM_NO_RECORD]. */
        var noRecord = false

        /** The vault's quiet note ([Manifests.NOT_CHECKED]), as VaultRepository.show derives it. */
        val notChecked: Boolean get() = state == ManifestState.None && memory[vaultId]?.let { it.notChecked && it.mark == null } == true

        fun checkedCopy(): SyncSnapshot? = files.readChecked("acct")?.let { SyncSnapshot.decode(it) }

        /** A foreground sync: the server's whole answer judged with the keys, then stored as the checked copy and remembered. */
        fun sync(hidden: Set<String> = emptySet()): ManifestState {
            val snap = s.snapshot().copy(bundle = bundle)
            val j = runBlocking { Manifests.judge(snap.vaults, snap.items, keys, Manifests.marks(memory), whole = true, hidden = hidden, log = s.logSource()) }
            memory = Manifests.merged(memory, j.remember)
            state = j.states.getValue(vaultId)
            acceptable = vaultId in j.acceptable
            noRecord = vaultId in j.noRecord
            files.writeChecked("acct", snap.copy(unresolved = if (state == ManifestState.Unresolved) listOf(vaultId) else emptyList()).encode())
            return state!!
        }

        /** The WorkManager refresh while the account is locked: no keys, so [answer] can't be checked. */
        fun backgroundRefresh(answer: SyncSnapshot = s.snapshot()) = runBlocking {
            val cached = (files.readRefreshed("acct") ?: files.readChecked("acct"))?.let { SyncSnapshot.decode(it) }
            val r = DeltaSync.refresh(cached, delta = false, trashSummary = true) { answer.copy(bundle = bundle).encode() }
            if (r is DeltaSync.CacheRefresh.Write) files.writeRefreshed("acct", r.snapshot.encode())
            r
        }

        /**
         * The next unlock (the app, the autofill service, the credential provider: one repository):
         * the checked copy is opened; what the refresh left is judged with the keys and taken or dropped.
         * Returns the rows shown and filled from. [rolledBack]: an item came older than remembered (the item edit counters).
         */
        fun unlock(rolledBack: Boolean = false): List<SyncItem> {
            val checked = checkedCopy()!!
            var shown = checked
            val next = files.readRefreshed("acct")?.let { SyncSnapshot.decode(it) }
            if (next != null) {
                val j = runBlocking { Manifests.judge(next.vaults, next.items, keys, Manifests.marks(memory), whole = false, log = null) }
                if (next.revision >= checked.revision && Manifests.adoptable(j, rolledBack)) {
                    memory = Manifests.merged(memory, j.remember)
                    files.writeChecked("acct", next.encode())
                    shown = next
                }
                files.dropRefreshed("acct")
            }
            return shown.items
        }

        /** "Use the server's copy", confirmed: one fresh whole answer, then accept on this phone or write a baseline. Returns what was done. */
        fun useServerCopy(noRecord: Boolean = this.noRecord): Manifests.ServerCopy? {
            if (sync() != ManifestState.Unresolved) return null
            val plan = Manifests.serverCopy(s.key, s.header(), role, s.rows)
            // Rule T3: only the case the user confirmed is carried out.
            if (!Manifests.asConfirmed(plan, noRecord)) throw UserException(Manifests.SERVER_COPY_CHANGED)
            when (plan) {
                is Manifests.ServerCopy.Accept -> memory = Manifests.replaced(memory, vaultId, plan.mark)
                // Forgotten only on the confirmation that says so; then marked "not checked".
                Manifests.ServerCopy.Forget -> memory = Manifests.replaced(memory, vaultId, null, notChecked = true)
                is Manifests.ServerCopy.Baseline -> {
                    val answer = s.putManifest(plan.body)
                    if (Manifests.stored(plan.entry, answer)) memory = Manifests.replaced(memory, vaultId, plan.entry.mark)
                }
                else -> return plan
            }
            sync()
            return plan
        }
    }

    private fun <T> withDir(block: (File) -> T): T {
        val dir = java.nio.file.Files.createTempDirectory("pa-copies").toFile()
        try {
            return block(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * Rule S1 (rereview-mobile F3): the server was restored from a backup. Every role accepts the older,
     * consistent state on its own phone: the memory is replaced (downwards) and nothing is sent.
     */
    @Test
    fun aRestoredBackupIsAcceptedOnThisPhoneAloneByAReaderToo() = withDir { dir ->
        val s = started()
        s.otherDevice(emptyList(), listOf(row("n1", "data-n1")))
        val backup = s.fork()
        repeat(3) { n -> s.otherDevice(emptyList(), listOf(row("later$n", "data-later$n"))) }
        for (role in listOf(Role.Read, Role.Write, Role.Owner)) {
            val phone = Phone(s.fork(), File(dir, role.name), role)
            assertEquals(ManifestState.Ok, phone.sync())
            assertEquals(5L, phone.memory.getValue(vaultId).mark!!.version)
            // The admin restores the backup: the vault at version 2, which this phone is ahead of.
            phone.s.restore(backup)
            assertEquals("rollback", phone.s.status(phone.memory.getValue(vaultId).mark))
            assertEquals(ManifestState.Unresolved, phone.sync())
            assertTrue("what the server shows adds up, so this phone alone can accept it", phone.acceptable)
            assertEquals(5L, phone.memory.getValue(vaultId).mark!!.version)
            val requests = phone.s.requests
            val puts = phone.s.manifestPuts
            val plan = phone.useServerCopy()
            assertEquals(Manifests.ServerCopy.Accept(backup.mark()), plan)
            assertEquals("no request to PUT …/manifest, no write at all", puts, phone.s.manifestPuts)
            assertEquals(requests, phone.s.requests)
            assertEquals("the memory is replaced, also downwards", Remembered(backup.mark(), 1), phone.memory[vaultId])
            assertEquals(ManifestState.Ok, phone.state)
            assertTrue(phone.checkedCopy()!!.unresolved.isEmpty())
            // From there the vault goes on as usual: the next write is followed without a log.
            phone.s.otherDevice(emptyList(), listOf(row("after", "data-after")))
            assertEquals(ManifestState.Ok, phone.sync())
            assertEquals(0, phone.s.logRequests)
            assertEquals(Remembered(phone.s.mark(), 1), phone.memory[vaultId])
        }
    }

    /** Rule S1: the server shows no manifest any more (a backup from before the vault's first one): the memory is forgotten, by any role. */
    @Test
    fun aVaultTheServerShowsWithoutAManifestIsAcceptedByForgetting() = withDir { dir ->
        val s = started()
        val phone = Phone(s, dir, Role.Read)
        assertEquals(ManifestState.Ok, phone.sync())
        s.manifest = null; s.manifestSeq = 0; s.manifestPrev = null; s.log = emptyList()
        assertEquals("rollback", s.status(phone.memory.getValue(vaultId).mark))
        assertEquals(ManifestState.Unresolved, phone.sync())
        assertTrue(phone.acceptable)
        // Review round 3, rule T3: this acceptance has its own confirmation, and isn't done on the ordinary one.
        assertTrue("the warning offers the \"no record\" text", phone.noRecord)
        val before = phone.memory
        assertEquals(
            "The server's copy of this vault changed just now, so it wasn't accepted. Check what the app shows now.",
            assertThrows(UserException::class.java) { phone.useServerCopy(noRecord = false) }.message,
        )
        assertEquals("nothing was forgotten on the ordinary confirmation", before, phone.memory)
        assertEquals(ManifestState.Unresolved, phone.state)
        assertTrue("the warning still offers the \"no record\" text", phone.noRecord)
        // The other way round (final review C5): "no record" confirmed, the fresh answer has a record: nothing accepted or sent.
        val mark = phone.memory.getValue(vaultId).mark!!
        val header = s.header()
        assertFalse(Manifests.asConfirmed(Manifests.ServerCopy.Accept(mark), noRecord = true))
        assertFalse(Manifests.asConfirmed(Manifests.ServerCopy.Baseline(kotlinx.serialization.json.JsonObject(emptyMap()), ManifestEntry(header.id, 1, "", "", "")), noRecord = true))
        assertTrue(Manifests.asConfirmed(Manifests.ServerCopy.Accept(mark), noRecord = false))
        assertTrue(Manifests.asConfirmed(Manifests.ServerCopy.Readers, noRecord = true))
        assertTrue(Manifests.asConfirmed(Manifests.ServerCopy.Broken, noRecord = false))
        assertEquals(Manifests.ServerCopy.Forget, phone.useServerCopy())
        assertEquals(Remembered(null, 1, notChecked = true), phone.memory[vaultId])
        assertEquals(ManifestState.None, phone.state)
        assertTrue("the vault says it isn't being checked", phone.notChecked)
        // The marker is kept with the memory (a restart still says it)…
        val stored = Manifests.encodeMemory(phone.memory)
        assertTrue(stored.contains("\"not_checked\":true"))
        assertEquals(phone.memory, Manifests.decodeMemory(stored))
        assertEquals("and an older copy of the memory doesn't bring the mark back", phone.memory, Manifests.joined(phone.memory, before))
        // A first manifest may be started again by the ordinary rule (by someone who can write).
        assertTrue(Manifests.mayStart(s.header(), ManifestState.None, Role.Owner, true, phone.memory[vaultId]?.mark, s.rows))
        s.putManifest(Manifests.startBody(s.key, s.header(), s.rows)!!.first)
        // …until a manifest exists again: checked, remembered, and the note is gone for good.
        assertEquals(ManifestState.Ok, phone.sync())
        assertFalse(phone.notChecked)
        assertEquals(Remembered(s.mark(), 1), phone.memory[vaultId])
        assertFalse(Manifests.encodeMemory(phone.memory).contains("not_checked"))
        // The marker never rides on an entry that has a mark, and an ordinary acceptance doesn't set it.
        assertEquals(Remembered(s.mark(), 1), Manifests.decodeMemory("""{"$vaultId":{"version":${s.manifestSeq},"link":"${s.link()}","accepts":1,"not_checked":true}}""")[vaultId])
        assertEquals(Remembered(s.mark(), 2), Manifests.replaced(phone.memory, vaultId, s.mark(), notChecked = true)[vaultId])
        assertEquals(Remembered(null, 2), Manifests.replaced(phone.memory, vaultId, null)[vaultId])
        assertEquals(mapOf(vaultId to Remembered(null, 0, notChecked = true)), Manifests.decodeMemory("""{"$vaultId":{"not_checked":true}}"""))
    }

    /** Rule T3: an accepted restore whose manifest is there is the ordinary case: no "no record" text, no note afterwards. */
    @Test
    fun anAcceptedRestoreWithAManifestIsNotMarkedUnchecked() = withDir { dir ->
        val s = started()
        val backup = s.fork()
        s.otherDevice(emptyList(), listOf(row("n", "data-n")))
        val phone = Phone(s, dir)
        assertEquals(ManifestState.Ok, phone.sync())
        s.restore(backup)
        assertEquals(ManifestState.Unresolved, phone.sync())
        assertTrue(phone.acceptable)
        assertFalse(phone.noRecord)
        assertTrue(phone.useServerCopy() is Manifests.ServerCopy.Accept)
        assertFalse(phone.notChecked)
        assertEquals(Remembered(backup.mark(), 1), phone.memory[vaultId])
    }

    /**
     * Review round 3, rule T2: a restored server answers with a lower revision (and lower vault
     * numbers) than the copy shown. That is never dropped as "stale": the revision check asks for a
     * sync, the answer is taken as it is, judged (the rollback is reported) and "Use the server's
     * copy" accepts it without a request.
     */
    @Test
    fun aLowerRevisionAfterARestoreIsFetchedAndJudgedNotDropped() = withDir { dir ->
        val s = started()
        s.otherDevice(emptyList(), listOf(row("n1", "data-n1")))
        val backup = s.fork()
        repeat(2) { n -> s.otherDevice(emptyList(), listOf(row("later$n", "data-later$n"))) }
        val phone = Phone(s, dir)
        assertEquals(ManifestState.Ok, phone.sync())
        val have = phone.checkedCopy()!!
        // A real restore: the database file of the backup, so the revision and the vault's number go down with the items.
        s.restore(backup)
        assertTrue(s.snapshot().revision < have.revision)
        assertTrue("the revision check sees a server that is behind", SyncDecision.isStale(s.snapshot().revision, mapOf(vaultId to s.seq), have.position))
        // The sync that follows: whatever the server sends is applied; a lower revision is no reason to keep the copy.
        val next = runBlocking { DeltaSync.fetch(have, delta = true, trashSummary = true) { s.snapshot().encode() } }
        assertEquals(s.snapshot().revision, next.revision)
        assertEquals(s.rows.map { it.id }.toSet(), next.items.map { it.id }.toSet())
        assertTrue(next.whole)
        val delta = SyncMerge.apply(SyncResponse(revision = kotlinx.serialization.json.JsonPrimitive(s.snapshot().revision), vaults = listOf(s.header()), items = emptyList(), delta = true), have)
        assertEquals("a delta with a lower revision is applied too (and then judged)", s.snapshot().revision, delta!!.revision)
        // Judged like any whole answer: the rollback is reported, and what the server shows can be accepted.
        val j = judge(next.vaults, next.items, phone.keys, Manifests.marks(phone.memory), whole = next.whole)
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        assertEquals(setOf(vaultId), j.acceptable)
        assertTrue(j.noRecord.isEmpty())
        assertEquals("the same through the phone's sync", ManifestState.Unresolved, phone.sync())
        val puts = s.manifestPuts
        val requests = s.requests
        assertEquals(Manifests.ServerCopy.Accept(backup.mark()), phone.useServerCopy())
        assertEquals(ManifestState.Ok, phone.state)
        assertEquals("no PUT …/manifest and no other write", puts to requests, s.manifestPuts to s.requests)
    }

    /** Final review N6: an item-counter or trash-time file that alone can't be read counts as unreadable memory and gets the reset. */
    @Test
    fun anUnreadableCounterOrTrashFileAloneAlsoLeadsToTheReset() {
        assertTrue(UnreadableMemory.readable(manifests = true, revs = true, trashSeen = true))
        assertFalse(UnreadableMemory.readable(manifests = false, revs = true, trashSeen = true))
        assertFalse("the item edit counters alone", UnreadableMemory.readable(manifests = true, revs = false, trashSeen = true))
        assertFalse("the trash times alone", UnreadableMemory.readable(manifests = true, revs = true, trashSeen = false))
        for (file in listOf("revs", "trashseen")) {
            val readable = UnreadableMemory.readable(manifests = true, revs = file != "revs", trashSeen = file != "trashseen")
            // Shown from the copy, synced, synced again: three failed reads across a finished sync.
            var t = UnreadableMemory.after(null, readable, synced = false)
            assertFalse(t!!.offerReset)
            t = UnreadableMemory.after(t, readable, synced = true)
            assertFalse(t!!.offerReset)
            t = UnreadableMemory.after(t, readable, synced = true)
            assertTrue("$file alone: \"Reset on this device\" is offered", t!!.offerReset)
            // One read that works (after the reset moved the file aside) starts over.
            assertNull(UnreadableMemory.after(t, readable = true, synced = true))
        }
        assertNull(UnreadableMemory.after(null, readable = true, synced = false))
    }

    /**
     * Review round 3, rule T4 and final review N7: "Use the server's copy" drops the kept newer copies
     * and the edit counters of the vault's items as this phone's own copy has them, and of no id that
     * only the answer fetched for the acceptance places in that vault.
     */
    @Test
    fun acceptingForgetsOnlyTheItemsThisPhonesCopyHasInThatVault() {
        val mine = SyncSnapshot(
            7,
            vaults = listOf(SyncVault("v1", role = "owner", keyKind = "account"), SyncVault("v2", role = "owner", keyKind = "account")),
            items = listOf(row("a", "d-a", vault = "v1"), row("b", "d-b", vault = "v1"), row("x", "d-x", vault = "v2")),
            held = listOf(row("w", "d-w", vault = "v1"), row("y", "d-y", vault = "v2")),
        )
        assertEquals(setOf("a", "b", "w"), ItemRevs.acceptedIds(mine, setOf("v1")))
        assertEquals(emptySet<String>(), ItemRevs.acceptedIds(mine, emptySet()))
        assertEquals(emptySet<String>(), ItemRevs.acceptedIds(null, setOf("v1")))
        // The answer fetched for the acceptance lists v2's item "x" under v1: its counter is not among the forgotten ones.
        val served = mine.copy(items = listOf(row("a", "d-a", vault = "v1"), row("x", "old-x", vault = "v1")), held = emptyList())
        val accepted = ItemRevs.acceptedIds(mine, setOf("v1"))
        assertFalse("x" in accepted)
        val revs = mapOf("a" to 5L, "b" to 3L, "x" to 9L, "w" to 2L)
        assertEquals("what is checked against at that sync", mapOf("x" to 9L), revs - accepted)
        // …so the older "x" served there is still a rollback for the core's check, whatever vault it is listed under.
        assertTrue(ItemRevs.judge((revs - accepted)["x"], 1, null) { r, n -> io.passauth.core.itemRevCheck(r?.toULong(), n.toULong()) } is ItemRevs.Verdict.Rollback)
        assertTrue(ItemRevs.judge((revs - accepted)["a"], 1, null) { r, n -> io.passauth.core.itemRevCheck(r?.toULong(), n.toULong()) } is ItemRevs.Verdict.Accept)
        // The memory afterwards: the accepted items' old counters are gone (what was served now counts), the others stay.
        assertEquals(mapOf("x" to 9L, "a" to 1L), ItemRevs.merged(revs - accepted, mapOf("a" to 1L), emptySet(), served.items.map { it.id }.toSet()))
        // The versions that waited for the accepted vault's items go too; another vault's stay.
        assertEquals(listOf("y"), ItemRevs.waiting(mine, served, accepted).map { it.id })
        assertTrue(served.items.any { it.id == "x" })
    }

    /**
     * Final review C3: an item moved from vault W to V and edited since; the user accepts V while the
     * answer lists the item under W again in its old ciphertext. Its counter and its newer copy are
     * not among what the acceptance forgets, so the served version is still judged older.
     */
    @Test
    fun acceptingKeepsTheCounterOfAnItemTheAnswerListsUnderAnotherVault() {
        val vaults = listOf(SyncVault("w", role = "owner", keyKind = "account"), SyncVault("v", role = "owner", keyKind = "account"))
        // This phone's copy: "x" now in V (moved and edited), "a" in V, "h" a version of V that waits.
        val mine = SyncSnapshot(
            7, vaults = vaults,
            items = listOf(row("x", "new-x", vault = "v"), row("a", "d-a", vault = "v")),
            held = listOf(row("h", "d-h", vault = "v")),
        )
        // The answer fetched for the acceptance: "x" back under W in its old ciphertext.
        val served = SyncSnapshot(8, vaults = vaults, items = listOf(row("x", "old-x", vault = "w"), row("a", "old-a", vault = "v")))
        val accepted = ItemRevs.acceptedIds(mine, setOf("v"), served)
        assertEquals(setOf("a", "h"), accepted)
        assertEquals("without the answer, every prior id of the vault", setOf("x", "a", "h"), ItemRevs.acceptedIds(mine, setOf("v")))
        val revs = mapOf("x" to 9L, "a" to 5L, "h" to 2L)
        assertEquals(mapOf("x" to 9L), revs - accepted)
        val check = { r: Long?, n: Long -> io.passauth.core.itemRevCheck(r?.toULong(), n.toULong()) }
        assertTrue("x is still judged older", ItemRevs.judge((revs - accepted)["x"], 1, null, check) is ItemRevs.Verdict.Rollback)
        assertTrue(ItemRevs.judge((revs - accepted)["a"], 1, null, check) is ItemRevs.Verdict.Accept)
        // The newer copy of "x" is still there to be kept in place of the served one; the accepted vault's other copies aren't.
        assertEquals(listOf("x"), ItemRevs.priorsFor(mine.items + mine.held, served, setOf("v")).map { it.id })
        assertEquals("new-x", ItemRevs.priorsFor(mine.items + mine.held, served, setOf("v")).single().data)
        // An item the answer lists in the accepted vault itself is forgotten as before; no acceptance changes nothing.
        assertEquals(mine.items + mine.held, ItemRevs.priorsFor(mine.items + mine.held, served, emptySet()))
        assertEquals(setOf("x"), ItemRevs.listedElsewhere(served, setOf("v")))
        // The counter stays in the memory afterwards.
        assertEquals(9L, ItemRevs.merged(revs - accepted, mapOf("a" to 1L), emptySet(), served.items.map { it.id }.toSet())["x"])
    }

    /**
     * Rule S1: the manifest served doesn't record the rows served. Only an account that can write can do
     * something: a baseline exactly one version above the row's (never above its memory), and its memory replaced.
     */
    @Test
    fun aBaselineIsOneVersionAboveTheRowAndReplacesTheMemory() = withDir { dir ->
        val s = started()
        s.otherDevice(emptyList(), listOf(row("n", "data-n")))
        val honest = s.mark()
        // This phone remembers a far higher version (of a history the server no longer has), and the rows don't add up.
        val writer = Phone(s, File(dir, "w"), Role.Write)
        val reader = Phone(s, File(dir, "r"), Role.Read)
        val follower = Phone(s, File(dir, "f"), Role.Read)
        follower.sync()
        val elsewhere = Phone(s, File(dir, "e"), Role.Read)
        elsewhere.memory = mapOf(vaultId to Remembered(ManifestMark(2, manifestDataHash("another version 2"))))
        writer.memory = mapOf(vaultId to Remembered(ManifestMark(50, manifestDataHash("a state the server no longer has"))))
        s.rows = s.rows.filter { it.id != "b" }
        assertEquals(ManifestState.Unresolved, writer.sync())
        assertFalse(writer.acceptable)
        // A view-only member can do nothing yet.
        assertEquals(ManifestState.Unresolved, reader.sync())
        assertEquals(Manifests.ServerCopy.Readers, reader.useServerCopy())
        assertEquals(1, s.manifestPuts)
        // The writer: base = the row, version = row + 1, built on the link of what the server shows.
        val plan = writer.useServerCopy() as Manifests.ServerCopy.Baseline
        assertEquals(2L, plan.body["base_seq"]!!.jsonPrimitive.long)
        assertEquals("row + 1, whatever this phone remembered", 3L, plan.body["seq"]!!.jsonPrimitive.long)
        assertEquals(honest.link, plan.body["prev"]!!.jsonPrimitive.content)
        assertEquals(s.seq - 1, plan.body["vault_seq"]!!.jsonPrimitive.long)
        assertEquals(plan.entry.mark, s.mark())
        assertEquals("replaced though a higher version was remembered", Remembered(plan.entry.mark, 1), writer.memory[vaultId])
        assertEquals(ManifestState.Ok, writer.state)
        // A device whose memory is on the history under the baseline follows it by itself…
        assertEquals(ManifestState.Ok, follower.sync())
        // …the others keep their warning, and each clears it on its own phone, whatever its role, without a request.
        assertEquals(ManifestState.Unresolved, elsewhere.sync())
        assertTrue(elsewhere.acceptable)
        val puts = s.manifestPuts
        assertEquals(Manifests.ServerCopy.Accept(plan.entry.mark), elsewhere.useServerCopy())
        assertEquals(puts, s.manifestPuts)
        assertEquals(ManifestState.Ok, elsewhere.state)
        assertEquals(ManifestState.Ok, reader.sync())

        // A manifest this phone can't open is still what a baseline is built on (its link needs nothing opened).
        val unreadable = s.header().copy(manifest = "AAAA-not-a-manifest")
        val over = Manifests.serverCopy(s.key, unreadable, Role.Owner, s.rows) as Manifests.ServerCopy.Baseline
        assertEquals(Manifests.linkOf(unreadable), over.body["prev"]!!.jsonPrimitive.content)
        assertEquals(s.manifestSeq + 1, over.body["seq"]!!.jsonPrimitive.long)
        // The vault changed between the sync and the request: a conflict (tried again from a new sync, three times in all).
        val stale = Manifests.startBody(s.key, s.header().copy(seq = s.seq - 1, manifest = "AAAA"), s.rows)!!.first
        assertTrue(Manifests.isConflict(assertThrows(ApiException::class.java) { s.putManifest(stale) }))
        // Nothing a baseline can be made from: a row without data or hash, or a version without its manifest.
        assertEquals(Manifests.ServerCopy.Broken, Manifests.serverCopy(s.key, unreadable, Role.Owner, s.rows + row("old", null, deleted = 3)))
        assertEquals(Manifests.ServerCopy.Broken, Manifests.serverCopy(s.key, s.header().copy(manifest = null), Role.Owner, s.rows))
        assertEquals(Manifests.ServerCopy.Broken, Manifests.serverCopy(s.key, unreadable.copy(manifestSeq = Manifests.MAX_NUMBER), Role.Owner, s.rows))
        // The baseline rate limit: the eleventh within the hour is refused in the usual shape; nothing is stored or remembered.
        s.baselines = 10
        val before = s.mark()
        s.rows = s.rows.drop(1)
        val limited = assertThrows(ApiException::class.java) { writer.useServerCopy() }
        assertTrue(limited.isRateLimited)
        assertNotNull(tooManyAttemptsMessage(limited))
        assertEquals(before, s.mark())
        assertEquals(ManifestState.Unresolved, writer.state)
        assertEquals(Remembered(plan.entry.mark, 1), writer.memory[vaultId])
    }

    /**
     * Rule S2 (rereview-mobile F2) as review round 3 left it (rule T1 c): an item that doesn't open is
     * listed and can be deleted for good with an ordinary manifest write; meanwhile nothing is held
     * back in its vault (the manifest passed), and the vault is fine again once the item is gone.
     */
    @Test
    fun anItemThatCannotBeOpenedIsDeletedForGoodAndTheVaultIsFineAgain() = withDir { dir ->
        val s = started()
        // A member posts an item with a garbage `item_key` and a correct manifest (the manifest only counts `data`).
        val bad = row("bad", "data-bad", revision = 4).copy(itemKey = "garbage")
        s.otherDevice(emptyList(), listOf(bad))
        val phone = Phone(s, dir)
        val hidden = setOf(vaultId)
        assertEquals(ManifestState.Unopenable, phone.sync(hidden))
        assertEquals("the chain still advances", s.mark(), phone.memory.getValue(vaultId).mark)
        // "Use the server's copy" isn't what helps here (and after a baseline the vault would still be warned).
        assertFalse(phone.acceptable)
        val header = s.header()
        // Rule T1: no write is held because of the row (the manifest passed): another item can be saved…
        assertTrue(Manifests.writable(ManifestState.Unopenable))
        assertNotNull("another item is saved as usual", Manifests.next(s.key, header, ManifestState.Unopenable, emptyList(), listOf(row("n", "d"))))
        assertEquals("a manifest that doesn't match is reviewed first", Manifests.HELD, assertThrows(UserException::class.java) { Manifests.next(s.key, header, ManifestState.Unresolved, listOf(bad), emptyList()) }.message)
        assertThrows("nor is a vault written that wasn't checked yet", UserException::class.java) { Manifests.next(s.key, header, ManifestState.Unchecked, emptyList(), listOf(row("n", "d"))) }
        // …and removing the row is an ordinary write: the row as synced leaves the manifest, live, in one request.
        val m = Manifests.next(s.key, header, ManifestState.Unopenable, listOf(bad), emptyList())!!
        val path = Manifests.deletePath(bad, m)
        assertTrue(path.startsWith("/items/bad/permanent?revision=4&manifest_seq=${m.seq}&manifest_prev="))
        val answer = s.deletePermanent(path)
        assertTrue(Manifests.mayApplyLocally(m, answer))
        assertTrue(s.rows.none { it.id == "bad" })
        // Applied to the copy like any own write; nothing is left that doesn't open: the vault is fine and writable.
        val copy = SyncMerge.applyLocal(LocalChange.Purge("bad"), vaultId, answer["vault_seq"]!!.jsonPrimitive.long, phone.checkedCopy()!!, m)!!
        assertEquals("ok", Manifests.verify(s.key, copy.vaults[0], m.mark, copy.items).status)
        assertEquals(ManifestState.Ok, phone.sync())
        assertNotNull(Manifests.next(s.key, s.header(), phone.state, emptyList(), listOf(row("n", "d"))))

        // Two such rows: after one is gone the vault stays warned until the other is too.
        s.otherDevice(emptyList(), listOf(bad, bad.copy(id = "bad2")))
        assertEquals(ManifestState.Unopenable, phone.sync(hidden))
        s.deletePermanent(Manifests.deletePath(bad, Manifests.next(s.key, s.header(), phone.state, listOf(bad), emptyList())))
        assertEquals(ManifestState.Unopenable, phone.sync(hidden))

        // The manifest is wrong as well: reviewed first. After the baseline the vault is still warned while the row is there
        // (Android showed "ok" until the next sync), and then the row is deleted.
        s.rows = s.rows.filter { it.id != "a" }
        assertEquals(ManifestState.Unresolved, phone.sync(hidden))
        val plan = Manifests.serverCopy(s.key, s.header(), Role.Owner, s.rows) as Manifests.ServerCopy.Baseline
        s.putManifest(plan.body)
        phone.memory = Manifests.replaced(phone.memory, vaultId, plan.entry.mark)
        assertEquals(ManifestState.Unopenable, phone.sync(hidden))
        val last = s.rows.first { it.id == "bad2" }
        s.deletePermanent(Manifests.deletePath(last, Manifests.next(s.key, s.header(), phone.state, listOf(last), emptyList())))
        assertEquals(ManifestState.Ok, phone.sync())

        // A vault without a manifest: no first one is started over such a row; it is deleted with a plain request.
        val plain = Server(key())
        plain.rows = listOf(row("a", "data-a"), bad)
        assertFalse(Manifests.mayStart(plain.header(), ManifestState.None, Role.Owner, true, null, plain.rows, unopenable = true))
        assertNull(Manifests.next(plain.key, plain.header(), ManifestState.None, listOf(bad), emptyList()))
        assertEquals("/items/bad/permanent?revision=4", Manifests.deletePath(bad, null))
        plain.deletePermanent(Manifests.deletePath(bad, null))
        assertTrue(Manifests.mayStart(plain.header(), ManifestState.None, Role.Owner, true, null, plain.rows))
    }

    /**
     * Rule S6: a create whose answer was lost is sent again with its manifest sealed again. The server
     * answers the same version, but not this manifest: the copy doesn't take it and nothing is remembered,
     * so the sync that follows finds no "other manifest at the same version".
     */
    @Test
    fun aRetriedCreateIsNoFalseMismatch() = withDir { dir ->
        val s = started()
        val phone = Phone(s, dir)
        phone.sync()
        val before = s.header()
        val n = row("n", "data-n")
        val first = Manifests.next(s.key, before, ManifestState.Ok, emptyList(), listOf(n))!!
        s.create(listOf(first), n)   // stored; the answer never arrives
        // The retry, from the same copy: the same version, another sealing.
        val again = Manifests.next(s.key, before, ManifestState.Ok, emptyList(), listOf(n))!!
        assertEquals(first.seq, again.seq)
        assertTrue("each sealing is its own", first.sealed != again.sealed && first.link != again.link)
        val answer = s.create(listOf(again), n)
        assertEquals("the version alone looks like this write", again.seq, Manifests.answered(answer))
        assertFalse(Manifests.stored(again, answer))
        assertFalse(Manifests.mayApplyLocally(again, answer))
        // Had it been remembered (the rule before): a warning at the next sync, though nothing is wrong.
        assertEquals("mismatch", s.status(again.mark))
        // As it is: nothing remembered, the sync checks what the server holds, and no warning shows.
        assertEquals(ManifestState.Ok, phone.sync())
        assertEquals(first.mark, phone.memory.getValue(vaultId).mark)
        // The same sealing sent again (the request repeated as it was) is this phone's manifest: taken.
        val m = row("m", "data-m")
        val once = Manifests.next(s.key, s.header(), ManifestState.Ok, emptyList(), listOf(m))!!
        s.create(listOf(once), m)
        assertTrue(Manifests.mayApplyLocally(once, s.create(listOf(once), m)))
    }

    /**
     * Rule S3 (rereview-mobile F1): a background refresh has no keys, so what it fetched never takes the
     * place of the copy this phone checked. Whatever the server sent it, the next unlock and the next
     * autofill show the checked rows; only an answer that passes with the keys is taken.
     */
    @Test
    fun aKeylessBackgroundRefreshNeverReplacesTheCheckedCopy() = withDir { dir ->
        val s = started()
        val a = s.rows.first { it.id == "a" }
        // The phone saw "a" edited, a new item, and the trashed "c" deleted for good: all checked, version 4.
        val old = s.fork()
        s.otherDevice(listOf(a), listOf(a.copy(data = "data-a2", revision = 2)))
        s.otherDevice(emptyList(), listOf(row("new", "data-new")))
        s.otherDevice(s.rows.filter { it.id == "c" }, emptyList())
        val phone = Phone(s, dir)
        assertEquals(ManifestState.Ok, phone.sync())
        val checked = phone.checkedCopy()!!.items
        val remembered = phone.memory
        fun answer(rows: List<SyncItem>, from: Server = s) = from.snapshot().copy(revision = s.seq + 1, items = rows)

        val hostile = mapOf(
            "an older version of an item" to answer(s.rows.map { if (it.id == "a") a else it }),
            "an item hidden" to answer(s.rows.filter { it.id != "new" }),
            "a deleted item brought back" to answer(s.rows + row("c", "data-c", deleted = 100)),
            "the whole vault as it was (a consistent older state)" to answer(old.rows, from = old),
            "rows the manifest can't count" to answer(s.rows + row("x", null, deleted = 5)),
        )
        for ((what, sent) in hostile) {
            assertTrue(what, phone.backgroundRefresh(sent) is DeltaSync.CacheRefresh.Write)
            // Nothing was written over the checked copy: an autofill or credential request right now reads the checked rows.
            assertEquals(what, checked, phone.checkedCopy()!!.items)
            // The unlock judges what the refresh left with the keys and drops it.
            assertEquals(what, checked, phone.unlock())
            assertNull("$what: dropped", phone.files.readRefreshed("acct"))
            assertEquals(what, checked, phone.checkedCopy()!!.items)
            assertEquals("$what: nothing remembered of it", remembered, phone.memory)
            // And the unlock after that.
            assertEquals(what, checked, phone.unlock())
        }
        // A vault without a manifest has only the item edit counters: an older version of an item there isn't taken either.
        phone.backgroundRefresh(answer(s.rows))
        assertEquals(checked, phone.unlock(rolledBack = true))
        assertNull(phone.files.readRefreshed("acct"))

        // An honest refresh (another device wrote once): taken at unlock, checked and remembered like a sync's answer.
        s.otherDevice(emptyList(), listOf(row("honest", "data-honest")))
        assertTrue(phone.backgroundRefresh() is DeltaSync.CacheRefresh.Write)
        assertEquals("still the checked copy until an unlock judged it", checked, phone.checkedCopy()!!.items)
        assertEquals(s.rows, phone.unlock())
        assertEquals(s.rows, phone.checkedCopy()!!.items)
        assertEquals(s.mark(), phone.memory.getValue(vaultId).mark)
        assertNull(phone.files.readRefreshed("acct"))
        // Two refreshes in a row go on from what the first left; the checked copy stays until the unlock.
        val before = phone.checkedCopy()!!.items
        s.otherDevice(emptyList(), listOf(row("h2", "data-h2")))
        phone.backgroundRefresh()
        assertEquals(DeltaSync.CacheRefresh.Write::class, phone.backgroundRefresh()::class)
        assertEquals(before, phone.checkedCopy()!!.items)
        assertEquals(s.rows, phone.unlock())
        // More than one step ahead needs the vault's log, which a locked or offline phone can't ask for:
        // not taken (the checked copy stays); the sync that follows asks and decides.
        s.otherDevice(emptyList(), listOf(row("h3", "data-h3")))
        s.otherDevice(emptyList(), listOf(row("h4", "data-h4")))
        val two = phone.checkedCopy()!!.items
        phone.backgroundRefresh()
        assertEquals(two, phone.unlock())
        assertEquals(ManifestState.Ok, phone.sync())
        assertEquals(s.rows, phone.checkedCopy()!!.items)
        // An item that doesn't open, a warning, a vault that isn't decided: never taken.
        val j = judge(listOf(s.header()), s.rows, phone.keys, Manifests.marks(phone.memory), hidden = setOf(vaultId))
        assertFalse(Manifests.adoptable(j, rolledBack = false))
        // The checked copy written (a sync, an own write) drops what a refresh left: it was made from an older copy.
        phone.backgroundRefresh()
        phone.files.writeRefreshed("acct", "x")
        phone.sync()
        assertNull(phone.files.readRefreshed("acct"))
        // A refreshed copy that doesn't read is nothing.
        phone.files.writeRefreshed("acct", "not a copy")
        assertNull(SyncSnapshot.decode(phone.files.readRefreshed("acct")!!))
        phone.files.delete("acct")
        assertNull(phone.files.readChecked("acct"))
        assertNull(phone.files.readRefreshed("acct"))
    }

    /** Info I4 / rule S7: a warning that stands is stored with the copy, so a restart finds it without fetching everything again. */
    @Test
    fun aStandingWarningIsStoredWithTheCopyAndNeverTakenFromAServer() = withDir { dir ->
        val s = started()
        val phone = Phone(s, dir)
        phone.sync()
        s.rows = s.rows.drop(1)
        assertEquals(ManifestState.Unresolved, phone.sync())
        val stored = phone.checkedCopy()!!
        assertEquals(listOf(vaultId), stored.unresolved)
        // After a restart the copy says which vaults were warned: a delta that still doesn't pass keeps the warning
        // (VaultRepository.show: no whole fetch for a vault whose warning already stands).
        val j = judge(stored.vaults, stored.items, phone.keys, Manifests.marks(phone.memory), whole = false)
        assertEquals(setOf(vaultId), j.undecided)
        assertTrue(j.undecided.all { it in stored.unresolved })
        // A server can't plant or clear it: the field is this phone's own.
        val answer = DeltaSync.parse("""{"revision":1,"vaults":[{"id":"v"}],"items":[],"unresolved":["v"]}""")!!
        assertTrue(SyncMerge.apply(answer, null)!!.unresolved.isEmpty())
        assertTrue(SyncMerge.applyLocal(LocalChange.ManifestOnly, vaultId, 9, stored)!!.unresolved == stored.unresolved)
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
        // Rule S5 (rereview-mobile F5): whatever retention the server names, this phone watches an item in the trash for
        // at least 7 days: `trash_days: 1` with every row "deleted long ago" empties nothing after a day.
        assertEquals(7L, Manifests.MIN_TRASH_WATCH_DAYS)
        assertEquals("seen for one day, the server says one day", emptyList<SyncItem>(), Manifests.dueTrash(lied, now, 1, lied.associate { it.id to now - day }, now))
        assertEquals("six days and 23 hours", emptyList<SyncItem>(), Manifests.dueTrash(lied, now, 1, lied.associate { it.id to now - 7 * day + 3600 }, now))
        assertEquals(listOf("fresh", "edge", "due", "ancient"), Manifests.dueTrash(lied, now, 1, lied.associate { it.id to now - 7 * day }, now).map { it.id })
        // The server's own rule stays strict: trashed exactly `trash_days` ago is not due yet, one second more is.
        val exact = listOf(row("edge", "d", deleted = now - 3 * day), row("past", "d", deleted = now - 3 * day - 1))
        assertEquals(listOf("past"), Manifests.dueTrash(exact, now, 3, exact.associate { it.id to now - 8 * day }, now).map { it.id })
        // A longer retention than the floor is watched in full.
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(lied, now, 30, lied.associate { it.id to now - 8 * day }, now))
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
        assertEquals("one version on: a mismatch at once", "mismatch", Manifests.verify(made, after, elsewhere, reencrypted).status)
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
        // Review round 3, rule T1 a: the server changed a key alone; the key this phone holds for the same data is the one re-encrypted from.
        val rekeyed = Manifests.rotationRows(copy, listOf(full[0].copy(itemKey = "a-key-the-server-made-up")) + full.drop(1))!!
        assertEquals(full, rekeyed)
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
        assertTrue(honest.unchecked.isEmpty())
        // A vault without a manifest is shown, and said to be unchecked (the web vault's and the iOS app's line).
        val none = Server(s.key).also { it.rows = s.rows }
        assertEquals(listOf("Personal"), grantorView(none, "[$a,$b,$c]").unchecked)
        assertTrue(grantorView(none, "[$a,$b,$c]").mismatched.isEmpty())
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
        assertEquals("This vault can't be changed until its warning is resolved.", Manifests.HELD)
        assertEquals("PassAuth couldn't check this vault with your server yet. Try again in a moment.", Manifests.UNCHECKED)
        assertEquals("This vault has no record of changes yet, so PassAuth couldn't check that nothing is missing or out of date.", Manifests.VIEW_UNCHECKED)
        assertEquals("Item that can't be opened", Manifests.UNOPENABLE_ITEM)
        // Review round 3 (T1, T3, T5): the same words in every app.
        assertEquals("An item in this vault can't be opened.", Manifests.UNOPENABLE)
        assertEquals("Delete for good", Manifests.DELETE_FOR_GOOD)
        assertEquals(
            "This item can't be opened on this device. It may still open on another device or in a newer version of PassAuth. Deleting it removes it for everyone.",
            Manifests.DELETE_FOR_GOOD_CONFIRM,
        )
        assertEquals("Item from a newer version of PassAuth", ItemOpening.NEWER_ITEM)
        assertEquals("Update PassAuth to see this item.", ItemOpening.NEWER_NOTE)
        assertEquals(
            "Your server no longer shows a record of changes for this vault. If you continue, PassAuth stops checking this vault for missing, restored or out-of-date items until a new record is started.",
            Manifests.CONFIRM_NO_RECORD,
        )
        assertEquals("This vault isn't being checked for missing or restored items.", Manifests.NOT_CHECKED)
        assertEquals("PassAuth couldn't reach your server. Check the connection and try again.", ServerSupport.CANT_CONNECT)
        assertEquals("This can't be done until every member's apps are up to date.", Manifests.NOT_READY)
        assertEquals("vault_manifest", Manifests.FEATURE)
        assertEquals(3, Manifests.ATTEMPTS)
        assertNotNull(Manifests.answered(buildJsonObject { put("manifest_seq", 0) }))
    }
}
