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
 * a vault with a manifest takes a write only with the next version, and stores it opaque.
 */
class ManifestsTest {
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

    /** What the server keeps of one vault, with its rule for writes. */
    private inner class Server(val key: VaultKey, val vault: String = vaultId, var epoch: Long = this@ManifestsTest.epoch) {
        var rows = listOf<SyncItem>()
        var seq = 0L
        var manifestSeq = 0L
        var manifest: String? = null
        var requests = 0

        fun header(ok: Boolean = true) = SyncVault(vault, role = "owner", keyKind = "account", keyEpoch = epoch, seq = seq, manifest = manifest, manifestSeq = manifestSeq, manifestOk = ok)
        fun snapshot() = SyncSnapshot(seq, vaults = listOf(header()), items = rows)

        /** Any write into the vault: the manifest sent must be the next one (or none for a vault without). */
        fun write(sent: List<ManifestEntry>, change: (List<SyncItem>) -> List<SyncItem>): JsonObject {
            requests++
            val m = sent.firstOrNull { it.vaultId == vault }
            if (manifestSeq > 0 && m == null) throw ApiException(400, "manifest_required", "Update PassAuth to change this vault.")
            if (m != null && m.seq != manifestSeq + 1) throw ApiException(409, "manifest_conflict", "the vault changed")
            if (m != null && manifestSeq == 0L) throw ApiException(409, "manifest_conflict", "the vault has no manifest")
            rows = change(rows)
            seq++
            if (m != null) {
                manifest = m.sealed
                manifestSeq = m.seq
            }
            return buildJsonObject { put("revision", 9); put("vault_seq", seq); put("manifest_seq", manifestSeq) }
        }

        /** `PUT /vaults/{id}/manifest`. */
        fun putManifest(body: JsonObject): JsonObject {
            if (body["base_seq"]!!.jsonPrimitive.long != manifestSeq || body["vault_seq"]!!.jsonPrimitive.long != seq) throw ApiException(409, "manifest_conflict", "x")
            manifest = body["sealed"]!!.jsonPrimitive.content
            manifestSeq = body["seq"]!!.jsonPrimitive.long
            seq++
            return buildJsonObject { put("vault_seq", seq); put("manifest_seq", manifestSeq) }
        }

        /** Another device's write (the same rules, straight from the server's state). */
        fun otherDevice(removed: List<SyncItem>, added: List<SyncItem>) {
            val m = Manifests.next(key, header(), ManifestState.Ok, removed, added)
            write(listOfNotNull(m)) { r -> r.filter { old -> removed.none { it.id == old.id } } + added }
        }

        fun status(remembered: Long? = null) = Manifests.verify(key, header(), remembered, rows).status
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
        s.putManifest(body)
        assertEquals("ok", s.status())
        return s
    }

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
            """{"revision":3,"cursor":"c","server_time":1000,"trash_days":30,"vaults":[{"id":"v","manifest":"m","manifest_seq":4,"manifest_ok":true}],
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
        assertEquals(true, snap.vaults[0].manifestOk)
        // The phone's own copy: its kept rows and the summary hashes survive store and load; the server's clock isn't stored.
        val mine = snap.copy(items = listOf(snap.items[0].copy(servedSha256 = "served"), snap.items[1]))
        val loaded = SyncSnapshot.decode(mine.encode())!!
        assertEquals("served", loaded.items[0].servedSha256)
        assertEquals("h", loaded.items[1].dataSha256)
        assertEquals("m", loaded.vaults[0].manifest)
        assertEquals(4L, loaded.vaults[0].manifestSeq)
        assertNull(loaded.serverTime)
        // A delta keeps the copy's rows as they are and takes the answer's vault rows.
        val delta = DeltaSync.parse("""{"revision":4,"delta":true,"vaults":[{"id":"v","manifest":"m2","manifest_seq":5}],"items":[{"id":"n","vault_id":"v","item_key":"k","data":"d","served_sha256":"x"}]}""")!!
        val merged = SyncMerge.apply(delta, loaded)!!
        assertEquals("served", merged.items.first { it.id == "a" }.servedSha256)
        assertNull(merged.items.first { it.id == "n" }.servedSha256)
        assertEquals(5L, merged.vaults[0].manifestSeq)
    }

    // ----------------------------------------------------------- verify

    @Test
    fun aSyncIsJudgedAgainstEachVaultsManifest() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        // Ok: the version is remembered.
        var j = Manifests.judge(listOf(s.header()), s.rows, keys, emptyMap())
        assertEquals(mapOf(vaultId to ManifestState.Ok), j.states)
        assertEquals(mapOf(vaultId to 1L), j.remember)
        // An item hidden, one brought back, an older version served: unresolved, nothing remembered.
        for (bad in listOf(s.rows.drop(1), s.rows + row("z", "old"), listOf(row("a", "older")) + s.rows.drop(1), s.rows.map { if (it.id == "c") it.copy(deletedAt = null) else it })) {
            j = Manifests.judge(listOf(s.header()), bad, keys, mapOf(vaultId to 1L))
            assertEquals(ManifestState.Unresolved, j.states[vaultId])
            assertTrue(j.remember.isEmpty())
        }
        // A lower version than this phone saw, or no manifest after one was seen: rollback.
        j = Manifests.judge(listOf(s.header()), s.rows, keys, mapOf(vaultId to 2L))
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        assertTrue(j.remember.isEmpty())
        j = Manifests.judge(listOf(s.header().copy(manifest = null, manifestSeq = 0)), s.rows, keys, mapOf(vaultId to 1L))
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        // A manifest that doesn't open (another vault's key epoch): mismatch.
        j = Manifests.judge(listOf(s.header().copy(keyEpoch = epoch + 1)), s.rows, keys, emptyMap())
        assertEquals(ManifestState.Unresolved, j.states[vaultId])
        // No manifest and none seen: nothing to check. A vault whose key isn't open isn't judged.
        j = Manifests.judge(listOf(s.header().copy(manifest = null, manifestSeq = 0), SyncVault("other", manifest = "x", manifestSeq = 3)), s.rows, keys, emptyMap())
        assertEquals(mapOf(vaultId to ManifestState.None), j.states)
        // Malformed rows (an id twice) are a mismatch, not a crash.
        assertEquals("mismatch", Manifests.verify(s.key, s.header(), null, s.rows + s.rows[0]).status)
    }

    @Test
    fun summaryRowsAreCountedByTheServersHashAndOldCopiesAreIncomplete() {
        val s = started()
        val keys = mapOf(vaultId to s.key)
        val summary = s.rows.map { if (it.deletedAt != null) it.copy(itemKey = null, data = null, dataSha256 = manifestDataHash(it.data!!)) else it }
        assertEquals(ManifestState.Ok, Manifests.judge(listOf(s.header()), summary, keys, emptyMap()).states[vaultId])
        // A wrong hash is a mismatch.
        val lied = summary.map { if (it.deletedAt != null) it.copy(dataSha256 = manifestDataHash("other")) else it }
        assertEquals(ManifestState.Unresolved, Manifests.judge(listOf(s.header()), lied, keys, emptyMap()).states[vaultId])
        // A copy cached before the hash existed: can't be counted; nothing remembered; asked for again in full.
        val old = summary.map { it.copy(dataSha256 = null) }
        val j = Manifests.judge(listOf(s.header()), old, keys, emptyMap())
        assertEquals(ManifestState.Unchecked, j.states[vaultId])
        assertEquals(setOf(vaultId), j.incomplete)
        assertTrue(j.remember.isEmpty())
        // Still without hashes in a whole answer from the server: a mismatch.
        val whole = Manifests.judge(listOf(s.header()), old, keys, emptyMap(), incompleteIsMismatch = true)
        assertEquals(ManifestState.Unresolved, whole.states[vaultId])
        assertTrue(whole.incomplete.isEmpty())
    }

    @Test
    fun deviceMemoryOnlyGoesUpAndKeepsVaultsThatAreGone() {
        val m = mapOf("a" to 3L, "gone" to 9L)
        assertEquals(mapOf("a" to 4L, "gone" to 9L, "b" to 1L), Manifests.merged(m, mapOf("a" to 4L, "b" to 1L)))
        assertEquals(m, Manifests.merged(m, mapOf("a" to 2L, "gone" to 1L, "zero" to 0L)))
        assertEquals(m, Manifests.decodeMemory(Manifests.encodeMemory(m)))
        assertEquals(mapOf("ok" to 1L), Manifests.decodeMemory("""{"ok":1,"zero":0,"s":"2","neg":-1,"f":1.5}"""))
        assertEquals(emptyMap<String, Long>(), Manifests.decodeMemory("not json"))
        assertEquals(emptyMap<String, Long>(), Manifests.decodeMemory(null))
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
        s.write(listOf(m)) { it + n }
        assertEquals("ok", s.status(1))
        // Edit: the row as held leaves, the row as sent arrives.
        val a = s.rows.first { it.id == "a" }
        val a2 = a.copy(data = "data-a2")
        m = entry(listOf(a), listOf(a2))
        s.write(listOf(m)) { r -> r.map { if (it.id == "a") a2 else it } }
        assertEquals("ok", s.status(2))
        // Trash: the same data, in the trash; the query names the item's revision and the manifest.
        val b = s.rows.first { it.id == "b" }
        m = entry(listOf(b), listOf(b.copy(deletedAt = 50)))
        assertEquals("?revision=12&manifest_seq=${m.seq}&manifest=${m.sealed}", Manifests.query(m, 12))
        s.write(listOf(m)) { r -> r.map { if (it.id == "b") b.copy(deletedAt = 50) else it } }
        assertEquals("ok", s.status(3))
        // Old trash deleted for good, several at once.
        val trash = s.rows.filter { it.deletedAt != null }
        assertEquals(2, trash.size)
        m = entry(trash, emptyList())
        val purge = Manifests.purgeBody(trash, m)
        assertEquals(trash.map { it.id }, purge["items"]!!.jsonArray.map { it.jsonObject["id"]!!.jsonPrimitive.content })
        assertEquals(1L, purge["items"]!!.jsonArray[0].jsonObject["revision"]!!.jsonPrimitive.long)
        assertEquals(m.json(), purge["manifests"]!!.jsonArray.single())
        s.write(listOf(m)) { r -> r.filter { it.deletedAt == null } }
        assertEquals("ok", s.status(4))
        assertEquals(5L, s.manifestSeq)
        // A wrong manifest (the row left out) would be stored by the server as it is, and everyone would see the mismatch.
        val wrong = entry(emptyList(), emptyList())
        s.write(listOf(wrong)) { it + row("x", "data-x") }
        assertEquals("mismatch", s.status(5))
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
        from.write(listOf(out, into)) { r -> r.filter { it.id != "a" } }
        to.write(listOf(out, into)) { it + moved }
        assertEquals("ok", from.status(1))
        assertEquals("ok", to.status(1))
        // Into a vault without a manifest: only the vault it leaves carries one.
        assertNull(Manifests.next(to.key, to.header().copy(manifest = null, manifestSeq = 0), ManifestState.None, emptyList(), listOf(moved)))
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
        // A row that can't be counted can't leave a manifest.
        assertThrows(UserException::class.java) { Manifests.next(s.key, s.header(), ManifestState.Ok, listOf(row("c", null, 100)), emptyList()) }
    }

    @Test
    fun theCopyTakesAnOwnWriteOnlyWithTheAnsweredManifestVersion() {
        val s = started()
        val n = row("n", "data-n")
        val m = Manifests.next(s.key, s.header(), ManifestState.Ok, emptyList(), listOf(n))!!
        val before = s.snapshot()
        val answer = s.write(listOf(m)) { it + n }
        assertTrue(Manifests.mayApplyLocally(m, answer))
        assertEquals(SyncDecision.AfterWrite.ApplyLocally, SyncDecision.afterWrite(before.vaults[0].seq, answer["vault_seq"]!!.jsonPrimitive.long))
        val next = SyncMerge.applyLocal(LocalChange.Put(n.copy(revision = 9)), vaultId, answer["vault_seq"]!!.jsonPrimitive.long, before, m)!!
        // The row's manifest and version are the ones sent: the copy's rows and manifest still belong together.
        assertEquals(m.sealed, next.vaults[0].manifest)
        assertEquals(m.seq, next.vaults[0].manifestSeq)
        assertEquals("ok", Manifests.verify(s.key, next.vaults[0], 1, next.items).status)
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
        assertEquals("ok", Manifests.verify(s.key, next.vaults[0], 1, next.items).status)
        // Through store and load too.
        val loaded = SyncSnapshot.decode(next.encode())!!
        assertEquals("ok", Manifests.verify(s.key, loaded.vaults[0], 2, loaded.items).status)
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
        assertEquals("ok", Manifests.verify(s.key, copy.vaults[0], 1, copy.items).status)
        // Editing it: the manifest drops what the server holds, not the kept data.
        val edited = kept.copy(data = "edited", servedSha256 = null)
        val m = Manifests.next(s.key, copy.vaults[0], ManifestState.Ok, listOf(kept), listOf(edited))!!
        s.write(listOf(m)) { r -> r.map { if (it.id == "a") edited else it } }
        assertEquals("ok", s.status(1))
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
        assertEquals("ok", s.status(1))
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
        assertEquals("ok", s.status(1))
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
        // Gone: also a conflict (the editor says it was deleted).
        assertThrows(ConflictException::class.java) { runBlocking { ItemWrites.update(base, send = { throw conflict }, resync = { null }) } }
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
        assertFalse("one was seen before", Manifests.mayStart(v, ManifestState.None, Role.Owner, true, 2, s.rows))
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
        // A server restored from a backup: an old manifest and old rows, below what this phone remembers.
        val s = started()
        s.otherDevice(emptyList(), listOf(row("n", "data-n")))
        val remembered = 6L
        assertEquals("rollback", s.status(remembered))
        val seq = Manifests.baselineSeq(s.manifestSeq, remembered)
        val (body, entry) = Manifests.startBody(s.key, s.header(), seq, s.rows)!!
        assertEquals(s.manifestSeq, body["base_seq"]!!.jsonPrimitive.long)
        assertEquals(7L, body["seq"]!!.jsonPrimitive.long)
        s.putManifest(body)
        assertEquals(7L, entry.seq)
        assertEquals("ok", s.status(remembered))
        assertEquals(7L, Manifests.verify(s.key, s.header(), remembered, s.rows).version)
        // The vault changed between the sync and the request: a conflict, tried again from a new sync.
        val stale = Manifests.startBody(s.key, s.header().copy(seq = s.seq - 1), 9, s.rows)!!.first
        assertTrue(Manifests.isConflict(assertThrows(ApiException::class.java) { s.putManifest(stale) }))
    }

    @Test
    fun oldTrashIsChosenByTheServersClockAndRetention() {
        val day = 86_400L
        val now = 100 * day
        val rows = listOf(row("live", "d"), row("fresh", "d", deleted = now - 29 * day), row("edge", "d", deleted = now - 30 * day), row("due", null, deleted = now - 30 * day - 1, sha = "h"), row("ancient", "d", deleted = 5))
        assertEquals(listOf("due", "ancient"), Manifests.dueTrash(rows, now, 30).map { it.id })
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, 0))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, null))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, null, 30))
        assertEquals(emptyList<SyncItem>(), Manifests.dueTrash(rows, now, -1))
    }

    @Test
    fun aKeyReplacementCarriesAWholeNewManifestForTheNewKeyAndEpoch() {
        val s = started()
        val made = account().newVaultKey(vaultId).key
        val reencrypted = s.rows.map { it.copy(itemKey = "new-" + it.id, data = "new-" + it.data) }
        val m = Manifests.rotationEntry(made, s.header(), reencrypted)!!
        assertEquals(s.manifestSeq + 1, m.seq)
        // After the rotation the server holds the new rows under the new epoch: checked with the new key.
        val after = s.header().copy(keyEpoch = epoch + 1, manifest = m.sealed, manifestSeq = m.seq)
        assertEquals("ok", Manifests.verify(made, after, 1, reencrypted).status)
        // Not with the old key, the old epoch or the old data.
        assertEquals("mismatch", Manifests.verify(s.key, after, 1, reencrypted).status)
        assertEquals("mismatch", Manifests.verify(made, after.copy(keyEpoch = epoch), 1, reencrypted).status)
        assertEquals("mismatch", Manifests.verify(made, after, 1, s.rows).status)
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
