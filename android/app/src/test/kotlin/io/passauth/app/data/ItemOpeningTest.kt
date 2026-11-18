package io.passauth.app.data

import io.passauth.core.CoreException
import io.passauth.core.EncryptedItem
import io.passauth.core.VaultKey
import io.passauth.core.accountFromSessionBytes
import java.io.File
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Review round 3, rule T1 (final review N2, N9): the three cases of a row that doesn't open,
 * with the real core (the host build) and real item ciphertext. [ItemOpening.open] is the function
 * `VaultRepository.decryptVault` calls for every row; what the repository then does with the result
 * (which row it stores, what it lists, the vault's state) is checked here through the same pure
 * pieces it uses ([ItemRevs.keepRows], [Manifests.judge], [Manifests.next], [Manifests.mayStart]),
 * not through VaultRepository itself (it needs the Android keystore and store).
 */
class ItemOpeningTest {
    private val fixture: JsonObject by lazy {
        val file = generateSequence(File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
            .map { File(it, "testdata/vectors.json") }.firstOrNull { it.isFile }
        Json.parseToJsonElement(requireNotNull(file) { "testdata/vectors.json not found" }.readText()).jsonObject["vaultManifest"]!!.jsonObject
    }
    private val vaultId: String get() = fixture["vaultId"]!!.jsonPrimitive.content
    private val epoch: Long get() = fixture["keyEpoch"]!!.jsonPrimitive.long

    private fun key(): VaultKey =
        accountFromSessionBytes(fixture["accountId"]!!.jsonPrimitive.content, java.util.Base64.getUrlDecoder().decode(fixture["sessionBytes"]!!.jsonPrimitive.content))
            .openVaultKey(vaultId, fixture["wrappedKey"]!!.jsonPrimitive.content, "account", epoch.toULong(), false)

    /** A real item row: encrypted by the core under [key]. */
    private fun saved(key: VaultKey, id: String, name: String, revision: Long = 1): SyncItem {
        val e = key.encryptItem(ItemCodec.encode(Item(name = name, login = Login(username = "alex"))), id, vaultId)
        return SyncItem(e.id, e.vaultId, e.key, e.data, revision)
    }

    /** The same item saved again (same Item Key, new data), as an edit stores it. */
    private fun edited(key: VaultKey, row: SyncItem, name: String): SyncItem {
        val e = key.updateItem(EncryptedItem(row.id, row.vaultId, row.itemKey!!, row.data!!), ItemCodec.encode(Item(name = name)))
        return row.copy(itemKey = e.key, data = e.data, revision = (row.revision ?: 0) + 1)
    }

    @Test
    fun aRowThatOpensIsTheItemAndTheRowAsServed() {
        val key = key()
        val row = saved(key, "i1", "Bank")
        val o = ItemOpening.open(row, emptyList(), key::decryptItem) as ItemOpening.Result.Opened
        assertEquals("Bank", o.item.name)
        assertEquals(row, o.row)
        assertFalse(o.keptKey)
    }

    /** What the core says, so the cases are told apart by its error and not by guessing. */
    @Test
    fun theCoreTellsAFailedDecryptionFromContentItCannotRead() {
        val key = key()
        val row = saved(key, "i1", "Bank")
        val other = saved(key, "i2", "Other")
        val wrongKey = runCatching { key.decryptItem(EncryptedItem(row.id, row.vaultId, other.itemKey!!, row.data!!)) }.exceptionOrNull()
        assertTrue("another item's key: $wrongKey", wrongKey is CoreException.DecryptFailed)
        val garbage = runCatching { key.decryptItem(EncryptedItem(row.id, row.vaultId, "garbage", row.data!!)) }.exceptionOrNull()
        assertNotNull(garbage)
        assertFalse("text that isn't ciphertext was never decrypted: $garbage", ItemOpening.isUnknownContent(garbage!!))
        val cut = runCatching { key.decryptItem(EncryptedItem(row.id, row.vaultId, row.itemKey!!, row.data!!.dropLast(8))) }.exceptionOrNull()
        assertFalse("nor was data that fails its check: $cut", ItemOpening.isUnknownContent(cut!!))
        assertFalse(ItemOpening.isUnknownContent(wrongKey!!))
        // The core's word for "decrypted, but not an item I know" (its `Error::Json`, shown as "json: …").
        assertTrue(ItemOpening.isUnknownContent(CoreException.Invalid("json: unknown variant `passport`, expected one of `login`, `note`")))
        assertFalse(ItemOpening.isUnknownContent(CoreException.Invalid("malformed data: base64")))
        assertFalse(ItemOpening.isUnknownContent(CoreException.Invalid("unsupported ciphertext version 9")))
    }

    /**
     * T1 a (final review N2): the server sends an item's real `data` with a damaged `item_key`. The
     * phone has the row it opened before: the item stays shown, the copy keeps the good key, the
     * vault is "ok" (nothing warned, nothing held) and the item can still be edited.
     */
    @Test
    fun aKeyTheServerChangedAloneIsReplacedByTheOneThisPhoneHolds() {
        val key = key()
        val good = saved(key, "i1", "Bank", revision = 3)
        val neighbour = saved(key, "i2", "Mail")
        for (bad in listOf("garbage", neighbour.itemKey!!, "")) {
            val served = good.copy(itemKey = bad)
            // The stored copy, the copy shown (decryptVault passes both) or a version that waits: any of them holds the key.
            val o = ItemOpening.open(served, listOf(good), key::decryptItem)
            assertTrue("key \"$bad\": $o", o is ItemOpening.Result.Opened)
            o as ItemOpening.Result.Opened
            assertEquals("Bank", o.item.name)
            assertTrue(o.keptKey)
            assertEquals("the copy keeps this phone's key, everything else as served", good, o.row)

            // What the repository stores: the served answer with that row in place ([ItemRevs.keepRows]); it is not a "kept newer copy".
            val answer = SyncSnapshot(9, vaults = listOf(SyncVault(vaultId, role = "owner", keyKind = "account", keyEpoch = epoch, seq = 4)), items = listOf(served, neighbour), whole = true)
            val copy = ItemRevs.keepRows(answer, mapOf(o.row.id to o.row))
            assertEquals(good, copy.items.first { it.id == "i1" })
            assertFalse(ItemRevs.isKept(copy.items.first { it.id == "i1" }))
            // The next time the server sends the bad key (a whole answer again), the copy still has the good one to stand in.
            assertTrue(ItemOpening.open(served, copy.items.filter { it.id == "i1" }, key::decryptItem) is ItemOpening.Result.Opened)
            // The copy's row opens by itself (a restart shows the item from the copy).
            assertEquals(ItemOpening.Result.Opened(o.item, good), ItemOpening.open(copy.items.first { it.id == "i1" }, emptyList(), key::decryptItem))
        }
    }

    /** T1 a, with a manifest: the vault passes (the manifest covers `data` only), nothing is hidden, and writes go on. */
    @Test
    fun aVaultWhoseServedKeyFailsButWhoseRowThisPhoneHoldsIsNotWarnedOrHeld() {
        val key = key()
        val good = saved(key, "i1", "Bank")
        val other = saved(key, "i2", "Mail")
        var header = SyncVault(vaultId, role = "owner", keyKind = "account", keyEpoch = epoch, seq = 4, manifestOk = true)
        val (_, first) = Manifests.startBody(key, header, listOf(good, other))!!
        header = header.copy(manifest = first.sealed, manifestSeq = first.seq, manifestPrev = first.prev)
        val served = listOf(good.copy(itemKey = "garbage"), other)
        // decryptVault: every row opens (one with the key this phone held) → no vault is "hidden".
        val results = served.map { ItemOpening.open(it, listOf(good, other).filter { k -> k.id == it.id }, key::decryptItem) }
        assertTrue(results.all { it is ItemOpening.Result.Opened })
        val hidden = served.zip(results).filter { it.second is ItemOpening.Result.Unopenable }.map { it.first.vaultId }.toSet()
        val j = runBlocking { Manifests.judge(listOf(header), served, mapOf(vaultId to key), emptyMap(), whole = true, hidden = hidden) }
        assertEquals(ManifestState.Ok, j.states[vaultId])
        assertTrue(j.unopenable.isEmpty() && j.failed.isEmpty())
        // The item itself can be saved again from the copy's row (the edit is built on the key that opens).
        val copyRow = (results[0] as ItemOpening.Result.Opened).row
        val again = edited(key, copyRow, "Bank (new)")
        assertNotNull(Manifests.next(key, header, j.states[vaultId], listOf(copyRow), listOf(again)))
    }

    /** T1 a doesn't apply: another version, another vault, or nothing of the item on this phone → case c, with the name when it is known. */
    @Test
    fun withoutARowOfTheSameDataTheItemCannotBeOpenedAndIsNamedWhenKnown() {
        val key = key()
        val old = saved(key, "i1", "Bank")
        val newer = edited(key, old, "Bank (changed elsewhere)")
        val served = newer.copy(itemKey = "garbage")
        // The phone only has the earlier version: its key isn't proof for this data (in fact it is the same Item Key
        // here, but only a row with the very same data may stand in), so the item is listed, by its last known name.
        assertEquals(ItemOpening.Result.Unopenable("Bank"), ItemOpening.open(served, listOf(old), key::decryptItem))
        // Never seen on this phone (a fresh sign-in): listed without a name.
        assertEquals(ItemOpening.Result.Unopenable(null), ItemOpening.open(served, emptyList(), key::decryptItem))
        // A row of another item, or of another vault, never stands in and never lends its name.
        assertEquals(ItemOpening.Result.Unopenable(null), ItemOpening.open(served, listOf(saved(key, "i2", "Mail")), key::decryptItem))
        assertEquals(ItemOpening.Result.Unopenable(null), ItemOpening.open(served, listOf(newer.copy(vaultId = "another-vault")), key::decryptItem))
        // The same data and the same failing key: nothing to try.
        assertEquals(ItemOpening.Result.Unopenable(null), ItemOpening.open(served, listOf(served), key::decryptItem))
        // Data that fails its own check isn't helped by a key either.
        val broken = newer.copy(data = newer.data!!.dropLast(4) + "AAAA")
        assertEquals(ItemOpening.Result.Unopenable("Bank"), ItemOpening.open(broken, listOf(old, newer), key::decryptItem))
        // A row without key or data (a trash summary row) can't be told at all: the repository never asks for those.
        assertEquals(ItemOpening.Result.Unopenable(null), ItemOpening.open(newer.copy(itemKey = null, data = null), listOf(newer), key::decryptItem))
    }

    /**
     * T1 c: the row is listed and can be deleted for good; the vault shows its notice
     * ([ManifestState.Unopenable]) but no write is held for it; no first manifest is started over it.
     */
    @Test
    fun anItemThatCannotBeOpenedIsListedWithoutHoldingTheVault() {
        val key = key()
        val fine = saved(key, "i1", "Bank")
        val bad = saved(key, "i2", "Mail", revision = 6).copy(itemKey = "garbage")
        var header = SyncVault(vaultId, role = "owner", keyKind = "account", keyEpoch = epoch, seq = 4, manifestOk = true)
        // Without a manifest: none is started over such a row.
        assertTrue(ItemOpening.open(bad, emptyList(), key::decryptItem) is ItemOpening.Result.Unopenable)
        assertFalse(Manifests.mayStart(header, ManifestState.None, Role.Owner, true, null, listOf(fine, bad), unopenable = true))
        assertTrue(Manifests.mayStart(header, ManifestState.None, Role.Owner, true, null, listOf(fine, bad), unopenable = false))
        // With one (another device wrote it; the manifest only counts `data`): the manifest passes, the vault carries the notice.
        val (_, first) = Manifests.startBody(key, header, listOf(fine, bad))!!
        header = header.copy(manifest = first.sealed, manifestSeq = first.seq, manifestPrev = first.prev)
        val j = runBlocking { Manifests.judge(listOf(header), listOf(fine, bad), mapOf(vaultId to key), emptyMap(), whole = true, hidden = setOf(vaultId)) }
        val state = j.states[vaultId]
        assertEquals(ManifestState.Unopenable, state)
        assertTrue("not something \"Use the server's copy\" is offered for", j.acceptable.isEmpty() && j.failed.isEmpty())
        assertEquals("the manifest is remembered as for any vault that passed", first.mark, j.remember[vaultId])
        // No hold: another item is saved, an item is edited, one is trashed…
        val added = saved(key, "i3", "New")
        assertNotNull(Manifests.next(key, header, state, emptyList(), listOf(added)))
        assertNotNull(Manifests.next(key, header, state, listOf(fine), listOf(edited(key, fine, "Bank 2"))))
        assertNotNull(Manifests.next(key, header, state, listOf(fine), listOf(fine.copy(deletedAt = 50))))
        // …and "Delete for good" removes the row as synced, live, in one request.
        val m = Manifests.next(key, header, state, listOf(bad), emptyList())!!
        assertTrue(Manifests.deletePath(bad, m).startsWith("/items/i2/permanent?revision=6&manifest_seq=${m.seq}&"))
    }

    /**
     * T1 b (final review N9): a row that decrypts but holds something this app can't read (an item
     * type or format of a newer app) is "Item from a newer version of PassAuth": not unopenable (no
     * delete, no notice), it doesn't block a first manifest, and its row counts in the manifest like
     * any other. The core's and the app's own reader are both covered; the ciphertext here is a
     * real item, read by a reader that stands for an older app (the core's binding can't encrypt an
     * item type it doesn't know).
     */
    @Test
    fun anItemOfANewerAppIsListedAsSuchAndNothingElse() {
        val key = key()
        val row = saved(key, "i1", "Passport")
        val fine = saved(key, "i2", "Bank")
        // The core can't parse what it decrypted.
        val coreCant: (EncryptedItem) -> String = { e -> key.decryptItem(e); throw CoreException.Invalid("json: unknown variant `passport`") }
        assertEquals(ItemOpening.Result.Newer, ItemOpening.open(row, emptyList(), coreCant))
        // The core reads it, this app's own model can't.
        assertEquals(ItemOpening.Result.Newer, ItemOpening.open(row, emptyList(), key::decryptItem) { throw kotlinx.serialization.SerializationException("unknown type") })
        // A key this phone holds isn't even tried for it, and it is never "can't be opened".
        assertEquals(ItemOpening.Result.Newer, ItemOpening.open(row, listOf(row.copy(itemKey = "other")), coreCant))
        // With a failed decryption first and this phone's key second, the content still decides.
        assertEquals(ItemOpening.Result.Newer, ItemOpening.open(row.copy(itemKey = "garbage"), listOf(row), key::decryptItem) { throw IllegalStateException("newer format") })

        // The vault: nothing hidden → "ok" with a manifest, and a first manifest may be started with the row counted.
        var header = SyncVault(vaultId, role = "owner", keyKind = "account", keyEpoch = epoch, seq = 4, manifestOk = true)
        assertTrue(Manifests.mayStart(header, ManifestState.None, Role.Owner, true, null, listOf(row, fine), unopenable = false))
        val (_, first) = Manifests.startBody(key, header, listOf(row, fine))!!
        header = header.copy(manifest = first.sealed, manifestSeq = first.seq, manifestPrev = first.prev)
        val j = runBlocking { Manifests.judge(listOf(header), listOf(row, fine), mapOf(vaultId to key), emptyMap(), whole = true, hidden = emptySet()) }
        assertEquals(ManifestState.Ok, j.states[vaultId])
        assertEquals("the row is counted: without it the manifest doesn't pass", ManifestState.Unresolved,
            runBlocking { Manifests.judge(listOf(header), listOf(fine), mapOf(vaultId to key), emptyMap(), whole = true) }.states[vaultId])
        assertNotNull(Manifests.next(key, header, j.states[vaultId], emptyList(), listOf(saved(key, "i3", "New"))))
    }

    /**
     * A trashed row that doesn't decrypt blocks a first manifest when this phone can tell: only when
     * the copy has the row's key and data. The app syncs with `trash=summary`, where trashed rows
     * come with a hash only, so there it can't tell (and doesn't claim to).
     */
    @Test
    fun aTrashedRowThatCannotBeOpenedBlocksAFirstManifestWhenItCanBeTold() {
        val key = key()
        val fine = saved(key, "i1", "Bank")
        val trashed = saved(key, "i2", "Old").copy(deletedAt = 100)
        val header = SyncVault(vaultId, role = "owner", keyKind = "account", keyEpoch = epoch, seq = 4, manifestOk = true)
        // With key and data: the same three cases as a live row.
        assertTrue(ItemOpening.open(trashed, emptyList(), key::decryptItem) is ItemOpening.Result.Opened)
        val bad = trashed.copy(itemKey = "garbage")
        assertEquals(ItemOpening.Result.Unopenable(null), ItemOpening.open(bad, emptyList(), key::decryptItem))
        assertTrue("the key this phone holds for the same data still opens it", ItemOpening.open(bad, listOf(trashed), key::decryptItem) is ItemOpening.Result.Opened)
        // decryptVault lists such a row (trashed = true) and its vault gets no first manifest; it is deleted like a live one.
        assertFalse(Manifests.mayStart(header, ManifestState.None, Role.Owner, true, null, listOf(fine, bad), unopenable = true))
        assertEquals("/items/i2/permanent?revision=1", Manifests.deletePath(bad, null))
        // A summary row (what this app's syncs bring): countable by its hash, nothing to open, so nothing is known.
        val summary = SyncItem("i2", vaultId, null, null, 1, 100, dataSha256 = io.passauth.core.manifestDataHash(trashed.data!!))
        assertNull(summary.itemKey)
        assertTrue(Manifests.countable(summary))
        assertTrue("a first manifest isn't held off by a row this phone can't look into", Manifests.mayStart(header, ManifestState.None, Role.Owner, true, null, listOf(fine, summary), unopenable = false))
    }
}
