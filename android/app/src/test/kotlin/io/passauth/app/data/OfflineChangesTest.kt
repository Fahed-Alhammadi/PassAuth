package io.passauth.app.data

import io.passauth.core.EncryptedItem
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Every rule of ARCHITECTURE "Offline changes (waiting to sync)" that the app decides without the network. */
class OfflineChangesTest {
    private fun item(name: String, password: String = "pw") = ItemCodec.encodeJson(Item(name = name, login = Login(username = "alice", password = password)))

    private fun change(
        kind: ChangeKind,
        itemId: String = "i1",
        base: Long? = if (kind == ChangeKind.Create) null else 4,
        name: String = "Shop",
        sent: SentBody? = null,
        state: ChangeState = ChangeState.Waiting,
    ) = OfflineChange("c-$itemId-$kind-$name", kind, "v1", itemId, base, if (kind == ChangeKind.Trash) null else item(name), sent, 1_000, state)

    private fun list(vararg c: OfflineChange) = OfflineList(changes = c.toList())

    private val sent = SentBody("key", "data-1", 2)

    // ------------------------------------------------------------ the list

    @Test
    fun listIsStoredInTheContractShape() {
        val text = AppJson.encodeToString(OfflineList.serializer(), list(change(ChangeKind.Edit, sent = sent, state = ChangeState.Held).copy(reason = "No")))
        val o = AppJson.parseToJsonElement(text).jsonObject
        assertEquals(JsonPrimitive(1), o["version"])
        val c = o["changes"]!!.jsonArray[0].jsonObject
        assertEquals(
            setOf("id", "kind", "vault_id", "item_id", "base_revision", "item", "sent", "created_at", "state", "reason"),
            c.keys,
        )
        assertEquals(JsonPrimitive("edit"), c["kind"])
        assertEquals(JsonPrimitive("held"), c["state"])
        assertEquals(setOf("key", "data", "key_epoch"), c["sent"]!!.jsonObject.keys)
        assertEquals(AppJson.decodeFromString(OfflineList.serializer(), text), list(change(ChangeKind.Edit, sent = sent, state = ChangeState.Held).copy(reason = "No")))
        // A create has no base revision, a trash no item.
        val t = AppJson.parseToJsonElement(AppJson.encodeToString(OfflineList.serializer(), list(change(ChangeKind.Create), change(ChangeKind.Trash, "i2")))).jsonObject["changes"]!!.jsonArray
        assertEquals("null", t[0].jsonObject["base_revision"].toString())
        assertEquals("null", t[1].jsonObject["item"].toString())
    }

    // ------------------------------------------------------- when a change waits

    @Test
    fun onlyNoAnswerOrGatewayErrorsWait() {
        assertTrue(OfflineChanges.shouldWait(UnreachableException()))
        for (status in listOf(502, 503, 504)) assertTrue(OfflineChanges.shouldWait(ApiException(status, "error", "x")))
        for (status in listOf(400, 401, 403, 404, 409, 429, 500, 507)) assertFalse("$status", OfflineChanges.shouldWait(ApiException(status, "error", "x")))
        // The app's own errors (and a plain "can't reach" from a refresh that got an answer) are shown.
        assertFalse(OfflineChanges.shouldWait(UserException(UNREACHABLE)))
        assertFalse(OfflineChanges.shouldWait(ConflictException()))
        assertFalse(OfflineChanges.shouldWait(IllegalStateException()))
    }

    // ---------------------------------------------------------- one per item

    @Test
    fun aNewChangeIsAdded() {
        val l = OfflineChanges.add(OfflineList(), change(ChangeKind.Edit))
        assertEquals(1, l.changes.size)
        assertEquals(1, OfflineChanges.add(l, change(ChangeKind.Create, "i2")).changes.count { it.itemId == "i2" })
    }

    @Test
    fun createPlusEditIsACreateWithTheNewItem() {
        val l = OfflineChanges.add(list(change(ChangeKind.Create, name = "A")), change(ChangeKind.Edit, base = null, name = "B"))
        val c = l.changes.single()
        assertEquals(ChangeKind.Create, c.kind)
        assertNull(c.baseRevision)
        assertEquals(item("B"), c.item)
    }

    @Test
    fun editPlusEditKeepsTheFirstBaseAndTheNewestItem() {
        val l = OfflineChanges.add(list(change(ChangeKind.Edit, base = 4, name = "A")), change(ChangeKind.Edit, base = 9, name = "B"))
        val c = l.changes.single()
        assertEquals(ChangeKind.Edit, c.kind)
        assertEquals(4L, c.baseRevision)
        assertEquals(item("B"), c.item)
        // A decision that stands stays to be made.
        val conflict = OfflineChanges.add(list(change(ChangeKind.Edit, state = ChangeState.Conflict)), change(ChangeKind.Edit, name = "C"))
        assertEquals(ChangeState.Conflict, conflict.changes.single().state)
        // Held is decided again.
        val held = OfflineChanges.add(list(change(ChangeKind.Edit, state = ChangeState.Held).copy(reason = "x")), change(ChangeKind.Edit, name = "C"))
        assertEquals(ChangeState.Waiting, held.changes.single().state)
        assertNull(held.changes.single().reason)
    }

    @Test
    fun editPlusTrashIsATrashWithTheFirstBase() {
        val l = OfflineChanges.add(list(change(ChangeKind.Edit, base = 4, sent = sent)), change(ChangeKind.Trash, base = 7))
        val c = l.changes.single()
        assertEquals(ChangeKind.Trash, c.kind)
        assertEquals(4L, c.baseRevision)
        assertNull(c.item)
        assertEquals(sent, c.sent)
    }

    @Test
    fun createPlusTrashRemovesTheChangeUnlessItMayBeOnTheServer() {
        assertTrue(OfflineChanges.add(list(change(ChangeKind.Create)), change(ChangeKind.Trash, base = null)).changes.isEmpty())
        val kept = OfflineChanges.add(list(change(ChangeKind.Create, sent = sent)), change(ChangeKind.Trash, base = null)).changes.single()
        assertEquals(ChangeKind.Trash, kept.kind)
        assertNull(kept.baseRevision)
        assertEquals(sent, kept.sent)
    }

    @Test
    fun aTrashedItemCantBeEditedOffline() {
        val trashed = list(change(ChangeKind.Trash))
        val e = assertThrows(UserException::class.java) { OfflineChanges.add(trashed, change(ChangeKind.Edit)) }
        assertEquals(OfflineChanges.TRASHED_OFFLINE, e.message)
        assertEquals(trashed, OfflineChanges.add(trashed, change(ChangeKind.Trash)))
    }

    @Test
    fun atMost500Changes() {
        val full = OfflineList(changes = (1..OfflineChanges.MAX).map { change(ChangeKind.Edit, "i$it") })
        val e = assertThrows(UserException::class.java) { OfflineChanges.add(full, change(ChangeKind.Edit, "new")) }
        assertEquals("Too many changes are waiting. Connect to the internet before making more.", e.message)
        // A change merged into one that waits is no new change.
        assertEquals(OfflineChanges.MAX, OfflineChanges.add(full, change(ChangeKind.Edit, "i3", name = "B")).changes.size)
    }

    // ---------------------------------------------------------------- sending

    @Test
    fun createDecisions() {
        val c = change(ChangeKind.Create, sent = sent)
        assertEquals(SendDecision.Send, OfflineChanges.decide(c, null))
        assertEquals(SendDecision.Done, OfflineChanges.decide(c, ServerRow(3, "data-1", false)))
        assertEquals(SendDecision.NewId, OfflineChanges.decide(c, ServerRow(3, "other", false)))
        assertEquals(SendDecision.NewId, OfflineChanges.decide(c.copy(sent = null), ServerRow(3, "data-1", false)))
    }

    @Test
    fun editDecisions() {
        val c = change(ChangeKind.Edit, base = 4, sent = sent)
        assertEquals(SendDecision.Conflict(deleted = true), OfflineChanges.decide(c, null))
        assertEquals(SendDecision.Conflict(deleted = true), OfflineChanges.decide(c, ServerRow(5, null, true)))
        assertEquals(SendDecision.Send, OfflineChanges.decide(c, ServerRow(4, "x", false)))
        assertEquals(SendDecision.Done, OfflineChanges.decide(c, ServerRow(5, "data-1", false)))
        assertEquals(SendDecision.Conflict(deleted = false), OfflineChanges.decide(c, ServerRow(5, "other", false)))
        assertEquals(SendDecision.Conflict(deleted = false), OfflineChanges.decide(c.copy(sent = null), ServerRow(5, "data-1", false)))
    }

    @Test
    fun trashDecisions() {
        val c = change(ChangeKind.Trash, base = 4)
        assertEquals(SendDecision.Done, OfflineChanges.decide(c, null))
        assertEquals(SendDecision.Done, OfflineChanges.decide(c, ServerRow(9, null, true)))
        assertEquals(SendDecision.Send, OfflineChanges.decide(c, ServerRow(4, "x", false)))
        assertEquals(SendDecision.Conflict(deleted = false), OfflineChanges.decide(c, ServerRow(5, "x", false)))
        // A created item trashed after an attempt that may have landed: trashed when it is that attempt.
        val fromCreate = c.copy(baseRevision = null, sent = sent)
        assertEquals(SendDecision.Send, OfflineChanges.decide(fromCreate, ServerRow(1, "data-1", false)))
        assertEquals(SendDecision.Conflict(deleted = false), OfflineChanges.decide(fromCreate, ServerRow(2, "other", false)))
    }

    @Test
    fun editMergedAfterALandedEditIsSentNotDropped() {
        // Edit sent (no answer, but it landed: server at 5 with data-1), then a newer edit merged in.
        val first = change(ChangeKind.Edit, base = 4, name = "Shop", sent = sent)
        val merged = OfflineChanges.add(list(first), change(ChangeKind.Edit, name = "Shop 2")).of("i1")!!
        assertEquals(sent, merged.sent)
        val row = ServerRow(5, "data-1", false)
        val theirs = ItemCodec.decodeJson(item("Shop"))
        val mine = ItemCodec.decodeJson(merged.item!!)
        val matches = OfflineChanges.sameContent(mine, theirs)
        assertFalse(matches)
        assertEquals(SendDecision.EditOver, OfflineChanges.decide(merged, row, sentMatches = matches))
        // Nothing merged since: the landed attempt is the change.
        assertEquals(SendDecision.Done, OfflineChanges.decide(first, row, sentMatches = OfflineChanges.sameContent(ItemCodec.decodeJson(first.item!!), theirs)))
    }

    @Test
    fun editMergedAfterALandedCreateIsSentAsAnEdit() {
        val first = change(ChangeKind.Create, name = "Shop", sent = sent)
        val merged = OfflineChanges.add(list(first), change(ChangeKind.Edit, name = "Shop 2")).of("i1")!!
        assertEquals(ChangeKind.Create, merged.kind)
        val matches = OfflineChanges.sameContent(ItemCodec.decodeJson(merged.item!!), ItemCodec.decodeJson(item("Shop")))
        assertEquals(SendDecision.EditOver, OfflineChanges.decide(merged, ServerRow(1, "data-1", false), sentMatches = matches))
        // Other content under the id: still a new id.
        assertEquals(SendDecision.NewId, OfflineChanges.decide(merged, ServerRow(1, "other", false), sentMatches = matches))
    }

    @Test
    fun trashMergedAfterALandedEditIsSent() {
        val first = change(ChangeKind.Edit, base = 4, sent = sent)
        val merged = OfflineChanges.add(list(first), change(ChangeKind.Trash)).of("i1")!!
        assertEquals(ChangeKind.Trash, merged.kind)
        assertEquals(4L, merged.baseRevision)
        // The server holds the landed edit (revision moved on): trashed, not a conflict.
        assertEquals(SendDecision.Send, OfflineChanges.decide(merged, ServerRow(5, "data-1", false)))
        // Changed by someone else after it: the user decides.
        assertEquals(SendDecision.Conflict(deleted = false), OfflineChanges.decide(merged, ServerRow(6, "other", false)))
    }

    @Test
    fun sameContentIgnoresRevFormatAndTimes() {
        val a = Item(name = "Shop", format = 3, createdAt = 1, updatedAt = 2, extra = JsonObject(mapOf("rev" to JsonPrimitive(4))))
        val b = Item(name = "Shop", createdAt = 5, updatedAt = 6, extra = JsonObject(mapOf("rev" to JsonPrimitive(5))))
        assertTrue(OfflineChanges.sameContent(a, b))
        assertFalse(OfflineChanges.sameContent(a, b.copy(name = "Shop 2")))
        assertFalse(OfflineChanges.sameContent(a, b.copy(extra = JsonObject(b.extra + ("attachments" to JsonPrimitive("x"))))))
    }

    @Test
    fun heldWhenTheVaultCantTakeIt() {
        val ok = VaultInfo("v1", "Mine", Role.Owner)
        assertNull(OfflineChanges.holdReason(ok))
        assertNull(OfflineChanges.holdReason(ok.copy(role = Role.Write, manifest = ManifestState.Ok)))
        assertNull(OfflineChanges.holdReason(ok.copy(manifest = ManifestState.Unopenable)))
        assertEquals(OfflineChanges.VAULT_GONE, OfflineChanges.holdReason(null))
        assertEquals(OfflineChanges.READ_ONLY, OfflineChanges.holdReason(ok.copy(role = Role.Read)))
        assertEquals(OfflineChanges.VAULT_WARNING, OfflineChanges.holdReason(ok.copy(manifest = ManifestState.Unresolved)))
        assertEquals(Manifests.UNCHECKED, OfflineChanges.holdReason(ok.copy(manifest = ManifestState.Unchecked)))
    }

    @Test
    fun failuresOfASend() {
        val words: (Throwable) -> String = { "said: ${it.message}" }
        assertEquals(SendFailure.Stop, OfflineChanges.afterFailure(UnreachableException(), 1, words))
        assertEquals(SendFailure.Stop, OfflineChanges.afterFailure(ApiException(503, "error", "x"), 2, words))
        // revision_conflict: sync and decide again, at most 3 times, then the user decides.
        val revision = ApiException(409, "revision_conflict", "x")
        assertEquals(SendFailure.Again, OfflineChanges.afterFailure(revision, 1, words))
        assertEquals(SendFailure.Again, OfflineChanges.afterFailure(ConflictException(), 2, words))
        assertEquals(SendFailure.Conflict, OfflineChanges.afterFailure(revision, 3, words))
        // manifest_conflict / vault_key_changed: again, at most 3 times, then held.
        val manifest = ApiException(409, "manifest_conflict", "x")
        val key = ApiException(409, "vault_key_changed", "x")
        assertEquals(SendFailure.Again, OfflineChanges.afterFailure(manifest, 1, words))
        assertEquals(SendFailure.Again, OfflineChanges.afterFailure(key, 2, words))
        assertEquals(SendFailure.Held("said: x"), OfflineChanges.afterFailure(manifest, 3, words))
        assertEquals(SendFailure.Held("said: ${Manifests.CHANGED_ELSEWHERE}"), OfflineChanges.afterFailure(UserException(Manifests.CHANGED_ELSEWHERE), 3, words))
        // Anything else: held with the app's wording.
        assertEquals(SendFailure.Held("said: quota"), OfflineChanges.afterFailure(ApiException(403, "quota_exceeded", "quota"), 1, words))
        assertEquals(SendFailure.Held("said: boom"), OfflineChanges.afterFailure(ApiException(500, "error", "boom"), 1, words))
        assertEquals(SendFailure.Held("said: full"), OfflineChanges.afterFailure(ApiException(507, "insufficient_storage", "full"), 1, words))
    }

    // -------------------------------------------------------------- decisions

    @Test
    fun keepMineAndMoveToTrashAnywayGoOverTheServersRevision() {
        val c = change(ChangeKind.Edit, base = 4, sent = sent, state = ChangeState.Conflict).copy(reason = "x")
        val next = OfflineChanges.over(c, 9)
        assertEquals(9L, next.baseRevision)
        assertNull(next.sent)
        assertEquals(ChangeState.Waiting, next.state)
        assertNull(next.reason)
        assertEquals(c.item, next.item)
        assertEquals(ChangeKind.Edit, next.kind)
    }

    @Test
    fun keepBothIsANewItemInTheSameVault() {
        val c = change(ChangeKind.Edit, base = 4, name = "Shop", sent = sent, state = ChangeState.Conflict)
        val rename: (JsonObject) -> JsonObject = { JsonObject(it + ("name" to JsonPrimitive("Shop" + OfflineChanges.COPY_SUFFIX))) }
        val next = OfflineChanges.asNew(c, "new-item", "new-change", rename)
        assertEquals(ChangeKind.Create, next.kind)
        assertEquals("new-item", next.itemId)
        assertEquals("v1", next.vaultId)
        assertNull(next.baseRevision)
        assertNull(next.sent)
        assertEquals(ChangeState.Waiting, next.state)
        assertEquals("Shop (offline copy)", ItemCodec.decodeJson(next.item!!).name)
    }

    @Test
    fun differencesMarkWhatChanged() {
        val mine = Item(name = "Shop", login = Login(username = "alice", password = "new"), notes = "n")
        val theirs = Item(name = "Shop", login = Login(username = "bob", password = "old"), notes = "n")
        val rows = OfflineChanges.differences(mine, theirs).associateBy { it.label }
        assertFalse(rows.getValue("Name").differs)
        assertTrue(rows.getValue("Username").differs)
        assertTrue(rows.getValue("Password").differs)
        assertTrue(rows.getValue("Password").secret)
        assertFalse(rows.getValue("Notes").differs)
        assertNull(rows["Card number"])
    }

    // ---------------------------------------------------------------- showing

    private fun entry(id: String, name: String, revision: Long = 4) =
        Entry(id, Item(name = name), "v1", revision, EncryptedItem(id, "v1", "k", "d"))

    private fun overlay(base: List<Entry>, l: OfflineList) = OfflineChanges.overlay(
        base, l, { it.id },
        { c, item, e -> Entry(c.itemId, item, e?.vaultId ?: c.vaultId, e?.revision ?: -1, e?.enc ?: EncryptedItem(c.itemId, c.vaultId, "", "")) },
    ) { runCatching { ItemCodec.decodeJson(it) }.getOrNull() }

    @Test
    fun theListGoesOnTopOfTheOfflineCopy() {
        val base = listOf(entry("a", "A"), entry("b", "B"), entry("c", "C"), entry("d", "D"))
        val shown = overlay(
            base,
            list(
                change(ChangeKind.Edit, "a", name = "A2"),
                change(ChangeKind.Trash, "b"),
                change(ChangeKind.Trash, "c", state = ChangeState.Conflict),
                change(ChangeKind.Create, "n", name = "New"),
            ),
        )
        assertEquals(listOf("a", "c", "d", "n"), shown.map { it.id })
        assertEquals("A2", shown[0].item.name)
        // The edited entry keeps the server's revision and key wrapping (writes merge into the change).
        assertEquals(4L, shown[0].revision)
        assertEquals("New", shown[3].item.name)
        assertEquals(-1L, shown[3].revision)
        assertEquals(base, overlay(base, OfflineList()))
        // A change whose item can't be read leaves the entry as it was.
        assertEquals("D", overlay(base, list(change(ChangeKind.Edit, "d").copy(item = JsonObject(mapOf("name" to JsonObject(emptyMap())))))).last().item.name)
    }

    @Test
    fun markersAndStatus() {
        assertEquals("Waiting to sync", OfflineChanges.marker(change(ChangeKind.Edit)))
        assertEquals("Not sent: This vault is no longer available.", OfflineChanges.marker(change(ChangeKind.Edit, state = ChangeState.Held).copy(reason = OfflineChanges.VAULT_GONE)))
        assertEquals("Changed on another device", OfflineChanges.marker(change(ChangeKind.Edit, state = ChangeState.Conflict)))
        assertNull(OfflineChanges.status(OfflineList()))
        assertEquals("1 change waiting to sync", OfflineChanges.status(list(change(ChangeKind.Edit))))
        assertEquals("2 changes waiting to sync", OfflineChanges.status(list(change(ChangeKind.Edit), change(ChangeKind.Trash, "i2", state = ChangeState.Held))))
        assertEquals("1 change needs your decision", OfflineChanges.status(list(change(ChangeKind.Edit), change(ChangeKind.Edit, "i2", state = ChangeState.Conflict))))
        assertEquals("2 changes need your decision", OfflineChanges.status(list(change(ChangeKind.Edit, state = ChangeState.Conflict), change(ChangeKind.Edit, "i2", state = ChangeState.Conflict))))
        assertNull(OfflineChanges.lostWarning(0))
        assertEquals("1 change hasn't been sent and will be lost.", OfflineChanges.lostWarning(1))
        assertEquals("3 changes haven't been sent and will be lost.", OfflineChanges.lostWarning(3))
    }

    @Test
    fun putAndRemove() {
        val l = list(change(ChangeKind.Edit, "a"), change(ChangeKind.Edit, "b"))
        assertEquals(listOf("b"), OfflineChanges.remove(l, "a").changes.map { it.itemId })
        val held = change(ChangeKind.Edit, "a", state = ChangeState.Held)
        assertEquals(ChangeState.Held, OfflineChanges.put(l, held).of("a")!!.state)
        assertEquals(listOf("a", "b"), OfflineChanges.put(l, held).changes.map { it.itemId })
        assertEquals(listOf("a", "b", "z"), OfflineChanges.put(l, change(ChangeKind.Create, "z")).changes.map { it.itemId })
    }
}
