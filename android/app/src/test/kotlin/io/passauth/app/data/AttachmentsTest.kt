package io.passauth.app.data

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Attachments ([Attachments], [FileTransfer], [Upload]): every case of the web vault's
 * `attachments.test.ts`, the item JSON keeping the list through edits, and the streaming
 * encryption against the real core.
 */
class AttachmentsTest {
    private val a = "0b6b7c1e-0f55-4f2e-9d55-3c3a3c3a3c3a"
    private val b = "1c7c8d2f-1066-4a3f-8e66-4d4b4d4b4d4b"
    private val c = "2d8d9e30-2177-4b40-9f77-5e5c5e5c5e5c"

    private fun file(id: String, name: String = "report.pdf", size: Long = 1200) = Attachment(id, name, size, "key-$id")
    private fun raw(f: Attachment): JsonObject = Attachments.entry(f)
    private fun item(list: List<JsonElement>? = null): Item {
        val base = Item.empty(ItemKind.Note, 1).copy(name = "Passport")
        return if (list == null) base else base.copy(extra = JsonObject(mapOf("attachments" to JsonArray(list))))
    }
    private fun obj(vararg p: Pair<String, Any?>): JsonObject = JsonObject(
        p.toMap().mapValues { (_, v) ->
            when (v) {
                null -> kotlinx.serialization.json.JsonNull
                is String -> JsonPrimitive(v)
                is Number -> JsonPrimitive(v)
                else -> v as JsonElement
            }
        },
    )

    /** The core's encrypted size: 20 + size + 16 per 64 KiB chunk (at least one). */
    private val encSize = { n: Long -> 20 + n + 16 * maxOf(1, (n + 65535) / 65536) }

    @Test
    fun listsTheFilesOfAnItem() {
        assertEquals(listOf(file(a), file(b, "scan.png", 5)), Attachments.read(item(listOf(raw(file(a)), raw(file(b, "scan.png", 5))))))
        assertEquals(emptyList<Attachment>(), Attachments.read(item()))
        assertEquals(emptyList<Attachment>(), Attachments.read(null))
        assertEquals(emptyList<Attachment>(), Attachments.read(item().copy(extra = JsonObject(mapOf("attachments" to JsonPrimitive("nope"))))))
    }

    @Test
    fun leavesOutMalformedEntriesAndRepeatedIds() {
        val list = Attachments.read(
            item(
                listOf(
                    raw(file(a)),
                    raw(file(a, "again.pdf")),
                    obj("id" to a.uppercase(), "name" to "upper", "size" to 1, "key" to "k"),
                    obj("id" to "not-a-uuid", "name" to "x", "size" to 1, "key" to "k"),
                    obj("id" to b, "name" to "no key", "size" to 1),
                    obj("id" to c, "name" to "  ", "size" to -4, "key" to "k"),
                    kotlinx.serialization.json.JsonNull,
                    JsonPrimitive("text"),
                ),
            ),
        )
        assertEquals(listOf(file(a), Attachment(c, "Attachment", 0, "k")), list)
    }

    @Test
    fun keepsIdsAsWritten() {
        val upper = a.uppercase()
        assertEquals(upper, Attachments.read(item(listOf(obj("id" to upper, "name" to "a", "size" to 1, "key" to "k"))))[0].id)
        assertTrue(Attachments.sameId(upper, a))
        assertFalse(Attachments.sameId(a, b))
    }

    @Test
    fun addsAndRemovesEntriesKeepingFieldsANewerAppWrote() {
        val newer = JsonObject(raw(file(a)) + ("mime" to JsonPrimitive("application/pdf")))
        val withB = Attachments.add(item(listOf(newer)), listOf(file(b)))
        assertEquals(JsonArray(listOf(newer, raw(file(b)))), withB.extra["attachments"])
        val withoutA = Attachments.remove(withB, a.uppercase())
        assertEquals(JsonArray(listOf(raw(file(b)))), withoutA.extra["attachments"])
    }

    @Test
    fun dropsTheFieldWhenTheLastFileGoes() {
        val one = item(listOf(raw(file(a))))
        val none = Attachments.remove(one, a)
        assertFalse("attachments" in none.extra)
        assertEquals(JsonArray(listOf(raw(file(a)))), one.extra["attachments"])
        assertFalse("attachments" in Attachments.withList(item(), emptyList()).extra)
    }

    @Test
    fun givesAnEditedDraftTheListOfTheItemAsLastSynced() {
        val draft = item(listOf(raw(file(a)))).copy(notes = "edited")
        val synced = item(listOf(raw(file(a)), raw(file(b))))
        assertEquals(draft.copy(extra = JsonObject(mapOf("attachments" to JsonArray(listOf(raw(file(a)), raw(file(b))))))), Attachments.withListOf(draft, synced))
        assertFalse("attachments" in Attachments.withListOf(draft, item()).extra)
    }

    @Test
    fun mergesTwoListsByIdTheFirstOnesEntriesFirst() {
        assertEquals(
            listOf(raw(file(a)), raw(file(b)), raw(file(c))),
            Attachments.merge(item(listOf(raw(file(a)), raw(file(b)))), item(listOf(raw(file(b, "older name")), raw(file(c))))),
        )
        assertEquals(listOf(raw(file(c))), Attachments.merge(item(), item(listOf(raw(file(c))))))
        assertEquals(emptyList<JsonElement>(), Attachments.merge(null, null))
    }

    @Test
    fun exportsStripTheListAndWithItEveryFileKey() {
        val stripped = Attachments.strip(item(listOf(raw(file(a)))))
        assertFalse("attachments" in stripped.extra)
        assertFalse(ItemCodec.encode(stripped).contains("key-"))
        val plain = item()
        assertTrue(Attachments.strip(plain) === plain)
        assertTrue(Attachments.any(listOf(item(), item(listOf(raw(file(a)))))))
        assertFalse(Attachments.any(listOf(item(), item(emptyList()))))
    }

    @Test
    fun comparesTheEncryptedSizeWithTheServersLimit() {
        val mib = Attachments.MIB
        assertTrue(Attachments.tooLarge(mib, 1, encSize)) // 1 MiB of plaintext is a little more encrypted
        assertFalse(Attachments.tooLarge(mib - 20 - 16 * 16, 1, encSize))
        assertTrue(Attachments.tooLarge(mib - 20 - 16 * 16 + 1, 1, encSize))
        assertFalse(Attachments.tooLarge(10 * mib, null, encSize))
        assertFalse(Attachments.tooLarge(10, 0, encSize))
        // The core agrees with the formula.
        for (n in listOf(0L, 1L, 65535L, 65536L, 65537L, 3 * mib)) assertEquals(encSize(n), io.passauth.core.fileEncryptedSize(n.toULong()).toLong())
    }

    @Test
    fun readsTheLimitFromApiConfig() {
        assertEquals(100L, Attachments.limitMb(obj("max_attachment_mb" to 100)))
        assertEquals(null, Attachments.limitMb(obj("max_attachment_mb" to 0)))
        assertEquals(null, Attachments.limitMb(obj("max_attachment_mb" to "100")))
        assertEquals(null, Attachments.limitMb(null))
    }

    @Test
    fun keepsAPickedFilesNameWithoutFoldersOrControlCharacters() {
        assertEquals("report.pdf", Attachments.cleanName("report.pdf"))
        assertEquals("scan 1.png", Attachments.cleanName("C:\\Users\\me\\scan 1.png"))
        assertEquals("abc.txt", Attachments.cleanName("a\u0000b\u001fc.txt"))
        assertEquals("Attachment", Attachments.cleanName("   "))
        assertEquals(255, Attachments.cleanName("x".repeat(300) + ".txt").length)
    }

    @Test
    fun savesUnderANameFileSystemsAccept() {
        assertEquals("report.pdf", Attachments.downloadName("report.pdf"))
        assertEquals("_.._etc_passwd", Attachments.downloadName("../../etc/passwd"))
        assertEquals("a_b_c__d_e_f_g", Attachments.downloadName("a:b*c?\"d<e>f|g"))
        assertEquals("attachment", Attachments.downloadName("..."))
        assertEquals("attachment", Attachments.downloadName(""))
    }

    @Test
    fun showsAndSavesANameThatCantPretendToBeAnotherFile() {
        assertEquals("invoicefdp.exe", Attachments.cleanName("invoice\u202Efdp.exe"))
        assertEquals("invoicefdp.exe", Attachments.downloadName("invoice\u202Efdp.exe"))
        assertEquals("abc.txt", Attachments.downloadName("\u2066a\u2067b\u2068c\u2069.txt\u200E\u200F\uFEFF"))
        assertEquals("scan.pdf", Attachments.downloadName("scan\u200B.p\u200Ddf"))
        // Windows drops trailing dots and spaces: "report.exe. " would really be "report.exe".
        assertEquals("report.exe", Attachments.cleanName("report.exe. . "))
        assertEquals("report.exe", Attachments.downloadName("report.exe. . "))
        // White space can't push the extension out of sight.
        assertEquals("invoice.pdf .exe", Attachments.downloadName("invoice.pdf\u3000    \u00A0  .exe"))
        assertEquals("abc.txt", Attachments.downloadName("a\u0000b\u0085c\u2028.txt"))
    }

    @Test
    fun neverSavesUnderAWindowsDeviceName() {
        for (name in listOf("CON", "con.txt", "Nul.tar.gz", "AUX", "prn.doc", "COM1.txt", "lpt9", "COM0.log", "LPT\u00B9.txt", "con .txt")) {
            assertEquals("_$name", Attachments.downloadName(name))
        }
        for (name in listOf("CONSOLE.txt", "COM10.txt", "aux file.txt", "icon.png", "my con.txt")) assertEquals(name, Attachments.downloadName(name))
    }

    @Test
    fun keepsTheExtensionWhenALongNameIsCut() {
        val saved = Attachments.downloadName("a".repeat(300) + ".pdf")
        assertEquals(200, CleanText.length(saved))
        assertTrue(saved.endsWith("a.pdf"))
        assertEquals(200, CleanText.length(Attachments.downloadName("b".repeat(300))))
        assertTrue(Attachments.cleanName("c".repeat(300) + ".tar.gz").endsWith("c.gz"))
    }

    @Test
    fun showsTheFilesOfAnItemUnderCleanNames() {
        assertEquals("paygpj.exe", Attachments.read(item(listOf(raw(file(a, "pay\u202Egpj.exe")))))[0].name)
        assertEquals("Attachment", Attachments.read(item(listOf(raw(file(a, "\u202E")))))[0].name)
        assertEquals("Attachment", Attachments.read(item(listOf(obj("id" to a, "name" to 42, "size" to 1200, "key" to "key-$a"))))[0].name)
    }

    private val stored = Attachments.readStored(
        AppJson.parseToJsonElement(
            """{"attachments":[{"id":"$a","size":1236,"state":"ready","updated_at":1000},{"id":"$b","size":80,"state":"pending","updated_at":1000},
            {"id":"$c","size":80,"state":"ready","updated_at":5000},{"id":"bad","size":1,"state":"ready"},{"id":"$a","size":1,"state":"deleted"}]}""",
        ),
    )

    @Test
    fun readsTheServersListLeavingOutMalformedEntries() {
        assertEquals(listOf(a, b, c), stored.map { it.id })
        assertEquals(emptyList<StoredAttachment>(), Attachments.readStored(AppJson.parseToJsonElement("{}")))
        assertEquals(emptyList<StoredAttachment>(), Attachments.readStored(kotlinx.serialization.json.JsonNull))
    }

    @Test
    fun findsListedFilesTheServerDoesntHaveReady() {
        val other = "3e9eaf41-3288-4c51-8088-6f6d6f6d6f6d"
        assertEquals(setOf(b, other), Attachments.missingOnServer(listOf(file(a.uppercase()), file(b), file(other)), stored))
    }

    @Test
    fun findsFinishedUploadsNoItemListsOnceNobodyCanStillBeAttachingThem() {
        val listed = item(listOf(raw(file(a))))
        assertEquals(emptyList<String>(), Attachments.leftovers(listed, stored, 1000 + Attachments.LEFTOVER_AFTER).map { it.id })
        assertEquals(listOf(c), Attachments.leftovers(listed, stored, 5000 + Attachments.LEFTOVER_AFTER).map { it.id })
        // Pending uploads are left to the server, which deletes them after an hour.
        assertEquals(listOf(a, c), Attachments.leftovers(item(), stored, 99_999).map { it.id })
    }

    // ---------------------------------------------------------- the item JSON

    @Test
    fun theItemKeepsItsFileListAndOtherNewFieldsThroughAnEdit() {
        val json = """{"name":"Passport","notes":"","attachments":[{"id":"$a","name":"scan.pdf","size":10,"key":"k","mime":"x"}],"future":{"x":1}}"""
        val item = ItemCodec.decode(json)
        assertEquals(1, Attachments.read(item).size)
        val edited = ItemCodec.decode(ItemCodec.encode(item.copy(notes = "changed")))
        val out = AppJson.parseToJsonElement(ItemCodec.encode(edited)) as JsonObject
        assertEquals(AppJson.parseToJsonElement(json).let { (it as JsonObject)["attachments"] }, out["attachments"])
        assertEquals(buildJsonObject { put("x", 1) }, out["future"])
        assertEquals("changed", (out["notes"] as JsonPrimitive).content)
        // Fields the app models are never taken from the extras.
        assertEquals(item, ItemCodec.decode(ItemCodec.encode(item)))
    }

    // ------------------------------------------- streaming, with the real core

    private val itemId = "11111111-2222-4333-8444-555555555555"

    private fun roundTrip(size: Int, chunk: Int) {
        val plain = ByteArray(size) { (it * 31 + 7).toByte() }
        val key = io.passauth.core.fileNewKey()
        val enc = ByteArrayOutputStream()
        val written = EncryptingCipher(key, itemId, a).use { FileTransfer.encrypt(ByteArrayInputStream(plain), size.toLong(), it, enc, chunk) }
        assertEquals(io.passauth.core.fileEncryptedSize(size.toULong()).toLong(), written)
        assertEquals(written, enc.size().toLong())
        val out = ByteArrayOutputStream()
        DecryptingCipher(key, itemId, a).use { FileTransfer.decrypt(ByteArrayInputStream(enc.toByteArray()), it, out) }
        assertArrayEquals(plain, out.toByteArray())
        // The whole-file function of the core reads it the same way.
        assertArrayEquals(plain, io.passauth.core.fileDecrypt(key, itemId, a, enc.toByteArray()))
    }

    @Test
    fun encryptsAndDecryptsInPiecesOfAnySize() {
        roundTrip(0, 1024)
        roundTrip(1, 1024)
        roundTrip(65536, 1000)
        roundTrip(200_000, 70_000)
        roundTrip(3 * 65536 + 5, FileTransfer.READ_CHUNK)
    }

    @Test
    fun aCutOrChangedFileNeverBecomesAFile() {
        val plain = ByteArray(150_000) { it.toByte() }
        val key = io.passauth.core.fileNewKey()
        val enc = ByteArrayOutputStream()
        EncryptingCipher(key, itemId, a).use { FileTransfer.encrypt(ByteArrayInputStream(plain), plain.size.toLong(), it, enc) }
        val bytes = enc.toByteArray()
        val dir = kotlin.io.path.createTempDirectory("pa-att").toFile()
        try {
            val dest = File(dir, "out.bin")
            // Cut short: no file, no part file.
            assertThrows(DamagedFile::class.java) {
                DecryptingCipher(key, itemId, a).use { FileTransfer.decryptToFile(ByteArrayInputStream(bytes.copyOf(bytes.size - 10)), it, dest) }
            }
            assertFalse(dest.exists())
            assertEquals(0, dir.listFiles()!!.size)
            // Bound to the attachment's id: another id doesn't open it.
            assertThrows(DamagedFile::class.java) {
                DecryptingCipher(key, itemId, b).use { FileTransfer.decryptToFile(ByteArrayInputStream(bytes), it, dest) }
            }
            assertEquals(0, dir.listFiles()!!.size)
            DecryptingCipher(key, itemId, a).use { FileTransfer.decryptToFile(ByteArrayInputStream(bytes), it, dest) }
            assertArrayEquals(plain, dest.readBytes())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aFileThatChangesSizeWhileReadIsRefused() {
        val key = io.passauth.core.fileNewKey()
        assertThrows(FileChanged::class.java) {
            EncryptingCipher(key, itemId, a).use { FileTransfer.encrypt(ByteArrayInputStream(ByteArray(10)), 11, it, ByteArrayOutputStream()) }
        }
        assertThrows(FileChanged::class.java) {
            EncryptingCipher(key, itemId, a).use { FileTransfer.encrypt(ByteArrayInputStream(ByteArray(12)), 11, it, ByteArrayOutputStream()) }
        }
    }

    private class Steps(val failPut: Boolean = false, val putRuns: Int = 1) : UploadSteps {
        val log = mutableListOf<String>()
        var keys = 0
        val body = ByteArrayOutputStream()
        override fun newId() = "99999999-2222-4333-8444-555555555555"
        override fun newKey(): String {
            keys++
            return io.passauth.core.fileNewKey()
        }
        override fun encryptedSize(plain: Long) = io.passauth.core.fileEncryptedSize(plain.toULong()).toLong()
        override fun encryptor(key: String, itemId: String, attachmentId: String): FileCipher = EncryptingCipher(key, itemId, attachmentId)
        override suspend fun register(itemId: String, id: String, size: Long) {
            log += "register $id $size"
        }
        override suspend fun put(id: String, size: Long, write: (OutputStream) -> Unit) {
            repeat(putRuns) {
                body.reset()
                write(body)
            }
            log += "put $id ${body.size()}"
            if (failPut) throw ApiException(507, "insufficient_storage", "full")
        }
        override suspend fun discard(id: String) {
            log += "discard $id"
        }
    }

    @Test
    fun uploadsRegisterThenSendExactlyTheEncryptedSize() = runBlocking {
        val plain = ByteArray(70_000) { 3 }
        val steps = Steps(putRuns = 2)
        val done = Upload.run({ ByteArrayInputStream(plain) }, plain.size.toLong(), itemId, steps)
        val size = io.passauth.core.fileEncryptedSize(70_000u).toLong()
        assertEquals(listOf("register ${done.id} $size", "put ${done.id} $size"), steps.log)
        // A second run of the body (after a renewed session) made a new key: the one returned opened the bytes sent last.
        assertEquals(2, steps.keys)
        assertArrayEquals(plain, io.passauth.core.fileDecrypt(done.key, itemId, done.id, steps.body.toByteArray()))
    }

    @Test
    fun aFailedUploadDeletesItsAttachment() = runBlocking {
        val steps = Steps(failPut = true)
        try {
            Upload.run({ ByteArrayInputStream(ByteArray(5)) }, 5, itemId, steps)
            fail("the upload should fail")
        } catch (e: ApiException) {
            assertEquals("insufficient_storage", e.code)
        }
        assertEquals("discard 99999999-2222-4333-8444-555555555555", steps.log.last())
        // Stopped before it started: nothing registered, nothing to delete.
        val stopped = Steps()
        assertThrows(TransferCancelled::class.java) { runBlocking { Upload.run({ ByteArrayInputStream(ByteArray(5)) }, 5, itemId, stopped, stopped = { true }) } }
        assertEquals(emptyList<String>(), stopped.log)
    }
}
