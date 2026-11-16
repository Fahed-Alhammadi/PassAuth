package io.passauth.app.data

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put

/** A file an item lists: [size] is the file's own size, [key] its own key (base64url). */
data class Attachment(val id: String, val name: String, val size: Long, val key: String)

/** An attachment as the server lists it (`GET /items/{id}/attachments`): never its name or key. */
data class StoredAttachment(
    val id: String,
    /** Bytes of the encrypted file. */
    val size: Long,
    /** "pending" or "ready". */
    val ready: Boolean,
    /** Unix seconds: when it was made, started uploading or became ready. */
    val updatedAt: Long,
)

/**
 * Attachments (servers with the `attachments` feature): files encrypted on the device, each with a
 * random key of its own, and listed inside the encrypted item as `attachments: [{id, name, size, key}]`
 * (kept in [Item.extra], so entries keep fields a newer app wrote). The server keeps the ciphertext
 * under the attachment's id and never sees a file's name, key or contents.
 *
 * Adding one: a new key → `POST /items/{id}/attachments {id, size: encrypted size}` → `PUT
 * /attachments/{id}` with the encrypted file → save the item listing it (if that save fails for
 * good, `DELETE` the attachment). Removing one: save the item without it, then `DELETE`.
 *
 * The web vault's `lib/attachments.ts`, with the same rules; pure and unit-tested in AttachmentsTest.
 */
object Attachments {
    const val FEATURE = "attachments"
    const val MIB = 1024L * 1024L

    /** Longest file name kept, in characters. */
    private const val NAME_MAX = 255

    /** Attachment ids are UUIDs (the server refuses anything else). */
    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    private fun rawList(item: Item?): List<JsonElement> = item?.extra?.get("attachments") as? JsonArray ?: emptyList()

    /** An entry's id, lowercased for comparing (the server answers in lowercase); null when it isn't a UUID. */
    private fun entryId(v: JsonElement?): String? {
        val id = ((v as? JsonObject)?.get("id") as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        return if (UUID.matches(id)) id.lowercase() else null
    }

    fun sameId(a: String, b: String) = a.equals(b, ignoreCase = true)

    /**
     * The files an item lists, for showing and opening them. Entries without an id or key, and
     * repeated ids, are left out. Ids are kept as written: the file's encryption is bound to them
     * exactly. Names are cleaned ([cleanName]): another member of a shared vault may have chosen
     * one to look like something else.
     */
    fun read(item: Item?): List<Attachment> {
        val seen = mutableSetOf<String>()
        val out = mutableListOf<Attachment>()
        for (raw in rawList(item)) {
            val lower = entryId(raw) ?: continue
            if (lower in seen) continue
            val v = raw as JsonObject
            val key = (v["key"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() } ?: continue
            seen += lower
            val size = (v["size"] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() && it >= 0 }?.let { Math.floor(it).toLong() } ?: 0
            val name = (v["name"] as? JsonPrimitive)?.takeIf { it.isString }?.content.orEmpty()
            out += Attachment((v["id"] as JsonPrimitive).content, cleanName(name), size, key)
        }
        return out
    }

    /** [item] listing exactly [list] (raw entries); an empty list removes the field, as for an item that never had files. */
    fun withList(item: Item, list: List<JsonElement>): Item =
        item.copy(extra = JsonObject(if (list.isEmpty()) item.extra - "attachments" else item.extra + ("attachments" to JsonArray(list))))

    fun entry(a: Attachment): JsonObject = buildJsonObject {
        put("id", a.id)
        put("name", a.name)
        put("size", a.size)
        put("key", a.key)
    }

    /** [item] with [added] at the end of its list. */
    fun add(item: Item, added: List<Attachment>): Item = withList(item, rawList(item) + added.map(::entry))

    /** [item] without attachment [id]. */
    fun remove(item: Item, id: String): Item = withList(item, rawList(item).filter { entryId(it) != id.lowercase() })

    /**
     * [item] (an edited draft) listing the files of [from] (the item as last synced): the editor never
     * changes the list. A value that isn't a list (from a newer app) is kept exactly as it was.
     */
    fun withListOf(item: Item, from: Item?): Item {
        val raw = from?.extra?.get("attachments")
        if (raw != null && raw !is JsonArray) return item.copy(extra = JsonObject(item.extra + ("attachments" to raw)))
        return withList(item, rawList(from))
    }

    /** Every entry of [first], then those of [second] with other ids. */
    fun merge(first: Item?, second: Item?): List<JsonElement> {
        val seen = mutableSetOf<String>()
        return (rawList(first) + rawList(second)).filter { raw -> entryId(raw)?.let { seen.add(it) } == true }
    }

    /** An item for an export file: without its file list (and so without the files' keys). */
    fun strip(item: Item): Item = if ("attachments" in item.extra) item.copy(extra = JsonObject(item.extra - "attachments")) else item

    /** Whether any of [items] lists a file (the export page then says files aren't included). */
    fun any(items: List<Item>): Boolean = items.any { read(it).isNotEmpty() }

    // -------------------------------------------------------------- sizes

    /**
     * Whether a file of [plainSize] bytes is too large for the server: its limit (`max_attachment_mb`)
     * applies to the encrypted size, as the server counts it. Null [maxMb] (an older server that
     * doesn't say) never refuses.
     */
    fun tooLarge(plainSize: Long, maxMb: Long?, encryptedSize: (Long) -> Long): Boolean {
        if (maxMb == null || maxMb <= 0) return false
        return encryptedSize(plainSize) > maxMb * MIB
    }

    /** The server's attachment limit in MB from `/api/config` `limits`, or null when it doesn't say. */
    fun limitMb(limits: JsonElement?): Long? {
        val p = (limits as? JsonObject)?.get("max_attachment_mb") as? JsonPrimitive ?: return null
        if (p.isString) return null
        val v = p.doubleOrNull ?: return null
        return if (v.isFinite() && v >= 1) Math.floor(v).toLong() else null
    }

    // -------------------------------------------------------------- names

    /** Longest name a saved file gets, in characters. */
    private const val SAVE_MAX = 200

    /** Characters a file name can't hold on some system, saved as "_". */
    private val NOT_IN_NAMES = Regex("[\\\\/:*?\"<>|]")

    /** Names Windows keeps for devices, also with any extension: a file can't be saved under them. */
    private val DEVICE_NAME = Regex("^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])\\s*(?:\\.|$)", RegexOption.IGNORE_CASE)

    /** No control or format characters, one space for any run of white space, no dots or spaces at the end. */
    private fun tidy(name: String): String = trimTrailingDots(CleanText.trim(CleanText.foldSpace(CleanText.stripInvisible(name))))

    private fun trimTrailingDots(s: String): String {
        var end = s.length
        while (end > 0) {
            val cp = s.codePointBefore(end)
            if (cp == '.'.code || CleanText.isSpace(cp)) end -= Character.charCount(cp) else break
        }
        return s.substring(0, end)
    }

    /** [name] cut to [max] characters, keeping a short extension at its end. */
    private fun shorten(name: String, max: Int): String {
        if (CleanText.length(name) <= max) return name
        val dot = name.lastIndexOf('.')
        val ext = if (dot > 0) name.substring(dot) else ""
        val extLen = CleanText.length(ext)
        val keep = if (extLen in 2..16) ext else ""
        return trimTrailingDots(CleanText.take(name, max - CleanText.length(keep))) + keep
    }

    /**
     * The name kept and shown for a file: its own name without folders, control or format
     * characters, runs of white space or trailing dots and spaces, at most 255 characters;
     * "Attachment" when nothing is left.
     */
    fun cleanName(name: String): String {
        val base = CleanText.stripInvisible(name).split('\\', '/').last()
        return shorten(tidy(base), NAME_MAX).ifEmpty { "Attachment" }
    }

    /**
     * The name a downloaded file is saved under: the stored name cleaned as above, with "_" for
     * characters a file system would refuse, without leading dots (no hidden files), not a Windows
     * device name, at most 200 characters with its extension kept; "attachment" when nothing is left.
     */
    fun downloadName(name: String): String {
        val replaced = tidy(name).replace(NOT_IN_NAMES, "_")
        var start = 0
        while (start < replaced.length && (replaced[start] == '.' || CleanText.isSpace(replaced.codePointAt(start)))) start++
        val clean = shorten(tidy(replaced.substring(start)), SAVE_MAX)
        if (clean.isEmpty()) return "attachment"
        return if (DEVICE_NAME.containsMatchIn(clean)) "_$clean" else clean
    }

    // ------------------------------------------------------ server's list

    /** The server's list for an item; malformed entries are left out. */
    fun readStored(value: JsonElement?): List<StoredAttachment> {
        val list = (value as? JsonObject)?.get("attachments") as? JsonArray ?: return emptyList()
        return list.mapNotNull { raw ->
            val id = entryId(raw) ?: return@mapNotNull null
            val v = raw as JsonObject
            val state = (v["state"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (state != "pending" && state != "ready") return@mapNotNull null
            fun n(k: String) = (v[k] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() }?.toLong() ?: 0
            StoredAttachment(id, n("size"), state == "ready", n("updated_at"))
        }
    }

    /** The listed files the server doesn't have ready (deleted since, e.g. listed again by restoring an earlier version). */
    fun missingOnServer(list: List<Attachment>, stored: List<StoredAttachment>): Set<String> {
        val ready = stored.filter { it.ready }.map { it.id }.toSet()
        return list.filter { it.id.lowercase() !in ready }.map { it.id }.toSet()
    }

    /** Uploads whose item doesn't list them may still be on their way to the item for this long (seconds). */
    const val LEFTOVER_AFTER = 15 * 60L

    /** Files on the server that the item doesn't list and that nobody is still attaching. */
    fun leftovers(item: Item?, stored: List<StoredAttachment>, now: Long): List<StoredAttachment> {
        val listed = read(item).map { it.id.lowercase() }.toSet()
        return stored.filter { it.ready && it.id !in listed && now - it.updatedAt >= LEFTOVER_AFTER }
    }
}
