package io.passauth.app.data

import java.net.URLEncoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put

/**
 * Send (servers with the `sends` feature): text shared through a link, `<server>/send/<id>#<key>`.
 * The app encrypts the name and the text with a random send key that exists only in the link's
 * fragment and keeps the key wrapped by the account key (`owner_key`), so the owner can copy the
 * link and edit the Send later. The server stores ciphertext only and decides who may open it, how
 * often and until when; an optional password is checked by the server with a verifier the
 * visitor's app derives from it (`access_salt`), not used for encryption.
 *
 * The web vault's `lib/sends.ts`, with the same rules; pure and unit-tested in SendsTest.
 * [SendActions] encrypts and talks to the server.
 */
object Sends {
    const val FEATURE = "sends"

    /** The link to share: the server's address, the Send's id and, after `#`, its key. */
    fun link(origin: String, id: String, key: String): String =
        "${origin.trimEnd('/')}/send/${URLEncoder.encode(id, "UTF-8").replace("+", "%20")}#$key"

    /** The link with its key (everything after `#`) hidden, for showing it on screen; copying uses the whole link. */
    fun maskedLink(link: String): String {
        val at = link.indexOf('#')
        return if (at < 0) link else link.substring(0, at + 1) + "•".repeat(12)
    }

    // -------------------------------------------------------------- sizes

    /** Bytes the core adds when it encrypts a field: a version byte, the 24-byte nonce and the 16-byte tag. */
    private const val OVERHEAD = 1 + 24 + 16

    fun utf8Length(text: String): Int = text.toByteArray(Charsets.UTF_8).size

    /** Characters of the encrypted field (unpadded base64url) for [plainBytes] bytes of text: what the server limits. */
    fun encryptedFieldLength(plainBytes: Int): Int = Math.ceil(((plainBytes + OVERHEAD).toLong() * 4) / 3.0).toInt()

    /** The most text (UTF-8 bytes) that fits the server's limit on the encrypted text (`limits.send_max_bytes`). */
    fun maxTextBytes(maxEncrypted: Int): Int = maxOf(0, Math.floor(maxEncrypted * 3 / 4.0).toInt() - OVERHEAD)

    /** The server's limit on a Send's encrypted text when `/api/config` doesn't say (1 MiB). */
    const val DEFAULT_MAX_BYTES = 1024 * 1024

    /** The longest a Send may stay when `/api/config` doesn't say: the server's default `send_max_days`. */
    const val DEFAULT_MAX_DAYS = 30

    /** Longest name accepted in the form (its ciphertext stays far below the server's 8 KiB). */
    const val NAME_MAX = 200

    /** Most views a Send may allow (the server's limit). */
    const val MAX_VIEWS = 1_000_000

    data class Limits(val maxDays: Int, val maxBytes: Int)

    /** `send_max_days` and `send_max_bytes` from `/api/config` `limits`, with the server's defaults when missing. */
    fun limits(limits: JsonElement?): Limits {
        val l = limits as? JsonObject
        fun whole(key: String, min: Int, fallback: Int): Int {
            val p = l?.get(key) as? JsonPrimitive ?: return fallback
            if (p.isString) return fallback
            val v = p.doubleOrNull ?: return fallback
            return if (v.isFinite() && v >= min) Math.floor(v).toInt() else fallback
        }
        return Limits(whole("send_max_days", 1, DEFAULT_MAX_DAYS), whole("send_max_bytes", 1024, DEFAULT_MAX_BYTES))
    }

    // ---------------------------------------------------------- durations

    private const val HOUR = 3600L
    private const val DAY = 24 * HOUR

    /** Durations offered for a Send's deletion and expiry, in seconds, with their labels. */
    private val PRESETS: List<Pair<Long, String>> = listOf(
        HOUR to "1 hour",
        DAY to "1 day",
        2 * DAY to "2 days",
        3 * DAY to "3 days",
        7 * DAY to "7 days",
        14 * DAY to "14 days",
        30 * DAY to "30 days",
        90 * DAY to "90 days",
        180 * DAY to "180 days",
        365 * DAY to "365 days",
    )

    private fun dayLabel(days: Long) = "$days ${if (days == 1L) "day" else "days"}"

    /** The durations within [maxDays] (the server's `send_max_days`), and the limit itself when it isn't one of them. */
    fun durationChoices(maxDays: Int): List<Pair<Long, String>> {
        val max = maxOf(1, maxDays) * DAY
        val within = PRESETS.filter { it.first <= max }
        return if (within.any { it.first == max }) within else within + (max to dayLabel(max / DAY))
    }

    /** The deletion offered first: 7 days, or the server's limit when that is shorter. */
    fun defaultDeletion(maxDays: Int): Long = minOf(7 * DAY, maxOf(1, maxDays) * DAY)

    // -------------------------------------------------------------- owner

    private fun num(v: JsonElement?): Long? = (v as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() }?.toLong()
    private fun text(v: JsonElement?): String? = (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }
    private fun bool(v: JsonElement?): Boolean? = (v as? JsonPrimitive)?.takeIf { !it.isString }?.content?.let { if (it == "true") true else if (it == "false") false else null }

    /** One Send from the owner's API, or null when malformed. */
    fun read(value: JsonElement?): OwnedSend? {
        val s = value as? JsonObject ?: return null
        val id = text(s["id"]) ?: return null
        val name = text(s["name"]) ?: return null
        val ownerKey = text(s["owner_key"]) ?: return null
        val deleteAt = num(s["delete_at"]) ?: return null
        return OwnedSend(
            id = id,
            name = name,
            ownerKey = ownerKey,
            hasPassword = bool(s["has_password"]) == true,
            accessSalt = text(s["access_salt"]),
            maxViews = num(s["max_views"]),
            views = num(s["views"]) ?: 0,
            expiresAt = num(s["expires_at"]),
            deleteAt = deleteAt,
            disabled = bool(s["disabled"]) == true,
            hideEmail = bool(s["hide_email"]) == true,
            available = bool(s["available"]) ?: true,
            createdAt = num(s["created_at"]) ?: 0,
            updatedAt = num(s["updated_at"]) ?: 0,
            data = text(s["data"]),
        )
    }

    /** `GET /sends`: the owner's Sends, newest first as the server sends them; malformed entries left out. */
    fun readList(value: JsonElement?): List<OwnedSend> =
        ((value as? JsonObject)?.get("sends") as? JsonArray)?.mapNotNull { read(it) }.orEmpty()

    /** Why a Send can or can't be opened right now (its own settings first, then the server's say). */
    fun state(s: OwnedSend, now: Long): SendState = when {
        s.deleteAt <= now -> SendState.Deleted
        s.disabled -> SendState.Disabled
        s.expiresAt != null && s.expiresAt <= now -> SendState.Expired
        s.maxViews != null && s.views >= s.maxViews -> SendState.UsedUp
        s.available -> SendState.Available
        else -> SendState.Unavailable
    }

    /** "Not opened yet", "Opened 3 times", "Opened 2 of 5 times". */
    fun viewsText(views: Long, maxViews: Long?): String = when {
        maxViews != null -> "Opened $views of $maxViews ${if (maxViews == 1L) "time" else "times"}"
        views == 0L -> "Not opened yet"
        else -> "Opened $views ${if (views == 1L) "time" else "times"}"
    }

    /** The `PUT /sends/{id}` body for [changes] (null clears `max_views` / `expires_at`; `access_verifier: null` removes the password). */
    fun changesBody(changes: SendChanges): JsonObject = buildJsonObject {
        changes.name?.let { put("name", it) }
        changes.data?.let { put("data", it) }
        when (val p = changes.password) {
            SendPassword.Keep -> Unit
            SendPassword.Remove -> put("access_verifier", JsonNull)
            is SendPassword.Set -> {
                put("access_salt", p.salt)
                put("access_verifier", p.verifier)
            }
        }
        changes.maxViews?.let { put("max_views", it.value?.let(::JsonPrimitive) ?: JsonNull) }
        changes.expiresAt?.let { put("expires_at", it.value?.let(::JsonPrimitive) ?: JsonNull) }
        changes.deleteAt?.let { put("delete_at", it) }
        changes.disabled?.let { put("disabled", it) }
        changes.hideEmail?.let { put("hide_email", it) }
    }

    /** "Active", "Turned off"… */
    fun stateLabel(s: SendState) = s.label
}

/** A Send as its owner's list shows it (`GET /sends`); [name] and [ownerKey] are encrypted. */
data class OwnedSend(
    val id: String,
    /** Encrypted with the send key. */
    val name: String,
    /** The send key wrapped by the account key. */
    val ownerKey: String,
    val hasPassword: Boolean = false,
    val accessSalt: String? = null,
    val maxViews: Long? = null,
    val views: Long = 0,
    val expiresAt: Long? = null,
    val deleteAt: Long,
    val disabled: Boolean = false,
    val hideEmail: Boolean = false,
    /** Whether a visitor can open it right now (the server's answer, which also knows if Send is turned off). */
    val available: Boolean = true,
    val createdAt: Long = 0,
    val updatedAt: Long = 0,
    /** Encrypted text: only in `GET /sends/{id}`. */
    val data: String? = null,
)

enum class SendState(val label: String) {
    Available("Active"),
    Disabled("Turned off"),
    UsedUp("Used up"),
    Expired("Expired"),
    Deleted("Deleted"),
    Unavailable("Unavailable"),
}

/** A setting changed to [value] (null: cleared). */
data class Change<T>(val value: T?)

/** What a Send's password does in a change. */
sealed interface SendPassword {
    data object Keep : SendPassword
    data object Remove : SendPassword
    data class Set(val salt: String, val verifier: String) : SendPassword
}

/** What a change of a Send sends (`PUT /sends/{id}` takes only what changed; null = unchanged). */
data class SendChanges(
    val name: String? = null,
    val data: String? = null,
    val password: SendPassword = SendPassword.Keep,
    val maxViews: Change<Long>? = null,
    val expiresAt: Change<Long>? = null,
    val deleteAt: Long? = null,
    val disabled: Boolean? = null,
    val hideEmail: Boolean? = null,
)

/** A new Send, in plain text. */
data class NewSend(
    val name: String,
    val text: String,
    val password: String?,
    val maxViews: Long?,
    val expiresAt: Long?,
    val deleteAt: Long,
    val hideEmail: Boolean,
)

/** What the owner changed (null = unchanged): plain name and text, a new password ("" removes it), and settings. */
data class SendEdit(
    val name: String? = null,
    val text: String? = null,
    /** null: keep; "": remove; else the new password. */
    val password: String? = null,
    val maxViews: Change<Long>? = null,
    val expiresAt: Change<Long>? = null,
    val deleteAt: Long? = null,
    val disabled: Boolean? = null,
    val hideEmail: Boolean? = null,
)

/** The core's Send functions and this account's key wrap (fakes in tests). */
interface SendCrypto {
    fun newKey(): String
    fun encrypt(key: String, field: String, plain: String): String
    fun decrypt(key: String, field: String, cipher: String): String
    fun wrap(key: String): String
    fun unwrap(wrapped: String): String
    fun passwordSalt(): String
    fun verifier(password: String, salt: String): String
}

/**
 * Send, the owner's side (the web vault's `send-client.ts`): encrypt, list, change and delete
 * Sends over [transport]. [crypto] is looked up for each call: a lock frees the account key.
 */
class SendActions(private val transport: SecurityTransport, private val crypto: () -> SendCrypto) {
    private fun path(id: String) = "/sends/${URLEncoder.encode(id, "UTF-8").replace("+", "%20")}"

    /** The Send's key (for its link and its text), from its `owner_key`. */
    fun keyOf(s: OwnedSend): String = crypto().unwrap(s.ownerKey)

    /** The Send's name, or null when it can't be decrypted (made by an account key this account no longer has). */
    fun nameOf(s: OwnedSend): String? = try {
        val c = crypto()
        c.decrypt(c.unwrap(s.ownerKey), "name", s.name)
    } catch (e: Exception) {
        if (e is UserException) throw e
        null
    }

    /** The Send's text (`data`, from `GET /sends/{id}`). */
    fun textOf(s: OwnedSend): String {
        val data = s.data ?: throw UserException(UNEXPECTED)
        val c = crypto()
        return c.decrypt(c.unwrap(s.ownerKey), "data", data)
    }

    suspend fun list(): List<OwnedSend> = Sends.readList(transport.call("/sends", null, "GET", true, emptyMap()))

    /** One Send with its text. */
    suspend fun get(id: String): OwnedSend = Sends.read(transport.call(path(id), null, "GET", true, emptyMap())) ?: throw UserException(UNEXPECTED)

    /** A new password's salt and verifier (Argon2id, about a second): the server keeps only the verifier's hash. */
    private fun passwordFields(c: SendCrypto, password: String): SendPassword.Set {
        val salt = c.passwordSalt()
        return SendPassword.Set(salt, c.verifier(password, salt))
    }

    /** The `POST /sends` body for [d] encrypted with [key]. */
    fun createBody(d: NewSend, key: String): JsonObject {
        val c = crypto()
        val pw = d.password?.takeIf { it.isNotEmpty() }?.let { passwordFields(c, it) }
        return buildJsonObject {
            put("kind", "text")
            put("name", c.encrypt(key, "name", d.name))
            put("data", c.encrypt(key, "data", d.text))
            put("owner_key", c.wrap(key))
            put("max_views", d.maxViews?.let(::JsonPrimitive) ?: JsonNull)
            put("expires_at", d.expiresAt?.let(::JsonPrimitive) ?: JsonNull)
            put("delete_at", d.deleteAt)
            put("hide_email", d.hideEmail)
            put("disabled", false)
            if (pw != null) {
                put("access_salt", pw.salt)
                put("access_verifier", pw.verifier)
            }
        }
    }

    /** Encrypt and save a new Send; returns it with its key (the link is made from [server]'s address). */
    suspend fun create(d: NewSend): Pair<OwnedSend, String> {
        val key = crypto().newKey()
        val send = Sends.read(transport.call("/sends", createBody(d, key), "POST", true, emptyMap())) ?: throw UserException(UNEXPECTED)
        return send to key
    }

    /** The changes [edit] makes to [s]: only what changed; name and text encrypted again with the same key (the link has it). */
    fun changesOf(s: OwnedSend, edit: SendEdit): SendChanges {
        val c = crypto()
        var name: String? = null
        var data: String? = null
        if (edit.name != null || edit.text != null) {
            val key = c.unwrap(s.ownerKey)
            if (edit.name != null) name = c.encrypt(key, "name", edit.name)
            if (edit.text != null) data = c.encrypt(key, "data", edit.text)
        }
        val password = when {
            edit.password == null -> SendPassword.Keep
            edit.password.isEmpty() -> SendPassword.Remove
            else -> passwordFields(c, edit.password)
        }
        return SendChanges(name, data, password, edit.maxViews, edit.expiresAt, edit.deleteAt, edit.disabled, edit.hideEmail)
    }

    /** Save changes to a Send. */
    suspend fun update(s: OwnedSend, edit: SendEdit): OwnedSend =
        Sends.read(transport.call(path(s.id), Sends.changesBody(changesOf(s, edit)), "PUT", true, emptyMap())) ?: throw UserException(UNEXPECTED)

    /** Delete a Send; one already gone counts as done. */
    suspend fun delete(id: String) {
        try {
            transport.call(path(id), null, "DELETE", true, emptyMap())
        } catch (e: ApiException) {
            if (e.status != 404) throw e
        }
    }

    companion object {
        const val UNEXPECTED = "The server sent an unexpected response. Try again."
    }
}
