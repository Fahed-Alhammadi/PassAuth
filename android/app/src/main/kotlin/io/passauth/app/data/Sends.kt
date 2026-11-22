package io.passauth.app.data

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
 * visitor's app derives from it (`access_salt`). Send v2 ([Sends.FEATURE_V2]): a Send with a
 * password is also encrypted with it (content key from the link key and the password); the owner
 * keeps that content key wrapped by the account key (`owner_content_key`). Without a password, or
 * on servers without v2: v1, encrypted with the link key only.
 *
 * The web vault's `lib/sends.ts`, with the same rules; pure and unit-tested in SendsTest.
 * [SendActions] encrypts and talks to the server.
 */
object Sends {
    const val FEATURE = "sends"

    /**
     * Send v2 (servers that list it): a Send with a password is encrypted with a key that needs the
     * link AND the password (`owner_content_key` lets the owner read it without the password).
     */
    const val FEATURE_V2 = "send_v2"

    /** The link to share: the server's address, the Send's id and, after `#`, its key. */
    fun link(origin: String, id: String, key: String): String =
        "${origin.trimEnd('/')}/send/${urlPart(id)}#$key"

    /** The link with its key (everything after `#`) hidden, for showing it on screen; copying uses the whole link. */
    fun maskedLink(link: String): String {
        val at = link.indexOf('#')
        return if (at < 0) link else link.substring(0, at + 1) + "•".repeat(12)
    }

    // -------------------------------------------------------------- sizes

    /** Bytes the core adds when it encrypts a field: a version byte, the 24-byte nonce and the 16-byte tag. */
    private const val OVERHEAD = 1 + 24 + 16

    /** The marker byte in front of a password Send's (v2) fields. */
    private const val V2_MARKER = 1

    fun utf8Length(text: String): Int = text.toByteArray(Charsets.UTF_8).size

    /** Characters of the encrypted field (unpadded base64url) for [plainBytes] bytes of text: what the server limits. */
    fun encryptedFieldLength(plainBytes: Int, v2: Boolean = false): Int =
        Math.ceil(((plainBytes + OVERHEAD + (if (v2) V2_MARKER else 0)).toLong() * 4) / 3.0).toInt()

    /** The most text (UTF-8 bytes) that fits the server's limit on the encrypted text (`limits.send_max_bytes`). */
    fun maxTextBytes(maxEncrypted: Int): Int = maxOf(0, Math.floor(maxEncrypted * 3 / 4.0).toInt() - OVERHEAD - V2_MARKER)

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
            ownerContentKey = text(s["owner_content_key"]),
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
        changes.ownerContentKey?.let { put("owner_content_key", it.value?.let(::JsonPrimitive) ?: JsonNull) }
        changes.maxViews?.let { put("max_views", it.value?.let(::JsonPrimitive) ?: JsonNull) }
        changes.expiresAt?.let { put("expires_at", it.value?.let(::JsonPrimitive) ?: JsonNull) }
        changes.deleteAt?.let { put("delete_at", it) }
        changes.disabled?.let { put("disabled", it) }
        changes.hideEmail?.let { put("hide_email", it) }
    }
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
    /** Send v2: the content key (link key + password) wrapped by the account key; null for v1 Sends. */
    val ownerContentKey: String? = null,
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
    /** Send v2's `owner_content_key`: set (a new password) or cleared (null value; back to v1); null = unchanged. */
    val ownerContentKey: Change<String>? = null,
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

    /** Send v2: the verifier and the content key, from one Argon2id run over [password] (and the link [key]). */
    fun passwordKeys(password: String, salt: String, key: String): SendKeys
    fun encryptV2(contentKey: String, field: String, plain: String): String

    /** A field of either version ([contentKey] needed for v2: else a `PasswordRequired` error). */
    fun open(key: String, contentKey: String?, field: String, cipher: String): String

    /** 1 or 2: a field's format, by its first byte. */
    fun fieldVersion(cipher: String): Int
    fun wrapContent(contentKey: String): String
    fun unwrapContent(wrapped: String): String
}

/** What a Send v2 password gives: the server's verifier and the content key (memory only). */
data class SendKeys(val verifier: String, val contentKey: String)

/**
 * Send, the owner's side (the web vault's `send-client.ts`): encrypt, list, change and delete
 * Sends over [transport]. [crypto] is looked up for each call: a lock frees the account key.
 * [sendV2]: whether the server takes Send v2 (`/api/config` features has `send_v2`; an older server
 * would drop `owner_content_key`): only then a Send with a password is written v2.
 */
class SendActions(
    private val transport: SecurityTransport,
    private val sendV2: suspend () -> Boolean = { false },
    private val crypto: () -> SendCrypto,
) {
    private fun path(id: String) = "/sends/${urlPart(id)}"

    /** The Send's key (for its link and its text), from its `owner_key`. */
    fun keyOf(s: OwnedSend): String = crypto().unwrap(s.ownerKey)

    /** Send v2's content key from `owner_content_key` (null: a v1 Send, or one this account can't open). */
    private fun contentKeyOf(c: SendCrypto, s: OwnedSend): String? = s.ownerContentKey?.let { w ->
        try {
            c.unwrapContent(w)
        } catch (e: Exception) {
            if (e is UserException) throw e
            null
        }
    }

    /**
     * A Send's field, v1 or v2 (by its first byte). The fields are trusted, not the server's word:
     * a field that is v2 without a content key, or v1 next to one, belongs to a Send that was
     * tampered with or half written; it is unreadable, never read (or "repaired") as v1.
     */
    private fun open(c: SendCrypto, s: OwnedSend, field: String, cipher: String): String {
        if (mixed(c, s, cipher)) throw UserException(UNREADABLE)
        return c.open(c.unwrap(s.ownerKey), contentKeyOf(c, s), field, cipher)
    }

    /** [cipher] (a field of [s]) has another format than the Send's `owner_content_key` says (v2 exactly when there is one). */
    private fun mixed(c: SendCrypto, s: OwnedSend, cipher: String): Boolean {
        val version = runCatching { c.fieldVersion(cipher) }.getOrNull() ?: return false
        return (version == 2) != (s.ownerContentKey != null)
    }

    /** Whether the Send's fields are v2 (encrypted with its password too). */
    private fun isV2(c: SendCrypto, s: OwnedSend): Boolean = runCatching { c.fieldVersion(s.name) == 2 }.getOrDefault(s.ownerContentKey != null)

    /** The Send's name, or null when it can't be decrypted (made by an account key this account no longer has; a v2 Send without a readable content key). */
    fun nameOf(s: OwnedSend): String? = try {
        val c = crypto()
        if (mixed(c, s, s.name)) null else open(c, s, "name", s.name)
    } catch (e: Exception) {
        if (e is UserException) throw e
        null
    }

    /** The Send's text (`data`, from `GET /sends/{id}`). */
    fun textOf(s: OwnedSend): String {
        val data = s.data ?: throw UserException(UNEXPECTED)
        return try {
            open(crypto(), s, "data", data)
        } catch (e: io.passauth.core.CoreException) {
            if (s.ownerContentKey != null || isV2(crypto(), s)) throw UserException(UNREADABLE)
            throw e
        }
    }

    suspend fun list(): List<OwnedSend> = Sends.readList(transport.call("/sends", null, "GET", true, emptyMap()))

    /** One Send with its text. */
    suspend fun get(id: String): OwnedSend = Sends.read(transport.call(path(id), null, "GET", true, emptyMap())) ?: throw UserException(UNEXPECTED)

    /** The `POST /sends` body for [d] encrypted with [key]; with a password and [v2], a Send v2. */
    fun createBody(d: NewSend, key: String, v2: Boolean = false): JsonObject {
        val c = crypto()
        val password = d.password?.takeIf { it.isNotEmpty() }
        var salt: String? = null
        var verifier: String? = null
        var name: String
        var data: String
        var ownerContentKey: String? = null
        if (password != null && v2) {
            salt = c.passwordSalt()
            val keys = c.passwordKeys(password, salt, key)
            verifier = keys.verifier
            name = c.encryptV2(keys.contentKey, "name", d.name)
            data = c.encryptV2(keys.contentKey, "data", d.text)
            ownerContentKey = c.wrapContent(keys.contentKey)
        } else {
            // Never a password with fields the link alone opens.
            if (password != null) throw UserException(SendActions.NEEDS_V2)
            name = c.encrypt(key, "name", d.name)
            data = c.encrypt(key, "data", d.text)
        }
        return buildJsonObject {
            put("kind", "text")
            put("name", name)
            put("data", data)
            put("owner_key", c.wrap(key))
            put("max_views", d.maxViews?.let(::JsonPrimitive) ?: JsonNull)
            put("expires_at", d.expiresAt?.let(::JsonPrimitive) ?: JsonNull)
            put("delete_at", d.deleteAt)
            put("hide_email", d.hideEmail)
            put("disabled", false)
            if (salt != null && verifier != null) {
                put("access_salt", salt)
                put("access_verifier", verifier)
            }
            ownerContentKey?.let { put("owner_content_key", it) }
        }
    }

    /** Encrypt and save a new Send; returns it with its key (the link is made from [server]'s address). */
    suspend fun create(d: NewSend): Pair<OwnedSend, String> {
        // A password Send is only ever written v2: on a server that doesn't take it, not at all.
        val v2 = !d.password.isNullOrEmpty()
        if (v2 && !sendV2()) throw UserException(NEEDS_V2)
        val key = crypto().newKey()
        val send = Sends.read(transport.call("/sends", createBody(d, key, v2), "POST", true, emptyMap())) ?: throw UserException(UNEXPECTED)
        return send to key
    }

    /**
     * The changes [edit] makes to [s]: only what changed, name and text encrypted again with the
     * same link key (the link has it). A new password makes (or keeps) it a v2 Send: both fields
     * encrypted again with the new content key (so [s] must have its `data`); removing the password
     * of a v2 Send turns it back into v1 the same way. [v2]: the server takes Send v2; without it a
     * password is neither set nor changed ([NEEDS_V2]): a Send is never written v1 with a password,
     * and a v2 Send never goes back to v1 while it keeps one. A v1 Send that has a password (made
     * before Send v2) on a server that takes v2 gets a new name or text only together with its
     * password, which makes it v2 ([NEEDS_PASSWORD]): its text is never again written so that the
     * link alone opens it.
     */
    fun changesOf(s: OwnedSend, edit: SendEdit, v2: Boolean = false): SendChanges {
        val c = crypto()
        val key = c.unwrap(s.ownerKey)
        val wasV2 = isV2(c, s)
        // Asked only when a field is encrypted or read again: settings change without it.
        val content: String? by lazy { if (wasV2) contentKeyOf(c, s) ?: throw UserException(UNREADABLE) else null }
        val newPassword = edit.password?.takeIf { it.isNotEmpty() }
        val removing = edit.password != null && edit.password.isEmpty()
        if (newPassword != null && !v2) throw UserException(NEEDS_V2)
        if (needsPassword(c, s, edit, v2)) throw UserException(NEEDS_PASSWORD)
        // The fields say what the Send is: one whose fields and content key disagree isn't rewritten.
        val rewrites = edit.name != null || edit.text != null || edit.password != null
        if (rewrites && (mixed(c, s, s.name) || s.data?.let { mixed(c, s, it) } == true)) throw UserException(UNREADABLE)
        // Both fields again in plain text, when the format or the content key changes.
        fun plain(): Pair<String, String> {
            val name = edit.name ?: c.open(key, content, "name", s.name)
            val text = edit.text ?: c.open(key, content, "data", s.data ?: throw UserException(UNEXPECTED))
            return name to text
        }
        return when {
            newPassword != null -> {
                val (name, text) = plain()
                val salt = c.passwordSalt()
                val keys = c.passwordKeys(newPassword, salt, key)
                SendChanges(
                    c.encryptV2(keys.contentKey, "name", name), c.encryptV2(keys.contentKey, "data", text),
                    SendPassword.Set(salt, keys.verifier), edit.maxViews, edit.expiresAt, edit.deleteAt, edit.disabled, edit.hideEmail,
                    ownerContentKey = Change(c.wrapContent(keys.contentKey)),
                )
            }
            wasV2 && removing -> {
                // Back to v1, only together with its password going: encrypted with the link key alone.
                val (name, text) = plain()
                SendChanges(
                    c.encrypt(key, "name", name), c.encrypt(key, "data", text),
                    SendPassword.Remove,
                    edit.maxViews, edit.expiresAt, edit.deleteAt, edit.disabled, edit.hideEmail,
                    ownerContentKey = Change(null),
                )
            }
            else -> {
                fun seal(field: String, plain: String) = content?.let { c.encryptV2(it, field, plain) } ?: c.encrypt(key, field, plain)
                // A new password was handled above (always v2): here it stays or goes.
                val password = if (removing) SendPassword.Remove else SendPassword.Keep
                SendChanges(edit.name?.let { seal("name", it) }, edit.text?.let { seal("data", it) }, password, edit.maxViews, edit.expiresAt, edit.deleteAt, edit.disabled, edit.hideEmail)
            }
        }
    }

    /**
     * [edit] changes the name or text of a v1 Send that has a password, without giving the password,
     * on a server that takes Send v2 ([v2]): refused ([NEEDS_PASSWORD]).
     */
    private fun needsPassword(c: SendCrypto, s: OwnedSend, edit: SendEdit, v2: Boolean): Boolean =
        v2 && s.hasPassword && edit.password == null && (edit.name != null || edit.text != null) && s.ownerContentKey == null && !isV2(c, s)

    /** Save changes to a Send. */
    suspend fun update(s: OwnedSend, edit: SendEdit): OwnedSend {
        // The server is asked what it takes only when the answer matters: a password given, or a v1 Send with one whose text changes.
        val asks = !edit.password.isNullOrEmpty() || needsPassword(crypto(), s, edit, true)
        val v2 = asks && sendV2()
        if (!edit.password.isNullOrEmpty() && !v2) throw UserException(NEEDS_V2)
        // A change of the format needs the text too (the list has none).
        val needsText = edit.password != null && s.data == null && (v2 || s.ownerContentKey != null || isV2(crypto(), s))
        val full = if (needsText) get(s.id) else s
        return Sends.read(transport.call(path(s.id), Sends.changesBody(changesOf(full, edit, v2)), "PUT", true, emptyMap())) ?: throw UserException(UNEXPECTED)
    }

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
        const val NEEDS_V2 = "Update your PassAuth server to protect a Send with a password."
        const val NEEDS_PASSWORD = "Enter this Send's password to change its text."
        const val UNREADABLE = "This Send is protected with its password and can't be read on this phone. You can still turn it off, delete it or copy its link."
    }
}
