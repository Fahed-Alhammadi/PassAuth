package io.passauth.app.data

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject

/**
 * The decrypted item, in exactly the JSON shape of `passauth_core::item` and the
 * web vault's `web/src/lib/types.ts` (snake_case). Items cross into the Rust core
 * as this JSON; the core stamps `format` and upgrades older items.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class Item(
    /** Omitted when unknown: the core rejects `null` and stamps the current format itself. */
    @EncodeDefault(EncodeDefault.Mode.NEVER) val format: Int? = null,
    val name: String = "",
    val notes: String = "",
    val favorite: Boolean = false,
    val folder: String? = null,
    val tags: List<String> = emptyList(),
    val login: Login? = null,
    val card: Card? = null,
    val identity: Identity? = null,
    @SerialName("ssh_key") val sshKey: SshKey? = null,
    val fields: List<Field> = emptyList(),
    @SerialName("password_history") val passwordHistory: List<PasswordChange> = emptyList(),
    @SerialName("created_at") val createdAt: Long = 0,
    @SerialName("updated_at") val updatedAt: Long = 0,
    /**
     * Top-level fields this app doesn't model (`attachments`, fields of newer apps), as the item
     * had them: [ItemCodec] keeps them through an edit, so saving here never erases them.
     */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
) {
    /**
     * The item's edit counter (core `rev`, inside the ciphertext, so the server can't change it; kept
     * in [extra] and written back unchanged, the core counts it up at every encryption); 0 = never
     * counted. Read-only here: never shown or edited.
     */
    val rev: Long
        get() = (extra["rev"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()?.takeIf { it >= 0 } ?: 0

    val kind: ItemKind
        get() = when {
            login != null -> ItemKind.Login
            card != null -> ItemKind.Card
            identity != null -> ItemKind.Identity
            sshKey != null -> ItemKind.SshKey
            else -> ItemKind.Note
        }

    /** Host of the first website (patterns excluded), for site icons. */
    val siteHost: String
        get() {
            for (u in login?.urls.orEmpty()) {
                if (u.match == UrlMatch.Regex || u.url.isBlank()) continue
                val p = UrlMatcher.parse(u.url) ?: continue
                if (p.scheme == "http" || p.scheme == "https") return p.hostname
            }
            return ""
        }

    companion object {
        fun empty(kind: ItemKind, nowSeconds: Long = System.currentTimeMillis() / 1000) = Item(
            login = if (kind == ItemKind.Login) Login(urls = listOf(LoginUrl())) else null,
            card = if (kind == ItemKind.Card) Card() else null,
            identity = if (kind == ItemKind.Identity) Identity() else null,
            sshKey = if (kind == ItemKind.SshKey) SshKey() else null,
            createdAt = nowSeconds,
            updatedAt = nowSeconds,
        )
    }
}

/** A website's match type; [wire] is its name in items and in the core's site functions. */
@Serializable
enum class UrlMatch(val wire: String) {
    @SerialName("default") Default("default"),
    @SerialName("domain") Domain("domain"),
    @SerialName("host") Host("host"),
    @SerialName("starts_with") StartsWith("starts_with"),
    @SerialName("exact") Exact("exact"),
    @SerialName("regex") Regex("regex"),
    @SerialName("never") Never("never"),
}

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = LoginUrlSerializer::class)
data class LoginUrl(
    val url: String = "",
    val match: UrlMatch = UrlMatch.Default,
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = PasskeySerializer::class)
data class Passkey(
    @SerialName("credential_id") val credentialId: String = "",
    @SerialName("rp_id") val rpId: String = "",
    @SerialName("rp_name") val rpName: String = "",
    @SerialName("user_handle") val userHandle: String = "",
    @SerialName("user_name") val userName: String = "",
    @SerialName("user_display_name") val userDisplayName: String = "",
    val algorithm: Int = -7,
    @SerialName("private_key") val privateKey: String = "",
    val counter: Long = 0,
    val discoverable: Boolean = true,
    @SerialName("created_at") val createdAt: Long = 0,
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = LoginSerializer::class)
data class Login(
    val username: String = "",
    val password: String = "",
    val urls: List<LoginUrl> = emptyList(),
    val totp: String? = null,
    val passkeys: List<Passkey> = emptyList(),
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = CardSerializer::class)
data class Card(
    @SerialName("cardholder_name") val cardholderName: String = "",
    val brand: String = "",
    val number: String = "",
    @SerialName("exp_month") val expMonth: String = "",
    @SerialName("exp_year") val expYear: String = "",
    val code: String = "",
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = IdentitySerializer::class)
data class Identity(
    val title: String = "",
    @SerialName("first_name") val firstName: String = "",
    @SerialName("middle_name") val middleName: String = "",
    @SerialName("last_name") val lastName: String = "",
    val company: String = "",
    val email: String = "",
    val phone: String = "",
    val address1: String = "",
    val address2: String = "",
    val city: String = "",
    val state: String = "",
    @SerialName("postal_code") val postalCode: String = "",
    val country: String = "",
    val username: String = "",
    val ssn: String = "",
    @SerialName("passport_number") val passportNumber: String = "",
    @SerialName("license_number") val licenseNumber: String = "",
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = SshKeySerializer::class)
data class SshKey(
    @SerialName("private_key") val privateKey: String = "",
    @SerialName("public_key") val publicKey: String = "",
    val fingerprint: String = "",
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@Serializable
enum class FieldType {
    @SerialName("text") Text,
    @SerialName("hidden") Hidden,
    @SerialName("boolean") Boolean,
}

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = FieldSerializer::class)
data class Field(
    val name: String = "",
    val value: String = "",
    val type: FieldType = FieldType.Text,
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

@OptIn(ExperimentalSerializationApi::class)
@KeepGeneratedSerializer
@Serializable(with = PasswordChangeSerializer::class)
data class PasswordChange(
    val password: String = "",
    @SerialName("changed_at") val changedAt: Long = 0,
    /** Fields this app doesn't model (from newer apps), kept through an edit. */
    @Transient val extra: JsonObject = EMPTY_EXTRA,
)

enum class ItemKind(val label: String) {
    Login("Login"),
    Note("Secure note"),
    Card("Card"),
    Identity("Identity"),
    SshKey("SSH key"),
}

/** JSON settings shared by the item model, the API and stored state. */
val AppJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = true
    coerceInputValues = true
}

val EMPTY_EXTRA = JsonObject(emptyMap())

/**
 * The plugin's serializer of [T] plus the object's fields it doesn't model, kept in the value's
 * `extra` (like [Item.extra]): an item from a newer app keeps every nested field through an edit
 * here (a login's, a website's, a passkey's, a card's…). Only for JSON; other formats get the plain one.
 */
abstract class KeepUnknownSerializer<T : Any>(
    private val base: KSerializer<T>,
    private val extraOf: (T) -> JsonObject,
    private val withExtra: (T, JsonObject) -> T,
) : KSerializer<T> {
    override val descriptor: SerialDescriptor get() = base.descriptor
    private val known: Set<String> by lazy { (0 until base.descriptor.elementsCount).map(base.descriptor::getElementName).toSet() }

    override fun deserialize(decoder: Decoder): T {
        val d = decoder as? JsonDecoder ?: return base.deserialize(decoder)
        val element = d.decodeJsonElement()
        val value = d.json.decodeFromJsonElement(base, element)
        val extra = (element as? JsonObject)?.filterKeys { it !in known }.orEmpty()
        return if (extra.isEmpty()) value else withExtra(value, JsonObject(extra))
    }

    override fun serialize(encoder: Encoder, value: T) {
        val extra = extraOf(value)
        val e = encoder as? JsonEncoder
        if (e == null || extra.isEmpty()) return base.serialize(encoder, value)
        val o = e.json.encodeToJsonElement(base, value) as JsonObject
        e.encodeJsonElement(JsonObject(o + extra.filterKeys { it !in o }))
    }
}

@OptIn(ExperimentalSerializationApi::class)
object LoginUrlSerializer : KeepUnknownSerializer<LoginUrl>(LoginUrl.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object PasskeySerializer : KeepUnknownSerializer<Passkey>(Passkey.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object LoginSerializer : KeepUnknownSerializer<Login>(Login.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object CardSerializer : KeepUnknownSerializer<Card>(Card.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object IdentitySerializer : KeepUnknownSerializer<Identity>(Identity.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object SshKeySerializer : KeepUnknownSerializer<SshKey>(SshKey.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object FieldSerializer : KeepUnknownSerializer<Field>(Field.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

@OptIn(ExperimentalSerializationApi::class)
object PasswordChangeSerializer : KeepUnknownSerializer<PasswordChange>(PasswordChange.generatedSerializer(), { it.extra }, { v, x -> v.copy(extra = x) })

object ItemCodec {
    /** The JSON names of the fields [Item] models. */
    private val KNOWN: Set<String> = Item.serializer().descriptor.let { d -> (0 until d.elementsCount).map(d::getElementName).toSet() }

    fun decode(json: String): Item {
        val o = AppJson.parseToJsonElement(json) as? JsonObject ?: return AppJson.decodeFromString(Item.serializer(), json)
        val item = AppJson.decodeFromJsonElement(Item.serializer(), o)
        val extra = o.filterKeys { it !in KNOWN }
        return if (extra.isEmpty()) item else item.copy(extra = JsonObject(extra))
    }

    /** `format` is left to the core (it stamps the current format on encrypt). Fields in [Item.extra] are kept. */
    fun encode(item: Item): String {
        if (item.extra.isEmpty()) return AppJson.encodeToString(Item.serializer(), item)
        val o = AppJson.encodeToJsonElement(Item.serializer(), item) as JsonObject
        return JsonObject(o + item.extra.filterKeys { it !in o }).toString()
    }

    /** [encode] as a JSON object (an offline change keeps the item this way). */
    fun encodeJson(item: Item): JsonObject {
        val o = AppJson.encodeToJsonElement(Item.serializer(), item) as JsonObject
        return if (item.extra.isEmpty()) o else JsonObject(o + item.extra.filterKeys { it !in o })
    }

    /** [decode] of a JSON object. */
    fun decodeJson(o: JsonObject): Item = decode(o.toString())
}
