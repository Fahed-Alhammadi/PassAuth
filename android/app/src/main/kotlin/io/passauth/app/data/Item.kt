package io.passauth.app.data

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

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
) {
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

@Serializable
enum class UrlMatch {
    @SerialName("default") Default,
    @SerialName("domain") Domain,
    @SerialName("host") Host,
    @SerialName("starts_with") StartsWith,
    @SerialName("exact") Exact,
    @SerialName("regex") Regex,
    @SerialName("never") Never,
}

@Serializable
data class LoginUrl(
    val url: String = "",
    val match: UrlMatch = UrlMatch.Default,
)

@Serializable
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
)

@Serializable
data class Login(
    val username: String = "",
    val password: String = "",
    val urls: List<LoginUrl> = emptyList(),
    val totp: String? = null,
    val passkeys: List<Passkey> = emptyList(),
)

@Serializable
data class Card(
    @SerialName("cardholder_name") val cardholderName: String = "",
    val brand: String = "",
    val number: String = "",
    @SerialName("exp_month") val expMonth: String = "",
    @SerialName("exp_year") val expYear: String = "",
    val code: String = "",
)

@Serializable
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
)

@Serializable
data class SshKey(
    @SerialName("private_key") val privateKey: String = "",
    @SerialName("public_key") val publicKey: String = "",
    val fingerprint: String = "",
)

@Serializable
enum class FieldType {
    @SerialName("text") Text,
    @SerialName("hidden") Hidden,
    @SerialName("boolean") Boolean,
}

@Serializable
data class Field(
    val name: String = "",
    val value: String = "",
    val type: FieldType = FieldType.Text,
)

@Serializable
data class PasswordChange(
    val password: String = "",
    @SerialName("changed_at") val changedAt: Long = 0,
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

object ItemCodec {
    fun decode(json: String): Item = AppJson.decodeFromString(Item.serializer(), json)

    /** `format` is left to the core (it stamps the current format on encrypt). */
    fun encode(item: Item): String = AppJson.encodeToString(Item.serializer(), item)
}
