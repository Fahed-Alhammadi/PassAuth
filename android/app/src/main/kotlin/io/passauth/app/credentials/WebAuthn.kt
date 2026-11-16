package io.passauth.app.credentials

import io.passauth.app.data.Passkey
import io.passauth.core.RpIdException
import io.passauth.core.isPublicSuffix
import io.passauth.core.normalizeHost
import kotlin.io.encoding.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/** A request PassAuth refuses; [kind] maps to a WebAuthn DOMException name. */
class WebAuthnException(val kind: Kind, message: String) : Exception(message) {
    enum class Kind { Security, NotAllowed, InvalidState, NotSupported, Malformed }
}

/** Unpadded base64url, as WebAuthn JSON and the extension use it. */
object B64Url {
    private val codec = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    fun encode(bytes: ByteArray): String = codec.encode(bytes)

    fun decode(s: String): ByteArray {
        val str = s.trimEnd('=')
        require(str.all { it.isLetterOrDigit() || it == '-' || it == '_' } && str.length % 4 != 1) { "malformed base64url" }
        return codec.decode(str)
    }

    /** Canonical (unpadded) form, or null if malformed. */
    fun canonical(s: String?): String? = s?.let { runCatching { encode(decode(it)) }.getOrNull() }
}

/** `PublicKeyCredentialCreationOptionsJSON`, the parts PassAuth uses. */
data class CreateOptions(
    val rpId: String?,
    val rpName: String,
    val userId: String,
    val userName: String,
    val userDisplayName: String,
    val challenge: String,
    /** COSE algorithms of the public-key entries of pubKeyCredParams. */
    val algorithms: List<Int>,
    /** pubKeyCredParams was empty: WebAuthn then means ES256 and RS256. */
    val defaultAlgorithms: Boolean,
    val excludeCredentials: Set<String>,
    val attachment: String?,
    val credProps: Boolean,
)

/** `PublicKeyCredentialRequestOptionsJSON`, the parts PassAuth uses. */
data class GetOptions(
    val rpId: String?,
    val challenge: String,
    val allowCredentials: Set<String>,
    /** allowCredentials was given and non-empty: only listed credentials qualify. */
    val requireListed: Boolean,
)

/**
 * WebAuthn request parsing, origin / RP ID checks and response JSON for the
 * Credential Manager provider. Same semantics as the extension's
 * `background/passkeys.ts`; the bytes (authenticator data, attestation object,
 * signatures) come from the Rust core.
 */
object WebAuthn {
    const val ES256 = -7
    const val APK_KEY_HASH_PREFIX = "android:apk-key-hash:"
    private val TRANSPORTS = listOf("internal", "hybrid")

    // ------------------------------------------------------------ parsing

    private fun malformed(what: String) = WebAuthnException(WebAuthnException.Kind.Malformed, "Malformed request: $what")

    private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

    private fun obj(json: String): JsonObject = try {
        io.passauth.app.data.AppJson.parseToJsonElement(json).jsonObject
    } catch (_: Exception) {
        throw malformed("options")
    }

    private fun descriptorIds(list: JsonElement?, what: String): Set<String> {
        if (list == null || list is kotlinx.serialization.json.JsonNull) return emptySet()
        val arr = list as? JsonArray ?: throw malformed(what)
        val ids = mutableSetOf<String>()
        for (d in arr) {
            val o = d as? JsonObject ?: throw malformed(what)
            val id = B64Url.canonical(o.string("id")) ?: throw malformed(what)
            if (o.string("type") == "public-key") ids += id
        }
        return ids
    }

    fun parseCreate(json: String): CreateOptions {
        val o = obj(json)
        val rp = o["rp"] as? JsonObject ?: throw malformed("rp")
        val user = o["user"] as? JsonObject ?: throw malformed("user")
        val userId = B64Url.canonical(user.string("id")) ?: throw malformed("user.id")
        val userIdLen = B64Url.decode(userId).size
        if (userIdLen < 1 || userIdLen > 64) throw malformed("user.id length")
        val challenge = B64Url.canonical(o.string("challenge")) ?: throw malformed("challenge")
        val params = o["pubKeyCredParams"] as? JsonArray ?: throw malformed("pubKeyCredParams")
        val algs = params.mapNotNull { p ->
            val po = p as? JsonObject ?: return@mapNotNull null
            if (po.string("type") != "public-key") null else (po["alg"] as? JsonPrimitive)?.intOrNull
        }
        val selection = o["authenticatorSelection"] as? JsonObject
        val ext = o["extensions"] as? JsonObject
        return CreateOptions(
            rpId = rp.string("id"),
            rpName = rp.string("name") ?: throw malformed("rp.name"),
            userId = userId,
            userName = user.string("name") ?: throw malformed("user.name"),
            userDisplayName = user.string("displayName").orEmpty(),
            challenge = challenge,
            algorithms = algs,
            defaultAlgorithms = params.isEmpty(),
            excludeCredentials = descriptorIds(o["excludeCredentials"], "excludeCredentials"),
            attachment = selection?.string("authenticatorAttachment"),
            credProps = (ext?.get("credProps") as? JsonPrimitive)?.contentOrNull == "true",
        )
    }

    fun parseGet(json: String): GetOptions {
        val o = obj(json)
        val challenge = B64Url.canonical(o.string("challenge")) ?: throw malformed("challenge")
        val allow = o["allowCredentials"]
        val ids = descriptorIds(allow, "allowCredentials")
        return GetOptions(o.string("rpId"), challenge, ids, allow is JsonArray && allow.isNotEmpty())
    }

    /** ES256 offered (an empty list means ES256 and RS256) and not cross-platform only. */
    fun supports(o: CreateOptions): Boolean =
        (o.defaultAlgorithms || ES256 in o.algorithms) && o.attachment != "cross-platform"

    // ------------------------------------------------------- origin / RP ID

    private fun security(message: String) = WebAuthnException(WebAuthnException.Kind.Security, message)

    /** The core's verdict as the error the page gets (a WebAuthn `SecurityError`). */
    private inline fun <T> checked(block: () -> T): T = try {
        block()
    } catch (e: RpIdException) {
        throw security(e.message ?: "Invalid RP ID.")
    }

    /**
     * The host of a web origin `https://host[:port]` (or http://localhost): the origin must be in
     * its serialised form and its host a domain (the core's `effectiveRpId` without a requested ID).
     */
    fun webOriginHost(origin: String): String = checked { io.passauth.core.effectiveRpId(null, origin) }

    fun isAppOrigin(origin: String) = origin.startsWith(APK_KEY_HASH_PREFIX)

    /** `android:apk-key-hash:<base64url SHA-256 of the signing certificate>`. */
    fun appOrigin(certSha256: ByteArray) = APK_KEY_HASH_PREFIX + B64Url.encode(certSha256)

    /**
     * The RP ID for a request from a web [origin] (the core's `effectiveRpId`): [requested] if it
     * equals the origin's host or is a registrable-domain suffix of it by the full Public Suffix
     * List; defaults to the host.
     */
    fun effectiveRpId(requested: String?, origin: String): String = checked { io.passauth.core.effectiveRpId(requested, origin) }

    /**
     * RP ID for a native app: must be given and be a domain that isn't a public suffix ("localhost"
     * aside); the app is then checked against its asset links. The core validates the requested
     * ID as it would for a page served from that very host.
     */
    fun appRpId(requested: String?): String {
        val host = requested?.let(::normalizeHost) ?: throw security("Invalid RP ID.")
        val rpId = try {
            io.passauth.core.effectiveRpId(requested, "https://$host")
        } catch (_: RpIdException) {
            throw security("Invalid RP ID.")
        }
        if (rpId != "localhost" && isPublicSuffix(rpId)) throw security("Invalid RP ID.")
        return rpId
    }

    // ------------------------------------------------------------ matching

    /** Passkeys usable for a request: same RP ID, ES256, listed in allowCredentials or discoverable. */
    fun matching(o: GetOptions, rpId: String, all: List<Passkey>): List<Passkey> = all.filter { p ->
        if (!p.rpId.equals(rpId, ignoreCase = true) || p.algorithm != ES256) return@filter false
        if (o.requireListed) B64Url.canonical(p.credentialId) in o.allowCredentials else p.discoverable
    }

    /** A passkey in [all] is listed in excludeCredentials (InvalidStateError, checked after consent). */
    fun excludedExists(o: CreateOptions, rpId: String, all: List<Passkey>): Boolean =
        all.any { it.rpId.equals(rpId, ignoreCase = true) && B64Url.canonical(it.credentialId) in o.excludeCredentials }

    /** The record stored in `login.passkeys[]`, like the extension's `createPasskey`. */
    fun passkeyRecord(o: CreateOptions, rpId: String, credentialId: ByteArray, pkcs8: ByteArray, nowSeconds: Long) = Passkey(
        credentialId = B64Url.encode(credentialId),
        rpId = rpId,
        rpName = o.rpName,
        userHandle = o.userId,
        userName = o.userName,
        userDisplayName = o.userDisplayName,
        algorithm = ES256,
        privateKey = B64Url.encode(pkcs8),
        counter = 0,
        discoverable = true,
        createdAt = nowSeconds,
    )

    // ------------------------------------------------------------ responses

    /** `RegistrationResponseJSON`. */
    fun registrationResponse(
        credentialId: ByteArray,
        clientDataJson: String,
        attestationObject: ByteArray,
        authenticatorData: ByteArray,
        publicKeySpki: ByteArray,
        credProps: Boolean,
    ): String {
        val id = B64Url.encode(credentialId)
        return buildJsonObject {
            put("id", id)
            put("rawId", id)
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            putJsonObject("response") {
                put("clientDataJSON", B64Url.encode(clientDataJson.encodeToByteArray()))
                put("attestationObject", B64Url.encode(attestationObject))
                put("authenticatorData", B64Url.encode(authenticatorData))
                put("transports", buildJsonArray { TRANSPORTS.forEach { add(JsonPrimitive(it)) } })
                put("publicKey", B64Url.encode(publicKeySpki))
                put("publicKeyAlgorithm", ES256)
            }
            putJsonObject("clientExtensionResults") {
                if (credProps) putJsonObject("credProps") { put("rk", true) }
            }
        }.toString()
    }

    /** `AuthenticationResponseJSON`. */
    fun authenticationResponse(
        p: Passkey,
        clientDataJson: String,
        authenticatorData: ByteArray,
        signature: ByteArray,
    ): String {
        val id = B64Url.canonical(p.credentialId) ?: p.credentialId
        return buildJsonObject {
            put("id", id)
            put("rawId", id)
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            putJsonObject("response") {
                put("clientDataJSON", B64Url.encode(clientDataJson.encodeToByteArray()))
                put("authenticatorData", B64Url.encode(authenticatorData))
                put("signature", B64Url.encode(signature))
                B64Url.canonical(p.userHandle)?.takeIf { it.isNotEmpty() }?.let { put("userHandle", it) }
            }
            putJsonObject("clientExtensionResults") {}
        }.toString()
    }
}
