package io.passauth.app.credentials

import android.os.SystemClock
import io.passauth.app.data.AppJson
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Digital Asset Links (https://developers.google.com/digital-asset-links):
 * a site lists the Android apps allowed to use its sign-in credentials in
 * `https://<domain>/.well-known/assetlinks.json`.
 */
object AssetLinks {
    const val GET_LOGIN_CREDS = "delegate_permission/common.get_login_creds"

    /** SHA-256 as upper-case hex pairs separated by colons ("AB:CD:…"), the assetlinks format. */
    fun fingerprint(sha256: ByteArray): String = sha256.joinToString(":") { "%02X".format(it.toInt() and 0xff) }

    private fun normFingerprint(s: String) = s.trim().uppercase(Locale.ROOT).replace(":", "")

    /**
     * Does the assetlinks.json [json] grant [relation] to the Android app [packageName]
     * signed with a certificate whose SHA-256 is one of [certFingerprints]? Malformed
     * files or statements grant nothing. `include` statements are not followed.
     */
    fun allows(json: String, packageName: String, certFingerprints: List<String>, relation: String = GET_LOGIN_CREDS): Boolean {
        val statements = runCatching { AppJson.parseToJsonElement(json) as? JsonArray }.getOrNull() ?: return false
        val wanted = certFingerprints.map(::normFingerprint).filter { it.length == 64 }.toSet()
        if (wanted.isEmpty()) return false
        return statements.any { st ->
            val o = st as? JsonObject ?: return@any false
            val relations = (o["relation"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            if (relation !in relations) return@any false
            val target = o["target"] as? JsonObject ?: return@any false
            if ((target["namespace"] as? JsonPrimitive)?.contentOrNull != "android_app") return@any false
            if ((target["package_name"] as? JsonPrimitive)?.contentOrNull != packageName) return@any false
            val prints = (target["sha256_cert_fingerprints"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            prints.any { normFingerprint(it) in wanted }
        }
    }
}

/**
 * Fetches and caches asset links: https only, no redirects (as Android App Links
 * verification), 5 s timeout, 256 KiB cap. Positive and negative results are
 * cached for an hour; network errors aren't cached.
 */
class AssetLinksVerifier(base: OkHttpClient, private val urlFor: (String) -> String = { "https://$it/.well-known/assetlinks.json" }) {
    private val http = base.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .callTimeout(5, TimeUnit.SECONDS)
        .build()

    private data class Cached(val json: String?, val at: Long)
    private val cache = ConcurrentHashMap<String, Cached>()

    private suspend fun fetch(domain: String): String? {
        cache[domain]?.let { if (SystemClock.elapsedRealtime() - it.at < 3_600_000) return it.json }
        val json = withContext(Dispatchers.IO) {
            http.newCall(Request.Builder().url(urlFor(domain)).get().build()).execute().use { r ->
                if (!r.isSuccessful) return@use null
                val body = r.body
                if (body.contentLength() > MAX_BYTES) return@use null
                val bytes = body.source().let { src ->
                    src.request(MAX_BYTES + 1L)
                    if (src.buffer.size > MAX_BYTES) return@use null
                    src.readByteArray()
                }
                bytes.decodeToString()
            }
        }
        cache[domain] = Cached(json, SystemClock.elapsedRealtime())
        return json
    }

    /** Does [domain] let [packageName] (signed with [certFingerprints]) use its sign-in credentials? */
    suspend fun verify(domain: String, packageName: String, certFingerprints: List<String>): Boolean {
        val json = try {
            fetch(domain)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            null
        } ?: return false
        return AssetLinks.allows(json, packageName, certFingerprints)
    }

    /** A cached answer only (no network), or null if unknown. */
    fun cached(domain: String, packageName: String, certFingerprints: List<String>): Boolean? {
        val c = cache[domain] ?: return null
        if (SystemClock.elapsedRealtime() - c.at >= 3_600_000) return null
        return c.json != null && AssetLinks.allows(c.json, packageName, certFingerprints)
    }

    private companion object {
        const val MAX_BYTES = 256 * 1024
    }
}
