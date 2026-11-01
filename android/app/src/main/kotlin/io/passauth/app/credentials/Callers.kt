package io.passauth.app.credentials

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import io.passauth.app.R
import io.passauth.app.data.AppJson
import java.util.Locale
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Privileged apps (browsers) that may make WebAuthn requests for any website, in
 * the Credential Manager `getOrigin()` allowlist format.
 *
 * `res/raw/privileged_allowlist.json` is Google Password Manager's published list,
 * https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json (downloaded
 * 2026-11-01, sha256 0891ee25…f319481), which the Credential Manager provider
 * guide (developer.android.com/identity/sign-in/credential-provider) points
 * providers to. It covers Chrome stable/beta/dev/canary, Chromium, Firefox,
 * Edge, Brave, Samsung Internet, Vivaldi, Opera, DuckDuckGo and others.
 */
object PrivilegedApps {
    /** package name → allowed signing-certificate fingerprints ("AB:CD:…", upper case). */
    fun parse(json: String): Map<String, Set<String>> {
        val apps = runCatching { (AppJson.parseToJsonElement(json) as JsonObject)["apps"] as JsonArray }.getOrNull() ?: return emptyMap()
        val out = mutableMapOf<String, MutableSet<String>>()
        for (a in apps) {
            val o = a as? JsonObject ?: continue
            if ((o["type"] as? JsonPrimitive)?.contentOrNull != "android") continue
            val info = o["info"] as? JsonObject ?: continue
            val pkg = (info["package_name"] as? JsonPrimitive)?.contentOrNull ?: continue
            val sigs = (info["signatures"] as? JsonArray).orEmpty().mapNotNull {
                ((it as? JsonObject)?.get("cert_fingerprint_sha256") as? JsonPrimitive)?.contentOrNull?.uppercase(Locale.ROOT)
            }
            out.getOrPut(pkg) { mutableSetOf() } += sigs
        }
        return out
    }

    @Volatile private var json: String? = null
    @Volatile private var parsed: Map<String, Set<String>>? = null

    fun json(context: Context): String = json ?: withTestApp(
        context.resources.openRawResource(R.raw.privileged_allowlist).use { it.readBytes().decodeToString() },
        io.passauth.app.BuildConfig.TEST_PRIVILEGED_APP,
    ).also { json = it }

    /** Debug builds can add one browser for emulator tests ("package|fingerprint"); release builds never do. */
    fun withTestApp(json: String, extra: String): String {
        val (pkg, fp) = extra.split('|').takeIf { it.size == 2 && it[0].isNotBlank() && it[1].isNotBlank() } ?: return json
        val root = AppJson.parseToJsonElement(json) as? JsonObject ?: return json
        val apps = (root["apps"] as? JsonArray).orEmpty()
        val signature = AppJson.parseToJsonElement("""{"build":"release","cert_fingerprint_sha256":"$fp"}""")
        var found = false
        // Credential Manager reads one entry per package: add the signature to an existing entry.
        val merged = apps.map { a ->
            val info = (a as? JsonObject)?.get("info") as? JsonObject
            if ((info?.get("package_name") as? JsonPrimitive)?.contentOrNull != pkg) return@map a
            found = true
            val sigs = (info["signatures"] as? JsonArray).orEmpty() + signature
            JsonObject(a + ("info" to JsonObject(info + ("signatures" to JsonArray(sigs)))))
        }
        val entry = AppJson.parseToJsonElement("""{"type":"android","info":{"package_name":"$pkg","signatures":[$signature]}}""")
        return JsonObject(root + ("apps" to JsonArray(if (found) merged else merged + entry))).toString()
    }

    fun all(context: Context): Map<String, Set<String>> = parsed ?: parse(json(context)).also { parsed = it }

    /** Is [packageName], signed with one of [certFingerprints], a listed browser? */
    fun isTrusted(context: Context, packageName: String, certFingerprints: List<String>): Boolean {
        val allowed = all(context)[packageName] ?: return false
        return certFingerprints.any { it.uppercase(Locale.ROOT) in allowed }
    }
}

/** Signing certificates of apps, as SHA-256 digests. */
object AppSigning {
    /** The current signers' certificates (DER), newest first. */
    fun certificates(info: SigningInfo): List<ByteArray> =
        if (info.hasMultipleSigners()) {
            info.apkContentsSigners.map { it.toByteArray() }
        } else {
            // The current certificate is the last in the rotation history.
            listOfNotNull(info.signingCertificateHistory?.lastOrNull()?.toByteArray())
                .ifEmpty { info.apkContentsSigners.map { it.toByteArray() } }
        }

    fun certificateDigests(info: SigningInfo, sha256: (ByteArray) -> ByteArray): List<ByteArray> = certificates(info).map(sha256)

    /** Signing info of an installed app, or null if it isn't visible. */
    fun of(context: Context, packageName: String): SigningInfo? = runCatching {
        context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
    }.getOrNull()
}

private fun JsonArray?.orEmpty(): List<kotlinx.serialization.json.JsonElement> = this ?: emptyList()
