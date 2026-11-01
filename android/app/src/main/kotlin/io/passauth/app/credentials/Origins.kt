package io.passauth.app.credentials

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import io.passauth.app.AppGraph
import io.passauth.core.sha256

/** The checked origin and RP ID of a WebAuthn request. */
data class CheckedOrigin(
    /** `https://…` for browsers, `android:apk-key-hash:…` for apps. */
    val origin: String,
    val rpId: String,
    /** The caller is a native app (validated with Digital Asset Links). */
    val app: Boolean,
)

/**
 * Who is asking: a privileged browser (its origin comes from the request and is
 * trusted only if the browser's package and signing certificate are on the
 * allowlist) or a native app (its origin is its signing-certificate hash, and the
 * RP's asset links must list the app).
 */
object Origins {
    /** A privileged caller's web origin (no trailing slash), or null if the request carries none. Throws if not allowlisted. */
    fun privilegedOrigin(context: Context, caller: CallingAppInfo): String? {
        if (!caller.isOriginPopulated()) return null
        val origin = try {
            caller.getOrigin(PrivilegedApps.json(context))
        } catch (e: Exception) {
            throw WebAuthnException(WebAuthnException.Kind.Security, "${caller.packageName} isn't a browser PassAuth trusts with website passkeys.")
        } ?: throw WebAuthnException(WebAuthnException.Kind.Security, "${caller.packageName} isn't a browser PassAuth trusts with website passkeys.")
        val o = origin.trimEnd('/')
        if (WebAuthn.isAppOrigin(o)) throw WebAuthnException(WebAuthnException.Kind.NotSupported, "Requests for another app aren't supported.")
        return o
    }

    /** SHA-256 of the calling app's current signing certificates. */
    fun certDigests(caller: CallingAppInfo): List<ByteArray> = AppSigning.certificateDigests(caller.signingInfo, ::sha256)

    /** Cheap check for listing entries (no network): the RP ID for this caller. */
    fun rpIdForBegin(context: Context, caller: CallingAppInfo, requested: String?): String {
        val web = privilegedOrigin(context, caller)
        return if (web != null) WebAuthn.effectiveRpId(requested, web) else WebAuthn.appRpId(requested)
    }

    /** The full check before creating or using a passkey (fetches the RP's asset links for apps). */
    suspend fun check(context: Context, graph: AppGraph, caller: CallingAppInfo, requestedRpId: String?): CheckedOrigin {
        val web = privilegedOrigin(context, caller)
        if (web != null) return CheckedOrigin(web, WebAuthn.effectiveRpId(requestedRpId, web), app = false)
        if (caller.packageName == context.packageName) throw WebAuthnException(WebAuthnException.Kind.NotAllowed, "Not allowed.")
        val rpId = WebAuthn.appRpId(requestedRpId)
        val digests = certDigests(caller)
        if (digests.isEmpty()) throw WebAuthnException(WebAuthnException.Kind.Security, "The app's signature couldn't be read.")
        val prints = digests.map(AssetLinks::fingerprint)
        if (!graph.assetLinks.verify(rpId, caller.packageName, prints)) {
            throw WebAuthnException(
                WebAuthnException.Kind.Security,
                "$rpId doesn't list this app (${caller.packageName}) in its Digital Asset Links, so PassAuth won't use its passkeys here.",
            )
        }
        return CheckedOrigin(WebAuthn.appOrigin(digests.first()), rpId, app = true)
    }
}
