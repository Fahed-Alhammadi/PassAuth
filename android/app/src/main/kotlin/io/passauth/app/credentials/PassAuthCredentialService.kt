package io.passauth.app.credentials

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import io.passauth.app.autofill.AutofillMatcher
import io.passauth.app.autofill.FillTarget
import io.passauth.app.data.Status
import io.passauth.app.data.VaultData
import io.passauth.app.graph
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * Credential Manager provider (Android 14+): creates and uses passkeys stored in
 * the active account's vault (same format as the extension), and offers saved
 * passwords. Every create or sign-in goes through [CredentialActivity], which
 * checks the caller's origin, verifies the user and builds the WebAuthn response.
 */
class PassAuthCredentialService : CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        graph.scope.launch {
            try {
                val state = graph.loadedState()
                if (request !is BeginCreatePublicKeyCredentialRequest || state.status == Status.Setup || state.status == Status.LoggedOut) {
                    return@launch callback.onResult(BeginCreateCredentialResponse())
                }
                // Only offer what PassAuth can do: ES256, platform authenticator.
                val options = runCatching { WebAuthn.parseCreate(request.requestJson) }.getOrNull()
                if (options == null || !WebAuthn.supports(options)) return@launch callback.onResult(BeginCreateCredentialResponse())
                val entry = CreateEntry.Builder(state.email, pending(this@PassAuthCredentialService, CredentialActivity.MODE_CREATE_PASSKEY))
                    .setDescription("Save the passkey in PassAuth (${state.email}).")
                    .build()
                callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "begin create failed: ${e.javaClass.simpleName}")
                callback.onError(CreateCredentialUnknownException("PassAuth couldn't handle this request."))
            }
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        graph.scope.launch {
            try {
                callback.onResult(beginGet(this@PassAuthCredentialService, request))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "begin get failed: ${e.javaClass.simpleName}")
                callback.onError(GetCredentialUnknownException("PassAuth couldn't handle this request."))
            }
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    companion object {
        private const val TAG = "PassAuthCredentials"
        private val codes = AtomicInteger(1)

        /** Mutable (the framework adds the request), explicit PendingIntent to [CredentialActivity]. */
        fun pending(context: Context, mode: String, entryId: String? = null, credentialId: String? = null): PendingIntent {
            val intent = Intent(context, CredentialActivity::class.java)
                .putExtra(CredentialActivity.EXTRA_MODE, mode)
                .apply {
                    entryId?.let { putExtra(CredentialActivity.EXTRA_ENTRY, it) }
                    credentialId?.let { putExtra(CredentialActivity.EXTRA_CREDENTIAL, it) }
                }
            return PendingIntent.getActivity(context, codes.getAndIncrement(), intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }

        /**
         * Entries for a sign-in request, or (when locked) an "Unlock PassAuth" action that
         * comes back here through [CredentialActivity] once unlocked.
         */
        suspend fun beginGet(context: Context, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
            val graph = context.graph
            val state = graph.loadedState()
            if (state.status == Status.Setup || state.status == Status.LoggedOut) return BeginGetCredentialResponse()
            val vault = graph.awaitVault()
                ?: return BeginGetCredentialResponse.Builder()
                    .addAuthenticationAction(AuthenticationAction("Unlock PassAuth (${state.email})", pending(context, CredentialActivity.MODE_UNLOCK)))
                    .build()
            return BeginGetCredentialResponse.Builder().setCredentialEntries(entries(context, request, vault)).build()
        }

        private fun entries(context: Context, request: BeginGetCredentialRequest, vault: VaultData): List<CredentialEntry> {
            val caller = request.callingAppInfo
            val out = mutableListOf<CredentialEntry>()
            for (option in request.beginGetCredentialOptions) {
                when (option) {
                    is BeginGetPublicKeyCredentialOption -> {
                        val o = runCatching { WebAuthn.parseGet(option.requestJson) }.getOrNull() ?: continue
                        // The full origin check (allowlist, asset links) runs when an entry is picked;
                        // here a web caller's RP ID must already fit its origin.
                        val rpId = caller?.let { runCatching { Origins.rpIdForBegin(context, it, o.rpId) }.getOrNull() } ?: o.rpId ?: continue
                        val all = vault.entries.flatMap { e -> e.item.login?.passkeys.orEmpty().map { e to it } }
                        val usable = WebAuthn.matching(o, rpId, all.map { it.second })
                        for (p in usable) {
                            val e = all.first { it.second === p }.first
                            out += PublicKeyCredentialEntry.Builder(
                                context,
                                p.userName.ifEmpty { p.userDisplayName.ifEmpty { e.item.name } },
                                pending(context, CredentialActivity.MODE_GET_PASSKEY, e.id, p.credentialId),
                                option,
                            ).setDisplayName(e.item.name.takeIf { it != p.userName }).build()
                        }
                    }
                    is BeginGetPasswordOption -> {
                        val target = caller?.let { passwordTarget(context, it) } ?: continue
                        val logins = vault.entries.mapNotNull { e -> e.item.login?.takeIf { it.password.isNotEmpty() }?.let { e to it } }
                        val fallback = graph(context).repo.state.value.settings.defaultMatch
                        for ((e, l) in logins) {
                            if (!AutofillMatcher.matches(target, l, fallback)) continue
                            if (AutofillMatcher.isVaultPage(target, graph(context).repo.state.value.server)) continue
                            out += PasswordCredentialEntry.Builder(
                                context,
                                l.username.ifEmpty { e.item.name },
                                pending(context, CredentialActivity.MODE_GET_PASSWORD, e.id),
                                option,
                            ).setDisplayName(e.item.name).build()
                        }
                    }
                }
            }
            return out
        }

        private fun graph(context: Context) = context.graph

        /**
         * Password requests: a browser's web origin (from the allowlist) matches by website;
         * an app matches its `androidapp://` logins.
         */
        fun passwordTarget(context: Context, caller: CallingAppInfo): FillTarget? {
            val origin = runCatching { Origins.privilegedOrigin(context, caller) }.getOrNull()
            if (origin != null) {
                val host = runCatching { WebAuthn.webOriginHost(origin.trimEnd('/')) }.getOrNull() ?: return null
                val scheme = origin.substringBefore("://")
                return FillTarget.Web(scheme, host)
            }
            if (caller.isOriginPopulated()) return null
            if (caller.packageName == context.packageName) return null
            return FillTarget.App(caller.packageName)
        }
    }
}
