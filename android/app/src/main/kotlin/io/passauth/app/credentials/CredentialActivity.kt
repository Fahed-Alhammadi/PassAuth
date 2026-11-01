package io.passauth.app.credentials

import android.content.Intent
import android.os.Bundle
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.domerrors.DataError
import androidx.credentials.exceptions.domerrors.DomError
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.domerrors.SecurityError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.PendingIntentHandler
import io.passauth.app.ServiceActivity
import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.Passkey
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultData
import io.passauth.app.ui.deviceAuthAvailable
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.verifyUser
import io.passauth.app.ui.vault.currentTotp
import io.passauth.core.passkeyAssert
import io.passauth.core.passkeyClientDataJson
import io.passauth.core.passkeyCreate
import io.passauth.core.sha256
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Handles a Credential Manager entry the user picked: create a passkey, sign in
 * with a passkey or password, or unlock and list the entries.
 *
 * User verification: unlocking PassAuth (master password or biometrics) counts;
 * otherwise the user confirms with biometrics or the screen lock before a passkey
 * is created or used. excludeCredentials is checked only after the user agreed, so
 * a site can't silently probe the vault (as in the extension).
 */
class CredentialActivity : ServiceActivity() {
    /** A result to deliver when the error screen is closed. */
    private var pendingResult: Intent? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return
        when (intent.getStringExtra(EXTRA_MODE)) {
            MODE_CREATE_PASSKEY -> createPasskey()
            MODE_GET_PASSKEY -> getPasskey()
            MODE_GET_PASSWORD -> getPassword()
            MODE_UNLOCK -> unlock()
            else -> cancel()
        }
    }

    override fun cancel() {
        val r = pendingResult
        if (r != null) setResult(RESULT_OK, r) else setResult(RESULT_CANCELED)
        finish()
    }

    private fun domError(kind: WebAuthnException.Kind): DomError = when (kind) {
        WebAuthnException.Kind.Security -> SecurityError()
        WebAuthnException.Kind.InvalidState -> InvalidStateError()
        WebAuthnException.Kind.NotSupported -> NotSupportedError()
        WebAuthnException.Kind.Malformed -> DataError()
        WebAuthnException.Kind.NotAllowed -> NotAllowedError()
    }

    private fun failCreate(e: Exception, show: Boolean = true) {
        val kind = (e as? WebAuthnException)?.kind ?: WebAuthnException.Kind.NotAllowed
        val r = Intent()
        PendingIntentHandler.setCreateCredentialException(r, CreatePublicKeyCredentialDomException(domError(kind), e.message))
        pendingResult = r
        if (show) message("Can't save this passkey", errorMessage(e)) else cancel()
    }

    private fun failGet(e: Exception, show: Boolean = true) {
        val kind = (e as? WebAuthnException)?.kind ?: WebAuthnException.Kind.NotAllowed
        val r = Intent()
        PendingIntentHandler.setGetCredentialException(r, GetPublicKeyCredentialDomException(domError(kind), e.message))
        pendingResult = r
        if (show) message("Can't sign in with this passkey", errorMessage(e)) else cancel()
    }

    private fun done(r: Intent) {
        setResult(RESULT_OK, r)
        finish()
    }

    // --------------------------------------------------------------- create

    private fun createPasskey() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return cancel()
        val call = request.callingRequest as? CreatePublicKeyCredentialRequest ?: return cancel()
        val options = try {
            WebAuthn.parseCreate(call.requestJson).also {
                if (!WebAuthn.supports(it)) throw WebAuthnException(WebAuthnException.Kind.NotSupported, "PassAuth only creates ES256 passkeys on this device.")
            }
        } catch (e: Exception) {
            return failCreate(e)
        }
        withVault("Unlock to save a passkey") { vault, unlockedHere ->
            val checked = try {
                Origins.check(this, graph, request.callingAppInfo, options.rpId)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withVault failCreate(e)
            }
            val who = options.userName.ifEmpty { options.userDisplayName }
            confirm(
                title = "Save a passkey?",
                subtitle = checked.rpId,
                body = "For $who on ${checked.rpId}" + (if (checked.app) " (requested by ${request.callingAppInfo.packageName})" else "") +
                    ". PassAuth keeps it in your vault (${graph.repo.state.value.email}).",
                action = "Save passkey",
            ) {
                if (!unlockedHere && deviceAuthAvailable(this)) {
                    if (!verifyUser("Save passkey", "$who · ${checked.rpId}")) return@confirm
                }
                val current = graph.repo.vault.value ?: vault
                val all = current.entries.flatMap { it.item.login?.passkeys.orEmpty() }
                if (WebAuthn.excludedExists(options, checked.rpId, all)) {
                    return@confirm failCreate(WebAuthnException(WebAuthnException.Kind.InvalidState, "A passkey for this account is already saved in PassAuth."))
                }
                val np = withContext(Dispatchers.Default) { passkeyCreate(checked.rpId) }
                val passkey = WebAuthn.passkeyRecord(options, checked.rpId, np.credentialId, np.privateKeyPkcs8, System.currentTimeMillis() / 1000)
                storePasskey(current, passkey)
                // With a clientDataHash (browsers) the browser uses its own clientDataJSON; ours is the
                // placeholder the provider guide asks for, built from the checked origin.
                val cdj = passkeyClientDataJson("webauthn.create", options.challenge, checked.origin)
                val json = WebAuthn.registrationResponse(np.credentialId, cdj, np.attestationObject, np.authenticatorData, np.publicKeySpki, options.credProps)
                val r = Intent()
                PendingIntentHandler.setCreateCredentialResponse(r, CreatePublicKeyCredentialResponse(json))
                done(r)
            }
        }
    }

    /** Attach to an existing login for the same site and username, or create one (the extension's `storePasskey`). */
    private suspend fun storePasskey(vault: VaultData, p: Passkey) {
        val site = UrlMatcher.baseDomain(p.rpId)
        val existing: Entry? = vault.entries.firstOrNull { e ->
            val l = e.item.login ?: return@firstOrNull false
            vault.canWrite(e) && l.username.equals(p.userName, ignoreCase = true) &&
                l.urls.any { u -> UrlMatcher.parse(u.url)?.takeIf { it.scheme == "http" || it.scheme == "https" }?.let { UrlMatcher.baseDomain(it.hostname) == site } == true }
        }
        if (existing != null) {
            val l = existing.item.login!!
            graph.repo.updateItem(existing, existing.item.copy(login = l.copy(passkeys = l.passkeys + p)))
            return
        }
        graph.repo.createItem(
            Item(
                name = p.rpName.ifEmpty { p.rpId },
                login = Login(username = p.userName, password = "", urls = listOf(LoginUrl("https://${p.rpId}", UrlMatch.Default)), passkeys = listOf(p)),
            ),
            null,
        )
    }

    // ------------------------------------------------------------------ get

    private fun getPasskey() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return cancel()
        val option = request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull() ?: return cancel()
        val entryId = intent.getStringExtra(EXTRA_ENTRY) ?: return cancel()
        val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL) ?: return cancel()
        val options = try {
            WebAuthn.parseGet(option.requestJson)
        } catch (e: Exception) {
            return failGet(e)
        }
        withVault("Unlock to sign in") { vault, unlockedHere ->
            try {
                val checked = Origins.check(this, graph, request.callingAppInfo, options.rpId)
                val entry = vault.get(entryId) ?: throw WebAuthnException(WebAuthnException.Kind.NotAllowed, "This passkey is no longer in your vault.")
                val p = entry.item.login?.passkeys?.firstOrNull { it.credentialId == credentialId }
                    ?: throw WebAuthnException(WebAuthnException.Kind.NotAllowed, "This passkey is no longer in your vault.")
                if (WebAuthn.matching(options, checked.rpId, listOf(p)).size != 1) {
                    throw WebAuthnException(WebAuthnException.Kind.NotAllowed, "The selected passkey is not valid for this request.")
                }
                val who = p.userName.ifEmpty { p.userDisplayName.ifEmpty { entry.item.name } }
                if (!unlockedHere) {
                    if (deviceAuthAvailable(this)) {
                        if (!verifyUser("Sign in with passkey", "$who · ${checked.rpId}")) return@withVault cancel()
                    } else {
                        // No screen lock to verify with: at least ask for an explicit tap.
                        return@withVault confirm("Sign in with passkey?", checked.rpId, "As $who.", "Sign in") { assert(option, options, checked, p) }
                    }
                }
                assert(option, options, checked, p)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                failGet(e)
            }
        }
    }

    private suspend fun assert(option: GetPublicKeyCredentialOption, options: GetOptions, checked: CheckedOrigin, p: Passkey) {
        val cdj = passkeyClientDataJson("webauthn.get", options.challenge, checked.origin)
        // Browsers send the hash of their own clientDataJSON; apps don't, so it's built here.
        val hash = option.clientDataHash ?: sha256(cdj.encodeToByteArray())
        val a = withContext(Dispatchers.Default) { passkeyAssert(B64Url.decode(p.privateKey), checked.rpId, hash) }
        val json = WebAuthn.authenticationResponse(p, cdj, a.authenticatorData, a.signature)
        val r = Intent()
        PendingIntentHandler.setGetCredentialResponse(r, GetCredentialResponse(PublicKeyCredential(json)))
        done(r)
    }

    private fun getPassword() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return cancel()
        if (request.credentialOptions.none { it is GetPasswordOption }) return cancel()
        val entryId = intent.getStringExtra(EXTRA_ENTRY) ?: return cancel()
        withVault("Unlock to sign in") { vault, _ ->
            val target = PassAuthCredentialService.passwordTarget(this, request.callingAppInfo)
            val entry = vault.get(entryId)
            val login = entry?.item?.login
            val fallback = graph.repo.state.value.settings.defaultMatch
            // Checked again: the login must still belong to this app or site.
            if (target == null || login == null || !io.passauth.app.autofill.AutofillMatcher.matches(target, login, fallback)) {
                val r = Intent()
                PendingIntentHandler.setGetCredentialException(r, GetCredentialUnknownException("This login isn't available for this app."))
                return@withVault done(r)
            }
            if (!login.totp.isNullOrBlank() && graph.repo.state.value.settings.autoCopyTotp) {
                runCatching { currentTotp(login.totp).code }.getOrNull()?.let {
                    graph.clipboard.copy(it, "Verification code")
                    toast("Verification code copied. Paste it when asked.")
                }
            }
            val r = Intent()
            PendingIntentHandler.setGetCredentialResponse(r, GetCredentialResponse(PasswordCredential(login.username, login.password)))
            done(r)
        }
    }

    // --------------------------------------------------------------- unlock

    private fun unlock() {
        val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent) ?: return cancel()
        withVault("Unlock PassAuth") { _, _ ->
            val response = PassAuthCredentialService.beginGet(this, request)
            val r = Intent()
            PendingIntentHandler.setBeginGetCredentialResponse(r, response)
            done(r)
        }
    }

    companion object {
        const val EXTRA_MODE = "mode"
        const val EXTRA_ENTRY = "entry"
        const val EXTRA_CREDENTIAL = "credential"
        const val MODE_CREATE_PASSKEY = "create_passkey"
        const val MODE_GET_PASSKEY = "get_passkey"
        const val MODE_GET_PASSWORD = "get_password"
        const val MODE_UNLOCK = "unlock"
    }
}
