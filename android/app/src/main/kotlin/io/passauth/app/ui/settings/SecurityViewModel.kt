package io.passauth.app.ui.settings

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.passauth.app.data.ApiException
import io.passauth.app.data.PolicyRules
import io.passauth.app.data.SecurityKeyInfo
import io.passauth.app.data.SessionInfo
import io.passauth.app.data.SessionList
import io.passauth.app.data.SessionText
import io.passauth.app.data.MasterPasswordRules
import io.passauth.app.data.SecretKeyChoice
import io.passauth.app.data.SecurityStatus
import io.passauth.app.data.ShowOnce
import io.passauth.app.data.TotpSetup
import io.passauth.app.data.TwoFactor
import io.passauth.app.data.VaultRepository
import io.passauth.app.data.securityErrorMessage
import io.passauth.app.ui.errorMessage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

/** Password-confirmed actions of these settings. */
enum class SecurityDialog { SecretKeyToggle, DisableTotp, DisableEmail, Regenerate, RemoveKey }

/** Turning a two-step method on without the master password filled in. */
const val ENTER_PASSWORD = "Enter your master password to continue."

/** What a sign-out confirmation (Signed-in devices) is about: one session, or every other one. */
sealed interface SignOutTarget {
    data class One(val session: SessionInfo) : SignOutTarget
    data class Others(val count: Int) : SignOutTarget
}

/**
 * State of Settings → Change master password and Two-step login. A ViewModel, so a
 * request in flight and what it returns (a new Secret Key, recovery codes) outlive
 * the activity being recreated. Secrets live only here, in memory: never in the
 * saved-instance state, and [clear] drops them when the screens are left.
 */
class SecurityViewModel(private val repo: VaultRepository) : ViewModel() {
    private val _notices = Channel<String>(Channel.BUFFERED)

    /** One-shot notices for the snackbar. */
    val notices = _notices.receiveAsFlow()

    private fun message(e: Exception) = securityErrorMessage(e) ?: errorMessage(e)

    // ------------------------------------------------- change master password

    var current by mutableStateOf("")
    var next by mutableStateOf("")
        private set
    var confirm by mutableStateOf("")
    var secretKey by mutableStateOf("")
    var choice by mutableStateOf(SecretKeyChoice.Keep)
    private var weakConfirmed = false
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
    var newSecretKey by mutableStateOf<ShowOnce<String>?>(null)

    fun updateNext(v: String) {
        next = v
        weakConfirmed = false
        // The weak-password warning was about the previous value.
        if (error == MasterPasswordRules.WEAK_MESSAGE) error = null
    }

    fun changePassword(bits: (String) -> Double) {
        if (busy) return
        error = null
        // The server's policy may ask for a longer master password than the app's own minimum.
        val minLength = PolicyRules.minPasswordLength(repo.state.value.policies)
        MasterPasswordRules.problem(current, next, confirm, if (next.isEmpty()) 0.0 else bits(next), weakConfirmed, minLength)?.let { p ->
            if (p == MasterPasswordRules.WEAK_MESSAGE) weakConfirmed = true
            error = p
            return
        }
        val chosen = choice
        busy = true
        viewModelScope.launch {
            try {
                val sk = repo.changeMasterPassword(current, next, chosen, secretKey.ifBlank { null })
                current = ""; next = ""; confirm = ""; secretKey = ""
                weakConfirmed = false
                choice = SecretKeyChoice.Keep
                _notices.trySend(
                    if (chosen == SecretKeyChoice.TurnOff) "Master password changed and Secret Key turned off. Other devices were signed out."
                    else "Master password changed. Other devices were signed out.",
                )
                if (sk != null) newSecretKey = ShowOnce(sk)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = message(e)
            } finally {
                busy = false
            }
        }
    }

    // ------------------------------------------------------- two-step login

    var status by mutableStateOf<SecurityStatus?>(null)
        private set
    var loading by mutableStateOf(false)
        private set
    var loadError by mutableStateOf<String?>(null)
        private set

    fun load() {
        if (loading) return
        loading = true
        loadError = null
        viewModelScope.launch {
            try {
                status = repo.securityStatus()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                loadError = message(e)
            } finally {
                loading = false
            }
        }
    }

    var totp by mutableStateOf<TotpSetup?>(null)
        private set
    var totpCode by mutableStateOf("")
    var totpBusy by mutableStateOf(false)
        private set
    var totpError by mutableStateOf<String?>(null)

    /**
     * The master password (and the Secret Key when this device doesn't keep it) that confirms
     * turning the authenticator app on: the server takes a method only with a fresh reauth token.
     * Memory only, cleared with the setup.
     */
    var totpPassword by mutableStateOf("")
    var totpSecretKey by mutableStateOf("")

    fun startTotp() = totpStep {
        totp = repo.totpSetup()
        totpCode = ""
    }

    fun enableTotp() {
        if (!TwoFactor.validTotp(totpCode)) return run { totpError = "Enter the 6-digit code from your authenticator app." }
        if (totpPassword.isEmpty()) return run { totpError = ENTER_PASSWORD }
        totpStep {
            val codes = repo.totpEnable(totpCode, totpPassword, totpSecretKey.ifBlank { null })
            totp = null
            totpCode = ""
            totpPassword = ""
            totpSecretKey = ""
            _notices.trySend("Authenticator app turned on.")
            enabled(codes)
        }
    }

    fun cancelTotp() {
        if (totpBusy) return
        totp = null
        totpCode = ""
        totpError = null
        totpPassword = ""
        totpSecretKey = ""
    }

    private fun totpStep(block: suspend () -> Unit) {
        if (totpBusy) return
        totpBusy = true
        totpError = null
        viewModelScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                totpError = message(e)
            } finally {
                totpBusy = false
            }
        }
    }

    var emailSent by mutableStateOf(false)
        private set
    var emailCode by mutableStateOf("")
    var emailBusy by mutableStateOf(false)
        private set
    var emailError by mutableStateOf<String?>(null)

    /** As [totpPassword], for email codes. */
    var emailPassword by mutableStateOf("")
    var emailSecretKey by mutableStateOf("")

    fun sendEmailCode() = emailStep {
        repo.emailTwoFactorSetup()
        emailSent = true
        emailCode = ""
        _notices.trySend("Code sent to ${status?.email.orEmpty()}.")
    }

    fun enableEmail() {
        if (TwoFactor.cleanCode(emailCode).isEmpty()) return run { emailError = "Enter the code from the email we sent you." }
        if (emailPassword.isEmpty()) return run { emailError = ENTER_PASSWORD }
        emailStep {
            val codes = repo.emailTwoFactorEnable(emailCode, emailPassword, emailSecretKey.ifBlank { null })
            emailSent = false
            emailCode = ""
            emailPassword = ""
            emailSecretKey = ""
            _notices.trySend("Email codes turned on.")
            enabled(codes)
        }
    }

    fun cancelEmail() {
        if (emailBusy) return
        emailSent = false
        emailCode = ""
        emailError = null
        emailPassword = ""
        emailSecretKey = ""
    }

    private fun emailStep(block: suspend () -> Unit) {
        if (emailBusy) return
        emailBusy = true
        emailError = null
        viewModelScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                emailError = message(e)
            } finally {
                emailBusy = false
            }
        }
    }

    /** Recovery codes shown once (after the first method, or regenerated). */
    var recovery by mutableStateOf<ShowOnce<List<String>>?>(null)

    private suspend fun enabled(codes: List<String>?) {
        if (!codes.isNullOrEmpty()) recovery = ShowOnce(codes)
        runCatching { status = repo.securityStatus() }
    }

    // ---------------------------------------------- password-confirmed dialogs

    var dialog by mutableStateOf<SecurityDialog?>(null)
        private set
    var dialogBusy by mutableStateOf(false)
        private set
    var dialogError by mutableStateOf<String?>(null)

    fun openDialog(d: SecurityDialog) {
        if (dialogBusy) return
        dialogError = null
        dialog = d
    }

    /** The security key the RemoveKey dialog is about. */
    var removingKey by mutableStateOf<SecurityKeyInfo?>(null)
        private set

    fun openRemoveKey(k: SecurityKeyInfo) {
        if (dialogBusy) return
        removingKey = k
        openDialog(SecurityDialog.RemoveKey)
    }

    fun closeDialog() {
        if (!dialogBusy) dialog = null
    }

    /** Runs the open dialog's action with the master password (server re-authentication). */
    fun confirmDialog(password: String, secretKey: String?, secretKeyOn: Boolean) {
        val d = dialog ?: return
        if (dialogBusy) return
        if (password.isEmpty()) return run { dialogError = "Enter your master password." }
        dialogBusy = true
        dialogError = null
        viewModelScope.launch {
            try {
                when (d) {
                    SecurityDialog.SecretKeyToggle -> {
                        val choice = if (secretKeyOn) SecretKeyChoice.TurnOff else SecretKeyChoice.TurnOn
                        val sk = repo.changeMasterPassword(password, password, choice, secretKey)
                        if (sk != null) newSecretKey = ShowOnce(sk)
                        else _notices.trySend("Secret Key turned off. Other devices were signed out.")
                    }
                    SecurityDialog.DisableTotp, SecurityDialog.DisableEmail -> {
                        val totp = d == SecurityDialog.DisableTotp
                        repo.disableTwoFactor(if (totp) TwoFactor.TOTP else TwoFactor.EMAIL, password, secretKey)
                        _notices.trySend(if (totp) "Authenticator app turned off." else "Email codes turned off.")
                        runCatching { status = repo.securityStatus() }
                    }
                    SecurityDialog.Regenerate -> {
                        recovery = ShowOnce(repo.regenerateRecoveryCodes(password, secretKey))
                        runCatching { status = repo.securityStatus() }
                    }
                    SecurityDialog.RemoveKey -> {
                        val k = removingKey ?: return@launch
                        repo.removeSecurityKey(k.id, password, secretKey)
                        _notices.trySend("Security key removed.")
                        removingKey = null
                        runCatching { status = repo.securityStatus() }
                    }
                }
                dialog = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                dialogError = message(e)
            } finally {
                dialogBusy = false
            }
        }
    }

    // ------------------------------------------------------ signed-in devices

    var sessions by mutableStateOf<SessionList?>(null)
        private set
    var sessionsLoading by mutableStateOf(false)
        private set
    var sessionsError by mutableStateOf<String?>(null)
        private set

    /** The sign-out being confirmed in the decision sheet. */
    var signingOut by mutableStateOf<SignOutTarget?>(null)
        private set
    var signOutBusy by mutableStateOf(false)
        private set
    var signOutError by mutableStateOf<String?>(null)
        private set

    fun loadSessions() {
        if (sessionsLoading) return
        sessionsLoading = true
        sessionsError = null
        viewModelScope.launch {
            try {
                sessions = repo.accountSessions()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (sessions == null) sessionsError = "Couldn't load your sessions. ${errorMessage(e)}" else _notices.trySend(errorMessage(e))
            } finally {
                sessionsLoading = false
            }
        }
    }

    fun askSignOut(target: SignOutTarget) {
        if (signOutBusy) return
        signOutError = null
        signingOut = target
    }

    fun cancelSignOut() {
        if (!signOutBusy) signingOut = null
    }

    fun confirmSignOut() {
        val t = signingOut ?: return
        if (signOutBusy) return
        signOutBusy = true
        signOutError = null
        viewModelScope.launch {
            try {
                when (t) {
                    is SignOutTarget.One -> {
                        repo.revokeSession(t.session.id)
                        _notices.trySend("${t.session.deviceName.ifEmpty { "Device" }} signed out.")
                    }
                    is SignOutTarget.Others -> _notices.trySend(SessionText.revokedOthers(repo.revokeOtherSessions()))
                }
                signingOut = null
                runCatching { sessions = repo.accountSessions() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                signOutError = errorMessage(e)
            } finally {
                signOutBusy = false
            }
        }
    }

    // -------------------------------------------------------- forget a device

    /** The device being forgotten (confirmed in the decision sheet). */
    var forgetting by mutableStateOf<SessionInfo?>(null)
        private set
    var forgetBusy by mutableStateOf(false)
        private set
    var forgetError by mutableStateOf<String?>(null)
        private set

    fun askForget(session: SessionInfo) {
        if (forgetBusy || signOutBusy || session.deviceId.isEmpty()) return
        forgetError = null
        forgetting = session
    }

    fun cancelForget() {
        if (!forgetBusy) forgetting = null
    }

    /**
     * Forget the device. [notify] shows a notice that outlives this screen: forgetting this device
     * signs the account out here, and the screen goes with it.
     */
    fun confirmForget(notify: (String) -> Unit) {
        val s = forgetting ?: return
        if (forgetBusy) return
        forgetBusy = true
        forgetError = null
        viewModelScope.launch {
            try {
                val r = repo.forgetDevice(s.deviceId)
                forgetting = null
                if (r.current) {
                    notify(SessionText.FORGOTTEN_HERE)
                } else {
                    notify(SessionText.forgotten(s.deviceName))
                    runCatching { sessions = repo.accountSessions() }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (e is ApiException && e.status == 404) {
                    // Already gone: show the list as it is now.
                    forgetting = null
                    runCatching { sessions = repo.accountSessions() }
                } else {
                    forgetError = errorMessage(e)
                }
            } finally {
                forgetBusy = false
            }
        }
    }

    /** Whether a request is running (leaving the screen would lose what it returns). */
    val working: Boolean get() = busy || totpBusy || emailBusy || dialogBusy

    /** Leaving the screens: forget typed passwords, setup keys and codes. */
    fun clear() {
        if (working) return
        current = ""; next = ""; confirm = ""; secretKey = ""
        weakConfirmed = false
        choice = SecretKeyChoice.Keep
        error = null
        totp = null; totpCode = ""; totpError = null; totpPassword = ""; totpSecretKey = ""
        emailSent = false; emailCode = ""; emailError = null; emailPassword = ""; emailSecretKey = ""
        dialog = null; dialogError = null
        if (!signOutBusy) { signingOut = null; signOutError = null }
        if (!forgetBusy) { forgetting = null; forgetError = null }
        // Shown-once values stay until confirmed: they can't be shown again.
    }
}
