package io.passauth.app.ui.settings

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
enum class SecurityDialog { SecretKeyToggle, DisableTotp, DisableEmail, Regenerate }

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
        MasterPasswordRules.problem(current, next, confirm, if (next.isEmpty()) 0.0 else bits(next), weakConfirmed)?.let { p ->
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

    fun startTotp() = totpStep {
        totp = repo.totpSetup()
        totpCode = ""
    }

    fun enableTotp() {
        if (!TwoFactor.validTotp(totpCode)) return run { totpError = "Enter the 6-digit code from your authenticator app." }
        totpStep {
            val codes = repo.totpEnable(totpCode)
            totp = null
            totpCode = ""
            _notices.trySend("Authenticator app turned on.")
            enabled(codes)
        }
    }

    fun cancelTotp() {
        if (totpBusy) return
        totp = null
        totpCode = ""
        totpError = null
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

    fun sendEmailCode() = emailStep {
        repo.emailTwoFactorSetup()
        emailSent = true
        emailCode = ""
        _notices.trySend("Code sent to ${status?.email.orEmpty()}.")
    }

    fun enableEmail() {
        if (TwoFactor.cleanCode(emailCode).isEmpty()) return run { emailError = "Enter the code from the email we sent you." }
        emailStep {
            val codes = repo.emailTwoFactorEnable(emailCode)
            emailSent = false
            emailCode = ""
            _notices.trySend("Email codes turned on.")
            enabled(codes)
        }
    }

    fun cancelEmail() {
        if (emailBusy) return
        emailSent = false
        emailCode = ""
        emailError = null
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

    /** Whether a request is running (leaving the screen would lose what it returns). */
    val working: Boolean get() = busy || totpBusy || emailBusy || dialogBusy

    /** Leaving the screens: forget typed passwords, setup keys and codes. */
    fun clear() {
        if (working) return
        current = ""; next = ""; confirm = ""; secretKey = ""
        weakConfirmed = false
        choice = SecretKeyChoice.Keep
        error = null
        totp = null; totpCode = ""; totpError = null
        emailSent = false; emailCode = ""; emailError = null
        dialog = null; dialogError = null
        // Shown-once values stay until confirmed: they can't be shown again.
    }
}
