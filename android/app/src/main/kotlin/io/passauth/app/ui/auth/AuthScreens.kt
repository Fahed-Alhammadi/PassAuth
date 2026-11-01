package io.passauth.app.ui.auth

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.passauth.app.data.AccountSummary
import io.passauth.app.data.Keystore
import io.passauth.app.data.LoginResult
import io.passauth.app.data.Status
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultRepository
import io.passauth.app.ui.SecureWindow
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.authenticate
import io.passauth.app.ui.biometricsAvailable
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.Avatar
import io.passauth.app.ui.components.CheckRow
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.components.LogoMark
import io.passauth.app.ui.components.PasswordField
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.components.initials
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.core.estimateBits
import kotlinx.coroutines.launch

/** Centered, scrollable column for the sign-in screens. */
@Composable
private fun AuthFrame(title: String, subtitle: String? = null, content: @Composable ColumnScope.() -> Unit) {
    Box(
        Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).safeDrawingPadding().imePadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            Modifier.widthIn(max = 480.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(24.dp))
            LogoMark(56.dp)
            Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = PassAuthTheme.colors.muted, textAlign = TextAlign.Center)
            }
            content()
        }
    }
}

private fun host(server: String) = UrlMatcher.parse(server)?.host ?: server

// ------------------------------------------------------------------ setup

@Composable
fun SetupScreen(ctx: UiCtx, initial: String = "", onCancel: (() -> Unit)? = null) {
    var url by rememberSaveable { mutableStateOf(initial) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    fun submit() {
        if (busy || url.isBlank()) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                ctx.repo.setServer(url)
            } catch (e: Exception) {
                error = errorMessage(e)
            }
            busy = false
        }
    }
    AuthFrame("Connect to your PassAuth server") {
        TextInput(
            url, { url = it }, "Server address",
            placeholder = "https://vault.example.com", keyboardType = KeyboardType.Uri,
            imeAction = ImeAction.Go, onImeAction = ::submit,
        )
        Text(
            "Use an https:// address. For a test server on this computer, the emulator reaches it at http://10.0.2.2.",
            style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
        )
        ErrorText(error)
        Button(onClick = ::submit, enabled = !busy && url.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Checking…" else "Connect")
        }
        if (onCancel != null) TextButton(onClick = onCancel) { Text("Cancel") }
        OtherAccounts(ctx)
    }
}

// ------------------------------------------------------------------ login

@Composable
fun LoginScreen(ctx: UiCtx) {
    val state = ctx.state
    var changingServer by rememberSaveable { mutableStateOf(false) }
    var creating by rememberSaveable { mutableStateOf(false) }
    var email by rememberSaveable { mutableStateOf(state.email) }
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var needKey by rememberSaveable { mutableStateOf(false) }
    var challenge by remember { mutableStateOf<LoginResult.TwoFactor?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    if (changingServer) return SetupScreen(ctx, initial = state.server, onCancel = { changingServer = false })
    if (creating) {
        return RegisterScreen(ctx, onSignIn = { e, p, sk ->
            creating = false
            email = e
            if (p != null) {
                busy = true
                ctx.scope.launch {
                    try {
                        ctx.repo.login(e, p, sk)
                    } catch (ex: Exception) {
                        error = errorMessage(ex)
                    }
                    busy = false
                }
            }
        }, onBack = { creating = false })
    }
    challenge?.let { c -> return TwoStepScreen(ctx, c, email) { challenge = null } }

    fun submit() {
        if (busy || email.isBlank() || password.isEmpty()) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                when (val r = ctx.repo.login(email, password, secretKey.ifBlank { null })) {
                    is LoginResult.TwoFactor -> challenge = r
                    LoginResult.Done -> Unit
                }
            } catch (e: Exception) {
                if (e.message == VaultRepository.SECRET_KEY_REQUIRED) needKey = true
                error = errorMessage(e)
            }
            busy = false
        }
    }

    AuthFrame("Sign in to PassAuth") {
        TextInput(email, { email = it }, "Email", keyboardType = KeyboardType.Email)
        PasswordField(
            password, { password = it }, "Master password",
            imeAction = if (needKey) ImeAction.Next else ImeAction.Done, onImeAction = { if (!needKey) submit() },
        )
        if (needKey) {
            TextInput(secretKey, { secretKey = it }, "Secret Key", mono = true, placeholder = "PA1-XXXXXX-…", imeAction = ImeAction.Done, onImeAction = ::submit)
        }
        ErrorText(error)
        Button(onClick = ::submit, enabled = !busy && email.isNotBlank() && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Signing in…" else "Sign in")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(host(state.server), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
            TextButton(onClick = { changingServer = true }) { Text("Change server") }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("New to PassAuth?", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
            TextButton(onClick = { creating = true }) { Text("Create account") }
        }
        OtherAccounts(ctx)
    }
}

private fun providerLabel(p: String) = when (p) {
    "totp" -> "Authenticator app"
    "email" -> "Email code"
    else -> "Recovery code"
}

@Composable
private fun TwoStepScreen(ctx: UiCtx, challenge: LoginResult.TwoFactor, email: String, onCancel: () -> Unit) {
    var provider by rememberSaveable { mutableStateOf(challenge.providers.firstOrNull() ?: "totp") }
    var code by remember { mutableStateOf("") }
    var remember by rememberSaveable { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var note by remember { mutableStateOf<String?>(null) }

    fun verify() {
        if (busy || code.isBlank()) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                ctx.repo.verifyTwoFactor(challenge.token, provider, code, remember)
            } catch (e: Exception) {
                error = errorMessage(e)
                busy = false
            }
        }
    }

    AuthFrame("Two-step login") {
        if (challenge.providers.size > 1) {
            Text("Verify with", style = MaterialTheme.typography.labelLarge, modifier = Modifier.fillMaxWidth())
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                challenge.providers.forEachIndexed { i, p ->
                    SegmentedButton(
                        selected = provider == p,
                        onClick = { provider = p; code = ""; error = null },
                        shape = SegmentedButtonDefaults.itemShape(i, challenge.providers.size),
                        label = { Text(providerLabel(p), maxLines = 1, style = MaterialTheme.typography.labelMedium) },
                    )
                }
            }
        }
        TextInput(
            code, { code = it }, if (provider == "recovery") "Recovery code" else "6-digit code", mono = true,
            keyboardType = if (provider == "recovery") KeyboardType.Ascii else KeyboardType.Number,
            imeAction = ImeAction.Done, onImeAction = ::verify,
        )
        if (provider == "email") {
            OutlinedButton(onClick = {
                ctx.scope.launch {
                    try {
                        ctx.repo.sendTwoFactorEmail(challenge.token)
                        note = "Code sent to $email."
                    } catch (e: Exception) {
                        error = errorMessage(e)
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Email me a code") }
        }
        CheckRow("Remember this device", remember, { remember = it }, help = "Skip two-step login on this device for a while.")
        note?.let { Alert(it, AlertKind.Ok) }
        ErrorText(error)
        Button(onClick = ::verify, enabled = !busy && code.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Verifying…" else "Verify and sign in")
        }
        TextButton(onClick = onCancel) { Text("Back") }
    }
}

// --------------------------------------------------------------- register

/** Create an account (the web vault's Register). `onSignIn(email, password?, secretKey?)`. */
@Composable
private fun RegisterScreen(ctx: UiCtx, onSignIn: (String, String?, String?) -> Unit, onBack: () -> Unit) {
    var email by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var hint by remember { mutableStateOf(false) }
    var withSecretKey by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var done by remember { mutableStateOf<io.passauth.app.data.Registered?>(null) }
    var saved by remember { mutableStateOf(false) }
    var closed by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { closed = ctx.repo.signupsAllowed() == false }

    val saveKit = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val sk = done?.secretKey ?: return@rememberLauncherForActivityResult
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            ctx.activity.contentResolver.openOutputStream(uri)!!.use { it.write(emergencyKit(ctx.state.server, email, sk).toByteArray()) }
        }.onSuccess { ctx.notify("Emergency Kit saved.") }.onFailure { ctx.notify("Couldn't save the Emergency Kit.") }
    }

    done?.let { d ->
        if (d.secretKey != null) SecureWindow()
        return AuthFrame("Your vault is ready") {
            if (d.secretKey != null) {
                Text(
                    "This is your Secret Key. You need it, together with your master password, to sign in on a new device. " +
                        "Save it now: it is shown only once and PassAuth cannot recover it.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    border = BorderStroke(1.dp, PassAuthTheme.colors.line),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    SelectionContainer {
                        Text(d.secretKey, fontFamily = FontFamily.Monospace, textAlign = TextAlign.Center, modifier = Modifier.padding(14.dp))
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(onClick = { saveKit.launch("PassAuth-Emergency-Kit.txt") }, modifier = Modifier.weight(1f)) { Text("Save Emergency Kit") }
                    OutlinedButton(onClick = { ctx.copy(d.secretKey, "Secret Key") }, modifier = Modifier.weight(1f)) { Text("Copy Secret Key") }
                }
                CheckRow("I saved my Secret Key somewhere safe", saved, { saved = it })
            }
            if (d.emailVerificationRequired) Alert("We sent a verification link to $email. Open it, then sign in.", AlertKind.Ok)
            ErrorText(error)
            Button(
                onClick = { onSignIn(email, if (d.emailVerificationRequired) null else password, d.secretKey) },
                enabled = d.secretKey == null || saved,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (d.emailVerificationRequired) "Go to sign in" else "Open my vault") }
        }
    }

    fun submit() {
        error = null
        if (password.length < 10) return run { error = "Use at least 10 characters for your master password." }
        if (password != confirm) return run { error = "The two passwords don't match." }
        if (estimateBits(password) < 50 && !hint) {
            hint = true
            return run { error = "This password is easy to guess. Choose a longer one, or select Create account again to use it anyway." }
        }
        busy = true
        ctx.scope.launch {
            try {
                done = ctx.repo.register(email, name, password, withSecretKey)
            } catch (e: Exception) {
                error = errorMessage(e)
            }
            busy = false
        }
    }

    AuthFrame("Create your PassAuth account", "Everything is encrypted on this device before it reaches the server.") {
        if (closed) {
            Alert("Sign-ups are closed on this server. Ask the administrator for an invitation, then create your account with the invited email address.")
        }
        TextInput(email, { email = it }, "Email", keyboardType = KeyboardType.Email)
        TextInput(name, { name = it }, "Your name")
        PasswordField(password, { password = it; hint = false }, "Master password", imeAction = ImeAction.Next)
        StrengthMeter(password)
        PasswordField(confirm, { confirm = it }, "Confirm master password", imeAction = ImeAction.Next)
        Alert("Your master password can't be reset. If you forget it, the data in your vault can't be recovered by anyone, including the server administrator.")
        CheckRow(
            "Add a Secret Key", withSecretKey, { withSecretKey = it },
            help = "A second, random key that never leaves your devices. Even if the server is breached, your vault can't be cracked by guessing your password. You'll enter it once on each new device.",
        )
        ErrorText(error)
        Button(onClick = ::submit, enabled = !busy && email.isNotBlank() && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Creating account…" else "Create account")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Already have an account?", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
            TextButton(onClick = onBack) { Text("Sign in") }
        }
    }
}

private fun emergencyKit(server: String, email: String, secretKey: String) = listOf(
    "PassAuth Emergency Kit",
    "",
    "Server:      $server",
    "Email:       $email",
    "Secret Key:  $secretKey",
    "",
    "Master password: ______________________________",
    "",
    "Keep this kit somewhere safe and offline, such as a printed copy in a drawer",
    "or safe. You need the Secret Key and your master password to sign in on a new",
    "device. PassAuth cannot recover either of them for you.",
    "",
).joinToString("\n")

/** Password strength from the core's estimate (bits of entropy), same thresholds as the web vault's meter. */
@Composable
fun StrengthMeter(password: String) {
    if (password.isEmpty()) return
    val bits = remember(password) { estimateBits(password) }
    val (label, level) = when {
        bits < 40 -> "Weak" to 1
        bits < 60 -> "Fair" to 2
        bits < 80 -> "Good" to 3
        else -> "Strong" to 4
    }
    val color = when (level) {
        1 -> MaterialTheme.colorScheme.error
        2 -> MaterialTheme.colorScheme.primary
        else -> PassAuthTheme.colors.ok
    }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(4) { i ->
                Box(
                    Modifier.weight(1f).height(4.dp).background(
                        if (i < level) color else PassAuthTheme.colors.line,
                        RoundedCornerShape(2.dp),
                    ),
                )
            }
        }
        Text("Strength: $label", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
    }
}

// ----------------------------------------------------------------- unlock

@Composable
fun UnlockScreen(ctx: UiCtx) {
    val state = ctx.state
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val needKey = state.secretKeyRequired && !state.secretKeyStored
    val canBio = state.biometricEnabled && biometricsAvailable(ctx.activity)

    fun submit() {
        if (busy || password.isEmpty()) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                ctx.repo.unlock(password, secretKey.ifBlank { null })
            } catch (e: Exception) {
                error = errorMessage(e)
                busy = false
            }
        }
    }

    fun biometric() {
        if (busy) return
        ctx.scope.launch {
            try {
                val (id, sealed) = ctx.repo.biometricBlob() ?: return@launch
                val key = Keystore.biometricKey(id)
                val cipher = try {
                    key?.let { Keystore.biometricCipher(it, sealed) }
                } catch (_: KeyPermanentlyInvalidatedException) {
                    null
                }
                if (cipher == null) {
                    ctx.repo.disableBiometric()
                    error = "Biometrics changed on this device. Unlock with your master password, then turn biometric unlock on again in Settings."
                    return@launch
                }
                val ok = ctx.activity.authenticate(cipher, "Unlock PassAuth", state.email) ?: return@launch
                busy = true
                ctx.repo.unlockWithBiometric(ok)
            } catch (e: Exception) {
                error = errorMessage(e)
                busy = false
            }
        }
    }
    LaunchedEffect(Unit) { if (canBio) biometric() }

    AuthFrame("Unlock PassAuth", state.email) {
        PasswordField(
            password, { password = it }, "Master password",
            imeAction = if (needKey) ImeAction.Next else ImeAction.Done, onImeAction = { if (!needKey) submit() },
        )
        if (needKey) TextInput(secretKey, { secretKey = it }, "Secret Key", mono = true, imeAction = ImeAction.Done, onImeAction = ::submit)
        ErrorText(error)
        Button(onClick = ::submit, enabled = !busy && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Unlocking…" else "Unlock")
        }
        if (canBio) {
            OutlinedButton(onClick = ::biometric, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.Fingerprint, null, Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text("Unlock with biometrics")
            }
        }
        TextButton(onClick = { ctx.launch { ctx.repo.logout() } }) { Text("Log out") }
        OtherAccounts(ctx)
    }
}

// --------------------------------------------------------- other accounts

private fun statusLabel(s: Status) = when (s) {
    Status.Unlocked -> "Unlocked"
    Status.Locked -> "Locked"
    Status.LoggedOut -> "Logged out"
    Status.Setup -> ""
}

/** On the setup, sign-in and unlock screens: switch to another account, or cancel adding one. */
@Composable
private fun OtherAccounts(ctx: UiCtx) {
    val state = ctx.state
    val others = state.accounts.filter { it.id != state.activeId }
    if (others.isEmpty()) return
    val adding = state.accounts.none { it.id == state.activeId }
    Column(Modifier.fillMaxWidth().padding(top = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(if (adding) "Or go back to" else "Switch account", style = MaterialTheme.typography.labelMedium, color = PassAuthTheme.colors.muted)
        others.forEach { a ->
            AccountRow(a) {
                ctx.launch { if (adding) ctx.repo.cancelAddAccount(a.id) else ctx.repo.switchAccount(a.id) }
            }
        }
    }
}

@Composable
fun AccountRow(a: AccountSummary, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(initials(a.name, a.email), 32.dp)
        Column(Modifier.weight(1f)) {
            Text(a.name.ifEmpty { a.email }, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
            Text(host(a.server), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted, maxLines = 1)
        }
        Text(statusLabel(a.status), style = MaterialTheme.typography.labelSmall, color = PassAuthTheme.colors.muted)
    }
}
