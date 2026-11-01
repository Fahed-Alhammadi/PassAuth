package io.passauth.app.ui.settings

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.LifecycleResumeEffect
import io.passauth.app.BuildConfig
import io.passauth.app.data.Keystore
import io.passauth.app.data.Settings
import io.passauth.app.data.ThemeMode
import io.passauth.app.data.TimeoutAction
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.VaultTimeout
import io.passauth.app.data.secondsLabel
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.authenticate
import io.passauth.app.ui.biometricsAvailable
import io.passauth.app.ui.components.AccountMenu
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.KeyValue
import io.passauth.app.ui.components.LogoMark
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.SelectField
import io.passauth.app.ui.components.ToggleRow
import io.passauth.app.ui.components.ValueText
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.Brand
import io.passauth.app.ui.theme.PassAuthTheme
import kotlinx.coroutines.launch

private val MATCHES = listOf(
    UrlMatch.Domain to "Base domain",
    UrlMatch.Host to "Host",
    UrlMatch.StartsWith to "Starts with",
    UrlMatch.Regex to "Regular expression",
    UrlMatch.Exact to "Exact",
    UrlMatch.Never to "Never",
)

private fun matchHelp(m: UrlMatch) = when (m) {
    UrlMatch.Host -> "Same host name and port only: login.example.com doesn't match www.example.com."
    UrlMatch.StartsWith -> "The page address must start with the saved website address."
    UrlMatch.Regex -> "The saved website is a regular expression tested against the page address. Advanced."
    UrlMatch.Exact -> "The page address must be exactly the saved website address."
    UrlMatch.Never -> "Never suggest or fill logins automatically. Items can still set their own matching."
    else -> "login.example.com and www.example.com both match example.com."
}

private fun formatTime(ms: Long): String {
    if (ms == 0L) return "never"
    return if (DateUtils.isToday(ms)) {
        "today at " + java.text.DateFormat.getTimeInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(ms))
    } else {
        java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(ms))
    }
}

private data class Section(val key: String, val title: String, val icon: ImageVector)

private val SECTIONS = listOf(
    Section("security", "Account security", Icons.Outlined.Lock),
    Section("autofill", "Autofill", Icons.Outlined.AutoFixHigh),
    Section("vault", "Vault options", Icons.Outlined.Inventory2),
    Section("appearance", "Appearance", Icons.Outlined.Palette),
    Section("about", "About", Icons.Outlined.Info),
)

/** Settings: a list of categories, each opening its own page (like the extension popup). */
@Composable
fun SettingsScreen(ctx: UiCtx, section: String?) {
    if (section == "export") return ExportScreen(ctx)
    val open = SECTIONS.firstOrNull { it.key == section }
    if (open == null) {
        Scaffold(topBar = { PageBar("Settings", brand = true) { AccountMenu(ctx) } }) { padding ->
            Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
                CardSection(null) {
                    SECTIONS.forEachIndexed { n, s ->
                        if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                        Row(
                            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button) { ctx.go(Route.Settings(s.key)) }.padding(vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp),
                        ) {
                            Icon(s.icon, null, tint = MaterialTheme.colorScheme.primary)
                            Text(s.title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                            Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
                        }
                    }
                }
            }
        }
        return
    }
    Scaffold(topBar = { PageBar(open.title, onBack = { ctx.go(Route.Settings()) }) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CardSection(null) {
                Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    when (open.key) {
                        "security" -> Security(ctx)
                        "autofill" -> Autofill(ctx)
                        "vault" -> VaultOptions(ctx)
                        "appearance" -> Appearance(ctx)
                        else -> About(ctx)
                    }
                }
            }
        }
    }
}

private fun UiCtx.update(f: (Settings) -> Settings) = launch { repo.updateSettings(f) }

@Composable
internal fun Muted(text: String) = Text(text, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)

@Composable
private fun ColumnScope.Security(ctx: UiCtx) {
    val s = ctx.state.settings
    SelectField("Vault timeout", VaultTimeout.entries.map { it to it.label }, s.vaultTimeout, { v -> ctx.update { it.copy(vaultTimeout = v) } })
    if (s.vaultTimeout == VaultTimeout.Never) {
        Alert(
            "With \"Never\", your vault key is stored on this device without the master password protecting it. Anyone who can unlock this phone and open PassAuth can open your vault.",
            AlertKind.Error,
        )
    }
    SelectField("Timeout action", listOf(TimeoutAction.Lock to "Lock", TimeoutAction.Logout to "Log out"), s.timeoutAction, { v -> ctx.update { it.copy(timeoutAction = v) } })
    Muted(
        if (s.timeoutAction == TimeoutAction.Lock) "Locking keeps your encrypted vault here; unlock with your master password or biometrics."
        else "Logging out removes the vault from this phone; sign in again (with two-step login) to use it.",
    )
    HorizontalDivider(color = PassAuthTheme.colors.line)
    val available = biometricsAvailable(ctx.activity)
    ToggleRow(
        "Unlock with biometrics",
        ctx.state.biometricEnabled,
        { on ->
            if (!on) {
                ctx.launch { ctx.repo.disableBiometric(); ctx.notify("Biometric unlock is off.") }
            } else if (!available) {
                ctx.notify("Set up a fingerprint or face unlock in Android settings first.")
            } else {
                ctx.launch {
                    val cipher = Keystore.biometricCipher(Keystore.newBiometricKey(ctx.state.activeId))
                    val ok = ctx.activity.authenticate(cipher, "Turn on biometric unlock", ctx.state.email) ?: return@launch
                    ctx.repo.enableBiometric(ok)
                    ctx.notify("Biometric unlock is on.")
                }
            }
        },
        help = if (available) {
            "Unlock this account with your fingerprint or face. It turns off by itself if biometrics on this phone change."
        } else {
            "Set up a fingerprint or face unlock in Android settings to use this."
        },
    )
    OutlinedButton(onClick = { ctx.launch { ctx.repo.lock() } }) {
        Icon(Icons.Outlined.Lock, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text("Lock now")
    }
    HorizontalDivider(color = PassAuthTheme.colors.line)
    Text("In the web vault", style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
    WebLink(ctx, "Two-step login", "Authenticator app, email codes and recovery codes.", "/settings/two-step")
    WebLink(ctx, "Change master password", "Also turns the Secret Key on or off.", "/settings/security")
    Muted("These open your web vault in the browser. Sign in there if it asks.")
}

/** A shortcut to a page of the account's web vault (path routes). */
@Composable
private fun WebLink(ctx: UiCtx, title: String, help: String, path: String) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp)
            .clickable(role = Role.Button, onClickLabel = "Open in browser") { ctx.openUrl(ctx.state.server.trimEnd('/') + path) }
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Muted(help)
        }
        Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, tint = PassAuthTheme.colors.muted)
    }
}

@Composable
private fun ColumnScope.Autofill(ctx: UiCtx) {
    val s = ctx.state.settings
    val context = LocalContext.current
    // Re-read the system settings whenever the screen comes back (after choosing PassAuth there).
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) {
        resumes++
        onPauseOrDispose { }
    }
    val autofillOn = remember(resumes) { SystemServices.autofillEnabled(context) }
    val providerOn = remember(resumes) { SystemServices.providerEnabled(context) }

    ServiceRow(
        "Autofill service", autofillOn,
        "Fill and save logins in apps and browsers.",
        if (autofillOn) "Change" else "Use PassAuth",
    ) { if (!SystemServices.openAutofillSettings(context)) ctx.notify("Open Android settings → Passwords, passkeys & accounts to choose PassAuth.") }
    ServiceRow(
        "Passkeys and passwords", providerOn,
        "Create and use passkeys, and sign in with saved passwords, through Android's Credential Manager.",
        if (providerOn) "Change" else "Use PassAuth",
    ) { if (!SystemServices.openProviderSettings(context)) ctx.notify("Open Android settings → Passwords, passkeys & accounts to turn on PassAuth.") }
    Muted("In Chrome on Android, also choose \"Autofill using another service\" in Chrome's settings (Autofill services), then restart Chrome.")
    HorizontalDivider(color = PassAuthTheme.colors.line)
    SelectField("Default URI match detection", MATCHES, s.defaultMatch, { v -> ctx.update { it.copy(defaultMatch = v) } })
    Muted("${matchHelp(s.defaultMatch)} Applies to websites set to \"Default\" in an item. Apps match logins with the website androidapp://<package name>.")
    ToggleRow(
        "Copy verification code automatically", s.autoCopyTotp, { v -> ctx.update { it.copy(autoCopyTotp = v) } },
        help = "After filling a login that has an authenticator key, the current code is copied so you can paste it.",
    )
    SelectField(
        "Clear clipboard",
        listOf(0 to "Never") + listOf(10, 20, 30, 60, 120, 300).map { it to "After ${secondsLabel(it)}" },
        s.clearClipboard,
        { v -> ctx.update { it.copy(clearClipboard = v) } },
    )
    Muted("Applies to everything PassAuth copies: passwords, usernames and verification codes.")
    HorizontalDivider(color = PassAuthTheme.colors.line)
    ToggleRow(
        "Ask to save and update logins", s.askToSave, { v -> ctx.update { it.copy(askToSave = v) } },
        help = "After you sign in somewhere, offer to save the login or update its changed password.",
    )
    Text("Never save on", style = MaterialTheme.typography.labelLarge)
    if (s.neverSave.isEmpty()) {
        Muted("No sites or apps. Choose \"Never\" on a save prompt to add one.")
    } else {
        Column {
            s.neverSave.sorted().forEach { key ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(neverSaveLabel(key), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    IconButton(onClick = { ctx.update { st -> st.copy(neverSave = st.neverSave - key) } }) {
                        Icon(Icons.Outlined.Close, contentDescription = "Remove ${neverSaveLabel(key)}", tint = PassAuthTheme.colors.muted)
                    }
                }
            }
        }
    }
}

private fun neverSaveLabel(key: String) = key.removePrefix("androidapp://").let { if (it != key) "App: $it" else it }

/** A system service PassAuth can be chosen for, with its status. */
@Composable
private fun ServiceRow(title: String, on: Boolean, help: String, action: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                if (on) "On: PassAuth is selected" else "Off",
                style = MaterialTheme.typography.bodySmall,
                color = if (on) PassAuthTheme.colors.ok else PassAuthTheme.colors.muted,
                fontWeight = FontWeight.Medium,
            )
            Muted(help)
        }
        OutlinedButton(onClick = onClick) { Text(action) }
    }
}

@Composable
private fun ColumnScope.VaultOptions(ctx: UiCtx) {
    var syncing by remember { mutableStateOf(false) }
    OutlinedButton(
        onClick = {
            syncing = true
            ctx.scope.launch {
                try {
                    ctx.repo.sync()
                    ctx.notify("Sync complete. Your vault is up to date.")
                } catch (e: Exception) {
                    ctx.notify("Sync failed: ${errorMessage(e)}")
                }
                syncing = false
            }
        },
        enabled = !syncing,
    ) {
        Icon(Icons.Outlined.Sync, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text(if (syncing) "Syncing…" else "Sync vault now")
    }
    Muted("Last sync: ${formatTime(ctx.state.lastSync)}")
    HorizontalDivider(color = PassAuthTheme.colors.line)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button) { ctx.go(Route.Settings("export")) }.padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Outlined.Download, null, tint = MaterialTheme.colorScheme.primary)
        Column(Modifier.weight(1f)) {
            Text("Export vault", style = MaterialTheme.typography.bodyLarge)
            Muted("Save a copy of your items to a file.")
        }
        Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
    }
    HorizontalDivider(color = PassAuthTheme.colors.line)
    Text("In the web vault", style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
    WebLink(ctx, "Vaults & sharing", "Create vaults and share them with others.", "/settings/vaults")
    WebLink(ctx, "Import items", "From another password manager or a PassAuth export.", "/import")
    WebLink(ctx, "Open web vault", "Everything else, in the browser.", "/vault")
}

@Composable
private fun ColumnScope.Appearance(ctx: UiCtx) {
    val s = ctx.state.settings
    SelectField(
        "Theme",
        listOf(ThemeMode.System to "Same as system", ThemeMode.Light to "Light", ThemeMode.Dark to "Dark"),
        s.theme,
        { v -> ctx.update { it.copy(theme = v) } },
    )
    ToggleRow(
        "Show website icons", s.showIcons, { v -> ctx.update { it.copy(showIcons = v) } },
        help = "Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents.",
    )
}

@Composable
private fun ColumnScope.About(ctx: UiCtx) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        LogoMark(64.dp)
        Text(
            androidx.compose.ui.text.buildAnnotatedString {
                append("Pass")
                withStyle(androidx.compose.ui.text.SpanStyle(color = Brand.Blue)) { append("Auth") }
            },
            fontSize = 24.sp, fontWeight = FontWeight.Bold,
        )
        Muted("Version ${BuildConfig.VERSION_NAME}")
        Muted("© Fahed Alhammadi")
    }
    KeyValue("Signed in as") { ValueText(ctx.state.email) }
    KeyValue("Server") { ValueText(ctx.state.server) }
    Muted("To use another PassAuth server, log out and choose \"Change server\" on the sign-in screen.")
    Button(
        onClick = { ctx.launch { ctx.repo.logout() } },
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError),
    ) { Text("Log out") }
    HorizontalDivider(color = PassAuthTheme.colors.line)
    Text("Delete account", style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
    Muted("Permanently delete ${ctx.state.email} from ${hostOf(ctx.state.server)}, with every vault you own and every item in them.")
    var deleting by remember { mutableStateOf(false) }
    OutlinedButton(
        onClick = { deleting = true },
        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.error),
    ) {
        Icon(Icons.Outlined.DeleteForever, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text("Delete account…")
    }
    if (deleting) DeleteAccountDialog(ctx) { deleting = false }
}

private fun hostOf(server: String) = io.passauth.app.data.UrlMatcher.parse(server)?.host ?: server

/** Google Play's in-app account deletion: warning, master password (server re-authentication), DELETE /api/account. */
@Composable
private fun DeleteAccountDialog(ctx: UiCtx, close: () -> Unit) {
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val needsSecretKey = ctx.state.secretKeyRequired && !ctx.state.secretKeyStored
    fun submit() {
        if (busy) return
        if (password.isEmpty()) return run { error = "Enter your master password." }
        busy = true
        error = null
        ctx.scope.launch {
            try {
                ctx.repo.deleteAccount(password, secretKey.ifBlank { null })
                close()
                ctx.notify("Your account has been deleted.")
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                error = errorMessage(e)
                busy = false
            }
        }
    }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = { if (!busy) close() },
        icon = { Icon(Icons.Outlined.Warning, null, tint = MaterialTheme.colorScheme.error) },
        title = { Text("Delete your account?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "This permanently deletes ${ctx.state.email} from your PassAuth server, with every vault you own and every item in them. " +
                        "People you shared those vaults with lose access too. Vaults others shared with you are not deleted.",
                )
                Alert("This can't be undone. Export your vault first if you want to keep a copy.", AlertKind.Error)
                io.passauth.app.ui.components.PasswordField(password, { password = it }, "Master password", onImeAction = ::submit)
                if (needsSecretKey) {
                    io.passauth.app.ui.components.TextInput(secretKey, { secretKey = it }, "Secret Key", mono = true)
                }
                io.passauth.app.ui.components.ErrorText(error)
            }
        },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy) {
                Text(if (busy) "Deleting…" else "Delete account", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = close, enabled = !busy) { Text("Cancel") } },
    )
}
