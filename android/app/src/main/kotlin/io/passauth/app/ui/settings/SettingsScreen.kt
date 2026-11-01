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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.Upload
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
    val open = SECTIONS.firstOrNull { it.key == section }
    if (open == null) {
        Scaffold(topBar = { PageBar("Settings", brand = true) { AccountMenu(ctx) } }) { padding ->
            Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
                CardSection(null) {
                    SECTIONS.forEachIndexed { n, s ->
                        if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                        Row(
                            Modifier.fillMaxWidth().clickable { ctx.go(Route.Settings(s.key)) }.padding(vertical = 14.dp),
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
private fun Muted(text: String) = Text(text, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)

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
}

@Composable
private fun ColumnScope.Autofill(ctx: UiCtx) {
    val s = ctx.state.settings
    Alert("Filling logins and passkeys in other apps and in your browser is coming in the next update. These settings already apply to it.")
    SelectField("Default URI match detection", MATCHES, s.defaultMatch, { v -> ctx.update { it.copy(defaultMatch = v) } })
    Muted("${matchHelp(s.defaultMatch)} Applies to websites set to \"Default\" in an item.")
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
    OutlinedButton(onClick = { ctx.openUrl("${ctx.state.server}/import") }) {
        Icon(Icons.Outlined.Upload, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text("Import items")
    }
    OutlinedButton(onClick = { ctx.openUrl(ctx.state.server) }) {
        Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text("Open web vault")
    }
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
}
