package io.passauth.app.ui.settings

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.automirrored.outlined.Chat
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.filled.ContactEmergency
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Inventory2
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.PanTool
import androidx.compose.material.icons.outlined.PersonAdd
import androidx.compose.material.icons.outlined.StarOutline
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import io.passauth.app.data.MAX_ACCOUNTS
import io.passauth.app.ui.components.Avatar
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.initials
import io.passauth.app.ui.theme.TileColors
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
import androidx.compose.material.icons.automirrored.outlined.Logout
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.ContactEmergency
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.GroupAdd
import androidx.compose.material.icons.outlined.HealthAndSafety
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.BuildConfig
import io.passauth.app.data.AccountUsage
import io.passauth.app.data.BACKGROUND_SYNC_DEFAULT
import io.passauth.app.data.QUOTA_EXCEEDED_MESSAGE
import io.passauth.app.data.BACKGROUND_SYNC_OPTIONS
import io.passauth.app.data.PolicyRules
import io.passauth.app.data.Settings
import io.passauth.app.data.ThemeMode
import io.passauth.app.data.TimeoutAction
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.VaultTimeout
import io.passauth.app.data.secondsLabel
import io.passauth.app.ui.auth.LogoutSheet
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.HEALTH
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.permissions.turnOnBiometricUnlock
import io.passauth.app.ui.biometricsAvailable
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
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.vault.HealthScreen
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

private data class Section(val key: String, val title: String, val icon: ImageVector, val tint: Color)

/** Pages opened from the settings list; account and about have their own layouts. */
private val SECTIONS = listOf(
    Section("account", "Account", Icons.Filled.Person, TileColors.Blue),
    Section("security", "Account security", Icons.Filled.Lock, TileColors.Blue),
    Section("autofill", "Autofill", Icons.Filled.Key, TileColors.Orange),
    Section("vault", "Vault options", Icons.Filled.Inventory2, TileColors.Purple),
    Section("appearance", "Appearance", Icons.Filled.Palette, TileColors.Pink),
    Section("about", "About PassAuth", Icons.Filled.Info, TileColors.Gray),
)

private fun section(key: String) = SECTIONS.first { it.key == key }

/**
 * Settings: the account card on top, then one group per job without header labels (like the iOS app): what you do
 * with the vault, how it's protected and filled, how the app looks, and About. Everything about
 * the account itself (switching, adding, locking, logging out, deleting) is on the Account page behind the card.
 */
@Composable
fun SettingsScreen(ctx: UiCtx, section: String?) {
    if (section == "export") return ExportScreen(ctx)
    if (section == "password") return ChangePasswordScreen(ctx)
    if (section == "two-step") return TwoStepScreen(ctx)
    if (section == "sessions") return SessionsScreen(ctx)
    if (section == HEALTH) return HealthScreen(ctx)
    if (section == "sends") return SendsScreen(ctx)
    if (section == "emergency") return EmergencyScreen(ctx)
    if (section == "sharing") return SharingScreen(ctx)
    val open = SECTIONS.firstOrNull { it.key == section }
    if (open == null) {
        Scaffold(topBar = { PageBar("Settings", brand = true) }) { padding ->
            Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(Space.xl)) {
                val vault by ctx.repo.vault.collectAsStateWithLifecycle()
                val waiting = vault?.invitations.orEmpty().size
                GroupCard {
                    AccountCard(ctx)
                    // Vaults shared with the account, waiting for an answer (servers with invitations).
                    if (waiting > 0) {
                        TileDivider()
                        TileRow("Vault invitations", Icons.Filled.GroupAdd, TileColors.Blue, { ctx.go(Route.Invitations()) }, "Vault invitations, $waiting waiting") {
                            CountBadge(waiting)
                        }
                    }
                }
                TileGroup {
                    TileRow("Password health", Icons.Filled.HealthAndSafety, TileColors.Green, { ctx.go(Route.Settings(HEALTH)) })
                    TileDivider()
                    TileRow("Send", Icons.AutoMirrored.Filled.Send, TileColors.Teal, { ctx.go(Route.Settings("sends")) })
                    TileDivider()
                    TileRow("Shared vaults and keys", Icons.Filled.Group, TileColors.Indigo, { ctx.go(Route.Settings("sharing")) })
                    TileDivider()
                    TileRow("Emergency access", Icons.Filled.ContactEmergency, TileColors.Red, { ctx.go(Route.Settings("emergency")) })
                    TileDivider()
                    PageRow(ctx, section("vault"))
                }
                TileGroup {
                    PageRow(ctx, section("security"))
                    TileDivider()
                    PageRow(ctx, section("autofill"))
                }
                TileGroup { PageRow(ctx, section("appearance")) }
                Column(verticalArrangement = Arrangement.spacedBy(Space.s)) {
                    TileGroup { PageRow(ctx, section("about")) }
                    Text(
                        "Version ${BuildConfig.VERSION_NAME}",
                        style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
                        textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth(),
                    )
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
            when (open.key) {
                "account" -> Account(ctx)
                "about" -> About(ctx)
                else -> CardSection(null) {
                    Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        when (open.key) {
                            "security" -> Security(ctx)
                            "autofill" -> Autofill(ctx)
                            "vault" -> VaultOptions(ctx)
                            else -> Appearance(ctx)
                        }
                    }
                }
            }
        }
    }
}

/** A grouped card holding tile rows (no inner padding: rows are full-width touch targets). */
@Composable
private fun TileGroup(content: @Composable ColumnScope.() -> Unit) = GroupCard { Column(content = content) }

/** The tile's side, growing a little with the font scale (like the iOS app). */
@Composable
private fun tileSide() = (29 * LocalDensity.current.fontScale.coerceIn(1f, 1.5f)).dp

/** Divider between tile rows, inset to the text column. */
@Composable
private fun TileDivider() = HorizontalDivider(Modifier.padding(start = Space.l + tileSide() + 14.dp), color = PassAuthTheme.colors.line)

/** A settings row: white symbol on a coloured rounded square, the title, an optional trailing part and a chevron. */
@Composable
private fun TileRow(
    title: String,
    icon: ImageVector,
    tint: Color,
    onClick: () -> Unit,
    description: String? = null,
    trailing: @Composable () -> Unit = {},
) {
    val side = tileSide()
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = Space.l, vertical = Space.m)
            .then(if (description != null) Modifier.semantics(mergeDescendants = true) { contentDescription = description } else Modifier),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(Modifier.size(side).clip(RoundedCornerShape(side * 0.24f)).background(tint), contentAlignment = Alignment.Center) {
            Icon(icon, null, tint = Color.White, modifier = Modifier.size(side * 0.6f))
        }
        Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        trailing()
        Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
    }
}

@Composable
private fun PageRow(ctx: UiCtx, s: Section) = TileRow(s.title, s.icon, s.tint, { ctx.go(Route.Settings(s.key)) })

/** The account card at the top of Settings: avatar, name, email and server; opens the Account page. */
@Composable
private fun AccountCard(ctx: UiCtx) {
    val s = ctx.state
    Row(
        Modifier.fillMaxWidth().clickable(role = Role.Button) { ctx.go(Route.Settings("account")) }
            .padding(horizontal = Space.l, vertical = Space.m)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Avatar(initials(s.name, s.email), 52.dp, image = s.avatar)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(s.name.ifEmpty { s.email }, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (s.name.isNotEmpty()) Text(s.email, style = MaterialTheme.typography.bodyMedium, color = PassAuthTheme.colors.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Icon(Icons.Outlined.Dns, null, tint = PassAuthTheme.colors.muted, modifier = Modifier.size(14.dp))
                Text(hostOf(s.server), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
    }
}

/**
 * Settings → Account: everything about the signed-in account in one place. Who and where, the accounts on this
 * device (switch, add), then Lock and Log out, then Delete account at the bottom.
 */
@Composable
private fun ColumnScope.Account(ctx: UiCtx) {
    val s = ctx.state
    Column(
        Modifier.fillMaxWidth().padding(vertical = Space.s).semantics(mergeDescendants = true) {},
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        AccountPhoto(ctx)
        Text(s.name.ifEmpty { s.email }, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        if (s.name.isNotEmpty()) Text(s.email, style = MaterialTheme.typography.bodyMedium, color = PassAuthTheme.colors.muted)
    }
    Column(verticalArrangement = Arrangement.spacedBy(Space.s)) {
        CardSection(null) { KeyValue("Server") { ValueText(s.server) } }
        Muted("To use another PassAuth server, add an account or log out and choose \"Change server\" on the sign-in screen.")
    }
    Column(verticalArrangement = Arrangement.spacedBy(Space.s)) {
        CardSection("Accounts on this device") {
            s.accounts.forEachIndexed { n, a ->
                if (n > 0) HorizontalDivider(Modifier.padding(start = 34.dp + Space.m), color = PassAuthTheme.colors.line)
                val current = a.id == s.activeId
                Row(
                    Modifier.fillMaxWidth().heightIn(min = 56.dp)
                        .clickable(role = Role.Button, enabled = !current) { ctx.launch { ctx.repo.switchAccount(a.id) } }
                        .padding(vertical = Space.s)
                        .semantics(mergeDescendants = true) { if (current) contentDescription = "${a.name.ifEmpty { a.email }}, current account" },
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(Space.m),
                ) {
                    Avatar(initials(a.name, a.email), 34.dp, image = a.avatar)
                    Column(Modifier.weight(1f)) {
                        Text(a.name.ifEmpty { a.email }, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(hostOf(a.server), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text(statusLabel(a.status), style = MaterialTheme.typography.labelMedium, color = PassAuthTheme.colors.muted)
                    if (current) Icon(Icons.Outlined.Check, null, tint = MaterialTheme.colorScheme.primary)
                }
            }
            if (s.accounts.size < MAX_ACCOUNTS) {
                HorizontalDivider(Modifier.padding(start = 34.dp + Space.m), color = PassAuthTheme.colors.line)
                ActionRow("Add account", Icons.Outlined.PersonAdd, MaterialTheme.colorScheme.primary) { ctx.launch { ctx.repo.addAccount() } }
            }
        }
        Muted("Up to $MAX_ACCOUNTS accounts, on the same or different PassAuth servers. Tap one to switch.")
    }
    var loggingOut by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(Space.s)) {
        CardSection(null) {
            ActionRow("Lock", Icons.Outlined.Lock, MaterialTheme.colorScheme.primary) { ctx.launch { ctx.repo.lock() } }
            HorizontalDivider(Modifier.padding(start = 34.dp + Space.m), color = PassAuthTheme.colors.line)
            ActionRow("Log out", Icons.AutoMirrored.Outlined.Logout, MaterialTheme.colorScheme.error) { loggingOut = true }
        }
        Muted("Locking keeps the encrypted vault on this device. Logging out removes it.")
    }
    if (loggingOut) LogoutSheet(ctx) { loggingOut = false }
    var deleting by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(Space.s)) {
        CardSection(null) {
            ActionRow("Delete account", Icons.Outlined.DeleteForever, MaterialTheme.colorScheme.error, chevron = true) { deleting = true }
        }
        Muted("Permanently deletes ${s.email} from ${hostOf(s.server)}, with every vault you own and every item in them.")
    }
    if (deleting) DeleteAccountDialog(ctx) { deleting = false }
}

/**
 * The Account page's big avatar. With a server that keeps profile pictures and the vault unlocked,
 * tapping it offers Choose photo… (system Photo Picker, images only) and Remove photo (when one is set).
 */
@Composable
private fun AccountPhoto(ctx: UiCtx) {
    val s = ctx.state
    val editable = s.avatarAvailable && s.status == io.passauth.app.data.Status.Unlocked
    if (!editable) {
        Avatar(initials(s.name, s.email), 72.dp, image = s.avatar)
        return
    }
    val context = androidx.compose.ui.platform.LocalContext.current
    var menu by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    val pick = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        ctx.launch {
            try {
                val jpeg = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { io.passauth.app.data.AvatarImage.prepare(context, uri) }
                ctx.repo.setAvatar(jpeg)
                ctx.notify("Profile photo updated")
            } finally {
                busy = false
            }
        }
    }
    Box {
        Box(
            Modifier.size(80.dp).clip(androidx.compose.foundation.shape.CircleShape)
                .clickable(enabled = !busy, role = Role.Button, onClickLabel = "Change profile photo") { menu = true }
                .clearAndSetSemantics { contentDescription = "Profile photo" },
            contentAlignment = Alignment.Center,
        ) {
            Avatar(initials(s.name, s.email), 72.dp, image = s.avatar)
        }
        // Camera badge: the avatar is the control.
        Box(
            Modifier.align(Alignment.BottomEnd).size(26.dp).clip(androidx.compose.foundation.shape.CircleShape)
                .background(MaterialTheme.colorScheme.background).padding(2.dp)
                .clip(androidx.compose.foundation.shape.CircleShape).background(MaterialTheme.colorScheme.primary),
            contentAlignment = Alignment.Center,
        ) {
            if (busy) {
                androidx.compose.material3.CircularProgressIndicator(Modifier.size(14.dp), color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
            } else {
                Icon(Icons.Filled.PhotoCamera, null, tint = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(14.dp))
            }
        }
        androidx.compose.material3.DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            androidx.compose.material3.DropdownMenuItem(
                text = { Text("Choose photo…") },
                leadingIcon = { Icon(Icons.Outlined.PhotoLibrary, null) },
                onClick = {
                    menu = false
                    pick.launch(androidx.activity.result.PickVisualMediaRequest(androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia.ImageOnly))
                },
            )
            if (s.avatar != null) {
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text("Remove photo", color = MaterialTheme.colorScheme.error) },
                    leadingIcon = { Icon(Icons.Outlined.Delete, null, tint = MaterialTheme.colorScheme.error) },
                    onClick = {
                        menu = false
                        busy = true
                        ctx.launch {
                            try {
                                ctx.repo.removeAvatar()
                                ctx.notify("Profile photo removed")
                            } finally {
                                busy = false
                            }
                        }
                    },
                )
            }
        }
    }
}

private fun statusLabel(s: io.passauth.app.data.Status) = when (s) {
    io.passauth.app.data.Status.Unlocked -> "Unlocked"
    io.passauth.app.data.Status.Locked -> "Locked"
    io.passauth.app.data.Status.LoggedOut -> "Logged out"
    io.passauth.app.data.Status.Setup -> ""
}

/** A tappable action in a card: icon and title in the action's colour. */
@Composable
private fun ActionRow(title: String, icon: ImageVector, color: Color, chevron: Boolean = false, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 52.dp).clickable(role = Role.Button, onClick = onClick).padding(vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.m),
    ) {
        Box(Modifier.size(34.dp), contentAlignment = Alignment.Center) { Icon(icon, null, tint = color) }
        Text(title, style = MaterialTheme.typography.bodyLarge, color = color, modifier = Modifier.weight(1f))
        if (chevron) Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
    }
}

private fun UiCtx.update(f: (Settings) -> Settings) = launch { repo.updateSettings(f) }

/** A small count in the accent colour (invitations waiting). */
@Composable
internal fun CountBadge(n: Int) {
    androidx.compose.material3.Surface(shape = androidx.compose.foundation.shape.RoundedCornerShape(50), color = MaterialTheme.colorScheme.primary, contentColor = MaterialTheme.colorScheme.onPrimary) {
        Text("$n", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp))
    }
}

@Composable
internal fun Muted(text: String) = Text(text, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)

@Composable
private fun ColumnScope.Security(ctx: UiCtx) {
    val s = ctx.state.settings
    // The servers' longest vault timeout: only the choices within it (a saved one above it was lowered).
    val limit = ctx.state.timeoutLimit
    SelectField(
        "Vault timeout",
        PolicyRules.timeoutOptions(limit).map { it to it.label },
        s.vaultTimeout,
        { v -> ctx.update { it.copy(vaultTimeout = v, vaultTimeoutLowered = false) } },
    )
    if (limit > 0) {
        Muted(PolicyRules.limitNote(limit))
        if (s.vaultTimeoutLowered) Alert(PolicyRules.loweredNote(s.vaultTimeout))
    }
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
            } else {
                ctx.turnOnBiometricUnlock()
            }
        },
        help = if (available) {
            "Unlock this account with your fingerprint or face. It turns off by itself if biometrics on this phone change."
        } else {
            "Set up a fingerprint or face unlock in Android settings to use this."
        },
    )
    io.passauth.app.push.PushSettingsRow(ctx)
    OutlinedButton(onClick = { ctx.launch { ctx.repo.lock() } }) {
        Icon(Icons.Outlined.Lock, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text("Lock now")
    }
    HorizontalDivider(color = PassAuthTheme.colors.line)
    AccountSecurityLinks(ctx)
    StorageUsage(ctx)
}

/** Items and storage against the server's limits (`GET /account`), shown only when the server's admin set a limit. */
@Composable
private fun ColumnScope.StorageUsage(ctx: UiCtx) {
    val account = ctx.state.activeId
    var usage by remember(account) { mutableStateOf<AccountUsage?>(null) }
    LaunchedEffect(account) { usage = runCatching { ctx.repo.accountUsage() }.getOrNull() }
    val u = usage?.takeIf { it.limited } ?: return
    HorizontalDivider(color = PassAuthTheme.colors.line)
    Text("Storage", style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
    u.itemsLine?.let { UsageRow("Items", it, u.itemsUsed ?: 0f) }
    u.storageLine?.let { UsageRow("Storage used", it, u.storageUsed ?: 0f) }
    if (u.full) Alert(QUOTA_EXCEEDED_MESSAGE, AlertKind.Error)
    Muted("Limits set by your server's admin. Items in the vaults you own count, including the trash.")
}

@Composable
private fun UsageRow(title: String, value: String, used: Float) {
    Column(Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(value, style = MaterialTheme.typography.bodyMedium, color = PassAuthTheme.colors.muted)
        }
        LinearProgressIndicator(
            progress = { used },
            modifier = Modifier.fillMaxWidth(),
            color = if (used >= 1f) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
        )
    }
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
    ChromeAutofillHint(ctx, resumes)
    HorizontalDivider(color = PassAuthTheme.colors.line)
    SelectField("Default URI match detection", MATCHES, s.defaultMatch, { v -> ctx.update { it.copy(defaultMatch = v) } })
    Muted("${matchHelp(s.defaultMatch)} Applies to websites set to \"Default\" in an item. Apps match logins with the website androidapp://<package name>, and logins of websites that list the app in their Digital Asset Links.")
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
    SelectField(
        "Background sync",
        BACKGROUND_SYNC_OPTIONS,
        BACKGROUND_SYNC_OPTIONS.firstOrNull { it.first == ctx.state.settings.backgroundSyncMinutes }?.first ?: BACKGROUND_SYNC_DEFAULT,
        { v -> ctx.update { it.copy(backgroundSyncMinutes = v) } },
    )
    Muted("Keeps your offline copy up to date while the app is closed.")
    HorizontalDivider(color = PassAuthTheme.colors.line)
    if (PolicyRules.exportAllowed(ctx.state.policies)) {
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
    } else {
        Muted(PolicyRules.EXPORT_OFF_NOTE)
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
        help = "Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents." +
            // On, but the server's icon service is off: say why there are only letters.
            if (s.showIcons && !ctx.state.showSiteIcons) " Your server doesn't offer website icons right now." else "",
    )
}

private object AboutLinks {
    const val WEBSITE = "https://fahed-alhammadi.github.io/PassAuth/"
    const val HELP = "https://fahed-alhammadi.github.io/PassAuth/support.html"
    const val FEEDBACK = "https://github.com/Fahed-Alhammadi/PassAuth/issues"
    const val PRIVACY = "https://fahed-alhammadi.github.io/PassAuth/privacy.html"
    const val RATE = "https://play.google.com/store/apps/details?id=io.passauth.app"
}

/**
 * Settings → About PassAuth (the same layout as the iOS app): one bold element, the brand panel with the app icon,
 * name, copyright line and version; below it what you do (help, feedback, rating), then what you read (website,
 * privacy policy).
 */
@Composable
private fun ColumnScope.About(ctx: UiCtx) {
    BrandPanel()
    CardSection(null) {
        LinkRow("Help", null, Icons.AutoMirrored.Outlined.HelpOutline) { ctx.openUrl(AboutLinks.HELP) }
        LinkDivider()
        LinkRow("Send feedback", null, Icons.AutoMirrored.Outlined.Chat) { ctx.openUrl(AboutLinks.FEEDBACK) }
        LinkDivider()
        LinkRow("Rate PassAuth", null, Icons.Outlined.StarOutline) { ctx.openUrl(AboutLinks.RATE) }
    }
    CardSection(null) {
        LinkRow("Website", "fahed-alhammadi.github.io/PassAuth", Icons.Outlined.Language) { ctx.openUrl(AboutLinks.WEBSITE) }
        LinkDivider()
        LinkRow("Privacy policy", null, Icons.Outlined.PanTool) { ctx.openUrl(AboutLinks.PRIVACY) }
    }
    Text(
        "Open source under the MIT License.",
        style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
        textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(top = Space.s),
    )
}

/** Navy into the brand blue (the shield's own gradient), a large faint shield behind, the app icon, name, © and version. */
@Composable
private fun BrandPanel() {
    val shape = RoundedCornerShape(20.dp)
    Box(
        Modifier.fillMaxWidth().clip(shape)
            .background(Brush.linearGradient(listOf(Brand.Navy, Color(0xFF0A3FA8))))
            .semantics(mergeDescendants = true) {},
    ) {
        LogoMark(260.dp, Modifier.align(Alignment.BottomEnd).offset(x = 70.dp, y = 50.dp).alpha(0.04f))
        Column(
            Modifier.fillMaxWidth().padding(horizontal = Space.xl).padding(top = 36.dp, bottom = 30.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                Modifier.size(88.dp).shadow(14.dp, RoundedCornerShape(20.dp))
                    .clip(RoundedCornerShape(20.dp))
                    .background(Brush.verticalGradient(listOf(Color.White, Color(0xFFDCE7FD)))),
                contentAlignment = Alignment.Center,
            ) { LogoMark(56.dp) }
            Text("PassAuth", color = Color.White, style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 18.dp))
            Text(
                "© 2026 Fahed Alhammadi. All rights reserved.",
                color = Color.White.copy(alpha = 0.8f), style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center, modifier = Modifier.padding(top = 4.dp),
            )
            Text(
                "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
                color = Brand.Cyan, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(top = 16.dp).clip(RoundedCornerShape(50)).background(Color.White.copy(alpha = 0.1f))
                    .padding(horizontal = 12.dp, vertical = 5.dp),
            )
        }
    }
}

@Composable
private fun LinkDivider() = HorizontalDivider(Modifier.padding(start = 24.dp + 14.dp), color = PassAuthTheme.colors.line)

/** A link row: icon in the accent colour, the name, an optional address under it, and the "opens outside the app" arrow. */
@Composable
private fun LinkRow(title: String, detail: String?, icon: ImageVector, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 52.dp).clickable(role = Role.Button, onClickLabel = "Open in the browser", onClick = onClick)
            .padding(vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (detail != null) Text(detail, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
        }
        Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, tint = PassAuthTheme.colors.muted, modifier = Modifier.size(18.dp))
    }
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
    DecisionSheet(
        onDismiss = close,
        title = "Delete your account?",
        subtitle = "${ctx.state.email} · ${hostOf(ctx.state.server)}",
        tile = { Tile(icon = Icons.Outlined.Warning, danger = true) },
        error = error,
        dismissable = !busy,
        actions = {
            PrimaryButton(if (busy) "Deleting…" else "Delete account", ::submit, enabled = password.isNotEmpty(), busy = busy, danger = true)
            QuietActions { QuietButton("Cancel", close, enabled = !busy) }
        },
    ) {
        PromptText(
            "This permanently deletes your account from your PassAuth server, with every vault you own and every item in them. " +
                "People you shared those vaults with lose access too. Vaults others shared with you are not deleted.",
        )
        Alert("This can't be undone. Export your vault first if you want to keep a copy.", AlertKind.Error)
        io.passauth.app.data.OfflineChanges.lostWarning(ctx.state.pendingChanges)?.let { io.passauth.app.ui.components.WarningNote(it) }
        // Verification sits right above the actions.
        Column(verticalArrangement = Arrangement.spacedBy(Space.m)) {
            io.passauth.app.ui.components.PasswordField(password, { password = it; error = null }, "Master password", onImeAction = ::submit)
            if (needsSecretKey) {
                io.passauth.app.ui.components.TextInput(secretKey, { secretKey = it }, "Secret Key", mono = true)
            }
        }
    }
}
