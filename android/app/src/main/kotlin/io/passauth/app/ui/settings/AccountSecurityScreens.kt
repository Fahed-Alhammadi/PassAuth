package io.passauth.app.ui.settings

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Password
import androidx.compose.material.icons.outlined.PhonelinkLock
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.contentType
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import io.passauth.app.data.EmergencyKit
import io.passauth.app.data.MasterPasswordRules
import io.passauth.app.data.QrEncoder
import io.passauth.app.data.SecretKeyChoice
import io.passauth.app.data.ShowOnce
import io.passauth.app.data.TwoFactor
import io.passauth.app.ui.Route
import io.passauth.app.ui.SecureWindow
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.auth.StrengthMeter
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.CheckRow
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.PasswordField
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.core.estimateBits
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The account's [SecurityViewModel] (one per account, kept by the activity). */
@Composable
internal fun securityViewModel(ctx: UiCtx): SecurityViewModel =
    viewModel(key = "security:${ctx.state.activeId}") { SecurityViewModel(ctx.repo) }

/**
 * Wiring shared by the security screens: snackbar notices, FLAG_SECURE, forgetting
 * secrets when the screen is really left (not when the activity is only recreated).
 */
@Composable
private fun SecurityScreenEffects(ctx: UiCtx, vm: SecurityViewModel) {
    SecureWindow()
    LaunchedEffect(vm) { vm.notices.collect { ctx.notify(it) } }
    DisposableEffect(vm) {
        onDispose { if (!ctx.activity.isChangingConfigurations) vm.clear() }
    }
    ShownOnceDialogs(ctx, vm)
}

/** Settings → Account security: the rows that open these screens. */
@Composable
internal fun AccountSecurityLinks(ctx: UiCtx) {
    Text("Account", style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
    NavRow(Icons.Outlined.Password, "Change master password", "Also turns the Secret Key on or off.") {
        ctx.go(Route.Settings("password"))
    }
    NavRow(Icons.Outlined.PhonelinkLock, "Two-step login", "Authenticator app, email codes and recovery codes.") {
        ctx.go(Route.Settings("two-step"))
    }
}

@Composable
private fun NavRow(icon: ImageVector, title: String, help: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onClick).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Muted(help)
        }
        Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
    }
}

@Composable
private fun SecurityPage(ctx: UiCtx, title: String, vm: SecurityViewModel, content: @Composable ColumnScope.() -> Unit) {
    // A running request returns something to show (new Secret Key, recovery codes): stay until it ends.
    BackHandler(enabled = vm.working) { ctx.notify("Wait until PassAuth finishes.") }
    Scaffold(topBar = { PageBar(title, onBack = { if (vm.working) ctx.notify("Wait until PassAuth finishes.") else ctx.go(Route.Settings("security")) }) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            content = content,
        )
    }
}

@Composable
private fun Card(title: String, on: Boolean? = null, content: @Composable ColumnScope.() -> Unit) {
    CardSection(null) {
        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f).semantics { heading() })
                if (on != null) OnBadge(on)
            }
            content()
        }
    }
}

@Composable
private fun OnBadge(on: Boolean) {
    Surface(
        shape = RoundedCornerShape(50),
        color = if (on) PassAuthTheme.colors.okSoft else MaterialTheme.colorScheme.surfaceVariant,
        contentColor = if (on) PassAuthTheme.colors.ok else PassAuthTheme.colors.muted,
    ) {
        Text(if (on) "On" else "Off", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp))
    }
}

// ------------------------------------------------------ master password

/** Settings → Account security → Change master password (and the Secret Key setting). */
@Composable
fun ChangePasswordScreen(ctx: UiCtx) {
    val vm = securityViewModel(ctx)
    SecurityScreenEffects(ctx, vm)
    val skOn = ctx.state.secretKeyRequired
    val needsSecretKey = skOn && !ctx.state.secretKeyStored
    val saveKit = rememberKitSaver(ctx)

    SecurityPage(ctx, "Master password", vm) {
        Card("Change master password") {
            Text(
                "Your master password encrypts your vault and is never sent to the server. If you forget it, nobody can recover your data.",
                style = MaterialTheme.typography.bodyMedium,
            )
            PasswordField(vm.current, { vm.current = it }, "Current master password", imeAction = ImeAction.Next)
            if (needsSecretKey) {
                TextInput(vm.secretKey, { vm.secretKey = it }, "Secret Key", mono = true)
                Muted("This phone doesn't have your Secret Key saved. Enter it from your Emergency Kit.")
            }
            PasswordField(vm.next, vm::updateNext, "New master password", imeAction = ImeAction.Next)
            StrengthMeter(vm.next, master = true)
            Muted("At least ${MasterPasswordRules.MIN_LENGTH} characters. A few unrelated words are easy to remember and hard to guess.")
            PasswordField(vm.confirm, { vm.confirm = it }, "Confirm new master password", onImeAction = { vm.changePassword(::estimateBits) })
            SecretKeyChoices(skOn, vm.choice) { vm.choice = it }
            ErrorText(vm.error)
            Muted("Changing your master password signs out all your other devices. This phone stays signed in.")
            Button(onClick = { vm.changePassword(::estimateBits) }, enabled = !vm.busy, modifier = Modifier.fillMaxWidth()) {
                if (vm.busy) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.size(8.dp))
                }
                Text(if (vm.busy) "Changing password…" else "Change master password")
            }
        }
        Card("Secret Key", on = skOn) {
            Text(
                "A Secret Key is a long random code that's combined with your master password when you sign in on a new device. " +
                    "Even if someone learns your master password, they can't open your vault without it.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Muted(
                when {
                    !skOn -> "When you turn it on, you'll get a Secret Key to save in an Emergency Kit."
                    ctx.state.secretKeyStored -> "This phone remembers your Secret Key. Keep your Emergency Kit somewhere safe: you need it to sign in on any other device."
                    else -> "This phone doesn't have your Secret Key saved. Use the Emergency Kit you saved when you turned it on."
                },
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { vm.openDialog(SecurityDialog.SecretKeyToggle) }, enabled = !vm.working) {
                    Icon(Icons.Outlined.Key, null, Modifier.size(18.dp))
                    Spacer(Modifier.size(8.dp))
                    Text(if (skOn) "Turn off Secret Key" else "Turn on Secret Key")
                }
                if (skOn && ctx.state.secretKeyStored) {
                    OutlinedButton(onClick = { ctx.launch { ctx.repo.storedSecretKey()?.let(saveKit) } }) {
                        Icon(Icons.Outlined.Download, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Save Emergency Kit")
                    }
                }
            }
        }
    }
    if (vm.dialog == SecurityDialog.SecretKeyToggle) {
        ConfirmPasswordDialog(
            ctx, vm,
            title = if (skOn) "Turn off Secret Key" else "Turn on Secret Key",
            action = if (skOn) "Turn off Secret Key" else "Turn on Secret Key",
            danger = skOn,
            text = (
                if (skOn) "After this, your master password alone unlocks your vault on a new device. Your current Secret Key and Emergency Kit stop working."
                else "PassAuth will create a Secret Key and show it once. You'll need it, together with your master password, to sign in on other devices."
                ) + " All your other devices will be signed out.",
        )
    }
}

@Composable
private fun SecretKeyChoices(on: Boolean, selected: SecretKeyChoice, onSelect: (SecretKeyChoice) -> Unit) {
    val options = if (on) {
        listOf(
            SecretKeyChoice.Keep to ("Keep my Secret Key" to "Your Secret Key and Emergency Kit keep working."),
            SecretKeyChoice.TurnOff to ("Turn off Secret Key" to "Your master password alone will open your vault on a new device."),
        )
    } else {
        listOf(
            SecretKeyChoice.Keep to ("No Secret Key" to "Your master password alone opens your vault on a new device."),
            SecretKeyChoice.TurnOn to ("Turn on Secret Key" to "PassAuth creates a Secret Key and shows it once, to save in an Emergency Kit."),
        )
    }
    Text("Secret Key", style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
    Column(Modifier.selectableGroup()) {
        options.forEach { (choice, text) ->
            Row(
                Modifier.fillMaxWidth().heightIn(min = 48.dp).selectable(selected = selected == choice, onClick = { onSelect(choice) }, role = Role.RadioButton)
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = selected == choice, onClick = null)
                Column(Modifier.weight(1f).padding(start = 12.dp)) {
                    Text(text.first, style = MaterialTheme.typography.bodyLarge)
                    Muted(text.second)
                }
            }
        }
    }
    if (on && selected == SecretKeyChoice.Keep) Muted("If this phone doesn't have your Secret Key saved, PassAuth creates a new one.")
}

/** Saves an Emergency Kit PDF where the user picks (Storage Access Framework). */
@Composable
private fun rememberKitSaver(ctx: UiCtx): (String) -> Unit {
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<String?>(null) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        val sk = pending
        pending = null
        if (uri == null || sk == null) return@rememberLauncherForActivityResult
        val server = ctx.state.server
        val email = ctx.state.email
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    ctx.activity.contentResolver.openOutputStream(uri, "wt")!!.use {
                        EmergencyKit.writePdf(it, server, email, sk, DateFormat.getDateInstance(DateFormat.LONG).format(Date()))
                    }
                }
            }.onSuccess { ctx.notify("Emergency Kit saved.") }.onFailure { ctx.notify("Couldn't save the Emergency Kit.") }
        }
    }
    return { sk ->
        pending = sk
        ctx.graph.lock.expectSystemScreen()
        launcher.launch(EmergencyKit.FILE_NAME)
    }
}

// ----------------------------------------------------------- shown once

/** The new Secret Key and new recovery codes: shown once, closed only after "I saved it". */
@Composable
private fun ShownOnceDialogs(ctx: UiCtx, vm: SecurityViewModel) {
    vm.newSecretKey?.let { once -> SecretKeyDialog(ctx, once, { vm.newSecretKey = it }) { vm.newSecretKey = null } }
    if (vm.newSecretKey == null) vm.recovery?.let { once -> RecoveryCodesDialog(ctx, once, { vm.recovery = it }) { vm.recovery = null } }
}

private val ONCE = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false)

@Composable
private fun SecretKeyDialog(ctx: UiCtx, once: ShowOnce<String>, update: (ShowOnce<String>) -> Unit, close: () -> Unit) {
    val saveKit = rememberKitSaver(ctx)
    AlertDialog(
        onDismissRequest = { if (once.mayClose()) close() },
        properties = ONCE,
        icon = { Icon(Icons.Outlined.Key, null) },
        title = { Text("Save your new Secret Key") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "This is the only time PassAuth shows your Secret Key. Any older Secret Key no longer works. " +
                        "Save it now: without it, you can't sign in on a new device. This phone remembers it.",
                )
                SecretBox(once.value, "Secret Key")
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { saveKit(once.value) }) {
                        Icon(Icons.Outlined.Download, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Save Emergency Kit")
                    }
                    OutlinedButton(onClick = { ctx.copy(once.value, "Secret Key") }) {
                        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Copy")
                    }
                }
                CheckRow("I saved my Secret Key", once.saved, { update(once.confirmSaved(it)) })
            }
        },
        confirmButton = { TextButton(onClick = { if (once.mayClose()) close() }, enabled = once.saved) { Text("Done") } },
    )
}

@Composable
private fun RecoveryCodesDialog(ctx: UiCtx, once: ShowOnce<List<String>>, update: (ShowOnce<List<String>>) -> Unit, close: () -> Unit) {
    val text = TwoFactor.recoveryText(ctx.state.server, once.value)
    val scope = rememberCoroutineScope()
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) { ctx.activity.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(text.toByteArray()) } }
            }.onSuccess { ctx.notify("Recovery codes saved.") }.onFailure { ctx.notify("Couldn't save the recovery codes.") }
        }
    }
    AlertDialog(
        onDismissRequest = { if (once.mayClose()) close() },
        properties = ONCE,
        title = { Text("Save your recovery codes") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "If you lose your phone or can't get email, a recovery code lets you sign in. Each code works once. " +
                        "This is the only time PassAuth shows them.",
                )
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    border = BorderStroke(1.dp, PassAuthTheme.colors.line),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    SelectionContainer {
                        Column(Modifier.padding(14.dp).semantics(mergeDescendants = true) { contentDescription = "Recovery codes: " + once.value.joinToString(", ") }) {
                            once.value.forEach { Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge) }
                        }
                    }
                }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { ctx.copy(once.value.joinToString("\n"), "Recovery codes") }) {
                        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Copy all")
                    }
                    OutlinedButton(onClick = {
                        ctx.graph.lock.expectSystemScreen()
                        val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                            .putExtra(Intent.EXTRA_SUBJECT, "PassAuth recovery codes")
                            .putExtra(Intent.EXTRA_TEXT, text)
                        runCatching { ctx.activity.startActivity(Intent.createChooser(send, "Share recovery codes")) }
                            .onFailure { ctx.notify("No app can share these codes. Copy them instead.") }
                    }) {
                        Icon(Icons.Outlined.Share, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Share")
                    }
                    OutlinedButton(onClick = {
                        ctx.graph.lock.expectSystemScreen()
                        save.launch("PassAuth recovery codes.txt")
                    }) {
                        Icon(Icons.Outlined.Download, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Save")
                    }
                }
                CheckRow("I saved my recovery codes", once.saved, { update(once.confirmSaved(it)) })
            }
        },
        confirmButton = { TextButton(onClick = { if (once.mayClose()) close() }, enabled = once.saved) { Text("Done") } },
    )
}

@Composable
private fun SecretBox(value: String, label: String) {
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        border = BorderStroke(1.dp, PassAuthTheme.colors.line),
        modifier = Modifier.fillMaxWidth(),
    ) {
        SelectionContainer {
            Text(
                value,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(14.dp).semantics { contentDescription = "$label: ${value.toCharArray().joinToString(" ")}" },
            )
        }
    }
}

// ------------------------------------------------------- two-step login

/** Settings → Account security → Two-step login. */
@Composable
fun TwoStepScreen(ctx: UiCtx) {
    val vm = securityViewModel(ctx)
    SecurityScreenEffects(ctx, vm)
    LaunchedEffect(vm) { vm.load() }
    val status = vm.status

    SecurityPage(ctx, "Two-step login", vm) {
        Text(
            "Two-step login asks for a code after your master password when you sign in on a new device, so a stolen password isn't enough.",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (status == null) {
            if (vm.loadError != null) {
                ErrorText(vm.loadError)
                OutlinedButton(onClick = vm::load, enabled = !vm.loading) { Text(if (vm.loading) "Loading…" else "Try again") }
            } else {
                Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(Modifier.semantics { contentDescription = "Loading two-step login" })
                }
            }
            return@SecurityPage
        }
        TotpCard(ctx, vm, status.totpOn)
        EmailCard(vm, status.emailOn, status.emailAvailable, status.email)
        Card("Recovery codes") {
            if (status.anyOn) {
                val n = status.recoveryCodesLeft
                Text(
                    "Use a recovery code to sign in if you lose access to your other methods. You have $n unused ${if (n == 1) "code" else "codes"} left.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (n <= 3) Alert("You're running low on recovery codes. Generate new ones and store them somewhere safe.")
                OutlinedButton(onClick = { vm.openDialog(SecurityDialog.Regenerate) }, enabled = !vm.working) { Text("Generate new recovery codes") }
            } else {
                Text("You'll get recovery codes when you turn on your first two-step method.", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }

    val lastOne = { p: String -> status?.isLast(p) == true }
    when (vm.dialog) {
        SecurityDialog.DisableTotp, SecurityDialog.DisableEmail -> {
            val totp = vm.dialog == SecurityDialog.DisableTotp
            ConfirmPasswordDialog(
                ctx, vm,
                title = if (totp) "Turn off authenticator app" else "Turn off email codes",
                action = "Turn off",
                danger = true,
                text = if (lastOne(if (totp) TwoFactor.TOTP else TwoFactor.EMAIL)) {
                    "This is your only two-step method. Turning it off also deletes your recovery codes, and signing in will need only your master password."
                } else {
                    "You can turn it on again at any time."
                },
            )
        }
        SecurityDialog.Regenerate -> ConfirmPasswordDialog(
            ctx, vm,
            title = "Generate new recovery codes",
            action = "Generate new codes",
            danger = true,
            text = "Your current recovery codes stop working as soon as the new ones are created.",
        )
        else -> {}
    }
}

@Composable
private fun TotpCard(ctx: UiCtx, vm: SecurityViewModel, on: Boolean) {
    Card("Authenticator app", on = on) {
        Text("Get a new 6-digit code every 30 seconds from an authenticator app.", style = MaterialTheme.typography.bodyMedium)
        val setup = vm.totp
        when {
            on -> DangerButton("Turn off authenticator app", enabled = !vm.working) { vm.openDialog(SecurityDialog.DisableTotp) }
            setup != null -> {
                Text("1. Scan the QR code with your authenticator app.", style = MaterialTheme.typography.bodyMedium)
                QrCode(setup.uri, Modifier.align(Alignment.CenterHorizontally))
                Muted("Can't scan it? Enter this setup key in the app instead:")
                SecretBox(setup.grouped, "Setup key")
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { ctx.copy(setup.secret, "Setup key") }) {
                        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Copy setup key")
                    }
                    OutlinedButton(onClick = { openAuthenticator(ctx, setup.uri) }) {
                        Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Open in authenticator app")
                    }
                }
                Text("2. Enter the code the app shows.", style = MaterialTheme.typography.bodyMedium)
                CodeField(vm.totpCode, { vm.totpCode = it; vm.totpError = null }, onDone = vm::enableTotp)
                ErrorText(vm.totpError)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = vm::enableTotp, enabled = !vm.totpBusy) { Text(if (vm.totpBusy) "Checking code…" else "Turn on authenticator app") }
                    TextButton(onClick = vm::cancelTotp, enabled = !vm.totpBusy) { Text("Cancel") }
                }
            }
            else -> {
                ErrorText(vm.totpError)
                Button(onClick = vm::startTotp, enabled = !vm.totpBusy && !vm.working) { Text(if (vm.totpBusy) "Starting setup…" else "Set up authenticator app") }
            }
        }
    }
}

private fun openAuthenticator(ctx: UiCtx, uri: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addCategory(Intent.CATEGORY_BROWSABLE)
    try {
        ctx.graph.lock.expectSystemScreen()
        ctx.activity.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        ctx.notify("No authenticator app on this phone opens setup links. Scan the QR code or enter the setup key instead.")
    }
}

@Composable
private fun EmailCard(vm: SecurityViewModel, on: Boolean, available: Boolean, email: String) {
    Card("Email codes", on = on) {
        Text("Get a one-time code by email at $email when you sign in.", style = MaterialTheme.typography.bodyMedium)
        when {
            on -> DangerButton("Turn off email codes", enabled = !vm.working) { vm.openDialog(SecurityDialog.DisableEmail) }
            !available -> {
                Muted("This server isn't set up to send email, so email codes aren't available. Ask your PassAuth administrator to configure email.")
                OutlinedButton(onClick = {}, enabled = false) { Text("Send setup code") }
            }
            vm.emailSent -> {
                Text("We sent a code to $email. Enter it below.", style = MaterialTheme.typography.bodyMedium)
                CodeField(vm.emailCode, { vm.emailCode = it; vm.emailError = null }, onDone = vm::enableEmail)
                ErrorText(vm.emailError)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = vm::enableEmail, enabled = !vm.emailBusy) { Text(if (vm.emailBusy) "Checking code…" else "Turn on email codes") }
                    TextButton(onClick = vm::sendEmailCode, enabled = !vm.emailBusy) { Text("Send a new code") }
                    TextButton(onClick = vm::cancelEmail, enabled = !vm.emailBusy) { Text("Cancel") }
                }
            }
            else -> {
                ErrorText(vm.emailError)
                Button(onClick = vm::sendEmailCode, enabled = !vm.emailBusy && !vm.working) { Text(if (vm.emailBusy) "Sending…" else "Send setup code") }
            }
        }
    }
}

@Composable
private fun DangerButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
        border = BorderStroke(1.dp, if (enabled) MaterialTheme.colorScheme.error else PassAuthTheme.colors.line),
    ) { Text(text) }
}

/** A verification code: number keyboard, offered to the keyboard's one-time-code suggestions. */
@Composable
private fun CodeField(value: String, onChange: (String) -> Unit, onDone: () -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = { v -> onChange(v.filter { it.isDigit() || it == ' ' }.take(12)) },
        label = { Text("Verification code") },
        singleLine = true,
        textStyle = MaterialTheme.typography.titleLarge.copy(fontFamily = FontFamily.Monospace),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, autoCorrectEnabled = false, imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { onDone() }),
        modifier = Modifier.fillMaxWidth().semantics { contentType = ContentType.SmsOtpCode },
    )
}

/** The setup QR code, drawn module by module (always dark on white, also in dark mode, so every scanner reads it). */
@Composable
private fun QrCode(text: String, modifier: Modifier = Modifier) {
    val matrix = remember(text) { QrEncoder.encode(text) }
    Canvas(
        modifier.size(220.dp).background(Color.White, RoundedCornerShape(8.dp))
            .semantics { contentDescription = "QR code to add PassAuth to your authenticator app" },
    ) {
        val cell = size.minDimension / matrix.size
        for (y in 0 until matrix.size) {
            for (x in 0 until matrix.size) {
                if (matrix[x, y]) drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
            }
        }
    }
}

// --------------------------------------------- password-confirmed actions

/** Confirms a sensitive action with the master password (server re-authentication), like the web vault's ConfirmPassword. */
@Composable
private fun ConfirmPasswordDialog(ctx: UiCtx, vm: SecurityViewModel, title: String, action: String, danger: Boolean, text: String) {
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    val needsSecretKey = ctx.state.secretKeyRequired && !ctx.state.secretKeyStored
    val submit = { vm.confirmDialog(password, secretKey.ifBlank { null }, ctx.state.secretKeyRequired) }
    AlertDialog(
        onDismissRequest = vm::closeDialog,
        icon = if (danger) ({ Icon(Icons.Outlined.Warning, null, tint = MaterialTheme.colorScheme.error) }) else null,
        title = { Text(title) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(text)
                PasswordField(password, { password = it; vm.dialogError = null }, "Master password", onImeAction = submit)
                if (needsSecretKey) TextInput(secretKey, { secretKey = it }, "Secret Key", mono = true)
                ErrorText(vm.dialogError)
            }
        },
        confirmButton = {
            TextButton(onClick = submit, enabled = !vm.dialogBusy) {
                Text(if (vm.dialogBusy) "Checking…" else action, color = if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            }
        },
        dismissButton = { TextButton(onClick = vm::closeDialog, enabled = !vm.dialogBusy) { Text("Cancel") } },
    )
}
