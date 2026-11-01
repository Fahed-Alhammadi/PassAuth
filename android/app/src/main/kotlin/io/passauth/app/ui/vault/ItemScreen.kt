package io.passauth.app.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.FieldType
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.KeyValue
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.SiteIcon
import io.passauth.app.ui.components.TotpRing
import io.passauth.app.ui.components.ValueText
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.core.estimateBits
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.delay

data class TotpCodeView(val code: String, val remaining: Int, val period: Int)

fun formatDate(unixSeconds: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(unixSeconds * 1000))

@Composable
fun ItemScreen(ctx: UiCtx, id: String) {
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    val v = vault
    val entry = v?.get(id)
    val back = { ctx.go(Route.Vault) }
    LaunchedEffect(v, entry) { if (v != null && entry == null) back() }
    if (v == null || entry == null) return
    val i = entry.item
    val l = i.login
    val canWrite = v.canWrite(entry)
    var confirmDelete by remember { mutableStateOf(false) }
    val weak = remember(l?.password) { l?.password?.let { it.isNotEmpty() && estimateBits(it) < 50 } ?: false }

    var code by remember { mutableStateOf<TotpCodeView?>(null) }
    LaunchedEffect(l?.totp) {
        val secret = l?.totp?.takeIf { it.isNotBlank() } ?: return@LaunchedEffect run { code = null }
        while (true) {
            code = runCatching { currentTotp(secret).let { TotpCodeView(it.code, it.remaining.toInt(), it.period.toInt()) } }.getOrNull()
            delay(1000 - System.currentTimeMillis() % 1000)
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Move to trash?") },
            text = { Text("Move this item to the trash?") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    ctx.launch {
                        ctx.repo.trashItem(entry)
                        ctx.notify("Moved to trash. You can restore it from the web vault.")
                        back()
                    }
                }) { Text("Move to trash", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }

    Scaffold(
        topBar = {
            PageBar("View ${i.kind.label.lowercase()}", onBack = back) {
                if (canWrite) {
                    IconButton(onClick = { ctx.launch { ctx.repo.setFavorite(entry, !i.favorite) } }) {
                        Icon(if (i.favorite) Icons.Filled.Star else Icons.Outlined.StarBorder, if (i.favorite) "Remove from favorites" else "Add to favorites")
                    }
                }
            }
        },
        bottomBar = {
            if (canWrite) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, tonalElevation = 2.dp) {
                    Row(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Button(onClick = { ctx.go(Route.Edit(id)) }) { Text("Edit") }
                        Spacer(Modifier.weight(1f))
                        IconButton(onClick = { confirmDelete = true }) {
                            Icon(Icons.Outlined.Delete, "Move to trash", tint = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CardSection(null) {
                Row(Modifier.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    SiteIcon(i.siteHost, i.name, ctx.state.server, ctx.state.settings.showIcons, ctx.graph.icons, 44.dp)
                    Text(i.name.ifEmpty { "Untitled" }, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                    if (i.favorite) Icon(Icons.Filled.Star, "Favorite", tint = MaterialTheme.colorScheme.primary)
                }
                Row(Modifier.padding(bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Meta(Icons.Outlined.Folder, i.folder?.takeIf { it.isNotEmpty() } ?: "No folder")
                    Meta(Icons.Outlined.Lock, v.vaultName(entry.vaultId))
                }
            }

            val c = code
            if (l != null && (l.username.isNotEmpty() || l.password.isNotEmpty() || l.passkeys.isNotEmpty() || c != null)) {
                CardSection("Login credentials") {
                    if (l.username.isNotEmpty()) {
                        KeyValue("Username", actions = { CopyButton(ctx, l.username, "Username") }) { ValueText(l.username) }
                    }
                    if (l.password.isNotEmpty()) {
                        Secret(ctx, "Password", l.password)
                        if (weak) {
                            Row(Modifier.padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.Shield, null, Modifier.size(16.dp), tint = PassAuthTheme.colors.warn)
                                Spacer(Modifier.size(6.dp))
                                Text("This password is easy to guess.", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.warn)
                                if (canWrite) TextButton(onClick = { ctx.go(Route.Edit(id)) }) { Text("Change it") }
                            }
                        }
                    }
                    l.passkeys.forEach { p ->
                        KeyValue("Passkey") {
                            ValueText(p.userName.ifEmpty { p.rpId })
                            Text("${p.rpId} · Created ${formatDate(p.createdAt)}", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
                        }
                    }
                    if (c != null) {
                        KeyValue("Verification code", actions = {
                            TotpRing(c.remaining, c.period)
                            CopyButton(ctx, c.code, "Verification code")
                        }) {
                            Text(
                                if (c.code.length == 6) "${c.code.take(3)} ${c.code.drop(3)}" else c.code,
                                fontFamily = FontFamily.Monospace, fontSize = 24.sp, fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                }
            }

            i.card?.let { card ->
                CardSection("Card details") {
                    if (card.cardholderName.isNotEmpty()) KeyValue("Cardholder name", actions = { CopyButton(ctx, card.cardholderName, "Cardholder name") }) { ValueText(card.cardholderName) }
                    if (card.brand.isNotEmpty()) KeyValue("Brand") { ValueText(card.brand) }
                    if (card.number.isNotEmpty()) Secret(ctx, "Number", card.number)
                    if (card.expMonth.isNotEmpty() || card.expYear.isNotEmpty()) KeyValue("Expires") { ValueText("${card.expMonth}/${card.expYear}") }
                    if (card.code.isNotEmpty()) Secret(ctx, "Security code", card.code)
                }
            }

            i.identity?.let { idn ->
                val rows = listOf(
                    "Name" to listOf(idn.title, idn.firstName, idn.middleName, idn.lastName).filter { it.isNotEmpty() }.joinToString(" "),
                    "Username" to idn.username,
                    "Email" to idn.email,
                    "Phone" to idn.phone,
                    "Company" to idn.company,
                    "Address" to listOf(idn.address1, idn.address2, idn.city, idn.state, idn.postalCode, idn.country).filter { it.isNotEmpty() }.joinToString(", "),
                    "Passport number" to idn.passportNumber,
                    "Licence number" to idn.licenseNumber,
                ).filter { it.second.isNotEmpty() }
                if (rows.isNotEmpty() || idn.ssn.isNotEmpty()) {
                    CardSection("Personal details") {
                        rows.forEach { (k, value) -> KeyValue(k, actions = { CopyButton(ctx, value, k) }) { ValueText(value) } }
                        if (idn.ssn.isNotEmpty()) Secret(ctx, "National ID number", idn.ssn)
                    }
                }
            }

            i.sshKey?.let { k ->
                CardSection("SSH key") {
                    if (k.publicKey.isNotEmpty()) KeyValue("Public key", actions = { CopyButton(ctx, k.publicKey, "Public key") }) { ValueText(k.publicKey, mono = true, maxLines = 2) }
                    if (k.fingerprint.isNotEmpty()) KeyValue("Fingerprint", actions = { CopyButton(ctx, k.fingerprint, "Fingerprint") }) { ValueText(k.fingerprint, mono = true) }
                    if (k.privateKey.isNotEmpty()) Secret(ctx, "Private key", k.privateKey, maxLines = 3)
                }
            }

            val urls = l?.urls.orEmpty().filter { it.url.isNotEmpty() }
            if (urls.isNotEmpty()) {
                CardSection("Autofill options") {
                    urls.forEachIndexed { n, u ->
                        KeyValue(if (urls.size > 1) "Website ${n + 1}" else "Website", actions = {
                            if (u.match != UrlMatch.Regex && UrlMatcher.parse(u.url)?.scheme?.startsWith("http") == true && u.url.contains("://")) {
                                IconButton(onClick = { ctx.openUrl(u.url) }) { Icon(Icons.AutoMirrored.Outlined.OpenInNew, "Open website") }
                            }
                            CopyButton(ctx, u.url, "Website")
                        }) { ValueText(u.url, maxLines = 1) }
                    }
                }
            }

            if (i.fields.isNotEmpty()) {
                CardSection("Custom fields") {
                    i.fields.forEach { f ->
                        when (f.type) {
                            FieldType.Hidden -> Secret(ctx, f.name.ifEmpty { "Hidden field" }, f.value)
                            FieldType.Boolean -> KeyValue(f.name.ifEmpty { "Field" }) { ValueText(if (f.value == "true") "Yes" else "No") }
                            FieldType.Text -> KeyValue(f.name.ifEmpty { "Field" }, actions = {
                                if (f.value.isNotEmpty()) CopyButton(ctx, f.value, f.name.ifEmpty { "Field" })
                            }) { ValueText(f.value) }
                        }
                    }
                }
            }

            if (i.notes.isNotEmpty()) {
                CardSection("Notes") {
                    Text(i.notes, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(vertical = 8.dp))
                }
            }

            CardSection("Item history") {
                Column(Modifier.padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    val muted = PassAuthTheme.colors.muted
                    if (i.updatedAt > 0) Text("Last edited ${formatDate(i.updatedAt)}", style = MaterialTheme.typography.bodySmall, color = muted)
                    if (i.createdAt > 0) Text("Created ${formatDate(i.createdAt)}", style = MaterialTheme.typography.bodySmall, color = muted)
                    i.passwordHistory.firstOrNull()?.let {
                        Text("Password changed ${formatDate(it.changedAt)}", style = MaterialTheme.typography.bodySmall, color = muted)
                    }
                }
            }
        }
    }
}

@Composable
private fun Meta(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, Modifier.size(15.dp), tint = PassAuthTheme.colors.muted)
        Spacer(Modifier.size(4.dp))
        Text(text, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
    }
}

@Composable
fun CopyButton(ctx: UiCtx, text: String, label: String) {
    IconButton(onClick = { ctx.copy(text, label) }) { Icon(Icons.Outlined.ContentCopy, "Copy ${label.lowercase()}") }
}

@Composable
private fun Secret(ctx: UiCtx, label: String, value: String, maxLines: Int = 1) {
    var show by rememberSaveable(label) { mutableStateOf(false) }
    KeyValue(label, actions = {
        IconButton(onClick = { show = !show }) {
            Icon(if (show) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, if (show) "Hide ${label.lowercase()}" else "Show ${label.lowercase()}")
        }
        CopyButton(ctx, value, label)
    }) {
        ValueText(if (show) value else "••••••••", mono = true, maxLines = if (show) Int.MAX_VALUE else maxLines)
    }
}
