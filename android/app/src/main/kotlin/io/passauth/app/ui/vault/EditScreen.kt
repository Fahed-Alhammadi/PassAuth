package io.passauth.app.ui.vault

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Card
import io.passauth.app.data.Field
import io.passauth.app.data.FieldType
import io.passauth.app.data.Identity
import io.passauth.app.data.Item
import io.passauth.app.data.ItemCodec
import io.passauth.app.data.ItemKind
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.OtpAuth
import io.passauth.app.data.OtpParse
import io.passauth.app.data.SshKey
import io.passauth.app.data.UrlMatch
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.auth.StrengthMeter
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.PasswordField
import io.passauth.app.ui.components.SelectField
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.components.ToggleRow
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.core.generatePassword
import kotlinx.coroutines.launch

val MATCH_OPTIONS = listOf(
    UrlMatch.Default to "Default (app setting)",
    UrlMatch.Domain to "Base domain",
    UrlMatch.Host to "Host",
    UrlMatch.StartsWith to "Starts with",
    UrlMatch.Regex to "Regular expression",
    UrlMatch.Exact to "Exact",
    UrlMatch.Never to "Never",
)

/** New item or edit an existing one (the web vault's item editor). */
@Composable
fun EditScreen(ctx: UiCtx, id: String? = null, kind: ItemKind? = null) {
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    val v = vault ?: return
    // The item as it was when editing started: if live sync brings a newer version meanwhile,
    // saving reports the conflict (revision check) instead of silently overwriting it.
    val current = id?.let { v.get(it) }
    val entry = remember(id, current == null) { current }
    val done = { to: String? -> ctx.go(if (to != null) Route.ItemView(to) else Route.Vault) }
    if (id != null && (current == null || entry == null)) return run { done(null) }

    // Saved as JSON so edits survive rotation.
    var json by rememberSaveable { mutableStateOf(ItemCodec.encode(entry?.item ?: Item.empty(kind ?: ItemKind.Login))) }
    val item = remember(json) { ItemCodec.decode(json) }
    fun set(next: Item) { json = ItemCodec.encode(next) }
    fun login(f: (Login) -> Login) = set(item.copy(login = f(item.login!!)))
    fun card(f: (Card) -> Card) = set(item.copy(card = f(item.card!!)))
    fun identity(f: (Identity) -> Identity) = set(item.copy(identity = f(item.identity!!)))
    fun ssh(f: (SshKey) -> SshKey) = set(item.copy(sshKey = f(item.sshKey!!)))

    val writable = v.writable
    var vaultId by rememberSaveable { mutableStateOf(entry?.vaultId ?: writable.firstOrNull()?.id.orEmpty()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val label = item.kind.label.lowercase()

    fun save() {
        if (busy) return
        error = null
        if (item.name.isBlank()) return run { error = "Give this item a name." }
        if (vaultId.isEmpty()) return run { error = "You don't have a vault you can write to." }
        val clean = item.copy(
            name = item.name.trim(),
            folder = item.folder?.trim()?.ifEmpty { null },
            login = item.login?.let { l -> l.copy(urls = l.urls.filter { it.url.isNotBlank() }.map { it.copy(url = it.url.trim()) }, totp = l.totp?.trim()?.ifEmpty { null }?.let(::normalizeTotp)) },
        )
        busy = true
        ctx.scope.launch {
            try {
                if (entry != null) {
                    ctx.repo.updateItem(entry, clean)
                    ctx.notify("Changes saved.")
                    done(entry.id)
                } else {
                    val newId = ctx.repo.createItem(clean, vaultId)
                    ctx.notify("Item saved.")
                    done(newId)
                }
            } catch (e: Exception) {
                error = errorMessage(e)
                busy = false
            }
        }
    }

    Scaffold(
        topBar = {
            PageBar(if (entry != null) "Edit $label" else "New $label", onBack = { done(entry?.id) }) {
                TextButton(onClick = ::save, enabled = !busy) { Text("Save", color = PassAuthTheme.colors.onHeader) }
            }
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Group(null) {
                TextInput(item.name, { set(item.copy(name = it)) }, "Name")
            }

            item.login?.let { l ->
                Group("Login credentials") {
                    TextInput(l.username, { u -> login { it.copy(username = u) } }, "Username", keyboardType = KeyboardType.Email)
                    PasswordField(
                        l.password, { p -> login { it.copy(password = p) } }, "Password", mono = true,
                        onGenerate = {
                            ctx.launch {
                                val p = generatePassword(null)
                                login { it.copy(password = p) }
                            }
                        },
                    )
                    StrengthMeter(l.password)
                    TotpInput(ctx, l.totp.orEmpty()) { t -> login { it.copy(totp = t.ifEmpty { null }) } }
                }
                Group("Autofill options") {
                    l.urls.forEachIndexed { n, u ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            TextInput(
                                u.url, { url -> login { it.copy(urls = it.urls.mapIndexed { j, x -> if (j == n) x.copy(url = url) else x }) } },
                                if (n == 0) "Website" else "Website ${n + 1}", placeholder = "https://example.com",
                                keyboardType = KeyboardType.Uri, modifier = Modifier.weight(1f),
                            )
                            IconButton(onClick = { login { it.copy(urls = it.urls.filterIndexed { j, _ -> j != n }) } }) {
                                Icon(Icons.Outlined.Delete, "Remove website")
                            }
                        }
                        SelectField("Match detection", MATCH_OPTIONS, u.match, { m ->
                            login { it.copy(urls = it.urls.mapIndexed { j, x -> if (j == n) x.copy(match = m) else x }) }
                        })
                    }
                    TextButton(onClick = { login { it.copy(urls = it.urls + LoginUrl()) } }) {
                        Icon(Icons.Outlined.Add, null)
                        Spacer(Modifier.size(6.dp))
                        Text("Add website")
                    }
                    if (l.passkeys.isNotEmpty()) {
                        Text(
                            "${l.passkeys.size} passkey${if (l.passkeys.size > 1) "s" else ""} saved. Passkeys are kept when you save.",
                            style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
                        )
                    }
                }
            }

            item.card?.let { c ->
                Group("Card details") {
                    TextInput(c.cardholderName, { s -> card { it.copy(cardholderName = s) } }, "Cardholder name")
                    TextInput(c.number, { s -> card { it.copy(number = s.filter { ch -> ch.isDigit() || ch == ' ' }) } }, "Card number", mono = true, keyboardType = KeyboardType.Number)
                    TextInput(c.brand, { s -> card { it.copy(brand = s) } }, "Brand")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextInput(c.expMonth, { s -> card { it.copy(expMonth = s) } }, "Expiry month", keyboardType = KeyboardType.Number, modifier = Modifier.weight(1f))
                        TextInput(c.expYear, { s -> card { it.copy(expYear = s) } }, "Expiry year", keyboardType = KeyboardType.Number, modifier = Modifier.weight(1f))
                    }
                    PasswordField(c.code, { s -> card { it.copy(code = s) } }, "Security code", mono = true)
                }
            }

            item.identity?.let { idn ->
                Group("Personal details") {
                    TextInput(idn.title, { s -> identity { it.copy(title = s) } }, "Title")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextInput(idn.firstName, { s -> identity { it.copy(firstName = s) } }, "First name", modifier = Modifier.weight(1f))
                        TextInput(idn.lastName, { s -> identity { it.copy(lastName = s) } }, "Last name", modifier = Modifier.weight(1f))
                    }
                    TextInput(idn.middleName, { s -> identity { it.copy(middleName = s) } }, "Middle name")
                    TextInput(idn.username, { s -> identity { it.copy(username = s) } }, "Username")
                    TextInput(idn.email, { s -> identity { it.copy(email = s) } }, "Email", keyboardType = KeyboardType.Email)
                    TextInput(idn.phone, { s -> identity { it.copy(phone = s) } }, "Phone", keyboardType = KeyboardType.Phone)
                    TextInput(idn.company, { s -> identity { it.copy(company = s) } }, "Company")
                    TextInput(idn.address1, { s -> identity { it.copy(address1 = s) } }, "Address")
                    TextInput(idn.address2, { s -> identity { it.copy(address2 = s) } }, "Address line 2")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextInput(idn.city, { s -> identity { it.copy(city = s) } }, "City", modifier = Modifier.weight(1f))
                        TextInput(idn.state, { s -> identity { it.copy(state = s) } }, "State", modifier = Modifier.weight(1f))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextInput(idn.postalCode, { s -> identity { it.copy(postalCode = s) } }, "Postal code", modifier = Modifier.weight(1f))
                        TextInput(idn.country, { s -> identity { it.copy(country = s) } }, "Country", modifier = Modifier.weight(1f))
                    }
                    PasswordField(idn.ssn, { s -> identity { it.copy(ssn = s) } }, "National ID number")
                    TextInput(idn.passportNumber, { s -> identity { it.copy(passportNumber = s) } }, "Passport number")
                    TextInput(idn.licenseNumber, { s -> identity { it.copy(licenseNumber = s) } }, "Licence number")
                }
            }

            item.sshKey?.let { k ->
                Group("SSH key") {
                    TextInput(k.privateKey, { s -> ssh { it.copy(privateKey = s) } }, "Private key", mono = true, singleLine = false, minLines = 3)
                    TextInput(k.publicKey, { s -> ssh { it.copy(publicKey = s) } }, "Public key", mono = true, singleLine = false, minLines = 2)
                    TextInput(k.fingerprint, { s -> ssh { it.copy(fingerprint = s) } }, "Fingerprint", mono = true)
                }
            }

            Group("Custom fields") {
                item.fields.forEachIndexed { n, f ->
                    fun setField(g: (Field) -> Field) = set(item.copy(fields = item.fields.mapIndexed { j, x -> if (j == n) g(x) else x }))
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextInput(f.name, { s -> setField { it.copy(name = s) } }, "Field name", modifier = Modifier.weight(1f))
                        SelectField(
                            "Type", listOf(FieldType.Text to "Text", FieldType.Hidden to "Hidden", FieldType.Boolean to "Yes/No"),
                            f.type, { t -> setField { it.copy(type = t, value = if (t == FieldType.Boolean) "false" else it.value) } },
                            Modifier.width(130.dp),
                        )
                        IconButton(onClick = { set(item.copy(fields = item.fields.filterIndexed { j, _ -> j != n })) }) {
                            Icon(Icons.Outlined.Delete, "Remove field")
                        }
                    }
                    when (f.type) {
                        FieldType.Boolean -> ToggleRow(f.name.ifEmpty { "Value" }, f.value == "true", { b -> setField { it.copy(value = b.toString()) } })
                        FieldType.Hidden -> PasswordField(f.value, { s -> setField { it.copy(value = s) } }, "Field value")
                        FieldType.Text -> TextInput(f.value, { s -> setField { it.copy(value = s) } }, "Field value")
                    }
                }
                TextButton(onClick = { set(item.copy(fields = item.fields + Field())) }) {
                    Icon(Icons.Outlined.Add, null)
                    Spacer(Modifier.size(6.dp))
                    Text("Add field")
                }
            }

            Group("Other") {
                TextInput(item.notes, { set(item.copy(notes = it)) }, "Notes", singleLine = false, minLines = 3)
                TextInput(item.folder.orEmpty(), { set(item.copy(folder = it.ifEmpty { null })) }, "Folder")
                val suggestions = v.folders.filter { it != item.folder && (item.folder.isNullOrEmpty() || it.contains(item.folder, ignoreCase = true)) }
                if (suggestions.isNotEmpty()) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.horizontalScrollRow()) {
                        suggestions.take(8).forEach { f -> AssistChip(onClick = { set(item.copy(folder = f)) }, label = { Text(f) }) }
                    }
                }
                if (entry == null && writable.size > 1) {
                    SelectField("Vault", writable.map { it.id to it.name }, vaultId, { vaultId = it })
                }
                ToggleRow("Favorite", item.favorite, { set(item.copy(favorite = it)) })
            }

            ErrorText(error)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = ::save, enabled = !busy) { Text(if (busy) "Saving…" else if (entry == null) "Save item" else "Save changes") }
                OutlinedButton(onClick = { done(entry?.id) }) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun Modifier.horizontalScrollRow(): Modifier = this.then(Modifier.horizontalScroll(rememberScrollState()))

@Composable
private fun Group(title: String?, content: @Composable ColumnScope.() -> Unit) {
    CardSection(title) {
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
    }
}

/** A valid plain key is stored cleaned up (upper case, no spaces); URIs and anything else stay as typed. */
private fun normalizeTotp(value: String): String = (OtpAuth.parse(value) as? OtpParse.Valid)?.key?.value ?: value
