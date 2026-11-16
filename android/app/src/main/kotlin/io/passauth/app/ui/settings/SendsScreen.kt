package io.passauth.app.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.passauth.app.data.Change
import io.passauth.app.data.NewSend
import io.passauth.app.data.OwnedSend
import io.passauth.app.data.SendEdit
import io.passauth.app.data.SendState
import io.passauth.app.data.Sends
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.CheckRow
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.PasswordField
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.SelectField
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.vault.formatDate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun nowSeconds() = System.currentTimeMillis() / 1000

/** Shown right after a Send was made: its link (the key part hidden until Show). */
private data class Created(val link: String, val name: String, val send: OwnedSend)

/**
 * Send (servers with `sends`; the web vault's Tools → Send): the account's Sends with their state,
 * new and edit, copy link, turn the link off and on, delete. Text is encrypted on this phone with a
 * key that is only in the link.
 */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun SendsScreen(ctx: UiCtx) {
    var features by remember { mutableStateOf<List<String>?>(null) }
    var limits by remember { mutableStateOf(Sends.Limits(Sends.DEFAULT_MAX_DAYS, Sends.DEFAULT_MAX_BYTES)) }
    var sends by remember { mutableStateOf<List<OwnedSend>?>(null) }
    var names by remember { mutableStateOf<Map<String, String?>>(emptyMap()) }
    var error by remember { mutableStateOf<String?>(null) }
    var editing by remember { mutableStateOf<OwnedSend?>(null) }
    var creating by remember { mutableStateOf(false) }
    var created by remember { mutableStateOf<Created?>(null) }
    var deleting by remember { mutableStateOf<OwnedSend?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    val enabled = features?.contains(Sends.FEATURE) == true

    LaunchedEffect(reload) {
        try {
            if (features == null) {
                features = ctx.repo.features()
                limits = Sends.limits(ctx.repo.serverLimits())
            }
            val list = ctx.repo.sends().list()
            // Names are decrypted once per Send (their key is unwrapped with the account key).
            names = withContext(Dispatchers.Default) { list.associate { it.id to ctx.repo.sends().nameOf(it) } }
            sends = list
            error = null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error = "Couldn't load your Sends. ${errorMessage(e)}"
        }
    }

    // Views counted while the app was away (someone opened a link) show when it comes back.
    androidx.lifecycle.compose.LifecycleResumeEffect(Unit) {
        if (sends != null) reload++
        onPauseOrDispose {}
    }

    if (creating || editing != null) {
        SendEditor(ctx, editing, limits, onClose = { creating = false; editing = null }) { result ->
            creating = false
            editing = null
            if (result != null) created = result else ctx.notify("Send saved.")
            reload++
        }
        return
    }

    Scaffold(
        topBar = {
            PageBar("Send", onBack = { ctx.go(Route.Settings()) }) {
                if (enabled) IconButton(onClick = { creating = true }) { Icon(Icons.Outlined.Add, "New Send") }
            }
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Share a password or a note through a link that works for anyone, even without PassAuth. The text is encrypted on this phone " +
                    "and the key is only in the link, so your server can't read it.",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (features != null && !enabled) {
                Alert("Send is turned off on this server, so links you made don't open now. Ask the server's admin if you need it.")
            }
            ErrorText(error)
            val list = sends
            when {
                list == null && error == null -> Muted("Loading…")
                list != null && list.isEmpty() -> CardSection(null) {
                    Column(Modifier.padding(vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("No Sends yet", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                        Muted("Each Send is deleted on the date you choose, and can stop working sooner: after a number of views, or at an expiry date.")
                    }
                }
                list != null -> list.forEach { s ->
                    SendCard(
                        ctx, s, names[s.id], enabled,
                        onEdit = { editing = s },
                        onToggle = {
                            ctx.launch {
                                withContext(Dispatchers.Default) { ctx.repo.sends().update(s, SendEdit(disabled = !s.disabled)) }
                                ctx.notify(if (s.disabled) "Link turned on." else "Link turned off.")
                                reload++
                            }
                        },
                        onDelete = { deleting = s },
                    )
                }
            }
            if (enabled) {
                Button(onClick = { creating = true }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    Icon(Icons.Outlined.Add, null)
                    Text("New Send", Modifier.padding(start = Space.s))
                }
            }
        }
    }

    created?.let { c -> CreatedSheet(ctx, c) { created = null } }
    deleting?.let { s ->
        var busy by remember { mutableStateOf(false) }
        var sheetError by remember { mutableStateOf<String?>(null) }
        DecisionSheet(
            onDismiss = { deleting = null },
            title = "Delete this Send?",
            subtitle = names[s.id] ?: "Send",
            tile = { Tile(icon = Icons.AutoMirrored.Outlined.Send, danger = true) },
            error = sheetError,
            dismissable = !busy,
            actions = {
                PrimaryButton(if (busy) "Deleting…" else "Delete Send", {
                    busy = true
                    ctx.scope.launch {
                        try {
                            ctx.repo.sends().delete(s.id)
                            deleting = null
                            ctx.notify("Send deleted.")
                            reload++
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            sheetError = errorMessage(e)
                        } finally {
                            busy = false
                        }
                    }
                }, busy = busy, danger = true)
                QuietActions { QuietButton("Cancel", { deleting = null }, enabled = !busy) }
            },
        ) { PromptText("Its link stops working at once, for everyone who has it.") }
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun SendCard(ctx: UiCtx, s: OwnedSend, name: String?, enabled: Boolean, onEdit: () -> Unit, onToggle: () -> Unit, onDelete: () -> Unit) {
    val now = nowSeconds()
    val state = Sends.state(s, now)
    val facts = listOfNotNull(
        Sends.viewsText(s.views, s.maxViews),
        s.expiresAt?.let { if (it > now) "Link expires ${formatDate(it)}" else "Link expired ${formatDate(it)}" },
        "Kept until ${formatDate(s.deleteAt)}",
        "Password".takeIf { s.hasPassword },
        "Your email hidden".takeIf { s.hideEmail },
    )
    val readable = name != null
    CardSection(null) {
        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Space.m),
                modifier = Modifier.semantics(mergeDescendants = true) {},
            ) {
                Tile(icon = Icons.AutoMirrored.Outlined.Send, onCard = true)
                Column(Modifier.weight(1f)) {
                    Text(name ?: "Send that can't be opened", style = MaterialTheme.typography.titleMedium)
                    facts.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted) }
                }
                StateBadge(state)
            }
            if (!readable) Muted("This Send was made with keys your account no longer has. Delete it and make a new one.")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                if (readable) {
                    OutlinedButton(onClick = {
                        ctx.launch {
                            val key = withContext(Dispatchers.Default) { ctx.repo.sends().keyOf(s) }
                            ctx.copy(ctx.repo.sendLink(s.id, key), "Link")
                        }
                    }) {
                        Icon(Icons.Outlined.ContentCopy, null)
                        Text("Copy link", Modifier.padding(start = Space.s))
                    }
                }
                if (readable && enabled) {
                    OutlinedButton(onClick = onEdit) {
                        Icon(Icons.Outlined.Edit, null)
                        Text("Edit", Modifier.padding(start = Space.s))
                    }
                }
                if (enabled) TextButton(onClick = onToggle, modifier = Modifier.heightIn(min = 48.dp)) { Text(if (s.disabled) "Turn on link" else "Turn off link") }
                TextButton(
                    onClick = onDelete,
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text("Delete…") }
            }
        }
    }
}

@Composable
private fun StateBadge(state: SendState) {
    val ok = state == SendState.Available
    Surface(
        shape = RoundedCornerShape(50),
        color = if (ok) PassAuthTheme.colors.okSoft else MaterialTheme.colorScheme.surfaceVariant,
        contentColor = if (ok) PassAuthTheme.colors.ok else MaterialTheme.colorScheme.onSurfaceVariant,
    ) {
        Text(state.label, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp))
    }
}

/** The deletion or expiry picked: a duration from now (seconds), the current date, a date picked, or never. */
private sealed interface When {
    data object Keep : When
    data object Never : When
    data object Custom : When
    data class In(val seconds: Long) : When
}

private enum class PasswordMode { Keep, Set, Remove }

/** New Send, or changes to one (its text is fetched and decrypted when the editor opens). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SendEditor(ctx: UiCtx, send: OwnedSend?, limits: Sends.Limits, onClose: () -> Unit, onSaved: (Created?) -> Unit) {
    val isNew = send == null
    val durations = remember(limits.maxDays) { Sends.durationChoices(limits.maxDays) }
    var loaded by remember { mutableStateOf<Pair<String, String>?>(if (isNew) "" to "" else null) }
    var name by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var passwordMode by remember { mutableStateOf(if (send?.hasPassword == true) PasswordMode.Keep else PasswordMode.Set) }
    var password by remember { mutableStateOf("") }
    var views by remember { mutableStateOf(send?.maxViews?.toString().orEmpty()) }
    var deletion by remember { mutableStateOf<When>(if (isNew) When.In(Sends.defaultDeletion(limits.maxDays)) else When.Keep) }
    var deletionAt by remember { mutableStateOf(send?.deleteAt ?: (nowSeconds() + Sends.defaultDeletion(limits.maxDays))) }
    var expiry by remember { mutableStateOf<When>(if (send?.expiresAt != null) When.Keep else When.Never) }
    var expiryAt by remember { mutableStateOf(send?.expiresAt ?: (nowSeconds() + 86400)) }
    var hideEmail by remember { mutableStateOf(send?.hideEmail ?: false) }
    var disabled by remember { mutableStateOf(send?.disabled ?: false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var picking by remember { mutableStateOf<String?>(null) }
    val close = { if (!busy) onClose() }
    BackHandler(onBack = close)

    LaunchedEffect(send?.id) {
        val s = send ?: return@LaunchedEffect
        try {
            val full = ctx.repo.sends().get(s.id)
            val values = withContext(Dispatchers.Default) { (ctx.repo.sends().nameOf(full) ?: "") to ctx.repo.sends().textOf(full) }
            loaded = values
            name = values.first
            text = values.second
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error = "Couldn't open this Send. ${errorMessage(e)}"
        }
    }

    val maxText = Sends.maxTextBytes(limits.maxBytes)
    val textBytes = Sends.utf8Length(text)

    fun pick(choice: When, custom: Long, current: Long?, now: Long): Long? = when (choice) {
        When.Never -> null
        When.Keep -> current
        When.Custom -> custom
        is When.In -> now + choice.seconds
    }

    fun submit() {
        val base = loaded ?: return
        error = null
        val now = nowSeconds()
        if (name.isBlank()) return run { error = "Give this Send a name. People who open it see it too." }
        if (text.isEmpty()) return run { error = "Enter the text to send." }
        if (textBytes > maxText) return run { error = "This text is too long. A Send holds up to ${formatBytes(maxText.toLong())} of text." }
        var maxViews: Long? = null
        if (views.isNotBlank()) {
            maxViews = views.trim().toLongOrNull()
            if (maxViews == null || maxViews < 1 || maxViews > Sends.MAX_VIEWS) return run { error = "Enter how many times it can be opened: a whole number from 1 to 1,000,000." }
        }
        val deleteAt = pick(deletion, deletionAt, send?.deleteAt, now)
        if (deleteAt == null || deleteAt <= now) return run { error = "Pick a deletion date in the future." }
        if (deletion != When.Keep && deleteAt > now + limits.maxDays * 86400L) {
            return run { error = "Pick a deletion date within ${limits.maxDays} ${if (limits.maxDays == 1) "day" else "days"}: your server keeps Sends no longer." }
        }
        val expiresAt = pick(expiry, expiryAt, send?.expiresAt, now)
        if (expiresAt != null) {
            if (expiry != When.Keep && expiresAt <= now) return run { error = "Pick an expiry date in the future, or choose Never." }
            if (expiresAt >= deleteAt) return run { error = "The Send is deleted before it would expire. Pick an expiry date before the deletion date, or choose Never." }
        }
        if (send?.hasPassword == true && passwordMode == PasswordMode.Set && password.isEmpty()) return run { error = "Enter the new password, or keep the current one." }
        busy = true
        ctx.scope.launch {
            try {
                if (send == null) {
                    val n = name.trim()
                    val (made, key) = withContext(Dispatchers.Default) {
                        ctx.repo.sends().create(NewSend(n, text, password.ifEmpty { null }, maxViews, expiresAt, deleteAt, hideEmail))
                    }
                    onSaved(Created(ctx.repo.sendLink(made.id, key), n, made))
                } else {
                    val edit = SendEdit(
                        name = name.trim().takeIf { it != base.first },
                        text = text.takeIf { it != base.second },
                        password = when {
                            send.hasPassword && passwordMode == PasswordMode.Remove -> ""
                            passwordMode == PasswordMode.Set && password.isNotEmpty() -> password
                            else -> null
                        },
                        maxViews = Change(maxViews).takeIf { maxViews != send.maxViews },
                        expiresAt = Change(expiresAt).takeIf { expiresAt != send.expiresAt },
                        deleteAt = deleteAt.takeIf { it != send.deleteAt },
                        disabled = disabled.takeIf { it != send.disabled },
                        hideEmail = hideEmail.takeIf { it != send.hideEmail },
                    )
                    withContext(Dispatchers.Default) { ctx.repo.sends().update(send, edit) }
                    onSaved(null)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = errorMessage(e)
                busy = false
            }
        }
    }

    val durationOptions: List<Pair<When, String>> = durations.map { (seconds, label) -> When.In(seconds) to "In $label" }
    Scaffold(topBar = { PageBar(if (isNew) "New Send" else "Edit Send", onBack = close) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            if (loaded == null) {
                if (error == null) Muted("Opening…") else ErrorText(error)
                return@Column
            }
            TextInput(name.take(Sends.NAME_MAX), { name = it.take(Sends.NAME_MAX) }, "Name")
            Muted("Shown to the people who open it, after any password.")
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Text") },
                minLines = 4,
                modifier = Modifier.fillMaxWidth(),
                textStyle = MaterialTheme.typography.bodyLarge,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                supportingText = if (textBytes > maxText * 0.8) ({ Text("${formatBytes(textBytes.toLong())} of ${formatBytes(maxText.toLong())}") }) else null,
                isError = textBytes > maxText,
            )
            if (send?.hasPassword == true) {
                SelectField(
                    "Password",
                    listOf(PasswordMode.Keep to "Keep the current password", PasswordMode.Set to "Set a new password", PasswordMode.Remove to "Remove the password"),
                    passwordMode,
                    { passwordMode = it },
                )
            }
            if (send?.hasPassword != true || passwordMode == PasswordMode.Set) {
                PasswordField(password, { password = it }, if (send?.hasPassword == true) "New password" else "Password (optional)")
                Muted("People need it, as well as the link, to open the Send. Tell it to them another way than the link.")
            }
            SelectField(
                "Delete it",
                buildList {
                    if (!isNew) add(When.Keep to formatDate(send!!.deleteAt))
                    addAll(durationOptions)
                    add(When.Custom to if (deletion == When.Custom) "On ${formatDay(deletionAt)}" else "On a date…")
                },
                deletion,
                { deletion = it; if (it == When.Custom) picking = "deletion" },
            )
            SelectField(
                "Link expires",
                buildList {
                    add(When.Never to "Never (when it's deleted)")
                    send?.expiresAt?.let { add(When.Keep to formatDate(it)) }
                    addAll(durationOptions)
                    add(When.Custom to if (expiry == When.Custom) "On ${formatDay(expiryAt)}" else "On a date…")
                },
                expiry,
                { expiry = it; if (it == When.Custom) picking = "expiry" },
            )
            Muted(
                "Your server deletes Sends after ${limits.maxDays} ${if (limits.maxDays == 1) "day" else "days"} at most. " +
                    "An expired link stops working; the Send stays in this list until it's deleted.",
            )
            TextInput(views, { v -> views = v.filter(Char::isDigit).take(7) }, "Limit how many times it can be opened (optional)", keyboardType = KeyboardType.Number)
            if (send != null && send.views > 0) Muted("${Sends.viewsText(send.views, null)} so far.")
            CheckRow("Hide my email address from the people who open it", hideEmail, { hideEmail = it })
            if (!isNew) CheckRow("Turn off the link: nobody can open it until you turn it on again", disabled, { disabled = it })
            ErrorText(error)
            PrimaryButton(if (busy) "Saving…" else if (isNew) "Create Send" else "Save changes", ::submit, busy = busy)
            QuietActions { QuietButton("Cancel", close, enabled = !busy) }
        }
    }

    picking?.let { which ->
        val initial = (if (which == "deletion") deletionAt else expiryAt) * 1000
        val state = rememberDatePickerState(initialSelectedDateMillis = initial)
        DatePickerDialog(
            onDismissRequest = { picking = null },
            confirmButton = {
                TextButton(onClick = {
                    state.selectedDateMillis?.let { ms ->
                        // The picked day at the current time of day (the picker gives midnight UTC of that day).
                        val zone = java.time.ZoneId.systemDefault()
                        val day = java.time.Instant.ofEpochMilli(ms).atZone(java.time.ZoneOffset.UTC).toLocalDate()
                        val at = day.atTime(java.time.LocalTime.now(zone)).atZone(zone).toEpochSecond()
                        if (which == "deletion") deletionAt = at else expiryAt = at
                    }
                    picking = null
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { picking = null }) { Text("Cancel") } },
        ) { DatePicker(state) }
    }
}

private fun formatDay(seconds: Long): String =
    java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(seconds * 1000))

/** Sizes as the server counts them (1 KB = 1024 bytes): "1 byte", "800 bytes", "64 KB", "1.5 MB". */
fun formatBytes(bytes: Long): String {
    val n = maxOf(0L, bytes)
    if (n < 1024) return if (n == 1L) "1 byte" else "%,d bytes".format(n)
    var value = n / 1024.0
    var unit = 0
    val units = listOf("KB", "MB", "GB", "TB")
    while (value >= 1024 && unit < units.size - 1) {
        value /= 1024
        unit++
    }
    val shown = if (value >= 100) "%,d".format(Math.round(value)) else (Math.round(value * 10) / 10.0).let { if (it % 1.0 == 0.0) "%,d".format(it.toLong()) else "%,.1f".format(it) }
    return "$shown ${units[unit]}"
}

/**
 * Shown once after creating a Send: its link to copy. The key part (after #) is hidden until Show,
 * so someone looking along doesn't get it; Copy link always copies the whole link.
 */
@Composable
private fun CreatedSheet(ctx: UiCtx, c: Created, close: () -> Unit) {
    var shown by remember { mutableStateOf(false) }
    val s = c.send
    val until = formatDate(s.expiresAt ?: s.deleteAt)
    val limit = s.maxViews?.let { if (it == 1L) ", at most once" else ", at most $it times" }.orEmpty()
    DecisionSheet(
        onDismiss = close,
        title = "Send created",
        subtitle = c.name,
        tile = { Tile(icon = Icons.AutoMirrored.Outlined.Send) },
        actions = {
            PrimaryButton("Copy link", { ctx.copy(c.link, "Link") }, icon = Icons.Outlined.ContentCopy)
            QuietActions { QuietButton("Done", close) }
        },
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (shown) c.link else Sends.maskedLink(c.link),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f).semantics { if (!shown) contentDescription = "Link, key hidden" },
            )
            IconButton(onClick = { shown = !shown }) {
                Icon(if (shown) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, if (shown) "Hide link" else "Show link")
            }
        }
        PromptText(
            "Anyone with this link${if (s.hasPassword) " and the password" else ""} can open it until $until$limit. The part after # is the key, so it's hidden here; " +
                "Copy link copies the whole link. Share it only with the people it's for. You can copy it again from the list.",
        )
    }
}
