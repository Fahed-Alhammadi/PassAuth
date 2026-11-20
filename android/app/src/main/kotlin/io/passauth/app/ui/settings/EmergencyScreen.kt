package io.passauth.app.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContactEmergency
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Emergency
import io.passauth.app.data.EmergencyClient
import io.passauth.app.data.Grant
import io.passauth.app.data.GrantLists
import io.passauth.app.data.GrantStatus
import io.passauth.app.data.GranteeAction
import io.passauth.app.data.GrantorAction
import io.passauth.app.data.Role
import io.passauth.app.data.RosterChangedError
import io.passauth.app.data.RosterState
import io.passauth.app.data.RotationReport
import io.passauth.app.data.ServerRoster
import io.passauth.app.data.Tone
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.PasswordField
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.components.WarningNote
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.vault.formatDate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** What a sheet of the Emergency page is about. */
private sealed interface Asking {
    data object Add : Asking
    data class Confirm(val g: Grant) : Asking
    data class Again(val g: Grant) : Asking
    data class Approve(val g: Grant) : Asking
    data class End(val g: Grant) : Asking
    data class Remove(val g: Grant) : Asking
    data class Wait(val g: Grant) : Asking
    data class Request(val g: Grant) : Asking
    data class Leave(val g: Grant, val decline: Boolean) : Asking
    data object UseServerList : Asking
    data object StartNewList : Asking
    data object ReplaceKeys : Asking

    /** Vaults whose members the user checks before their keys are replaced (first signed list, or people no longer listed). */
    data class Review(val reviews: List<io.passauth.app.data.MemberReview>) : Asking
}

/** The contact's key fingerprint (the core's format), or null when it can't be shown. */
private fun fingerprintOf(publicKey: String): String? =
    if (publicKey.isEmpty()) null else runCatching { io.passauth.core.fingerprint(publicKey) }.getOrNull()

private val whenText = { s: Long -> formatDate(s) }

/**
 * Emergency access (servers with `emergency_access`; the web vault's Settings → Emergency access),
 * both roles: as grantor, name trusted contacts, confirm them after checking their fingerprint,
 * change the waiting period (shorter needs the master password), approve (master password) or
 * reject requests, end access, remove (the personal vaults' keys are replaced at once); the roster
 * notices ("Use the server's list", "Start a new list") and "Confirm again". As contact: accept or
 * decline, ask for access, see the waiting time, view the grantor's personal vaults read-only.
 */
@Composable
fun EmergencyScreen(ctx: UiCtx) {
    var viewing by remember { mutableStateOf<Grant?>(null) }
    viewing?.let { g -> return EmergencyVaultScreen(ctx, g) { viewing = null } }

    val client = ctx.repo.emergency
    var features by remember { mutableStateOf<List<String>?>(null) }
    var lists by remember { mutableStateOf<GrantLists?>(null) }
    var roster by remember { mutableStateOf<RosterState?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    var asking by remember { mutableStateOf<Asking?>(null) }
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()

    LaunchedEffect(reload) {
        try {
            val f = ctx.repo.features()
            features = f
            if (f != null && Emergency.FEATURE !in f) return@LaunchedEffect
            lists = client.listGrants()
            roster = runCatching { client.rosterState() }.getOrNull()
            error = null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error = "Couldn't load your emergency contacts. ${errorMessage(e)}"
        }
    }
    val enabled = features?.contains(Emergency.FEATURE) == true
    val outdated = enabled && features?.contains(Emergency.KEYS_FEATURE) != true
    val done: (String) -> Unit = { text ->
        asking = null
        ctx.notify(text)
        reload++
    }
    // Vaults whose key the server asks to replace (a contact or member who held it left, or a removal
    // didn't finish) that this account manages. With signed sharing a vault shared with others gets
    // its new key here too (sealed and signed for each member); without it, those are only listed:
    // their keys are replaced in the web vault or the desktop app.
    val sharing by ctx.repo.sharing.collectAsStateWithLifecycle()
    val signs = sharing.enabled && ctx.repo.canReplaceSharedKeys()
    val waiting = vault?.vaults.orEmpty().filter { it.rotationPending && (it.personal || signs) && (it.role == Role.Owner || it.role == Role.Admin) }
    var split by remember { mutableStateOf<Pair<List<String>, List<String>>?>(null) }
    LaunchedEffect(waiting.map { it.id }, signs) {
        split = if (waiting.isEmpty() || signs) null else try {
            ctx.repo.splitShared(waiting.map { it.id })
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            null
        }
    }
    val sharedIds = split?.second.orEmpty().toSet()
    val pending = waiting.filter { it.id !in sharedIds }
    val pendingShared = waiting.filter { it.id in sharedIds }

    Scaffold(topBar = { PageBar("Emergency access", onBack = { ctx.go(Route.Settings()) }) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Name someone you trust who can ask to view your personal vaults if you can't, say after an accident. You're told at once and have the " +
                    "waiting period to say no. After that they can view your personal vaults, not the ones you share and not your Sends, and can't change anything.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Muted(
                "The waiting period is a rule of your server, not of the encryption. Once someone has had access, they keep what they saw. If you stop " +
                    "trusting them, remove them: PassAuth then changes the keys of your personal vaults, so they can't read anything you add afterwards, " +
                    "unless your server is later compromised. Change the passwords that matter too.",
            )
            when {
                outdated -> Alert(EmergencyClient.SERVER_TOO_OLD)
                features != null && !enabled -> Alert(
                    "Emergency access is turned off on this server: nobody can be named, accept or ask for access while it's off. Ask the server's admin if you need it.",
                )
            }
            ErrorText(error)
            roster?.problem?.let { problem ->
                CardSection(null) {
                    Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        WarningNote(if (problem == "older") EmergencyClient.ROSTER_ROLLED_BACK else EmergencyClient.ROSTER_UNREADABLE)
                        OutlinedButton(onClick = { asking = if (problem == "older") Asking.UseServerList else Asking.StartNewList }) {
                            Text(if (problem == "older") "Use the server's list…" else "Start a new list…")
                        }
                    }
                }
            }
            if (pending.isNotEmpty()) {
                CardSection(null) {
                    Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        WarningNote(
                            if (pending.size == 1) "${pending[0].name} needs a new key: someone who could open it doesn't have access any more."
                            else "${pending.size} of your vaults need a new key: someone who could open them doesn't have access any more.",
                        )
                        OutlinedButton(onClick = { asking = Asking.ReplaceKeys }) { Text("Replace keys…") }
                    }
                }
            }
            if (pendingShared.isNotEmpty()) {
                CardSection(null) {
                    Column(Modifier.padding(vertical = 10.dp)) {
                        WarningNote(
                            (if (pendingShared.size == 1) "${pendingShared[0].name} needs a new key: someone who could open it doesn't have access any more. "
                            else "${pendingShared.size} of your shared vaults need a new key: someone who could open them doesn't have access any more. ") +
                                RotationReport.sharedText(pendingShared.map { it.name }),
                        )
                    }
                }
            }

            SectionTitle("Your trusted contacts")
            val l = lists
            if (l == null && error == null && (features == null || enabled)) Muted("Loading…")
            if (l != null && l.asGrantor.isEmpty()) Muted("You haven't named anyone yet.")
            l?.asGrantor?.forEach { g ->
                ContactCard(
                    g,
                    enabled = enabled && !outdated,
                    unlisted = roster?.confirmAgain?.contains(g.id) == true,
                    removed = roster?.removed?.contains(g.id) == true,
                    onAsk = { asking = it },
                    onReject = {
                        ctx.launch {
                            client.rejectGrant(g.id)
                            done("Request rejected.")
                        }
                    },
                )
            }
            if (enabled) {
                Button(onClick = { asking = Asking.Add }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("Add a trusted contact") }
            }

            SectionTitle("People who trust you")
            if (l != null && l.asGrantee.isEmpty()) Muted("Nobody has named you as their emergency contact.")
            l?.asGrantee?.forEach { g ->
                TrustingCard(
                    g,
                    enabled = enabled,
                    onAccept = {
                        ctx.launch {
                            client.acceptGrant(g.id)
                            done("Accepted. ${Emergency.personName(g.grantor)} confirms you next.")
                        }
                    },
                    onAsk = { asking = it },
                    onView = { viewing = g },
                )
            }
            val own = remember(ctx.state.activeId) { ctx.repo.ownFingerprint() }
            if (own != null) {
                CardSection("Your key fingerprint") {
                    Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        SelectionContainer { Text(own, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge) }
                        Muted("Someone who names you as their emergency contact checks this with you before confirming you.")
                    }
                }
            }
        }
    }

    when (val a = asking) {
        null -> Unit
        Asking.Add -> AddContactSheet(ctx, close = { asking = null }) { name -> done("$name was asked to be your emergency contact.") }
        is Asking.Confirm -> ConfirmContactSheet(ctx, a.g, again = false, close = { asking = null }) { done("${Emergency.personName(a.g.grantee)} is your emergency contact now.") }
        is Asking.Again -> ConfirmContactSheet(ctx, a.g, again = true, close = { asking = null }) { done("${Emergency.personName(a.g.grantee)} is back on your list of emergency contacts.") }
        is Asking.Approve -> {
            val who = Emergency.personName(a.g.grantee)
            ActionSheet(
                ctx, "Give $who access now?", a.g.grantee.email, "Approve access", "Approving…", needsPassword = true, danger = true,
                close = { asking = null },
                run = { pw -> client.approveGrant(a.g.id, pw!!); done("$who can view your vaults now.") },
            ) { PromptText("$who can view your personal vaults at once, without waiting. They keep what they see, even if you end their access later.") }
        }
        is Asking.End -> {
            val who = Emergency.personName(a.g.grantee)
            ActionSheet(
                ctx, "End $who's access?", a.g.grantee.email, "End access", "Ending…", danger = true,
                close = { asking = null },
                run = { client.rejectGrant(a.g.id); done("Access ended.") },
            ) {
                PromptText(
                    "$who can't view your vaults any more, but keeps whatever they already saw. They can ask for access again. If you no longer trust them, " +
                        "remove them instead: PassAuth then changes the keys of your personal vaults. Change the passwords that matter too.",
                )
            }
        }
        is Asking.Remove -> {
            val who = Emergency.personName(a.g.grantee)
            ActionSheet(
                ctx, "Remove $who?", "Emergency contact", "Remove contact", if (Emergency.hasKeys(a.g)) "Removing and changing keys…" else "Removing…", danger = true,
                close = { asking = null },
                run = {
                    val r = client.removeContact(a.g)
                    done(
                        when {
                            r.failed != null -> "$who was removed, but the keys of your personal vaults weren't changed yet. Use Replace keys on this page to finish it."
                            r.leftover != null -> "$who was removed. ${r.leftover}"
                            r.rotated > 0 -> "Emergency contact removed and vault keys changed."
                            else -> "Emergency contact removed."
                        },
                    )
                },
            ) { PromptText(Emergency.removalText(a.g)) }
        }
        is Asking.Wait -> WaitSheet(ctx, a.g, close = { asking = null }) { done("Waiting period changed.") }
        is Asking.Request -> {
            val who = Emergency.personName(a.g.grantor)
            ActionSheet(
                ctx, "Ask for access to $who's vaults?", a.g.grantor.email, "Ask for access", "Asking…",
                close = { asking = null },
                run = { client.requestAccess(a.g.id); done("$who was told about your request.") },
            ) {
                PromptText(
                    "$who is emailed at once. Unless they reject it, you can view their own vaults in ${Emergency.daysText(a.g.waitDays)}. " +
                        "Ask only if they really can't reach their vaults themselves.",
                )
            }
        }
        is Asking.Leave -> {
            val who = Emergency.personName(a.g.grantor)
            ActionSheet(
                ctx,
                if (a.decline) "Decline $who's invitation?" else "Stop being $who's emergency contact?",
                a.g.grantor.email,
                if (a.decline) "Decline" else "Stop being their contact",
                "Removing…",
                danger = true,
                close = { asking = null },
                run = { client.leaveGrant(a.g.id); done(if (a.decline) "Invitation declined." else "You're no longer their emergency contact.") },
            ) { PromptText("You won't be able to ask for access to $who's vaults. They can name you again.") }
        }
        Asking.UseServerList -> UseServerListSheet(ctx, close = { asking = null }) { done("This phone uses your server's list of emergency contacts now.") }
        Asking.StartNewList -> ActionSheet(
            ctx, "Start a new list of emergency contacts?", null, "Start a new list", "Saving…", needsPassword = true,
            close = { asking = null },
            run = { pw -> client.startNewRoster(pw!!); done("New list of emergency contacts started. Confirm your contacts again.") },
        ) {
            PromptText(
                "Your server's list can't be opened with your account's key, so PassAuth can't tell which contacts you trust. A new list starts empty: " +
                    "until you confirm them again, none of your contacts gets keys to new or changed vaults.",
            )
        }
        Asking.ReplaceKeys -> ActionSheet(
            ctx, "Replace vault keys?", pending.joinToString(", ") { it.name }, "Replace keys", "Replacing…",
            close = { asking = null },
            run = {
                val r = ctx.repo.rotateVaultKeys(pending.map { it.id })
                if (r.reviews.isNotEmpty()) {
                    if (r.rotated > 0) ctx.notify("Vault keys replaced.")
                    asking = Asking.Review(r.reviews)
                } else {
                    done(r.leftover?.let { if (r.rotated > 0) "Vault keys replaced. $it" else it } ?: "Vault keys replaced.")
                }
            },
        ) {
            PromptText(
                "PassAuth makes new keys for these vaults and encrypts their items again, so people who no longer have access can't read anything you add " +
                    "afterwards. Changing a vault's key also deletes the earlier versions kept of its items.",
            )
        }
        is Asking.Review -> MemberReviewSheet(ctx, a.reviews, close = { asking = null }) { approvals ->
            val r = ctx.repo.rotateVaultKeys(a.reviews.map { it.vaultId }, approvals = approvals)
            if (r.reviews.isNotEmpty()) {
                // The members changed since the review: show what the server lists now.
                asking = Asking.Review(r.reviews)
                throw io.passauth.app.data.UserException(io.passauth.app.data.SignedSharing.CHANGED_JUST_NOW)
            }
            done(r.leftover?.let { if (r.rotated > 0) "Vault keys replaced. $it" else it } ?: "Vault keys replaced.")
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 4.dp).semantics { heading() })
}

@Composable
private fun StatusBadge(label: String, tone: Tone) {
    val (bg, fg) = when (tone) {
        Tone.Ok -> PassAuthTheme.colors.okSoft to PassAuthTheme.colors.ok
        Tone.Warn -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        Tone.Info -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Surface(shape = RoundedCornerShape(50), color = bg, contentColor = fg) {
        Text(label, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp))
    }
}

/** A grant's card: who, the waiting period, what its state means now, and what can be done. */
@Composable
private fun GrantCard(who: String, g: Grant, label: String, text: String, tone: Tone, content: @Composable ColumnScope.() -> Unit) {
    CardSection(null) {
        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Space.m),
                modifier = Modifier.semantics(mergeDescendants = true) {},
            ) {
                Tile(icon = Icons.Outlined.ContactEmergency, onCard = true)
                Column(Modifier.weight(1f)) {
                    Text(who, style = MaterialTheme.typography.titleMedium)
                    Text("Waiting period: ${Emergency.daysText(g.waitDays)}", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
                }
                StatusBadge(label, tone)
            }
            Text(text, style = MaterialTheme.typography.bodyMedium)
            content()
        }
    }
}

private fun display(name: String, email: String, shown: String) = if (name.trim().isNotEmpty()) "$shown ($email)" else shown

/** Someone the account named (the account is the grantor). */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ContactCard(g: Grant, enabled: Boolean, unlisted: Boolean, removed: Boolean, onAsk: (Asking) -> Unit, onReject: () -> Unit) {
    val who = Emergency.personName(g.grantee)
    val status = Emergency.grantorStatus(g, whenText)
    val actions = Emergency.grantorActions(g)
    GrantCard(display(g.grantee.name, g.grantee.email, who), g, status.label, status.text, status.tone) {
        if (g.v1Exposed) WarningNote(Emergency.v1Warning(who))
        if (removed) WarningNote(Emergency.removedText(who))
        if (unlisted) {
            Muted(
                "Your list of emergency contacts doesn't have $who (a change that didn't finish, or a new list), so PassAuth doesn't give them keys to " +
                    "new or changed vaults. Confirm them again to put them back.",
            )
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (enabled && unlisted) Button(onClick = { onAsk(Asking.Again(g)) }) { Text("Confirm again…") }
            if (enabled && !removed && GrantorAction.Confirm in actions) {
                Button(onClick = { onAsk(Asking.Confirm(g)) }) { Text(if (g.reconfirm) "Check and confirm again…" else "Check and confirm…") }
            }
            if (GrantorAction.Approve in actions) Button(onClick = { onAsk(Asking.Approve(g)) }) { Text("Approve now…") }
            if (GrantorAction.Reject in actions) OutlinedButton(onClick = onReject) { Text("Reject request") }
            if (GrantorAction.End in actions) OutlinedButton(onClick = { onAsk(Asking.End(g)) }) { Text("End access…") }
            if (GrantorAction.Wait in actions) TextButton(onClick = { onAsk(Asking.Wait(g)) }, modifier = Modifier.heightIn(min = 48.dp)) { Text("Change waiting period") }
            if (GrantorAction.Remove in actions) {
                TextButton(
                    onClick = { onAsk(Asking.Remove(g)) },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text("Remove…") }
            }
        }
    }
}

/** Someone who named the account (the account is the contact). */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TrustingCard(g: Grant, enabled: Boolean, onAccept: () -> Unit, onAsk: (Asking) -> Unit, onView: () -> Unit) {
    val who = Emergency.personName(g.grantor)
    val status = Emergency.granteeStatus(g, whenText)
    val actions = Emergency.granteeActions(g)
    GrantCard(display(g.grantor.name, g.grantor.email, who), g, status.label, status.text, status.tone) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (enabled && GranteeAction.Accept in actions) Button(onClick = onAccept) { Text("Accept") }
            if (GranteeAction.Decline in actions) {
                TextButton(
                    onClick = { onAsk(Asking.Leave(g, decline = true)) },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text("Decline…") }
            }
            if (enabled && GranteeAction.Request in actions) OutlinedButton(onClick = { onAsk(Asking.Request(g)) }) { Text("Ask for access…") }
            if (enabled && GranteeAction.View in actions) Button(onClick = onView) { Text("View $who's vaults") }
            if (GranteeAction.Remove in actions) {
                TextButton(
                    onClick = { onAsk(Asking.Leave(g, decline = false)) },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text("Stop being their contact…") }
            }
        }
    }
}

/**
 * A decision sheet that runs [run] (with the master password when [needsPassword]) and shows its
 * error; it can't be dismissed while running.
 */
@Composable
private fun ActionSheet(
    ctx: UiCtx,
    title: String,
    subtitle: String?,
    action: String,
    busyAction: String,
    needsPassword: Boolean = false,
    danger: Boolean = false,
    enabled: Boolean = true,
    close: () -> Unit,
    run: suspend (String?) -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var password by remember { mutableStateOf("") }
    fun go() {
        if (busy) return
        if (needsPassword && password.isEmpty()) return run { error = "Enter your master password." }
        busy = true
        error = null
        ctx.scope.launch {
            try {
                run(if (needsPassword) password else null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = errorMessage(e)
            } finally {
                busy = false
            }
        }
    }
    DecisionSheet(
        onDismiss = close,
        title = title,
        subtitle = subtitle,
        tile = { Tile(icon = Icons.Outlined.ContactEmergency, danger = danger) },
        error = error,
        dismissable = !busy,
        actions = {
            PrimaryButton(if (busy) busyAction else action, ::go, busy = busy, danger = danger, enabled = enabled)
            QuietActions { QuietButton("Cancel", close, enabled = !busy) }
        },
    ) {
        content()
        if (needsPassword) PasswordField(password, { password = it; error = null }, "Master password", onImeAction = ::go)
    }
}

@Composable
private fun AddContactSheet(ctx: UiCtx, close: () -> Unit, added: (String) -> Unit) {
    var email by remember { mutableStateOf("") }
    var days by remember { mutableStateOf(Emergency.DEFAULT_WAIT_DAYS.toString()) }
    ActionSheet(
        ctx, "Add a trusted contact", null, "Add contact", "Adding…",
        close = close,
        run = {
            val wait = days.trim().toDoubleOrNull()
            if (email.isBlank()) throw io.passauth.app.data.UserException("Enter your contact's email address.")
            if (wait == null || !Emergency.validWait(wait)) {
                throw io.passauth.app.data.UserException("Choose a waiting period from ${Emergency.MIN_WAIT_DAYS} to ${Emergency.MAX_WAIT_DAYS} days.")
            }
            val g = ctx.repo.emergency.inviteContact(email, wait.toLong())
            added(Emergency.personName(g.grantee))
        },
    ) {
        TextInput(email, { email = it }, "Their email address", keyboardType = KeyboardType.Email)
        TextInput(days, { v -> days = v.filter(Char::isDigit).take(2) }, "Waiting period (days)", keyboardType = KeyboardType.Number)
        PromptText("They need an account on this server. They accept, then you confirm them by checking their fingerprint together.")
        Muted(Emergency.confirmMeaning("your contact"))
    }
}

/** "Check and confirm" or "Confirm again": the contact's fingerprint to compare, and what confirming gives. */
@Composable
private fun ConfirmContactSheet(ctx: UiCtx, g: Grant, again: Boolean, close: () -> Unit, confirmed: () -> Unit) {
    val who = Emergency.personName(g.grantee)
    val fp = remember(g.grantee.publicKey) { fingerprintOf(g.grantee.publicKey) }
    ActionSheet(
        ctx,
        if (again) "Confirm $who again?" else "Confirm $who?",
        g.grantee.email,
        if (again) "Confirm again" else "Confirm contact",
        "Confirming…",
        enabled = fp != null,
        close = close,
        run = {
            if (again) ctx.repo.emergency.confirmAgain(g) else ctx.repo.emergency.confirmContact(g)
            confirmed()
        },
    ) {
        if (again) {
            PromptText("$who gets keys to your new and changed personal vaults again. First make sure it's really their account: the key below is the one your server names for them now.")
        } else {
            if (g.reconfirm) PromptText(Emergency.reconfirmText(who))
            PromptText("Confirming lets $who ask for access later: a key to your personal vaults is locked so that only their account can open it. First make sure it's really their account.")
            WarningNote(Emergency.confirmMeaning(who, g.v1Exposed))
        }
        if (fp != null) {
            HorizontalDivider(color = PassAuthTheme.colors.sheetLine)
            Text("$who's key fingerprint", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            SelectionContainer { Text(fp, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge) }
            PromptText("Ask $who to read you their fingerprint, in person or on a call. In PassAuth it's on the Emergency access page, or in Settings, then Account. Confirm only if it matches exactly.")
        } else {
            Alert(
                "PassAuth can't show $who's fingerprint, so their account can't be checked${if (again) "" else " and they can't be confirmed"}. Remove them, then add them again.",
                AlertKind.Error,
            )
        }
    }
}

@Composable
private fun WaitSheet(ctx: UiCtx, g: Grant, close: () -> Unit, saved: () -> Unit) {
    val who = Emergency.personName(g.grantee)
    var days by remember { mutableStateOf(g.waitDays.toString()) }
    var password by remember { mutableStateOf("") }
    val wanted = days.trim().toDoubleOrNull()
    // A shorter period lets the contact in sooner: it needs the master password, as approving does.
    val shorter = wanted != null && Emergency.validWait(wanted) && wanted < g.waitDays
    ActionSheet(
        ctx, "Change the waiting period", who, "Save", "Saving…",
        close = close,
        run = {
            if (wanted == null || !Emergency.validWait(wanted)) {
                throw io.passauth.app.data.UserException("Choose a waiting period from ${Emergency.MIN_WAIT_DAYS} to ${Emergency.MAX_WAIT_DAYS} days.")
            }
            if (shorter && password.isEmpty()) throw io.passauth.app.data.UserException("Enter your master password to shorten the waiting period.")
            ctx.repo.emergency.changeWait(g.id, wanted.toLong(), if (shorter) password else null)
            saved()
        },
    ) {
        TextInput(days, { v -> days = v.filter(Char::isDigit).take(2) }, "Days to say no after $who asks", keyboardType = KeyboardType.Number)
        Muted(
            "From ${Emergency.MIN_WAIT_DAYS} to ${Emergency.MAX_WAIT_DAYS} days." +
                if (g.status == GrantStatus.Requested) " A request already waiting follows the new period, counted from when they asked." else "",
        )
        if (shorter) {
            PasswordField(password, { password = it }, "Master password")
            Muted("A shorter waiting period lets $who in sooner, so it needs your master password.")
        }
    }
}

/**
 * "Use the server's list" (after the server's admin restored a backup): the server's roster with the
 * names, emails and fingerprints from inside it, marked when this phone's last trusted list doesn't
 * have them; written forward with the master password. A list that changed meanwhile is shown again.
 */
@Composable
private fun UseServerListSheet(ctx: UiCtx, close: () -> Unit, done: () -> Unit) {
    var list by remember { mutableStateOf<ServerRoster?>(null) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var load by remember { mutableIntStateOf(0) }
    LaunchedEffect(load) {
        list = null
        try {
            list = ctx.repo.emergency.loadServerRoster()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            loadError = errorMessage(e)
        }
    }
    ActionSheet(
        ctx, "Use your server's list of emergency contacts?", null, "Use the server's list", "Saving…", needsPassword = true, danger = true,
        enabled = list != null,
        close = close,
        run = { pw ->
            val l = list ?: throw io.passauth.app.data.UserException("Wait for the list to load, then try again.")
            try {
                ctx.repo.emergency.useServerRoster(l, pw!!)
            } catch (e: RosterChangedError) {
                // Changed since it was shown: read it again and show it again, never written unseen.
                load++
                throw e
            }
            done()
        },
    ) {
        PromptText(
            "Only do this if your server's admin restored a backup. Contacts you removed after that backup could get access to your personal vaults again. " +
                "Check the list below before you continue.",
        )
        val l = list
        when {
            l == null && loadError == null -> Muted("Loading…")
            l != null && l.entries.isEmpty() -> PromptText("The server's list has no contacts.")
            l != null -> l.entries.forEach { r ->
                Column(Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}) {
                    Text(Emergency.entryLabel(r.entry), style = MaterialTheme.typography.bodyLarge)
                    when {
                        r.removed -> Muted("Removed earlier: stays removed")
                        r.wouldReturn -> Text("Would get access again", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    Muted("Key fingerprint: ${fingerprintOf(r.entry.contactKey) ?: "unknown"}")
                }
            }
        }
        ErrorText(loadError)
    }
}

// -------------------------------------------------------------- the vault

/**
 * A grantor's own vaults, read-only, through an approved emergency access. Decrypted into memory
 * only: nothing is stored, and it is gone when this page closes or the vault locks. Never used for
 * autofill.
 */
@Composable
private fun EmergencyVaultScreen(ctx: UiCtx, g: Grant, back: () -> Unit) {
    androidx.activity.compose.BackHandler(onBack = back)
    var view by remember { mutableStateOf<io.passauth.app.data.GrantorVault?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var query by remember { mutableStateOf("") }
    var showTrash by remember { mutableStateOf(false) }
    var opened by remember { mutableStateOf<io.passauth.app.data.GrantorEntry?>(null) }
    LaunchedEffect(g.id) {
        try {
            view = ctx.repo.emergency.openGrantorVault(g.id)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error = errorMessage(e)
        }
    }
    val who = Emergency.personName(g.grantor)
    opened?.let { entry ->
        androidx.activity.compose.BackHandler { opened = null }
        return EmergencyItemScreen(ctx, g, entry, view?.vaults?.firstOrNull { it.first == entry.vaultId }?.second ?: "Vault") { opened = null }
    }
    Scaffold(topBar = { PageBar("$who's vaults", onBack = back) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Alert("View only. Nothing of it is saved on this phone: it's gone when you leave this page or PassAuth locks.")
            ErrorText(error)
            val v = view
            if (v == null && error == null) Muted("Opening…")
            if (v != null) {
                // A vault whose items aren't what its manifest records (view only: nothing to resolve here).
                v.mismatched.forEach { name ->
                    Alert(if (v.vaults.size > 1) "$name: ${io.passauth.app.data.Manifests.WARNING}" else io.passauth.app.data.Manifests.WARNING, AlertKind.Error)
                }
                // A vault without a record of changes: shown, and said that nothing could be checked.
                v.unchecked.forEach { name -> Muted("$name: ${io.passauth.app.data.Manifests.VIEW_UNCHECKED}") }
                if (v.failed > 0) WarningNote("${if (v.failed == 1) "One item couldn't be opened and is" else "${v.failed} items couldn't be opened and are"} left out.")
                TextInput(query, { query = it }, "Search")
                val trashed = v.items.count { it.deletedAt != null }
                if (trashed > 0) {
                    io.passauth.app.ui.components.CheckRow("Show items in the trash ($trashed)", showTrash, { showTrash = it })
                }
                val q = query.trim().lowercase()
                val list = io.passauth.app.data.ItemSearch.search(v.items.filter { showTrash || it.deletedAt == null }, q) { it.item }
                if (v.items.isEmpty()) Muted("These vaults are empty.") else if (list.isEmpty()) Muted("Nothing matches.")
                CardSection(null) {
                    list.forEachIndexed { n, e ->
                        if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                        Row(
                            Modifier.fillMaxWidth().heightIn(min = 56.dp)
                                .clickable(role = androidx.compose.ui.semantics.Role.Button) { opened = e }
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(Space.m),
                        ) {
                            Tile(e.item.name, onCard = true, globe = !ctx.state.showSiteIcons && e.item.kind == io.passauth.app.data.ItemKind.Login)
                            Column(Modifier.weight(1f)) {
                                Text(e.item.name.ifEmpty { "Untitled" }, style = MaterialTheme.typography.bodyLarge)
                                val sub = listOfNotNull(
                                    e.item.login?.username?.takeIf { it.isNotEmpty() },
                                    v.vaults.firstOrNull { it.first == e.vaultId }?.second,
                                    "In the trash".takeIf { e.deletedAt != null },
                                ).joinToString(" · ")
                                if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
                            }
                        }
                    }
                }
            }
        }
    }
}

/** One item of a grantor's vault, read-only, with copy buttons and its files (downloaded through the access). */
@Composable
private fun EmergencyItemScreen(ctx: UiCtx, g: Grant, e: io.passauth.app.data.GrantorEntry, vaultName: String, back: () -> Unit) {
    val i = e.item
    Scaffold(topBar = { PageBar(i.name.ifEmpty { "Untitled" }, onBack = back) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Muted("In ${Emergency.personName(g.grantor)}'s vault $vaultName. View only.")
            io.passauth.app.ui.vault.ItemDetailCards(ctx, i)
            io.passauth.app.ui.vault.AttachmentsCard(ctx, e.id, i, canWrite = false, readOnly = true) { a ->
                "${EmergencyClient.path(g.id)}/attachments/${java.net.URLEncoder.encode(a.id, "UTF-8")}"
            }
        }
    }
}
