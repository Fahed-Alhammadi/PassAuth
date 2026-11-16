package io.passauth.app.ui.settings

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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.GroupAdd
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Invitation
import io.passauth.app.data.InvitationText
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.components.WarningNote
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Space
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** What an answer sheet is about. */
private data class Answer(val invitation: Invitation, val accept: Boolean)

/**
 * Vault invitations (servers with `vault_invitations`; the web vault's Settings → Vaults & sharing):
 * each vault shared with the account and waiting for an answer, with the fingerprint the server
 * lists for the sharer (not proof that they sent it: accept only invitations you expected).
 * Accept / Decline are confirmed in a decision sheet.
 */
@Composable
fun InvitationsScreen(ctx: UiCtx, fromVault: Boolean) {
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    val invitations = vault?.invitations.orEmpty()
    var answering by remember { mutableStateOf<Answer?>(null) }
    val back = { ctx.go(if (fromVault) Route.Vault else Route.Settings()) }

    Scaffold(topBar = { PageBar("Vault invitations", onBack = back) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(InvitationText.INTRO, style = MaterialTheme.typography.bodyMedium)
            if (invitations.isEmpty()) {
                Muted("There are no invitations waiting.")
            }
            invitations.forEach { inv ->
                InvitationCard(inv, onAccept = { answering = Answer(inv, true) }, onDecline = { answering = Answer(inv, false) })
            }
        }
    }
    answering?.let { a -> AnswerSheet(ctx, a) { answering = null } }
}

private val dateFormat = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT)

private fun date(ts: Long): String = dateFormat.format(java.util.Date(ts * 1000))

/** The sharer's key fingerprint (the core's format), or null when it can't be shown. */
@Composable
private fun fingerprintOf(inv: Invitation): String? {
    val key = inv.invitedBy?.publicKey.orEmpty()
    return remember(key) { if (key.isEmpty()) null else runCatching { io.passauth.core.fingerprint(key) }.getOrNull() }
}

@Composable
private fun InvitationCard(inv: Invitation, onAccept: () -> Unit, onDecline: () -> Unit) {
    val fp = fingerprintOf(inv)
    CardSection(null) {
        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.m)) {
                Tile(icon = Icons.Outlined.GroupAdd, onCard = true)
                Column(Modifier.weight(1f)) {
                    Text(InvitationText.title(inv), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                    Text(InvitationText.fromLine(inv, ::date), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
                }
                RoleBadge(InvitationText.roleLabel(inv.role))
            }
            when {
                inv.name == null -> WarningNote(InvitationText.cantOpen(inv))
                fp != null -> {
                    FingerprintBlock(inv, fp)
                    Muted(InvitationText.EXPECTED)
                }
                else -> WarningNote(InvitationText.noFingerprint(inv))
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (inv.name != null) Button(onClick = onAccept) { Text("Accept…") }
                TextButton(
                    onClick = onDecline,
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text("Decline…") }
            }
        }
    }
}

@Composable
private fun RoleBadge(text: String) {
    Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surfaceVariant, contentColor = MaterialTheme.colorScheme.onSurfaceVariant) {
        Text(text, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp))
    }
}

/** "Fingerprint your server lists for alex@example.com" and the fingerprint itself (selectable, monospace). */
@Composable
private fun FingerprintBlock(inv: Invitation, fp: String) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(InvitationText.fingerprintLabel(inv), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer {
            Text(fp, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

/** Accept or decline, confirmed in a decision sheet. */
@Composable
private fun AnswerSheet(ctx: UiCtx, answer: Answer, close: () -> Unit) {
    val inv = answer.invitation
    val fp = fingerprintOf(inv)
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    fun confirm() {
        if (busy) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                if (answer.accept) {
                    ctx.repo.acceptInvitation(inv.vaultId)
                    ctx.notify(InvitationText.joined(inv))
                } else {
                    ctx.repo.declineInvitation(inv.vaultId)
                    ctx.notify("Invitation declined.")
                }
                close()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = errorMessage(e)
            } finally {
                busy = false
            }
        }
    }
    if (answer.accept) {
        DecisionSheet(
            onDismiss = close,
            title = InvitationText.acceptTitle(inv),
            subtitle = InvitationText.acceptSubtitle(inv),
            tile = { Tile(icon = Icons.Outlined.GroupAdd) },
            error = error,
            dismissable = !busy,
            actions = {
                PrimaryButton(if (busy) "Accepting…" else "Accept invitation", ::confirm, busy = busy)
                QuietActions { QuietButton("Cancel", close, enabled = !busy) }
            },
        ) {
            PromptText(InvitationText.acceptBody(inv))
            if (fp != null) {
                HorizontalDivider(color = PassAuthTheme.colors.sheetLine)
                FingerprintBlock(inv, fp)
                PromptText(InvitationText.EXPECTED)
            } else {
                WarningNote(InvitationText.noFingerprint(inv))
            }
        }
    } else {
        DecisionSheet(
            onDismiss = close,
            title = "Decline this invitation?",
            subtitle = InvitationText.declineSubtitle(inv),
            tile = { Tile(icon = Icons.Outlined.GroupAdd, danger = true) },
            error = error,
            dismissable = !busy,
            actions = {
                PrimaryButton(if (busy) "Declining…" else "Decline invitation", ::confirm, busy = busy, danger = true)
                QuietActions { QuietButton("Cancel", close, enabled = !busy) }
            },
        ) {
            PromptText(InvitationText.DECLINE_BODY)
        }
    }
}
