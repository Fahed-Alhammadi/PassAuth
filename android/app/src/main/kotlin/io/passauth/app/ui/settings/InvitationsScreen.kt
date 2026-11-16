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
import androidx.compose.runtime.LaunchedEffect
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
import io.passauth.app.data.ConsentVault
import io.passauth.app.data.InvitationTrust
import io.passauth.app.data.SignerView
import io.passauth.app.data.PinState
import io.passauth.app.data.SignedSharing
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
    val sharing by ctx.repo.sharing.collectAsStateWithLifecycle()
    var answering by remember { mutableStateOf<Answer?>(null) }
    var consenting by remember { mutableStateOf<Pair<ConsentVault, Boolean>?>(null) }
    val back = { ctx.go(if (fromVault) Route.Vault else Route.Settings()) }

    Scaffold(topBar = { PageBar("Vault invitations", onBack = back) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(InvitationText.INTRO, style = MaterialTheme.typography.bodyMedium)
            if (invitations.isEmpty() && sharing.consent.isEmpty()) {
                Muted("There are no invitations waiting.")
            }
            sharing.consent.forEach { c ->
                // While the trust memory is missing: Accept, or leave it for later (no Decline: a server could use it to push you out of real vaults).
                ConsentCard(c, onAccept = { consenting = c to true }, onDecline = { consenting = c to false }, canDecline = !sharing.memoryMissing)
            }
            invitations.forEach { inv ->
                InvitationCard(inv, onAccept = { answering = Answer(inv, true) }, onDecline = { answering = Answer(inv, false) })
            }
        }
    }
    // A sheet shows one check: when the invitation or vault is checked differently meanwhile (another
    // signer, key or roster), the sheet closes and the card shows the new check; one that is gone closes quietly.
    val answerNow = answering?.let { a -> invitations.firstOrNull { it.vaultId == a.invitation.vaultId } }
    val consentNow = consenting?.let { (c, _) -> sharing.consent.firstOrNull { it.vaultId == c.vaultId } }
    LaunchedEffect(answering, answerNow) {
        val a = answering ?: return@LaunchedEffect
        if (answerNow != a.invitation) {
            answering = null
            if (answerNow != null) ctx.notify(InvitationText.CHANGED)
        }
    }
    LaunchedEffect(consenting, consentNow) {
        val (c, _) = consenting ?: return@LaunchedEffect
        if (consentNow != c) {
            consenting = null
            if (consentNow != null) ctx.notify(SignedSharing.CHANGED_JUST_NOW)
        }
    }
    answering?.let { a -> AnswerSheet(ctx, a) { answering = null } }
    consenting?.let { (c, accept) -> ConsentSheet(ctx, c, accept) { consenting = null } }
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
                inv.trust != InvitationTrust.Unchecked -> SignedBlock(inv)
                fp != null -> {
                    FingerprintBlock(inv, fp)
                    Muted(InvitationText.EXPECTED)
                }
                else -> WarningNote(InvitationText.noFingerprint(inv))
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (inv.acceptable) Button(onClick = onAccept) { Text("Accept…") }
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

/**
 * Signed sharing: who signed the invitation and their identity fingerprint with its pin state, or
 * why it can't be accepted (not signed, or not verified).
 */
@Composable
private fun SignedBlock(inv: Invitation) {
    when (val t = inv.trust) {
        is InvitationTrust.Signed -> SignerBlock(t.signer, false)
        InvitationTrust.Unsigned -> WarningNote(SignedSharing.unsignedInvitation(InvitationText.sharerShort(inv)))
        is InvitationTrust.Refused -> WarningNote(t.reason)
        InvitationTrust.Unchecked -> {}
    }
}

/** Who signed (the pinned email first, the server's different one only as "listed by your server as …"), with the fingerprint and its pin state. */
@Composable
internal fun SignerBlock(s: SignerView, deleted: Boolean) {
    Text(SignedSharing.signerLine(s, deleted), style = MaterialTheme.typography.bodyMedium)
    val label = when (s.pin) {
        PinState.New -> SignedSharing.firstTime(s.email)
        PinState.Upgraded -> "${s.email}'s new identity fingerprint: compare it with them"
        else -> "${s.email}'s identity fingerprint" + if (s.verified && s.listedEmail == null) " · Verified" else ""
    }
    FingerprintText(label, s.fingerprint)
}

/** A shared vault the account never accepted: shown like an invitation, used only once accepted. */
@Composable
private fun ConsentCard(c: ConsentVault, onAccept: () -> Unit, onDecline: () -> Unit, canDecline: Boolean) {
    CardSection(null) {
        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.m)) {
                Tile(icon = Icons.Outlined.GroupAdd, onCard = true)
                Column(Modifier.weight(1f)) {
                    Text(c.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                }
                RoleBadge(InvitationText.roleLabel(c.role))
            }
            WarningNote(if (c.replaced) SignedSharing.CONSENT_REPLACED else SignedSharing.CONSENT)
            val s = c.signer
            when {
                s != null -> SignerBlock(s, c.deleted)
                c.replaced -> {}
                c.unsignedAllowed -> Muted(SignedSharing.NOT_YET_SIGNED + ": accept it only if you expected it.")
                else -> WarningNote(SignedSharing.CONSENT_UNSIGNED)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (c.acceptable) Button(onClick = onAccept) { Text("Accept…") }
                // A replaced key stays locked until accepted (declining it would leave the vault).
                if (!c.replaced && canDecline) TextButton(
                    onClick = onDecline,
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text("Decline…") }
            }
        }
    }
}

/** Accept or decline a vault held for consent, confirmed in a decision sheet. */
@Composable
private fun ConsentSheet(ctx: UiCtx, c: ConsentVault, accept: Boolean, close: () -> Unit) {
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    fun confirm() {
        if (busy) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                if (accept) {
                    ctx.repo.acceptConsent(c)
                    ctx.notify("${c.name} is in your vault now.")
                } else {
                    ctx.repo.declineConsent(c.vaultId)
                    ctx.notify("Declined. PassAuth won't use ${c.name}.")
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
    DecisionSheet(
        onDismiss = close,
        title = if (accept) "Accept ${c.name}?" else "Decline ${c.name}?",
        subtitle = if (c.rejoin) "Shared with you again" else null,
        tile = { Tile(icon = Icons.Outlined.GroupAdd, danger = !accept) },
        error = error,
        dismissable = !busy,
        actions = {
            PrimaryButton(if (busy) (if (accept) "Accepting…" else "Declining…") else (if (accept) "Accept vault" else "Decline vault"), ::confirm, busy = busy, danger = !accept)
            QuietActions { QuietButton("Cancel", close, enabled = !busy) }
        },
    ) {
        if (accept) {
            PromptText(if (c.replaced) SignedSharing.CONSENT_REPLACED else SignedSharing.CONSENT)
            c.signer?.let { SignerBlock(it, c.deleted) }
        } else {
            PromptText("PassAuth won't use this vault, and you leave it. It comes back only if someone shares it with you again.")
        }
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
                    ctx.repo.acceptInvitation(inv)
                    ctx.notify(InvitationText.joined(inv))
                } else {
                    ctx.repo.declineInvitation(inv)
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
            if (inv.trust is InvitationTrust.Signed) {
                HorizontalDivider(color = PassAuthTheme.colors.sheetLine)
                SignedBlock(inv)
            } else if (fp != null) {
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
