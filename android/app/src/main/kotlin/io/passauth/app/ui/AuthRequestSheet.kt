package io.passauth.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import io.passauth.app.data.Answering
import io.passauth.app.data.Closed
import io.passauth.app.data.DeviceApprovals
import io.passauth.app.data.InboxNotice
import io.passauth.app.data.ShownRequest
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.KeyValue
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.RowDivider
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.components.ValueText
import io.passauth.app.ui.components.WarningNote
import io.passauth.app.ui.theme.Space
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * A new device asks to sign in to the unlocked account (shown while the vault is open in the app,
 * AppRoot). The request on screen was frozen when its sheet opened ([io.passauth.app.data.ApprovalQueue]):
 * who asks, as the new device calls itself (cleaned and cut short), and three sets of five words
 * worked out here from the request's own key (never the server's), to pick the ones the new device
 * shows. The right words approve and show the code to enter on the new device until Done; other
 * words deny the request (a note says so before anything else comes up); "None of these" denies,
 * "Not now" puts it off. The words take a tap only a second after the sheet appeared (and after the
 * app comes back on screen); "Not now" gets the focus first. A newer request waits in line; a
 * listing that changes the shown one (another key) closes it with a note. Answers run in the app's
 * scope, so a rotation doesn't lose one.
 */
@Composable
fun AuthRequestPrompt(ctx: UiCtx) {
    val inbox = ctx.graph.inbox
    val queue by inbox.queue.collectAsState()
    val notify by rememberUpdatedState(ctx.notify)
    LaunchedEffect(inbox) {
        inbox.notices.collect { n ->
            when (n) {
                is InboxNotice.Text -> notify(n.text)
                is InboxNotice.Failed -> notify(DeviceApprovals.errorMessage(n.error) ?: errorMessage(n.error))
            }
        }
    }
    queue.closed?.let { return ClosedSheet(it, onClose = inbox::closedRead) }
    val shown = queue.shown ?: return
    // Keyed by the request and its key: another request (or key) is another sheet, never this one updated.
    // (Not by the challenge: the server seals it again for every listing; the frozen one is used.)
    key(shown.request.id, shown.request.publicKey) { RequestSheet(ctx, shown) }
}

/** Why the shown request's sheet closed (it changed, or the words picked weren't its): nothing else comes up until this is read. */
@Composable
private fun ClosedSheet(closed: Closed, onClose: () -> Unit) {
    DecisionSheet(
        onDismiss = onClose,
        title = closed.title,
        tile = { Tile(icon = Icons.Outlined.Warning, danger = true) },
        actions = { PrimaryButton("OK", onClose) },
    ) {
        PromptText(closed.text)
    }
}

@Composable
private fun RequestSheet(ctx: UiCtx, shown: ShownRequest) {
    val inbox = ctx.graph.inbox
    val r = shown.request
    val code = shown.code
    val busy = shown.answering

    // The words take a tap only a second after they appeared, and again after the app comes back on screen.
    var armed by remember { mutableStateOf(false) }
    var resumed by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) {
        resumed++
        onPauseOrDispose { armed = false }
    }
    LaunchedEffect(resumed) {
        armed = false
        delay(DeviceApprovals.CHOICE_DELAY_MS)
        armed = true
    }
    // Out of time before it was answered: the sheet closes with a note.
    if (code == null && busy == null) {
        LaunchedEffect(r.id) {
            delay(maxOf(0L, r.expiresAt * 1000 - System.currentTimeMillis()))
            inbox.expired(r.id)
        }
    }

    fun approve(phrase: String) {
        if (!armed || busy != null) return
        ctx.graph.scope.launch { inbox.approve(r.id, phrase) }
    }

    fun deny() {
        if (busy == null) ctx.graph.scope.launch { inbox.deny(r.id) }
    }

    val now = System.currentTimeMillis() / 1000
    val notNow = remember { FocusRequester() }
    // One sheet throughout: approving turns it into the code, it isn't replaced by another one.
    DecisionSheet(
        onDismiss = { if (code == null) inbox.putOff(r.id) },
        title = if (code != null) DeviceApprovals.APPROVED_TITLE else DeviceApprovals.TITLE,
        subtitle = ctx.state.email,
        tile = { Tile(icon = Icons.Outlined.Devices) },
        // The code stays until Done: it can't be swiped or backed away.
        dismissable = code == null && busy == null,
        actions = {
            if (code != null) {
                PrimaryButton(DeviceApprovals.DONE, { inbox.done(r.id) })
            } else {
                QuietActions {
                    QuietButton(if (busy == Answering.Deny) "Denying…" else DeviceApprovals.NONE, ::deny, enabled = busy == null, danger = true)
                    QuietButton(DeviceApprovals.NOT_NOW, { inbox.putOff(r.id) }, enabled = busy == null, modifier = Modifier.focusRequester(notNow))
                }
                // The focus starts on "Not now": a key press already on its way must never approve.
                LaunchedEffect(r.id) { runCatching { notNow.requestFocus() } }
            }
        },
    ) {
        if (code != null) ApprovedCode(code) else Choices(ctx, shown, now, armed, ::approve)
    }
}

/** Approved: the code to enter on the new device, large and grouped ("123 456"). */
@Composable
private fun ApprovedCode(code: String) {
    PromptText(DeviceApprovals.CODE)
    Text(
        DeviceApprovals.groupedCode(code),
        style = MaterialTheme.typography.displaySmall,
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.SemiBold,
        textAlign = TextAlign.Center,
        // Read out digit by digit.
        modifier = Modifier.fillMaxWidth().semantics { contentDescription = code.toList().joinToString(" ") },
    )
    PromptText(DeviceApprovals.CODE_HELP)
}

/** Who asks (claims, cleaned) and the three sets of words to pick from. */
@Composable
private fun Choices(ctx: UiCtx, shown: ShownRequest, now: Long, armed: Boolean, approve: (String) -> Unit) {
    val r = shown.request
    val busy = shown.answering
    PromptText(DeviceApprovals.body(ctx.state.email))
    GroupCard {
        Column(Modifier.padding(horizontal = Space.l, vertical = Space.xs)) {
            KeyValue(DeviceApprovals.DEVICE) { ValueText(DeviceApprovals.device(r)) }
            RowDivider(inset = 0.dp)
            KeyValue(DeviceApprovals.APP) { ValueText(DeviceApprovals.app(r)) }
            DeviceApprovals.address(r)?.let {
                RowDivider(inset = 0.dp)
                KeyValue(DeviceApprovals.ADDRESS) { ValueText(it) }
            }
            RowDivider(inset = 0.dp)
            KeyValue(DeviceApprovals.REQUESTED) { ValueText(DeviceApprovals.requested(r.createdAt, now)) }
        }
    }
    if (shown.choices.isNotEmpty()) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(Space.s)) {
            Text(
                DeviceApprovals.QUESTION,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { heading() },
            )
            shown.choices.forEach { phrase ->
                OutlinedButton(
                    onClick = { approve(phrase) },
                    enabled = armed && busy == null,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                ) {
                    Text(phrase, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                }
            }
            if (busy == Answering.Approve) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.s)) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    PromptText("Approving…")
                }
            }
        }
    } else {
        WarningNote(DeviceApprovals.CANNOT_CHECK)
    }
    PromptText(DeviceApprovals.HELP)
}
