package io.passauth.app.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.IdentityChange
import io.passauth.app.data.KnownPerson
import io.passauth.app.data.MemberReview
import io.passauth.app.data.PinState
import io.passauth.app.data.ReviewApproval
import io.passauth.app.data.ReviewPerson
import io.passauth.app.data.SignedSharing
import io.passauth.app.data.VaultTrust
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.CheckRow
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** A fingerprint the user compares (selectable, monospace) under its label. */
@Composable
internal fun FingerprintText(label: String, fingerprint: String) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer { Text(fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge) }
    }
}

/** What a sheet of the page is about. */
private sealed interface Ask {
    data class Verify(val p: KnownPerson) : Ask
    data class Trust(val c: IdentityChange) : Ask
}

/**
 * Settings → Shared vaults and keys (servers with signed sharing): this account's identity
 * fingerprint (computed here), vaults PassAuth refused, people whose keys changed (Trust the new
 * key), each shared vault's signature state, and the people whose keys this account pinned, with
 * "Mark as verified" after comparing a fingerprint with them.
 */
@Composable
fun SharingScreen(ctx: UiCtx) {
    val status by ctx.repo.sharing.collectAsStateWithLifecycle()
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    var ask by remember { mutableStateOf<Ask?>(null) }

    Scaffold(topBar = { PageBar("Shared vaults and keys", onBack = { ctx.go(Route.Settings()) }) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (vault == null) {
                Muted("Unlock your vault to see this.")
                return@Column
            }
            if (!status.enabled) {
                Muted("Your server doesn't sign shared vaults yet, so PassAuth can't check who shared a vault with you. Accept only invitations you expected.")
                return@Column
            }
            Text(
                "Whoever shares a vault key signs it. PassAuth checks every signature against the keys it has seen for that person, " +
                    "and doesn't use a shared vault it can't verify.",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (status.paused) WarningNote(SignedSharing.PAUSED)
            status.pinsProblem?.let { WarningNote(it) }
            CardSection("Your identity") {
                Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    val fp = status.fingerprint
                    if (fp != null) {
                        FingerprintText("Your identity fingerprint", fp)
                        Muted("People who share vaults with you compare this with what their app shows for you.")
                    } else if (status.paused) {
                        Muted("Your identity fingerprint isn't shown while sharing is paused.")
                    } else {
                        Muted("Your signing identity is set up the next time PassAuth reaches your server.")
                    }
                }
            }
            if (status.consent.isNotEmpty()) {
                CardSection("Waiting for your answer") {
                    Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Muted(
                            if (status.consent.size == 1) "Your server added ${status.consent[0].name} to your account. PassAuth doesn't use it until you accept it."
                            else "Your server added ${status.consent.size} vaults to your account. PassAuth doesn't use them until you accept them.",
                        )
                        FlowRow { OutlinedButton(onClick = { ctx.go(Route.Invitations(fromVault = false)) }) { Text("Review…") } }
                    }
                }
            }
            if (status.changed.isNotEmpty()) {
                CardSection("Keys that changed") {
                    status.changed.forEach { c ->
                        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            WarningNote(c.text)
                            c.listedEmail?.let { Muted("Listed by your server as $it") }
                            FingerprintText("New fingerprint", c.fingerprint)
                            OutlinedButton(onClick = { ask = Ask.Trust(c) }) { Text("Trust the new key…") }
                        }
                    }
                }
            }
            if (status.refused.isNotEmpty()) {
                CardSection("Vaults not used") {
                    status.refused.forEachIndexed { n, r ->
                        if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                        Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(r.name, style = MaterialTheme.typography.bodyLarge)
                            WarningNote(r.reason)
                        }
                    }
                }
            }
            val shared = vault?.vaults.orEmpty().filter { !it.personal }
            if (shared.isNotEmpty()) {
                CardSection("Shared with you") {
                    shared.forEachIndexed { n, v ->
                        if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                        Column(Modifier.padding(vertical = 10.dp)) {
                            Text(v.name, style = MaterialTheme.typography.bodyLarge)
                            when (val t = v.trust) {
                                is VaultTrust.Signed -> {
                                    Muted(SignedSharing.signerLine(t.signer, t.deleted))
                                }
                                VaultTrust.NotYetSigned -> Muted(SignedSharing.NOT_YET_SIGNED + ": ask an owner or admin to sign it in the web vault or the desktop app.")
                                else -> {}
                            }
                        }
                    }
                }
            }
            CardSection("People you share with") {
                if (status.people.isEmpty()) {
                    Column(Modifier.padding(vertical = 10.dp)) { Muted("PassAuth remembers each person's keys the first time you share a vault with them.") }
                }
                status.people.forEachIndexed { n, p ->
                    if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                    Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(p.email.ifEmpty { p.userId }, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                            Muted(if (p.verified) "Verified" else "Not verified")
                        }
                        SelectionContainer { Text(p.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium) }
                        if (!p.verified) {
                            FlowRow { OutlinedButton(onClick = { ask = Ask.Verify(p) }) { Text("Mark as verified…") } }
                        }
                    }
                }
            }
        }
    }
    when (val a = ask) {
        is Ask.Verify -> SharingSheet(
            ctx,
            title = "Mark ${a.p.email.ifEmpty { "this person" }} as verified?",
            action = "Mark as verified",
            busyAction = "Saving…",
            close = { ask = null },
            run = { ctx.repo.markVerified(a.p.userId, a.p.identityHash); ctx.notify("Marked as verified.") },
        ) {
            PromptText("Compare this fingerprint with the one ${a.p.email.ifEmpty { "they" }} see in their app under Shared vaults and keys, in person or on a call. Mark it only when they're the same.")
            FingerprintText("Fingerprint", a.p.fingerprint)
        }
        is Ask.Trust -> {
            var compared by remember(a) { mutableStateOf(false) }
            SharingSheet(
                ctx,
                title = if (a.c.conflict) "Trust the new account for ${a.c.email}?" else "Trust ${a.c.email}'s new key?",
                action = "Trust the new key",
                busyAction = "Saving…",
                    close = { ask = null },
                run = { ctx.repo.trustNewKey(a.c, compared); ctx.notify("New key trusted.") },
                enabled = compared || !a.c.conflict,
            ) {
                PromptText(
                    if (a.c.conflict) {
                        "Your server lists a second account with this email. That happens if your server made it up, so compare this fingerprint " +
                            "with the one they see in their app before you continue."
                    } else {
                        "Their keys are different from the ones PassAuth saw before. That happens if your server changed them, so compare this fingerprint " +
                            "with the one they see in their app before you continue."
                    },
                )
                FingerprintText("New fingerprint", a.c.fingerprint)
                // The email this pins, as the server lists it now.
                PromptText("PassAuth saves it for ${a.c.pinShown.ifEmpty { SignedSharing.someone(a.c.userId) }}.")
                CheckRow("I compared it with them and it's the same", compared, { compared = it })
            }
        }
        null -> {}
    }
}

@Composable
private fun SharingSheet(
    ctx: UiCtx,
    title: String,
    action: String,
    busyAction: String,
    close: () -> Unit,
    run: suspend () -> Unit,
    enabled: Boolean = true,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    fun confirm() {
        if (busy) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                run()
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
        title = title,
        tile = { Tile(icon = Icons.Outlined.Key) },
        error = error,
        dismissable = !busy,
        actions = {
            PrimaryButton(if (busy) busyAction else action, ::confirm, enabled = enabled, busy = busy)
            QuietActions { QuietButton("Cancel", close, enabled = !busy) }
        },
        content = content,
    )
}

/** The pin state of a reviewed member, in words. */
private fun pinLabel(p: ReviewPerson): String = when {
    p.isSelf -> "You"
    p.pin == PinState.Match && p.verified && p.listedEmail == null -> "Verified"
    p.pin == PinState.Match -> "Not verified"
    p.pin == PinState.Upgraded -> "New fingerprint: compare it"
    else -> "New: compare it"
}

/**
 * Before a vault key is replaced (and its signed member list signed): every member the new key goes
 * to, with the pinned email first, the identity fingerprint and its pin state. The first time a vault
 * is signed the user confirms they compared them; people the signed list names but the server no
 * longer lists are confirmed one by one. Nothing is sealed or signed before [run].
 */
@Composable
internal fun MemberReviewSheet(ctx: UiCtx, reviews: List<MemberReview>, close: () -> Unit, run: suspend (Map<String, ReviewApproval>) -> Unit) {
    var compared by remember(reviews) { mutableStateOf(false) }
    var dropped by remember(reviews) { mutableStateOf(setOf<String>()) }
    val first = reviews.any { it.first }
    val allMissing = reviews.flatMap { r -> r.missing.map { r.vaultId + "|" + it.userId } }.toSet()
    val ready = (!first || compared) && dropped.containsAll(allMissing)
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    fun confirm() {
        if (busy || !ready) return
        busy = true
        error = null
        ctx.scope.launch {
            try {
                run(reviews.associate { r -> r.vaultId to ReviewApproval(r.digest, r.missing.map { it.userId }.filter { (r.vaultId + "|" + it) in dropped }.toSet(), r.emailsToPin()) })
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
        title = "Check who gets the new key",
        subtitle = reviews.joinToString(", ") { it.vaultName },
        tile = { Tile(icon = Icons.Outlined.Key) },
        error = error,
        dismissable = !busy,
        actions = {
            PrimaryButton(if (busy) "Replacing…" else "Replace keys", ::confirm, busy = busy, enabled = ready)
            QuietActions { QuietButton("Cancel", close, enabled = !busy) }
        },
    ) {
        reviews.forEach { r ->
            Text(r.vaultName, style = MaterialTheme.typography.titleSmall)
            if (r.first) WarningNote(SignedSharing.FIRST_TIME)
            r.members.forEach { p ->
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(p.email, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                        Muted(pinLabel(p))
                    }
                    p.listedEmail?.let { Muted("Listed by your server as $it") }
                    SelectionContainer { Text(p.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium) }
                }
            }
            r.missing.forEach { m ->
                val k = r.vaultId + "|" + m.userId
                CheckRow(
                    "${m.email} is in the signed member list but your server no longer lists them (they left, declined or were removed). Replace the key without them.",
                    k in dropped,
                    { on -> dropped = if (on) dropped + k else dropped - k },
                )
            }
            HorizontalDivider(color = PassAuthTheme.colors.sheetLine)
        }
        if (first) CheckRow("I compared these fingerprints with the people (in person or on a call)", compared, { compared = it })
        PromptText("The new key is sealed only to these people. Changing a vault's key also deletes the earlier versions kept of its items.")
    }
}
