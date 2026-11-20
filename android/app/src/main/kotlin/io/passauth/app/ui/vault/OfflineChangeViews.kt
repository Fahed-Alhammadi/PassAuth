package io.passauth.app.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.CloudUpload
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.automirrored.outlined.NoteAdd
import androidx.compose.material.icons.outlined.Smartphone
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.SyncProblem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import io.passauth.app.data.ChangeKind
import io.passauth.app.data.ChangeState
import io.passauth.app.data.OfflineChange
import io.passauth.app.data.OfflineChanges
import io.passauth.app.data.VaultRepository.ConflictChoice
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.ChoiceRow
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.GroupLabel
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.RowDivider
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Space

/**
 * The item page's card for an item with an offline change: what state it is in, "Review" for a
 * change that waits for the user's decision, and "Discard this change" (confirmed).
 */
@Composable
fun ChangeCard(ctx: UiCtx, name: String, change: OfflineChange) {
    var discarding by remember { mutableStateOf(false) }
    var reviewing by remember { mutableStateOf(false) }
    val conflict = change.state == ChangeState.Conflict
    CardSection(null) {
        Row(Modifier.padding(vertical = Space.s).semantics(mergeDescendants = true) {}, verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (change.state == ChangeState.Waiting) Icons.Outlined.CloudUpload else Icons.Outlined.ErrorOutline, null,
                tint = if (change.state == ChangeState.Waiting) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
            Column(Modifier.weight(1f).padding(start = Space.m)) {
                Text(OfflineChanges.marker(change), style = MaterialTheme.typography.bodyLarge)
                Text(
                    when {
                        conflict -> "This item changed on another device after you changed it here. Choose which version to keep."
                        change.state == ChangeState.Held -> "PassAuth tries again when this changes."
                        else -> when (change.kind) {
                            ChangeKind.Create -> "This new item is saved on this device and is sent when PassAuth reaches your server."
                            ChangeKind.Edit -> "Your change is saved on this device and is sent when PassAuth reaches your server."
                            ChangeKind.Trash -> "Moving it to the trash is sent when PassAuth reaches your server."
                        }
                    },
                    style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(Space.s)) {
            if (conflict) TextButton(onClick = { reviewing = true }) { Text("Review") }
            TextButton(onClick = { discarding = true }) { Text(OfflineChanges.DISCARD, color = MaterialTheme.colorScheme.error) }
        }
    }
    if (discarding) {
        DecisionSheet(
            onDismiss = { discarding = false },
            title = "${OfflineChanges.DISCARD}?",
            subtitle = name,
            tile = { Tile(icon = Icons.Outlined.SyncProblem, danger = true) },
            actions = {
                PrimaryButton(OfflineChanges.DISCARD, {
                    discarding = false
                    ctx.launch {
                        ctx.repo.discardChange(change.itemId)
                        ctx.notify("Change discarded.")
                    }
                }, danger = true)
                QuietActions { QuietButton("Cancel", { discarding = false }) }
            },
        ) { PromptText(OfflineChanges.DISCARD_CONFIRM) }
    }
    if (reviewing) ConflictSheet(ctx, change.itemId) { reviewing = false }
}

/**
 * "Changed on another device": both versions with the fields that differ marked (secrets hidden
 * until shown), then the choices of the contract. Nothing is sent until the user decides.
 */
@Composable
fun ConflictSheet(ctx: UiCtx, itemId: String, close: () -> Unit) {
    val view = remember(itemId) { ctx.repo.conflictView(itemId) }
    if (view == null) {
        close()
        return
    }
    val c = view.change
    val deleted = view.theirs == null || c.reason == OfflineChanges.DELETED
    data class Option(val choice: ConflictChoice, val title: String, val detail: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)
    val options = when {
        c.kind == ChangeKind.Trash -> listOf(
            Option(ConflictChoice.Mine, "Move to trash anyway", "The other device's changes go to the trash with it.", Icons.Outlined.Delete),
            Option(ConflictChoice.Other, "Keep the other", "The item stays as the other device saved it.", Icons.Outlined.Devices),
        )
        deleted -> listOf(
            Option(ConflictChoice.Both, "Save mine as a new item", "Your version is saved again as a new item.", Icons.AutoMirrored.Outlined.NoteAdd),
            Option(ConflictChoice.Other, "Discard mine", "Your change is removed from this device.", Icons.Outlined.Close),
        )
        else -> listOf(
            Option(ConflictChoice.Mine, "Keep mine", "Your version replaces the other one.", Icons.Outlined.Smartphone),
            Option(ConflictChoice.Other, "Keep the other", "Your change is removed from this device.", Icons.Outlined.Devices),
            Option(ConflictChoice.Both, "Keep both", "Your version is saved as a new item named \"${(view.mine?.name ?: "").ifEmpty { "Untitled" }}${OfflineChanges.COPY_SUFFIX}\".", Icons.Outlined.ContentCopy),
        )
    }
    var chosen by remember { mutableStateOf(options.first().choice) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var show by remember { mutableStateOf(false) }
    DecisionSheet(
        onDismiss = close,
        title = if (deleted && c.kind != ChangeKind.Trash) "Deleted on another device" else OfflineChanges.CONFLICT,
        subtitle = (view.mine ?: view.theirs)?.name?.ifEmpty { "Untitled" },
        tile = { Tile(icon = Icons.Outlined.Sync) },
        error = error,
        dismissable = !busy,
        actions = {
            PrimaryButton(options.first { it.choice == chosen }.title, {
                busy = true
                error = null
                ctx.scope.launch {
                    try {
                        ctx.repo.resolveConflict(itemId, chosen)
                        close()
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        error = errorMessage(e)
                        busy = false
                    }
                }
            }, busy = busy)
            QuietActions { QuietButton("Not now", close, enabled = !busy) }
        },
    ) {
        val mine = view.mine
        val theirs = view.theirs
        if (mine != null && theirs != null && c.kind == ChangeKind.Edit) {
            val rows = OfflineChanges.differences(mine, theirs)
            val anySecret = rows.any { it.secret && it.differs }
            Row(verticalAlignment = Alignment.CenterVertically) {
                GroupLabel("This device and the other", Modifier.weight(1f))
                if (anySecret) TextButton(onClick = { show = !show }) { Text(if (show) "Hide passwords" else "Show passwords") }
            }
            GroupCard {
                rows.forEachIndexed { n, r ->
                    if (n > 0) RowDivider()
                    DiffRow(r.label, r.mine, r.theirs, r.differs, r.secret && !show)
                }
            }
        } else if (deleted && c.kind == ChangeKind.Edit) {
            PromptText("Someone deleted this item on another device after you changed it here.")
        } else if (c.kind == ChangeKind.Trash) {
            PromptText("Someone changed this item on another device after you moved it to the trash here.")
        }
        GroupCard {
            options.forEachIndexed { n, o ->
                if (n > 0) RowDivider()
                ChoiceRow(o.title, o.detail, chosen == o.choice, { chosen = o.choice }, enabled = !busy, icon = o.icon)
            }
        }
    }
}

@Composable
private fun DiffRow(label: String, mine: String, theirs: String, differs: Boolean, hidden: Boolean) {
    fun shown(v: String) = when {
        v.isEmpty() -> "—"
        hidden -> "••••••••"
        else -> v
    }
    Column(Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.s).semantics(mergeDescendants = true) {}) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, style = MaterialTheme.typography.labelLarge, fontWeight = if (differs) FontWeight.SemiBold else FontWeight.Normal, modifier = Modifier.weight(1f))
            if (differs) {
                Icon(Icons.Outlined.ErrorOutline, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.error)
                Text("Different", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(start = 4.dp))
            }
        }
        if (differs) {
            Text("This device: ${shown(mine)}", style = MaterialTheme.typography.bodyMedium)
            Text("Other device: ${shown(theirs)}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text(shown(mine), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
